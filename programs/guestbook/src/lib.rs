#![no_std]

use pinocchio::{
    account_info::AccountInfo,
    instruction::{Seed, Signer},
    program_entrypoint,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::{Allocate, Assign, CreateAccount, Transfer};

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint {
    use pinocchio::{no_allocator, nostd_panic_handler};
    no_allocator!();
    nostd_panic_handler!();
}

program_entrypoint!(process_instruction);

pub const MAX_MESSAGE_LEN: usize = 100;

pub const BOOK_SEED: &[u8] = b"book";
pub const ENTRY_SEED: &[u8] = b"entry";

pub const BOOK_DISC: u8 = 1;
pub const ENTRY_DISC: u8 = 2;

// Book: disc(1) | owner(32) | bump(1) | entry_count u64 LE (8)
pub const BOOK_LEN: usize = 1 + 32 + 1 + 8;
// Entry: disc(1) | author(32) | book(32) | timestamp i64 LE(8) | id u64 LE(8) | bump(1) | msg_len(1) | message(100)
pub const ENTRY_LEN: usize = 1 + 32 + 32 + 8 + 8 + 1 + 1 + MAX_MESSAGE_LEN;

const ENTRY_AUTHOR: usize = 1;
const ENTRY_BOOK: usize = 33;
const ENTRY_TS: usize = 65;
const ENTRY_ID: usize = 73;
const ENTRY_BUMP: usize = 81;
const ENTRY_MSG_LEN: usize = 82;
const ENTRY_MSG: usize = 83;

pub const IX_INIT_BOOK: u8 = 0;
pub const IX_SIGN: u8 = 1;
pub const IX_CLOSE_ENTRY: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum GuestbookError {
    MessageTooLong = 0,
    Overflow = 1,
}

impl From<GuestbookError> for ProgramError {
    fn from(e: GuestbookError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let (disc, rest) = data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    match *disc {
        IX_INIT_BOOK => init_book(program_id, accounts, rest),
        IX_SIGN => sign(program_id, accounts, rest),
        IX_CLOSE_ENTRY => close_entry(program_id, accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Accounts: payer (signer, writable), owner (signer), book (writable PDA), system program.
fn init_book(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if !data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let [payer, owner, book, system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !payer.is_signer() || !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !payer.is_writable() || !book.is_writable() {
        return Err(ProgramError::InvalidArgument);
    }
    check_system_program(system_program)?;

    let (expected, bump) = find_program_address(&[BOOK_SEED, owner.key().as_ref()], program_id);
    if book.key() != &expected {
        return Err(ProgramError::InvalidSeeds);
    }

    let bump_seed = [bump];
    let seeds = [
        Seed::from(BOOK_SEED),
        Seed::from(owner.key().as_ref()),
        Seed::from(&bump_seed),
    ];
    create_pda(payer, book, BOOK_LEN, program_id, &seeds)?;

    let mut d = book.try_borrow_mut_data()?;
    d[0] = BOOK_DISC;
    d[1..33].copy_from_slice(owner.key().as_ref());
    d[33] = bump;
    d[34..42].copy_from_slice(&0u64.to_le_bytes());
    Ok(())
}

/// Accounts: author (signer, writable), book (writable), entry (writable PDA), system program.
/// Data: the message bytes (at most 100).
fn sign(program_id: &Pubkey, accounts: &[AccountInfo], message: &[u8]) -> ProgramResult {
    if message.len() > MAX_MESSAGE_LEN {
        return Err(GuestbookError::MessageTooLong.into());
    }
    let [author, book, entry, system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !author.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !author.is_writable() || !book.is_writable() || !entry.is_writable() {
        return Err(ProgramError::InvalidArgument);
    }
    check_system_program(system_program)?;

    if !book.is_owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }
    let id = {
        let d = book.try_borrow_data()?;
        if d.len() != BOOK_LEN || d[0] != BOOK_DISC {
            return Err(ProgramError::InvalidAccountData);
        }
        u64::from_le_bytes(d[34..42].try_into().unwrap())
    };
    let next_id = id.checked_add(1).ok_or(GuestbookError::Overflow)?;

    let id_bytes = id.to_le_bytes();
    let (expected, bump) = find_program_address(
        &[ENTRY_SEED, book.key().as_ref(), id_bytes.as_ref()],
        program_id,
    );
    if entry.key() != &expected {
        return Err(ProgramError::InvalidSeeds);
    }

    let timestamp = Clock::get()?.unix_timestamp;

    let bump_seed = [bump];
    let seeds = [
        Seed::from(ENTRY_SEED),
        Seed::from(book.key().as_ref()),
        Seed::from(id_bytes.as_ref()),
        Seed::from(&bump_seed),
    ];
    create_pda(author, entry, ENTRY_LEN, program_id, &seeds)?;

    {
        let mut d = entry.try_borrow_mut_data()?;
        d[0] = ENTRY_DISC;
        d[ENTRY_AUTHOR..ENTRY_AUTHOR + 32].copy_from_slice(author.key().as_ref());
        d[ENTRY_BOOK..ENTRY_BOOK + 32].copy_from_slice(book.key().as_ref());
        d[ENTRY_TS..ENTRY_TS + 8].copy_from_slice(&timestamp.to_le_bytes());
        d[ENTRY_ID..ENTRY_ID + 8].copy_from_slice(&id_bytes);
        d[ENTRY_BUMP] = bump;
        d[ENTRY_MSG_LEN] = message.len() as u8;
        d[ENTRY_MSG..ENTRY_MSG + message.len()].copy_from_slice(message);
    }

    let mut b = book.try_borrow_mut_data()?;
    b[34..42].copy_from_slice(&next_id.to_le_bytes());
    Ok(())
}

/// Accounts: author (signer, writable), entry (writable). Rent goes back to the author.
fn close_entry(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if !data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let [author, entry] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !author.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !author.is_writable() || !entry.is_writable() {
        return Err(ProgramError::InvalidArgument);
    }
    if !entry.is_owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }
    {
        let d = entry.try_borrow_data()?;
        if d.len() != ENTRY_LEN || d[0] != ENTRY_DISC {
            return Err(ProgramError::InvalidAccountData);
        }
        if &d[ENTRY_AUTHOR..ENTRY_AUTHOR + 32] != author.key().as_ref() {
            return Err(ProgramError::IllegalOwner);
        }
    }

    {
        let mut author_lamports = author.try_borrow_mut_lamports()?;
        let mut entry_lamports = entry.try_borrow_mut_lamports()?;
        *author_lamports = author_lamports
            .checked_add(*entry_lamports)
            .ok_or(GuestbookError::Overflow)?;
        *entry_lamports = 0;
    }
    entry.close()
}

fn check_system_program(account: &AccountInfo) -> ProgramResult {
    if account.key() != &pinocchio_system::ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    Ok(())
}

/// Creates a PDA account; tolerates a pre-funded address (create_account would fail on it).
fn create_pda(
    payer: &AccountInfo,
    account: &AccountInfo,
    space: usize,
    owner: &Pubkey,
    seeds: &[Seed],
) -> ProgramResult {
    let rent = Rent::get()?.minimum_balance(space);
    let signers = [Signer::from(seeds)];
    let current = account.lamports();
    if current == 0 {
        CreateAccount {
            from: payer,
            to: account,
            lamports: rent,
            space: space as u64,
            owner,
        }
        .invoke_signed(&signers)
    } else {
        let missing = rent.saturating_sub(current);
        if missing > 0 {
            Transfer {
                from: payer,
                to: account,
                lamports: missing,
            }
            .invoke()?;
        }
        Allocate {
            account,
            space: space as u64,
        }
        .invoke_signed(&signers)?;
        Assign { account, owner }.invoke_signed(&signers)
    }
}
