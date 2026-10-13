use litesvm::LiteSVM;
use solana_sdk::{
    clock::Clock,
    instruction::{AccountMeta, Instruction, InstructionError},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_program,
    transaction::{Transaction, TransactionError},
};

const BOOK_LEN: usize = 42;
const ENTRY_LEN: usize = 183;

struct Env {
    svm: LiteSVM,
    program_id: Pubkey,
    owner: Keypair,
    book: Pubkey,
}

fn setup() -> Env {
    let mut svm = LiteSVM::new();
    let program_id = Pubkey::new_unique();
    let so = concat!(env!("CARGO_MANIFEST_DIR"), "/target/deploy/guestbook.so");
    svm.add_program_from_file(program_id, so)
        .expect("run `cargo build-sbf` first");

    let owner = Keypair::new();
    svm.airdrop(&owner.pubkey(), 10_000_000_000).unwrap();
    let (book, _) = Pubkey::find_program_address(&[b"book", owner.pubkey().as_ref()], &program_id);

    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(owner.pubkey(), true),
            AccountMeta::new_readonly(owner.pubkey(), true),
            AccountMeta::new(book, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data: vec![0],
    };
    send(&mut svm, &[ix], &owner, &[&owner]).expect("init_book");
    Env { svm, program_id, owner, book }
}

fn send(
    svm: &mut LiteSVM,
    ixs: &[Instruction],
    payer: &Keypair,
    signers: &[&Keypair],
) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    svm.expire_blockhash();
    let tx = Transaction::new_signed_with_payer(
        ixs,
        Some(&payer.pubkey()),
        signers,
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).map(|_| ())
}

fn entry_pda(env: &Env, id: u64) -> Pubkey {
    Pubkey::find_program_address(
        &[b"entry", env.book.as_ref(), &id.to_le_bytes()],
        &env.program_id,
    )
    .0
}

fn sign_ix(env: &Env, author: &Pubkey, id: u64, message: &[u8]) -> Instruction {
    let mut data = vec![1];
    data.extend_from_slice(message);
    Instruction {
        program_id: env.program_id,
        accounts: vec![
            AccountMeta::new(*author, true),
            AccountMeta::new(env.book, false),
            AccountMeta::new(entry_pda(env, id), false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data,
    }
}

fn close_ix(env: &Env, author: &Pubkey, id: u64) -> Instruction {
    Instruction {
        program_id: env.program_id,
        accounts: vec![
            AccountMeta::new(*author, true),
            AccountMeta::new(entry_pda(env, id), false),
        ],
        data: vec![2],
    }
}

fn funded(env: &mut Env) -> Keypair {
    let kp = Keypair::new();
    env.svm.airdrop(&kp.pubkey(), 10_000_000_000).unwrap();
    kp
}

fn instruction_error(e: &litesvm::types::FailedTransactionMetadata) -> Option<InstructionError> {
    match &e.err {
        TransactionError::InstructionError(_, ie) => Some(ie.clone()),
        _ => None,
    }
}

fn custom_code(e: &litesvm::types::FailedTransactionMetadata) -> Option<u32> {
    match instruction_error(e) {
        Some(InstructionError::Custom(c)) => Some(c),
        _ => None,
    }
}

#[test]
fn init_book_creates_book() {
    let env = setup();
    let acc = env.svm.get_account(&env.book).expect("book exists");
    assert_eq!(acc.owner, env.program_id);
    assert_eq!(acc.data.len(), BOOK_LEN);
    assert_eq!(acc.data[0], 1);
    assert_eq!(&acc.data[1..33], env.owner.pubkey().as_ref());
    assert_eq!(&acc.data[34..42], &0u64.to_le_bytes());
}

#[test]
fn sign_creates_entry() {
    let mut env = setup();
    let mut clock = env.svm.get_sysvar::<Clock>();
    clock.unix_timestamp = 1_700_000_000;
    env.svm.set_sysvar(&clock);

    let alice = funded(&mut env);
    let ix = sign_ix(&env, &alice.pubkey(), 0, b"hello world");
    send(&mut env.svm, &[ix], &alice, &[&alice]).expect("sign");

    let acc = env.svm.get_account(&entry_pda(&env, 0)).expect("entry exists");
    assert_eq!(acc.owner, env.program_id);
    assert_eq!(acc.data.len(), ENTRY_LEN);
    assert_eq!(acc.data[0], 2);
    assert_eq!(&acc.data[1..33], alice.pubkey().as_ref());
    assert_eq!(&acc.data[33..65], env.book.as_ref());
    assert_eq!(&acc.data[65..73], &1_700_000_000i64.to_le_bytes());
    assert_eq!(acc.data[82] as usize, 11);
    assert_eq!(&acc.data[83..94], b"hello world");

    let book = env.svm.get_account(&env.book).unwrap();
    assert_eq!(&book.data[34..42], &1u64.to_le_bytes());

    // A second signer (not the book owner) gets the next id.
    let bob = funded(&mut env);
    let ix = sign_ix(&env, &bob.pubkey(), 1, b"hi");
    send(&mut env.svm, &[ix], &bob, &[&bob]).expect("second sign");
    let acc = env.svm.get_account(&entry_pda(&env, 1)).unwrap();
    assert_eq!(&acc.data[1..33], bob.pubkey().as_ref());
}

#[test]
fn message_limit_is_100_bytes() {
    let mut env = setup();
    let alice = funded(&mut env);

    let too_long = vec![b'a'; 101];
    let ix = sign_ix(&env, &alice.pubkey(), 0, &too_long);
    let err = send(&mut env.svm, &[ix], &alice, &[&alice]).expect_err("101 bytes must fail");
    assert_eq!(custom_code(&err), Some(0));
    assert!(env.svm.get_account(&entry_pda(&env, 0)).is_none());

    let exact = vec![b'a'; 100];
    let ix = sign_ix(&env, &alice.pubkey(), 0, &exact);
    send(&mut env.svm, &[ix], &alice, &[&alice]).expect("100 bytes must succeed");
}

#[test]
fn stranger_cannot_close_entry_but_author_can() {
    let mut env = setup();
    let alice = funded(&mut env);
    let mallory = funded(&mut env);

    let ix = sign_ix(&env, &alice.pubkey(), 0, b"mine");
    send(&mut env.svm, &[ix], &alice, &[&alice]).unwrap();
    let entry = entry_pda(&env, 0);
    let entry_lamports = env.svm.get_account(&entry).unwrap().lamports;

    // Stranger signs as themselves.
    let ix = close_ix(&env, &mallory.pubkey(), 0);
    let err = send(&mut env.svm, &[ix], &mallory, &[&mallory]).expect_err("stranger must not close");
    assert_eq!(instruction_error(&err), Some(InstructionError::IllegalOwner));
    assert!(env.svm.get_account(&entry).is_some());

    // Stranger names the author but does not sign for them.
    let mut ix = close_ix(&env, &alice.pubkey(), 0);
    ix.accounts[0].is_signer = false;
    let err = send(&mut env.svm, &[ix], &mallory, &[&mallory]).expect_err("missing author signature");
    assert_eq!(
        instruction_error(&err),
        Some(InstructionError::MissingRequiredSignature)
    );
    assert!(env.svm.get_account(&entry).is_some());

    // Author closes and gets rent back.
    let before = env.svm.get_account(&alice.pubkey()).unwrap().lamports;
    let ix = close_ix(&env, &alice.pubkey(), 0);
    send(&mut env.svm, &[ix], &alice, &[&alice]).expect("author closes");
    let closed = env.svm.get_account(&entry);
    assert!(closed.map_or(true, |a| a.lamports == 0 && a.data.is_empty()));
    let after = env.svm.get_account(&alice.pubkey()).unwrap().lamports;
    assert_eq!(after, before + entry_lamports - 5_000);
}

#[test]
fn book_owner_cannot_close_someone_elses_entry() {
    let mut env = setup();
    let alice = funded(&mut env);
    let ix = sign_ix(&env, &alice.pubkey(), 0, b"mine");
    send(&mut env.svm, &[ix], &alice, &[&alice]).unwrap();

    let owner = Keypair::from_bytes(&env.owner.to_bytes()).unwrap();
    let ix = close_ix(&env, &owner.pubkey(), 0);
    let err = send(&mut env.svm, &[ix], &owner, &[&owner]).expect_err("owner is not the author");
    assert_eq!(instruction_error(&err), Some(InstructionError::IllegalOwner));
    assert!(env.svm.get_account(&entry_pda(&env, 0)).is_some());
}

#[test]
fn init_book_requires_owner_signature_and_is_not_repeatable() {
    let mut env = setup();
    let payer = funded(&mut env);
    let other = Keypair::new();
    let (other_book, _) =
        Pubkey::find_program_address(&[b"book", other.pubkey().as_ref()], &env.program_id);

    // Payer names another owner who does not sign.
    let ix = Instruction {
        program_id: env.program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(other.pubkey(), false),
            AccountMeta::new(other_book, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data: vec![0],
    };
    let err = send(&mut env.svm, &[ix], &payer, &[&payer]).expect_err("owner must sign");
    assert_eq!(
        instruction_error(&err),
        Some(InstructionError::MissingRequiredSignature)
    );
    assert!(env.svm.get_account(&other_book).is_none());

    // Re-initializing an existing book fails and leaves it intact.
    let ix = Instruction {
        program_id: env.program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(env.owner.pubkey(), true),
            AccountMeta::new(env.book, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data: vec![0],
    };
    let owner = Keypair::from_bytes(&env.owner.to_bytes()).unwrap();
    send(&mut env.svm, &[ix], &payer, &[&payer, &owner]).expect_err("book already exists");
    let acc = env.svm.get_account(&env.book).unwrap();
    assert_eq!(acc.data[0], 1);
    assert_eq!(&acc.data[1..33], env.owner.pubkey().as_ref());
}

#[test]
fn prefunded_entry_address_does_not_block_signing() {
    let mut env = setup();
    let alice = funded(&mut env);
    let griefer = funded(&mut env);
    let entry = entry_pda(&env, 0);

    let transfer =
        solana_sdk::system_instruction::transfer(&griefer.pubkey(), &entry, 1_000);
    send(&mut env.svm, &[transfer], &griefer, &[&griefer]).unwrap();

    let ix = sign_ix(&env, &alice.pubkey(), 0, b"still works");
    send(&mut env.svm, &[ix], &alice, &[&alice]).expect("sign over prefunded PDA");
    assert_eq!(env.svm.get_account(&entry).unwrap().owner, env.program_id);
}
