#[path = "../src/release/linux_export_sequence.rs"]
mod sequence;
use std::io;
#[derive(Default)]
struct Owner {
    reserved: bool,
    events: Vec<String>,
    receipts: Vec<String>,
}
fn attempt(owner: &mut Owner, scenario: &str) -> io::Result<()> {
    assert!(
        !owner.reserved,
        "next same-account attempt preceded recovery"
    );
    owner.reserved = true;
    owner.events.push(scenario.to_owned());
    owner
        .events
        .push("native-wait-family-request-retained".into());
    Ok(())
}
#[test]
fn each_original_attempt_is_recovered_before_its_same_account_successor() {
    let mut owner = Owner::default();
    let result = sequence::run(&mut owner, &["symlink", "fifo"], attempt, |owner| {
        assert!(owner.reserved);
        assert_eq!(
            owner.events.last().unwrap(),
            "native-wait-family-request-retained"
        );
        owner.events.push("measured-recovery-proof-retained".into());
        owner
            .receipts
            .push(owner.events[owner.events.len() - 3].clone());
        owner.reserved = false;
        Ok(())
    });
    assert!(result.is_ok());
    assert_eq!(owner.receipts, ["symlink", "fifo"]);
    assert_eq!(
        owner.events,
        [
            "symlink",
            "native-wait-family-request-retained",
            "measured-recovery-proof-retained",
            "fifo",
            "native-wait-family-request-retained",
            "measured-recovery-proof-retained"
        ]
    );
}
#[test]
fn recovery_refusal_retains_original_error_and_owner_and_prevents_next_dispatch() {
    let mut owner = Owner::default();
    let result = sequence::run(&mut owner, &["symlink", "fifo"], attempt, |_| {
        Err(io::Error::from_raw_os_error(13))
    });
    let error = result.err().unwrap();
    assert_eq!(error.scenario, "symlink");
    assert_eq!(error.stage, sequence::Stage::Recovery);
    assert_eq!(error.stage.phase(), "export-recovery");
    assert_eq!(error.error.raw_os_error(), Some(13));
    assert!(owner.reserved);
    assert!(owner.receipts.is_empty());
    assert_eq!(
        owner.events,
        ["symlink", "native-wait-family-request-retained"]
    );
}
#[test]
fn failed_attempt_cannot_invent_recovery_or_dispatch_another_attempt() {
    let mut owner = Owner::default();
    let result = sequence::run(
        &mut owner,
        &["symlink", "fifo"],
        |owner, scenario| {
            attempt(owner, scenario)?;
            Err(io::Error::from_raw_os_error(5))
        },
        |_| panic!("incomplete attempt cannot invent a measured recovery"),
    );
    let error = result.err().unwrap();
    assert_eq!(error.stage, sequence::Stage::Attempt);
    assert_eq!(error.stage.phase(), "export-case");
    assert_eq!(error.error.raw_os_error(), Some(5));
    assert!(owner.reserved);
    assert_eq!(owner.events.first().unwrap(), "symlink");
    assert_eq!(owner.events.len(), 2);
}
