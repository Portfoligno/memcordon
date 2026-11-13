use memcordon_ci::{
    windows_consumer_readiness::{
        descriptor::controller_start::Binding,
        post_listener_end::{self as post, Evidence, Stage},
    },
    windows_listener_wait::{Identity, Owner},
};
use memcordon_platform::windows_private_fixture_binding::{
    DotLocalInput, PrivateFixtureAncestor, PrivateFixtureBinding,
};
use std::time::{Duration, Instant};

#[path = "../src/windows_private_peer_debt.rs"]
pub mod debt;

const ROOT: Identity = Identity { pid: 10, birth: 20 };
const GUARDIAN: Identity = Identity { pid: 30, birth: 40 };
const GUARDIANS: [Identity; 1] = [GUARDIAN];

fn private_binding() -> PrivateFixtureBinding {
    let temporary = std::env::temp_dir();
    let root = temporary.ancestors().last().unwrap().to_path_buf();
    let parent = root.join("owned");
    let directory = |path, file_index| PrivateFixtureAncestor {
        path,
        volume_serial: 7,
        file_index,
        attributes: 0x10,
    };
    let fixture = parent.join("fixture.exe");
    let binding = PrivateFixtureBinding {
        revision: 2,
        fixture: fixture.clone(),
        volume_serial: 7,
        file_index: 42,
        attributes: 0x20,
        links: 1,
        bytes: 1234,
        sha256: "ab".repeat(32),
        native_path_utf16: r"\Device\Volume\owned\fixture.exe".encode_utf16().collect(),
        ancestors: vec![directory(root.clone(), 1), directory(parent.clone(), 11)],
        local_input: DotLocalInput::Directory(directory(parent.join("fixture.exe.local"), 12)),
        output_ancestors: vec![
            directory(root.clone(), 1),
            directory(root.join("output"), 13),
        ],
    };
    binding
        .validate(&[fixture, parent.join("fixture.exe.local/provider.dll")])
        .unwrap();
    binding
}
fn start() -> Binding {
    Binding {
        pid: ROOT.pid,
        birth: ROOT.birth as u64,
        challenge: b"original".to_vec(),
        descriptor_sha256: [7; 32],
    }
}
fn evidence<'a>(start: &'a Binding, binding: &'a PrivateFixtureBinding) -> Evidence<'a> {
    Evidence {
        expected_root: ROOT,
        owner: Owner {
            identity: ROOT,
            exit_status: Some(2),
        },
        start: Some(start),
        descriptor_sha256: [7; 32],
        challenge: b"original",
        port: 40000,
        observed_guardian: GUARDIAN,
        held_guardians: &GUARDIANS,
        declared_private: Some(binding),
        retained_private: Some(binding),
    }
}

#[test]
fn private_spawn_uncertainty_remains_charged_during_bounded_settlement() {
    let start = start();
    let binding = private_binding();
    let now = Instant::now();
    let cutoff = now + Duration::from_secs(1);
    let mut debt = debt::PeerDebt::default();
    debt.note_spawn();
    for (stage, primary) in [
        (
            Stage::BeforeOwnerCheck,
            "native listener root is not held live",
        ),
        (
            Stage::AfterOwnerCheck,
            "native listener owner retired during observation",
        ),
        (
            Stage::BeforePeerAdmission,
            "private root retired before peer admission",
        ),
    ] {
        let failed = post::qualify(evidence(&start, &binding), stage, now, cutoff).unwrap();
        assert_eq!(failed.ended.identity, ROOT);
        assert_eq!(failed.ended.status, 2);
        assert!(failed.to_string().starts_with(primary));
        assert!(
            stage
                .abort("terminal capture failed")
                .to_string()
                .starts_with(primary)
        );
        assert!(
            debt.release_barrier().is_err(),
            "frontend settlement cannot retire unknown recipients"
        );
    }
}

#[test]
fn missing_or_mismatched_native_start_guardian_and_custody_facts_reject_settlement() {
    let start = start();
    let binding = private_binding();
    let mut different = binding.clone();
    different.file_index += 1;
    let now = Instant::now();
    let cutoff = now + Duration::from_secs(1);
    for field in [
        "zero-pid",
        "zero-birth",
        "live",
        "success",
        "other-root",
        "missing-start",
        "digest",
        "challenge",
        "empty-challenge",
        "port",
        "guardian",
        "missing-guardian",
        "missing-declaration",
        "missing-custody",
        "other-custody",
    ] {
        let mut input = evidence(&start, &binding);
        match field {
            "zero-pid" => input.expected_root.pid = 0,
            "zero-birth" => input.expected_root.birth = 0,
            "live" => input.owner.exit_status = None,
            "success" => input.owner.exit_status = Some(0),
            "other-root" => input.owner.identity.birth += 1,
            "missing-start" => input.start = None,
            "digest" => input.descriptor_sha256[0] ^= 1,
            "challenge" => input.challenge = b"other",
            "empty-challenge" => input.challenge = b"",
            "port" => input.port = 0,
            "guardian" => input.observed_guardian.birth += 1,
            "missing-guardian" => input.held_guardians = &[],
            "missing-declaration" => input.declared_private = None,
            "missing-custody" => input.retained_private = None,
            "other-custody" => input.retained_private = Some(&different),
            _ => unreachable!(),
        }
        assert!(
            post::qualify(input, Stage::BeforeOwnerCheck, now, cutoff).is_none(),
            "{field}"
        );
    }
    for field in ["pid", "birth", "hash", "challenge"] {
        let mut changed = start.clone();
        match field {
            "pid" => changed.pid += 1,
            "birth" => changed.birth += 1,
            "hash" => changed.descriptor_sha256[0] ^= 1,
            "challenge" => changed.challenge.push(0),
            _ => unreachable!(),
        }
        assert!(
            post::qualify(
                evidence(&changed, &binding),
                Stage::BeforeOwnerCheck,
                now,
                cutoff
            )
            .is_none(),
            "START {field}"
        );
    }
    let duplicate = [GUARDIAN, GUARDIAN];
    let mut input = evidence(&start, &binding);
    input.held_guardians = &duplicate;
    assert!(post::qualify(input, Stage::BeforeOwnerCheck, now, cutoff).is_none());
}

#[test]
fn original_absolute_cutoff_has_no_post_listener_grace() {
    let start = start();
    let binding = private_binding();
    let cutoff = Instant::now();
    for now in [cutoff, cutoff + Duration::from_nanos(1)] {
        assert!(
            post::qualify(
                evidence(&start, &binding),
                Stage::BeforeOwnerCheck,
                now,
                cutoff
            )
            .is_none()
        );
    }
}

fn frontend_command() -> std::process::Command {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args([
        "bounded_frontend_helper",
        "--exact",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ]);
    command.stdin(std::process::Stdio::piped());
    command
}

#[test]
fn typed_post_listener_primary_survives_actual_natural_frontend_settlement() {
    use std::io::Write;
    let start = start();
    let binding = private_binding();
    let now = Instant::now();
    let cutoff = now + Duration::from_secs(5);
    let failure = post::qualify(
        evidence(&start, &binding),
        Stage::BeforeOwnerCheck,
        now,
        cutoff,
    )
    .unwrap();
    let error = memcordon_testkit::run_until_owned_spawn_with_io_output_limit_outcome(
        frontend_command(),
        cutoff,
        4096,
        |mut command| command.spawn(),
        move |_, input, _| {
            let mut input = input.unwrap();
            if let Err(error) = input.write_all(b"R") {
                return memcordon_testkit::OwnedCallbackOutcome::Abort(error);
            }
            memcordon_testkit::OwnedCallbackOutcome::ApplicationEnded(std::io::Error::other(
                failure,
            ))
        },
    )
    .unwrap_err();
    let memcordon_testkit::ProcessTestError::ApplicationEnded { error, settlement } = error else {
        panic!("post-listener application failure must remain primary");
    };
    let primary = error
        .get_ref()
        .unwrap()
        .downcast_ref::<post::Failure>()
        .unwrap();
    assert_eq!(primary.ended.identity, ROOT);
    assert_eq!(primary.ended.status, 2);
    assert_eq!(settlement.unwrap().status.code(), Some(2));
}

#[test]
fn typed_post_listener_primary_survives_original_cutoff_with_secondary_failure() {
    let start = start();
    let binding = private_binding();
    let now = Instant::now();
    let cutoff = now + Duration::from_secs(1);
    let failure = post::qualify(
        evidence(&start, &binding),
        Stage::BeforePeerAdmission,
        now,
        cutoff,
    )
    .unwrap();
    let retained_stdin = std::sync::Arc::new(std::sync::Mutex::new(None));
    let callback_stdin = std::sync::Arc::clone(&retained_stdin);
    let error = memcordon_testkit::run_until_owned_spawn_with_io_output_limit_outcome(
        frontend_command(),
        cutoff,
        4096,
        |mut command| command.spawn(),
        move |_, input, _| {
            *callback_stdin.lock().unwrap() = input;
            memcordon_testkit::OwnedCallbackOutcome::ApplicationEnded(std::io::Error::other(
                failure,
            ))
        },
    )
    .unwrap_err();
    assert!(Instant::now() >= cutoff);
    drop(retained_stdin);
    let memcordon_testkit::ProcessTestError::ApplicationEnded { error, settlement } = error else {
        panic!("original application failure must survive settlement expiry");
    };
    assert_eq!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<post::Failure>()
            .unwrap()
            .ended
            .status,
        2
    );
    assert!(
        settlement.is_err(),
        "expired wait cannot become natural completion"
    );
    assert!(
        error
            .to_string()
            .starts_with("private root retired before peer admission")
    );
}

#[test]
#[ignore]
fn bounded_frontend_helper() {
    use std::io::Read;
    let mut release = [0u8; 1];
    std::io::stdin().read_exact(&mut release).unwrap();
    assert_eq!(release, *b"R");
    std::process::exit(2);
}
