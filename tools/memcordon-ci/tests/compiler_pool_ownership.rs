#![cfg(unix)]

use memcordon_ci::{command::CommandSpec, compiler_pool, work_outcome::WriterSettlement};
use std::{os::unix::fs::FileTypeExt, path::PathBuf, process::Command, time::Duration};

fn materialize(owner: compiler_pool::CompilerOwner) -> memcordon_ci::Result<Command> {
    CommandSpec::cargo(
        "rustup",
        std::path::Path::new("."),
        "1.97.1",
        Duration::from_secs(5),
    )
    .arg("check")
    .compiler_owner(owner)
    .materialize()
}

fn fifo(command: &Command) -> PathBuf {
    let value = command
        .get_envs()
        .find(|(key, _)| *key == "CARGO_MAKEFLAGS")
        .unwrap()
        .1
        .unwrap()
        .to_str()
        .unwrap();
    PathBuf::from(value.strip_prefix("-j --jobserver-auth=fifo:").unwrap())
}

#[test]
fn admitted_protocol_is_child_local_and_follows_environment_sanitization() {
    let keys = [
        "MAKEFLAGS",
        "MFLAGS",
        "CARGO_BUILD_JOBS",
        "CARGO_MAKEFLAGS",
        "GH_TOKEN",
        "GITHUB_TOKEN",
    ];
    let before: Vec<_> = keys.iter().map(std::env::var_os).collect();
    let home = tempfile::tempdir_in("/tmp").unwrap();
    let owners = compiler_pool::pair(1, false).unwrap();
    let command = CommandSpec::cargo("rustup", home.path(), "1.97.1", Duration::from_secs(5))
        .arg("check")
        .isolated_cargo(home.path())
        .compiler_owner(owners[0].clone())
        .materialize()
        .unwrap();
    // No child was spawned: release these reservations before assertions.
    owners[0].settle(WriterSettlement::NotStarted).unwrap();
    owners[1].settle(WriterSettlement::NotStarted).unwrap();
    let changes: std::collections::BTreeMap<_, _> = command.get_envs().collect();
    for key in [
        "MAKEFLAGS",
        "MFLAGS",
        "CARGO_BUILD_JOBS",
        "GH_TOKEN",
        "GITHUB_TOKEN",
    ] {
        assert_eq!(changes.get(std::ffi::OsStr::new(key)), Some(&None));
    }
    assert!(
        std::fs::symlink_metadata(fifo(&command))
            .unwrap()
            .file_type()
            .is_fifo()
    );
    let after: Vec<_> = keys.iter().map(std::env::var_os).collect();
    assert!(
        before == after,
        "child protocol must not mutate parent environment"
    );
    let ordinary = CommandSpec::cargo(
        "rustup",
        std::path::Path::new("."),
        "1.97.1",
        Duration::from_secs(5),
    )
    .arg("check")
    .materialize()
    .unwrap();
    assert!(!ordinary.get_envs().any(|(key, _)| key == "CARGO_MAKEFLAGS"));
}

#[test]
fn named_fifo_missing_or_replaced_cannot_admit_another_root() {
    for replace in [false, true] {
        let owners = compiler_pool::pair(2, true).unwrap();
        let first = materialize(owners[0].clone()).unwrap();
        let path = fifo(&first);
        std::fs::remove_file(&path).unwrap();
        if replace {
            std::fs::write(&path, b"not a jobserver").unwrap();
        }
        assert!(materialize(owners[1].clone()).is_err());
        owners[0].settle(WriterSettlement::NotStarted).unwrap();
        owners[1].settle(WriterSettlement::NotStarted).unwrap();
    }
}

#[test]
fn actual_adapter_rejects_every_explicit_jobs_form_before_admission() {
    for arguments in [vec!["--jobs", "1"], vec!["--jobs=1"], vec!["-j1"]] {
        let owners = compiler_pool::pair(1, false).unwrap();
        let result = CommandSpec::cargo(
            "rustup",
            std::path::Path::new("."),
            "1.97.1",
            Duration::from_secs(5),
        )
        .arg("check")
        .args(arguments)
        .compiler_owner(owners[0].clone())
        .materialize();
        assert!(result.is_err());
        // Rejection precedes pool admission; the reservation still has one use.
        materialize(owners[0].clone()).unwrap();
        owners[0].settle(WriterSettlement::NotStarted).unwrap();
        owners[1].settle(WriterSettlement::NotStarted).unwrap();
    }
}

#[test]
fn real_pinned_cargo_failure_returns_serial_reservation_after_settlement() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::write(root.path().join("Cargo.toml"), "this is not TOML\n").unwrap();
    let owners = compiler_pool::pair(1, false).unwrap();
    let result = CommandSpec::cargo("rustup", root.path(), "1.97.1", Duration::from_secs(10))
        .args(["check", "--offline"])
        .compiler_owner(owners[0].clone())
        .run_owned();
    assert!(result.writers().permits_reading());
    assert!(result.into_result().is_err());
    materialize(owners[1].clone()).unwrap();
    owners[1].settle(WriterSettlement::NotStarted).unwrap();
}

#[test]
fn bounded_cargo_timeout_returns_reservation_only_with_settled_writers() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::create_dir(root.path().join("src")).unwrap();
    std::fs::write(
        root.path().join("Cargo.toml"),
        "[package]\nname=\"bounded-pool-owner\"\nversion=\"0.0.0\"\nedition=\"2021\"\n",
    )
    .unwrap();
    std::fs::write(root.path().join("src/lib.rs"), "pub fn value() {}\n").unwrap();
    std::fs::write(root.path().join("build.rs"),
        "fn main() { std::fs::write(\"build-script-entered\", b\"entered\").unwrap(); std::thread::sleep(std::time::Duration::from_secs(10)); }\n").unwrap();
    let owners = compiler_pool::pair(1, false).unwrap();
    let started = std::time::Instant::now();
    let work_cutoff = started + Duration::from_secs(3);
    let operation_cutoff = started + Duration::from_secs(13);
    let result = CommandSpec::cargo("rustup", root.path(), "1.97.1", Duration::from_secs(3))
        .args(["check", "--offline"])
        .bounded_until(operation_cutoff)
        .compiler_owner(owners[0].clone())
        .run_owned();
    let settled = result.writers().permits_reading();
    let failure = result.into_result().unwrap_err();
    assert!(
        failure.to_string().contains("subprocess exceeded"),
        "expected actual child timeout: {failure}"
    );
    assert!(
        root.path().join("build-script-entered").is_file(),
        "timeout fixture must reach its actual Cargo build script; actual failure: {failure}"
    );
    // The original operation includes the adapter's reserved ten-second cleanup.
    assert!(std::time::Instant::now() >= work_cutoff - Duration::from_millis(100));
    assert!(
        std::time::Instant::now() <= operation_cutoff,
        "owned cleanup exceeded its original slice: {failure}"
    );
    let admission = materialize(owners[1].clone());
    assert_eq!(admission.is_ok(), settled);
    if settled {
        owners[1].settle(WriterSettlement::NotStarted).unwrap();
    } else {
        // An uncertain process may still be writing into this fixture.
        let _retained = root.keep();
    }
}

#[test]
fn nested_preparation_cannot_expand_its_inherited_pool_budget() {
    use memcordon_ci::{failure_mode::FailureMode, performance_plan::Layout, preparation};
    preparation::complete_lanes_with_allocation(
        Layout::Parallel,
        FailureMode::CollectAll,
        [1, 1],
        || {
            let inherited = preparation::active_group().unwrap().compiler_jobs();
            preparation::complete_lanes(
                Layout::Parallel,
                || {
                    assert_eq!(
                        preparation::active_group().unwrap().compiler_jobs(),
                        inherited
                    );
                    assert!(compiler_pool::pair(inherited + 1, inherited + 1 > 1).is_err());
                    let owners = compiler_pool::pair(inherited, false)?;
                    materialize(owners[0].clone())?;
                    owners[0].settle(WriterSettlement::NotStarted)?;
                    materialize(owners[1].clone())?;
                    owners[1].settle(WriterSettlement::NotStarted)
                },
                || Ok(()),
            )
        },
        || Ok(()),
    )
    .unwrap();
}
