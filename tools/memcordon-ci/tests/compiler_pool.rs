#![cfg(unix)]
use memcordon_ci::{command::CommandSpec, compiler_pool, work_outcome::WriterSettlement};
#[path = "fixtures/compiler_pool_protocol.rs"]
mod protocol;
use protocol::{Protocol, Role};
use std::{
    path::Path,
    time::{Duration, Instant, SystemTime},
};

fn graph(root: &Path, members: usize, wrapper: &Path, cutoff: Instant) {
    std::fs::create_dir_all(root.join(".cargo")).unwrap();
    let config = toml::toml! {[build] rustc-wrapper = "placeholder"};
    let mut config = config;
    config
        .get_mut("build")
        .unwrap()
        .as_table_mut()
        .unwrap()
        .insert(
            "rustc-wrapper".into(),
            toml::Value::String(wrapper.to_str().unwrap().into()),
        );
    std::fs::write(
        root.join(".cargo/config.toml"),
        toml::to_string(&config).unwrap(),
    )
    .unwrap();
    let names: Vec<_> = (0..members).map(|i| format!("unit{i}")).collect();
    let manifest = toml::toml! {[workspace] resolver="2" members=names};
    std::fs::write(root.join("Cargo.toml"), toml::to_string(&manifest).unwrap()).unwrap();
    for i in 0..members {
        let unit = root.join(format!("unit{i}"));
        std::fs::create_dir_all(unit.join("src")).unwrap();
        std::fs::write(
            unit.join("Cargo.toml"),
            format!("[package]\nname=\"unit{i}\"\nversion=\"0.0.0\"\nedition=\"2021\"\n"),
        )
        .unwrap();
        std::fs::write(unit.join("src/lib.rs"), "pub fn value()->u32 { 1 }\n").unwrap();
    }
    cargo(root)
        .arg("generate-lockfile")
        .arg("--offline")
        .bounded_until(cutoff)
        .run()
        .unwrap();
}

fn cargo(root: &Path) -> CommandSpec {
    CommandSpec::cargo("rustup", root, "1.97.1", Duration::from_secs(30))
}

#[test]
fn real_pinned_cargo_shares_reserved_roots_and_borrows_settled_capacity() {
    let temp = tempfile::tempdir_in("/tmp").unwrap();
    let wrapper = temp.path().join("compiler-observer");
    CommandSpec::toolchain_program(
        "rustup",
        Path::new(env!("CARGO_MANIFEST_DIR")),
        "1.97.1",
        "rustc",
        Duration::from_secs(30),
    )
    .args([
        "--edition=2021",
        "tests/fixtures/compiler_pool_wrapper.rs",
        "-o",
    ])
    .arg(&wrapper)
    .run()
    .unwrap();
    for budget in [1, 2, 4] {
        let base = temp.path().join(format!("budget{budget}"));
        std::fs::create_dir(&base).unwrap();
        let cutoff = Instant::now() + Duration::from_secs(30);
        let protocol = Protocol::create(
            &base.join("control"),
            budget,
            SystemTime::now() + cutoff.saturating_duration_since(Instant::now()),
        )
        .unwrap();
        let product_wrapper = base.join("control/product-wrapper");
        let native_wrapper = base.join("control/native-wrapper");
        std::fs::copy(&wrapper, &product_wrapper).unwrap();
        std::fs::copy(&wrapper, &native_wrapper).unwrap();
        let first = base.join("product");
        let second = base.join("native");
        graph(&first, 1, &product_wrapper, cutoff);
        graph(&second, 8, &native_wrapper, cutoff);
        if budget == 2 {
            let path = second.join(".cargo/config.toml");
            let mut config: toml::Table =
                toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            config
                .get_mut("build")
                .unwrap()
                .as_table_mut()
                .unwrap()
                .insert("jobs".into(), toml::Value::Integer(99));
            std::fs::write(path, toml::to_string(&config).unwrap()).unwrap();
        }
        let owners = compiler_pool::pair(budget, budget > 1).unwrap();
        let product = cargo(&first)
            .args(["build", "--release", "--locked", "--offline"])
            .bounded_until(cutoff)
            .compiler_owner(owners[0].clone());
        let native = cargo(&second)
            .args([
                "test",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--release",
                "--no-run",
                "--locked",
                "--offline",
            ])
            .bounded_until(cutoff)
            .compiler_owner(owners[1].clone());
        let native = if budget == 4 {
            native.args(["--config", "build.jobs=99"])
        } else {
            native
        };
        if budget == 1 {
            protocol.release_all().unwrap();
            settled_command(product.run_owned()).unwrap();
            settled_command(native.run_owned()).unwrap();
        } else {
            std::thread::scope(|scope| {
                // On coordinator unwind this guard drops before scope's
                // implicit joins, so no admitted wrapper remains gated.
                let _release = protocol.release_guard();
                let mut first = Some(scope.spawn(|| settled_command(product.run_owned())));
                let second = scope.spawn(|| settled_command(native.run_owned()));
                let phases = (|| -> Result<protocol::State, String> {
                    let initial = protocol
                        .wait_roles(1, budget - 1, cutoff)
                        .map_err(|error| error.to_string())?;
                    if initial.total() != budget {
                        return Err("initial root sharing differs".into());
                    }
                    protocol
                        .release(Role::Product)
                        .map_err(|error| error.to_string())?;
                    first
                        .take()
                        .expect("original product thread")
                        .join()
                        .map_err(|_| "product command thread panicked".to_string())??;
                    // run_owned settled/donated before returning. Already
                    // registered native wrappers count in this locked state;
                    // no subsequent event/late marker is required.
                    protocol
                        .wait_roles(0, budget, cutoff)
                        .map_err(|error| error.to_string())
                })();
                let released = protocol.release_all();
                let product_result = first.map(|thread| thread.join()).transpose();
                let native_result = second.join();
                let events = protocol.events().unwrap_or_else(|error| error.to_string());
                assert!(
                    released.is_ok(),
                    "gate release={released:?}; events={events}"
                );
                if let Some(result) = product_result.expect("product command thread panicked") {
                    assert!(
                        result.is_ok(),
                        "product={result:?}; phase={phases:?}; events={events}"
                    );
                }
                assert!(
                    native_result.as_ref().is_ok_and(|result| result.is_ok()),
                    "native={native_result:?}; phase={phases:?}; events={events}"
                );
                let borrowed =
                    phases.unwrap_or_else(|error| panic!("rendezvous={error}; events={events}"));
                assert_eq!(borrowed.product, 0);
                assert_eq!(
                    borrowed.native, budget,
                    "remaining native Cargo did not borrow settled product capacity: {events}"
                );
            });
        }
        let state = protocol.snapshot().unwrap();
        assert_eq!(state.total(), 0);
        let events = protocol.events().unwrap();
        let maximum = state.maximum;
        assert!(
            maximum <= budget,
            "budget={budget} max={maximum} events={events}"
        );
        assert_eq!(
            maximum, budget,
            "real Cargo did not use shared capacity: {events}"
        );
    }
}

fn settled_command(
    outcome: memcordon_ci::work_outcome::WorkOutcome<Vec<u8>>,
) -> Result<(), String> {
    let writers = outcome.writers();
    let result = outcome.into_result().map_err(|error| error.to_string());
    if writers != WriterSettlement::Settled {
        return Err(format!(
            "original compiler writers={writers:?}; result={result:?}"
        ));
    }
    result.map(|_| ())
}

#[test]
fn locked_role_snapshot_counts_native_admitted_before_coordinator_observation() {
    let temp = tempfile::tempdir().unwrap();
    let protocol = Protocol::create(
        &temp.path().join("control"),
        2,
        SystemTime::now() + Duration::from_secs(3),
    )
    .unwrap();
    let cutoff = Instant::now() + Duration::from_secs(3);
    let product = protocol.admit(Role::Product).unwrap();
    let native = protocol.admit(Role::Native).unwrap();
    assert_eq!(protocol.wait_roles(1, 1, cutoff).unwrap().total(), 2);
    product.finish().unwrap();
    let donated = protocol.admit(Role::Native).unwrap();
    let snapshot = protocol.wait_roles(0, 2, cutoff).unwrap();
    assert_eq!(
        (snapshot.product, snapshot.native, snapshot.maximum),
        (0, 2, 2)
    );
    donated.finish().unwrap();
    native.finish().unwrap();
    assert_eq!(protocol.snapshot().unwrap().total(), 0);
}

#[test]
fn rendezvous_failure_guard_releases_both_roles_and_rejects_stale_gates() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("control");
    let deadline = SystemTime::now() + Duration::from_secs(3);
    let protocol = Protocol::create(&root, 2, deadline).unwrap();
    let panic = std::panic::catch_unwind(|| {
        let _release = protocol.release_guard();
        panic!("coordinator failure before join");
    });
    assert!(panic.is_err());
    protocol.wait_gate(Role::Product).unwrap();
    protocol.wait_gate(Role::Native).unwrap();
    assert_eq!(
        protocol.release(Role::Product).unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert!(Protocol::create(&root, 2, deadline).is_err());
    // Dropping an admission on a callback/spawn error still unregisters it.
    {
        let _admission = protocol.admit(Role::Product).unwrap();
    }
    assert_eq!(protocol.snapshot().unwrap().total(), 0);
}

#[test]
fn missing_or_extra_roles_and_expired_original_cutoff_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let protocol = Protocol::create(
        &temp.path().join("control"),
        2,
        SystemTime::now() + Duration::from_secs(3),
    )
    .unwrap();
    let native = protocol.admit(Role::Native).unwrap();
    assert_eq!(
        protocol
            .wait_roles(1, 1, Instant::now())
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::TimedOut
    );
    let product = protocol.admit(Role::Product).unwrap();
    assert!(protocol.admit(Role::Native).is_err());
    assert_eq!(protocol.snapshot().unwrap().total(), 2);
    assert_eq!(protocol.snapshot().unwrap().maximum, 3);
    assert!(
        protocol
            .wait_roles(1, 1, Instant::now() + Duration::from_secs(1))
            .is_err()
    );
    product.finish().unwrap();
    native.finish().unwrap();
    let expired = Protocol::create(
        &temp.path().join("expired"),
        2,
        SystemTime::now() - Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(
        expired.wait_gate(Role::Native).unwrap_err().kind(),
        std::io::ErrorKind::TimedOut
    );
    assert_eq!(
        expired
            .wait_roles(0, 0, Instant::now() + Duration::from_secs(1))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::TimedOut
    );
    expired.release_all().unwrap();
}

#[test]
fn uncertain_or_unsettled_roots_never_donate_or_admit_twice() {
    let [first, second] = compiler_pool::pair(1, false).unwrap();
    let materialize = |owner| {
        cargo(Path::new("."))
            .arg("check")
            .compiler_owner(owner)
            .materialize()
    };
    materialize(first.clone()).unwrap();
    assert!(materialize(first.clone()).is_err());
    assert!(materialize(second.clone()).is_err());
    first.settle(WriterSettlement::Unknown).unwrap();
    assert!(materialize(second.clone()).is_err());
    first.settle(WriterSettlement::Settled).unwrap();
    materialize(second.clone()).unwrap();
    second.settle(WriterSettlement::NotStarted).unwrap();
    assert!(second.settle(WriterSettlement::Settled).is_err());
    let owners = compiler_pool::pair(2, true).unwrap();
    assert!(
        cargo(Path::new("."))
            .arg("build")
            .arg("--jobs=2")
            .compiler_owner(owners[0].clone())
            .materialize()
            .is_err()
    );
    owners[0].settle(WriterSettlement::NotStarted).unwrap();
    owners[1].settle(WriterSettlement::NotStarted).unwrap();
}
