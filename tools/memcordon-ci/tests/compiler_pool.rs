#![cfg(unix)]
use memcordon_ci::{command::CommandSpec, compiler_pool, work_outcome::WriterSettlement};
use std::{
    path::Path,
    time::{Duration, Instant},
};

fn graph(root: &Path, members: usize, wrapper: &Path) {
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
        let first = base.join("product");
        let second = base.join("native");
        graph(&first, 1, &wrapper);
        graph(&second, 8, &wrapper);
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
        std::fs::write(wrapper.with_extension("count"), "0").unwrap();
        std::fs::write(wrapper.with_extension("events"), "").unwrap();
        match std::fs::remove_file(wrapper.with_extension("settled")) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("reset settled-owner observation: {error}"),
        }
        let owners = compiler_pool::pair(budget, budget > 1).unwrap();
        let cutoff = Instant::now() + Duration::from_secs(30);
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
            assert!(product.run_owned().into_result().is_ok());
            assert!(native.run_owned().into_result().is_ok());
        } else {
            std::thread::scope(|scope| {
                let first = scope.spawn(|| {
                    let result = product.run_owned();
                    assert!(result.writers().permits_reading());
                    std::fs::write(wrapper.with_extension("settled"), "settled").unwrap();
                    result
                });
                let second = scope.spawn(|| native.run_owned());
                assert!(first.join().unwrap().into_result().is_ok());
                assert!(second.join().unwrap().into_result().is_ok());
            });
        }
        assert_eq!(
            std::fs::read_to_string(wrapper.with_extension("count")).unwrap(),
            "0"
        );
        let events = std::fs::read_to_string(wrapper.with_extension("events")).unwrap();
        let maximum = events
            .lines()
            .map(|line| {
                line.split_whitespace()
                    .nth(2)
                    .unwrap()
                    .parse::<usize>()
                    .unwrap()
            })
            .max()
            .unwrap();
        assert!(
            maximum <= budget,
            "budget={budget} max={maximum} events={events}"
        );
        assert_eq!(
            maximum, budget,
            "real Cargo did not use shared capacity: {events}"
        );
        if budget > 1 {
            let after = events
                .lines()
                .filter(|line| line.split_whitespace().nth(3) == Some("true"))
                .map(|line| {
                    line.split_whitespace()
                        .nth(2)
                        .unwrap()
                        .parse::<usize>()
                        .unwrap()
                })
                .max()
                .unwrap();
            assert_eq!(
                after, budget,
                "remaining native Cargo did not borrow settled product capacity: {events}"
            );
        }
    }
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
