use std::ffi::OsStr;
use std::process::Command;

#[test]
fn subprocesses_expose_exactly_one_selected_cargo_capability_interface() {
    for inherit_crates_io_token in [false, true] {
        let mut spec = memcordon_ci::command::CommandSpec::new(
            "memcordon-ci-command-policy-fixture",
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
            std::time::Duration::from_secs(1),
        );
        if inherit_crates_io_token {
            spec = spec.inherit_crates_io_registry_token();
        }
        let mut command = Command::new("memcordon-ci-command-policy-fixture");
        spec.apply_environment(&mut command);
        let environment_state = |name: &str| {
            command
                .get_envs()
                .find(|(key, _)| *key == OsStr::new(name))
                .map(|(_, value)| value)
        };
        assert_eq!(
            environment_state("CARGO_REGISTRY_TOKEN"),
            Some(None),
            "the legacy singular-token interface must always be removed"
        );
        assert_eq!(
            environment_state("CARGO_REGISTRIES_CRATES_IO_TOKEN"),
            if inherit_crates_io_token {
                None
            } else {
                Some(None)
            },
            "the standard crates.io variable must follow the selected capability only"
        );
    }
}
