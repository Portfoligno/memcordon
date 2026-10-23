#![cfg(all(target_os = "macos", feature = "test-support"))]

use memcordon_platform::test_support::{
    OuterTestBoundary, macos_owned_child_identity, macos_owned_compile_sample,
};

#[test]
#[ignore = "owned subprocess fixture invoked only by the parent test"]
fn held_compiler_fixture() {
    std::thread::sleep(std::time::Duration::from_secs(5));
}

#[test]
fn samples_only_the_original_admitted_native_group_and_birth() {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", "held_compiler_fixture", "--ignored"]);
    OuterTestBoundary::configure(&mut command).unwrap();
    let mut child = command.spawn().unwrap();
    let boundary = OuterTestBoundary::after_spawn(&child).unwrap();
    let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let root = macos_owned_child_identity(&child).unwrap();
        let sample = macos_owned_compile_sample(root).unwrap();
        assert_eq!(sample["root_pid"], root.pid);
        assert!(
            sample["processes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|member| member["pid"] == root.pid
                    && member["observation"]["Ok"]["resident_bytes"].is_number())
        );
        let mut foreign = root;
        foreign.birth += 1;
        assert!(macos_owned_compile_sample(foreign).is_err());
    }));
    boundary.terminate_and_reap(&mut child).unwrap();
    observed.unwrap()
}
