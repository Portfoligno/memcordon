#[path = "../../../tools/memcordon-ci/src/linux_request_arguments.rs"]
mod producer;
#[path = "../../../tools/memcordon-ci/src/windows_current_arguments.rs"]
mod windows_producer;

#[test]
fn installed_windows_producers_use_standalone_sealed() {
    use std::path::Path;
    let directory = tempfile::tempdir().unwrap();
    let request = directory.path().join("request.json");
    std::fs::write(&request, br#"{"format":"memcordon.workload-request","revision":1,"runtime":{"kind":"windows-sealed","profile":"windows-sealed-current-token-v1"},"requirements":[]}"#).unwrap();
    let paths = windows_producer::Paths {
        request: &request,
        report: Path::new("result.json"),
        fixture: Path::new("fixture.exe"),
    };
    let observation = Path::new("observations");
    let terminal = Path::new("terminal.json");
    let preallocation = windows_producer::preallocation(&paths, observation);
    for args in [
        &preallocation,
        &windows_producer::held(&paths, observation, terminal, None),
        &windows_producer::held(&paths, observation, terminal, Some(Path::new("pid"))),
        &windows_producer::service_restart(&paths, terminal),
    ] {
        assert_eq!(args.iter().filter(|arg| *arg == "--sealed").count(), 1);
        assert!(!args.iter().any(|arg| arg == "--boundary"));
        #[cfg(windows)]
        assert!(memcordon::invocation::route(args).is_ok());
    }
    assert!(
        memcordon::invocation::route(&preallocation).is_ok(),
        "{:?}",
        memcordon::invocation::route(&preallocation)
    );
    let mut duplicate = preallocation.clone();
    duplicate.insert(0, "--sealed".into());
    assert!(memcordon::invocation::route(&duplicate).is_err());
}

#[test]
fn original_request_lifetime_uses_public_wait_for_contract() {
    for lifetime in [
        memcordon_core::Lifetime::Command,
        memcordon_core::Lifetime::Workload,
    ] {
        let mut arguments = vec!["+1GiB".into(), "+60s".into()];
        arguments.extend(producer::wait_arguments(lifetime));
        arguments.extend(["--".into(), "program".into()]);
        let memcordon::invocation::Invocation::Execute(parsed) =
            memcordon::invocation::route(&arguments).unwrap()
        else {
            panic!("execution required")
        };
        assert_eq!(parsed.policy.wait_for, lifetime);
        arguments[2] = "--lifetime".into();
        assert!(memcordon::invocation::route(&arguments).is_err());
    }
}
