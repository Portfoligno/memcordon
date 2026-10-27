use super::*;
use crate::linux::private_init_diagnostic::Phase;
use std::time::Duration;

#[test]
fn progress_prefix_never_substitutes_for_authenticated_startup() {
    let (provider, init) = private_namespace_startup_channel().unwrap();
    init.progress(Phase::ChildClosureEntered);
    init.progress(Phase::RootPublishBefore);
    drop(init);
    let error = provider
        .receive(
            std::process::id() as libc::pid_t,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap_err();
    assert!(
        error.starts_with("MCSEALED-PRIVATE-INIT: startup channel EOF"),
        "{error}"
    );
    assert!(error.contains("phase=ChildClosureEntered"));
    assert!(error.contains("phase=RootPublishBefore"));
}
