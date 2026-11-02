//! Fixture clock/argv adapter; native registry ownership belongs to platform.
pub(super) use memcordon_platform::test_support::windows_winsock_registry::{
    Mapping, OwnedKey, uninherited_self_check,
};

pub(super) fn self_check() -> std::io::Result<i32> {
    memcordon_platform::test_support::windows_winsock_registry::self_check(
        |deadline| {
            let (work_cutoff_qpc, qpc_frequency) =
                memcordon_platform::test_support::windows_native_work_cutoff(deadline)?;
            let clock = super::descriptor::ControlClock {
                revision: 1,
                work_cutoff_qpc,
                qpc_frequency,
            };
            let mut command = super::child_command()?;
            command
                .arg("winsock-registry-uninherited-self-check")
                .arg(serde_json::to_string(&clock).map_err(std::io::Error::other)?);
            Ok(command)
        },
        super::settle_peer_failure,
    )
}
