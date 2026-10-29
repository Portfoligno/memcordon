//! Internal network-launcher measurements; these are never ordinary probe replies.

use memcordon_core::native_readiness::ReadinessObservation;

pub(crate) fn complete(observation: &ReadinessObservation) -> bool {
    observation.format == "memcordon.network-launcher-readiness"
        && observation.revision == 1
        && observation.probe_role == "private-network-launcher"
        && observation.workload_profile_probe_verified
        && observation.version == env!("CARGO_PKG_VERSION")
        && observation.mechanism == "linux-pid-namespace-cgroup-v2"
        && observation.provider_identity == "memcordon-sealed-agent-v2"
        && observation.control_service_identity == "memcordon-sealed-agent.service:v2"
        && observation.launcher_service_identity == "memcordon-sealed-network-launcher.service:v2"
        && observation.native_facts_complete()
}

#[cfg(all(unix, any(test, feature = "private-tcp")))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Family {
    Unix,
    Ipv4,
    RouteNetlink,
    Ipv6,
}

#[cfg(all(unix, any(test, feature = "private-tcp")))]
pub(crate) fn validate_creation(
    family: Family,
    result: Result<(), i32>,
    denied_errno: i32,
) -> Result<(), String> {
    match (family, result) {
        (Family::Ipv6, Err(errno)) if errno == denied_errno => Ok(()),
        (Family::Unix | Family::Ipv4 | Family::RouteNetlink, Ok(())) => Ok(()),
        (_, result) => Err(format!(
            "network launcher family probe differs: {family:?}: {result:?}"
        )),
    }
}
