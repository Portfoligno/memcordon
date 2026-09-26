//! Final-public release-case contract. This is deliberately not an H1 probe or
//! candidate-M0 case owner. Raw public frames alone cannot construct a result:
//! authenticated V2 transport and protected native settlement are still needed.

use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{
    PrivateReleaseStageV1, REQUIRED_PRIVATE_RELEASE_SELECTORS_V1, private_release_case_key_v1,
};
use memcordon_core::workload_contract::WorkloadContractV2;
use memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2;
use memcordon_core::workload_plan_v2::PrivatePlanReceiptV2;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::MetadataExt;
use std::time::Duration;

use crate::package::VerifiedInstalledPrivateAuthorityLease;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExpectedFinalPublicOutcomeV1 {
    PublicGrantRejected,
    TargetCompleted,
    AuthorizationUncertainRetired,
    FrontendLostRetired,
    GuardianLostRetired,
    RetirementFailureBlockedReuse,
}

impl ExpectedFinalPublicOutcomeV1 {
    pub(crate) fn requires_allocated_attempt(self) -> bool {
        self != Self::PublicGrantRejected
    }
}

/// A closed catalogue identity. Its key is stage-separated from the same
/// candidate selector and challenge, so candidate evidence cannot fill a
/// final-public slot.
pub(crate) struct FinalPublicCaseSpecV1 {
    selector: &'static str,
    challenge: [u8; 32],
    expected: ExpectedFinalPublicOutcomeV1,
}

impl FinalPublicCaseSpecV1 {
    pub(crate) fn new(selector: &str, challenge: [u8; 32]) -> Result<Self, String> {
        let selector = REQUIRED_PRIVATE_RELEASE_SELECTORS_V1
            .into_iter()
            .find(|fixed| *fixed == selector)
            .ok_or("MCSEALED-PRIVATE-RELEASE: final-public selector differs")?;
        if challenge == [0; 32] {
            return Err("MCSEALED-PRIVATE-RELEASE: final-public challenge is zero".into());
        }
        let expected = match selector {
            "private_tcp::wrong_grant_profile_and_port_rejected" => {
                ExpectedFinalPublicOutcomeV1::PublicGrantRejected
            }
            "private_tcp::authorization_uncertainty_retired" => {
                ExpectedFinalPublicOutcomeV1::AuthorizationUncertainRetired
            }
            "private_tcp::frontend_loss_retired" => {
                ExpectedFinalPublicOutcomeV1::FrontendLostRetired
            }
            "private_tcp::guardian_loss_retired" => {
                ExpectedFinalPublicOutcomeV1::GuardianLostRetired
            }
            "private_tcp::retirement_failure_blocks_reuse" => {
                ExpectedFinalPublicOutcomeV1::RetirementFailureBlockedReuse
            }
            _ => ExpectedFinalPublicOutcomeV1::TargetCompleted,
        };
        Ok(Self {
            selector,
            challenge,
            expected,
        })
    }

    pub(crate) fn selector(&self) -> &'static str {
        self.selector
    }

    pub(crate) fn expected(&self) -> ExpectedFinalPublicOutcomeV1 {
        self.expected
    }

    pub(crate) fn result_key(&self) -> DiagnosticSha256 {
        private_release_case_key_v1(
            PrivateReleaseStageV1::FinalPublic,
            self.selector,
            &self.challenge,
        )
        .expect("closed selector and nonzero challenge remain valid")
    }

    /// This validates the exact public preallocation result, not a native
    /// terminal. In particular an unavailable Q/H1 or a malformed request is
    /// not a proof that a live V2 grant rejected the intended wrong-grant case.
    pub(crate) fn validate_public_grant_rejection(
        &self,
        rejection: &crate::rejection::RejectionV1,
    ) -> Result<(), String> {
        if self.expected != ExpectedFinalPublicOutcomeV1::PublicGrantRejected
            || rejection.code != "MCSEALED-PRIVATE-PUBLIC-GRANT-REJECTED"
            || rejection.target_created
            || rejection.target_released
        {
            return Err("MCSEALED-PRIVATE-RELEASE: exact public grant rejection absent".into());
        }
        rejection.validate()
    }
}

/// A current, authenticated public V2 plan joined to the move-only installed
/// M1/Q/H1 lease. The plan is fetched from the verified provider socket here;
/// an arbitrary receipt parsed from JSON cannot construct this authority.
/// It is a snapshot, not permission to replay or publish a physical case.
#[allow(dead_code)] // Release-Q provenance and physical final-case runners remain closed.
pub(crate) struct FinalPublicPlanAuthorityV1 {
    case: FinalPublicCaseSpecV1,
    installed: VerifiedInstalledPrivateAuthorityLease,
    contract: WorkloadContractV2,
    plan: PrivatePlanReceiptV2,
    raw_plan_response: Vec<u8>,
    observed_grant_bytes: Vec<u8>,
}

#[allow(dead_code)]
impl FinalPublicPlanAuthorityV1 {
    pub(crate) fn acquire(
        case: FinalPublicCaseSpecV1,
        installed: VerifiedInstalledPrivateAuthorityLease,
        contract: WorkloadContractV2,
    ) -> Result<Self, String> {
        if !case.expected().requires_allocated_attempt() {
            return Err(
                "MCSEALED-PRIVATE-RELEASE: wrong-grant case cannot acquire a positive plan".into(),
            );
        }
        let (plan, raw_plan_response) =
            match memcordon_platform::private_plan_exchange_v2(&contract)? {
                memcordon_platform::PrivatePlanExchangeV2::Available {
                    receipt,
                    raw_response,
                } => (receipt, raw_response),
                memcordon_platform::PrivatePlanExchangeV2::Rejected { evidence, .. } => {
                    return Err(format!(
                        "MCSEALED-PRIVATE-RELEASE: public V2 plan rejected [{}]",
                        evidence.code
                    ));
                }
            };
        validate_plan_binding(&plan, &installed)?;
        // The public plan is a snapshot. Independently read the exact active
        // policy after it, require the same registry digest, and resolve the
        // current caller/grant. The policy lease is released before launch;
        // the public service repeats admission at the release boundary.
        let policy = crate::policy_registry::native::Lease::acquire()?;
        let activation = policy
            .read_v2()?
            .ok_or("MCSEALED-PRIVATE-RELEASE: active V2 grant registry absent")?;
        if activation.registry_digest != plan.registry_digest {
            return Err("MCSEALED-PRIVATE-RELEASE: public plan policy snapshot changed".into());
        }
        // SAFETY: getuid has no pointer arguments and reports this public
        // client's real UID, also used by the provider's peer credential.
        let uid = unsafe { libc::getuid() };
        let grant = memcordon_core::workload_registry_v2::resolve_v2(
            &activation.registry,
            &activation.epoch,
            &contract,
            &memcordon_core::workload_registry::CallerSelector::Linux { uid },
            memcordon_core::workload_registry_v2::ProfileKindV2::LinuxTcp4PrivateV1,
            installed.qualification_digest(),
        )
        .map_err(|rejection| {
            format!(
                "MCSEALED-PRIVATE-RELEASE: current V2 grant changed: {:?}",
                rejection.code
            )
        })?;
        let observed_grant_bytes = serde_json::to_vec(grant).map_err(|error| error.to_string())?;
        Ok(Self {
            case,
            installed,
            contract,
            plan,
            raw_plan_response,
            observed_grant_bytes,
        })
    }

    pub(crate) fn case(&self) -> &FinalPublicCaseSpecV1 {
        &self.case
    }

    pub(crate) fn contract(&self) -> &WorkloadContractV2 {
        &self.contract
    }

    pub(crate) fn plan(&self) -> &PrivatePlanReceiptV2 {
        &self.plan
    }

    pub(crate) fn raw_plan_response(&self) -> &[u8] {
        &self.raw_plan_response
    }

    pub(crate) fn observed_grant_bytes(&self) -> &[u8] {
        &self.observed_grant_bytes
    }

    pub(crate) fn installed(&self) -> &VerifiedInstalledPrivateAuthorityLease {
        &self.installed
    }

    /// Invoke the actual public V2 client while retaining the M1/Q/H1 package
    /// generation lock. This is not a selector pass: only a future fixed
    /// fixture runner can interpret the observed workload and cleanup.
    pub(crate) fn execute_actual_public_v2(
        self,
        policy: &memcordon_core::Policy,
        command: &memcordon_core::CommandSpec,
        context: memcordon_platform::AttemptContext,
    ) -> FinalPublicExecutionV1 {
        let result =
            memcordon_platform::execute_private_v2(policy, command, &self.contract, context);
        match result {
            Ok(memcordon_platform::PrivateServiceResultV2::Complete(terminal)) => {
                let report = terminal.report();
                if report.source_commit != self.installed.source_commit()
                    || report.runtime_manifest_sha256 != *self.installed.runtime_manifest_sha256()
                    || report.installed_qualification_sha256
                        != *self.installed.qualification_digest()
                    || report.native_abi != self.plan.native_abi
                {
                    return FinalPublicExecutionV1::TransportFailure {
                        authority: self,
                        error: memcordon_platform::PrivateLaunchErrorV2::AfterSubmission(
                            memcordon_platform::PrivateResponseFailureV2 {
                                detail: "final-public terminal differs from held M1/Q/H1".into(),
                                raw_response: Some(terminal.raw_response().to_vec()),
                            },
                        ),
                    };
                }
                FinalPublicExecutionV1::AuthenticatedTerminal {
                    authority: self,
                    terminal,
                }
            }
            Ok(result) => FinalPublicExecutionV1::Nonterminal {
                authority: self,
                result,
            },
            Err(error) => FinalPublicExecutionV1::TransportFailure {
                authority: self,
                error,
            },
        }
    }
}

/// Transport/denial and authenticated terminal are deliberately separate.
/// None alone proves that a catalogue fixture behaved as expected or that a
/// five-attachment final-public result may be published.
#[allow(dead_code)] // Fixed physical selectors remain pending Q/H1 provenance.
pub(crate) enum FinalPublicExecutionV1 {
    AuthenticatedTerminal {
        authority: FinalPublicPlanAuthorityV1,
        terminal: Box<memcordon_platform::PrivateAuthenticatedTerminalV2>,
    },
    Nonterminal {
        authority: FinalPublicPlanAuthorityV1,
        result: memcordon_platform::PrivateServiceResultV2,
    },
    TransportFailure {
        authority: FinalPublicPlanAuthorityV1,
        error: memcordon_platform::PrivateLaunchErrorV2,
    },
}

/// An exact denial observed on the authenticated public provider channel,
/// under a held qualified M1/Q/H1 lease. This remains an observation only:
/// the caller must independently prove that the supplied contract is the
/// catalogue's wrong-profile/port mutant before publishing a case result.
#[allow(dead_code)] // Physical final-public case producer is not yet available.
pub(crate) struct FinalPublicGrantRejectionV1 {
    case: FinalPublicCaseSpecV1,
    installed: VerifiedInstalledPrivateAuthorityLease,
    contract: WorkloadContractV2,
    evidence: Box<memcordon_core::ProviderRejectionEvidence>,
    raw_response: Vec<u8>,
}

#[allow(dead_code)]
impl FinalPublicGrantRejectionV1 {
    pub(crate) fn observe(
        case: FinalPublicCaseSpecV1,
        installed: VerifiedInstalledPrivateAuthorityLease,
        contract: WorkloadContractV2,
    ) -> Result<Self, String> {
        if case.expected() != ExpectedFinalPublicOutcomeV1::PublicGrantRejected {
            return Err("MCSEALED-PRIVATE-RELEASE: not a wrong-grant selector".into());
        }
        let (evidence, raw_response) =
            match memcordon_platform::private_plan_exchange_v2(&contract)? {
                memcordon_platform::PrivatePlanExchangeV2::Rejected {
                    evidence,
                    raw_response,
                } => (evidence, raw_response),
                memcordon_platform::PrivatePlanExchangeV2::Available { .. } => {
                    return Err("MCSEALED-PRIVATE-RELEASE: wrong grant was admitted".into());
                }
            };
        if evidence.code != "MCSEALED-PRIVATE-PUBLIC-GRANT-REJECTED"
            || evidence.target_created
            || evidence.target_released
        {
            return Err("MCSEALED-PRIVATE-RELEASE: exact public V2 grant denial absent".into());
        }
        Ok(Self {
            case,
            installed,
            contract,
            evidence,
            raw_response,
        })
    }

    pub(crate) fn raw_response(&self) -> &[u8] {
        &self.raw_response
    }

    pub(crate) fn evidence(&self) -> &memcordon_core::ProviderRejectionEvidence {
        &self.evidence
    }

    pub(crate) fn case(&self) -> &FinalPublicCaseSpecV1 {
        &self.case
    }

    pub(crate) fn contract(&self) -> &WorkloadContractV2 {
        &self.contract
    }

    pub(crate) fn installed(&self) -> &VerifiedInstalledPrivateAuthorityLease {
        &self.installed
    }
}

fn validate_plan_binding(
    plan: &PrivatePlanReceiptV2,
    installed: &VerifiedInstalledPrivateAuthorityLease,
) -> Result<(), String> {
    let expected_abi = match installed.filter_abi() {
        super::network_filter::NativeAbi::X86_64 => QualifiedNativeAbiV2::X86_64LinuxGnu,
        super::network_filter::NativeAbi::Aarch64 => QualifiedNativeAbiV2::Aarch64LinuxGnu,
    };
    if plan.runtime_manifest_sha256 != *installed.runtime_manifest_sha256()
        || plan.installed_qualification_sha256 != *installed.qualification_digest()
        || plan.generation_digest != *installed.generation_digest()
        || plan.source_commit != installed.source_commit()
        || plan.native_abi != expected_abi
    {
        return Err("MCSEALED-PRIVATE-RELEASE: public plan differs from held M1/Q/H1".into());
    }
    Ok(())
}

/// Exact internal workload for the final-public native TCP selector. It
/// performs real loopback bind/listen/connect/accept and challenge exchange
/// inside the target's network namespace. It is not callable from H1's probe
/// dispatcher, and its self-report is never sufficient to complete a case.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalPublicTcpFixtureObservationV1 {
    pub(crate) schema_version: u8,
    pub(crate) network_namespace_inode: u64,
    pub(crate) listener_port: u16,
    pub(crate) client_port: u16,
    pub(crate) challenge_sha256: DiagnosticSha256,
    pub(crate) response_sha256: DiagnosticSha256,
    pub(crate) observed_response_bytes: [u8; 32],
}

pub(crate) fn run_final_public_tcp_fixture(
    challenge: [u8; 32],
    port: u16,
    dual: bool,
    mut held: impl FnMut(&FinalPublicTcpFixtureObservationV1) -> Result<(), String>,
) -> Result<FinalPublicTcpFixtureObservationV1, String> {
    let mut response_bytes = Vec::with_capacity(64);
    response_bytes.extend_from_slice(b"memcordon-final-public-tcp-fixture-v1\0");
    response_bytes.extend_from_slice(&challenge);
    response_bytes.extend_from_slice(&port.to_be_bytes());
    run_final_public_tcp_fixture_with_response(
        challenge,
        port,
        dual,
        memcordon_core::workload_codec::hash_bytes(&response_bytes),
        held,
    )
}

#[derive(Serialize)]
pub(crate) struct FinalPublicTopologyFixtureObservationV1 {
    pub(crate) schema_version: u8,
    pub(crate) tcp: FinalPublicTcpFixtureObservationV1,
    pub(crate) namespace_reentry_errno: Option<i32>,
    pub(crate) namespace_creation_errno: Option<i32>,
    pub(crate) namespace_operand: Option<FinalPublicNamespaceOperandV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalPublicNamespaceOperandV1 {
    pub(crate) descriptor: i32,
    pub(crate) device: u64,
    pub(crate) inode: u64,
}

pub(crate) fn run_final_public_topology_fixture(
    selector: &str,
    challenge: [u8; 32],
    port: u16,
    mut held: impl FnMut(&FinalPublicTopologyFixtureObservationV1) -> Result<(), String>,
) -> Result<FinalPublicTopologyFixtureObservationV1, String> {
    let denials = match selector {
        super::private_release_case::TOPOLOGY_SELECTOR => None,
        super::private_release_denial::NAMESPACE_SELECTOR => {
            Some(super::private_release_denial::observe_namespace_denials_held()?)
        }
        _ => return Err("public topology selector outside reviewed protocol".into()),
    };
    let response = memcordon_core::private_release_case_v1::public_fixture_expected_response_v1(
        selector, &challenge, port,
    )?;
    let response: [u8; 32] = response
        .try_into()
        .map_err(|_| "public topology response width differs")?;
    let namespace_reentry_errno = denials.as_ref().map(|(bytes, _)| {
        i32::from_le_bytes(bytes[..4].try_into().expect("fixed native errno width"))
    });
    let namespace_creation_errno = denials.as_ref().map(|(bytes, _)| {
        i32::from_le_bytes(bytes[4..].try_into().expect("fixed native errno width"))
    });
    let namespace_operand = denials
        .as_ref()
        .map(|(_, namespace)| {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::MetadataExt;
            let metadata = namespace.metadata().map_err(|error| error.to_string())?;
            Ok::<_, String>(FinalPublicNamespaceOperandV1 {
                descriptor: namespace.as_raw_fd(),
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        })
        .transpose()?;
    let tcp = run_final_public_tcp_fixture_with_response(
        challenge,
        port,
        false,
        DiagnosticSha256::from_bytes(response),
        |tcp| {
            held(&FinalPublicTopologyFixtureObservationV1 {
                schema_version: 3,
                tcp: tcp.clone(),
                namespace_reentry_errno,
                namespace_creation_errno,
                namespace_operand: namespace_operand.clone(),
            })
        },
    )?;
    Ok(FinalPublicTopologyFixtureObservationV1 {
        schema_version: 3,
        tcp,
        namespace_reentry_errno,
        namespace_creation_errno,
        namespace_operand,
    })
}

fn run_final_public_tcp_fixture_with_response(
    challenge: [u8; 32],
    port: u16,
    dual: bool,
    response_sha256: DiagnosticSha256,
    mut held: impl FnMut(&FinalPublicTcpFixtureObservationV1) -> Result<(), String>,
) -> Result<FinalPublicTcpFixtureObservationV1, String> {
    if challenge == [0; 32] || port == 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: zero TCP fixture challenge".into());
    }
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: TCP bind: {error}"))?;
    let listener_addr = listener.local_addr().map_err(|error| error.to_string())?;
    if !listener_addr.ip().is_ipv4()
        || !listener_addr.ip().is_loopback()
        || listener_addr.port() == 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: TCP listener address differs".into());
    }
    match TcpListener::bind(listener_addr) {
        Err(error) if error.raw_os_error() == Some(libc::EADDRINUSE) => {}
        Err(error) => {
            return Err(format!(
                "MCSEALED-PRIVATE-RELEASE: occupied-port control: {error}"
            ));
        }
        Ok(_) => return Err("MCSEALED-PRIVATE-RELEASE: occupied-port control was admitted".into()),
    }
    let free_control = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: free-port control: {error}"))?;
    if free_control
        .local_addr()
        .map_err(|error| error.to_string())?
        .port()
        == listener_addr.port()
    {
        return Err("MCSEALED-PRIVATE-RELEASE: free-port control aliases occupied listener".into());
    }
    let mut client = TcpStream::connect(listener_addr)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: TCP connect: {error}"))?;
    let (mut accepted, peer_addr) = listener
        .accept()
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: TCP accept: {error}"))?;
    let client_addr = client.local_addr().map_err(|error| error.to_string())?;
    if peer_addr != client_addr
        || accepted.local_addr().map_err(|error| error.to_string())? != listener_addr
    {
        return Err("MCSEALED-PRIVATE-RELEASE: TCP endpoint readback differs".into());
    }
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    accepted
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    client
        .write_all(&challenge)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: TCP challenge send: {error}"))?;
    let mut received = [0_u8; 32];
    accepted
        .read_exact(&mut received)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: TCP challenge read: {error}"))?;
    if received != challenge {
        return Err("MCSEALED-PRIVATE-RELEASE: TCP challenge differs".into());
    }
    accepted
        .write_all(response_sha256.bytes())
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: TCP response send: {error}"))?;
    let mut observed_response = [0_u8; 32];
    client
        .read_exact(&mut observed_response)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: TCP response read: {error}"))?;
    if observed_response != *response_sha256.bytes() {
        return Err("MCSEALED-PRIVATE-RELEASE: TCP response differs".into());
    }
    let network_namespace_inode = std::fs::metadata("/proc/self/ns/net")
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: netns readback: {error}"))?
        .ino();
    if network_namespace_inode == 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: netns identity is zero".into());
    }
    let mut observed = FinalPublicTcpFixtureObservationV1 {
        schema_version: 2,
        network_namespace_inode,
        listener_port: listener_addr.port(),
        client_port: client_addr.port(),
        challenge_sha256: memcordon_core::workload_codec::hash_bytes(&challenge),
        response_sha256,
        observed_response_bytes: observed_response,
    };
    held(&observed)?;
    if dual {
        // The first ACK is supplied only after the root observer's overlap
        // sample. This second real exchange can be scheduled after R1 while
        // retaining the second attempt's original listener and connection.
        client
            .write_all(&challenge)
            .map_err(|error| error.to_string())?;
        accepted
            .read_exact(&mut received)
            .map_err(|error| error.to_string())?;
        if received != challenge {
            return Err("dual post-retirement challenge differs".into());
        }
        accepted
            .write_all(observed.response_sha256.bytes())
            .map_err(|error| error.to_string())?;
        client
            .read_exact(&mut observed_response)
            .map_err(|error| error.to_string())?;
        if observed_response != *observed.response_sha256.bytes() {
            return Err("dual post-retirement response differs".into());
        }
        observed.observed_response_bytes = observed_response;
        held(&observed)?;
    }
    Ok(observed)
}

/// A separate final-public attempt for the fixed same-namespace collision
/// selector. The first live listener must prevent an identical second bind;
/// this cannot be inferred from the TCP roundtrip attempt above.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalPublicPortCollisionObservationV1 {
    pub(crate) schema_version: u8,
    pub(crate) network_namespace_inode: u64,
    pub(crate) bound_port: u16,
    pub(crate) challenge_sha256: DiagnosticSha256,
    pub(crate) collision_os_code: i32,
    pub(crate) observed_response_bytes: [u8; 32],
}

pub(crate) fn run_final_public_port_collision_fixture(
    challenge: [u8; 32],
    port: u16,
    held: impl FnOnce(&FinalPublicPortCollisionObservationV1) -> Result<(), String>,
) -> Result<FinalPublicPortCollisionObservationV1, String> {
    if challenge == [0; 32] || port == 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: zero collision challenge".into());
    }
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: collision first bind: {error}"))?;
    let address = listener.local_addr().map_err(|error| error.to_string())?;
    if !address.ip().is_ipv4() || !address.ip().is_loopback() || address.port() == 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: collision address differs".into());
    }
    let collision = match TcpListener::bind(address) {
        Ok(_) => return Err("MCSEALED-PRIVATE-RELEASE: competing bind was admitted".into()),
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => error,
        Err(error) => {
            return Err(format!(
                "MCSEALED-PRIVATE-RELEASE: competing bind failed for another reason: {error}"
            ));
        }
    };
    let collision_os_code = collision
        .raw_os_error()
        .ok_or("MCSEALED-PRIVATE-RELEASE: collision errno absent")?;
    if collision_os_code != libc::EADDRINUSE {
        return Err("MCSEALED-PRIVATE-RELEASE: collision errno differs".into());
    }
    // Collision is not an invalid-operand control: the original occupied
    // listener remains usable for an exact bidirectional challenge exchange.
    let mut client = TcpStream::connect(address).map_err(|error| error.to_string())?;
    let (mut accepted, peer) = listener.accept().map_err(|error| error.to_string())?;
    if peer != client.local_addr().map_err(|error| error.to_string())? {
        return Err("collision peer differs".into());
    }
    for stream in [&client, &accepted] {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| error.to_string())?;
    }
    client
        .write_all(&challenge)
        .map_err(|error| error.to_string())?;
    let mut received = [0_u8; 32];
    accepted
        .read_exact(&mut received)
        .map_err(|error| error.to_string())?;
    if received != challenge {
        return Err("collision listener challenge differs".into());
    }
    accepted
        .write_all(&challenge)
        .map_err(|error| error.to_string())?;
    client
        .read_exact(&mut received)
        .map_err(|error| error.to_string())?;
    if received != challenge {
        return Err("collision original listener response differs".into());
    }
    // A valid free-port control is held alongside the occupied listener;
    // replay joins its actual checked port-zero bind and sampled socket FD.
    let free = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .map_err(|error| format!("collision free-bind control: {error}"))?;
    if free.local_addr().map_err(|error| error.to_string())?.port() == address.port() {
        return Err("collision free-bind control aliases occupied port".into());
    }
    let network_namespace_inode = std::fs::metadata("/proc/self/ns/net")
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: netns readback: {error}"))?
        .ino();
    if network_namespace_inode == 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: netns identity is zero".into());
    }
    let observed = FinalPublicPortCollisionObservationV1 {
        schema_version: 2,
        network_namespace_inode,
        bound_port: address.port(),
        challenge_sha256: memcordon_core::workload_codec::hash_bytes(&challenge),
        collision_os_code,
        observed_response_bytes: received,
    };
    held(&observed)?;
    Ok(observed)
}
