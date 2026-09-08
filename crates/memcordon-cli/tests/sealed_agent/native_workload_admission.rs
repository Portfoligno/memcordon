#![cfg(any(target_os = "linux", target_os = "windows"))]
use memcordon_core::workload_contract::*;
use memcordon_core::workload_evidence::*;
use memcordon_core::workload_registry::*;
use memcordon_core::{BoundedVec, DiagnosticSha256};
use std::num::{NonZeroU16, NonZeroU64};

#[cfg(target_os = "linux")]
use crate::policy_registry::native::Lease;
#[cfg(target_os = "windows")]
use crate::windows::policy_registry::Lease;

fn id(value: &str) -> LogicalId {
    LogicalId::new(value.to_owned()).unwrap()
}
fn profile() -> BaselineProfile {
    if cfg!(target_os = "windows") {
        BaselineProfile::WindowsHostNetworkExternal
    } else {
        BaselineProfile::LinuxUnixCreate
    }
}
fn caller() -> CallerSelector {
    #[cfg(target_os = "linux")]
    {
        CallerSelector::Linux {
            uid: unsafe { libc::geteuid() },
        }
    }
    #[cfg(target_os = "windows")]
    {
        CallerSelector::Windows {
            sid: memcordon_core::BoundedText::new(
                &crate::windows::token::process_envelope(std::process::id())
                    .unwrap()
                    .user_sid,
            )
            .unwrap(),
        }
    }
}
struct Restore(Option<PolicyRegistryV1>);
impl Restore {
    fn finish(mut self) {
        let registry = self
            .0
            .take()
            .expect("fixture registry restoration is pending");
        Lease::acquire()
            .and_then(|lease| lease.activate(registry, None))
            .expect("fixture must restore registry before qualification succeeds");
    }
}
impl Drop for Restore {
    fn drop(&mut self) {
        let Some(registry) = self.0.take() else {
            return;
        };
        let result = Lease::acquire().and_then(|lease| lease.activate(registry, None));
        if let Err(error) = result {
            eprintln!("native admission fixture registry restoration failed: {error}");
        }
    }
}
fn fixture() -> (WorkloadContractV1, Restore) {
    let discovery =
        memcordon_platform::workload_discovery().expect("installed qualified provider discovery");
    let lease = Lease::acquire().unwrap();
    let previous = lease.read().unwrap().expect("service activation exists");
    let restore = Restore(Some(previous.registry));
    let plan = DiagnosticSha256::from_bytes([17; 32]);
    let mut profiles = BoundedVec::default();
    profiles
        .try_push(ProfileDefinitionV1 {
            profile: profile(),
            reference: profile().reference(),
            enabled: true,
            qualification_digest: discovery.qualification_digest,
        })
        .unwrap();
    let mut callers = BoundedVec::default();
    callers.try_push(caller()).unwrap();
    let mut plans = BoundedVec::default();
    plans.try_push(plan.clone()).unwrap();
    let mut grants = BoundedVec::default();
    grants
        .try_push(PolicyGrantV1 {
            id: id("native-fixture"),
            revision: NonZeroU64::MIN,
            profile: profile().reference(),
            ceiling: profile().ceiling(),
            enabled: true,
            callers,
            approved_plans: plans,
        })
        .unwrap();
    let active = lease
        .activate(
            PolicyRegistryV1 {
                schema_version: ContractVersionOne::default(),
                profiles,
                grants,
                active_attempt_disposition: GrantChangeDisposition::DrainExisting,
            },
            None,
        )
        .unwrap();
    let contract = WorkloadContractV1 {
        schema_version: ContractVersionOne::default(),
        workload_plan_digest: plan.clone(),
        authorized_profile: profile().reference(),
        authorization: AuthorizationRef {
            grant_id: id("native-fixture"),
            grant_revision: NonZeroU64::MIN,
            approved_plan_digest: plan,
        },
        ceiling: profile().ceiling(),
        requirements: BoundedVec::default(),
        endpoints: BoundedVec::default(),
        expected_epoch: active.epoch,
    };
    (contract, restore)
}
fn execute(
    contract: &WorkloadContractV1,
    tcp_port: Option<u16>,
) -> (
    std::process::ExitStatus,
    memcordon_core::MemcordonReport,
    bool,
) {
    let directory = tempfile::TempDir::new().unwrap();
    let declaration = directory.path().join("contract.json");
    let report = directory.path().join("report.json");
    let marker = directory.path().join("marker");
    std::fs::write(&declaration, serde_json::to_vec(contract).unwrap()).unwrap();
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_memcordon"));
    command
        .arg("--sealed")
        .arg("--workload-contract")
        .arg(declaration)
        .arg("--report")
        .arg(&report)
        .arg("--")
        .arg(env!("CARGO_BIN_EXE_memcordon-test-fixture"));
    if let Some(port) = tcp_port {
        command.arg("tcp-client").arg(port.to_string());
    } else {
        command.arg("gate-marker");
    }
    command.arg(&marker);
    let status = command.status().unwrap();
    let report = serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
    (status, report, marker.exists())
}

#[test]
#[ignore = "requires an installed qualified provider and administrative registry access"]
fn native_exact_grant_epoch_and_terminal_checkpoint_are_enforced() {
    let (mut request, restore) = fixture();
    assert!(matches!(
        memcordon_platform::workload_plan(&request).unwrap(),
        WorkloadResolutionReportV1::Planned { .. }
    ));
    let (status, report, marker) = execute(&request, None);
    assert!(status.success() && marker);
    let attempt = report.attempts.last().unwrap();
    assert!(attempt.policy_enforcement.terminal_success());
    assert!(matches!(
        report.policy.effective.workload,
        WorkloadResolutionReportV1::Admitted { .. }
    ));
    let lease = Lease::acquire().unwrap();
    let active = lease.read().unwrap().unwrap();
    let next = lease.activate(active.registry, None).unwrap();
    drop(lease);
    let (status, report, marker) = execute(&request, None);
    assert!(!status.success() && !marker);
    assert!(matches!(
        report.policy.effective.workload,
        WorkloadResolutionReportV1::Rejected {
            rejection: AdmissionRejectionV1 {
                code: AdmissionCode::PolicyEpochStale,
                ..
            },
            ..
        }
    ));
    request.expected_epoch = next.epoch;
    request.authorization.grant_id = id("not-approved");
    assert!(matches!(
        memcordon_platform::workload_plan(&request).unwrap(),
        WorkloadResolutionReportV1::Rejected {
            rejection: AdmissionRejectionV1 {
                code: AdmissionCode::ProfileNotAuthorized,
                ..
            },
            ..
        }
    ));
    restore.finish();
    live_activation_preserves_drain_and_enforces_revoke();
}

struct LiveChild {
    process: std::process::Child,
    epoch: PolicyEpoch,
}
impl Drop for LiveChild {
    fn drop(&mut self) {
        if self.process.try_wait().ok().flatten().is_none() {
            let _ = self.process.kill();
        }
        let _ = self.process.wait();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            match Lease::acquire().and_then(|lease| lease.live_bindings()) {
                Ok(bindings)
                    if bindings
                        .iter()
                        .all(|(_, snapshot)| snapshot.request.expected_epoch != self.epoch) =>
                {
                    break;
                }
                _ if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(10))
                }
                _ => {
                    if std::thread::panicking() {
                        eprintln!("native fixture retirement observation failed during unwinding");
                    } else {
                        panic!("native fixture retirement observation failed");
                    }
                    break;
                }
            }
        }
    }
}

fn live_activation_preserves_drain_and_enforces_revoke() {
    for revoke in [false, true] {
        let (request, restore) = fixture();
        let directory = tempfile::TempDir::new().unwrap();
        let declaration = directory.path().join("contract.json");
        let report_path = directory.path().join("report.json");
        let ready = directory.path().join("ready");
        let finish = directory.path().join("finish");
        std::fs::write(&declaration, serde_json::to_vec(&request).unwrap()).unwrap();
        let process = std::process::Command::new(env!("CARGO_BIN_EXE_memcordon"))
            .args(["--sealed", "--workload-contract"])
            .arg(declaration)
            .arg("--report")
            .arg(&report_path)
            .arg("--")
            .arg(env!("CARGO_BIN_EXE_memcordon-test-fixture"))
            .arg("gate-wait")
            .arg(&ready)
            .arg(&finish)
            .spawn()
            .unwrap();
        let mut child = LiveChild {
            process,
            epoch: request.expected_epoch.clone(),
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while !ready.exists() {
            assert!(
                child.process.try_wait().unwrap().is_none(),
                "workload exited before authorization marker"
            );
            assert!(
                std::time::Instant::now() < deadline,
                "authorization marker deadline"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let lease = Lease::acquire().unwrap();
        let mut registry = lease.read().unwrap().unwrap().registry;
        registry.active_attempt_disposition = if revoke {
            GrantChangeDisposition::RevokeActive
        } else {
            GrantChangeDisposition::DrainExisting
        };
        let next = lease.activate(registry, None).unwrap();
        drop(lease);
        assert_ne!(next.epoch, request.expected_epoch);
        assert!(matches!(
            memcordon_platform::workload_plan(&request).unwrap(),
            WorkloadResolutionReportV1::Rejected {
                rejection: AdmissionRejectionV1 {
                    code: AdmissionCode::PolicyEpochStale,
                    ..
                },
                ..
            }
        ));
        if !revoke {
            assert!(
                child.process.try_wait().unwrap().is_none(),
                "drain must preserve the live admitted workload"
            );
            std::fs::write(&finish, b"finish\n").unwrap();
        }
        let status = loop {
            if let Some(status) = child.process.try_wait().unwrap() {
                break status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "policy retirement deadline"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(
            status.success(),
            !revoke,
            "revocation must terminate the waiting workload unsuccessfully"
        );
        let report: memcordon_core::MemcordonReport =
            serde_json::from_slice(&std::fs::read(report_path).unwrap()).unwrap();
        let attempt = report
            .attempts
            .last()
            .expect("live workload retained attempt");
        assert!(
            attempt.policy_enforcement.terminal_success(),
            "both drain and revoke must retire the exact admitted checkpoint"
        );
        assert!(
            attempt
                .restart_safety
                .is_safe_for(memcordon_core::BoundaryRequirement::Sealed)
        );
        drop(child);
        restore.finish();
    }
}

#[test]
#[ignore = "requires an installed qualified provider and administrative registry access"]
fn native_tcp_requirement_preserves_baseline_authority() {
    #[cfg(target_os = "windows")]
    use std::io::{Read, Write};
    let (mut request, restore) = fixture();
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut operations = BoundedVec::default();
    for operation in [
        TcpOperation::Create,
        TcpOperation::Connect,
        TcpOperation::StreamRead,
        TcpOperation::StreamWrite,
    ] {
        operations.try_push(operation).unwrap();
    }
    request
        .requirements
        .try_push(RequirementV1::Tcp {
            id: id("host-loopback-client"),
            family: IpFamily::V4,
            operations: TcpOperations::new(operations).unwrap(),
            scope: TcpScope::HostSharedLoopback,
            local_ports: LocalPortRequirement::KernelAssigned,
            peer: TcpPeerRequirement::ExactAddress {
                endpoint: TcpEndpoint::V4 {
                    address: [127, 0, 0, 1],
                    port: NonZeroU16::new(port).unwrap(),
                },
            },
        })
        .unwrap();
    #[cfg(target_os = "linux")]
    {
        let (status, report, marker) = execute(&request, None);
        assert!(!status.success() && !marker);
        let WorkloadResolutionReportV1::Rejected {
            binding: observed,
            rejection,
            ..
        } = &report.policy.effective.workload
        else {
            panic!("strict TCP must reject before authorization")
        };
        assert_eq!(
            observed,
            &RequestBindingV1::from_contract(&request).unwrap()
        );
        assert_eq!(rejection.code, AdmissionCode::PolicyIncompatible);
        assert_eq!(
            rejection.conflicts.as_slice(),
            &[AdmissionConflictV1 {
                requirement: Some(id("host-loopback-client")),
                code: AdmissionCode::PolicyIncompatible
            }]
        );
        assert_eq!(rejection.remaining_conflicts, 0);
        assert!(report.attempts.iter().all(|attempt| {
            !attempt.launch.target_released
                && attempt
                    .restart_safety
                    .is_safe_for(memcordon_core::BoundaryRequirement::Sealed)
        }));
    }
    #[cfg(target_os = "windows")]
    {
        for ceiling in [
            DirectSocketCeiling::NoNewInetSockets,
            DirectSocketCeiling::AttemptPrivateIpv4StackAllPorts,
        ] {
            let mut strict = request.clone();
            strict.ceiling.direct_socket_authority = ceiling;
            let (status, report, marker) = execute(&strict, None);
            assert!(
                !status.success() && !marker,
                "Windows baseline must reject stronger network ceilings before execution"
            );
            let WorkloadResolutionReportV1::Rejected {
                binding, rejection, ..
            } = &report.policy.effective.workload
            else {
                panic!("strong ceiling requires typed rejection")
            };
            assert_eq!(binding, &RequestBindingV1::from_contract(&strict).unwrap());
            assert_eq!(rejection.code, AdmissionCode::PolicyIncompatible);
            assert!(
                report
                    .attempts
                    .iter()
                    .all(|attempt| !attempt.launch.target_released)
            );
        }
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && std::time::Instant::now() < deadline =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(10))
                    }
                    Err(error) => panic!("TCP fixture accept failed: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            stream.write_all(&byte).unwrap();
        });
        let (status, report, marker) = execute(&request, Some(port));
        server.join().unwrap();
        assert!(status.success() && marker);
        assert!(
            report
                .attempts
                .last()
                .unwrap()
                .policy_enforcement
                .terminal_success()
        );
        assert!(matches!(
            report.policy.effective.workload,
            WorkloadResolutionReportV1::Admitted {
                effective: EffectiveWorkloadPolicyV1 {
                    restriction: BaselineRestrictionObservationV1::WindowsNetworkExternallyGoverned,
                    ..
                },
                ..
            }
        ));
    }
    restore.finish();
}
