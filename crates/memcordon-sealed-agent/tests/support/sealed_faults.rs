use std::ffi::CString;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use memcordon_sealed_agent::linux::launch::{
    FaultExecutionOutcome, FaultPlan, FaultPoint, FaultReady, RetirementOwner, TerminalFacts,
};
use memcordon_sealed_agent::rejection::RejectionPhaseV1;
use memcordon_sealed_agent::request::Lifetime;
use serde::Serialize;

use crate::support;

const FAULT_READY_BYTES: &[u8] = b"authorized\n";
const FRONTEND_READY_BYTES: &[u8] = b"frontend-ready\n";
const FAULT_EVIDENCE_PREFIX: &str = "MCSEALED-FAULT-EVIDENCE:";

pub struct CapturedFaultOutcome {
    pub outcome: FaultExecutionOutcome,
    pub marker_observed: bool,
    pub guardian_reaped: bool,
    pub final_record_absent: bool,
    pub final_cgroup_absent: bool,
}

#[derive(Serialize)]
struct FaultScenarioEvidence<'a> {
    schema_version: u32,
    selector: &'a str,
    attempt_id: String,
    rejection: &'a memcordon_sealed_agent::rejection::RejectionV1,
    retirement_owner: &'static str,
    marker_observed: bool,
    guardian_reaped: bool,
    final_record_absent: bool,
    final_cgroup_absent: bool,
}

struct FrontendProcess {
    child: Option<Child>,
    pid: libc::pid_t,
}

impl FrontendProcess {
    fn spawn(program: &Path, marker: &Path, mode: &str) -> Result<Self, String> {
        if !matches!(
            std::fs::symlink_metadata(marker),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        ) {
            return Err("MCSEALED-FRONTEND-SETUP: readiness marker already exists".to_owned());
        }
        let mut child = Command::new(program)
            .arg(mode)
            .arg(marker)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("MCSEALED-FRONTEND-SETUP: spawn failed: {error}"))?;
        let pid = match libc::pid_t::try_from(child.id()) {
            Ok(pid) if pid > 0 => pid,
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("MCSEALED-FRONTEND-SETUP: child pid was invalid".to_owned());
            }
        };
        let mut process = Self {
            child: Some(child),
            pid,
        };
        process.wait_until_ready(marker)?;
        Ok(process)
    }

    fn pid(&self) -> libc::pid_t {
        self.pid
    }

    fn wait_until_ready(&mut self, marker: &Path) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self
                .child
                .as_mut()
                .expect("frontend child must remain owned")
                .try_wait()
                .map_err(|error| format!("MCSEALED-FRONTEND-SETUP: wait failed: {error}"))?
            {
                return Err(format!(
                    "MCSEALED-FRONTEND-SETUP: helper exited before readiness: {status}"
                ));
            }
            match std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(marker)
            {
                Ok(mut ready) => {
                    let metadata = ready.metadata().map_err(|error| {
                        format!("MCSEALED-FRONTEND-SETUP: readiness metadata failed: {error}")
                    })?;
                    let length = usize::try_from(metadata.len()).map_err(|_| {
                        "MCSEALED-FRONTEND-SETUP: readiness length overflow".to_owned()
                    })?;
                    if !metadata.file_type().is_file() || length > FRONTEND_READY_BYTES.len() {
                        return Err("MCSEALED-FRONTEND-SETUP: invalid readiness marker".to_owned());
                    }
                    let mut observed = Vec::with_capacity(length);
                    ready.read_to_end(&mut observed).map_err(|error| {
                        format!("MCSEALED-FRONTEND-SETUP: readiness read failed: {error}")
                    })?;
                    if observed == FRONTEND_READY_BYTES {
                        if self
                            .child
                            .as_mut()
                            .expect("frontend child must remain owned")
                            .try_wait()
                            .map_err(|error| {
                                format!("MCSEALED-FRONTEND-SETUP: live check failed: {error}")
                            })?
                            .is_some()
                        {
                            return Err(
                                "MCSEALED-FRONTEND-SETUP: helper exited after readiness".to_owned()
                            );
                        }
                        return Ok(());
                    }
                    if length == FRONTEND_READY_BYTES.len() {
                        return Err("MCSEALED-FRONTEND-SETUP: readiness bytes differed".to_owned());
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "MCSEALED-FRONTEND-SETUP: readiness open failed: {error}"
                    ));
                }
            }
            if Instant::now() >= deadline {
                return Err("MCSEALED-FRONTEND-SETUP: readiness deadline expired".to_owned());
            }
            std::thread::yield_now();
        }
    }

    fn terminate_and_reap(mut self) -> Result<ExitStatus, String> {
        let mut child = self
            .child
            .take()
            .expect("frontend child must remain owned until retirement");
        let status = match child
            .try_wait()
            .map_err(|error| format!("MCSEALED-FRONTEND-REAP: status failed: {error}"))?
        {
            Some(status) => status,
            None => {
                child
                    .kill()
                    .map_err(|error| format!("MCSEALED-FRONTEND-REAP: SIGKILL failed: {error}"))?;
                child
                    .wait()
                    .map_err(|error| format!("MCSEALED-FRONTEND-REAP: wait failed: {error}"))?
            }
        };
        if status.signal() != Some(libc::SIGKILL) {
            return Err(format!(
                "MCSEALED-FRONTEND-REAP: expected SIGKILL, observed {status}"
            ));
        }
        Ok(status)
    }
}

impl Drop for FrontendProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            match child.try_wait() {
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
    }
}

pub fn assert_frontend_hold_lifecycle(program: &Path) {
    let temporary = tempfile::tempdir().expect("frontend lifecycle directory must exist");
    let marker = temporary.path().join("frontend-ready");
    let frontend = FrontendProcess::spawn(program, &marker, "frontend-hold")
        .expect("frontend helper must become exactly ready");
    assert_eq!(
        std::fs::read(&marker).expect("frontend marker must remain readable"),
        FRONTEND_READY_BYTES
    );
    frontend
        .terminate_and_reap()
        .expect("frontend helper must be SIGKILLed and reaped");
}

pub fn assert_frontend_hold_rejects_early_exit(program: &Path) {
    let temporary = tempfile::tempdir().expect("frontend early-exit directory must exist");
    let marker = temporary.path().join("frontend-ready");
    let error = match FrontendProcess::spawn(program, &marker, "frontend-exit-before-ready") {
        Ok(frontend) => {
            drop(frontend);
            panic!("frontend setup accepted a helper that exited before readiness");
        }
        Err(error) => error,
    };
    assert!(error.starts_with("MCSEALED-FRONTEND-SETUP: helper exited before readiness:"));
    assert!(!error.contains(FAULT_EVIDENCE_PREFIX));
    assert!(
        matches!(
            std::fs::symlink_metadata(&marker),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        ),
        "an early-exit helper must not create readiness evidence"
    );
}

pub fn prepare_fault_target(
    fixture: &support::StagedFixture,
) -> (
    std::path::PathBuf,
    memcordon_sealed_agent::request::LaunchRequestV1,
) {
    let marker = fixture.directory().join("fault-ready");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&marker)
        .expect("fault marker must be isolated and precreated");
    let marker_c = CString::new(marker.as_os_str().as_bytes()).expect("marker path has no NUL");
    assert_eq!(unsafe { libc::chown(marker_c.as_ptr(), 65_534, 65_534) }, 0);
    let mut request = fixture
        .request("fault-ready", Lifetime::Command)
        .expect("fault request must be valid");
    request
        .arguments
        .push(marker.as_os_str().as_bytes().to_vec());
    (marker, request)
}

pub fn execute_loss(
    point: FaultPoint,
    wait_until_target_ready: bool,
) -> Result<TerminalFacts, Box<CapturedFaultOutcome>> {
    let fixture = support::StagedFixture::new().expect("fault fixture must stage");
    let (marker, request) = prepare_fault_target(&fixture);
    let frontend_marker = fixture.directory().join("frontend-ready");
    let frontend_process =
        FrontendProcess::spawn(fixture.program(), &frontend_marker, "frontend-hold")
            .expect("fault frontend helper must become exactly ready");
    let frontend = frontend_process.pid();
    let (descriptors, attempt) = support::resources(frontend).expect("fault resources must exist");
    let result = memcordon_sealed_agent::linux::launch::execute_with_fault_typed(
        request,
        descriptors,
        attempt,
        frontend,
        65_534,
        65_534,
        Vec::new(),
        FaultPlan {
            point,
            postauthorization_ready: wait_until_target_ready.then(|| FaultReady {
                path: marker.clone(),
                expected: FAULT_READY_BYTES.to_vec(),
            }),
            provider_loss_claim_path: None,
        },
    );
    frontend_process
        .terminate_and_reap()
        .expect("fault frontend helper must be SIGKILLed and reaped");
    result.map_err(|outcome| {
        let identity = support::attempt_identity(outcome.attempt_id);
        Box::new(CapturedFaultOutcome {
            guardian_reaped: outcome.rejection.cleanup.helpers_reaped,
            marker_observed: std::fs::read(&marker)
                .is_ok_and(|contents| contents == FAULT_READY_BYTES),
            final_record_absent: path_absent(
                &std::path::Path::new(memcordon_sealed_agent::linux::STATE_ROOT).join(&identity),
            ),
            final_cgroup_absent: path_absent(
                &std::path::Path::new(memcordon_sealed_agent::linux::CGROUP_ROOT).join(identity),
            ),
            outcome,
        })
    })
}

pub fn emit_fault_evidence(selector: &str, captured: &CapturedFaultOutcome) {
    let retirement_owner = match captured.outcome.retirement_owner {
        RetirementOwner::Guardian => "guardian",
        RetirementOwner::Provider => "provider",
    };
    let evidence = FaultScenarioEvidence {
        schema_version: 1,
        selector,
        attempt_id: support::attempt_identity(captured.outcome.attempt_id),
        rejection: &captured.outcome.rejection,
        retirement_owner,
        marker_observed: captured.marker_observed,
        guardian_reaped: captured.guardian_reaped,
        final_record_absent: captured.final_record_absent,
        final_cgroup_absent: captured.final_cgroup_absent,
    };
    println!(
        "\n{FAULT_EVIDENCE_PREFIX}{}",
        serde_json::to_string(&evidence).expect("fault evidence must serialize")
    );
}

pub fn assert_loss_outcome(
    selector: &str,
    captured: &CapturedFaultOutcome,
    code: &str,
    phase: RejectionPhaseV1,
    target_released: bool,
    retirement_owner: RetirementOwner,
) {
    let rejection = &captured.outcome.rejection;
    emit_fault_evidence(selector, captured);
    assert_eq!(rejection.code, code);
    assert_eq!(rejection.phase, phase);
    assert!(rejection.detail.starts_with(&format!("{code}:")));
    assert!(rejection.target_created);
    assert_eq!(rejection.target_released, target_released);
    assert!(rejection.cleanup.attempted);
    assert!(rejection.cleanup.direct_child_reaped);
    assert_eq!(rejection.cleanup.workload_empty, Some(true));
    assert!(rejection.cleanup.helpers_reaped);
    assert!(rejection.cleanup.containment_removed);
    assert!(rejection.cleanup.sealed_boundary_retired);
    assert!(rejection.cleanup.errors.is_empty());
    rejection
        .validate()
        .expect("typed loss rejection must be self-consistent");
    assert_eq!(captured.outcome.retirement_owner, retirement_owner);
    assert_eq!(captured.marker_observed, target_released);
    assert!(captured.guardian_reaped);
    assert!(captured.final_record_absent);
    assert!(captured.final_cgroup_absent);
}

fn path_absent(path: &std::path::Path) -> bool {
    matches!(
        std::fs::symlink_metadata(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    )
}

pub fn exit_as_provider_worker(
    request: memcordon_sealed_agent::request::LaunchRequestV1,
    claim_path: std::path::PathBuf,
    attempt: [u8; 16],
) -> ! {
    let frontend = unsafe { libc::getppid() };
    let (descriptors, _) = support::resources(frontend).unwrap();
    let _ = memcordon_sealed_agent::linux::launch::execute_with_fault_typed(
        request,
        descriptors,
        attempt,
        frontend,
        65_534,
        65_534,
        Vec::new(),
        FaultPlan {
            point: FaultPoint::ProviderWorkerLossAfterGuardianCreation,
            postauthorization_ready: None,
            provider_loss_claim_path: Some(claim_path),
        },
    );
    unsafe { libc::_exit(87) }
}
