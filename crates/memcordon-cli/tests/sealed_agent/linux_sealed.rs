#![cfg(target_os = "linux")]

mod support;

#[path = "support/retained_streams.rs"]
mod retained_streams;

#[path = "support/concurrency.rs"]
mod concurrency;

#[cfg(feature = "test-support")]
#[path = "support/sealed_faults.rs"]
mod sealed_faults;

use crate::linux::launch::{ExecFailureClass, TargetExecStatus};
use crate::request::Lifetime;
#[cfg(feature = "test-support")]
use crate::{
    linux::launch::{
        FaultExecutionOutcome, FaultPlan, FaultPoint, GuardianTrigger, RetirementOwner,
    },
    rejection::{RejectionCleanupV1, RejectionPhaseV1, RejectionV1},
};

struct EphemeralCertificationUser {
    name: String,
    uid: libc::uid_t,
    removed: bool,
}

impl EphemeralCertificationUser {
    fn create(role: &str, primary_gid: Option<libc::gid_t>) -> Self {
        let name = format!("mcrd{role}{:x}", std::process::id());
        let mut command = std::process::Command::new("/usr/sbin/useradd");
        command
            .arg("--no-create-home")
            .arg("--shell")
            .arg("/usr/sbin/nologin");
        if let Some(gid) = primary_gid {
            command.arg("--gid").arg(gid.to_string());
        }
        let output = command
            .arg(&name)
            .output()
            .expect("credential-transition certification requires /usr/sbin/useradd");
        assert!(
            output.status.success(),
            "ephemeral certification user creation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = std::process::Command::new("/usr/bin/id")
            .arg("-u")
            .arg(&name)
            .output()
            .expect("credential-transition certification requires /usr/bin/id");
        assert!(output.status.success(), "ephemeral user uid lookup failed");
        let uid = String::from_utf8(output.stdout)
            .expect("ephemeral uid is UTF-8")
            .trim()
            .parse()
            .expect("ephemeral uid is numeric");
        Self {
            name,
            uid,
            removed: false,
        }
    }

    fn remove(mut self) {
        let status = std::process::Command::new("/usr/sbin/userdel")
            .arg(&self.name)
            .status()
            .expect("credential-transition certification requires /usr/sbin/userdel");
        assert!(
            status.success(),
            "ephemeral certification user cleanup failed"
        );
        self.removed = true;
    }
}

struct EphemeralSudoersRule {
    path: std::path::PathBuf,
    removed: bool,
}

impl EphemeralSudoersRule {
    fn create(caller: &str, candidate: &str, fixture: &std::path::Path, uid: libc::uid_t) -> Self {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        let path = std::path::Path::new("/etc/sudoers.d")
            .join(format!("memcordon-credential-{}", std::process::id()));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o440)
            .open(&path)
            .expect("ephemeral sudoers rule must be created exclusively");
        writeln!(
            file,
            "{caller} ALL=({candidate}) NOPASSWD: {} assert-effective-uid {uid}",
            fixture.display()
        )
        .expect("ephemeral sudoers rule must be written");
        file.sync_all()
            .expect("ephemeral sudoers rule must be durable");
        let status = std::process::Command::new("/usr/sbin/visudo")
            .arg("-c")
            .arg("-f")
            .arg(&path)
            .status()
            .expect("sudo certification requires /usr/sbin/visudo");
        assert!(status.success(), "ephemeral sudoers rule is invalid");
        Self {
            path,
            removed: false,
        }
    }

    fn remove(mut self) {
        std::fs::remove_file(&self.path).expect("ephemeral sudoers rule cleanup failed");
        self.removed = true;
    }
}

impl Drop for EphemeralSudoersRule {
    fn drop(&mut self) {
        if !self.removed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl Drop for EphemeralCertificationUser {
    fn drop(&mut self) {
        if !self.removed {
            let _ = std::process::Command::new("/usr/sbin/userdel")
                .arg(&self.name)
                .status();
        }
    }
}

fn assert_no_process_uses_uid(uid: libc::uid_t) {
    let remaining = std::fs::read_dir("/proc")
        .expect("process inventory")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
        })
        .filter_map(|entry| std::fs::read_to_string(entry.path().join("status")).ok())
        .filter_map(|status| crate::linux::envelope::parse_proc_status(&status).ok())
        .any(|status| status.uids.contains(&uid));
    assert!(
        !remaining,
        "alternate-credential descendant survived sealed retirement"
    );
}

fn assert_public_transition_report(path: &std::path::Path) {
    let report: memcordon_core::MemcordonReport =
        serde_json::from_slice(&std::fs::read(path).expect("public transition report must exist"))
            .expect("public transition report must be schema-valid");
    assert_eq!(
        report.schema_version,
        memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION
    );
    assert!(report.error.is_none());
    let supervision = report
        .supervision
        .as_ref()
        .expect("public transition report must contain supervision");
    assert_eq!(supervision.wrapper_exit_code, 0);
    assert_eq!(supervision.targets_authorized, 1);
    assert_eq!(report.attempts.len(), 1);
    let attempt = report.attempts.first().expect("one transition attempt");
    assert!(memcordon_core::boundary_evidence_is_consistent(
        &attempt.launch,
        &attempt.restart_safety,
        &attempt.boundary_detail,
    ));
    assert!(matches!(
        &attempt.boundary_detail,
        memcordon_core::BoundaryMechanismEvidence::LinuxPidNamespaceCgroupV2(native)
            if native.boundary_independent_of_credentials
                && native.cgroup_empty_verified
                && native.namespace_init_reaped
                && native.guardian_reaped
                && native.cgroup_removed
    ));
}

#[cfg(feature = "test-support")]
#[test]
fn staged_frontend_hold_is_ready_live_and_sigkill_reaped() {
    sealed_faults::assert_frontend_hold_lifecycle(std::path::Path::new(support::fixture()));
}

#[cfg(feature = "test-support")]
#[test]
fn staged_frontend_hold_rejects_exit_before_readiness() {
    sealed_faults::assert_frontend_hold_rejects_early_exit(
        std::path::Path::new(support::fixture()),
    );
}

fn run(mode: &str, lifetime: Lifetime) {
    let facts = support::execute(mode, lifetime).expect("native sealed launch must complete");
    assert_eq!(
        facts.child_status, 0,
        "fixture mode {mode} did not complete successfully"
    );
    support::assert_retired(&facts);
}

fn assert_forked_certification(child: libc::pid_t, scenario: &str) {
    assert!(child > 0, "{scenario}: fork failed");
    let mut status = 0;
    // SAFETY: child is the direct child returned by fork and status is writable.
    assert_eq!(unsafe { libc::waitpid(child, &raw mut status, 0) }, child);
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "{scenario}: child status {status}"
    );
}

fn assert_transition_terminal(
    result: Result<crate::linux::launch::TerminalFacts, String>,
) -> crate::linux::launch::TerminalFacts {
    let facts = result.expect("credential transition must finish under the sealed boundary");
    assert_eq!(facts.child_status, 0);
    assert!(facts.boundary_independent_of_credentials);
    assert!(facts.target_initial_credentials_verified);
    assert!(facts.initial_provider_capabilities_absent);
    assert!(facts.assignment_verified);
    assert!(facts.namespaces_verified);
    assert!(facts.descriptors_verified);
    assert!(facts.writable_ancestor_cgroup_denied);
    assert!(facts.parent_namespace_handles_denied);
    assert!(facts.recursive_provider_request_denied);
    assert!(facts.cgroup_kill_invoked);
    support::assert_retired(&facts);
    facts
}

#[test]
#[ignore = "requires privileged Linux sealed credential-transition certification"]
fn sealed_setid_transition_preserves_boundary() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = support::StagedFixture::new().expect("root-owned fixture must stage");
    std::fs::set_permissions(fixture.program(), std::fs::Permissions::from_mode(0o4755))
        .expect("set-ID fixture permissions must be installed");
    assert_eq!(
        std::fs::metadata(fixture.program())
            .expect("set-ID fixture metadata")
            .permissions()
            .mode()
            & 0o4777,
        0o4755
    );
    let facts = assert_transition_terminal(support::execute_request(
        fixture
            .request("assert-credential-transition-root", Lifetime::Command)
            .expect("set-ID launch request"),
    ));
    assert!(!facts.caller_no_new_privs);
    assert!(facts.target_no_new_privs_matched);
}

#[test]
#[ignore = "requires privileged Linux sealed credential-transition certification"]
fn sealed_sudo_transition_preserves_boundary() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let fixture = support::StagedFixture::new().expect("root-owned fixture must stage");
    let sudo = std::path::Path::new("/usr/bin/sudo");
    assert!(sudo.is_file(), "sudo certification requires /usr/bin/sudo");
    let provider_gid = std::fs::symlink_metadata(crate::linux::SOCKET_PATH)
        .expect("installed public provider socket metadata")
        .gid();
    assert_ne!(provider_gid, 0, "provider access group must be non-root");
    let caller = EphemeralCertificationUser::create("caller", Some(provider_gid));
    let candidate = EphemeralCertificationUser::create("sudo", None);
    let sudoers = EphemeralSudoersRule::create(
        &caller.name,
        &candidate.name,
        fixture.program(),
        candidate.uid,
    );
    let report_directory = tempfile::Builder::new()
        .prefix("memcordon-sudo-transition-")
        .tempdir_in("/tmp")
        .expect("sudo transition report directory");
    std::fs::set_permissions(
        report_directory.path(),
        std::fs::Permissions::from_mode(0o770),
    )
    .expect("sudo report directory permissions");
    let report_directory_c = std::ffi::CString::new(
        report_directory
            .path()
            .as_os_str()
            .as_encoded_bytes()
            .to_vec(),
    )
    .expect("sudo report directory has no NUL");
    // SAFETY: the path is live and NUL-terminated; uid -1 preserves root ownership.
    assert_eq!(
        unsafe { libc::chown(report_directory_c.as_ptr(), libc::uid_t::MAX, provider_gid) },
        0,
        "sudo report directory group ownership"
    );
    let report = report_directory.path().join("execution.json");
    let memcordon = std::env::current_dir()
        .expect("certification working directory")
        .join("target/ci/sealed-agent/debug/memcordon");
    assert!(
        memcordon.is_file(),
        "sudo certification requires CI memcordon"
    );
    let output = std::process::Command::new("/usr/bin/setpriv")
        .arg("--reuid")
        .arg(caller.uid.to_string())
        .arg("--regid")
        .arg(provider_gid.to_string())
        .arg("--clear-groups")
        .arg("--")
        .arg(&memcordon)
        .arg("--sealed")
        .arg("--report")
        .arg(&report)
        .arg("--")
        .arg(sudo)
        .arg("-n")
        .arg("-u")
        .arg(&candidate.name)
        .arg("--")
        .arg(fixture.program())
        .arg("assert-effective-uid")
        .arg(candidate.uid.to_string())
        .output()
        .expect("public sudo transition must execute through native argv");
    assert!(
        output.status.success(),
        "public sudo transition failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_public_transition_report(&report);
    assert_no_process_uses_uid(candidate.uid);
    assert_no_process_uses_uid(caller.uid);
    sudoers.remove();
    candidate.remove();
    caller.remove();
}

#[test]
#[ignore = "requires privileged Linux sealed credential-transition certification"]
fn sealed_file_capability_transition_preserves_boundary() {
    let fixture = support::StagedFixture::new().expect("root-owned fixture must stage");
    let status = std::process::Command::new("setcap")
        .arg("cap_setuid=ep")
        .arg(fixture.program())
        .status()
        .expect("file-capability certification requires setcap");
    assert!(status.success(), "setcap did not install cap_setuid=ep");
    let facts = assert_transition_terminal(support::execute_request(
        fixture
            .request("assert-file-capability-transition", Lifetime::Command)
            .expect("file-capability launch request"),
    ));
    assert!(!facts.caller_no_new_privs);
    assert!(facts.target_no_new_privs_matched);
}

#[test]
#[ignore = "requires privileged Linux sealed credential-transition certification"]
fn sealed_caller_no_new_privs_is_reproduced() {
    // SAFETY: this privileged certification forks before running the isolated synchronous case.
    let child = unsafe { libc::fork() };
    if child == 0 {
        // SAFETY: prctl receives scalar arguments and irreversibly tightens only this child.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            unsafe { libc::_exit(101) };
        }
        let success = support::execute("exit", Lifetime::Command).is_ok_and(|facts| {
            facts.caller_no_new_privs && facts.target_no_new_privs_matched && facts.boundary_retired
        });
        unsafe { libc::_exit(i32::from(!success)) };
    }
    assert_forked_certification(child, "caller no-new-privileges reproduction");
}

#[test]
#[ignore = "requires privileged Linux sealed credential-transition certification"]
fn sealed_caller_capability_bounding_set_is_reproduced() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = support::StagedFixture::new().expect("root-owned fixture must stage");
    std::fs::set_permissions(fixture.program(), std::fs::Permissions::from_mode(0o4755))
        .expect("bounding-set set-ID fixture permissions");
    // SAFETY: this privileged certification forks before tightening the child bounding set.
    let child = unsafe { libc::fork() };
    if child == 0 {
        let before = crate::linux::envelope::parse_proc_status(
            &std::fs::read_to_string("/proc/self/status").expect("caller status"),
        )
        .expect("caller status parses")
        .capability_bounding_set;
        let capability = (0..64)
            .find(|capability| before & (1_u64 << capability) != 0)
            .expect("certification caller must have a droppable bounding capability");
        // SAFETY: prctl receives a capability number observed in this child's bounding set.
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability as libc::c_ulong, 0, 0, 0) } != 0
        {
            unsafe { libc::_exit(102) };
        }
        let after = crate::linux::envelope::parse_proc_status(
            &std::fs::read_to_string("/proc/self/status").expect("reduced caller status"),
        )
        .expect("reduced caller status parses")
        .capability_bounding_set;
        let mut request =
            match fixture.request("assert-bounding-capability-absent", Lifetime::Command) {
                Ok(value) => value,
                Err(_) => unsafe { libc::_exit(103) },
            };
        request.arguments.push(capability.to_string().into_bytes());
        let success = before != after
            && support::execute_request(request).is_ok_and(|facts| {
                facts.target_capability_bounding_set_matched
                    && facts.caller_capability_bounding_set_digest.len() == 64
                    && facts.boundary_independent_of_credentials
                    && facts.boundary_retired
            });
        unsafe { libc::_exit(i32::from(!success)) };
    }
    assert_forked_certification(child, "caller capability bounding-set reproduction");
}

#[test]
#[ignore = "requires privileged Linux sealed credential-transition certification"]
fn sealed_caller_mount_context_is_reproduced() {
    let mountpoint = tempfile::Builder::new()
        .prefix("memcordon-sealed-caller-mount-")
        .tempdir_in("/tmp")
        .expect("caller mountpoint");
    // SAFETY: this privileged certification forks before unsharing the child's mount context.
    let child = unsafe { libc::fork() };
    if child == 0 {
        // SAFETY: unshare and mount receive valid scalar flags and live C strings.
        if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0
            || unsafe {
                libc::mount(
                    std::ptr::null(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                )
            } != 0
        {
            unsafe { libc::_exit(103) };
        }
        let mountpoint_c =
            std::ffi::CString::new(mountpoint.path().as_os_str().as_encoded_bytes().to_vec())
                .expect("mountpoint has no NUL");
        if unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                mountpoint_c.as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV,
                c"size=64k,mode=0755".as_ptr().cast(),
            )
        } != 0
        {
            unsafe { libc::_exit(104) };
        }
        let marker = mountpoint.path().join("caller-marker");
        if std::fs::write(&marker, b"caller-mount-context\n").is_err() {
            unsafe { libc::_exit(105) };
        }
        let fixture = match support::StagedFixture::new() {
            Ok(value) => value,
            Err(_) => unsafe { libc::_exit(106) },
        };
        let mut request = match fixture.request("assert-mount-marker", Lifetime::Command) {
            Ok(value) => value,
            Err(_) => unsafe { libc::_exit(107) },
        };
        request
            .arguments
            .push(marker.as_os_str().as_encoded_bytes().to_vec());
        let success = support::execute_request(request).is_ok_and(|facts| {
            facts.target_mount_context_derived_from_caller
                && facts.caller_mount_namespace_digest.len() == 64
                && facts.boundary_retired
                && facts.child_status == 0
        });
        unsafe { libc::_exit(i32::from(!success)) };
    }
    assert_forked_certification(child, "caller mount-context reproduction");
}

#[test]
#[ignore = "requires privileged Linux sealed credential-transition certification"]
fn sealed_recursive_provider_request_is_rejected() {
    let fixture = support::StagedFixture::new().expect("root-owned fixture must stage");
    let memcordon = std::env::current_dir()
        .expect("certification working directory")
        .join("target/ci/sealed-agent/debug/memcordon");
    assert!(
        memcordon.is_file(),
        "recursive certification requires the CI memcordon executable"
    );
    let report_directory = tempfile::Builder::new()
        .prefix("memcordon-recursive-provider-")
        .tempdir_in("/tmp")
        .expect("recursive rejection report directory");
    let report = report_directory.path().join("rejection.json");
    let mut request = fixture
        .request("assert-recursive-provider-rejected", Lifetime::Command)
        .expect("recursive provider launch request");
    request
        .arguments
        .push(memcordon.as_os_str().as_encoded_bytes().to_vec());
    request
        .arguments
        .push(report.as_os_str().as_encoded_bytes().to_vec());
    assert_transition_terminal(support::execute_request_as(request, 0, 0, Vec::new()));
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_direct_exit_retires_fresh_boundary() {
    run("exit", Lifetime::Command);
}

#[test]
fn sealed_fixture_deadline_is_future_monotonic_time() {
    let before = crate::linux::clock::monotonic_millis().unwrap();
    let request = support::request("exit", Lifetime::Command).unwrap();
    let after = crate::linux::clock::monotonic_millis().unwrap();
    let deadline = request.policy.absolute_deadline_millis.unwrap();
    assert!(deadline >= before.saturating_add(30_000));
    assert!(deadline <= after.saturating_add(30_000));
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_future_deadline_authorizes_and_retires() {
    let facts = support::execute("exit", Lifetime::Command).unwrap();
    assert_eq!(facts.child_status, 0);
    assert!(!facts.deadline_exceeded);
    assert!(facts.authorization_offset_millis < 30_000);
    support::assert_retired(&facts);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_expired_deadline_never_authorizes_and_retires() {
    let marker = std::path::Path::new("/tmp/memcordon-sealed-preauthorization-marker");
    let _ = std::fs::remove_file(marker);
    let now = crate::linux::clock::monotonic_millis().unwrap();
    let fixture = support::StagedFixture::new().unwrap();
    let fixture_directory = fixture.directory().to_owned();
    let request = fixture.request_with_deadline("mark", Lifetime::Command, now.saturating_sub(1));
    // SAFETY: getpid has no pointer or ownership requirements and identifies this live frontend.
    let frontend_pid = unsafe { libc::getpid() };
    let (descriptors, attempt) = support::resources(frontend_pid).unwrap();
    let identity = attempt
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let record_path = std::path::Path::new(crate::linux::STATE_ROOT).join(&identity);
    let transaction_path = record_path.with_extension("new");
    let cgroup_path = std::path::Path::new(crate::linux::CGROUP_ROOT).join(&identity);
    let error = crate::linux::launch::execute(
        request,
        descriptors,
        attempt,
        frontend_pid,
        65_534,
        65_534,
        Vec::new(),
    )
    .expect_err("an expired deadline must fail before gate release");
    assert_eq!(
        error,
        "MCSEALED-AUTHORIZATION: deadline expired before authorization; target was not authorized"
    );
    assert!(
        !marker.exists(),
        "expired target passed its authorization gate"
    );
    assert!(
        !record_path.exists(),
        "failed attempt record was not retired"
    );
    assert!(
        !transaction_path.exists(),
        "failed attempt record transaction was not retired"
    );
    assert!(
        !cgroup_path.exists(),
        "failed attempt cgroup was not retired"
    );
    let ambiguity = crate::linux::recovery::recover().unwrap();
    assert!(
        ambiguity.is_empty(),
        "expired attempt poisoned subsequent recovery: {ambiguity:?}"
    );
    drop(fixture);
    assert!(
        !fixture_directory.exists(),
        "expired attempt leaked its isolated fixture"
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_staged_fixture_is_isolated_and_removed_after_retirement() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let fixture = support::StagedFixture::new().unwrap();
    let second_fixture = support::StagedFixture::new().unwrap();
    let fixture_directory = fixture.directory().to_owned();
    let second_directory = second_fixture.directory().to_owned();
    assert_ne!(fixture_directory, second_directory);
    let directory_metadata = std::fs::symlink_metadata(&fixture_directory).unwrap();
    let program_metadata = std::fs::symlink_metadata(fixture.program()).unwrap();
    assert_eq!(directory_metadata.uid(), 0);
    assert_eq!(directory_metadata.permissions().mode() & 0o777, 0o755);
    assert!(program_metadata.file_type().is_file());
    assert_eq!(program_metadata.uid(), 0);
    assert_eq!(program_metadata.permissions().mode() & 0o777, 0o555);
    let facts = support::execute_request(fixture.request("exit", Lifetime::Command).unwrap())
        .expect("isolated staged fixture must execute as the reduced target identity");
    assert_eq!(facts.child_status, 0);
    support::assert_retired(&facts);
    drop(fixture);
    drop(second_fixture);
    assert!(
        !fixture_directory.exists(),
        "retired attempt leaked its isolated fixture"
    );
    assert!(
        !second_directory.exists(),
        "unused isolated fixture leaked its unique directory"
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_child_outlives_direct_target_until_cleanup() {
    run("child", Lifetime::Command);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_double_fork_remains_in_pid_namespace_and_cgroup() {
    run("double-fork", Lifetime::Command);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_setsid_daemon_remains_contained() {
    run("setsid", Lifetime::Command);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_retained_streams_do_not_finish_before_retirement() {
    let fixture = support::StagedFixture::new().unwrap();
    let fixture_directory = fixture.directory().to_owned();
    let request = fixture
        .request("retained-stream", Lifetime::Workload)
        .unwrap();
    let captured = retained_streams::execute(request)
        .expect("retained-stream workload must complete before its attempt deadline");
    assert!(
        captured.execution_millis >= 400,
        "provider returned before the descendant retained its streams"
    );
    assert!(
        captured.execution_millis < 10_000,
        "bounded retained-stream workload approached its attempt deadline"
    );
    assert_eq!(
        captured.stdout,
        b"retained-stdout-open\nretained-stdout-release\n"
    );
    assert_eq!(
        captured.stderr,
        b"retained-stderr-open\nretained-stderr-release\n"
    );
    assert_eq!(captured.facts.child_status, 0);
    assert_eq!(captured.facts.exec_status, TargetExecStatus::Succeeded);
    assert!(captured.facts.spawn_error_reported);
    assert!(!captured.facts.deadline_exceeded);
    assert!(!captured.facts.memory_limit_exceeded);
    support::assert_retired(&captured.facts);
    drop(fixture);
    assert!(
        !fixture_directory.exists(),
        "retained-stream attempt leaked its isolated fixture"
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_fork_storm_is_empty_before_result() {
    run("fork-storm", Lifetime::Command);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_fork_during_cleanup_cannot_survive() {
    run("fork-storm", Lifetime::Command);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_target_cannot_move_to_parent_or_sibling_cgroup() {
    run("deny-cgroup", Lifetime::Command);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_target_cannot_setns_into_host_namespace() {
    run("deny-setns", Lifetime::Command);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_target_cannot_mount_writable_cgroup_view() {
    run("deny-cgroup-mount", Lifetime::Command);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_target_inherits_only_verified_descriptors() {
    run("identity", Lifetime::Command);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_target_cannot_disable_namespace_init() {
    run("child", Lifetime::Command);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
#[cfg(feature = "test-support")]
fn sealed_frontend_loss_before_authorization_never_runs_target() {
    let captured = sealed_faults::execute_loss(FaultPoint::FrontendLossBeforeAuthorization, false)
        .expect_err("frontend loss must abort authorization");
    sealed_faults::assert_loss_outcome(
        "sealed_frontend_loss_before_authorization_never_runs_target",
        &captured,
        "MCSEALED-FRONTEND-LOSS-BEFORE-AUTHORIZATION",
        RejectionPhaseV1::Authorization,
        false,
        RetirementOwner::Guardian,
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
#[cfg(feature = "test-support")]
fn sealed_frontend_loss_after_authorization_triggers_guardian() {
    let captured = sealed_faults::execute_loss(FaultPoint::FrontendLossAfterAuthorization, true)
        .expect_err("frontend loss cannot report success");
    sealed_faults::assert_loss_outcome(
        "sealed_frontend_loss_after_authorization_triggers_guardian",
        &captured,
        "MCSEALED-FRONTEND-LOSS-AFTER-AUTHORIZATION",
        RejectionPhaseV1::Monitoring,
        true,
        RetirementOwner::Guardian,
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
#[cfg(feature = "test-support")]
fn sealed_provider_worker_loss_triggers_guardian() {
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
    let fixture = support::StagedFixture::new().unwrap();
    let (marker, request) = sealed_faults::prepare_fault_target(&fixture);
    let claim_path = fixture.directory().join("provider-loss-claim");
    let attempt = [0x44; 16];
    let worker = unsafe { libc::fork() };
    assert!(worker >= 0);
    if worker == 0 {
        sealed_faults::exit_as_provider_worker(request, claim_path, attempt);
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(worker, &raw mut status, 0) }, worker);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 86);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let claim_bytes = loop {
        match std::fs::read(&claim_path) {
            Ok(bytes) => break bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("provider-loss claim read failed: {error}"),
        }
        assert!(
            std::time::Instant::now() < deadline,
            "guardian omitted provider-loss terminal claim"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    let claim = crate::linux::launch::decode_guardian_terminal_for_test(&claim_bytes).unwrap();
    assert_eq!(claim.trigger, GuardianTrigger::ProviderLoss);
    assert_eq!(claim.attempt_id, attempt);
    assert!(claim.cgroup_kill_invoked);
    assert!(claim.populated_zero_observed);
    assert!(claim.containment_removed);
    assert!(claim.record_retired);
    let mut helpers_reaped = 0_u32;
    loop {
        let reaped = unsafe { libc::waitpid(-1, &raw mut status, libc::WNOHANG) };
        if reaped > 0 {
            helpers_reaped += 1;
            continue;
        }
        if reaped == -1 {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "provider-loss helpers were not reaped"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        helpers_reaped >= 2,
        "namespace init and guardian were not both reaped"
    );
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 0) }, 0);
    assert!(std::fs::read(&marker).is_ok_and(|contents| contents.is_empty()));
    support::assert_attempt_retired(attempt);
    let rejection = RejectionV1::from_launch_facts(
        "MCSEALED-PROVIDER-WORKER-LOSS",
        RejectionPhaseV1::GuardianStartup,
        "MCSEALED-PROVIDER-WORKER-LOSS: authenticated guardian retirement",
        false,
        false,
        RejectionCleanupV1 {
            attempted: true,
            direct_child_reaped: true,
            workload_empty: Some(true),
            helpers_reaped: true,
            containment_removed: true,
            sealed_boundary_retired: true,
            errors: Vec::new(),
        },
    )
    .unwrap();
    sealed_faults::emit_fault_evidence(
        "sealed_provider_worker_loss_triggers_guardian",
        &sealed_faults::CapturedFaultOutcome {
            outcome: crate::linux::launch::FaultExecutionOutcome {
                attempt_id: attempt,
                rejection,
                retirement_owner: RetirementOwner::Guardian,
            },
            marker_observed: false,
            guardian_reaped: true,
            final_record_absent: true,
            final_cgroup_absent: true,
        },
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
#[cfg(feature = "test-support")]
fn sealed_guardian_loss_before_authorization_fails_closed() {
    let captured = sealed_faults::execute_loss(FaultPoint::GuardianLossBeforeAuthorization, false)
        .expect_err("guardian loss must abort authorization");
    sealed_faults::assert_loss_outcome(
        "sealed_guardian_loss_before_authorization_fails_closed",
        &captured,
        "MCSEALED-GUARDIAN-LOSS-BEFORE-AUTHORIZATION",
        RejectionPhaseV1::Authorization,
        false,
        RetirementOwner::Provider,
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
#[cfg(feature = "test-support")]
fn sealed_guardian_loss_after_authorization_cannot_report_success() {
    let captured = sealed_faults::execute_loss(FaultPoint::GuardianLossAfterAuthorization, true)
        .expect_err("guardian loss cannot report success");
    sealed_faults::assert_loss_outcome(
        "sealed_guardian_loss_after_authorization_cannot_report_success",
        &captured,
        "MCSEALED-GUARDIAN-LOSS-AFTER-AUTHORIZATION",
        RejectionPhaseV1::Monitoring,
        true,
        RetirementOwner::Provider,
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
#[cfg(feature = "test-support")]
fn sealed_cgroup_kill_failure_never_reports_retirement() {
    let captured =
        sealed_faults::execute_loss(FaultPoint::CgroupKillFailureAfterAuthorization, true)
            .expect_err("injected cgroup.kill failure cannot report success");
    sealed_faults::assert_loss_outcome(
        "sealed_cgroup_kill_failure_never_reports_retirement",
        &captured,
        "MCSEALED-CGROUP-KILL-FAILURE",
        RejectionPhaseV1::Retirement,
        true,
        RetirementOwner::Provider,
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
#[cfg(feature = "test-support")]
fn sealed_persistent_populated_state_blocks_restart() {
    let captured =
        sealed_faults::execute_loss(FaultPoint::PersistentPopulatedAfterAuthorization, true)
            .expect_err("persistent populated state cannot report success");
    sealed_faults::assert_loss_outcome(
        "sealed_persistent_populated_state_blocks_restart",
        &captured,
        "MCSEALED-CGROUP-NOT-EMPTY",
        RejectionPhaseV1::Retirement,
        true,
        RetirementOwner::Provider,
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
#[cfg(feature = "test-support")]
fn sealed_namespace_init_reap_delay_blocks_result() {
    let captured =
        sealed_faults::execute_loss(FaultPoint::NamespaceInitReapDelayAfterAuthorization, true)
            .expect_err("live namespace init cannot report terminal success");
    sealed_faults::assert_loss_outcome(
        "sealed_namespace_init_reap_delay_blocks_result",
        &captured,
        "MCSEALED-NAMESPACE-INIT-REAP-DELAY",
        RejectionPhaseV1::Retirement,
        true,
        RetirementOwner::Provider,
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
#[cfg(feature = "test-support")]
fn sealed_guardian_reap_failure_blocks_result() {
    let captured =
        sealed_faults::execute_loss(FaultPoint::GuardianReapFailureAfterAuthorization, true)
            .expect_err("live guardian cannot report terminal success");
    sealed_faults::assert_loss_outcome(
        "sealed_guardian_reap_failure_blocks_result",
        &captured,
        "MCSEALED-GUARDIAN-REAP-FAILURE",
        RejectionPhaseV1::Retirement,
        true,
        RetirementOwner::Provider,
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
#[cfg(feature = "test-support")]
fn sealed_faults_before_authorization_never_create_marker() {
    let fixture = support::StagedFixture::new().unwrap();
    let (marker, request) = sealed_faults::prepare_fault_target(&fixture);
    let attempt = [0xb1; 16];
    let error = crate::linux::launch::execute(
        request,
        Vec::new(),
        attempt,
        unsafe { libc::getpid() },
        65_534,
        65_534,
        Vec::new(),
    )
    .expect_err("descriptor fault must fail before authorization");
    assert_eq!(
        error,
        "MCSEALED-LAUNCH-DESCRIPTOR-SET: exact descriptor inventory required"
    );
    let rejection = RejectionV1::from_launch_error(&error, attempt);
    assert_eq!(rejection.code, "MCSEALED-LAUNCH-DESCRIPTOR-SET");
    assert_eq!(rejection.phase, RejectionPhaseV1::RequestValidation);
    assert!(!rejection.target_created);
    assert!(!rejection.target_released);
    assert!(!rejection.cleanup.attempted);
    rejection.validate().unwrap();
    assert!(std::fs::read(&marker).is_ok_and(|contents| contents.is_empty()));
    support::assert_attempt_retired(attempt);
    sealed_faults::emit_fault_evidence(
        "sealed_faults_before_authorization_never_create_marker",
        &sealed_faults::CapturedFaultOutcome {
            outcome: FaultExecutionOutcome {
                attempt_id: attempt,
                rejection,
                retirement_owner: RetirementOwner::Provider,
            },
            marker_observed: false,
            guardian_reaped: false,
            final_record_absent: true,
            final_cgroup_absent: true,
        },
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
#[cfg(feature = "test-support")]
fn sealed_namespace_init_failure_is_typed_prompt_and_retired() {
    let fixture = support::StagedFixture::new().unwrap();
    let (marker, request) = sealed_faults::prepare_fault_target(&fixture);
    let frontend = unsafe { libc::getpid() };
    let (descriptors, attempt) = support::resources(frontend).unwrap();
    let started = std::time::Instant::now();
    let outcome = crate::linux::launch::execute_with_fault_typed(
        request,
        descriptors,
        attempt,
        frontend,
        65_534,
        65_534,
        Vec::new(),
        FaultPlan {
            point: FaultPoint::NamespaceInitFailureBeforeTarget,
            postauthorization_ready: None,
            provider_loss_claim_path: None,
        },
    )
    .expect_err("namespace-init fault must fail before target creation");
    let rejection = &outcome.rejection;
    assert_eq!(rejection.code, "MCSEALED-NAMESPACE-INIT-TARGET-FORK");
    assert_eq!(rejection.phase, RejectionPhaseV1::TargetCreation);
    assert!(!rejection.target_created);
    assert!(!rejection.target_released);
    assert!(rejection.cleanup.attempted);
    assert!(rejection.cleanup.direct_child_reaped);
    assert_eq!(rejection.cleanup.workload_empty, Some(true));
    assert!(rejection.cleanup.helpers_reaped);
    assert!(rejection.cleanup.containment_removed);
    assert!(rejection.cleanup.sealed_boundary_retired);
    assert!(rejection.cleanup.errors.is_empty());
    rejection.validate().unwrap();
    assert!(started.elapsed() < std::time::Duration::from_secs(4));
    assert!(std::fs::read(&marker).is_ok_and(|contents| contents.is_empty()));
    support::assert_attempt_retired(attempt);
    assert_eq!(outcome.retirement_owner, RetirementOwner::Provider);
    sealed_faults::emit_fault_evidence(
        "sealed_namespace_init_failure_is_typed_prompt_and_retired",
        &sealed_faults::CapturedFaultOutcome {
            outcome,
            marker_observed: false,
            guardian_reaped: true,
            final_record_absent: true,
            final_cgroup_absent: true,
        },
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_native_nonzero_exit_preserves_provenance() {
    let captured = support::execute_captured("exit-17", Lifetime::Command).unwrap();
    assert_eq!(captured.facts.child_status, 17);
    assert_eq!(captured.facts.exec_status, TargetExecStatus::Succeeded);
    assert!(captured.facts.spawn_error_reported);
    support::assert_retired(&captured.facts);
    support::assert_attempt_retired(captured.attempt);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_native_exit_126_and_127_are_not_exec_failures() {
    for (mode, expected) in [("exit-126", 126), ("exit-127", 127)] {
        let captured = support::execute_captured(mode, Lifetime::Command).unwrap();
        assert_eq!(captured.facts.child_status, expected);
        assert_eq!(captured.facts.exec_status, TargetExecStatus::Succeeded);
        assert!(captured.facts.spawn_error_reported);
        support::assert_retired(&captured.facts);
        support::assert_attempt_retired(captured.attempt);
    }
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_missing_target_preserves_enoent_exec_provenance() {
    let fixture = support::StagedFixture::new().unwrap();
    let request = fixture.request("exit", Lifetime::Command).unwrap();
    drop(fixture);
    let captured = support::execute_request_captured(request).unwrap();
    assert_eq!(captured.facts.child_status, 127);
    assert_eq!(
        captured.facts.exec_status,
        TargetExecStatus::Failed {
            class: ExecFailureClass::NotFound,
            os_code: libc::ENOENT,
        }
    );
    assert!(captured.facts.spawn_error_reported);
    support::assert_retired(&captured.facts);
    support::assert_attempt_retired(captured.attempt);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_non_executable_target_preserves_eacces_exec_provenance() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = support::StagedFixture::new().unwrap();
    std::fs::set_permissions(fixture.program(), std::fs::Permissions::from_mode(0o444)).unwrap();
    let request = fixture.request("exit", Lifetime::Command).unwrap();
    let captured = support::execute_request_captured(request).unwrap();
    assert_eq!(captured.facts.child_status, 126);
    assert_eq!(
        captured.facts.exec_status,
        TargetExecStatus::Failed {
            class: ExecFailureClass::NotExecutable,
            os_code: libc::EACCES,
        }
    );
    assert!(captured.facts.spawn_error_reported);
    support::assert_retired(&captured.facts);
    support::assert_attempt_retired(captured.attempt);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_restart_uses_fresh_retired_boundary() {
    let first = support::execute_captured("exit", Lifetime::Command).unwrap();
    let second = support::execute_captured("exit", Lifetime::Command).unwrap();
    assert_eq!(first.facts.child_status, 0);
    assert_eq!(second.facts.child_status, 0);
    assert_ne!(first.facts.target_pid, second.facts.target_pid);
    assert_ne!(first.attempt, second.attempt);
    assert_ne!(first.identity(), second.identity());
    support::assert_retired(&first.facts);
    support::assert_retired(&second.facts);
    support::assert_attempt_retired(first.attempt);
    support::assert_attempt_retired(second.attempt);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_simultaneous_attempts_have_disjoint_boundaries() {
    concurrency::run();
}

#[test]
fn sealed_concurrency_worker_selector_names_exact_consolidated_test() {
    let executable = std::env::args_os()
        .next()
        .expect("consolidated sealed-agent test executable path must be available");
    let output = std::process::Command::new(executable)
        .args([
            concurrency::WORKER_TEST_NAME,
            "--exact",
            "--ignored",
            "--list",
        ])
        .output()
        .expect("consolidated sealed-agent test executable must support list mode");
    assert!(
        output.status.success(),
        "listing the concurrency worker selector failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("libtest list output must be UTF-8");
    let listed = stdout
        .lines()
        .filter(|line| line.ends_with(": test"))
        .collect::<Vec<_>>();
    assert_eq!(
        listed,
        [format!("{}: test", concurrency::WORKER_TEST_NAME)],
        "the nested worker selector must name exactly one consolidated test"
    );
}

#[test]
fn sealed_concurrency_evidence_starts_on_an_independent_line() {
    let output = format!(
        "running 1 test\ntest sealed_simultaneous_attempts_have_disjoint_boundaries ... {}ok\n",
        concurrency::frame_evidence("{}")
    );
    let payloads = output
        .lines()
        .filter_map(|line| line.strip_prefix("MCSEALED-CONCURRENCY-EVIDENCE:"))
        .collect::<Vec<_>>();
    assert_eq!(payloads, ["{}"]);
}
