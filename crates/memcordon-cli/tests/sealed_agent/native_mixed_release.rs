//! Held same-image helpers for the actual inner leased-release regression.
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

fn release_failure(scenario: &str, operation: &str, cause: impl std::fmt::Display) -> String {
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: getrlimit initializes the whole structure on success and opens no descriptor.
    let limits = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } == 0 {
        // SAFETY: the successful call initialized this value.
        let limit = unsafe { limit.assume_init() };
        format!("soft={}; hard={}", limit.rlim_cur, limit.rlim_max)
    } else {
        format!(
            "limit-observation-unavailable={}",
            std::io::Error::last_os_error()
        )
    };
    format!(
        "native release scenario={scenario}; operation={operation}; observer-pid={}; failure-observation-{limits}; cause={cause}",
        std::process::id()
    )
}

pub(super) struct HeldHelper {
    pub(super) child: std::process::Child,
    pub(super) pidfd: Option<OwnedFd>,
    birth: u64,
    image: std::fs::File,
    stdout: Option<std::process::ChildStdout>,
    pub(super) retirement: Option<serde_json::Value>,
}
impl HeldHelper {
    pub(super) fn start(
        helpers: &mut Vec<Self>,
        uid: u32,
        gid: u32,
        challenge: &[u8; 32],
        deadline: Instant,
    ) -> Result<usize, String> {
        let image = std::fs::File::open(std::env::current_exe().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let fd = image.as_raw_fd();
        let mut command = std::process::Command::new("/usr/bin/setpriv");
        command
            .args([
                "--reuid",
                &uid.to_string(),
                "--regid",
                &gid.to_string(),
                "--clear-groups",
                "--no-new-privs",
                "--",
                &format!("/proc/self/fd/{fd}"),
                "--exact",
                "native_mixed_release::native_owned_release_gate_helper",
                "--ignored",
                "--nocapture",
            ])
            .env_clear()
            .current_dir("/")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit());
        memcordon_platform::test_support::inherit_test_descriptor_at(
            &mut command,
            image
                .as_fd()
                .try_clone_to_owned()
                .map_err(|e| e.to_string())?,
            fd,
        )
        .map_err(|e| e.to_string())?;
        let child = command.spawn().map_err(|e| e.to_string())?;
        let pid = child.id();
        helpers.push(Self {
            child,
            pidfd: None,
            birth: 0,
            image,
            stdout: None,
            retirement: None,
        });
        let index = helpers.len() - 1;
        let owner = &mut helpers[index];
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        if raw < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        owner.pidfd = Some(unsafe { OwnedFd::from_raw_fd(raw) });
        owner.stdout = Some(
            owner
                .child
                .stdout
                .take()
                .ok_or("native helper stdout absent")?,
        );
        let observation = (|| -> Result<(), String> {
            let birth = crate::linux::envelope::process_start_time(pid as i32)?;
            owner.birth = birth;
            owner
                .child
                .stdin
                .as_mut()
                .ok_or("native helper input absent")?
                .write_all(challenge)
                .map_err(|e| e.to_string())?;
            let ready = owner.message("MC-NATIVE-RELEASE-READY ", deadline)?;
            if ready["pid"] != pid
                || ready["birth"] != birth
                || ready["uid"] != uid
                || ready["gid"] != gid
                || ready["challenge"] != hex(challenge)
            {
                return Err("native helper readiness association differs".into());
            }
            use std::os::unix::fs::MetadataExt;
            let actual = std::fs::File::open(format!("/proc/{pid}/exe"))
                .map_err(|e| e.to_string())?
                .metadata()
                .map_err(|e| e.to_string())?;
            let expected = owner.image.metadata().map_err(|e| e.to_string())?;
            if (actual.dev(), actual.ino()) != (expected.dev(), expected.ino())
                || crate::linux::envelope::process_start_time(pid as i32)? != birth
            {
                return Err("native helper held executable changed".into());
            }
            Ok(())
        })();
        observation?;
        Ok(index)
    }
    fn message(&mut self, marker: &str, deadline: Instant) -> Result<serde_json::Value, String> {
        let mut line = Vec::new();
        let mut total = 0usize;
        loop {
            if Instant::now() >= deadline {
                return Err("native helper observation deadline".into());
            }
            let stdout = self.stdout.as_mut().ok_or("native helper stdout absent")?;
            let mut poll = libc::pollfd {
                fd: stdout.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let count = unsafe { libc::poll(&mut poll, 1, 10) };
            if count < 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            if count == 0 {
                continue;
            }
            let mut byte = [0];
            let count = stdout.read(&mut byte).map_err(|e| e.to_string())?;
            if count == 0 {
                return Err("native helper closed observation stream".into());
            }
            total += 1;
            if total > 65536 {
                return Err("native helper observation exceeds bound".into());
            }
            if byte[0] == b'\n' {
                let text = std::str::from_utf8(&line).map_err(|e| e.to_string())?;
                if let Some((_, value)) = text.split_once(marker) {
                    memcordon_core::canonical_json::reject_duplicate_json_keys(value.as_bytes())?;
                    return serde_json::from_str(value).map_err(|e| e.to_string());
                }
                line.clear();
            } else {
                line.push(byte[0]);
            }
        }
    }
    pub(super) fn settle(&mut self, deadline: Instant) -> Result<(), String> {
        use std::os::unix::process::ExitStatusExt;
        let mut failures = Vec::new();
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                if let Some(pidfd) = &self.pidfd {
                    if unsafe {
                        libc::syscall(
                            libc::SYS_pidfd_send_signal,
                            pidfd.as_raw_fd(),
                            libc::SIGKILL,
                            std::ptr::null::<libc::siginfo_t>(),
                            0,
                        )
                    } < 0
                    {
                        let error = std::io::Error::last_os_error();
                        if error.raw_os_error() != Some(libc::ESRCH) {
                            failures.push(error.to_string());
                        }
                    }
                } else if let Err(error) = self.child.kill() {
                    failures.push(error.to_string());
                }
            }
            Err(e) => failures.push(e.to_string()),
        }
        self.child.stdin.take();
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    let Some(pidfd) = &self.pidfd else {
                        failures
                            .push("helper reaped without acquired PIDFD; no native receipt".into());
                        break;
                    };
                    let mut poll = libc::pollfd {
                        fd: pidfd.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    if unsafe { libc::poll(&mut poll, 1, 0) } != 1
                        || poll.revents & libc::POLLIN == 0
                    {
                        failures.push("reaped helper PIDFD does not observe retirement".into());
                    } else {
                        self.retirement = Some(
                            serde_json::json!({"pid":self.child.id(),"birth":self.birth,"raw_wait_status":status.into_raw(),"exit_code":status.code(),"signal":status.signal(),"pidfd_retirement_observed":true}),
                        );
                    }
                    break;
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Ok(None) => {
                    failures.push("native helper reap deadline".into());
                    break;
                }
                Err(e) => {
                    failures.push(e.to_string());
                    break;
                }
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
#[ignore = "requires the original native job's actually installed owned V3 fixture"]
fn native_leased_release_emit_actual_component_receipt() {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Fixture {
        contract: memcordon_core::workload_contract_v3::WorkloadContractV3,
        registry: memcordon_core::workload_registry_v3::RuntimePrivatePolicyRegistryV3,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        run_id: String,
        recipe_id: String,
        native_target: String,
        artifact_root: std::path::PathBuf,
        artifact_prefix: String,
        challenge: [u8; 32],
        work_deadline_unix_millis: u64,
        cleanup_deadline_unix_millis: u64,
        fixture_path: std::path::PathBuf,
        fixture_sha256: String,
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(65537)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 65536);
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).unwrap();
    let input: Input = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert!(input.artifact_root.is_absolute());
    assert_ne!(input.challenge, [0; 32]);
    let fixture_bytes = crate::linux::protected_read::read_protected_absolute(
        &input.fixture_path,
        16 * 1024 * 1024,
        None,
    )
    .unwrap();
    use sha2::{Digest, Sha256};
    assert_eq!(hex(&Sha256::digest(&fixture_bytes)), input.fixture_sha256);
    memcordon_core::canonical_json::reject_duplicate_json_keys(&fixture_bytes).unwrap();
    let fixture: Fixture = serde_json::from_slice(&fixture_bytes).unwrap();
    assert!(
        !input.run_id.is_empty()
            && !input.recipe_id.is_empty()
            && !input.artifact_prefix.is_empty()
            && input
                .artifact_prefix
                .split('/')
                .all(|p| !p.is_empty() && p != "." && p != "..")
            && !input.artifact_prefix.contains(['\\', ':'])
    );
    assert_eq!(
        input.native_target,
        if cfg!(target_arch = "x86_64") {
            "x86_64-unknown-linux-gnu"
        } else if cfg!(target_arch = "aarch64") {
            "aarch64-unknown-linux-gnu"
        } else {
            panic!("native supported Linux host required")
        }
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    assert!(
        now < u128::from(input.work_deadline_unix_millis)
            && input.work_deadline_unix_millis < input.cleanup_deadline_unix_millis
    );
    let work = Instant::now()
        + Duration::from_millis(
            (u128::from(input.work_deadline_unix_millis) - now)
                .try_into()
                .unwrap(),
        );
    let cleanup = Instant::now()
        + Duration::from_millis(
            (u128::from(input.cleanup_deadline_unix_millis) - now)
                .try_into()
                .unwrap(),
        );
    let retain = |name: &str, bytes: &[u8]| -> Result<String, String> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(input.artifact_root.join(name))
            .map_err(|e| e.to_string())?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| e.to_string())?;
        Ok(format!("{}/{name}", input.artifact_prefix))
    };
    let fixture_artifact = retain("release-fixture.json", &fixture_bytes).unwrap();
    let mut helpers = Vec::<HeldHelper>::new();
    let mut observations = Vec::new();
    let result = (|| -> Result<(), String> {
        HeldHelper::start(&mut helpers, 65534, 65534, &input.challenge, work)
            .map_err(|error| release_failure("setup", "start caller helper", error))?;
        let cwd = std::fs::File::open("/")
            .map_err(|error| release_failure("setup", "open caller cwd", error))?;
        let mut contract = fixture.contract.clone();
        for stale in [true, false] {
            let scenario = if stale { "stale" } else { "current" };
            use sha2::{Digest, Sha256};
            let mut hash = Sha256::new();
            hash.update(input.challenge);
            hash.update([u8::from(stale)]);
            let digest = hash.finalize();
            let mut attempt = [0u8; 16];
            attempt.copy_from_slice(&digest[..16]);
            let caller = crate::linux::envelope::capture(
                helpers[0].child.id() as i32,
                65534,
                65534,
                &[],
                cwd.as_fd(),
            )
            .map_err(|error| release_failure(scenario, "capture caller envelope", error))?;
            let frontend = crate::linux::private_attempt::ProcessIdentityV4::observe(
                helpers[0].child.id() as i32,
                helpers[0]
                    .pidfd
                    .as_ref()
                    .ok_or("caller PIDFD absent")?
                    .as_fd(),
            )
            .map_err(|error| release_failure(scenario, "observe frontend identity", error))?;
            let worker_pid = std::process::id();
            let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, worker_pid, 0) } as i32;
            if raw < 0 {
                return Err(release_failure(
                    scenario,
                    "open worker PIDFD",
                    std::io::Error::last_os_error(),
                ));
            }
            let worker_fd = unsafe { OwnedFd::from_raw_fd(raw) };
            let worker = crate::linux::private_attempt::ProcessIdentityV4::observe(
                worker_pid as i32,
                worker_fd.as_fd(),
            )
            .map_err(|error| release_failure(scenario, "observe worker identity", error))?;
            let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map_err(|error| release_failure(scenario, "read boot identity", error))?;
            let mut record = crate::linux::private_attempt::PrivateAttemptRecordV4::allocated(
                memcordon_core::BoundedText::new(&hex(&attempt)).map_err(str::to_owned)?,
                memcordon_core::BoundedText::new(boot.trim()).map_err(str::to_owned)?,
                frontend,
                memcordon_core::DiagnosticSha256::from_bytes(caller.envelope.digest()),
            )?;
            let launch = crate::request::LaunchRequestV2 {
                restart_attempt: 0,
                workload_contract: None,
                program: contract.launch.entrypoint.as_str().as_bytes().to_vec(),
                arguments: Vec::new(),
                environment: Vec::new(),
                policy: crate::request::LaunchPolicyV2 {
                    memory_limit_bytes: Some(1024 * 1024 * 1024),
                    swap_limit: crate::request::SwapLimit::Bytes(0),
                    absolute_deadline_millis: None,
                    deadline_scope: crate::request::DeadlineScope::Attempt,
                    lifetime: crate::request::Lifetime::Workload,
                    poll_interval_millis: 10,
                    signal_grace_millis: 100,
                    command_exit_grace_millis: 100,
                    limit_grace_millis: 100,
                },
                descriptors: vec![
                    crate::request::DescriptorPurpose::CurrentDirectory,
                    crate::request::DescriptorPurpose::Stdin,
                    crate::request::DescriptorPurpose::Stdout,
                    crate::request::DescriptorPurpose::Stderr,
                    crate::request::DescriptorPurpose::FrontendLiveness,
                ],
            };
            let mut journal = None;
            let mut admission =
                crate::linux::mixed_admission::MixedOperationalAdmission::authenticate_component(
                    contract.clone(),
                    launch,
                    caller,
                    attempt,
                    |metadata| {
                        record.mixed_admission_metadata = Some(metadata.clone());
                        record.mixed_worker = Some(worker);
                        journal = Some(
                            crate::linux::private_attempt::DurablePrivateAttempt::create(record)
                                .map_err(|error| {
                                    release_failure(scenario, "publish ownership journal", error)
                                })?,
                        );
                        Ok(())
                    },
                )
                .map_err(|error| release_failure(scenario, "authenticate admission", error))?;
            let metadata = admission.component_metadata().clone();
            let uid = admission.component_target_uid();
            let suffix = if stale { "stale" } else { "current" };
            let effective_invocation = retain(
                &format!("{suffix}-effective-invocation.bin"),
                &admission
                    .component_effective_invocation()
                    .map_err(|error| {
                        release_failure(scenario, "encode effective invocation", error)
                    })?,
            )
            .map_err(|error| release_failure(scenario, "retain effective invocation", error))?;
            let journal_before = journal
                .as_ref()
                .ok_or("actual ownership journal absent")?
                .component_native_bytes()
                .map_err(|error| release_failure(scenario, "read original journal", error))?;
            let reference_before = admission
                .component_reference_bytes()
                .map_err(|error| release_failure(scenario, "read admission reference", error))?;
            let reference_native_before = admission
                .component_reference_observation()
                .map_err(|error| release_failure(scenario, "observe admission reference", error))?;
            let journal_before_path =
                retain(&format!("{suffix}-journal-before.bin"), &journal_before)
                    .map_err(|error| release_failure(scenario, "retain original journal", error))?;
            let reference_path = retain(&format!("{suffix}-reference.json"), &reference_before)
                .map_err(|error| release_failure(scenario, "retain admission reference", error))?;
            let account = fixture
                .registry
                .execution_identities
                .as_slice()
                .iter()
                .find(|a| a.uid.get() == uid)
                .ok_or("actual exclusive account definition absent")?;
            let target =
                HeldHelper::start(&mut helpers, uid, account.gid.get(), &input.challenge, work)
                    .map_err(|error| release_failure(scenario, "start target helper", error))?;
            let before = crate::policy_registry::native::Lease::acquire()
                .map_err(|error| release_failure(scenario, "acquire policy lease", error))?
                .read_v3()
                .map_err(|error| release_failure(scenario, "read policy activation", error))?
                .ok_or("actual V3 activation absent")?;
            if before.registry != fixture.registry || before.epoch != metadata.epoch {
                return Err("actual native setup activation differs".into());
            }
            let after = if stale {
                crate::policy_registry::native::Lease::acquire()
                    .map_err(|error| {
                        release_failure(scenario, "acquire stale policy lease", error)
                    })?
                    .activate_v3(fixture.registry.clone(), None)
                    .map_err(|error| release_failure(scenario, "activate stale policy", error))?
            } else {
                before.clone()
            };
            let mut callbacks = 0u32;
            let release = admission.component_release(helpers[target].child.id(), || {
                callbacks += 1;
                helpers[target]
                    .child
                    .stdin
                    .as_mut()
                    .ok_or("target gate absent")?
                    .write_all(&[0xA5])
                    .map_err(|e| e.to_string())
            });
            let gate = if stale {
                let error = release
                    .err()
                    .ok_or("stale actual epoch unexpectedly released")?;
                if error.reason != memcordon_core::result_v2::MixedAdmissionRejectionV2::StaleEpoch
                    || error.detail != "mixed epoch/grant changed before release"
                    || callbacks != 0
                {
                    return Err(release_failure(
                        scenario,
                        "validate stale release refusal",
                        format!(
                            "reason={:?}; detail={}; callbacks={callbacks}",
                            error.reason, error.detail
                        ),
                    ));
                }
                let mut poll = libc::pollfd {
                    fd: helpers[target]
                        .stdout
                        .as_ref()
                        .ok_or("target stdout absent")?
                        .as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                if unsafe { libc::poll(&mut poll, 1, 0) } != 0 {
                    return Err("unreleased target emitted gate bytes".into());
                }
                serde_json::json!({"refusal":error.detail,"received":[],"callbacks":callbacks})
            } else {
                release.map_err(|failure| {
                    release_failure(scenario, "release target gate", failure.detail)
                })?;
                let observed = helpers[target]
                    .message("MC-NATIVE-RELEASE-GATE ", work)
                    .map_err(|error| release_failure(scenario, "observe target gate", error))?;
                if callbacks != 1
                    || observed["pid"] != helpers[target].child.id()
                    || observed["birth"] != helpers[target].birth
                    || observed["challenge"] != hex(&input.challenge)
                    || observed["received"] != serde_json::json!([165])
                {
                    return Err("actual native gate receipt differs".into());
                }
                serde_json::json!({"refusal":null,"received":observed["received"],"callbacks":callbacks})
            };
            let journal_after = journal
                .as_ref()
                .ok_or("actual ownership journal absent")?
                .component_native_bytes()
                .map_err(|error| release_failure(scenario, "read post-release journal", error))?;
            let reference_after = admission
                .component_reference_bytes()
                .map_err(|error| release_failure(scenario, "read post-release reference", error))?;
            if journal_after != journal_before || reference_after != reference_before {
                return Err("inner leased callback changed ownership evidence".into());
            }
            let journal_after_path = retain(&format!("{suffix}-journal-after.bin"), &journal_after)
                .map_err(|error| release_failure(scenario, "retain post-release journal", error))?;
            helpers[target]
                .settle(cleanup)
                .map_err(|error| release_failure(scenario, "settle target helper", error))?;
            admission
                .retire_component_admission()
                .map_err(|error| release_failure(scenario, "retire admission", error))?;
            let reference_native_after = admission
                .component_reference_observation()
                .map_err(|error| release_failure(scenario, "observe retired reference", error))?;
            journal
                .take()
                .ok_or("actual ownership journal absent")?
                .retire_unallocated()
                .map_err(|error| release_failure(scenario, "retire unallocated journal", error))?;
            observations.push(serde_json::json!({"scenario":if stale{"stale-epoch-refused"}else{"current-epoch-released"},"metadata":metadata,"effective_invocation":effective_invocation,"journal_before":journal_before_path,"journal_after":journal_after_path,"reference":reference_path,"reference_native_before":reference_native_before,"reference_native_after":reference_native_after,"activation_before":before,"activation_after":after,"target_pid":helpers[target].child.id(),"target_birth":helpers[target].birth,"target_retirement":helpers[target].retirement,"gate":gate,"private_root_materialized":false}));
            contract.expected_epoch = after.epoch;
        }
        Ok(())
    })();
    let mut failures = Vec::new();
    if let Err(error) = result {
        failures.push(error);
    }
    for helper in &mut helpers {
        if let Err(error) = helper.settle(cleanup) {
            failures.push(error);
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("; "));
    let image = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    let receipt = serde_json::json!({"format":"memcordon.linux-leased-release-component","revision":1,"run_id":input.run_id,"recipe_id":input.recipe_id,"native_target":input.native_target,"test_name":"native_mixed_release::native_leased_release_emit_actual_component_receipt","executable_sha256":hex(&Sha256::digest(image)),"challenge_sha256":hex(&Sha256::digest(input.challenge)),"fixture":fixture_artifact,"fixture_sha256":input.fixture_sha256,"scope":"inner-leased-callback-no-private-root","observations":observations,"helper_retirement":helpers.iter().map(|helper|helper.retirement.clone().expect("successful settlement captured actual wait/PIDFD receipt")).collect::<Vec<_>>()});
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(input.artifact_root.join("release-native-receipt.json"))
        .unwrap();
    file.write_all(&serde_json::to_vec(&receipt).unwrap())
        .unwrap();
    file.sync_all().unwrap();
    std::fs::File::open(&input.artifact_root)
        .unwrap()
        .sync_all()
        .unwrap();
}

#[test]
#[ignore = "only launched through an explicitly retained native component owner"]
fn native_owned_release_gate_helper() {
    let mut challenge = [0u8; 32];
    std::io::stdin().read_exact(&mut challenge).unwrap();
    assert_ne!(challenge, [0; 32]);
    let pid = std::process::id();
    let birth = crate::linux::envelope::process_start_time(pid as i32).unwrap();
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    assert_ne!(uid, 0);
    assert_ne!(gid, 0);
    let challenge = challenge
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    println!(
        "MC-NATIVE-RELEASE-READY {}",
        serde_json::json!({"pid":pid,"birth":birth,"uid":uid,"gid":gid,"challenge":challenge})
    );
    std::io::stdout().flush().unwrap();
    let mut gate = [0u8; 1];
    std::io::stdin().read_exact(&mut gate).unwrap();
    assert_eq!(gate, [0xA5]);
    println!(
        "MC-NATIVE-RELEASE-GATE {}",
        serde_json::json!({"pid":pid,"birth":birth,"challenge":challenge,"received":gate})
    );
    std::io::stdout().flush().unwrap();
}
