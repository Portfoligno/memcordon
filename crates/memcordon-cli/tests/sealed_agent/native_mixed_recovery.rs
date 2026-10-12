//! Actual internal native retirement boundary; the parent owns crash/recovery.
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

#[path = "native_recovery_streams.rs"]
mod native_recovery_streams;

#[test]
#[ignore = "original native administrator fixture and retained crash parent required"]
fn native_account_retirement_boundary_emit_actual_receipt() {
    run_recovery_component(false);
}

#[test]
#[ignore = "original native administrator fixture and retained native parent required"]
fn native_lost_terminal_response_emit_actual_receipt() {
    run_recovery_component(true);
}

fn run_recovery_component(lost_terminal: bool) {
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
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Fixture {
        contract: memcordon_core::workload_contract_v3::WorkloadContractV3,
        registry: memcordon_core::workload_registry_v3::RuntimePrivatePolicyRegistryV3,
    }
    let mut input_bytes = Vec::new();
    std::io::stdin()
        .take(65537)
        .read_to_end(&mut input_bytes)
        .unwrap();
    assert!(input_bytes.len() <= 65536);
    memcordon_core::canonical_json::reject_duplicate_json_keys(&input_bytes).unwrap();
    let input: Input = serde_json::from_slice(&input_bytes).unwrap();
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert!(input.artifact_root.is_absolute());
    assert_ne!(input.challenge, [0; 32]);
    assert!(
        !input.run_id.is_empty()
            && !input.recipe_id.is_empty()
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
            panic!("supported native Linux required")
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
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let fixture_bytes = crate::linux::protected_read::read_protected_absolute(
        &input.fixture_path,
        16 * 1024 * 1024,
        None,
    )
    .unwrap();
    assert_eq!(hex(&Sha256::digest(&fixture_bytes)), input.fixture_sha256);
    memcordon_core::canonical_json::reject_duplicate_json_keys(&fixture_bytes).unwrap();
    let fixture: Fixture = serde_json::from_slice(&fixture_bytes).unwrap();
    let retain = |name: &str, bytes: &[u8]| -> Result<String, String> {
        let staging = input.artifact_root.join(format!(".{name}.pending"));
        let named = input.artifact_root.join(name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging)
            .map_err(|e| e.to_string())?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| e.to_string())?;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let parent = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&input.artifact_root)
            .map_err(|e| e.to_string())?;
        let staged_name =
            std::ffi::CString::new(format!(".{name}.pending")).map_err(|e| e.to_string())?;
        let published_name = std::ffi::CString::new(name).map_err(|e| e.to_string())?;
        if unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                parent.as_raw_fd(),
                staged_name.as_ptr(),
                parent.as_raw_fd(),
                published_name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        use std::os::unix::fs::MetadataExt;
        let held = file.metadata().map_err(|e| e.to_string())?;
        let current = std::fs::symlink_metadata(&named).map_err(|e| e.to_string())?;
        if (held.dev(), held.ino(), held.nlink()) != (current.dev(), current.ino(), 1) {
            return Err("native boundary publication inode/links differ".into());
        }
        parent.sync_all().map_err(|e| e.to_string())?;
        Ok(format!("{}/{name}", input.artifact_prefix))
    };
    let mut helpers = Vec::new();
    let mut completed_export = None;
    let outcome = (|| -> Result<(), String> {
        // The measured libtest image is not the installed package authority.
        // Ask the genuine, protected installed executable to verify itself
        // before creating any admission or account reservation.
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let agent_path = std::path::Path::new("/usr/libexec/memcordon-sealed-agent");
        let agent_handle = std::fs::File::options()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(agent_path)
            .map_err(|error| error.to_string())?;
        let agent_identity = agent_handle.metadata().map_err(|error| error.to_string())?;
        let agent = crate::linux::protected_read::read_protected_absolute(
            agent_path,
            128 * 1024 * 1024,
            Some(0o755),
        )?;
        let before = std::fs::symlink_metadata(agent_path).map_err(|error| error.to_string())?;
        if !agent_identity.is_file()
            || !before.is_file()
            || (
                agent_identity.dev(),
                agent_identity.ino(),
                agent_identity.nlink(),
            ) != (before.dev(), before.ino(), 1)
        {
            return Err("installed provider pin differs before genuine verification".into());
        }
        let mut command = std::process::Command::new(agent_path);
        command.args(["package", "verify", "--json"]);
        let verified = memcordon_testkit::run_with_deadline_output_limit(
            &mut command,
            work.saturating_duration_since(Instant::now()),
            1024 * 1024,
        )
        .map_err(|error| format!("installed provider verification: {error}"))?;
        retain("installed-provider-verify-stdout.bin", &verified.stdout)?;
        retain("installed-provider-verify-stderr.bin", &verified.stderr)?;
        retain(
            "installed-provider-verify-status.json",
            &serde_json::to_vec(&serde_json::json!({
                "code": verified.status.code(),
                "success": verified.status.success(),
            }))
            .map_err(|error| error.to_string())?,
        )?;
        if !verified.status.success() || !verified.stderr.is_empty() {
            return Err(
                "genuine installed provider verification failed; actual capture retained".into(),
            );
        }
        memcordon_core::canonical_json::reject_duplicate_json_keys(&verified.stdout)?;
        let inspection: crate::inspection_schema::InstalledProviderInspection =
            serde_json::from_slice(&verified.stdout).map_err(|error| error.to_string())?;
        let current = std::fs::symlink_metadata(agent_path).map_err(|error| error.to_string())?;
        let held = agent_handle.metadata().map_err(|error| error.to_string())?;
        if (
            agent_identity.dev(),
            agent_identity.ino(),
            agent_identity.nlink(),
        ) != (held.dev(), held.ino(), held.nlink())
            || (held.dev(), held.ino(), held.nlink()) != (current.dev(), current.ino(), 1)
            || agent
                != crate::linux::protected_read::read_protected_absolute(
                    agent_path,
                    128 * 1024 * 1024,
                    Some(0o755),
                )?
        {
            return Err("installed provider image changed during genuine verification".into());
        }
        let manifest_bytes = crate::linux::runtime_manifest::source(agent_path, &agent)?;
        let manifest = memcordon_core::runtime_manifest::RuntimeManifest::parse(&manifest_bytes)?;
        let agent_digest = hex(&Sha256::digest(&agent));
        if !inspection.installed_artifacts_valid
            || !inspection.agent.compiled_metadata_valid
            || inspection.agent.executable_sha256 != agent_digest
            || inspection.installed_executable_sha256 != agent_digest
            || inspection.agent.version != manifest.version
            || inspection.agent.source_commit != manifest.source_commit
        {
            return Err(
                "genuine installed provider inspection differs from protected image/manifest"
                    .into(),
            );
        }
        let provider = manifest.public_binding(&manifest_bytes)?;
        super::native_mixed_release::HeldHelper::start(
            &mut helpers,
            65534,
            65534,
            &input.challenge,
            work,
        )?;
        let (mut frontend_capture, [stdin, stdout, stderr]) =
            native_recovery_streams::Capture::acquire(&input.artifact_root, work)?;
        let fixture_artifact = retain("recovery-fixture.json", &fixture_bytes)?;
        let cwd = std::fs::File::open("/").map_err(|e| e.to_string())?;
        let caller = crate::linux::envelope::capture(
            helpers[0].child.id() as i32,
            65534,
            65534,
            &[],
            cwd.as_fd(),
        )?;
        let frontend = crate::linux::private_attempt::ProcessIdentityV4::observe(
            helpers[0].child.id() as i32,
            helpers[0]
                .pidfd
                .as_ref()
                .ok_or("caller PIDFD absent")?
                .as_fd(),
        )?;
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) } as i32;
        if raw < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let worker_fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let worker = crate::linux::private_attempt::ProcessIdentityV4::observe(
            std::process::id() as i32,
            worker_fd.as_fd(),
        )?;
        let digest = Sha256::digest(input.challenge);
        let mut attempt = [0; 16];
        attempt.copy_from_slice(&digest[..16]);
        let attempt_text = hex(&attempt);
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|e| e.to_string())?;
        let record = crate::linux::private_attempt::PrivateAttemptRecordV4::allocated(
            memcordon_core::BoundedText::new(&attempt_text).map_err(str::to_owned)?,
            memcordon_core::BoundedText::new(boot.trim()).map_err(str::to_owned)?,
            frontend,
            memcordon_core::DiagnosticSha256::from_bytes(caller.envelope.digest()),
        )?;
        let launch = crate::request::LaunchRequestV2 {
            restart_attempt: 0,
            workload_contract: None,
            program: fixture
                .contract
                .launch
                .entrypoint
                .as_str()
                .as_bytes()
                .to_vec(),
            arguments: vec![
                b"bytes-argv-status".to_vec(),
                hex(&input.challenge).into_bytes(),
                b"0".to_vec(),
            ],
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
        let activation = crate::policy_registry::native::Lease::acquire()?
            .read_v3()?
            .ok_or("actual activation absent")?;
        if activation.registry != fixture.registry {
            return Err("component fixture actual registry differs".into());
        }
        let mut current_contract = fixture.contract.clone();
        current_contract.expected_epoch = activation.epoch.clone();
        current_contract.validate()?;
        let current_contract_path = retain(
            "current-contract.json",
            &serde_json::to_vec(&current_contract).map_err(|e| e.to_string())?,
        )?;
        let activation_path = retain(
            "current-activation.json",
            &serde_json::to_vec(&activation).map_err(|e| e.to_string())?,
        )?;
        let native_launch =
            crate::request::encode_launch_request(&launch).map_err(|e| format!("{e:?}"))?;
        let terminal_request = memcordon_core::mixed_runtime::MixedRuntimeRequest {
            format: "memcordon.mixed-runtime-request".into(),
            revision: 2,
            contract: current_contract.clone(),
            native_launch,
            attempt_deadline_millis: None,
        }
        .encode()?;
        let mut journal = None;
        let mut admission =
            crate::linux::mixed_admission::MixedOperationalAdmission::authenticate_component(
                current_contract,
                launch,
                caller,
                attempt,
                |metadata| {
                    journal =
                        Some(crate::linux::private_attempt::DurablePrivateAttempt::create(record)?);
                    journal
                        .as_mut()
                        .expect("original native journal retained")
                        .attach_mixed_admission_metadata(metadata.clone())?;
                    journal
                        .as_mut()
                        .expect("original native journal retained")
                        .record_mixed_worker(worker.clone())?;
                    Ok(())
                },
            )?;
        let mut owner = crate::linux::private_lifecycle::PrivateAttemptOwner::new(
            journal.take().ok_or("actual native journal absent")?,
        )?;
        let metadata = admission.component_metadata().clone();
        let mut retained_export_receipt = None;
        let (execution,retirement)=owner.component_execute_to_pre_account(&mut admission,provider.clone(),attempt,worker_fd.as_fd(),[stdin,stdout,stderr],work,cleanup,&mut |finished| frontend_capture.observe(finished),&mut |owner,admission,prepared|{
                retain("native-prepared.json",&serde_json::to_vec(prepared).map_err(|e|e.to_string())?)?;
                let native=owner.component_pre_account_observation(admission)?;
                let export_path=native["export_path"].as_str().ok_or("native boundary export owner path absent")?;
                let export_bytes=crate::linux::protected_read::read_protected_absolute(
                    &std::path::Path::new(export_path).join("export-receipt.json"),16*1024*1024,None)?;
                retain("export-receipt.json",&export_bytes)?;
                retained_export_receipt=Some(export_bytes);
                let ownership=owner.component_account_ownership(admission)?;
                retain("account-ownership.json",&serde_json::to_vec(&ownership).map_err(|error|error.to_string())?)?;
                let journal=retain("boundary-journal.bin",&owner.component_native_journal_bytes()?)?;let reference=retain("boundary-reference.json",&admission.component_reference_bytes()?)?;
                retain("account-boundary.json",&serde_json::to_vec(&serde_json::json!({"format":"memcordon.linux-pre-account-native-boundary","revision":1,"run_id":input.run_id,"recipe_id":input.recipe_id,"native_target":input.native_target,"test_name":if lost_terminal{"native_mixed_recovery::native_lost_terminal_response_emit_actual_receipt"}else{"native_mixed_recovery::native_account_retirement_boundary_emit_actual_receipt"},"worker":worker,"challenge_sha256":hex(&Sha256::digest(input.challenge)),"fixture":fixture_artifact,"fixture_sha256":input.fixture_sha256,"current_contract":current_contract_path,"actual_activation":activation_path,"journal":journal,"reference":reference,"native":native,"work_deadline_unix_millis":input.work_deadline_unix_millis,"cleanup_deadline_unix_millis":input.cleanup_deadline_unix_millis})).map_err(|e|e.to_string())?)?;
                if lost_terminal{return Ok(());}
                while Instant::now()<work{std::thread::sleep(Duration::from_millis(10));}
                Err("original crash parent did not terminate held boundary worker before work cutoff".into())
            })?;
        if !lost_terminal {
            return Err("crash boundary unexpectedly returned".into());
        }
        let request_bytes = terminal_request;
        let export_retirement = retirement.clone();
        let request = crate::protocol::Frame {
            kind: crate::protocol::MessageKind::MixedLaunch,
            nonce: input.challenge[..16]
                .try_into()
                .map_err(|_| "challenge nonce width")?,
            attempt_id: attempt,
            payload: request_bytes.clone(),
        };
        let frame = crate::linux::mixed_runtime::component_terminal(
            &request,
            memcordon_core::result_v2::MixedRuntimeOutcomeV2::Executed {
                admission: metadata,
                request_bytes_sha256: memcordon_core::workload_codec::hash_bytes(&request_bytes),
                provider,
                execution,
                retirement,
            },
        )?;
        let actual_carrier: memcordon_core::result_v2::MixedRuntimeCarrierV2 =
            serde_json::from_slice(&frame.payload).map_err(|e| e.to_string())?;
        actual_carrier.validate()?;
        let carrier = retain("completed-terminal-carrier.json", &frame.payload)?;
        let request_path = retain("terminal-request.json", &request_bytes)?;
        let (sender, peer) = std::os::unix::net::UnixStream::pair().map_err(|e| e.to_string())?;
        peer.shutdown(std::net::Shutdown::Both)
            .map_err(|e| e.to_string())?;
        drop(peer);
        struct NativeDelivery {
            stream: std::os::unix::net::UnixStream,
            errno: Option<i32>,
        }
        impl Write for NativeDelivery {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let result = self.stream.write(bytes);
                if let Err(error) = &result {
                    self.errno = error.raw_os_error();
                }
                result
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.stream.flush()
            }
        }
        let mut sender = NativeDelivery {
            stream: sender,
            errno: None,
        };
        let error = crate::protocol::write_frame(&mut sender, &frame)
            .err()
            .ok_or("closed native terminal peer unexpectedly accepted delivery")?;
        let native_errno = sender
            .errno
            .ok_or("terminal protocol failed without actual native write errno")?;
        retain("lost-terminal-native-receipt.json",&serde_json::to_vec(&serde_json::json!({"format":"memcordon.linux-lost-terminal-component","revision":1,"run_id":input.run_id,"recipe_id":input.recipe_id,"native_target":input.native_target,"test_name":"native_mixed_recovery::native_lost_terminal_response_emit_actual_receipt","worker":worker,"challenge_sha256":hex(&Sha256::digest(input.challenge)),"carrier":carrier,"request":request_path,"delivery_error":format!("{error:?}"),"native_errno":native_errno,"work_deadline_unix_millis":input.work_deadline_unix_millis,"cleanup_deadline_unix_millis":input.cleanup_deadline_unix_millis})).map_err(|e|e.to_string())?)?;
        completed_export = Some((
            owner,
            export_retirement,
            retained_export_receipt.ok_or("original retained export receipt absent")?,
        ));
        Ok(())
    })();
    let mut failures = Vec::new();
    if let Err(error) = outcome {
        failures.push(error);
    }
    for helper in &mut helpers {
        if let Err(error) = helper.settle(cleanup) {
            failures.push(error);
        }
    }
    if lost_terminal {
        if failures.is_empty() {
            match completed_export.as_mut() {
                Some((owner, retirement, receipt)) => {
                    match owner.component_retire_empty_export(retirement, receipt, cleanup) {
                        Ok(observation) => match serde_json::to_vec(&observation) {
                            Ok(bytes) => {
                                if let Err(error) = retain("empty-export-retirement.json", &bytes) {
                                    failures.push(error);
                                }
                            }
                            Err(error) => failures.push(error.to_string()),
                        },
                        Err(error) => failures.push(error),
                    }
                }
                None => failures.push("original completed export owner absent".into()),
            }
        }
        if failures.is_empty() {
            let retirements = helpers
                .iter()
                .map(|helper| {
                    helper
                        .retirement
                        .clone()
                        .ok_or("actual caller helper retirement absent")
                })
                .collect::<Result<Vec<_>, _>>();
            match retirements {
                Ok(retirements) => match serde_json::to_vec(&retirements) {
                    Ok(bytes) => {
                        if let Err(error) = retain("lost-terminal-helper-retirements.json", &bytes)
                        {
                            failures.push(error);
                        }
                    }
                    Err(error) => failures.push(error.to_string()),
                },
                Err(error) => failures.push(error.into()),
            }
        }
        assert!(
            failures.is_empty(),
            "native lost-terminal component: {}",
            failures.join("; ")
        );
    } else {
        panic!(
            "native crash harness must be terminated by retained parent: {}",
            failures.join("; ")
        );
    }
}
