//! Current installed owner interventions against original held native attempts.
use super::{artifacts, linux_request_fixture::CallerSession, linux_test_execution::CallerImages};
use crate::{CiError, Result};
use serde_json::json;
use std::{collections::BTreeMap, fs, io::Write, path::Path, time::Instant};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeInput {
    format: String,
    revision: u32,
    operation: String,
    association: memcordon_core::workload_request::WorkloadAttemptAssociationV1,
    cutoff_millis: u64,
}

/// Unprivileged current-wire peer. It owns only its ordinary connection and
/// cannot turn a descriptive locator into a live attempt owner.
pub fn probe(input: &Path, output: &Path) -> Result<()> {
    use std::{
        io::Read,
        os::unix::{fs::OpenOptionsExt, net::UnixStream},
        time::Duration,
    };
    if rustix::process::geteuid().is_root() {
        return Err(CiError::Message(
            "foreign current probe must run under its actual ordinary OS user".into(),
        ));
    }
    let bytes = if input == Path::new("-") {
        let mut bytes = Vec::new();
        std::io::stdin().take(65537).read_to_end(&mut bytes)?;
        bytes
    } else {
        artifacts::read_file(input)?
    };
    if bytes.len() > 65536 {
        return Err(CiError::Message(
            "current peer probe input exceeds request bound".into(),
        ));
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).map_err(CiError::Message)?;
    let request: ProbeInput = serde_json::from_slice(&bytes)?;
    request
        .association
        .validate()
        .map_err(|error| CiError::Message(error.to_string()))?;
    if request.format != "memcordon.native-owner-request" || request.revision != 1 {
        return Err(CiError::Message(
            "unsupported current peer probe input".into(),
        ));
    }
    let now = super::linux_test_images::monotonic_millis()?;
    let remaining = request
        .cutoff_millis
        .checked_sub(now)
        .filter(|value| *value > 0 && *value <= 30 * 1000)
        .ok_or_else(|| CiError::Message("original peer probe deadline exhausted".into()))?;
    let timeout = Duration::from_millis(remaining.min(10000));
    let mut observation = json!({"format":"memcordon.native-owner-probe","revision":1,"operation":request.operation,"association":request.association,"uid":rustix::process::getuid().as_raw(),"euid":rustix::process::geteuid().as_raw(),"gid":rustix::process::getgid().as_raw(),"pid":std::process::id(),"birth":crate::linux_consumer_readiness::process_birth(std::process::id()).map_err(CiError::Message)?,"connected":false,"request_bytes":null,"response_bytes":null,"errno":null,"opened":null});
    if request.operation == "inspect" {
        let path = Path::new("/var/lib/memcordon/workload-attempts")
            .join(hex::encode(request.association.attempt));
        match fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(_) => observation["opened"] = json!(true),
            Err(error) => {
                observation["opened"] = json!(false);
                observation["errno"] = json!(error.raw_os_error());
            }
        }
    } else {
        let (kind, payload) = match request.operation.as_str() {
            "cancel" => (35_u16, Vec::new()),
            "recover" => (40_u16, serde_json::to_vec(&request.association)?),
            _ => {
                return Err(CiError::Message(
                    "unsupported current peer operation".into(),
                ));
            }
        };
        let mut frame = Vec::new();
        frame.extend(5_u16.to_be_bytes());
        frame.extend(kind.to_be_bytes());
        frame.extend(
            u32::try_from(72 + payload.len())
                .map_err(|error| CiError::Message(error.to_string()))?
                .to_be_bytes(),
        );
        frame.extend(request.association.challenge);
        frame.extend(request.association.attempt);
        frame.extend(
            hex::decode(artifacts::checksum(&payload))
                .map_err(|error| CiError::Message(error.to_string()))?,
        );
        frame.extend(payload);
        observation["request_bytes"] = json!(frame);
        match UnixStream::connect("/run/memcordon/sealed-agent.sock") {
            Ok(mut stream) => {
                observation["connected"] = json!(true);
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))?;
                let result = (|| -> std::io::Result<Vec<u8>> {
                    stream.write_all(&frame)?;
                    let mut header = [0u8; 72];
                    stream.read_exact(&mut header)?;
                    let length =
                        u32::from_be_bytes(header[4..8].try_into().expect("fixed header")) as usize;
                    if !(72..=65536).contains(&length) {
                        return Err(std::io::Error::other(
                            "current peer response length invalid",
                        ));
                    }
                    let mut reply = header.to_vec();
                    reply.resize(length, 0);
                    stream.read_exact(&mut reply[72..])?;
                    Ok(reply)
                })();
                match result {
                    Ok(reply) => observation["response_bytes"] = json!(reply),
                    Err(error) => observation["errno"] = json!(error.raw_os_error()),
                }
            }
            Err(error) => observation["errno"] = json!(error.raw_os_error()),
        }
    }
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(output)?;
    file.write_all(&serde_json::to_vec(&observation)?)?;
    file.sync_all()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn owner_probe(
    scenario: &str,
    caller: &CallerSession,
    foreign: &CallerSession,
    probe: &Path,
    controller: &Path,
    working: &Path,
    association: &memcordon_core::workload_request::WorkloadAttemptAssociationV1,
    held: &[crate::linux_consumer_readiness::HeldLinuxProcess],
    cutoff: Instant,
) -> Result<BTreeMap<String, Vec<u8>>> {
    use std::{
        os::unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            process::ExitStatusExt,
        },
        time::Duration,
    };
    let selected = if scenario.starts_with("foreign-") {
        foreign
    } else {
        caller
    };
    let mut sent = association.clone();
    if scenario == "stale-attempt" {
        sent.attempt[0] ^= 1;
    }
    if scenario == "request-substitution" {
        sent.request_sha256 = memcordon_core::hash_bytes(b"different-current-request");
    }
    let now = super::linux_test_images::monotonic_millis()?;
    let millis = u64::try_from(
        cutoff
            .saturating_duration_since(Instant::now())
            .min(std::time::Duration::from_secs(30))
            .as_millis(),
    )
    .map_err(|error| CiError::Message(error.to_string()))?;
    let request = ProbeInput {
        format: "memcordon.native-owner-request".into(),
        revision: 1,
        operation: match scenario {
            "foreign-inspect" => "inspect",
            "foreign-cancel" => "cancel",
            _ => "recover",
        }
        .into(),
        association: sent,
        cutoff_millis: now
            .checked_add(millis)
            .ok_or_else(|| CiError::Message("original peer cutoff overflow".into()))?,
    };
    let input_bytes = serde_json::to_vec(&request)?;
    let input_path = controller.join(format!("peer-{scenario}-input.json"));
    let mut input = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&input_path)?;
    input.write_all(&input_bytes)?;
    input.sync_all()?;
    drop(input);
    let input = fs::File::open(input_path)?;
    let directory = working.join(format!("peer-{scenario}"));
    fs::create_dir(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    rustix::fs::chown(
        &directory,
        Some(rustix::process::Uid::from_raw(selected.uid)),
        Some(rustix::process::Gid::from_raw(selected.gid)),
    )
    .map_err(std::io::Error::from)?;
    let output = directory.join("response.json");
    let uid = selected.uid.to_string();
    let gid = selected.gid.to_string();
    let args: Vec<std::ffi::OsString> = vec![
        "--reuid".into(),
        uid.into(),
        "--regid".into(),
        gid.into(),
        "--init-groups".into(),
        "--".into(),
        probe.as_os_str().into(),
        "current-linux-owner-probe".into(),
        "--input".into(),
        "-".into(),
        "--output".into(),
        output.as_os_str().into(),
    ];
    let before: Vec<_> = held
        .iter()
        .map(|process| process.live_snapshot())
        .collect::<std::result::Result<_, _>>()
        .map_err(CiError::Message)?;
    let child = std::sync::Mutex::new(None);
    let observed =
        crate::command::CommandSpec::new("/usr/bin/setpriv", &directory, Duration::from_secs(30))
            .bounded_until(cutoff)
            .args(&args)
            .output_quiet_with_stdin_and_creation(&input, |process| {
                let birth = crate::linux_consumer_readiness::process_birth(process.id())
                    .map_err(CiError::Message)?;
                *child.lock().expect("original peer query holder") = Some(
                    crate::linux_consumer_readiness::HeldLinuxProcess::acquire(process.id(), birth)
                        .map_err(CiError::Message)?,
                );
                Ok(())
            })?;
    let child = child
        .into_inner()
        .expect("original peer query holder")
        .ok_or_else(|| CiError::Message("actual peer child was not held before input".into()))?;
    if !child.exited().map_err(CiError::Message)? {
        return Err(CiError::Message(
            "original peer child not retired after its direct wait".into(),
        ));
    }
    let after: Vec<_> = held
        .iter()
        .map(|process| process.live_snapshot())
        .collect::<std::result::Result<_, _>>()
        .map_err(CiError::Message)?;
    let image = artifacts::read_file(probe)?;
    let metadata = fs::symlink_metadata(probe)?;
    use std::os::unix::ffi::OsStrExt;
    let observation = json!({"format":"memcordon.current-owner-intervention","revision":1,"scenario":scenario,"original":association,"uid":selected.uid,"gid":selected.gid,"held_before":before,"held_after":after,
        "child":{"pid":child.process_id,"birth":child.birth,"held_before_input":true,"retired":true,"raw_wait_status":observed.status.into_raw()},"command":{"executable":"/usr/bin/setpriv","arguments":args.iter().map(|arg|arg.as_bytes().to_vec()).collect::<Vec<_>>()},"probe_image":{"uid":metadata.uid(),"mode":metadata.mode()&0o777,"links":metadata.nlink(),"sha256":artifacts::checksum(&image)}});
    Ok(BTreeMap::from([
        (
            "owner-intervention.json".into(),
            serde_json::to_vec(&observation)?,
        ),
        ("owner-input.json".into(), input_bytes),
        ("owner-response.json".into(), artifacts::read_file(&output)?),
        ("owner-stdout.bin".into(), observed.stdout),
        ("owner-stderr.bin".into(), observed.stderr),
    ]))
}

fn before_preparation_experiment(
    caller: &CallerSession,
    images: &CallerImages,
    provider: &memcordon_core::PublicProviderBindingV1,
    controller: &Path,
    directory: &Path,
    work: Instant,
    cleanup: Instant,
) -> Result<super::linux_test_lifetime::Experiment> {
    use super::{
        linux_current_phase_gate::{NativeNamespaceWatch, NativeReadGate},
        linux_request_launch::{LaunchInput, RequestLaunch},
    };
    use std::os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        process::ExitStatusExt,
    };
    let fixture = super::linux_test_lifetime::pack_experiment(caller, images, directory, work)?;
    let (memory, memory_bytes) = super::linux_snapshot_budget::memory_budget(
        &images.runtime,
        &images.input,
        128 * 1024 * 1024,
    )?;
    let bundle = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&fixture.bundle)?;
    let identity = bundle.metadata()?;
    let watcher = NativeNamespaceWatch::new(
        &[
            ("journal", Path::new("/var/lib/memcordon/workload-attempts")),
            (
                "input-staging",
                Path::new("/var/lib/memcordon/workload-inputs"),
            ),
            (
                "footprint",
                Path::new("/var/lib/memcordon/workload-resources"),
            ),
            ("root-staging", Path::new("/run/memcordon")),
            ("cgroup", Path::new("/sys/fs/cgroup/memcordon-sealed")),
        ],
        work,
    )
    .map_err(|error| {
        error.context(format!(
            "before-preparation namespace watch root={}",
            directory.display()
        ))
    })?;
    let namespace_before = watcher.snapshot()?;
    let gate = NativeReadGate::on_file(&bundle, caller.uid, work)?;
    let observations = directory.join("observations");
    fs::create_dir(&observations)?;
    fs::set_permissions(&observations, fs::Permissions::from_mode(0o700))?;
    rustix::fs::chown(
        &observations,
        Some(rustix::process::Uid::from_raw(caller.uid)),
        Some(rustix::process::Gid::from_raw(caller.gid)),
    )
    .map_err(std::io::Error::from)?;
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|error| CiError::Message(error.to_string()))?;
    let challenge = hex::encode(nonce);
    let arguments: Vec<std::ffi::OsString> = vec![
        "exec-held".into(),
        challenge.clone().into(),
        "/bin/owned-readiness".into(),
        "binary-file".into(),
        challenge.into(),
    ];
    use std::os::unix::ffi::OsStrExt;
    let invocation = json!({"format":"memcordon.current-preparation-invocation","revision":1,"installed_cli":caller.installed_cli,"caller_uid":caller.uid,"caller_gid":caller.gid,"memory_token":memory.as_bytes(),"memory_bytes":memory_bytes,"deadline_token":"+30s","lifetime":"command","request_path":fixture.request,"input_path":fixture.bundle,"entrypoint":"owned-readiness","arguments":arguments.iter().map(|value|value.as_bytes().to_vec()).collect::<Vec<_>>(),"report_format":"result-v3","request_sha256":fixture.request_sha256,"provider":provider});
    let mut launch = RequestLaunch::start(LaunchInput {
        extra_descriptor: None,
        lifetime: memcordon_core::Lifetime::Command,
        controller_directory: controller,
        observation_directory: Some(&observations),
        stdin: None,
        interactive: false,
        caller,
        fixture: &fixture,
        directory,
        provider,
        entrypoint: std::ffi::OsStr::new("owned-readiness"),
        arguments: &arguments,
        memory: memory.as_os_str(),
        deadline: std::ffi::OsStr::new("+30s"),
        output_directory: None,
        work_cutoff: work,
        cleanup_cutoff: cleanup,
    })?;
    let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<super::linux_test_lifetime::Experiment> {
            let mut frontend = launch
                .retain_frontend(work)?
                .duplicate_for_intervention(work)
                .map_err(|error| {
                    CiError::Message(format!("original pre-input frontend query hold: {error:?}"))
                })?;
            let mut permission = gate.wait_for(&frontend)?;
            if permission.process_id != frontend.process_id
                || permission.device != identity.dev()
                || permission.inode != identity.ino()
            {
                return Err(CiError::Message(
                    "input-open kernel event belongs to another original process/file".into(),
                ));
            }
            let image = frontend
                .hold_executable_image(work)
                .map_err(CiError::Message)?;
            let namespace_blocked = watcher.snapshot()?;
            let snapshot = frontend.live_snapshot().map_err(CiError::Message)?;
            let blocked = permission.observation();
            let mut action = json!({"format":"memcordon.current-before-preparation-action","revision":1,"frontend":{"pid":frontend.process_id,"birth":frontend.birth},"snapshot":snapshot,"image":image,"credentials":frontend.native_credentials().map_err(CiError::Message)?,"signal":2,"native_signal_result":null,"blocked":blocked});
            super::source::write_json(
                &controller.join("before-preparation-observation.json"),
                &json!({"action":action,"namespaces":namespace_blocked}),
            )?;
            frontend
                .signal_interrupt()
                .map_err(CiError::Message)?
                .map_err(|code| {
                    CiError::Message(format!(
                        "actual original pre-input interrupt failed: {code}"
                    ))
                })?;
            action["native_signal_result"] = json!(0);
            if let Err(error) = permission.allow()
                && !frontend.exited().map_err(CiError::Message)?
            {
                return Err(error);
            }
            action["released"] = permission.observation();
            launch.close_input();
            let capture = launch.capture_until(cleanup)?;
            if !frontend.exited().map_err(CiError::Message)? {
                return Err(CiError::Message(
                    "original pre-input frontend not retired after direct wait".into(),
                ));
            }
            let namespace_after = watcher.snapshot()?;
            let events = watcher.drain()?;
            let mut observer_entries = Vec::new();
            for entry in fs::read_dir(&observations)? {
                observer_entries.push(entry?.file_name().as_bytes().to_vec());
            }
            observer_entries.sort();
            let locator_present = directory.join("workload-observation.json").try_exists()?;
            let mut files = BTreeMap::from([
                ("request.json".into(), fs::read(&fixture.request)?),
                ("invocation.json".into(), serde_json::to_vec(&invocation)?),
                (
                    "creation-intent.json".into(),
                    fs::read(controller.join("frontend-creation-intent.json"))?,
                ),
                (
                    "original-frontend.json".into(),
                    fs::read(controller.join("original-frontend.json"))?,
                ),
                (
                    "bundle-held.json".into(),
                    serde_json::to_vec(
                        &json!({"path":fixture.bundle,"device":identity.dev(),"inode":identity.ino(),"uid":identity.uid(),"mode":identity.mode(),"links":identity.nlink(),"length":identity.len(),"readonly_descriptor":true}),
                    )?,
                ),
                (
                    "namespace-proof.json".into(),
                    serde_json::to_vec(
                        &json!({"format":"memcordon.current-preparation-native-observation","revision":1,"before":namespace_before,"blocked":namespace_blocked,"after":namespace_after,"events":events,"observer_entries":observer_entries,"locator_present":locator_present}),
                    )?,
                ),
                ("action.json".into(), serde_json::to_vec(&action)?),
                ("stdout.bin".into(), capture.stdout.clone()),
                ("stderr.bin".into(), capture.stderr.clone()),
                (
                    "frontend-wait.json".into(),
                    serde_json::to_vec(
                        &json!({"pid":frontend.process_id,"birth":frontend.birth,"pidfd_readable":true,"status":capture.status.code(),"raw_wait_status":capture.status.into_raw()}),
                    )?,
                ),
                (
                    "provider-manifest.json".into(),
                    fs::read("/usr/libexec/memcordon-runtime-manifest.json")?,
                ),
                (
                    "entrypoint.bin".into(),
                    artifacts::read_file(&images.runtime_source.join("bin/owned-readiness"))?,
                ),
                (
                    "runtime-snapshot.json".into(),
                    images.runtime.canonical_bytes().map_err(CiError::Message)?,
                ),
                (
                    "input-snapshot.json".into(),
                    images.input.canonical_bytes().map_err(CiError::Message)?,
                ),
            ]);
            match fs::read(directory.join("workload-result.json")) {
                Ok(bytes) => {
                    files.insert("result.json".into(), bytes);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            Ok(super::linux_test_lifetime::Experiment {
                scenario: "before-preparation".into(),
                directory: directory.into(),
                files,
            })
        },
    ));
    let _retirement = crate::cancellation::retirement_scope(cleanup);
    let body = match body {
        Ok(result) => result,
        Err(panic) => {
            match launch.cancel_and_settle(cleanup) {
                Ok(_) => {
                    if let Err(error) = launch.retire_bundle_exact(&fixture) {
                        eprintln!("native input retirement after unwind: {error}");
                    }
                }
                Err(error) => eprintln!("native request settlement after unwind: {error}"),
            }
            std::panic::resume_unwind(panic)
        }
    };
    match body {
        Ok(observed) => {
            launch.retire_bundle_exact(&fixture)?;
            Ok(observed)
        }
        Err(primary) => match launch.cancel_and_settle(cleanup) {
            Ok(_) => Err(primary),
            Err(settlement) => Err(CiError::Message(format!(
                "{primary}; original pre-input child settlement incomplete: {settlement}"
            ))),
        },
    }
}

fn drain_intervention(
    scenario: &str,
    controller: &Path,
    launch: &mut super::linux_request_launch::RequestLaunch,
    association: &memcordon_core::workload_request::WorkloadAttemptAssociationV1,
    held: &[crate::linux_consumer_readiness::HeldLinuxProcess],
    action: &mut serde_json::Value,
    work: Instant,
) -> Result<BTreeMap<String, Vec<u8>>> {
    use super::linux_current_phase_gate::{NativeReadGate, NativeTraceStop};
    use std::os::unix::fs::OpenOptionsExt;
    if held.len() != 5 {
        return Err(CiError::Message(
            "original drain process holds differ".into(),
        ));
    }
    let expected = serde_json::to_value(association)?;
    let worker_pid = held[0].process_id;
    let gate = NativeReadGate::new(
        Path::new("/var/lib/memcordon/workload-attempts"),
        work,
        move |pid, bytes| {
            serde_json::from_slice::<serde_json::Value>(bytes).is_ok_and(|record| {
                record["format"] == "memcordon.private-workload-journal"
                    && record["revision"] == 1
                    && record["association"] == expected
                    && record["worker"]["pid"] == pid
                    && pid == worker_pid
                    && record["phase"] == "execution-observed"
                    && record["cleanup_cutoff_nanos"]
                        .as_u64()
                        .is_some_and(|value| value > 0)
            })
        },
    )?;
    launch.send_input(b"R".to_vec())?;
    launch.close_input();
    let mut permission = gate.wait_for(launch.retain_frontend(work)?)?;
    let before: serde_json::Value = serde_json::from_slice(&permission.record)?;
    if before["cleanup_boot_id"] != association.boot_id.as_str()
        || before["native"]["exec_observed"] != true
    {
        return Err(CiError::Message(
            "drain gate lacks the original boot-bound cleanup cutoff and actual released execution"
                .into(),
        ));
    }
    let cutoff = before["cleanup_cutoff_nanos"]
        .as_u64()
        .ok_or_else(|| CiError::Message("native original cleanup cutoff absent".into()))?;
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    let nanos = u64::try_from(now.tv_sec)
        .map_err(|error| CiError::Message(error.to_string()))?
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(now.tv_nsec as u64))
        .ok_or_else(|| CiError::Message("native monotonic clock overflow".into()))?;
    let trace_cutoff = Instant::now()
        .checked_add(std::time::Duration::from_nanos(
            cutoff.saturating_sub(nanos),
        ))
        .ok_or_else(|| CiError::Message("original native cleanup cutoff range invalid".into()))?
        .min(work);
    let mut worker = held[0]
        .duplicate_for_intervention(trace_cutoff)
        .map_err(|error| CiError::Message(format!("original drain worker hold: {error:?}")))?;
    let image = worker
        .hold_executable_image(trace_cutoff)
        .map_err(CiError::Message)?;
    let readback = permission.record.clone();
    let blocked = permission.observation();
    let mut trace = NativeTraceStop::attach(worker, &mut permission, trace_cutoff)?;
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/var/lib/memcordon/workload-attempts")?;
    let attempt = hex::encode(association.attempt);
    let expected = serde_json::to_value(association)?;
    let renamed = trace.after_rename(
        &directory,
        &format!("{attempt}.update"),
        &attempt,
        |bytes| {
            serde_json::from_slice::<serde_json::Value>(bytes).is_ok_and(|record| {
                record["format"] == "memcordon.private-workload-journal"
                    && record["revision"] == 1
                    && record["association"] == expected
                    && record["phase"] == "retiring"
                    && record["cleanup_cutoff_nanos"] == cutoff
            })
        },
    )?;
    let record: Vec<u8> = serde_json::from_value(renamed["record_bytes"].clone())?;
    let actor = if scenario == "during-drain" {
        "frontend"
    } else {
        scenario
            .strip_suffix("-drain")
            .ok_or_else(|| CiError::Message("unsupported native drain actor".into()))?
    };
    let frontend = launch.retain_frontend(trace_cutoff)?;
    let victim = match actor {
        "frontend" => frontend,
        "worker" => &held[0],
        "control" => &held[1],
        "guardian" => &held[2],
        _ => return Err(CiError::Message("unknown original drain victim".into())),
    };
    let proof = json!({"format":"memcordon.current-owner-drain-phase","revision":1,"association":association,"actor":actor,"read_gate":blocked,"rename_exit":renamed,"worker_image":image,"cleanup_cutoff_nanos":cutoff});
    super::source::write_json(
        &controller.join(format!("current-phase-{attempt}.json")),
        &proof,
    )?;
    let signal = if scenario == "during-drain" { 2 } else { 9 };
    let delivered = if signal == 2 {
        victim.signal_interrupt()
    } else {
        victim.signal_kill()
    };
    delivered
        .map_err(CiError::Message)?
        .map_err(|code| CiError::Message(format!("original native drain signal failed: {code}")))?;
    action["signal"] = json!(signal);
    action["victim"] = json!({"pid":victim.process_id,"birth":victim.birth});
    action["native_signal_result"] = json!(0);
    trace.detach()?;
    Ok(BTreeMap::from([
        ("drain-phase.json".into(), serde_json::to_vec(&proof)?),
        ("drain-readback.json".into(), readback),
        ("drain-record.json".into(), record),
    ]))
}

#[allow(clippy::too_many_arguments)]
fn allocation_experiment(
    caller: &CallerSession,
    images: &CallerImages,
    provider: &memcordon_core::PublicProviderBindingV1,
    controller: &Path,
    directory: &Path,
    scenario: &str,
    work: Instant,
    cleanup: Instant,
) -> Result<super::linux_test_lifetime::Experiment> {
    use super::{
        linux_current_phase_gate::NativeReadGate,
        linux_request_launch::{LaunchInput, RequestLaunch},
    };
    use crate::linux_consumer_readiness::HeldLinuxProcess;
    use std::{
        os::unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            process::ExitStatusExt,
        },
        time::Duration,
    };
    let fixture = super::linux_test_lifetime::pack_experiment(caller, images, directory, work)?;
    let (memory, memory_bytes) = super::linux_snapshot_budget::memory_budget(
        &images.runtime,
        &images.input,
        128 * 1024 * 1024,
    )?;
    let expected = String::from(fixture.request_sha256.clone());
    let uid = caller.uid;
    let gate = NativeReadGate::new(
        Path::new("/var/lib/memcordon/workload-attempts"),
        work,
        move |pid, bytes| {
            serde_json::from_slice::<serde_json::Value>(bytes).is_ok_and(|record| {
                record["format"] == "memcordon.private-workload-journal"
                    && record["revision"] == 1
                    && record["request_sha256"] == expected
                    && record["caller_uid"] == uid
                    && record["worker"]["pid"] == pid
                    && record["phase"] == "guardian-ready"
                    && record["intents"]["namespace_init"] == false
                    && record["intents"]["target"] == false
                    && record["native"].is_null()
            })
        },
    )?;
    let observations = directory.join("observations");
    fs::create_dir(&observations)?;
    fs::set_permissions(&observations, fs::Permissions::from_mode(0o700))?;
    rustix::fs::chown(
        &observations,
        Some(rustix::process::Uid::from_raw(caller.uid)),
        Some(rustix::process::Gid::from_raw(caller.gid)),
    )
    .map_err(std::io::Error::from)?;
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|error| CiError::Message(error.to_string()))?;
    let challenge = hex::encode(nonce);
    let arguments: Vec<std::ffi::OsString> = vec![
        "exec-held".into(),
        challenge.clone().into(),
        "/bin/owned-readiness".into(),
        "binary-file".into(),
        challenge.clone().into(),
    ];
    let mut launch = RequestLaunch::start(LaunchInput {
        extra_descriptor: None,
        lifetime: memcordon_core::Lifetime::Command,
        controller_directory: controller,
        observation_directory: Some(&observations),
        stdin: None,
        interactive: true,
        caller,
        fixture: &fixture,
        directory,
        provider,
        entrypoint: std::ffi::OsStr::new("owned-readiness"),
        arguments: &arguments,
        memory: memory.as_os_str(),
        deadline: std::ffi::OsStr::new("+30s"),
        output_directory: None,
        work_cutoff: work,
        cleanup_cutoff: cleanup,
    })?;
    let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<super::linux_test_lifetime::Experiment> {
            let frontend = launch
                .retain_frontend(work)?
                .duplicate_for_intervention(work)
                .map_err(|error| {
                    CiError::Message(format!(
                        "original allocation frontend hold failed: {error:?}"
                    ))
                })?;
            let mut permission = gate.wait_for(&frontend)?;
            let record: serde_json::Value = serde_json::from_slice(&permission.record)?;
            let association = launch.association()?;
            if record["association"] != serde_json::to_value(&association)?
                || record["frontend"]["pid"] != frontend.process_id
                || record["frontend"]["start_time"] != frontend.birth
                || record["boot_id"]
                    != fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim()
                || record["release"] != "not-released"
                || !record["namespace_init"].is_null()
                || !record["target"].is_null()
            {
                return Err(CiError::Message(
                    "kernel allocation readback does not belong to the original pre-target attempt"
                        .into(),
                ));
            }
            let worker_birth = record["worker"]["start_time"]
                .as_u64()
                .ok_or_else(|| CiError::Message("original kernel worker birth absent".into()))?;
            let worker = HeldLinuxProcess::acquire(permission.process_id, worker_birth)
                .map_err(CiError::Message)?;
            let control =
                HeldLinuxProcess::acquire(association.control.pid, association.control.birth)
                    .map_err(CiError::Message)?;
            let guardian_pid =
                u32::try_from(record["guardian"]["pid"].as_u64().ok_or_else(|| {
                    CiError::Message("original partial guardian PID absent".into())
                })?)
                .map_err(|error| CiError::Message(error.to_string()))?;
            let guardian_birth = record["guardian"]["start_time"]
                .as_u64()
                .ok_or_else(|| CiError::Message("original partial guardian birth absent".into()))?;
            let mut guardian = HeldLinuxProcess::acquire(guardian_pid, guardian_birth)
                .map_err(CiError::Message)?;
            guardian.verify_parent(&worker).map_err(CiError::Message)?;
            let mut held = vec![
                ("frontend", frontend),
                ("worker", worker),
                ("control", control),
                ("guardian", guardian),
            ];
            let manifest_bytes = fs::read("/usr/libexec/memcordon-runtime-manifest.json")?;
            let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)?;
            let mut before = Vec::new();
            for (role, process) in &mut held {
                let image = process
                    .hold_executable_image(work)
                    .map_err(CiError::Message)?;
                let component = if *role == "frontend" {
                    "public-cli"
                } else {
                    "sealed-agent"
                };
                if !manifest["components"].as_array().is_some_and(|components| {
                    components.iter().any(|candidate| {
                        candidate["id"] == component && candidate["sha256"] == image["sha256"]
                    })
                }) {
                    return Err(CiError::Message(
                        "original allocation actor image differs from selected installed component"
                            .into(),
                    ));
                }
                before.push(json!({"role":role,"snapshot":process.live_snapshot().map_err(CiError::Message)?,"credentials":process.native_credentials().map_err(CiError::Message)?,"image":image,"pidfd_readable":false}));
            }
            let attempt = hex::encode(association.attempt);
            let mut resources = Vec::new();
            let mut directories = Vec::new();
            for (role, path, field) in [
                (
                    "cgroup",
                    Path::new("/sys/fs/cgroup/memcordon-sealed").join(&attempt),
                    "cgroup",
                ),
                (
                    "root-staging",
                    Path::new("/run/memcordon").join(format!("private-root-{attempt}")),
                    "staging",
                ),
                (
                    "input-staging",
                    Path::new("/var/lib/memcordon/workload-inputs").join(&attempt),
                    "input_staging",
                ),
            ] {
                if record[field].is_null() {
                    continue;
                }
                let file = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&path)?;
                let identity = file.metadata()?;
                if identity.uid() != 0
                    || record[field]["device"] != identity.dev()
                    || record[field]["inode"] != identity.ino()
                {
                    return Err(CiError::Message(
                        "partial native allocation inode differs from original protected record"
                            .into(),
                    ));
                }
                resources.push(
                    json!({"role":role,"path":path,"device":identity.dev(),"inode":identity.ino()}),
                );
                directories.push((path, file));
            }
            let charge_path = Path::new("/var/lib/memcordon/workload-resources").join(&attempt);
            let charge = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&charge_path)?;
            let charge_identity = charge.metadata()?;
            if !charge_identity.is_file()
                || charge_identity.uid() != 0
                || charge_identity.nlink() != 1
                || charge_identity.len() != 8
                || charge_identity.mode() & 0o777 != 0o600
            {
                return Err(CiError::Message(
                    "partial native footprint charge custody differs".into(),
                ));
            }
            resources.push(json!({"role":"footprint","path":charge_path,"device":charge_identity.dev(),"inode":charge_identity.ino()}));
            let start = fs::read(observations.join(format!("{attempt}.start.json")))?;
            let mut files = BTreeMap::from([
                ("request.json".into(), fs::read(&fixture.request)?),
                (
                    "attempt.json".into(),
                    fs::read(directory.join("workload-observation.json"))?,
                ),
                ("start.json".into(), start),
                ("phase-before.json".into(), permission.record.clone()),
                ("held-before.json".into(), serde_json::to_vec(&before)?),
                (
                    "allocations-before.json".into(),
                    serde_json::to_vec(&resources)?,
                ),
                ("provider-manifest.json".into(), manifest_bytes),
            ]);
            use std::os::unix::ffi::OsStrExt;
            files.insert("operands.json".into(),serde_json::to_vec(&json!({"working_directory":null,"memory_bytes":memory_bytes,"deadline_millis":30000,"lifetime":"command","target_argv":arguments.iter().map(|argument|argument.as_bytes().to_vec()).collect::<Vec<_>>()}))?);
            let blocked = permission.observation();
            super::source::write_json(
                &controller.join(format!("current-attempt-{attempt}.json")),
                &json!({"format":"memcordon.current-controller-attempt-capture","revision":1,"scenario":scenario,"association":association,"captures":files,"gate":blocked}),
            )?;
            let actor = scenario
                .strip_suffix("-allocation")
                .ok_or_else(|| CiError::Message("unsupported native allocation actor".into()))?;
            let victim = held
                .iter()
                .find(|(role, _)| *role == actor)
                .ok_or_else(|| CiError::Message("original allocation victim role absent".into()))?;
            victim
                .1
                .signal_kill()
                .map_err(CiError::Message)?
                .map_err(|code| {
                    CiError::Message(format!("original allocation victim kill failed: {code}"))
                })?;
            let mut action = json!({"format":"memcordon.current-owner-phase-action","revision":1,"phase":"allocation","actor":actor,"association":association,"victim":{"pid":victim.1.process_id,"birth":victim.1.birth},"signal":9,"native_signal_result":0,"blocked":blocked});
            let release = permission.allow();
            if let Err(error) = release {
                if actor != "worker" {
                    return Err(error);
                }
                while !held[1].1.exited().map_err(CiError::Message)? {
                    if Instant::now() >= cleanup {
                        return Err(error);
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            action["released"] = permission.observation();
            files.insert("phase-action.json".into(), serde_json::to_vec(&action)?);
            launch.close_input();
            let capture = launch.capture_until(cleanup)?;
            files.insert("stdout.bin".into(), capture.stdout.clone());
            files.insert("stderr.bin".into(), capture.stderr.clone());
            files.insert("frontend-wait.json".into(),serde_json::to_vec(&json!({"status":capture.status.code(),"raw_wait_status":capture.status.into_raw()}))?);
            match fs::read(directory.join("workload-result.json")) {
                Ok(bytes) => {
                    files.insert("result.json".into(), bytes);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            for (role, process) in &held {
                if *role == "guardian" {
                    continue;
                }
                while !process.exited().map_err(CiError::Message)? {
                    if Instant::now() >= cleanup {
                        return Err(CiError::Message(
                            "original allocation actor retirement cutoff exhausted".into(),
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            let recovery = launch.recover()?;
            files.insert(
                "recovery.json".into(),
                fs::read(directory.join("workload-recovery.json"))?,
            );
            files.insert("recovery-process.json".into(),serde_json::to_vec(&json!({"status":recovery.process.status.code(),"stdout":recovery.process.stdout,"stderr":recovery.process.stderr}))?);
            files.insert(
                "journal-after.json".into(),
                fs::read(Path::new("/var/lib/memcordon/workload-attempts").join(&attempt))?,
            );
            for (_, process) in &held {
                while !process.exited().map_err(CiError::Message)? {
                    if Instant::now() >= cleanup {
                        return Err(CiError::Message(
                            "original partial helper retirement cutoff exhausted".into(),
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            let retired:Vec<_>=held.iter().map(|(role,process)|json!({"role":role,"pid":process.process_id,"birth":process.birth,"pidfd_readable":true})).collect();
            files.insert("held-after.json".into(), serde_json::to_vec(&retired)?);
            let mut absent = Vec::new();
            for (path, _) in &directories {
                match fs::symlink_metadata(path) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        absent.push(json!({"path":path,"absent":true}))
                    }
                    Err(error) => return Err(error.into()),
                    Ok(_) => {
                        return Err(CiError::Message(
                            "original partial native directory remains".into(),
                        ));
                    }
                }
            }
            if !matches!(fs::symlink_metadata(&charge_path),Err(error)if error.kind()==std::io::ErrorKind::NotFound)
            {
                return Err(CiError::Message(
                    "original partial native charge remains".into(),
                ));
            }
            absent.push(json!({"path":charge_path,"absent":true}));
            files.insert(
                "allocations-after.json".into(),
                serde_json::to_vec(&absent)?,
            );
            let ack = caller
                .command(directory, cleanup)?
                .args(["workload", "acknowledge", "--observation"])
                .arg(directory.join("workload-observation.json"))
                .output_quiet()?;
            crate::command::require_successful_output(
                "actual original partial-attempt acknowledgment",
                &ack,
            )?;
            files.insert(
                "acknowledgment-process.json".into(),
                serde_json::to_vec(
                    &json!({"status":ack.status.code(),"stdout":ack.stdout,"stderr":ack.stderr}),
                )?,
            );
            let mut metadata_absent = Vec::new();
            for name in [attempt.clone(), format!("{attempt}.recovery-lock")] {
                let path = Path::new("/var/lib/memcordon/workload-attempts").join(name);
                if !matches!(fs::symlink_metadata(&path),Err(error)if error.kind()==std::io::ErrorKind::NotFound)
                {
                    return Err(CiError::Message(
                        "acknowledged partial native metadata remains".into(),
                    ));
                }
                metadata_absent.push(json!({"path":path,"absent":true}));
            }
            files.insert(
                "metadata-after.json".into(),
                serde_json::to_vec(&metadata_absent)?,
            );
            files.insert(
                "entrypoint.bin".into(),
                artifacts::read_file(&images.runtime_source.join("bin/owned-readiness"))?,
            );
            files.insert(
                "runtime-snapshot.json".into(),
                images.runtime.canonical_bytes().map_err(CiError::Message)?,
            );
            files.insert(
                "input-snapshot.json".into(),
                images.input.canonical_bytes().map_err(CiError::Message)?,
            );
            Ok(super::linux_test_lifetime::Experiment {
                scenario: scenario.into(),
                directory: directory.into(),
                files,
            })
        },
    ));
    let _retirement = crate::cancellation::retirement_scope(cleanup);
    let body = match body {
        Ok(result) => result,
        Err(panic) => {
            match launch.cancel_and_settle(cleanup) {
                Ok(_) => {
                    if let Err(error) = launch.retire_bundle_exact(&fixture) {
                        eprintln!("native input retirement after unwind: {error}");
                    }
                }
                Err(error) => eprintln!("native request settlement after unwind: {error}"),
            }
            std::panic::resume_unwind(panic)
        }
    };
    match body {
        Ok(observed) => {
            launch.retire_bundle_exact(&fixture)?;
            Ok(observed)
        }
        Err(primary) => match launch.cancel_and_settle(cleanup) {
            Ok(_) => Err(primary),
            Err(settlement) => Err(CiError::Message(format!(
                "{primary}; original allocation frontend settlement incomplete: {settlement}"
            ))),
        },
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_installed(
    root: &Path,
    caller: &CallerSession,
    foreign: &CallerSession,
    probe: &Path,
    images: &CallerImages,
    provider: &memcordon_core::PublicProviderBindingV1,
    controller_directory: &Path,
    working_directory: &Path,
    work: Instant,
    cleanup: Instant,
) -> Result<()> {
    let images = images.minimal();
    if !root.is_absolute() || !probe.is_absolute() || caller.uid == foreign.uid || work >= cleanup {
        return Err(CiError::Message(
            "owner experiment needs distinct actual callers and original cutoffs".into(),
        ));
    }
    let controllers = controller_directory;
    for (family, scenario, facet) in [
        ("C-LIFETIME", "frontend-loss", "lost-terminal-response"),
        ("C-LIFETIME", "guardian-loss", "released-guardian-loss"),
        ("C-LIFETIME", "service-loss", "released-service-loss"),
        ("C-LIFETIME", "worker-loss", "released-worker-loss"),
        ("C-LIFETIME", "recovery", "repeated-recovery"),
        ("C-OWNER", "foreign-inspect", "release-barrier"),
        ("C-OWNER", "foreign-cancel", "release-barrier"),
        ("C-OWNER", "foreign-recover", "release-barrier"),
        ("C-OWNER", "stale-attempt", "release-barrier"),
        ("C-OWNER", "request-substitution", "release-barrier"),
        (
            "C-CANCEL",
            "service-restart-fresh-request",
            "release-barrier",
        ),
        ("L-LIFE-02", "frontend-release", "lost-terminal-response"),
        ("L-LIFE-02", "worker-release", "released-worker-loss"),
        ("L-LIFE-02", "guardian-release", "released-guardian-loss"),
        ("L-LIFE-02", "control-release", "released-control-loss"),
        ("L-LIFE-02", "frontend-allocation", "allocation"),
        ("L-LIFE-02", "worker-allocation", "allocation"),
        ("L-LIFE-02", "guardian-allocation", "allocation"),
        ("L-LIFE-02", "control-allocation", "allocation"),
        ("L-LIFE-02", "frontend-drain", "drain-frontend"),
        ("L-LIFE-02", "worker-drain", "drain-worker"),
        ("L-LIFE-02", "guardian-drain", "drain-guardian"),
        ("L-LIFE-02", "control-drain", "drain-control"),
        ("C-CANCEL", "during-drain", "controlled-drain-cancel"),
        ("C-CANCEL", "before-preparation", "before-preparation"),
    ] {
        let case_controller = controllers.join(format!("owner-{scenario}"));
        let frontend_controller = case_controller.join("frontend");
        let controller_directory = &frontend_controller;
        let operation = (|| -> Result<()> {
            fs::create_dir(&case_controller)?;
            fs::create_dir(&frontend_controller)?;
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&case_controller, fs::Permissions::from_mode(0o700))?;
            fs::set_permissions(&frontend_controller, fs::Permissions::from_mode(0o700))?;
            let directory = working_directory.join(format!("current-owner-{scenario}"));
            fs::create_dir(&directory)?;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
            rustix::fs::chown(
                &directory,
                Some(rustix::process::Uid::from_raw(caller.uid)),
                Some(rustix::process::Gid::from_raw(caller.gid)),
            )
            .map_err(std::io::Error::from)?;
            let mut intervention =
                |association: &memcordon_core::workload_request::WorkloadAttemptAssociationV1,
                 held: &[crate::linux_consumer_readiness::HeldLinuxProcess]| {
                    owner_probe(
                        scenario,
                        caller,
                        foreign,
                        probe,
                        controller_directory,
                        working_directory,
                        association,
                        held,
                        work,
                    )
                };
            let mut previous = None;
            if scenario == "service-restart-fresh-request" {
                let previous_controller = case_controller.join("previous");
                fs::create_dir(&previous_controller)?;
                fs::set_permissions(&previous_controller, fs::Permissions::from_mode(0o700))?;
                let old = working_directory.join("previous-service-restart");
                fs::create_dir(&old)?;
                fs::set_permissions(&old, fs::Permissions::from_mode(0o700))?;
                rustix::fs::chown(
                    &old,
                    Some(rustix::process::Uid::from_raw(caller.uid)),
                    Some(rustix::process::Gid::from_raw(caller.gid)),
                )
                .map_err(std::io::Error::from)?;
                let retired = super::linux_test_lifetime::experiment(
                    caller,
                    images,
                    provider,
                    super::linux_test_lifetime::ExperimentContext {
                        controller: &previous_controller,
                        directory: &old,
                        scenario,
                        facet: "released-service-loss",
                        work,
                        cleanup,
                    },
                )?;
                let restarted = crate::command::CommandSpec::new(
                    "/usr/bin/systemctl",
                    controller_directory,
                    std::time::Duration::from_secs(30),
                )
                .bounded_until(work)
                .args(["restart", "memcordon-sealed-agent.service"])
                .output_quiet()?;
                crate::command::require_successful_output(
                    "actual selected current service restart",
                    &restarted,
                )?;
                let query = crate::command::CommandSpec::new(
                    "/usr/bin/systemctl",
                    controller_directory,
                    std::time::Duration::from_secs(30),
                )
                .bounded_until(work)
                .args([
                    "show",
                    "--property=MainPID",
                    "--value",
                    "memcordon-sealed-agent.service",
                ])
                .output_quiet()?;
                crate::command::require_successful_output(
                    "actual restarted service PID query",
                    &query,
                )?;
                let pid = std::str::from_utf8(&query.stdout)
                    .map_err(|error| CiError::Message(error.to_string()))?
                    .trim()
                    .parse::<u32>()
                    .map_err(|error| CiError::Message(error.to_string()))?;
                if pid <= 1 {
                    return Err(CiError::Message(
                        "restarted actual current service instance absent".into(),
                    ));
                }
                let birth = crate::linux_consumer_readiness::process_birth(pid)
                    .map_err(CiError::Message)?;
                let mut service =
                    crate::linux_consumer_readiness::HeldLinuxProcess::acquire(pid, birth)
                        .map_err(CiError::Message)?;
                let image = service
                    .hold_executable_image(work)
                    .map_err(CiError::Message)?;
                previous = Some((retired, restarted, query, service, image));
            }
            let mut released_intervention =
                |launch: &mut super::linux_request_launch::RequestLaunch,
                 association: &memcordon_core::workload_request::WorkloadAttemptAssociationV1,
                 held: &[crate::linux_consumer_readiness::HeldLinuxProcess],
                 action: &mut serde_json::Value| {
                    drain_intervention(
                        scenario,
                        controller_directory,
                        launch,
                        association,
                        held,
                        action,
                        work,
                    )
                };
            let mut experiment = if facet == "before-preparation" {
                before_preparation_experiment(
                    caller,
                    images,
                    provider,
                    controller_directory,
                    &directory,
                    work,
                    cleanup,
                )?
            } else if facet == "allocation" {
                allocation_experiment(
                    caller,
                    images,
                    provider,
                    controller_directory,
                    &directory,
                    scenario,
                    work,
                    cleanup,
                )?
            } else {
                super::linux_test_lifetime::experiment_with_phases(
                    caller,
                    images,
                    provider,
                    controller_directory,
                    &directory,
                    scenario,
                    facet,
                    work,
                    cleanup,
                    if family == "C-OWNER" {
                        Some(&mut intervention)
                    } else {
                        None
                    },
                    if facet.starts_with("drain-") || facet == "controlled-drain-cancel" {
                        Some(&mut released_intervention)
                    } else {
                        None
                    },
                )?
            };
            if let Some((previous, restarted, query, service, image)) = previous {
                if service.exited().map_err(CiError::Message)? {
                    return Err(CiError::Message(
                        "actual restarted service retired during fresh request".into(),
                    ));
                }
                for (name, bytes) in previous.files {
                    experiment.files.insert(format!("previous-{name}"), bytes);
                }
                experiment.files.insert("restart.json".into(),serde_json::to_vec(&json!({"program":"/usr/bin/systemctl","arguments":["restart","memcordon-sealed-agent.service"],"status":restarted.status.code(),"stdout":restarted.stdout,"stderr":restarted.stderr,"query":{"program":"/usr/bin/systemctl","arguments":["show","--property=MainPID","--value","memcordon-sealed-agent.service"],"status":query.status.code(),"stdout":query.stdout,"stderr":query.stderr},"service":{"pid":service.process_id,"birth":service.birth,"image":image,"held_before_fresh_request":true,"pidfd_readable_after_fresh_request":false}}))?);
            }
            super::linux_test_lifetime_assertions::assert_experiment(&experiment, facet, provider)
        })();
        operation?;
    }
    Ok(())
}
