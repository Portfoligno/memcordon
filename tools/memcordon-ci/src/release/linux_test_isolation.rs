//! Native isolation experiments keep their positive controls and live owners.
use super::{
    linux_request_fixture::CallerSession,
    linux_test_assertions::{assert_case_with, operation},
    linux_test_execution::{self, CallerImages, ExecutedCase, TestInput},
    linux_test_scenarios::{self, Scenario},
};
use crate::{CiError, Result};
use memcordon_core::PublicProviderBindingV1;
use serde_json::Value;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::Path,
    time::{Duration, Instant},
};

fn fail(message: &str) -> CiError {
    CiError::Message(message.into())
}
fn binary(value: &Value) -> Result<Vec<u8>> {
    Ok(serde_json::from_value(value.clone())?)
}
fn recipe(family: &str, scenario: &str) -> Result<Scenario> {
    linux_test_scenarios::scenarios()?
        .into_iter()
        .find(|case| case.key.family == family && case.key.scenario == scenario)
        .ok_or_else(|| fail("required native isolation scenario absent"))
}
fn succeeded(result: &Value) -> Result<()> {
    if result["outcome"]["kind"] != "completed"
        || result["outcome"]["wrapper_status"] != 0
        || result["outcome"]["native_termination"]["code"] != 0
    {
        return Err(fail("native isolation target did not complete"));
    }
    Ok(())
}
fn acknowledge(caller: &CallerSession, case: &ExecutedCase, cleanup: Instant) -> Result<()> {
    let output = caller
        .command(&case.directory, cleanup)?
        .args(["workload", "acknowledge", "--observation"])
        .arg(case.directory.join("workload-observation.json"))
        .output()?;
    crate::command::require_successful_output("settled native isolation acknowledgment", &output)?;
    let ack = memcordon_core::workload_request::WorkloadAcknowledgmentV1::parse(&output.stdout)
        .map_err(|error| fail(&error.to_string()))?;
    if ack.association != case.locator {
        return Err(fail(
            "native isolation acknowledgment names another attempt",
        ));
    }
    Ok(())
}
struct Context<'a> {
    caller: &'a CallerSession,
    images: &'a CallerImages,
    provider: &'a PublicProviderBindingV1,
    working: &'a Path,
    controller: &'a Path,
    work: Instant,
    cleanup: Instant,
}
impl Context<'_> {
    fn input<'a>(&'a self, controller: &'a Path, directory: &'a Path) -> TestInput<'a> {
        TestInput {
            controller_directory: controller,
            caller: self.caller,
            images: self.images,
            provider: self.provider,
            directory,
            work_cutoff: self.work,
            cleanup_cutoff: self.cleanup,
        }
    }
    fn directory(&self, name: &str) -> Result<std::path::PathBuf> {
        let path = self.controller.join(name);
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(path)
    }
    fn execute(&self, name: &str, recipe: Scenario) -> Result<ExecutedCase> {
        let controller = self.directory(name)?;
        linux_test_execution::run_recipe(self.input(&controller, &self.working.join(name)), recipe)
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run(
    root: &Path,
    caller: &CallerSession,
    _foreign: &CallerSession,
    images: &CallerImages,
    provider: &PublicProviderBindingV1,
    working: &Path,
    controller: &Path,
    work: Instant,
    cleanup: Instant,
) -> Result<()> {
    if !root.is_absolute() || Instant::now() >= work || work >= cleanup {
        return Err(fail("native isolation requires original remaining cutoffs"));
    }
    let context = Context {
        caller,
        images: images.minimal(),
        provider,
        working,
        controller,
        work,
        cleanup,
    };
    host_sockets(&context)?;
    host_paths(&context)?;
    descriptors(&context)?;
    pairs(&context)
}

fn host_sockets(context: &Context<'_>) -> Result<()> {
    for scenario in ["host-tcp", "nonloopback"] {
        let host = if scenario == "host-tcp" {
            Ipv4Addr::LOCALHOST
        } else {
            let route = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
            route.connect((Ipv4Addr::new(192, 0, 2, 1), 9))?;
            match route.local_addr()?.ip() {
                std::net::IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_unspecified() => ip,
                _ => return Err(fail("host lacks a real nonloopback route")),
            }
        };
        let listener = TcpListener::bind((host, 0))?;
        let address = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let positive = TcpStream::connect_timeout(
            &address,
            context
                .work
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(3)),
        )?;
        let (accepted, peer) = listener.accept()?;
        if peer != positive.local_addr()? {
            return Err(fail("host positive control accepted another peer"));
        }
        drop((accepted, positive));
        let held = rustix::fs::fstat(listener.as_fd()).map_err(std::io::Error::from)?;
        let host_namespace = fs::read_link("/proc/self/ns/net")?;
        let host_inode = host_namespace
            .to_str()
            .and_then(|value| value.strip_prefix("net:["))
            .and_then(|value| value.strip_suffix(']'))
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| fail("host network namespace identity absent"))?;
        let mut selected = recipe("L-ISO-01", scenario)?;
        selected.mode = "isolation-peer".into();
        selected.arguments = vec!["tcp".into(), address.to_string().into()];
        let case = context.execute(scenario, selected)?;
        match listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(fail("isolated target connected to actual host listener")),
        }
        if rustix::fs::fstat(listener.as_fd())
            .map_err(std::io::Error::from)?
            .st_ino
            != held.st_ino
        {
            return Err(fail("host listener identity changed"));
        }
        assert_case_with(&case, |rows, result, native| {
            succeeded(result)?;
            let denial = operation(rows, "isolation-peer-denied")?;
            if denial["kind"] != "tcp"
                || denial["endpoint"] != address.to_string()
                || ![1, 101, 111, 113]
                    .iter()
                    .any(|code| denial["native_errno"] == *code)
                || native["network_namespace"]["inode"] == host_inode
                || binary(&operation(rows, "isolation-private-tcp-positive")?["bytes"])?
                    != case.challenge.as_bytes()
            {
                return Err(fail(
                    "host TCP denial lost exact listener or private positive control",
                ));
            }
            Ok(())
        })?;
        acknowledge(context.caller, &case, context.cleanup)?;
    }
    let socket = context.working.join("host-isolation.sock");
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o666))?;
    listener.set_nonblocking(true)?;
    let positive = UnixStream::connect(&socket)?;
    let accepted = listener.accept()?;
    drop((positive, accepted));
    let held = fs::symlink_metadata(&socket)?;
    let mut selected = recipe("L-ISO-02", "host-temp-socket")?;
    selected.arguments = vec![socket.as_os_str().to_owned()];
    let case = context.execute("host-temp-socket", selected)?;
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(error) => return Err(error.into()),
        Ok(_) => return Err(fail("isolated target reached host Unix listener")),
    }
    let named = fs::symlink_metadata(&socket)?;
    if (held.dev(), held.ino(), held.mode(), held.nlink())
        != (named.dev(), named.ino(), named.mode(), named.nlink())
    {
        return Err(fail("held host Unix socket changed"));
    }
    assert_case_with(&case, |rows, result, _| {
        succeeded(result)?;
        let denial = operation(rows, "forbidden-unix-path-denied")?;
        if denial["path"] != socket.to_string_lossy().as_ref()
            || ![1, 2, 13, 20, 111]
                .iter()
                .any(|code| denial["native_errno"] == *code)
            || binary(&operation(rows, "private-unix-pair-positive")?["bytes"])?
                != case.challenge.as_bytes()
        {
            return Err(fail("host Unix denial lost exact path or positive bytes"));
        }
        Ok(())
    })?;
    acknowledge(context.caller, &case, context.cleanup)?;
    fs::remove_file(&socket)?;
    use std::os::linux::net::SocketAddrExt;
    let mut token = [0u8; 32];
    getrandom::fill(&mut token).map_err(|error| fail(&error.to_string()))?;
    let name = hex::encode(token);
    let address = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
    let listener = UnixListener::bind_addr(&address)?;
    listener.set_nonblocking(true)?;
    let mut positive = UnixStream::connect_addr(&address)?;
    let (mut receiver, _) = listener.accept()?;
    let remaining = context
        .work
        .saturating_duration_since(Instant::now())
        .min(Duration::from_secs(3));
    positive.set_write_timeout(Some(remaining))?;
    receiver.set_read_timeout(Some(remaining))?;
    positive.write_all(&token)?;
    let mut actual = [0u8; 32];
    receiver.read_exact(&mut actual)?;
    if actual != token {
        return Err(fail("actual host abstract positive bytes differ"));
    }
    drop((positive, receiver));
    let mut selected = recipe("L-ISO-03", "host-abstract")?;
    selected.mode = "isolation-peer".into();
    selected.arguments = vec!["abstract".into(), name.clone().into()];
    let case = context.execute("host-abstract", selected)?;
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(error) => return Err(error.into()),
        Ok(_) => return Err(fail("isolated target reached host abstract socket")),
    }
    assert_case_with(&case, |rows, result, _| {
        succeeded(result)?;
        let denial = operation(rows, "isolation-peer-denied")?;
        if denial["kind"] != "abstract"
            || denial["endpoint"] != name
            || ![1, 2, 13, 111]
                .iter()
                .any(|code| denial["native_errno"] == *code)
            || binary(&operation(rows, "isolation-private-tcp-positive")?["bytes"])?
                != case.challenge.as_bytes()
        {
            return Err(fail(
                "host abstract denial lost original endpoint or neighboring control",
            ));
        }
        Ok(())
    })?;
    acknowledge(context.caller, &case, context.cleanup)
}

fn host_paths(context: &Context<'_>) -> Result<()> {
    for scenario in [
        "symlink",
        "dotdot",
        "proc-root",
        "proc-cwd",
        "proc-fd",
        "hardlink",
        "mount-alias",
    ] {
        let source = context.working.join(scenario).with_extension("host.bin");
        let mut marker = [0u8; 32];
        getrandom::fill(&mut marker).map_err(|error| fail(&error.to_string()))?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o444)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&source)?;
        file.write_all(&marker)?;
        file.sync_all()?;
        let held = file.metadata()?;
        let pid = std::process::id();
        let probe = match scenario {
            "proc-root" => std::path::PathBuf::from("/proc")
                .join(pid.to_string())
                .join("root")
                .join(
                    source
                        .strip_prefix("/")
                        .map_err(|error| fail(&error.to_string()))?,
                ),
            "proc-cwd" => {
                let mut path = std::path::PathBuf::from("/proc")
                    .join(pid.to_string())
                    .join("cwd");
                for _ in 0..128 {
                    path.push("..");
                }
                path.join(
                    source
                        .strip_prefix("/")
                        .map_err(|error| fail(&error.to_string()))?,
                )
            }
            "proc-fd" => std::path::PathBuf::from("/proc")
                .join(pid.to_string())
                .join("fd")
                .join(file.as_raw_fd().to_string()),
            _ => source.clone(),
        };
        if fs::read(&probe)? != marker {
            return Err(fail("host path positive control failed"));
        }
        let mut selected = recipe("L-ISO-04", scenario)?;
        selected.mode = "isolation-path".into();
        selected.arguments = vec![
            scenario.into(),
            source.as_os_str().to_owned(),
            probe.as_os_str().to_owned(),
        ];
        let case = context.execute(scenario, selected)?;
        let named = fs::symlink_metadata(&source)?;
        if (named.dev(), named.ino(), named.nlink()) != (held.dev(), held.ino(), 1)
            || fs::read(&source)? != marker
        {
            return Err(fail("host path test changed original held object"));
        }
        assert_case_with(&case, |rows, result, _| {
            succeeded(result)?;
            let alias = operation(rows, "isolation-path-alias")?;
            let expected = match scenario {
                "symlink" => std::path::PathBuf::from("/work/isolation-symbolic-alias"),
                "dotdot" => std::path::PathBuf::from("/work")
                    .join("..")
                    .join("..")
                    .join(
                        source
                            .strip_prefix("/")
                            .map_err(|error| fail(&error.to_string()))?,
                    ),
                _ => probe.clone(),
            };
            if alias["kind"] != scenario
                || alias["source"] != source.to_string_lossy().as_ref()
                || alias["probe"] != expected.to_string_lossy().as_ref()
            {
                return Err(fail("target path alias differs from actual host object"));
            }
            match scenario {
                "hardlink" => {
                    if ![1, 2, 13, 18]
                        .iter()
                        .any(|code| alias["native_import_errno"] == *code)
                        || binary(
                            &operation(rows, "isolation-private-hardlink-positive")?["bytes"],
                        )? != case.challenge.as_bytes()
                    {
                        return Err(fail(
                            "hardlink refusal lost native error or private positive",
                        ));
                    }
                }
                "mount-alias" => {
                    if alias["native_import_errno"] != 1 {
                        return Err(fail("native mount import was not denied"));
                    }
                }
                _ => {
                    if !alias["native_import_errno"].is_null() {
                        return Err(fail("alias failed before intended open probe"));
                    }
                }
            }
            let denial = operation(rows, "native-outside-file-denied")?;
            if denial["kind"] != scenario
                || binary(&denial["path"])? != expected.as_os_str().as_encoded_bytes()
                || denial["native_result"] != -1
                || ![1, 2, 13, 40]
                    .iter()
                    .any(|code| denial["native_errno"] == *code)
                || binary(&operation(rows, "neighboring-private-file")?["bytes"])?
                    != b"private-read-write-positive"
            {
                return Err(fail(
                    "native path denial lost exact operand or neighboring positive",
                ));
            }
            Ok(())
        })?;
        acknowledge(context.caller, &case, context.cleanup)?;
        fs::remove_file(&source)?;
    }
    Ok(())
}

fn descriptors(context: &Context<'_>) -> Result<()> {
    for scenario in ["opath", "extra-host-fd", "stdio-host-socket"] {
        let controller = context.directory(scenario)?;
        let source = context.working.join(scenario).with_extension("host.bin");
        let mut token = [0u8; 32];
        getrandom::fill(&mut token).map_err(|error| fail(&error.to_string()))?;
        let (descriptor, peer) = if scenario == "opath" {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o444)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&source)?;
            file.write_all(&token)?;
            file.sync_all()?;
            drop(file);
            if fs::read(&source)? != token {
                return Err(fail("O_PATH host positive bytes differ"));
            }
            (
                OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&source)?,
                None,
            )
        } else {
            let (mut receiver, mut sender) = UnixStream::pair()?;
            let remaining = context
                .work
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(3));
            sender.set_write_timeout(Some(remaining))?;
            receiver.set_read_timeout(Some(remaining))?;
            sender.write_all(&token)?;
            let mut received = [0u8; 32];
            receiver.read_exact(&mut received)?;
            if received != token {
                return Err(fail("host descriptor positive bytes differ"));
            }
            sender.shutdown(std::net::Shutdown::Write)?;
            (File::from(OwnedFd::from(receiver)), Some(sender))
        };
        let held = descriptor.metadata()?;
        let flags = rustix::fs::fcntl_getfl(&descriptor)
            .map_err(std::io::Error::from)?
            .bits();
        let mut selected = if scenario == "opath" {
            recipe("L-ISO-04", scenario)?
        } else {
            recipe("L-ISO-05", scenario)?
        };
        if scenario == "opath" {
            selected.mode = "outside-file".into();
            selected.arguments = vec!["opath".into(), source.as_os_str().to_owned(), "128".into()];
        } else {
            selected.mode = "descriptor-isolation".into();
            selected.arguments.clear();
        }
        let case = linux_test_execution::run_recipe_with_descriptors(
            context.input(&controller, &context.working.join(scenario)),
            selected,
            if scenario == "stdio-host-socket" {
                None
            } else {
                Some(&descriptor)
            },
            if scenario == "stdio-host-socket" {
                Some(&descriptor)
            } else {
                None
            },
        )?;
        let after = descriptor.metadata()?;
        if (after.dev(), after.ino(), after.mode()) != (held.dev(), held.ino(), held.mode()) {
            return Err(fail("host descriptor identity changed"));
        }
        let original = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(controller.join("original-frontend.json"))?;
        let metadata = original.metadata()?;
        if metadata.uid() != 0
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() > 1024 * 1024
        {
            return Err(fail("frontend descriptor observation custody differs"));
        }
        let mut observed = Vec::new();
        original.take(1024 * 1024 + 1).read_to_end(&mut observed)?;
        let frontend: Value = serde_json::from_slice(&observed)?;
        let mapped = &frontend[if scenario == "stdio-host-socket" {
            "stdin_descriptor"
        } else {
            "extra_descriptor"
        }];
        if mapped["target_descriptor"]
            != if scenario == "stdio-host-socket" {
                0
            } else {
                128
            }
            || mapped["device"] != held.dev()
            || mapped["inode"] != held.ino()
            || mapped["mode"] != held.mode()
            || mapped["uid"] != held.uid()
            || mapped["flags"] != flags
        {
            return Err(fail("host descriptor did not reach intended frontend slot"));
        }
        assert_case_with(&case, |rows, result, native| {
            succeeded(result)?;
            if frontend["process"] != native["caller"]
                || frontend["request_sha256"] != result["request"]["request_sha256"]
            {
                return Err(fail("descriptor observation differs from live frontend"));
            }
            if scenario == "opath" {
                let denial = operation(rows, "native-outside-file-denied")?;
                if denial["kind"] != "opath"
                    || denial["native_descriptor"] != 128
                    || denial["native_result"] != -1
                    || denial["native_errno"] != 9
                    || binary(&denial["path"])? != source.as_os_str().as_encoded_bytes()
                    || binary(&operation(rows, "neighboring-private-file")?["bytes"])?
                        != b"private-read-write-positive"
                {
                    return Err(fail(
                        "O_PATH authority was retained or private positive failed",
                    ));
                }
            } else {
                let actual = operation(rows, "native-descriptor-isolation")?;
                let streams = actual["stdio"]
                    .as_array()
                    .ok_or_else(|| fail("native stdio observations absent"))?;
                if streams.len() != 3 {
                    return Err(fail("native stdio count differs"));
                }
                for (index, stream) in streams.iter().enumerate() {
                    if stream["descriptor"] != index
                        || stream["inode"].as_u64().is_none_or(|value| value == 0)
                        || stream["mode"]
                            .as_u64()
                            .is_none_or(|mode| mode & 0o170000 != 0o010000)
                    {
                        return Err(fail(
                            "target inherited host socket instead of provider byte pipes",
                        ));
                    }
                }
                if actual["extra_descriptor"] != 128
                    || actual["native_errno"] != 9
                    || binary(&operation(rows, "private-unix-pair-positive")?["bytes"])?
                        != case.challenge.as_bytes()
                {
                    return Err(fail(
                        "target retained extra host descriptor or lost private IO",
                    ));
                }
            }
            Ok(())
        })?;
        acknowledge(context.caller, &case, context.cleanup)?;
        drop(peer);
        if scenario == "opath" {
            if fs::read(&source)? != token {
                return Err(fail("O_PATH source bytes changed"));
            }
            fs::remove_file(source)?;
        }
    }
    Ok(())
}

fn pairs(context: &Context<'_>) -> Result<()> {
    use memcordon_core::{
        identifiers::LogicalId,
        workload_requirements::{LocalPortRequestV1, PrivatePeerRequestV1, RequirementRequestV1},
    };
    for (family, scenario, kind) in [
        ("L-MIX-04", "cross-attempt", "tcp"),
        ("L-ISO-03", "other-attempt-abstract", "abstract"),
        ("L-ISO-06", "same-sandbox-uid-cross-attempt", "tcp"),
        ("L-ISO-06", "foreign-resource-handle", "proc-fd"),
        ("L-ISO-06", "stale-resource-owner", "tcp"),
    ] {
        let work = context.work.min(Instant::now() + Duration::from_secs(30));
        let controller = context.directory(scenario)?;
        let peer_controller = controller.join("peer-controller");
        fs::create_dir(&peer_controller)?;
        fs::set_permissions(&peer_controller, fs::Permissions::from_mode(0o700))?;
        let mut selected = recipe("L-ISO-03", "own-abstract-positive")?;
        selected.key.family = family.into();
        selected.key.scenario = scenario.into();
        selected.mode = "isolation-listener".into();
        selected.arguments.clear();
        selected
            .requirements
            .push(RequirementRequestV1::TcpListener {
                id: LogicalId::new("isolation-tcp".into()).map_err(CiError::Message)?,
                local_port: LocalPortRequestV1::KernelAssigned,
                peer: PrivatePeerRequestV1::DynamicLoopbackWithinThisAttempt,
            });
        let mut peer_recipe = selected.clone();
        peer_recipe.mode = "isolation-peer".into();
        let mut peer_case = None;
        let mut original_ready = None;
        let mut intervention =
            |launch: &mut super::linux_request_launch::RequestLaunch,
             association: &memcordon_core::workload_request::WorkloadAttemptAssociationV1|
             -> Result<Value> {
                let ready = loop {
                    let snapshot = launch.snapshot_until(work)?;
                    let mut selected = None;
                    for line in snapshot
                        .stdout()?
                        .split_inclusive(|byte| *byte == b'\n')
                        .filter(|line| line.ends_with(b"\n"))
                    {
                        let row: Value = serde_json::from_slice(line)?;
                        if row["operation"] == "isolation-listener-ready"
                            && selected.replace(row).is_some()
                        {
                            return Err(fail("original native listener phase duplicated"));
                        }
                    }
                    if let Some(ready) = selected {
                        break ready;
                    }
                    if Instant::now() >= work {
                        return Err(fail("native listener phase timed out before peer launch"));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                };
                let (owners, before) =
                    linux_test_execution::hold_current_attempt(association, work)?;
                let endpoint = match kind {
                    "proc-fd" => {
                        let pid = before["native"]["target"]["pid"]
                            .as_u64()
                            .filter(|pid| *pid > 0)
                            .ok_or_else(|| fail("held foreign target PID absent"))?;
                        let descriptor = ready["observation"]["tcp_descriptor"]
                            .as_u64()
                            .filter(|fd| *fd >= 3)
                            .ok_or_else(|| fail("held foreign listener descriptor absent"))?;
                        std::path::PathBuf::from("/proc")
                            .join(pid.to_string())
                            .join("fd")
                            .join(descriptor.to_string())
                            .to_string_lossy()
                            .into_owned()
                    }
                    "tcp" => ready["observation"]["tcp"]
                        .as_str()
                        .ok_or_else(|| fail("held listener TCP endpoint absent"))?
                        .into(),
                    _ => String::from_utf8(binary(&ready["observation"]["abstract_name"])?)
                        .map_err(|error| fail(&error.to_string()))?,
                };
                if kind == "proc-fd" {
                    let original = fs::metadata(&endpoint)?;
                    if original.mode() & 0o170000 != 0o140000
                        || original.uid() as u64
                            != before["native"]["target_uid"]
                                .as_u64()
                                .ok_or_else(|| fail("holder target UID absent"))?
                    {
                        return Err(fail(
                            "foreign resource probe lacks actual owned listener object",
                        ));
                    }
                }
                peer_recipe.arguments = vec![kind.into(), endpoint.clone().into()];
                let peer = linux_test_execution::run_recipe(
                    TestInput {
                        controller_directory: &peer_controller,
                        caller: context.caller,
                        images: context.images,
                        provider: context.provider,
                        directory: &context.working.join(scenario).with_extension("peer"),
                        work_cutoff: work,
                        cleanup_cutoff: context.cleanup,
                    },
                    peer_recipe.clone(),
                )?;
                assert_case_with(&peer, |rows, result, native| {
                    succeeded(result)?;
                    let denial = operation(rows, "isolation-peer-denied")?;
                    if denial["kind"] != kind
                        || denial["endpoint"] != endpoint
                        || ![1, 2, 13, 101, 111, 113]
                            .iter()
                            .any(|code| denial["native_errno"] == *code)
                        || binary(&denial["neighbor_bytes"])? != peer.challenge.as_bytes()
                        || binary(&operation(rows, "isolation-private-tcp-positive")?["bytes"])?
                            != peer.challenge.as_bytes()
                        || result["provider"] != serde_json::to_value(&association.provider)?
                    {
                        return Err(fail(
                            "cross-attempt denial lost actual foreign listener or private positive",
                        ));
                    }
                    for namespace in [
                        "mount_namespace",
                        "pid_namespace",
                        "network_namespace",
                        "ipc_namespace",
                    ] {
                        if native[namespace] == before["native"][namespace] {
                            return Err(fail("different attempts shared a private namespace"));
                        }
                    }
                    if native["target"] == before["native"]["target"]
                        || native["root_device"] == before["native"]["root_device"]
                            && native["root_inode"] == before["native"]["root_inode"]
                        || family == "L-ISO-06"
                            && native["target_uid"] != before["native"]["target_uid"]
                    {
                        return Err(fail(
                            "cross-attempt test reused target/root or failed to exercise shared UID",
                        ));
                    }
                    if kind == "proc-fd" {
                        let positive = operation(rows, "isolation-private-opath-positive")?;
                        if positive["mode"]
                            .as_u64()
                            .is_none_or(|mode| mode & 0o170000 != 0o100000)
                            || positive["inode"].as_u64().is_none_or(|inode| inode == 0)
                            || binary(&positive["bytes"])? != peer.challenge.as_bytes()
                        {
                            return Err(fail(
                                "foreign descriptor denial lost native private O_PATH positive",
                            ));
                        }
                    }
                    Ok(())
                })?;
                if scenario == "stale-resource-owner" {
                    stale_recovery(context.caller, &peer, work)?;
                }
                let before_processes = before["processes"]
                    .as_array()
                    .ok_or_else(|| fail("original live holder population absent"))?;
                if owners.len() != before_processes.len() || owners.is_empty() {
                    return Err(fail("live holder owner set differs"));
                }
                for (owner, observed) in owners.iter().zip(before_processes) {
                    if owner.exited().map_err(CiError::Message)?
                        || serde_json::to_value(owner.live_snapshot().map_err(CiError::Message)?)?
                            != observed["snapshot"]
                    {
                        return Err(fail("held listener owner changed during peer test"));
                    }
                }
                acknowledge(context.caller, &peer, context.cleanup)?;
                original_ready = Some(ready);
                peer_case = Some(peer);
                launch.send_input(b"R".to_vec())?;
                Ok(Value::Null)
            };
        let holder = linux_test_execution::run_recipe_with_intervention(
            TestInput {
                controller_directory: &controller,
                caller: context.caller,
                images: context.images,
                provider: context.provider,
                directory: &context.working.join(scenario).with_extension("holder"),
                work_cutoff: work,
                cleanup_cutoff: context.cleanup,
            },
            selected,
            &mut intervention,
        )?;
        if peer_case.is_none() {
            return Err(fail("cross-attempt peer was not actually executed"));
        }
        let original = original_ready.ok_or_else(|| fail("held listener phase absent"))?;
        assert_case_with(&holder, |rows, result, _| {
            succeeded(result)?;
            let ready = operation(rows, "isolation-listener-ready")?;
            let retired = operation(rows, "isolation-listener-retired")?;
            if *ready != original["observation"]
                || binary(&ready["positive_bytes"])? != holder.challenge.as_bytes()
            {
                return Err(fail("holder listener positive/challenge changed"));
            }
            for field in [
                "tcp",
                "abstract_name",
                "tcp_descriptor",
                "abstract_descriptor",
            ] {
                if ready[field] != retired[field] {
                    return Err(fail("holder replaced listener before native retirement"));
                }
            }
            Ok(())
        })?;
        acknowledge(context.caller, &holder, context.cleanup)?;
    }
    Ok(())
}

fn stale_recovery(caller: &CallerSession, case: &ExecutedCase, work: Instant) -> Result<()> {
    let name = hex::encode(case.locator.attempt);
    let paths = [
        std::path::PathBuf::from("/var/lib/memcordon/workload-inputs").join(&name),
        std::path::PathBuf::from("/run/memcordon").join(format!("private-root-{name}")),
        std::path::PathBuf::from("/var/lib/memcordon/workload-resources").join(&name),
        std::path::PathBuf::from("/sys/fs/cgroup/memcordon-sealed").join(&name),
    ];
    let absent = || -> Result<()> {
        for path in &paths {
            match fs::symlink_metadata(path) {
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(fail("retired peer retained an actual native resource")),
            }
        }
        Ok(())
    };
    absent()?;
    let report = case.directory.join("stale-recovery.json");
    let mut held = None;
    let output = caller
        .command(&case.directory, work)?
        .args(["workload", "recover", "--observation"])
        .arg(case.directory.join("workload-observation.json"))
        .arg("--report")
        .arg(&report)
        .output_quiet_with_exec_observation(|child| {
            let birth = crate::linux_consumer_readiness::process_birth(child.id())
                .map_err(CiError::Message)?;
            held = Some(
                crate::linux_consumer_readiness::HeldLinuxProcess::acquire(child.id(), birth)
                    .map_err(CiError::Message)?,
            );
            Ok(())
        })?;
    crate::command::require_successful_output(
        "current recovery of an already retired attempt",
        &output,
    )?;
    if !output.stdout.is_empty()
        || !output.stderr.is_empty()
        || !held
            .ok_or_else(|| fail("stale recovery child was not held"))?
            .exited()
            .map_err(CiError::Message)?
    {
        return Err(fail(
            "stale recovery produced unexpected bytes or retained its native child",
        ));
    }
    let terminal = memcordon_core::result_v3::LinuxWorkloadTerminalV1::parse(&fs::read(report)?)
        .map_err(CiError::Message)?;
    let result = serde_json::to_value(
        case.result
            .as_ref()
            .ok_or_else(|| fail("stale recovery lacks original result"))?,
    )?;
    let value = serde_json::to_value(&terminal)?;
    if terminal.association != case.locator
        || value["request"] != result["request"]
        || value["native"] != result["runtime"]["native"]
        || value["outcome"] != serde_json::json!({"kind":"exited","code":0})
        || value["cleanup"]["state"] != "complete"
        || value["failures"] != serde_json::json!([])
    {
        return Err(fail(
            "stale recovery rebound or recreated original attempt state",
        ));
    }
    absent()
}
