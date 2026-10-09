//! MemCordon-owned workload behavior; provider evidence remains independently checked.
pub mod descriptor;
mod native;
mod toolchain;

use descriptor::{Case, Descriptor};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub sequence: u32,
    pub stage: String,
    pub pid: u32,
    pub ordinal: Option<u32>,
    pub value: Vec<u8>,
}

struct Transcript {
    file: fs::File,
    sequence: u32,
}

impl Transcript {
    fn event(&mut self, stage: &str, ordinal: Option<u32>, value: &[u8]) -> io::Result<()> {
        let event = Event {
            sequence: self.sequence,
            stage: stage.into(),
            pid: std::process::id(),
            ordinal,
            value: value.to_vec(),
        };
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("event sequence overflow"))?;
        let bytes = serde_json::to_vec(&event).map_err(io::Error::other)?;
        let length = u32::try_from(bytes.len()).map_err(io::Error::other)?;
        self.file.write_all(&length.to_le_bytes())?;
        self.file.write_all(&bytes)?;
        self.file.flush()
    }
}

fn read_descriptor(path: &Path) -> io::Result<Descriptor> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !metadata.is_file()
        || metadata.len() > descriptor::MAX_DESCRIPTOR_BYTES as u64
    {
        return Err(io::Error::other(
            "descriptor is not a bounded ordinary file",
        ));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((descriptor::MAX_DESCRIPTOR_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    Descriptor::parse(&bytes).map_err(io::Error::other)
}

fn child_command() -> io::Result<Command> {
    let mut command = Command::new(std::env::current_exe()?);
    command.arg("consumer-readiness-windows");
    Ok(command)
}

fn frame_write(stream: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    stream.write_all(
        &u32::try_from(payload.len())
            .map_err(io::Error::other)?
            .to_le_bytes(),
    )?;
    stream.write_all(payload)?;
    stream.flush()
}

fn frame_read(stream: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length > 64 * 1024 {
        return Err(io::Error::other("application frame exceeds bound"));
    }
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

fn read_http_header(stream: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() >= 4096 {
            return Err(io::Error::other("HTTP header exceeds bound"));
        }
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        bytes.push(byte[0]);
    }
    Ok(bytes)
}

fn tcp_peer(port: u16, challenge: &[u8], output_root: &std::path::Path) -> io::Result<()> {
    let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))?;
    // The retained peer awaits server half-close through compiler/churn work;
    // the independently owned public deadline bounds that whole operation.
    stream.set_read_timeout(Some(Duration::from_secs(600)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    stream.write_all(b"GET /readiness HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
    let header = read_http_header(&mut stream)?;
    if header != b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" {
        return Err(io::Error::other("HTTP response differs"));
    }
    let mut received = Vec::new();
    frame_write(&mut received, &header)?;
    for payload in [Vec::new(), vec![0, 255, 128, 10], challenge.to_vec()] {
        frame_write(&mut stream, &payload)?;
        let actual = frame_read(&mut stream)?;
        if actual != payload {
            return Err(io::Error::other("TCP binary frame differs"));
        }
        frame_write(&mut received, &actual)?;
    }
    fs::write(output_root.join("tcp-peer-received.bin"), &received)?;
    stream.shutdown(Shutdown::Write)?;
    let mut byte = [0];
    if stream.read(&mut byte)? != 0 {
        return Err(io::Error::other("TCP half-close did not reach EOF"));
    }
    Ok(())
}

fn binary_files(descriptor: &Descriptor, transcript: &mut Transcript) -> io::Result<()> {
    let directory = descriptor.output_root.join("nested");
    fs::create_dir(&directory)?;
    fs::write(directory.join("empty.bin"), [])?;
    let bytes: Vec<u8> = (0..=255).collect();
    let temporary = directory.join("unrenamed.bin");
    fs::write(&temporary, &bytes)?;
    let renamed = directory.join("all-bytes.bin");
    fs::rename(temporary, &renamed)?;
    if fs::read(renamed)? != bytes {
        return Err(io::Error::other("binary file readback differs"));
    }
    fs::write(directory.join("challenge.bin"), &descriptor.challenge)?;
    transcript.event("binary-files", None, &descriptor.challenge)
}

fn joint(descriptor: &Descriptor, transcript: &mut Transcript, churn: bool) -> io::Result<()> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    // The original socket stays held until every IPC/churn/descendant stage completes.
    let conflicting_bind = match TcpListener::bind(address) {
        Ok(_) => return Err(io::Error::other("competing bind acquired live endpoint")),
        Err(error) => error,
    };
    let conflicting_code = conflicting_bind.raw_os_error();
    if conflicting_code != Some(10048) {
        return Err(io::Error::other(format!(
            "competing bind did not report WSAEADDRINUSE: {conflicting_bind}"
        )));
    }
    transcript.event(
        "tcp-conflicting-bind",
        None,
        &conflicting_code
            .expect("validated native bind code")
            .to_le_bytes(),
    )?;
    transcript.event("tcp-listener-owned", None, &address.port().to_le_bytes())?;
    if descriptor.case == Case::EndpointMismatch {
        let policy_endpoint = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let allowed = policy_endpoint.local_addr()?.port();
        let refusal = EndpointPolicy::ExactNumericPort(allowed)
            .check(address.port())
            .expect_err("two retained TCP listeners cannot own the same endpoint");
        transcript.event(
            "endpoint-policy-refused-before-readiness",
            None,
            &serde_json::to_vec(&refusal).map_err(io::Error::other)?,
        )?;
        let gate = descriptor
            .start_gate
            .as_ref()
            .ok_or_else(|| io::Error::other("endpoint refusal lacks owned observation barrier"))?;
        native::wait_controller_gate(
            std::ffi::OsStr::new(&format!("{gate}-endpoint-observed")),
            || Ok(()),
        )?;
        return Ok(());
    }
    let challenge_path = descriptor.output_root.join("tcp-challenge.bin");
    fs::write(&challenge_path, &descriptor.challenge)?;
    let mut peer = child_command()?
        .arg("tcp-peer")
        .arg(address.port().to_string())
        .arg(challenge_path)
        .arg(&descriptor.output_root)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    transcript.event(
        "tcp-peer-created",
        None,
        &serde_json::to_vec(&native::child_identity(&peer)?).map_err(io::Error::other)?,
    )?;
    let (mut stream, _) = listener.accept()?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let header = read_http_header(&mut stream)?;
    if header != b"GET /readiness HTTP/1.1\r\nHost: localhost\r\n\r\n" {
        return Err(io::Error::other("HTTP request differs"));
    }
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")?;
    let mut received = Vec::new();
    frame_write(&mut received, &header)?;
    for payload in [
        Vec::new(),
        vec![0, 255, 128, 10],
        descriptor.challenge.clone(),
    ] {
        let actual = frame_read(&mut stream)?;
        if actual != payload {
            return Err(io::Error::other("TCP application frame differs"));
        }
        frame_write(&mut received, &actual)?;
        frame_write(&mut stream, &payload)?;
    }
    fs::write(
        descriptor.output_root.join("tcp-server-received.bin"),
        &received,
    )?;
    let pipe = native::named_pipe_exchange(&descriptor.challenge)?;
    fs::write(
        descriptor
            .output_root
            .join("named-pipe-server-received.bin"),
        &pipe.server_received,
    )?;
    fs::write(
        descriptor
            .output_root
            .join("named-pipe-client-received.bin"),
        &pipe.client_received,
    )?;
    transcript.event("named-pipe-while-tcp-owned", None, &descriptor.challenge)?;
    binary_files(descriptor, transcript)?;
    toolchain::execute(descriptor, transcript)?;
    protected_write_probes(descriptor, transcript)?;
    if churn {
        process_churn(descriptor, transcript)?;
    } else {
        generation_chain(3, &descriptor.challenge)?;
        transcript.event("descendants-complete", None, &descriptor.challenge)?;
    }
    if let Some(gate) = &descriptor.completion_gate {
        native::wait_controller_gate(std::ffi::OsStr::new(gate), || {
            transcript.event(
                "capacity-live-before-natural-completion",
                None,
                &descriptor.challenge,
            )
        })?;
    }
    let mut byte = [0];
    if stream.read(&mut byte)? != 0 {
        return Err(io::Error::other("TCP peer did not half-close"));
    }
    stream.shutdown(Shutdown::Write)?;
    if !peer.wait()?.success() {
        return Err(io::Error::other("TCP child failed"));
    }
    transcript.event("tcp-peer-complete", None, &descriptor.challenge)
}

fn protected_write_probes(descriptor: &Descriptor, transcript: &mut Transcript) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    for path in &descriptor.denied_write_paths {
        match OpenOptions::new().write(true).create_new(true).open(path) {
            Err(error)
                if error.kind() == io::ErrorKind::PermissionDenied
                    && error.raw_os_error() == Some(5) =>
            {
                let receipt = serde_json::to_vec(&serde_json::json!({
                    "path_utf16":path.as_os_str().encode_wide().collect::<Vec<_>>(),
                    "win32_code":error.raw_os_error(),
                }))
                .map_err(io::Error::other)?;
                transcript.event("protected-write-denied", None, &receipt)?;
            }
            Err(error) => {
                return Err(io::Error::other(format!(
                    "protected write had wrong error: {error}"
                )));
            }
            Ok(_) => {
                return Err(io::Error::other(
                    "protected driver/provider write succeeded",
                ));
            }
        }
    }
    Ok(())
}

enum EndpointPolicy {
    ExactNumericPort(u16),
}

#[derive(Debug, Serialize)]
struct EndpointRefusal {
    kind: &'static str,
    allowed_port: u16,
    observed_port: u16,
}

impl EndpointPolicy {
    fn check(self, observed_port: u16) -> Result<(), EndpointRefusal> {
        match self {
            Self::ExactNumericPort(allowed_port) if allowed_port == observed_port => Ok(()),
            Self::ExactNumericPort(allowed_port) => Err(EndpointRefusal {
                kind: "numeric-port-policy-mismatch",
                allowed_port,
                observed_port,
            }),
        }
    }
}

fn generation_chain(depth: u32, challenge: &[u8]) -> io::Result<()> {
    if depth == 0 {
        return Ok(());
    }
    let output = child_command()?
        .arg("generation")
        .arg((depth - 1).to_string())
        .arg(serde_json::to_string(challenge).map_err(io::Error::other)?)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !output.status.success() || output.stdout != challenge || !output.stderr.is_empty() {
        return Err(io::Error::other(
            "generated descendant output/status differs",
        ));
    }
    Ok(())
}

fn process_churn(descriptor: &Descriptor, transcript: &mut Transcript) -> io::Result<()> {
    let mut ordinal = 0u32;
    while ordinal < descriptor.churn_creations {
        let cohort = descriptor
            .churn_live
            .min(descriptor.churn_creations - ordinal);
        let mut children: Vec<(u32, Child)> = Vec::new();
        for _ in 0..cohort {
            // Each ordinal creates one process. Extra depth probes are explicit
            // supplemental creations, never counted in the frozen 4096 units.
            let child = child_command()?
                .arg("cohort-leaf")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            transcript.event(
                "child-created",
                Some(ordinal),
                &serde_json::to_vec(&native::child_identity(&child)?).map_err(io::Error::other)?,
            )?;
            children.push((ordinal, child));
            ordinal = ordinal
                .checked_add(1)
                .ok_or_else(|| io::Error::other("ordinal overflow"))?;
        }
        // Hold every child at its native stdio barrier; the driver can retain
        // process handles while the transcript publishes the complete cohort.
        for (_, child) in &mut children {
            let mut ready = [0; 1];
            child
                .stdout
                .as_mut()
                .ok_or_else(|| io::Error::other("missing child stdout"))?
                .read_exact(&mut ready)?;
            if ready != [0xA5] {
                return Err(io::Error::other("cohort readiness differs"));
            }
        }
        transcript.event("cohort-live", Some(ordinal), &cohort.to_le_bytes())?;
        native::wait_controller_gate_reset(std::ffi::OsStr::new(
            descriptor
                .cohort_gate
                .as_ref()
                .expect("validated cohort gate"),
        ))?;
        for (_, child) in &mut children {
            child
                .stdin
                .take()
                .ok_or_else(|| io::Error::other("missing child stdin"))?
                .write_all(&[0x5A])?;
        }
        for (unit, child) in children {
            let output = child.wait_with_output()?;
            if !output.status.success() || !output.stdout.is_empty() || !output.stderr.is_empty() {
                return Err(io::Error::other(
                    "churn child failed or emitted unexpected bytes",
                ));
            }
            transcript.event("child-completed", Some(unit), &[])?;
        }
        let gate = descriptor
            .generation_gate
            .as_ref()
            .expect("validated generation gate");
        let mut generation = child_command()?
            .arg("held-generation")
            .arg("2")
            .arg(gate)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut ready = [0];
        generation
            .stdout
            .as_mut()
            .expect("piped generation readiness")
            .read_exact(&mut ready)?;
        if ready != [0xA5] {
            return Err(io::Error::other("held generation did not become live"));
        }
        transcript.event("generation-live", Some(ordinal), &[])?;
        let output = generation.wait_with_output()?;
        if !output.status.success() || !output.stdout.is_empty() || !output.stderr.is_empty() {
            return Err(io::Error::other(
                "held three-generation branch did not complete",
            ));
        }
    }
    transcript.event("churn-complete", None, &ordinal.to_le_bytes())
}

pub fn run(mut args: impl Iterator<Item = OsString>) -> io::Result<i32> {
    let first = args
        .next()
        .ok_or_else(|| io::Error::other("missing Windows workload input"))?;
    match first.to_str() {
        Some("argv-nul-refusal") => {
            use std::os::windows::ffi::OsStringExt;
            let program = args
                .next()
                .ok_or_else(|| io::Error::other("NUL refusal target missing"))?;
            let contract_path = args
                .next()
                .ok_or_else(|| io::Error::other("NUL refusal contract missing"))?;
            let output = args
                .next()
                .ok_or_else(|| io::Error::other("NUL refusal output missing"))?;
            if args.next().is_some() {
                return Err(io::Error::other("unexpected NUL refusal arguments"));
            }
            let contract = memcordon_core::workload_contract::WorkloadContractV1::parse(&fs::read(
                contract_path,
            )?)
            .map_err(io::Error::other)?;
            let policy = memcordon::Policy::new(memcordon::ByteSize::gib(4))
                .sealed()
                .with_workload_contract(contract)
                .map_err(io::Error::other)?;
            let native_argument = vec![b'a' as u16, 0, b'b' as u16];
            let command =
                memcordon::CommandSpec::new(program).args([OsString::from_wide(&native_argument)]);
            let result = memcordon::Limiter::new(policy).command(command).run();
            let error = result
                .err()
                .ok_or_else(|| io::Error::other("native NUL command unexpectedly authorized"))?;
            let evidence = serde_json::json!({"format":"memcordon.windows-native-argv-refusal", "revision":1,
                "argument_utf16":native_argument, "code":error.code, "category":format!("{:?}", error.category),
                "target_pid":error.target_pid, "target_released":error.target_released,
                "provider_association":error.provider_association, "detail":error.message});
            let bytes = serde_json::to_vec(&evidence).map_err(io::Error::other)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            if fs::read(&output)? != bytes {
                return Err(io::Error::other(
                    "native NUL refusal named readback differs",
                ));
            }
            if error.code != "MCSEALED-WINDOWS-REQUEST"
                || !matches!(error.category, memcordon_core::ErrorCategory::Usage)
                || error.target_pid.is_some()
                || error.target_released
            {
                return Err(io::Error::other(
                    "native NUL argument did not fail before target authorization",
                ));
            }
            return Ok(0);
        }
        Some("token-snapshot") => {
            if args.next().is_some() {
                return Err(io::Error::other("extra token snapshot arguments"));
            }
            io::stdout().write_all(&native::token_observation()?)?;
            return Ok(0);
        }
        Some("restricted-frontend") => return native::restricted_frontend(args),
        Some("sentinel-frontend") => return native::sentinel_frontend(args),
        Some("tcp-peer") => {
            let port = args
                .next()
                .and_then(|p| p.to_str().and_then(|s| s.parse::<u16>().ok()))
                .ok_or_else(|| io::Error::other("invalid TCP peer port"))?;
            let path = args
                .next()
                .ok_or_else(|| io::Error::other("missing peer challenge"))?;
            let output_root = args
                .next()
                .ok_or_else(|| io::Error::other("missing peer output root"))?;
            if args.next().is_some() {
                return Err(io::Error::other("extra peer arguments"));
            }
            tcp_peer(port, &fs::read(path)?, std::path::Path::new(&output_root))?;
            return Ok(0);
        }
        Some("generation") => {
            let depth = args
                .next()
                .and_then(|p| p.to_str().and_then(|s| s.parse::<u32>().ok()))
                .filter(|depth| *depth <= 3)
                .ok_or_else(|| io::Error::other("invalid generation depth"))?;
            let bytes: Vec<u8> = serde_json::from_str(
                &args
                    .next()
                    .and_then(|p| p.into_string().ok())
                    .ok_or_else(|| io::Error::other("missing generation challenge"))?,
            )
            .map_err(io::Error::other)?;
            if bytes.len() > 4096 || args.next().is_some() {
                return Err(io::Error::other("generation input exceeds bound"));
            }
            generation_chain(depth, &bytes)?;
            io::stdout().write_all(&bytes)?;
            return Ok(0);
        }
        Some("token-change-child") => {
            let output = args
                .next()
                .ok_or_else(|| io::Error::other("missing token-change output"))?;
            let challenge = args
                .next()
                .ok_or_else(|| io::Error::other("missing token-change challenge"))?;
            if args.next().is_some() {
                return Err(io::Error::other("extra token-change argv"));
            }
            let challenge: Vec<u8> = serde_json::from_str(
                challenge
                    .to_str()
                    .ok_or_else(|| io::Error::other("invalid challenge encoding"))?,
            )
            .map_err(io::Error::other)?;
            if challenge.len() > 4096 {
                return Err(io::Error::other("token-change challenge exceeds bound"));
            }
            native::assert_job_and_sentinels(&[])?;
            let token = native::token_observation()?;
            let observed: serde_json::Value =
                serde_json::from_slice(&token).map_err(io::Error::other)?;
            if observed
                .get("restricted")
                .and_then(serde_json::Value::as_bool)
                != Some(true)
            {
                return Err(io::Error::other(
                    "token-change child did not retain the restricted native envelope",
                ));
            }
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output)?
                .write_all(&challenge)?;
            io::stdout().write_all(&token)?;
            return Ok(0);
        }
        Some("intermediate-exit") => {
            let gate = args
                .next()
                .ok_or_else(|| io::Error::other("missing intermediate gate"))?;
            let output = args
                .next()
                .ok_or_else(|| io::Error::other("missing intermediate output"))?;
            let challenge = args
                .next()
                .ok_or_else(|| io::Error::other("missing intermediate challenge"))?;
            if args.next().is_some() {
                return Err(io::Error::other("extra intermediate argv"));
            }
            let mut child = child_command()?
                .arg("descendant-hold")
                .arg(gate)
                .arg(output)
                .arg(challenge)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()?;
            let mut ready = [0];
            child
                .stdout
                .as_mut()
                .expect("piped readiness")
                .read_exact(&mut ready)?;
            if ready != [0xA5] || child.try_wait()?.is_some() {
                return Err(io::Error::other("grandchild was not held live"));
            }
            frame_write(
                &mut io::stdout(),
                &serde_json::to_vec(&native::child_identity(&child)?).map_err(io::Error::other)?,
            )?;
            let mut release = [0_u8];
            io::stdin().read_exact(&mut release)?;
            if release != [0xA5] {
                return Err(io::Error::other("intermediate controller release differs"));
            }
            return Ok(0);
        }
        Some("held-generation") => {
            let depth = args
                .next()
                .and_then(|p| p.to_str().and_then(|s| s.parse::<u32>().ok()))
                .filter(|depth| *depth <= 2)
                .ok_or_else(|| io::Error::other("invalid held generation depth"))?;
            let gate = args
                .next()
                .ok_or_else(|| io::Error::other("missing generation gate"))?;
            if args.next().is_some() {
                return Err(io::Error::other("extra generation args"));
            }
            if depth == 0 {
                io::stdout().write_all(&[0xA5])?;
                io::stdout().flush()?;
                native::wait_controller_gate_reset(&gate)?;
            } else {
                let mut child = child_command()?
                    .arg("held-generation")
                    .arg((depth - 1).to_string())
                    .arg(&gate)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()?;
                let mut ready = [0];
                child
                    .stdout
                    .as_mut()
                    .expect("piped readiness")
                    .read_exact(&mut ready)?;
                if ready != [0xA5] {
                    return Err(io::Error::other("nested generation readiness differs"));
                }
                io::stdout().write_all(&[0xA5])?;
                io::stdout().flush()?;
                let output = child.wait_with_output()?;
                if !output.status.success()
                    || !output.stdout.is_empty()
                    || !output.stderr.is_empty()
                {
                    return Err(io::Error::other("nested held generation failed"));
                }
            }
            return Ok(0);
        }
        Some("cohort-leaf") => {
            if args.next().is_some() {
                return Err(io::Error::other("extra leaf arguments"));
            }
            native::assert_job_and_sentinels(&[])?;
            io::stdout().write_all(&[0xA5])?;
            io::stdout().flush()?;
            let mut gate = [0];
            io::stdin().read_exact(&mut gate)?;
            if gate != [0x5A] {
                return Err(io::Error::other("cohort release differs"));
            }
            return Ok(0);
        }
        Some("descendant-hold") => {
            let gate = args
                .next()
                .ok_or_else(|| io::Error::other("missing descendant gate"))?;
            let output = args
                .next()
                .ok_or_else(|| io::Error::other("missing descendant product"))?;
            let bytes: Vec<u8> = serde_json::from_str(
                &args
                    .next()
                    .and_then(|p| p.into_string().ok())
                    .ok_or_else(|| io::Error::other("missing descendant challenge"))?,
            )
            .map_err(io::Error::other)?;
            if bytes.len() > 4096 || args.next().is_some() {
                return Err(io::Error::other("descendant input exceeds bound"));
            }
            native::wait_controller_gate(&gate, || {
                io::stdout().write_all(&[0xA5])?;
                io::stdout().flush()
            })?;
            fs::write(output, bytes)?;
            return Ok(0);
        }
        _ => {}
    }
    let descriptor = read_descriptor(Path::new(&first))?;
    let actual_arguments: Vec<OsString> = args.collect();
    if actual_arguments
        != descriptor
            .arguments
            .iter()
            .map(OsString::from)
            .collect::<Vec<_>>()
    {
        return Err(io::Error::other(
            "native argv differs from independently supplied descriptor",
        ));
    }
    use std::os::windows::ffi::OsStrExt;
    let actual_argv = serde_json::to_vec(&serde_json::json!({
        "encoding":"windows_utf16", "values":actual_arguments.iter().map(|argument|argument.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>(),
    })).map_err(io::Error::other)?;
    fs::write(
        descriptor.output_root.join("native-argv.json"),
        &actual_argv,
    )?;
    let mut transcript = Transcript {
        file: OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&descriptor.transcript)?,
        sequence: 0,
    };
    transcript.event("started", None, &descriptor.challenge)?;
    transcript.event("native-argv-observed", None, &actual_argv)?;
    native::assert_job_and_sentinels(&descriptor.sentinel_handles)?;
    transcript.event(
        "sentinel-handles-excluded",
        None,
        &u32::try_from(descriptor.sentinel_handles.len())
            .map_err(io::Error::other)?
            .to_le_bytes(),
    )?;
    let envelope = native::token_observation()?;
    transcript.event("token-envelope", None, &envelope)?;
    if let Some(gate) = &descriptor.start_gate {
        native::wait_controller_gate(std::ffi::OsStr::new(gate), || Ok(()))?;
        transcript.event("controller-released", None, &descriptor.challenge)?;
    }
    match descriptor.case {
        Case::Joint | Case::EndpointMismatch => joint(&descriptor, &mut transcript, false)?,
        Case::Churn => joint(&descriptor, &mut transcript, true)?,
        Case::Toolchain => toolchain::execute(&descriptor, &mut transcript)?,
        Case::BinaryFiles => binary_files(&descriptor, &mut transcript)?,
        Case::BinaryStreams => {
            let stdout = descriptor.stdout.clone();
            let stderr = descriptor.stderr.clone();
            let out = thread::spawn(move || -> io::Result<()> {
                for _ in 0..128 {
                    io::stdout().write_all(&stdout)?;
                }
                io::stdout().flush()
            });
            for _ in 0..128 {
                io::stderr().write_all(&stderr)?;
            }
            io::stderr().flush()?;
            out.join()
                .map_err(|_| io::Error::other("stdout writer panicked"))??;
        }
        Case::Envelope => {
            if !descriptor.denied_write_paths.is_empty() {
                binary_files(&descriptor, &mut transcript)?;
                protected_write_probes(&descriptor, &mut transcript)?;
            }
        }
        Case::EmptyStreams | Case::NativeArgv | Case::ApplicationExit => {}
        Case::DeadlineDemand | Case::HeldDemand => {
            let mut child = child_command()?
                .arg("cohort-leaf")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            let mut ready = [0u8];
            child
                .stdout
                .as_mut()
                .ok_or_else(|| io::Error::other("demand child readiness pipe absent"))?
                .read_exact(&mut ready)?;
            if ready != [0xA5] {
                return Err(io::Error::other(
                    "demand child did not enter native held barrier",
                ));
            }
            transcript.event(
                "child-created",
                Some(0),
                &serde_json::to_vec(&native::child_identity(&child)?).map_err(io::Error::other)?,
            )?;
            transcript.event("policy-demand-started", None, &descriptor.challenge)?;
            loop {
                std::hint::black_box(&child);
                thread::sleep(Duration::from_millis(5));
            }
        }
        Case::MemoryDemand => {
            transcript.event("policy-demand-started", None, &descriptor.challenge)?;
            let mut committed = Vec::<Vec<u8>>::new();
            loop {
                let mut allocation = Vec::new();
                if allocation.try_reserve_exact(8 * 1024 * 1024).is_err() {
                    loop {
                        thread::sleep(Duration::from_millis(5));
                    }
                }
                allocation.resize(8 * 1024 * 1024, 0xA5);
                std::hint::black_box(&allocation);
                committed.push(allocation);
                std::hint::black_box(&committed);
            }
        }
        Case::NestedJob => native::nested_job()?,
        Case::BreakawayDenied => native::breakaway_denied()?,
        Case::AllowedTokenChange => {
            let executable = std::env::current_exe()?;
            let output = child_command()?
                .arg("restricted-frontend")
                .arg(&executable)
                .arg("consumer-readiness-windows")
                .arg("token-change-child")
                .arg(descriptor.output_root.join("token-change-output.bin"))
                .arg(serde_json::to_string(&descriptor.challenge).map_err(io::Error::other)?)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()?;
            if !output.status.success() || !output.stderr.is_empty() {
                return Err(io::Error::other("allowed token-change descendant failed"));
            }
            transcript.event("allowed-token-change-retained-job", None, &output.stdout)?;
        }
        Case::RootFirst | Case::IntermediateFirst => {
            let gate = descriptor
                .descendant_gate
                .as_ref()
                .expect("validated descendant gate");
            let owned_gate = native::create_controller_gate(gate)?;
            if descriptor.case == Case::IntermediateFirst {
                let intermediate_gate = format!("{gate}-intermediate-live");
                let intermediate_owner = native::create_controller_gate(&intermediate_gate)?;
                let mut intermediate = child_command()?
                    .arg("intermediate-exit")
                    .arg(gate)
                    .arg(descriptor.output_root.join("descendant-output.bin"))
                    .arg(serde_json::to_string(&descriptor.challenge).map_err(io::Error::other)?)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .spawn()?;
                let identity: memcordon_core::WindowsProcessIdentityV1 = serde_json::from_slice(
                    &frame_read(intermediate.stdout.as_mut().expect("piped intermediate"))?,
                )
                .map_err(io::Error::other)?;
                let parent = native::child_identity(&intermediate)?;
                transcript.event(
                    "intermediate-live-with-descendant",
                    None,
                    &serde_json::to_vec(&serde_json::json!({"parent":parent,"child":identity}))
                        .map_err(io::Error::other)?,
                )?;
                native::wait_controller_gate(std::ffi::OsStr::new(&intermediate_gate), || Ok(()))?;
                intermediate
                    .stdin
                    .take()
                    .expect("piped intermediate release")
                    .write_all(&[0xA5])?;
                if !intermediate.wait()?.success() {
                    return Err(io::Error::other("intermediate did not exit naturally"));
                }
                drop(intermediate_owner);
                transcript.event(
                    "intermediate-exits-with-live-descendant",
                    None,
                    &serde_json::to_vec(&identity).map_err(io::Error::other)?,
                )?;
                native::wait_controller_gate(std::ffi::OsStr::new(gate), || Ok(()))?;
                drop(owned_gate);
            } else {
                let mut child = child_command()?
                    .arg("descendant-hold")
                    .arg(gate)
                    .arg(descriptor.output_root.join("descendant-output.bin"))
                    .arg(serde_json::to_string(&descriptor.challenge).map_err(io::Error::other)?)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .spawn()?;
                let mut ready = [0];
                child
                    .stdout
                    .as_mut()
                    .expect("piped stdout")
                    .read_exact(&mut ready)?;
                if ready != [0xA5] || child.try_wait()?.is_some() {
                    return Err(io::Error::other("descendant was not held live"));
                }
                let identity = native::child_identity(&child)?;
                transcript.event(
                    "root-exits-with-live-descendant",
                    None,
                    &serde_json::to_vec(&identity).map_err(io::Error::other)?,
                )?;
                drop(owned_gate);
            }
            // Intentionally relinquish only the root's wait; Job ownership must
            // continue after this process exits. Collection drains descendant I/O.
        }
    }
    transcript.event("finished", None, &descriptor.challenge)?;
    transcript.file.sync_all()?;
    if descriptor.case == Case::EndpointMismatch {
        Ok(42)
    } else {
        Ok(i32::try_from(descriptor.application_status).map_err(io::Error::other)?)
    }
}
