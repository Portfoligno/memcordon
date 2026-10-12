use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Transcript {
    sequence: u64,
    challenge: String,
}
impl Transcript {
    fn record(&mut self, operation: &str, observation: serde_json::Value) -> Result<()> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or("transcript sequence overflow")?;
        let row = serde_json::json!({"format":"memcordon.linux-readiness-transcript","revision":1,
            "sequence":self.sequence,"challenge":self.challenge,"root_pid":std::process::id(),
            "root_birth":birth(std::process::id())?,"operation":operation,"observation":observation});
        let mut output = io::stdout().lock();
        serde_json::to_writer(&mut output, &row)?;
        output.write_all(b"\n")?;
        output.flush()?;
        Ok(())
    }
}

fn birth(pid: u32) -> Result<u64> {
    let stat = std::fs::read_to_string(
        std::path::Path::new("/proc")
            .join(pid.to_string())
            .join("stat"),
    )?;
    let (_, fields) = stat
        .rsplit_once(')')
        .ok_or("native process stat malformed")?;
    Ok(fields
        .split_whitespace()
        .nth(19)
        .ok_or("native process birth absent")?
        .parse()?)
}

pub fn run() -> Result<()> {
    let mut arguments = std::env::args_os().skip(1);
    let mode = arguments.next().ok_or("fixture mode absent")?;
    if mode == "native-export-permission" {
        return crate::native_export::run(arguments);
    }
    let challenge = arguments
        .next()
        .ok_or("challenge absent")?
        .into_string()
        .map_err(|_| "challenge not UTF-8")?;
    if challenge.len() != 64
        || !challenge.bytes().all(|b| b.is_ascii_hexdigit())
        || challenge.bytes().all(|b| b == b'0')
    {
        return Err("challenge must be a nonzero 32-byte hexadecimal value".into());
    }
    let mut transcript = Transcript {
        sequence: 0,
        challenge,
    };
    match mode.to_str().ok_or("mode not UTF-8")? {
        "exec-held" => {
            use std::os::unix::process::CommandExt;
            let program = arguments.next().ok_or("held native executable absent")?;
            if !std::path::Path::new(&program).is_absolute() {
                return Err("held executable must be absolute".into());
            }
            announce_child(Vec::new())?;
            wait_release()?;
            Err(std::process::Command::new(program)
                .args(arguments)
                .exec()
                .into())
        }
        "export-object" => {
            let scenario = arguments
                .next()
                .ok_or("export scenario absent")?
                .into_string()
                .map_err(|_| "export scenario not UTF-8")?;
            if arguments.next().is_some() {
                return Err("unexpected export argument".into());
            }
            export_object(&mut transcript, &scenario)
        }
        "export-writer-child" => {
            if arguments.next().is_some() {
                return Err("unexpected writer-child argument".into());
            }
            export_writer_child()
        }
        "cooperation" => {
            if arguments.next().is_some() {
                return Err("unexpected cooperation argument".into());
            }
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
            let endpoint = listener.local_addr()?;
            let mut child = std::process::Command::new(std::env::current_exe()?)
                .arg("cooperation-peer")
                .arg(&transcript.challenge)
                .arg(endpoint.to_string())
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::inherit())
                .spawn()?;
            let pid = child.id();
            let child_birth = birth(pid)?;
            let mut reader = std::io::BufReader::new(
                child
                    .stdout
                    .take()
                    .ok_or("cooperation child output absent")?,
            );
            use std::io::BufRead;
            let mut ready = Vec::new();
            reader.by_ref().take(65536).read_until(b'\n', &mut ready)?;
            if !ready.ends_with(b"\n") {
                return Err("cooperation child readiness absent".into());
            }
            transcript.record("same-attempt-cooperation-held",serde_json::json!({"pid":pid,"birth":child_birth,"members":[],"endpoint":endpoint.to_string(),"transcript":ready}))?;
            wait_release()?;
            child
                .stdin
                .as_mut()
                .ok_or("cooperation child gate absent")?
                .write_all(b"R")?;
            let (mut server, _) = listener.accept()?;
            server.set_read_timeout(Some(Duration::from_secs(5)))?;
            server.set_write_timeout(Some(Duration::from_secs(5)))?;
            let expected = transcript.challenge.as_bytes();
            let mut received = vec![0; expected.len()];
            server.read_exact(&mut received)?;
            if received != expected {
                return Err("cooperation server received different challenge".into());
            }
            server.write_all(&received)?;
            drop(server);
            let mut peer = Vec::new();
            reader.take(65537).read_to_end(&mut peer)?;
            if peer.len() > 65536 {
                return Err("cooperation child output exceeds bound".into());
            }
            let status = child.wait()?;
            if !status.success() {
                return Err("cooperation child failed".into());
            }
            transcript.record("same-attempt-cooperation-complete",serde_json::json!({"pid":pid,"birth":child_birth,"endpoint":endpoint.to_string(),"server_received":received,"peer_transcript":peer,"native_status":status.code()}))?;
            Ok(())
        }
        "cooperation-peer" => {
            let endpoint: std::net::SocketAddr = arguments
                .next()
                .ok_or("cooperation endpoint absent")?
                .into_string()
                .map_err(|_| "endpoint not UTF-8")?
                .parse()?;
            if arguments.next().is_some()
                || !endpoint.is_ipv4()
                || !endpoint.ip().is_loopback()
                || endpoint.port() == 0
            {
                return Err("cooperation peer endpoint differs".into());
            }
            transcript.record(
                "cooperation-peer-ready",
                serde_json::json!({"endpoint":endpoint.to_string()}),
            )?;
            wait_release()?;
            let mut client = TcpStream::connect_timeout(&endpoint, Duration::from_secs(5))?;
            client.set_read_timeout(Some(Duration::from_secs(5)))?;
            client.set_write_timeout(Some(Duration::from_secs(5)))?;
            client.write_all(transcript.challenge.as_bytes())?;
            let mut received = vec![0; transcript.challenge.len()];
            client.read_exact(&mut received)?;
            if received != transcript.challenge.as_bytes() {
                return Err("cooperation peer received different challenge".into());
            }
            transcript.record(
                "cooperation-peer-received",
                serde_json::json!({"endpoint":endpoint.to_string(),"bytes":received}),
            )?;
            Ok(())
        }
        "tcp-http" => {
            if arguments.next().is_some() {
                return Err("unexpected TCP fixture argument".into());
            }
            tcp_http(&mut transcript, None, false)
        }
        "endpoint-mismatch" => {
            if arguments.next().is_some() {
                return Err("unexpected mismatch argument".into());
            }
            let intended = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
            let competitor = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
            if intended.local_addr()? == competitor.local_addr()? {
                return Err("distinct retained endpoints aliased".into());
            }
            let peer =
                TcpStream::connect_timeout(&competitor.local_addr()?, Duration::from_secs(5))?;
            let (accepted, _) = competitor.accept()?;
            transcript.record("application-endpoint-mismatch", serde_json::json!({"intended":intended.local_addr()?.to_string(),
                "observed":accepted.local_addr()?.to_string(),"both_listeners_retained":true,"readiness_reached":false,"application_status":42}))?;
            wait_release()?;
            drop(peer);
            drop(accepted);
            std::process::exit(42);
        }
        "joint" | "joint-reserved-exit" | "joint-memory" => {
            let directory = std::path::PathBuf::from(
                arguments.next().ok_or("owned writable directory absent")?,
            );
            let cargo =
                std::path::PathBuf::from(arguments.next().ok_or("owned Cargo executable absent")?);
            let rustc =
                std::path::PathBuf::from(arguments.next().ok_or("owned rustc executable absent")?);
            let linker =
                std::path::PathBuf::from(arguments.next().ok_or("owned linker executable absent")?);
            let manifest =
                std::path::PathBuf::from(arguments.next().ok_or("owned offline manifest absent")?);
            if arguments.next().is_some() {
                return Err("unexpected joint fixture argument".into());
            }
            tcp_http(
                &mut transcript,
                Some((directory, cargo, rustc, linker, manifest)),
                mode == "joint-memory",
            )?;
            if mode == "joint-reserved-exit" {
                transcript.record(
                    "joint-reserved-application-exit",
                    serde_json::json!({"requested_exit_code":125}),
                )?;
                std::process::exit(125);
            }
            Ok(())
        }
        "competing-bind" => {
            let endpoint: std::net::SocketAddr = arguments
                .next()
                .ok_or("competing endpoint absent")?
                .into_string()
                .map_err(|_| "endpoint not UTF-8")?
                .parse()?;
            if arguments.next().is_some() {
                return Err("unexpected competitor argument".into());
            }
            let error = TcpListener::bind(endpoint)
                .err()
                .ok_or("descendant competing bind succeeded")?;
            if error.raw_os_error() != Some(libc::EADDRINUSE) {
                return Err(error.into());
            }
            transcript.record("descendant-competing-bind", serde_json::json!({"endpoint":endpoint.to_string(),"native_errno":libc::EADDRINUSE}))?;
            wait_release()
        }
        "unix-rights" => {
            let directory =
                std::path::PathBuf::from(arguments.next().ok_or("owned UNIX directory absent")?);
            if arguments.next().is_some() {
                return Err("unexpected UNIX fixture argument".into());
            }
            unix_rights(&mut transcript, &directory)?.retire()
        }
        "bytes-argv-status" => {
            let status: i32 = arguments
                .next()
                .ok_or("native status absent")?
                .into_string()
                .map_err(|_| "status not UTF-8")?
                .parse()?;
            if !(0..=255).contains(&status) {
                return Err("native status outside exit byte".into());
            }
            use std::os::unix::ffi::OsStrExt;
            // The actual native vector includes the fixture bootstrap values;
            // it is compared with the exact provider target argv, not a
            // reconstructed suffix assembled from expected input.
            let actual_arguments: Vec<Vec<u8>> = std::env::args_os()
                .skip(1)
                .map(|value| value.as_bytes().to_vec())
                .collect();
            transcript.record(
                "native-argv-observed",
                serde_json::json!({"argv":actual_arguments,"native_exit_status":status}),
            )?;
            let bytes: Vec<u8> = (u8::MIN..=u8::MAX).collect();
            transcript.record("byte-vector", serde_json::json!({"bytes":bytes}))?;
            io::stderr().write_all(&bytes)?;
            io::stderr().flush()?;
            std::process::exit(status);
        }
        "raw-byte-streams" => {
            let bytes: Vec<u8> = (u8::MIN..=u8::MAX).collect();
            io::stdout().write_all(&bytes)?;
            io::stdout().flush()?;
            io::stderr().write_all(&bytes)?;
            io::stderr().flush()?;
            Ok(())
        }
        "binary-file" => {
            if arguments.next().is_some() {
                return Err("binary file fixture received unexpected argument".into());
            }
            let vector: Vec<u8> = (u8::MIN..=u8::MAX).collect();
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open("/work/binary-file.bin")?;
            file.write_all(&vector)?;
            file.sync_all()?;
            if std::fs::read("/work/binary-file.bin")? != vector {
                return Err("actual binary file readback differs".into());
            }
            transcript.record("binary-file-readback", serde_json::json!({"bytes":vector}))
        }
        "empty-message" => {
            if arguments.next().is_some() {
                return Err("empty message fixture received unexpected argument".into());
            }
            let (mut sender, mut receiver) = std::os::unix::net::UnixStream::pair()?;
            sender.set_write_timeout(Some(Duration::from_secs(5)))?;
            receiver.set_read_timeout(Some(Duration::from_secs(5)))?;
            sender.write_all(&0u32.to_le_bytes())?;
            let mut frame = [0u8; 4];
            receiver.read_exact(&mut frame)?;
            if u32::from_le_bytes(frame) != 0 {
                return Err("actual empty framed message length changed".into());
            }
            receiver.write_all(&frame)?;
            sender.read_exact(&mut frame)?;
            if frame != 0u32.to_le_bytes() {
                return Err("actual empty framed response changed".into());
            }
            transcript.record(
                "empty-message-exchanged",
                serde_json::json!({"received_length_prefix":frame,"payload":Vec::<u8>::new()}),
            )
        }
        "own-abstract-held" => {
            use std::os::fd::AsRawFd;
            use std::os::linux::net::SocketAddrExt;
            use std::os::unix::fs::MetadataExt;
            if arguments.next().is_some() {
                return Err("held abstract fixture received unexpected argument".into());
            }
            let name = format!("memcordon-readiness-{}", transcript.challenge).into_bytes();
            let address = std::os::unix::net::SocketAddr::from_abstract_name(&name)?;
            let listener = std::os::unix::net::UnixListener::bind_addr(&address)?;
            let mut client = std::os::unix::net::UnixStream::connect_addr(&address)?;
            let (mut server, _) = listener.accept()?;
            client.set_write_timeout(Some(Duration::from_secs(5)))?;
            server.set_read_timeout(Some(Duration::from_secs(5)))?;
            let payload = b"abstract-unix-readiness";
            client.write_all(payload)?;
            let mut received = vec![0; payload.len()];
            server.read_exact(&mut received)?;
            if received != payload {
                return Err("held abstract native roundtrip differs".into());
            }
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: the live owned listener remains open throughout this native observation.
            if unsafe { libc::fstat(listener.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
            // SAFETY: successful fstat initialized the native structure above.
            let stat = unsafe { stat.assume_init() };
            let observation = serde_json::json!({"name":name,"socket_inode":stat.st_ino,
                "network_namespace_inode":std::fs::metadata("/proc/self/ns/net")?.ino(),
                "baseline_client_connected":client.peer_addr()?.as_abstract_name()==Some(name.as_slice()),
                "baseline_server_accepted":server.local_addr()?.as_abstract_name()==Some(name.as_slice()),"bytes":received});
            transcript.record("other-attempt-abstract-held", observation.clone())?;
            wait_release()?;
            transcript.record("other-attempt-abstract-released", observation)
        }
        "own-abstract" => {
            use std::os::linux::net::SocketAddrExt;
            if arguments.next().is_some() {
                return Err("own abstract fixture received unexpected argument".into());
            }
            let name = transcript.challenge.as_bytes().to_vec();
            let address = std::os::unix::net::SocketAddr::from_abstract_name(&name)?;
            let listener = std::os::unix::net::UnixListener::bind_addr(&address)?;
            let mut client = std::os::unix::net::UnixStream::connect_addr(&address)?;
            let (mut server, _) = listener.accept()?;
            client.set_write_timeout(Some(Duration::from_secs(5)))?;
            server.set_read_timeout(Some(Duration::from_secs(5)))?;
            let payload = b"abstract-unix-readiness";
            client.write_all(payload)?;
            let mut received = vec![0; payload.len()];
            server.read_exact(&mut received)?;
            if received != payload {
                return Err("actual own abstract received bytes differ".into());
            }
            transcript.record(
                "unix-abstract-round-trip",
                serde_json::json!({"name":name,"bytes":received}),
            )
        }
        "empty-input" => {
            if arguments.next().is_some() {
                return Err("empty input fixture received unexpected argument".into());
            }
            let mut input = Vec::new();
            io::stdin().take(1).read_to_end(&mut input)?;
            if !input.is_empty() {
                return Err("declared empty native input was not EOF".into());
            }
            io::stdout().flush()?;
            io::stderr().flush()?;
            Ok(())
        }
        "bounded-large-output" => {
            if arguments.next().is_some() {
                return Err("large output fixture received unexpected argument".into());
            }
            let vector: Vec<u8> = (u8::MIN..=u8::MAX).collect();
            for _ in 0..8192 {
                io::stdout().write_all(&vector)?;
                io::stderr().write_all(&vector)?;
            }
            io::stdout().flush()?;
            io::stderr().flush()?;
            Ok(())
        }
        "authority-denial" => {
            let operation = arguments
                .next()
                .ok_or("authority probe operation absent")?
                .into_string()
                .map_err(|_| "probe not UTF-8")?;
            if arguments.next().is_some() {
                return Err("unexpected authority probe argument".into());
            }
            authority_denial(&mut transcript, &operation)
        }
        "descriptor-isolation" => {
            if arguments.next().is_some() {
                return Err("unexpected descriptor isolation operand".into());
            }
            let mut descriptors = Vec::new();
            for descriptor in 0..3 {
                let mut native = std::mem::MaybeUninit::<libc::stat>::uninit();
                // SAFETY: fstat writes one native stat into this valid pointer;
                // the object is read only after a successful return.
                if unsafe { libc::fstat(descriptor, native.as_mut_ptr()) } != 0 {
                    return Err(io::Error::last_os_error().into());
                }
                let native = unsafe { native.assume_init() };
                if native.st_mode & libc::S_IFMT != libc::S_IFIFO {
                    return Err(
                        "target inherited external socket instead of provider byte pipe".into(),
                    );
                }
                descriptors.push(serde_json::json!({"descriptor":descriptor,"device":native.st_dev,"inode":native.st_ino,"mode":native.st_mode}));
            }
            // SAFETY: F_GETFD has no pointer operand and does not mutate an FD.
            if unsafe { libc::fcntl(128, libc::F_GETFD) } != -1
                || io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
            {
                return Err("target retained hostile external descriptor128".into());
            }
            transcript.record("native-descriptor-isolation",serde_json::json!({"stdio":descriptors,"extra_descriptor":128,"native_errno":libc::EBADF}))?;
            let (mut left, mut right) = std::os::unix::net::UnixStream::pair()?;
            left.write_all(transcript.challenge.as_bytes())?;
            let mut observed = vec![0; transcript.challenge.len()];
            right.read_exact(&mut observed)?;
            if observed != transcript.challenge.as_bytes() {
                return Err("private descriptor neighbor roundtrip differs".into());
            }
            transcript.record(
                "private-unix-pair-positive",
                serde_json::json!({"bytes":observed}),
            )
        }
        "outside-file" => {
            let kind = arguments
                .next()
                .ok_or("outside file probe kind absent")?
                .into_string()
                .map_err(|_| "outside probe kind not UTF8")?;
            let path = arguments.next().ok_or("outside native pathname absent")?;
            let descriptor = if kind == "opath" {
                Some(
                    arguments
                        .next()
                        .ok_or("hostile O_PATH descriptor absent")?
                        .into_string()
                        .map_err(|_| "hostile descriptor not UTF8")?
                        .parse::<i32>()?,
                )
            } else {
                None
            };
            if arguments.next().is_some() {
                return Err("unexpected outside file operand".into());
            }
            outside_file(&mut transcript, &kind, &path, descriptor)
        }
        "forbidden-tcp" => {
            let endpoint: std::net::SocketAddr = arguments
                .next()
                .ok_or("owned forbidden TCP endpoint absent")?
                .into_string()
                .map_err(|_| "endpoint not UTF-8")?
                .parse()?;
            if !endpoint.is_ipv4() || arguments.next().is_some() {
                return Err("forbidden TCP endpoint shape differs".into());
            }
            let error = TcpStream::connect_timeout(&endpoint, Duration::from_secs(3))
                .err()
                .ok_or("forbidden external TCP communication succeeded")?;
            let code = error
                .raw_os_error()
                .ok_or("external TCP probe has no native errno")?;
            if ![
                libc::ECONNREFUSED,
                libc::ENETUNREACH,
                libc::EHOSTUNREACH,
                libc::EPERM,
            ]
            .contains(&code)
            {
                return Err(error.into());
            }
            transcript.record(
                "forbidden-tcp-denied",
                serde_json::json!({"endpoint":endpoint.to_string(),"native_errno":code}),
            )
        }
        "forbidden-unix-path" => {
            let path = std::path::PathBuf::from(
                arguments
                    .next()
                    .ok_or("owned forbidden Unix socket path absent")?,
            );
            if !path.is_absolute() || arguments.next().is_some() {
                return Err("forbidden Unix socket path shape differs".into());
            }
            let error = std::os::unix::net::UnixStream::connect(&path)
                .err()
                .ok_or("forbidden external Unix socket became target authority")?;
            let code = error
                .raw_os_error()
                .ok_or("forbidden Unix socket native errno absent")?;
            if ![
                libc::ENOENT,
                libc::EACCES,
                libc::EPERM,
                libc::ECONNREFUSED,
                libc::ENOTDIR,
            ]
            .contains(&code)
            {
                return Err(error.into());
            }
            // The neighboring positive exercises actual in-namespace socket IO,
            // so a blanket Unix-socket failure cannot satisfy this probe.
            let (mut sender, mut receiver) = std::os::unix::net::UnixStream::pair()?;
            sender.write_all(transcript.challenge.as_bytes())?;
            let mut observed = vec![0; transcript.challenge.len()];
            receiver.read_exact(&mut observed)?;
            if observed != transcript.challenge.as_bytes() {
                return Err("private Unix pair changed bytes".into());
            }
            transcript.record(
                "private-unix-pair-positive",
                serde_json::json!({"bytes": observed}),
            )?;
            transcript.record(
                "forbidden-unix-path-denied",
                serde_json::json!({"path":path,"native_errno":code}),
            )
        }
        "forbidden-path" => {
            let path =
                std::path::PathBuf::from(arguments.next().ok_or("owned forbidden path absent")?);
            if !path.is_absolute() || arguments.next().is_some() {
                return Err("forbidden path shape differs".into());
            }
            let error = std::fs::File::open(&path)
                .err()
                .ok_or("forbidden external file became target authority")?;
            let code = error
                .raw_os_error()
                .ok_or("forbidden path native errno absent")?;
            if ![
                libc::ENOENT,
                libc::EACCES,
                libc::EPERM,
                libc::ELOOP,
                libc::ENOTDIR,
            ]
            .contains(&code)
            {
                return Err(error.into());
            }
            transcript.record(
                "forbidden-path-denied",
                serde_json::json!({"path":path,"native_errno":code}),
            )
        }
        "forbidden-abstract" => {
            use std::os::linux::net::SocketAddrExt;
            use std::os::unix::ffi::OsStrExt;
            let name = arguments
                .next()
                .ok_or("owned forbidden abstract name absent")?;
            if arguments.next().is_some() {
                return Err("unexpected abstract probe argument".into());
            }
            let address = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
            let error = std::os::unix::net::UnixStream::connect_addr(&address)
                .err()
                .ok_or("forbidden cross-namespace abstract peer reached")?;
            let code = error.raw_os_error().ok_or("abstract denial errno absent")?;
            if ![libc::ECONNREFUSED, libc::EPERM, libc::EACCES].contains(&code) {
                return Err(error.into());
            }
            transcript.record(
                "forbidden-abstract-denied",
                serde_json::json!({"name":name.as_bytes(),"native_errno":code}),
            )
        }
        "held-child" => held_child(),
        "held-tree" => held_tree(),
        "tree-leaves" => tree_leaves(),
        "natural-churn" => natural_churn(&mut transcript),
        "population-deadline" => population(&mut transcript),
        "memory-pressure" => {
            transcript.record(
                "memory-pressure-ready",
                serde_json::json!({"chunk_bytes":1048576}),
            )?;
            wait_release()?;
            memory_pressure()
        }
        "memory-pressure-child" => {
            announce_child(Vec::new())?;
            wait_release()?;
            memory_pressure()
        }
        "memory-pressure-descendant" => {
            let (mut child, observation) =
                native_child("memory-pressure-child", &transcript.challenge)?;
            let result = (|| -> Result<()> {
                transcript.record(
                    "memory-pressure-descendant-held",
                    serde_json::json!({"native_tree":observation,"chunk_bytes":1048576}),
                )?;
                wait_release()?;
                child
                    .stdin
                    .as_mut()
                    .ok_or("memory child input owner absent")?
                    .write_all(b"R")?;
                loop {
                    std::thread::park_timeout(Duration::from_secs(1));
                }
            })();
            let original = result
                .err()
                .ok_or("memory descendant unexpectedly returned")?;
            let signal = child.kill();
            child.stdin.take();
            let reap = child.wait();
            if signal.is_err() || reap.is_err() {
                return Err(format!(
                    "{original}; memory child cleanup unresolved: signal={signal:?}, reap={reap:?}"
                )
                .into());
            }
            Err(original)
        }
        "orphan-child" => {
            let original_parent = unsafe { libc::getppid() } as u32;
            let original_parent_birth = birth(original_parent)?;
            announce_child(Vec::new())?;
            // The controller first holds this child, then releases its parent.
            // Only the parent's actual pipe closure delivers EOF here.
            let mut release = Vec::new();
            io::stdin().take(2).read_to_end(&mut release)?;
            if !release.is_empty() {
                return Err("orphan descendant received a fabricated release byte".into());
            }
            while unsafe { libc::getppid() } as u32 == original_parent {
                std::thread::sleep(Duration::from_millis(1));
            }
            let bytes: Vec<u8> = (u8::MIN..=u8::MAX).collect();
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open("/work/orphan-descendant.bin")?;
            output.write_all(&bytes)?;
            output.sync_all()?;
            let mut receipt = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open("/work/orphan-completion.json")?;
            serde_json::to_writer(
                &mut receipt,
                &serde_json::json!({"format":"memcordon.linux-orphan-completion","revision":1,
                "challenge":transcript.challenge,"pid":std::process::id(),"birth":birth(std::process::id())?,
                "original_parent_pid":original_parent,"original_parent_birth":original_parent_birth,
                "reparented_pid":unsafe{libc::getppid()} as u32}),
            )?;
            receipt.write_all(b"\n")?;
            receipt.sync_all()?;
            Ok(())
        }
        "orphan-intermediate" => {
            let (child, observation) = native_child("orphan-child", &transcript.challenge)?;
            announce_child(vec![observation])?;
            wait_release()?;
            drop(child);
            Ok(())
        }
        "root-first" => {
            let (child, observation) = native_child("orphan-child", &transcript.challenge)?;
            transcript.record("root-exiting-before-held-descendant", observation)?;
            wait_release()?;
            drop(child);
            Ok(())
        }
        "intermediate-first" => {
            let (mut child, observation) =
                native_child("orphan-intermediate", &transcript.challenge)?;
            transcript.record(
                "intermediate-and-descendant-held-before-exit",
                observation.clone(),
            )?;
            wait_release()?;
            release_and_wait(&mut child)?;
            transcript.record("intermediate-retired-descendant-held", observation)?;
            loop {
                std::thread::park();
            }
        }
        _ => Err("unknown Linux readiness fixture mode".into()),
    }
}

fn authority_denial(transcript: &mut Transcript, operation: &str) -> Result<()> {
    let positive = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let (mut sender, mut receiver) = std::os::unix::net::UnixStream::pair()?;
    sender.write_all(b"positive")?;
    let mut received = vec![0; b"positive".len()];
    receiver.read_exact(&mut received)?;
    if received != b"positive" {
        return Err("neighboring permitted UNIX operation failed".into());
    }
    transcript.record("neighboring-permitted-sockets", serde_json::json!({"tcp_endpoint":positive.local_addr()?.to_string(),"unix_bytes":received}))?;
    let result = match operation {
        "ipv6" => unsafe {
            libc::socket(
                libc::AF_INET6,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                libc::IPPROTO_TCP,
            ) as i64
        },
        "udp" => unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                libc::IPPROTO_UDP,
            ) as i64
        },
        "raw" => unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::IPPROTO_RAW,
            ) as i64
        },
        "packet" => unsafe {
            libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) as i64
        },
        "netlink" => unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            ) as i64
        },
        "pidfd-getfd" => unsafe { libc::syscall(libc::SYS_pidfd_getfd, -1, 0, 0) as i64 },
        "ptrace" => unsafe {
            libc::ptrace(
                libc::PTRACE_ATTACH,
                libc::getppid(),
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            ) as i64
        },
        "namespace-entry" => unsafe { libc::setns(-1, libc::CLONE_NEWNET) as i64 },
        _ => return Err("unknown authority denial probe".into()),
    };
    if result >= 0 {
        if ["ipv6", "udp", "raw", "packet", "netlink"].contains(&operation) {
            unsafe {
                libc::close(result as i32);
            }
        }
        return Err("forbidden native authority operation unexpectedly succeeded".into());
    }
    let code = io::Error::last_os_error()
        .raw_os_error()
        .ok_or("native denial errno absent")?;
    let expected = match operation {
        "ipv6" | "packet" | "netlink" => libc::EAFNOSUPPORT,
        "udp" | "raw" => libc::EPROTONOSUPPORT,
        "pidfd-getfd" | "ptrace" | "namespace-entry" => libc::EPERM,
        _ => return Err("unknown authority errno applicability".into()),
    };
    if code != expected {
        return Err("authority probe did not reach selected closed-filter native denial".into());
    }
    transcript.record(
        "native-authority-denied",
        serde_json::json!({"probe":operation,"native_errno":code,"result":result}),
    )
}

fn outside_file(
    transcript: &mut Transcript,
    kind: &str,
    path: &std::ffi::OsStr,
    descriptor: Option<i32>,
) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    if ![
        "symlink",
        "dotdot",
        "proc-root",
        "proc-cwd",
        "proc-fd",
        "hardlink",
        "opath",
        "mount-alias",
    ]
    .contains(&kind)
    {
        return Err("unknown native outside-path vector".into());
    }
    let baseline = std::path::Path::new("/work/private-path-positive.bin");
    let token = b"private-read-write-positive";
    std::fs::write(baseline, token)?;
    let observed = std::fs::read(baseline)?;
    if observed != token {
        return Err("neighboring private file native effects differ".into());
    }
    transcript.record(
        "neighboring-private-file",
        serde_json::json!({"path":baseline.as_os_str().as_bytes(),"bytes":observed}),
    )?;
    if kind == "opath" {
        let descriptor = descriptor
            .filter(|fd| *fd == 128)
            .ok_or("original leaked O_PATH descriptor differs")?;
        let result = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        let error = if result < 0 {
            io::Error::last_os_error().raw_os_error()
        } else {
            return Err("hostile O_PATH descriptor reached target authority".into());
        };
        if error != Some(libc::EBADF) {
            return Err("hostile O_PATH descriptor did not reach native closure check".into());
        }
        return transcript.record("native-outside-file-denied",serde_json::json!({"kind":kind,"path":path.as_bytes(),"native_descriptor":descriptor,"native_result":result,"native_errno":error}));
    }
    let native = std::ffi::CString::new(path.as_bytes())?;
    let flags = if kind == "opath" {
        libc::O_PATH | libc::O_CLOEXEC
    } else {
        libc::O_RDONLY | libc::O_CLOEXEC
    };
    let result = unsafe { libc::open(native.as_ptr(), flags) };
    let error = if result < 0 {
        io::Error::last_os_error().raw_os_error()
    } else {
        unsafe { libc::close(result) };
        return Err("outside private root native open unexpectedly succeeded".into());
    };
    let code = error.ok_or("outside native denial errno absent")?;
    if ![libc::ENOENT, libc::EACCES, libc::EPERM, libc::ELOOP].contains(&code) {
        return Err("outside pathname did not reach isolated native denial".into());
    }
    transcript.record("native-outside-file-denied",serde_json::json!({"kind":kind,"path":path.as_bytes(),"native_open_flags":flags,"native_result":result,"native_errno":code}))
}

fn memory_pressure() -> Result<()> {
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    loop {
        let mut chunk = vec![0u8; 1048576];
        chunk.fill(0xa5);
        std::hint::black_box(&chunk);
        chunks.push(chunk);
        std::hint::black_box(&chunks);
    }
}

fn native_child(
    command: &str,
    challenge: &str,
) -> Result<(std::process::Child, serde_json::Value)> {
    use std::io::BufRead;
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .arg(command)
        .arg(challenge)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()?;
    let observed = (|| -> Result<serde_json::Value> {
        let mut ready = Vec::new();
        let output = child.stdout.take().ok_or("child readiness stream absent")?;
        let mut bounded = std::io::BufReader::new(output).take(64 * 1024);
        bounded.read_until(b'\n', &mut ready)?;
        if !ready.ends_with(b"\n") {
            return Err("child readiness missing/truncated".into());
        }
        let observation: serde_json::Value = serde_json::from_slice(&ready)?;
        if observation.get("pid").and_then(serde_json::Value::as_u64) != Some(u64::from(child.id()))
            || observation.get("birth").and_then(serde_json::Value::as_u64)
                != Some(birth(child.id())?)
        {
            return Err("child readiness native identity differs".into());
        }
        Ok(observation)
    })();
    match observed {
        Ok(observation) => Ok((child, observation)),
        Err(original) => {
            // A failed readiness receipt does not surrender the creation owner.
            let mut failures = Vec::new();
            match child.try_wait() {
                Ok(None) => {
                    if let Err(error) = child.kill() {
                        failures.push(format!("signal: {error}"));
                    }
                }
                Ok(Some(_)) => {}
                Err(error) => failures.push(format!("observe: {error}")),
            };
            child.stdin.take();
            if let Err(error) = child.wait() {
                failures.push(format!("reap: {error}"));
            }
            if failures.is_empty() {
                Err(original)
            } else {
                Err(format!(
                    "{original}; exact readiness child cleanup unresolved: {}",
                    failures.join("; ")
                )
                .into())
            }
        }
    }
}

fn announce_child(members: Vec<serde_json::Value>) -> Result<()> {
    let row = serde_json::json!({"pid":std::process::id(),"birth":birth(std::process::id())?,
        "parent_pid":unsafe {libc::getppid()},"members":members});
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &row)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

fn wait_release() -> Result<()> {
    let mut byte = [0];
    io::stdin().read_exact(&mut byte)?;
    if byte != *b"R" {
        return Err("native child release marker differs".into());
    }
    Ok(())
}

fn export_object(transcript: &mut Transcript, scenario: &str) -> Result<()> {
    let output = if scenario == "traversal" {
        "/work/parent/exported.bin"
    } else {
        "/work/exported.bin"
    };
    let mut socket = None;
    let mut writer = None;
    let mut writer_identity = None;
    let kind = match scenario {
        "symlink" => {
            std::os::unix::fs::symlink("/owned-source/Cargo.toml", output)?;
            "symlink"
        }
        "fifo" => {
            let path = std::ffi::CString::new(output)?;
            if unsafe { libc::mkfifo(path.as_ptr(), 0o600) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
            "fifo"
        }
        "socket" => {
            socket = Some(std::os::unix::net::UnixListener::bind(output)?);
            "socket"
        }
        "traversal" => {
            std::fs::create_dir("/work/other")?;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open("/work/other/exported.bin")?;
            file.write_all(transcript.challenge.as_bytes())?;
            file.sync_all()?;
            std::os::unix::fs::symlink("/work/other", "/work/parent")?;
            "parent-symlink"
        }
        "device" => "admin-device-required",
        "concurrent-writer" => {
            let (child, identity) = native_child("export-writer-child", &transcript.challenge)?;
            // Retain the actual Child before a fallible controller receipt.
            writer = Some(child);
            writer_identity = Some(identity);
            "regular-with-held-writer"
        }
        _ => return Err("unsupported export-object scenario".into()),
    };
    let result = (|| -> Result<()> {
        if let Some(identity) = writer_identity {
            transcript.record("export-writer-held", identity)?;
        }
        transcript.record(
            "export-object-ready",
            serde_json::json!({"scenario":scenario,"path":output,"kind":kind,
            "source_path":if scenario=="traversal"{Some("/work/other/exported.bin")}else{None}}),
        )?;
        if let Some(child) = writer.as_mut() {
            let mut stop = [0];
            io::stdin().read_exact(&mut stop)?;
            if stop != *b"S" {
                return Err("export writer stop marker differs".into());
            }
            release_and_wait(child)?;
            use std::os::unix::process::ExitStatusExt;
            let status = child.wait()?;
            transcript.record("export-writer-retired",serde_json::json!({"pid":child.id(),
                "native_wait_completed":true,"raw_wait_status":status.into_raw(),"native_exit_code":status.code(),
                "native_signal":status.signal(),"before_root_release":true}))?;
        }
        wait_release()?;
        transcript.record(
            "export-object-controller-release",
            serde_json::json!({"scenario":scenario,"path":output}),
        )?;
        Ok(())
    })();
    if let Err(original) = result {
        if let Some(child) = writer.as_mut() {
            let cleanup = (|| -> Result<()> {
                if child.try_wait()?.is_none() {
                    child.kill()?;
                }
                child.wait()?;
                Ok(())
            })();
            if let Err(error) = cleanup {
                return Err(format!("{original}; exact writer cleanup unresolved: {error}").into());
            }
        }
        return Err(original);
    }
    drop(socket);
    transcript.record(
        "export-object-completed",
        serde_json::json!({"scenario":scenario,"path":output}),
    )
}

fn export_writer_child() -> Result<()> {
    use std::io::{Seek, SeekFrom};
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open("/work/exported.bin")?;
    output.write_all(b"writer-initial")?;
    output.sync_all()?;
    announce_child(Vec::new())?;
    let mut writes = 0u64;
    loop {
        let mut descriptor = libc::pollfd {
            fd: 0,
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, 5) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        if result > 0 {
            wait_release()?;
            break;
        }
        writes = writes.checked_add(1).ok_or("writer sequence overflow")?;
        output.seek(SeekFrom::Start(0))?;
        output.write_all(&writes.to_le_bytes())?;
        output.flush()?;
    }
    output.sync_all()?;
    Ok(())
}

fn release_and_wait(child: &mut std::process::Child) -> Result<()> {
    child
        .stdin
        .take()
        .ok_or("child release pipe absent")?
        .write_all(b"R")?;
    if !child.wait()?.success() {
        return Err("released descendant did not finish naturally".into());
    }
    Ok(())
}

fn preserve_child_failure(
    child: &mut std::process::Child,
    original: Box<dyn std::error::Error>,
) -> Box<dyn std::error::Error> {
    let mut failures = Vec::new();
    match child.try_wait() {
        Ok(Some(_)) => {}
        Ok(None) => {
            if let Err(error) = child.kill() {
                failures.push(format!("owned child signal: {error}"));
            }
        }
        Err(error) => {
            failures.push(format!("owned child observation: {error}"));
            if let Err(error) = child.kill() {
                failures.push(format!("owned child signal: {error}"));
            }
        }
    }
    child.stdin.take();
    if let Err(error) = child.wait() {
        failures.push(format!("owned child reap unresolved: {error}"));
    }
    if failures.is_empty() {
        original
    } else {
        format!("{original}; {}", failures.join("; ")).into()
    }
}

fn held_child() -> Result<()> {
    announce_child(Vec::new())?;
    wait_release()
}

fn held_tree() -> Result<()> {
    // Two retained leaders plus sixty-two leaves give exactly sixty-four
    // descendants at depths one, two and three in a cohort.
    let challenge = std::env::args().nth(2).ok_or("tree challenge absent")?;
    let (mut leader, observation) = native_child("tree-leaves", &challenge)?;
    announce_child(vec![observation])?;
    wait_release()?;
    release_and_wait(&mut leader)
}

fn tree_leaves() -> Result<()> {
    let challenge = std::env::args().nth(2).ok_or("leaf challenge absent")?;
    let mut children = Vec::new();
    let mut observations = Vec::new();
    for _ in 0..62 {
        let (child, observation) = native_child("held-child", &challenge)?;
        children.push(child);
        observations.push(observation);
    }
    announce_child(observations)?;
    wait_release()?;
    for child in &mut children {
        release_and_wait(child)?;
    }
    Ok(())
}

fn natural_churn(transcript: &mut Transcript) -> Result<()> {
    for generation in 0..64 {
        let (mut child, observation) = native_child("held-tree", &transcript.challenge)?;
        transcript.record("churn-cohort-held", serde_json::json!({"generation":generation,"cohort_population":64,"maximum_depth":3,"native_tree":observation}))?;
        wait_release()?;
        release_and_wait(&mut child)?;
        transcript.record("churn-cohort-naturally-retired", serde_json::json!({"generation":generation,"cumulative_children":(generation + 1) * 64}))?;
    }
    Ok(())
}

fn population(transcript: &mut Transcript) -> Result<()> {
    let mut children = Vec::new();
    let mut observations = Vec::new();
    for _ in 0..256 {
        let (child, observation) = native_child("held-child", &transcript.challenge)?;
        children.push(child);
        observations.push(observation);
    }
    transcript.record(
        "population-held-until-native-deadline",
        serde_json::json!({"population":children.len() + 1,"children":observations}),
    )?;
    // The provider owns deadline termination. No fixture-side kill or release
    // may manufacture its native empty/retirement observation.
    loop {
        let mut byte = [0];
        if io::stdin().read(&mut byte)? == 0 {
            std::thread::park();
        }
    }
}

struct HeldUnixRights {
    descriptors: Vec<std::os::fd::OwnedFd>,
    socket_path: std::path::PathBuf,
    file_path: std::path::PathBuf,
}
impl HeldUnixRights {
    fn retire(self) -> Result<()> {
        drop(self.descriptors);
        std::fs::remove_file(self.socket_path)?;
        std::fs::remove_file(self.file_path)?;
        Ok(())
    }
}
fn unix_rights(transcript: &mut Transcript, directory: &std::path::Path) -> Result<HeldUnixRights> {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    let socket_path = directory.join("readiness.sock");
    let listener = UnixListener::bind(&socket_path)?;
    let mut client = UnixStream::connect(&socket_path)?;
    let (mut server, _) = listener.accept()?;
    let payload = b"path-unix-readiness";
    client.write_all(payload)?;
    let mut received = vec![0; payload.len()];
    server.read_exact(&mut received)?;
    if received != payload {
        return Err("pathname UNIX bytes differ".into());
    }
    transcript.record(
        "unix-path-round-trip",
        serde_json::json!({"path":socket_path,"bytes":received}),
    )?;
    use std::os::linux::net::SocketAddrExt;
    let abstract_name = transcript.challenge.as_bytes().to_vec();
    let abstract_address = std::os::unix::net::SocketAddr::from_abstract_name(&abstract_name)?;
    let abstract_listener = UnixListener::bind_addr(&abstract_address)?;
    let mut abstract_client = UnixStream::connect_addr(&abstract_address)?;
    let (mut abstract_server, _) = abstract_listener.accept()?;
    let abstract_payload = b"abstract-unix-readiness";
    abstract_client.write_all(abstract_payload)?;
    let mut abstract_bytes = vec![0; abstract_payload.len()];
    abstract_server.read_exact(&mut abstract_bytes)?;
    if abstract_bytes != abstract_payload {
        return Err("abstract UNIX bytes differ".into());
    }
    transcript.record(
        "unix-abstract-round-trip",
        serde_json::json!({"name":abstract_name,"bytes":abstract_bytes}),
    )?;
    let (sender, receiver) = UnixStream::pair()?;
    let file_path = directory.join("rights-input.bin");
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&file_path)?;
    file.write_all(b"descriptor-readiness")?;
    file.sync_all()?;
    let tcp = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let endpoint = tcp.local_addr()?;
    let descriptors = [file.as_raw_fd(), tcp.as_raw_fd()];
    let mut marker = *b"R";
    let mut vector = libc::iovec {
        iov_base: marker.as_mut_ptr().cast(),
        iov_len: marker.len(),
    };
    // usize storage gives cmsghdr its native alignment; CMSG_SPACE defines the extent.
    let control_size =
        unsafe { libc::CMSG_SPACE(std::mem::size_of_val(&descriptors) as _) } as usize;
    let mut control = vec![0usize; control_size.div_ceil(std::mem::size_of::<usize>())];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control_size;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null() {
            return Err("SCM_RIGHTS control header absent".into());
        }
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(&descriptors) as _) as usize;
        std::ptr::copy_nonoverlapping(
            descriptors.as_ptr(),
            libc::CMSG_DATA(header).cast(),
            descriptors.len(),
        );
        if libc::sendmsg(sender.as_raw_fd(), &message, libc::MSG_NOSIGNAL) != 1 {
            return Err(io::Error::last_os_error().into());
        }
    }
    control.fill(0);
    message.msg_controllen = control_size;
    let count =
        unsafe { libc::recvmsg(receiver.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    if count != 1
        || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
        || marker != *b"R"
    {
        return Err("SCM_RIGHTS transfer truncated or malformed".into());
    }
    transcript.record(
        "unix-stream-pair-round-trip",
        serde_json::json!({"bytes":marker.to_vec()}),
    )?;
    let received_fds = unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null()
            || (*header).cmsg_level != libc::SOL_SOCKET
            || (*header).cmsg_type != libc::SCM_RIGHTS
            || (*header).cmsg_len
                != libc::CMSG_LEN(std::mem::size_of_val(&descriptors) as _) as usize
        {
            return Err("SCM_RIGHTS received descriptor shape differs".into());
        }
        std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<[i32; 2]>())
    };
    use std::os::fd::FromRawFd;
    let mut received_file = unsafe { std::fs::File::from_raw_fd(received_fds[0]) };
    let received_listener = unsafe { TcpListener::from_raw_fd(received_fds[1]) };
    use std::os::unix::fs::MetadataExt;
    let original_file = file.metadata()?;
    let imported_file = received_file.metadata()?;
    let mut original_listener: libc::stat = unsafe { std::mem::zeroed() };
    let mut imported_listener: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(tcp.as_raw_fd(), &mut original_listener) } != 0
        || unsafe { libc::fstat(received_listener.as_raw_fd(), &mut imported_listener) } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    if (original_file.dev(), original_file.ino()) != (imported_file.dev(), imported_file.ino())
        || (original_listener.st_dev, original_listener.st_ino)
            != (imported_listener.st_dev, imported_listener.st_ino)
    {
        return Err("SCM_RIGHTS native descriptor identity changed".into());
    }
    use std::io::{Seek, SeekFrom};
    received_file.seek(SeekFrom::Start(0))?;
    let mut file_bytes = Vec::new();
    std::io::Read::by_ref(&mut received_file)
        .take(1024)
        .read_to_end(&mut file_bytes)?;
    if file_bytes != b"descriptor-readiness" || received_listener.local_addr()? != endpoint {
        return Err("transferred regular file/listener identity differs".into());
    }
    let mut network_client = TcpStream::connect_timeout(&endpoint, Duration::from_secs(5))?;
    let (mut network_server, _) = received_listener.accept()?;
    let network_payload = b"rights-listener";
    network_client.write_all(network_payload)?;
    network_server.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut network_bytes = vec![0; network_payload.len()];
    network_server.read_exact(&mut network_bytes)?;
    if network_bytes != network_payload {
        return Err("transferred listener bytes differ".into());
    }
    transcript.record("scm-rights-regular-and-listener", serde_json::json!({"file_bytes":file_bytes,"endpoint":endpoint.to_string(),"network_bytes":network_bytes,
        "file_device":original_file.dev(),"file_inode":original_file.ino(),"received_file_device":imported_file.dev(),"received_file_inode":imported_file.ino(),
        "listener_device":original_listener.st_dev,"listener_inode":original_listener.st_ino,"received_listener_device":imported_listener.st_dev,"received_listener_inode":imported_listener.st_ino}))?;
    Ok(HeldUnixRights {
        descriptors: vec![
            listener.into(),
            client.into(),
            server.into(),
            abstract_listener.into(),
            abstract_client.into(),
            abstract_server.into(),
            sender.into(),
            receiver.into(),
            file.into(),
            received_file.into(),
            tcp.into(),
            received_listener.into(),
            network_client.into(),
            network_server.into(),
        ],
        socket_path,
        file_path,
    })
}

fn tcp_http(
    transcript: &mut Transcript,
    joint: Option<(
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
    )>,
    memory: bool,
) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let endpoint = listener.local_addr()?;
    let competitor = TcpListener::bind(endpoint)
        .err()
        .ok_or("competing bind unexpectedly succeeded")?;
    if competitor.raw_os_error() != Some(libc::EADDRINUSE) {
        return Err(competitor.into());
    }
    transcript.record(
        "bind-zero-and-competing-bind",
        serde_json::json!({"endpoint":endpoint.to_string(),
        "native_errno":libc::EADDRINUSE,"listener_retained":true}),
    )?;
    let mut competitor = std::process::Command::new(std::env::current_exe()?)
        .arg("competing-bind")
        .arg(&transcript.challenge)
        .arg(endpoint.to_string())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()?;
    use std::io::BufRead;
    let competing_result = (|| -> Result<()> {
        let competitor_birth = birth(competitor.id())?;
        let competitor_id = competitor.id();
        let mut competitor_output = Vec::new();
        std::io::BufReader::new(competitor.stdout.take().ok_or("competitor stdout absent")?)
            .take(64 * 1024)
            .read_until(b'\n', &mut competitor_output)?;
        if !competitor_output.ends_with(b"\n") {
            return Err("descendant competitor readiness absent".into());
        }
        transcript.record("descendant-competing-bind-held", serde_json::json!({"pid":competitor_id,"birth":competitor_birth,"members":[],"transcript":competitor_output}))?;
        wait_release()?;
        release_and_wait(&mut competitor)?;
        transcript.record("descendant-competing-bind-retired", serde_json::json!({"pid":competitor_id,"birth":competitor_birth,"transcript":competitor_output}))?;
        Ok(())
    })();
    if let Err(error) = competing_result {
        return Err(preserve_child_failure(&mut competitor, error));
    }
    let request = b"GET /readiness HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nreadiness";
    let mut client = TcpStream::connect_timeout(&endpoint, Duration::from_secs(5))?;
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    client.set_write_timeout(Some(Duration::from_secs(5)))?;
    let (mut server, peer) = listener.accept()?;
    server.set_read_timeout(Some(Duration::from_secs(5)))?;
    server.set_write_timeout(Some(Duration::from_secs(5)))?;
    client.write_all(request)?;
    let mut received = vec![0; request.len()];
    server.read_exact(&mut received)?;
    if received != request {
        return Err("HTTP request bytes differ".into());
    }
    server.write_all(response)?;
    let mut received_response = vec![0; response.len()];
    client.read_exact(&mut received_response)?;
    if received_response != response {
        return Err("HTTP response bytes differ".into());
    }
    transcript.record(
        "http-round-trip",
        serde_json::json!({"endpoint":endpoint.to_string(),"peer":peer.to_string(),
        "request":received,"response":received_response}),
    )?;
    let mut empty_client = TcpStream::connect_timeout(&endpoint, Duration::from_secs(5))?;
    let (mut empty_server, _) = listener.accept()?;
    empty_client.set_read_timeout(Some(Duration::from_secs(5)))?;
    empty_server.set_read_timeout(Some(Duration::from_secs(5)))?;
    let empty_request = b"POST /empty HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n";
    let empty_response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    empty_client.write_all(empty_request)?;
    let mut empty_received = vec![0; empty_request.len()];
    empty_server.read_exact(&mut empty_received)?;
    empty_server.write_all(empty_response)?;
    let mut empty_response_received = vec![0; empty_response.len()];
    empty_client.read_exact(&mut empty_response_received)?;
    if empty_received != empty_request || empty_response_received != empty_response {
        return Err("empty HTTP message bytes differ".into());
    }
    transcript.record("http-empty-body-round-trip", serde_json::json!({"request":empty_received,"response":empty_response_received,"body":Vec::<u8>::new()}))?;
    if let Some((directory, cargo, rustc, linker, manifest)) = joint {
        let unix_owners = unix_rights(transcript, &directory)?;
        let (mut descendant_tree, tree_observation) =
            match native_child("held-tree", &transcript.challenge) {
                Ok(child) => child,
                Err(original) => {
                    return match unix_owners.retire() {
                        Ok(()) => Err(original),
                        Err(cleanup) => Err(format!(
                            "{original}; owned Unix resource retirement failed: {cleanup}"
                        )
                        .into()),
                    };
                }
            };
        let joint_result = (|| -> Result<()> {
            transcript.record("joint-descendant-tree-held", tree_observation)?;
            wait_release()?;
            let output = directory.join("offline-target");
            if !cargo.is_absolute()
                || !rustc.is_absolute()
                || !linker.is_absolute()
                || !manifest.is_absolute()
                || !directory.is_absolute()
            {
                return Err("owned compiler/input/output paths must be absolute".into());
            }
            let config_path = directory.join("owned-cargo-config.toml");
            let mut config = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&config_path)?;
            config.write_all(b"[target.'cfg(target_os = \"linux\")']\nlinker = ")?;
            serde_json::to_writer(
                &mut config,
                linker.to_str().ok_or("owned linker path not UTF-8")?,
            )?;
            config.write_all(b"\n")?;
            config.sync_all()?;
            let mut challenge_file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(directory.join("generated-child-challenge.txt"))?;
            challenge_file.write_all(transcript.challenge.as_bytes())?;
            challenge_file.sync_all()?;
            let mut compiler = std::process::Command::new(std::env::current_exe()?)
                .arg("exec-held")
                .arg(&transcript.challenge)
                .arg(cargo)
                .arg("test")
                .arg("--offline")
                .arg("--locked")
                .arg("--config")
                .arg(&config_path)
                .arg("--manifest-path")
                .arg(manifest)
                .arg("--target-dir")
                .arg(&output)
                .arg("--")
                .arg("--nocapture")
                .arg("--test-threads=1")
                .env_clear()
                .env("CARGO_HOME", directory.join("cargo-home"))
                .env("RUSTC", rustc)
                .env("TMPDIR", &directory)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::inherit())
                .spawn()?;
            let compiler_result = (|| -> Result<()> {
                use std::io::BufRead;
                let mut compiler_stream = std::io::BufReader::new(
                    compiler.stdout.take().ok_or("compiler stdout absent")?,
                );
                let mut ready = Vec::new();
                compiler_stream
                    .by_ref()
                    .take(65536)
                    .read_until(b'\n', &mut ready)?;
                if !ready.ends_with(b"\n") {
                    return Err("held compiler readiness absent".into());
                }
                let compiler_identity: serde_json::Value = serde_json::from_slice(&ready)?;
                if compiler_identity["pid"].as_u64() != Some(u64::from(compiler.id()))
                    || compiler_identity["birth"].as_u64() != Some(birth(compiler.id())?)
                {
                    return Err("held compiler native identity differs".into());
                }
                transcript.record("offline-compiler-held", compiler_identity.clone())?;
                wait_release()?;
                compiler
                    .stdin
                    .as_mut()
                    .ok_or("native compiler gate absent")?
                    .write_all(b"R")?;
                compiler.stdin.take();
                let mut compiler_output = Vec::new();
                let mut generated_held = false;
                loop {
                    let mut line = Vec::new();
                    let remaining = (4 * 1024 * 1024usize)
                        .checked_sub(compiler_output.len())
                        .ok_or("compiler output exceeded bound")?;
                    compiler_stream
                        .by_ref()
                        .take(remaining as u64 + 1)
                        .read_until(b'\n', &mut line)?;
                    if line.is_empty() {
                        break;
                    }
                    compiler_output.extend_from_slice(&line);
                    if compiler_output.len() > 4 * 1024 * 1024 {
                        return Err("offline compiler output exceeded bound".into());
                    }
                    let marker = b"MEMCORDON-GENERATED-CHILD-HELD ";
                    if let Some(offset) = line
                        .windows(marker.len())
                        .position(|window| window == marker)
                    {
                        if generated_held || !line.ends_with(b"\n") {
                            return Err("generated child native gate duplicated/truncated".into());
                        }
                        let created: serde_json::Value =
                            serde_json::from_slice(&line[offset + marker.len()..])?;
                        if created["challenge"] != transcript.challenge
                            || created["compiler_pid"] != compiler_identity["pid"]
                            || created["compiler_birth"] != compiler_identity["birth"]
                        {
                            return Err(
                                "generated child compiler/challenge association differs".into()
                            );
                        }
                        let tree = serde_json::json!({"pid":created["compiler_pid"],"birth":created["compiler_birth"],"members":[{
                    "pid":created["parent_pid"],"birth":created["parent_birth"],"members":[{"pid":created["pid"],"birth":created["birth"],"members":[]}]}]});
                        transcript.record(
                            "joint-generated-child-held",
                            serde_json::json!({"native_tree":tree,"created":created}),
                        )?;
                        wait_release()?;
                        if memory {
                            let (mut allocator, observation) =
                                native_child("memory-pressure-child", &transcript.challenge)?;
                            let result = (|| -> Result<()> {
                                transcript.record("memory-pressure-descendant-held", serde_json::json!({"native_tree":observation,"chunk_bytes":1048576}))?;
                                wait_release()?;
                                allocator
                                    .stdin
                                    .as_mut()
                                    .ok_or("joint allocator input owner absent")?
                                    .write_all(b"R")?;
                                loop {
                                    std::thread::park_timeout(Duration::from_secs(1));
                                }
                            })();
                            return Err(preserve_child_failure(
                                &mut allocator,
                                result
                                    .err()
                                    .ok_or("joint allocator unexpectedly returned")?,
                            ));
                        }
                        let mut gate = std::fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                            .open(directory.join("generated-child-controller-release"))?;
                        gate.write_all(b"R")?;
                        gate.sync_all()?;
                        std::fs::File::open(&directory)?.sync_all()?;
                        generated_held = true;
                    }
                }
                if !generated_held {
                    return Err("actual generated child native controller gate missing".into());
                }
                let status = compiler.wait()?;
                if !status.success() {
                    return Err("owned offline Rust compiler/test driver failed".into());
                }
                let generated_path = directory.join("generated-readiness-artifact.bin");
                let generated = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&generated_path)?;
                let generated_metadata = generated.metadata()?;
                let mut generated_bytes = Vec::new();
                generated.take(257).read_to_end(&mut generated_bytes)?;
                if !generated_metadata.is_file()
                    || generated_metadata.nlink() != 1
                    || generated_bytes != (u8::MIN..=u8::MAX).collect::<Vec<_>>()
                {
                    return Err("actual generated executable binary product differs".into());
                }
                transcript.record("generated-executable-binary-product", serde_json::json!({
            "path":generated_path,"device":generated_metadata.dev(),"inode":generated_metadata.ino(),
            "bytes":generated_bytes}))?;
                transcript.record("offline-rust-compile-and-test", serde_json::json!({"native_status":status.code(),"output":output,"test_stdout":compiler_output,"tcp_listener_still_bound":listener.local_addr()? == endpoint}))?;
                Ok(())
            })();
            if let Err(error) = compiler_result {
                return Err(preserve_child_failure(&mut compiler, error));
            }
            transcript.record(
                "joint-unix-rights-held-through-build",
                serde_json::json!({"owned_native_descriptors":unix_owners.descriptors.len(),
            "path":unix_owners.socket_path,"transferred_file":unix_owners.file_path}),
            )?;
            release_and_wait(&mut descendant_tree)?;
            transcript.record(
                "joint-descendant-tree-naturally-retired",
                serde_json::json!({"tcp_listener_still_bound":listener.local_addr()? == endpoint}),
            )?;
            Ok(())
        })();
        if let Err(error) = joint_result {
            let original = preserve_child_failure(&mut descendant_tree, error);
            return match unix_owners.retire() {
                Ok(()) => Err(original),
                Err(cleanup) => {
                    Err(format!("{original}; owned Unix retirement unresolved: {cleanup}").into())
                }
            };
        }
        unix_owners.retire()?;
    }
    drop(server);
    drop(client);
    drop(listener);
    transcript.record("tcp-endpoints-closed", serde_json::json!({}))
}
