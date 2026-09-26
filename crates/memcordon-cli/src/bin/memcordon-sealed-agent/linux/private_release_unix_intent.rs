//! Closed target subwitness for the pathname and abstract AF_UNIX intents.
//! The reviewed filter rejects socket creation before either address can be
//! passed to bind. This module cannot publish a release case by itself.

use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::time::Instant;

use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use serde::{Deserialize, Serialize};

use super::private_attempt::ProcessIdentityV4;

pub(crate) const SELECTOR: &str = "private_tcp::af_unix_abstract_and_pathname_denied";
const DOMAIN: &[u8] = b"memcordon-private-unix-intent-v1\0";
const PROC_UNIX_LIMIT: u64 = 1024 * 1024;
const ACK_DOMAIN: &[u8] = b"memcordon-private-unix-observer-ack-v1\0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnixAbsenceSnapshotV1 {
    pub(crate) network_namespace_inode: u64,
    pub(crate) mount_namespace_inode: u64,
    pub(crate) target_root_inode: u64,
    pub(crate) proc_unix_sha256: DiagnosticSha256,
    pub(crate) pathname_absent: bool,
    pub(crate) abstract_absent: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnixIntentSupervisorAbsenceV1 {
    pub(crate) target: ProcessIdentityV4,
    pub(crate) challenge_sha256: DiagnosticSha256,
    pub(crate) before_release: UnixAbsenceSnapshotV1,
    pub(crate) after_denials_before_ack: UnixAbsenceSnapshotV1,
    pub(crate) ack_sha256: DiagnosticSha256,
}

impl UnixIntentSupervisorAbsenceV1 {
    pub(crate) fn verify_binding(
        &self,
        challenge: &[u8; 32],
        target: &ProcessIdentityV4,
        expected_network_namespace_inode: u64,
    ) -> Result<(), String> {
        let snapshots = [&self.before_release, &self.after_denials_before_ack];
        if self.target != *target
            || self.challenge_sha256 != hash_bytes(challenge)
            || self.ack_sha256 != observer_ack_digest(challenge)
            || snapshots.iter().any(|snapshot| {
                snapshot.network_namespace_inode != expected_network_namespace_inode
                    || snapshot.mount_namespace_inode == 0
                    || snapshot.target_root_inode == 0
                    || snapshot.proc_unix_sha256 == DiagnosticSha256::from_bytes([0; 32])
                    || !snapshot.pathname_absent
                    || !snapshot.abstract_absent
            })
            || self.before_release.mount_namespace_inode
                != self.after_denials_before_ack.mount_namespace_inode
            || self.before_release.target_root_inode
                != self.after_denials_before_ack.target_root_inode
        {
            return Err("MCSEALED-PRIVATE-RELEASE: Unix supervisor absence binding differs".into());
        }
        Ok(())
    }
}

pub(crate) fn observer_ack_digest(challenge: &[u8; 32]) -> DiagnosticSha256 {
    let mut bytes = ACK_DOMAIN.to_vec();
    bytes.extend_from_slice(challenge);
    hash_bytes(&bytes)
}

/// Reads exactly the fixed target record while the target remains alive and
/// blocked for the observer ACK. The owning worker later checks EOF/extra
/// bytes after target retirement.
pub(crate) fn read_held_target_response(
    pipe: &mut std::fs::File,
    challenge: &[u8; 32],
    deadline: Instant,
    mut pump_relay: impl FnMut() -> Result<(), String>,
) -> Result<Vec<u8>, String> {
    use std::os::fd::AsRawFd;
    let expected = expected_observation_bytes(challenge)?;
    let mut response = vec![0_u8; expected.len()];
    let mut read = 0;
    while read < response.len() {
        pump_relay()?;
        match pipe.read(&mut response[read..]) {
            Ok(0) => return Err("MCSEALED-PRIVATE-RELEASE: Unix target closed before ACK".into()),
            Ok(count) => read += count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err("MCSEALED-PRIVATE-RELEASE: Unix target response timed out".into());
                }
                let mut pollfd = libc::pollfd {
                    fd: pipe.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let millis = remaining.as_millis().clamp(1, 10) as i32;
                // SAFETY: poll observes only the retained fixed stdout pipe.
                let status = unsafe { libc::poll(&raw mut pollfd, 1, millis) };
                if status == 0 {
                    continue;
                }
                if status < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
                {
                    continue;
                }
                if status < 0 || pollfd.revents & (libc::POLLIN | libc::POLLHUP) == 0 {
                    return Err("MCSEALED-PRIVATE-RELEASE: Unix target response poll failed".into());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.to_string()),
        }
    }
    if response != expected {
        return Err("MCSEALED-PRIVATE-RELEASE: Unix target response differs".into());
    }
    Ok(response)
}

/// The worker reads through the pinned target's proc view while its pidfd is
/// retained. The caller checks that exact pidfd/start identity around this
/// read; the target remains gated or is waiting for the observer ACK.
pub(crate) fn observe_target_absence(
    target: &ProcessIdentityV4,
    challenge: &[u8; 32],
    expected_network_namespace_inode: u64,
) -> Result<UnixAbsenceSnapshotV1, String> {
    use std::os::unix::fs::MetadataExt;
    let proc_root = Path::new("/proc").join(target.pid.to_string());
    let net = std::fs::metadata(proc_root.join("ns/net")).map_err(|error| error.to_string())?;
    let mount = std::fs::metadata(proc_root.join("ns/mnt")).map_err(|error| error.to_string())?;
    let root = std::fs::metadata(proc_root.join("root")).map_err(|error| error.to_string())?;
    if net.ino() != expected_network_namespace_inode || mount.ino() == 0 || root.ino() == 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: Unix observer namespace differs".into());
    }
    let mut inventory = Vec::new();
    std::fs::File::open(proc_root.join("net/unix"))
        .map_err(|error| error.to_string())?
        .take(PROC_UNIX_LIMIT + 1)
        .read_to_end(&mut inventory)
        .map_err(|error| error.to_string())?;
    if inventory.len() as u64 > PROC_UNIX_LIMIT {
        return Err("MCSEALED-PRIVATE-RELEASE: Unix observer inventory exceeds bound".into());
    }
    let pathname = endpoint_name(challenge, IntentKind::Pathname);
    let abstract_name = endpoint_name(challenge, IntentKind::Abstract);
    let pathname_absent =
        match std::fs::symlink_metadata(proc_root.join("root/tmp").join(&pathname)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Ok(_) => false,
            Err(error) => return Err(error.to_string()),
        };
    let pathname_in_proc = proc_unix_endpoint_absent(&inventory, &format!("/tmp/{pathname}"))?;
    let abstract_absent = proc_unix_endpoint_absent(&inventory, &format!("@{abstract_name}"))?;
    if !pathname_absent || !pathname_in_proc || !abstract_absent {
        return Err("MCSEALED-PRIVATE-RELEASE: Unix observer found endpoint".into());
    }
    Ok(UnixAbsenceSnapshotV1 {
        network_namespace_inode: net.ino(),
        mount_namespace_inode: mount.ino(),
        target_root_inode: root.ino(),
        proc_unix_sha256: hash_bytes(&inventory),
        pathname_absent: true,
        abstract_absent: true,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IntentKind {
    Pathname = 1,
    Abstract = 2,
}

fn endpoint_name(challenge: &[u8; 32], kind: IntentKind) -> String {
    let mut name = String::from("memcordon-private-unix-");
    for byte in challenge {
        write!(&mut name, "{byte:02x}").expect("writing to String cannot fail");
    }
    name.push_str(match kind {
        IntentKind::Pathname => "-path",
        IntentKind::Abstract => "-abstract",
    });
    name
}

fn address_bytes(name: &str, kind: IntentKind) -> Result<Vec<u8>, String> {
    let mut address = Vec::with_capacity(name.len() + 1);
    if kind == IntentKind::Abstract {
        address.push(0);
    } else {
        // The protected case directory is deliberately root-only. The
        // unprivileged target checks a fixed traversable location instead.
        address.extend_from_slice(b"/tmp/");
    }
    address.extend_from_slice(name.as_bytes());
    if kind == IntentKind::Pathname {
        address.push(0);
    }
    if address.len()
        > std::mem::size_of::<libc::sockaddr_un>() - std::mem::size_of::<libc::sa_family_t>()
    {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: AF_UNIX intent exceeds sun_path".into());
    }
    Ok(address)
}

fn endpoint_absent(name: &str, kind: IntentKind) -> Result<(), String> {
    if kind == IntentKind::Pathname {
        match std::fs::symlink_metadata(Path::new("/tmp").join(name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: pathname endpoint exists".into());
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    let mut observed = Vec::new();
    std::fs::File::open("/proc/net/unix")
        .map_err(|error| error.to_string())?
        .take(PROC_UNIX_LIMIT + 1)
        .read_to_end(&mut observed)
        .map_err(|error| error.to_string())?;
    if observed.len() as u64 > PROC_UNIX_LIMIT {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: AF_UNIX inventory exceeds bound".into());
    }
    let pathname = match kind {
        IntentKind::Pathname => format!("/tmp/{name}"),
        IntentKind::Abstract => format!("@{name}"),
    };
    if !proc_unix_endpoint_absent(&observed, &pathname)? {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: AF_UNIX endpoint present".into());
    }
    Ok(())
}

/// Parses complete proc rows and compares the exact endpoint field. A name
/// embedded in an unrelated endpoint is not evidence that this endpoint
/// exists. Malformed or truncated inventory fails closed.
pub(crate) fn proc_unix_endpoint_absent(bytes: &[u8], endpoint: &str) -> Result<bool, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE-FIXTURE: AF_UNIX inventory is not UTF-8")?;
    if !text.ends_with('\n') {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: AF_UNIX inventory is truncated".into());
    }
    let mut lines = text.lines();
    let header = lines
        .next()
        .ok_or("MCSEALED-PRIVATE-RELEASE-FIXTURE: AF_UNIX inventory header absent")?;
    if header.split_ascii_whitespace().collect::<Vec<_>>()
        != [
            "Num", "RefCount", "Protocol", "Flags", "Type", "St", "Inode", "Path",
        ]
    {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: AF_UNIX inventory header differs".into());
    }
    for line in lines {
        let mut rest = line.trim_ascii_start();
        let mut fields = Vec::with_capacity(7);
        for field_index in 0..7 {
            if rest.is_empty() {
                return Err(
                    "MCSEALED-PRIVATE-RELEASE-FIXTURE: AF_UNIX inventory row differs".into(),
                );
            }
            let field_end = rest
                .find(|character: char| character.is_ascii_whitespace())
                .unwrap_or(rest.len());
            fields.push(&rest[..field_end]);
            let remaining = &rest[field_end..];
            // The seventh separator belongs to the inode column. Consume
            // exactly one byte so leading spaces in a pathname remain part
            // of the endpoint rather than disappearing during normalization.
            rest = if field_index == 6 {
                remaining.strip_prefix(' ').unwrap_or(remaining)
            } else {
                remaining.trim_ascii_start()
            };
        }
        if fields[0]
            .strip_suffix(':')
            .is_none_or(|number| !number.bytes().all(|byte| byte.is_ascii_hexdigit()))
            || fields[1..6]
                .iter()
                .any(|field| !field.bytes().all(|byte| byte.is_ascii_hexdigit()))
            || !fields[6].bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: AF_UNIX inventory row differs".into());
        }
        if rest == endpoint {
            return Ok(false);
        }
    }
    Ok(true)
}

fn begin_observation(challenge: &[u8; 32]) -> Result<Vec<u8>, String> {
    if *challenge == [0; 32] {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: zero challenge".into());
    }
    let mut output = Vec::new();
    output.extend_from_slice(DOMAIN);
    output.extend_from_slice(challenge);
    Ok(output)
}

fn append_denial(
    output: &mut Vec<u8>,
    challenge: &[u8; 32],
    kind: IntentKind,
    observed_errno: i32,
) -> Result<(), String> {
    let address = address_bytes(&endpoint_name(challenge, kind), kind)?;
    let length = u16::try_from(address.len())
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE-FIXTURE: intent length overflow")?;
    output.push(kind as u8);
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(&address);
    output.extend_from_slice(&observed_errno.to_le_bytes());
    output.push(0); // bind_attempted = false
    output.push(0); // endpoint_created = false
    Ok(())
}

/// Fixed, challenge-bound result shape. Both entries explicitly say that bind
/// was never attempted and no endpoint was created by the denied socket call.
pub(crate) fn expected_observation_bytes(challenge: &[u8; 32]) -> Result<Vec<u8>, String> {
    let mut output = begin_observation(challenge)?;
    for kind in [IntentKind::Pathname, IntentKind::Abstract] {
        append_denial(&mut output, challenge, kind, libc::EAFNOSUPPORT)?;
    }
    Ok(output)
}

/// Runs only inside the filtered target. A successful socket, another errno,
/// or an endpoint observed before or after either attempt fails the witness.
pub(crate) fn observe_target_denials(challenge: &[u8; 32]) -> Result<Vec<u8>, String> {
    let mut observed = begin_observation(challenge)?;
    for kind in [IntentKind::Pathname, IntentKind::Abstract] {
        let name = endpoint_name(challenge, kind);
        endpoint_absent(&name, kind)?;
        // SAFETY: socket has scalar arguments. Unexpected success returns one
        // owned descriptor, closed before reporting a failed witness.
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        let errno = std::io::Error::last_os_error().raw_os_error();
        if fd >= 0 {
            // SAFETY: successful socket returned one unique descriptor.
            unsafe { libc::close(fd) };
            return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: AF_UNIX socket succeeded".into());
        }
        if errno != Some(libc::EAFNOSUPPORT) {
            return Err(format!(
                "MCSEALED-PRIVATE-RELEASE-FIXTURE: AF_UNIX socket errno {errno:?} differs"
            ));
        }
        endpoint_absent(&name, kind)?;
        append_denial(
            &mut observed,
            challenge,
            kind,
            errno.expect("exact EAFNOSUPPORT was checked"),
        )?;
    }
    Ok(observed)
}

/// Separate pinned target verb. It cannot be invoked through the ordinary
/// candidate fixture selector gate, and emits only the closed raw subwitness.
pub(crate) fn run_target_fixture() -> Result<(), String> {
    let (mut real_uid, mut effective_uid, mut saved_uid) = (0, 0, 0);
    let (mut real_gid, mut effective_gid, mut saved_gid) = (0, 0, 0);
    // SAFETY: each call writes only three live scalar output slots.
    if unsafe { libc::getresuid(&raw mut real_uid, &raw mut effective_uid, &raw mut saved_uid) }
        != 0
        || unsafe { libc::getresgid(&raw mut real_gid, &raw mut effective_gid, &raw mut saved_gid) }
            != 0
        || real_uid == 0
        || real_gid == 0
        || real_uid != effective_uid
        || real_uid != saved_uid
        || real_gid != effective_gid
        || real_gid != saved_gid
        // SAFETY: a null getgroups buffer with size zero queries only count.
        || unsafe { libc::getgroups(0, std::ptr::null_mut()) } != 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: Unix intent credentials differ".into());
    }
    let mut challenge = [0_u8; 32];
    std::io::stdin()
        .read_exact(&mut challenge)
        .map_err(|error| {
            format!("MCSEALED-PRIVATE-RELEASE-FIXTURE: Unix intent challenge: {error}")
        })?;
    super::private_release_case::hold_post_exec_baseline(&challenge)?;
    let observed = observe_target_denials(&challenge)?;
    std::io::stdout().write_all(&observed).map_err(|error| {
        format!("MCSEALED-PRIVATE-RELEASE-FIXTURE: Unix intent output: {error}")
    })?;
    std::io::stdout()
        .flush()
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-FIXTURE: Unix intent flush: {error}"))?;
    let mut ack = [0_u8; 32];
    std::io::stdin()
        .read_exact(&mut ack)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-FIXTURE: observer ACK: {error}"))?;
    if ack != *observer_ack_digest(&challenge).bytes() {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: observer ACK differs".into());
    }
    Ok(())
}
