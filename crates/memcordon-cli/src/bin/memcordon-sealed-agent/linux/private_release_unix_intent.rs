//! Closed target subwitness for the pathname and abstract AF_UNIX intents.
//! The reviewed filter rejects socket creation before either address can be
//! passed to bind. This module cannot publish a release case by itself.

use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::path::Path;

pub(crate) const SELECTOR: &str = "private_tcp::af_unix_abstract_and_pathname_denied";
const DOMAIN: &[u8] = b"memcordon-private-unix-intent-v1\0";
const PROC_UNIX_LIMIT: u64 = 1024 * 1024;

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
    if observed.len() as u64 > PROC_UNIX_LIMIT
        || observed
            .windows(name.len())
            .any(|window| window == name.as_bytes())
    {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: AF_UNIX endpoint present".into());
    }
    Ok(())
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
    let observed = observe_target_denials(&challenge)?;
    std::io::stdout()
        .write_all(&observed)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-FIXTURE: Unix intent output: {error}"))
}
