//! External, owned-file export observation. This is a fixture helper, never an
//! installed-provider hook or a source of workload authorization.
#![cfg(target_os = "linux")]

use std::error::Error;
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_PACKET: usize = 64 * 1024;
const ACCESS_PERM: u64 = 0x0002_0000;
const ALLOW: u32 = 1;
const REPORT_PIDFD: u32 = 0x80;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Source {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    length: u64,
    ctime_seconds: i64,
    ctime_nanoseconds: i64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cgroup {
    device: u64,
    inode: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Worker {
    pid: u32,
    birth: u64,
    image_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Setup {
    format: String,
    revision: u32,
    challenge_hex: String,
    work_unix_ms: u64,
    cleanup_unix_ms: u64,
    source: Source,
    cgroup: Cgroup,
    worker: Worker,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ack {
    format: String,
    revision: u32,
    event_id: String,
    challenge_hex: String,
    source_device: u64,
    source_inode: u64,
    worker_pid: u32,
    worker_birth: u64,
    family_retirement_sha256: String,
    cgroup_retirement_sha256: String,
    retirement_kind: String,
}

fn now() -> Result<u64, Box<dyn Error>> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}
fn remaining(cutoff: u64) -> Result<i32, Box<dyn Error>> {
    let available = cutoff
        .checked_sub(now()?)
        .filter(|value| *value != 0)
        .ok_or("original native export cutoff exhausted")?;
    Ok(i32::try_from(available.min(1000))?)
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Box<dyn Error>> {
    if bytes.len() > MAX_PACKET {
        return Err("native export packet too large".into());
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(bytes)?;
    Ok(serde_json::from_slice(bytes)?)
}
fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn hex_decode(text: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("native digest/challenge codec differs".into());
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}
fn sha(bytes: &[u8]) -> String {
    hex_encode(Sha256::digest(bytes))
}
fn birth(pid: u32) -> Result<u64, Box<dyn Error>> {
    let value = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let tail = value
        .rsplit_once(')')
        .ok_or("native worker stat malformed")?
        .1;
    Ok(tail
        .split_whitespace()
        .nth(19)
        .ok_or("native worker birth absent")?
        .parse()?)
}
fn worker_live(worker: &Worker, pidfd: &OwnedFd, cutoff: u64) -> Result<(), Box<dyn Error>> {
    remaining(cutoff)?;
    let mut information = File::open(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut information)
        .take(4097)
        .read_to_end(&mut bytes)?;
    native::close(information.into())?;
    if bytes.len() > 4096 {
        return Err("actual worker PIDFD observation exceeds bound".into());
    }
    let identities = std::str::from_utf8(&bytes)?
        .lines()
        .filter_map(|line| line.strip_prefix("Pid:"))
        .map(str::trim)
        .collect::<Vec<_>>();
    if identities.len() != 1 || identities[0].parse::<u32>()? != worker.pid {
        return Err("actual native PIDFD refers to another worker".into());
    }
    if worker.pid == 0 || worker.birth == 0 || native::poll(pidfd.as_raw_fd(), 0)? {
        return Err("actual selected export worker is not live".into());
    }
    if birth(worker.pid)? != worker.birth {
        return Err("native export worker birth changed".into());
    }
    let mut image = File::open(format!("/proc/{}/exe", worker.pid))?;
    let before = image.metadata()?;
    if !before.is_file() || before.len() > 512 * 1024 * 1024 {
        return Err("worker image bound differs".into());
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        remaining(cutoff)?;
        let count = image.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let after = image.metadata()?;
    if hex_encode(hasher.finalize()) != worker.image_sha256
        || (
            before.dev(),
            before.ino(),
            before.len(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.ctime(),
            after.ctime_nsec(),
        )
        || birth(worker.pid)? != worker.birth
        || native::poll(pidfd.as_raw_fd(), 0)?
    {
        return Err("actual export worker image/identity changed".into());
    }
    native::close(image.into())?;
    Ok(())
}
fn removed(cgroup: &OwnedFd, expected: &Cgroup) -> Result<serde_json::Value, Box<dyn Error>> {
    let file = File::from(native::duplicate(cgroup.as_raw_fd())?);
    let actual = file.metadata()?;
    native::close(file.into())?;
    if !actual.is_dir()
        || (actual.dev(), actual.ino()) != (expected.device, expected.inode)
        || actual.nlink() != 0
        || !native::cgroup2(cgroup.as_raw_fd())?
    {
        return Err("actual original cgroup inode is not natively removed".into());
    }
    Ok(
        serde_json::json!({"device":actual.dev(),"inode":actual.ino(),"native_links":actual.nlink(),"filesystem":"cgroup2","kind":"removed-held-inode"}),
    )
}

/// fd0 is one parent-owned SOCK_SEQPACKET channel. It transfers exactly the
/// owned source and cgroup descriptors; no named source path is accepted.
pub fn run(mut arguments: impl Iterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    if !native::root() {
        return Err("native export controller requires actual root identity".into());
    }
    let mut cutoff = |name: &str| -> Result<u64, Box<dyn Error>> {
        if arguments.next().as_deref() != Some(std::ffi::OsStr::new(name)) {
            return Err("native export original cutoff argument absent".into());
        }
        Ok(arguments
            .next()
            .and_then(|value| value.into_string().ok())
            .ok_or("native export cutoff malformed")?
            .parse()?)
    };
    let work_unix_ms = cutoff("--work-unix-ms")?;
    let cleanup_unix_ms = cutoff("--cleanup-unix-ms")?;
    if arguments.next().is_some() || work_unix_ms >= cleanup_unix_ms {
        return Err("native export original cutoff arguments differ".into());
    }
    remaining(work_unix_ms)?;
    let peer = native::take_stdin()?;
    let (packet, mut rights) = match native::receive(peer.as_raw_fd(), work_unix_ms) {
        Ok(packet) => packet,
        Err(original) => {
            let closed = native::close(peer);
            return Err(format!("{original}; initial peer close={closed:?}").into());
        }
    };
    if rights.len() != 2 {
        let mut errors = Vec::new();
        for owner in rights {
            if let Err(error) = native::close(owner) {
                errors.push(error.to_string());
            }
        }
        if let Err(error) = native::close(peer) {
            errors.push(error.to_string());
        }
        return Err(format!(
            "native export setup needs exactly two owned descriptors; closure={errors:?}"
        )
        .into());
    }
    let cgroup = rights.pop().expect("two validated rights");
    let source = rights.pop().expect("two validated rights");
    let mut group = None;
    let mut event = None;
    let mut event_pidfd = None;
    let mut worker = None;
    let mut marked = false;
    let mut answered = false;
    let mut answer_attempted = false;
    let setup: Setup = match decode(&packet) {
        Ok(setup) => setup,
        Err(original) => {
            let mut errors = Vec::new();
            for owner in [source, cgroup, peer] {
                if let Err(error) = native::close(owner) {
                    errors.push(error.to_string());
                }
            }
            return Err(format!("{original}; native setup closure={errors:?}").into());
        }
    };
    let operation = (|| -> Result<serde_json::Value, Box<dyn Error>> {
        if setup.format != "memcordon.native-export-permission-setup"
            || setup.revision != 1
            || setup.work_unix_ms != work_unix_ms
            || setup.cleanup_unix_ms != cleanup_unix_ms
            || now()? >= setup.work_unix_ms
        {
            return Err("native export setup identity/deadlines differ".into());
        }
        let challenge = hex_decode(&setup.challenge_hex)?;
        if challenge.len() != 32 || challenge.iter().all(|byte| *byte == 0) {
            return Err("native export challenge differs".into());
        }
        let source_file = File::from(native::duplicate(source.as_raw_fd())?);
        let observed = source_file.metadata()?;
        if !observed.is_file()
            || observed.nlink() != 1
            || (
                observed.dev(),
                observed.ino(),
                observed.uid(),
                observed.gid(),
                observed.len(),
                observed.ctime(),
                observed.ctime_nsec(),
            ) != (
                setup.source.device,
                setup.source.inode,
                setup.source.uid,
                setup.source.gid,
                setup.source.length,
                setup.source.ctime_seconds,
                setup.source.ctime_nanoseconds,
            )
            || !native::append_read_write(source.as_raw_fd())?
        {
            return Err("actual owned source descriptor differs".into());
        }
        native::close(source_file.into())?;
        let cgroup_file = File::from(native::duplicate(cgroup.as_raw_fd())?);
        let observed = cgroup_file.metadata()?;
        if !observed.is_dir()
            || (observed.dev(), observed.ino()) != (setup.cgroup.device, setup.cgroup.inode)
            || !native::cgroup2(cgroup.as_raw_fd())?
        {
            return Err("actual owned cgroup descriptor differs".into());
        }
        native::close(cgroup_file.into())?;
        worker = Some(native::pidfd(setup.worker.pid)?);
        worker_live(
            &setup.worker,
            worker.as_ref().expect("held worker"),
            setup.work_unix_ms,
        )?;
        group = Some(native::fanotify()?);
        let group_fd = group.as_ref().expect("created group").as_raw_fd();
        native::mark(group_fd, source.as_raw_fd(), true)?;
        marked = true;
        native::send(
            peer.as_raw_fd(),
            &serde_json::to_vec(&serde_json::json!({
                "format":"memcordon.native-export-permission-armed","revision":1,
                "challenge_hex":setup.challenge_hex,"source":setup.source,"worker":setup.worker
            }))?,
            setup.work_unix_ms,
        )?;
        let (received, pidfd, pid) = native::event(group_fd, setup.work_unix_ms)?;
        event = Some(received);
        event_pidfd = Some(pidfd);
        if pid != setup.worker.pid {
            return Err("permission event belongs to another process".into());
        }
        worker_live(
            &setup.worker,
            event_pidfd.as_ref().expect("received PIDFD"),
            setup.work_unix_ms,
        )?;
        let event_file = File::from(native::duplicate(
            event.as_ref().expect("event held").as_raw_fd(),
        )?);
        let actual = event_file.metadata()?;
        native::close(event_file.into())?;
        if !actual.is_file()
            || actual.nlink() != 1
            || (
                actual.dev(),
                actual.ino(),
                actual.uid(),
                actual.gid(),
                actual.len(),
                actual.ctime(),
                actual.ctime_nsec(),
            ) != (
                setup.source.device,
                setup.source.inode,
                setup.source.uid,
                setup.source.gid,
                setup.source.length,
                setup.source.ctime_seconds,
                setup.source.ctime_nanoseconds,
            )
        {
            return Err("actual permission event source differs".into());
        }
        let cgroup_retirement = removed(&cgroup, &setup.cgroup)?;
        let event_id = sha(&serde_json::to_vec(
            &serde_json::json!({"challenge":setup.challenge_hex,"pid":pid,"birth":setup.worker.birth,
                "device":actual.dev(),"inode":actual.ino(),"uid":actual.uid(),"gid":actual.gid(),"length":actual.len(),
                "ctime_seconds":actual.ctime(),"ctime_nanoseconds":actual.ctime_nsec()}),
        )?);
        native::send(
            peer.as_raw_fd(),
            &serde_json::to_vec(&serde_json::json!({
                "format":"memcordon.native-export-permission-event","revision":1,
                "event_id":event_id,"challenge_hex":setup.challenge_hex,"source":setup.source,
                "worker":setup.worker,"cgroup_retirement":cgroup_retirement
            }))?,
            setup.work_unix_ms,
        )?;
        let (acknowledgment, unexpected) = native::receive(peer.as_raw_fd(), setup.work_unix_ms)?;
        if !unexpected.is_empty() {
            let mut errors = Vec::new();
            for owner in unexpected {
                if let Err(error) = native::close(owner) {
                    errors.push(error.to_string());
                }
            }
            return Err(format!(
                "native export ACK transfers unexpected descriptors; closure={errors:?}"
            )
            .into());
        }
        let ack: Ack = decode(&acknowledgment)?;
        if ack.format != "memcordon.native-export-permission-ack"
            || ack.revision != 1
            || ack.event_id != event_id
            || ack.challenge_hex != setup.challenge_hex
            || (
                ack.source_device,
                ack.source_inode,
                ack.worker_pid,
                ack.worker_birth,
            ) != (
                setup.source.device,
                setup.source.inode,
                setup.worker.pid,
                setup.worker.birth,
            )
            || hex_decode(&ack.family_retirement_sha256)?.len() != 32
            || hex_decode(&ack.cgroup_retirement_sha256)?.len() != 32
            || ack.retirement_kind != "removed-held-inode"
        {
            return Err("native export parent acknowledgment differs".into());
        }
        if removed(&cgroup, &setup.cgroup)? != cgroup_retirement {
            return Err("native removed cgroup changed before append".into());
        }
        worker_live(
            &setup.worker,
            event_pidfd.as_ref().expect("event PIDFD"),
            setup.work_unix_ms,
        )?;
        let mut writer = File::from(native::duplicate(source.as_raw_fd())?);
        let before_append = writer.metadata()?;
        if !before_append.is_file()
            || before_append.nlink() != 1
            || (
                before_append.dev(),
                before_append.ino(),
                before_append.uid(),
                before_append.gid(),
                before_append.len(),
                before_append.ctime(),
                before_append.ctime_nsec(),
            ) != (
                setup.source.device,
                setup.source.inode,
                setup.source.uid,
                setup.source.gid,
                setup.source.length,
                setup.source.ctime_seconds,
                setup.source.ctime_nanoseconds,
            )
        {
            return Err("source changed before controlled append".into());
        }
        writer.write_all(&challenge)?;
        writer.sync_all()?;
        let after_metadata = writer.metadata()?;
        let after = after_metadata.len();
        if !after_metadata.is_file()
            || after_metadata.nlink() != 1
            || (
                after_metadata.dev(),
                after_metadata.ino(),
                after_metadata.uid(),
                after_metadata.gid(),
            ) != (
                setup.source.device,
                setup.source.inode,
                setup.source.uid,
                setup.source.gid,
            )
        {
            return Err("controlled append changed owned source identity".into());
        }
        native::close(writer.into())?;
        if after
            != setup
                .source
                .length
                .checked_add(32)
                .ok_or("source length overflow")?
        {
            return Err("actual append length differs".into());
        }
        answer_attempted = true;
        native::answer(group_fd, event.as_ref().expect("event held").as_raw_fd())?;
        answered = true;
        Ok(
            serde_json::json!({"event_id":event_id,"before_length":setup.source.length,"after_length":after,
                "before_ctime_seconds":setup.source.ctime_seconds,"before_ctime_nanoseconds":setup.source.ctime_nanoseconds,
                "after_ctime_seconds":after_metadata.ctime(),"after_ctime_nanoseconds":after_metadata.ctime_nsec(),
                "family_retirement_sha256":ack.family_retirement_sha256,"cgroup_retirement_sha256":ack.cgroup_retirement_sha256,"cgroup_retirement":cgroup_retirement}),
        )
    })();
    let mut settlement_errors = Vec::new();
    if let (Some(group), Some(event)) = (&group, &event) {
        if !answered {
            answer_attempted = true;
            match native::answer(group.as_raw_fd(), event.as_raw_fd()) {
                Ok(()) => answered = true,
                Err(error) => settlement_errors.push(format!("permission answer: {error}")),
            }
        }
    }
    let mut unmark_observation = serde_json::Value::Null;
    if marked {
        if let Some(group) = &group {
            match native::mark(group.as_raw_fd(), source.as_raw_fd(), false) {
                Ok(()) => {
                    unmark_observation =
                        serde_json::json!({"attempted":true,"completed":true,"errno":null})
                }
                Err(error) => {
                    unmark_observation = serde_json::json!({"attempted":true,"completed":false,"errno":error.raw_os_error()});
                    settlement_errors.push(format!("unmark: {error}"));
                }
            }
        }
    }
    let mut closures = Vec::new();
    for (role, owner) in [
        ("event", event.take()),
        ("event-pidfd", event_pidfd.take()),
        ("worker-pidfd", worker.take()),
        ("group", group.take()),
        ("source", Some(source)),
        ("cgroup", Some(cgroup)),
    ] {
        if let Some(owner) = owner {
            match native::close(owner) {
                Ok(()) => closures.push(
                    serde_json::json!({"role":role,"attempted":true,"completed":true,"errno":null}),
                ),
                Err(error) => {
                    closures.push(serde_json::json!({"role":role,"attempted":true,"completed":false,"errno":error.raw_os_error()}));
                    settlement_errors.push(format!("{role} close: {error}"));
                }
            }
        }
    }
    let settled = serde_json::json!({"format":"memcordon.native-export-permission-settled","revision":1,"challenge_hex":setup.challenge_hex,
        "work_unix_ms":setup.work_unix_ms,"cleanup_unix_ms":setup.cleanup_unix_ms,
        "permission_answer":{"attempted":answer_attempted,"fan_allow_written":answered},
        "mark_installed":marked,"unmark":unmark_observation,"closures":closures,
        "operation":operation.as_ref().ok(),"operation_error":operation.as_ref().err().map(ToString::to_string),"settlement_errors":settlement_errors});
    let publication = native::send(
        peer.as_raw_fd(),
        &serde_json::to_vec(&settled)?,
        setup.cleanup_unix_ms,
    );
    let peer_close = native::close(peer);
    publication?;
    peer_close?;
    if now()? >= setup.cleanup_unix_ms {
        return Err("original export cleanup cutoff exhausted".into());
    }
    operation?;
    if !settlement_errors.is_empty() {
        return Err("native export settlement retained errors".into());
    }
    Ok(())
}

/// Each unsafe call below has a native descriptor owner and initialized,
/// bounded storage. No source bytes are read after the permission mark.
#[allow(unsafe_code)]
mod native {
    use super::*;
    use std::io;
    fn result(value: i32) -> io::Result<i32> {
        if value < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(value)
        }
    }
    pub fn root() -> bool {
        (unsafe { libc::geteuid() }) == 0
    }
    pub fn close(owner: OwnedFd) -> io::Result<()> {
        // SAFETY: ownership is consumed exactly once; never retry close(EINTR).
        result(unsafe { libc::close(owner.into_raw_fd()) }).map(|_| ())
    }
    pub fn duplicate(fd: i32) -> io::Result<OwnedFd> {
        // SAFETY: fcntl duplicates a live borrowed descriptor with CLOEXEC.
        let raw = result(unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) })?;
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }
    pub fn take_stdin() -> io::Result<OwnedFd> {
        // SAFETY: this host-only mode exclusively owns its inherited stdin.
        let peer = unsafe { OwnedFd::from_raw_fd(0) };
        let mut kind = 0_i32;
        let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
        // SAFETY: initialized integer output and its exact writable length.
        result(unsafe {
            libc::getsockopt(
                peer.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut kind as *mut i32).cast(),
                &mut length,
            )
        })?;
        if kind != libc::SOCK_SEQPACKET {
            return Err(io::Error::other("stdin is not native SeqPacket"));
        }
        Ok(peer)
    }
    pub fn poll(fd: i32, timeout: i32) -> io::Result<bool> {
        let mut state = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized writable pollfd; no borrowed owners move.
        let count = result(unsafe { libc::poll(&mut state, 1, timeout) })?;
        if state.revents & libc::POLLNVAL != 0 {
            return Err(io::Error::other("native descriptor invalid"));
        }
        Ok(count > 0)
    }
    pub fn receive(peer: i32, cutoff: u64) -> Result<(Vec<u8>, Vec<OwnedFd>), Box<dyn Error>> {
        while !poll(peer, remaining(cutoff)?)? {}
        let mut bytes = vec![0_u8; MAX_PACKET];
        let mut control = [0_usize; 64];
        let mut vector = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control);
        // SAFETY: both buffers have initialized bounded writable storage.
        let count = unsafe { libc::recvmsg(peer, &mut message, libc::MSG_CMSG_CLOEXEC) };
        if count < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let mut owned = Vec::new();
        let mut invalid = false;
        let control_start = control.as_ptr() as usize;
        let control_end = control_start
            .checked_add(message.msg_controllen)
            .ok_or("native control length overflow")?;
        if message.msg_controllen > std::mem::size_of_val(&control) {
            return Err("native control storage bound differs".into());
        }
        // SAFETY: CMSG helpers walk only the kernel-returned bounded control buffer.
        let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        while !header.is_null() {
            let address = header as usize;
            if address < control_start
                || address
                    .checked_add(std::mem::size_of::<libc::cmsghdr>())
                    .is_none_or(|end| end > control_end)
            {
                invalid = true;
                break;
            }
            let value = unsafe { &*header };
            let minimum = unsafe { libc::CMSG_LEN(0) } as usize;
            if value.cmsg_len < minimum
                || address
                    .checked_add(value.cmsg_len)
                    .is_none_or(|end| end > control_end)
            {
                invalid = true;
                break;
            }
            if value.cmsg_level == libc::SOL_SOCKET && value.cmsg_type == libc::SCM_RIGHTS {
                let length = value.cmsg_len - minimum;
                if length % std::mem::size_of::<i32>() != 0 {
                    invalid = true;
                }
                let pointer = unsafe { libc::CMSG_DATA(header) }.cast::<i32>();
                for ordinal in 0..length / std::mem::size_of::<i32>() {
                    let raw = unsafe { pointer.add(ordinal).read_unaligned() };
                    if raw < 0 {
                        invalid = true;
                    } else {
                        owned.push(unsafe { OwnedFd::from_raw_fd(raw) });
                    }
                }
            } else {
                invalid = true;
            }
            header = unsafe { libc::CMSG_NXTHDR(&message, header) };
        }
        if invalid
            || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            || count == 0
            || count as usize > MAX_PACKET
        {
            let mut errors = Vec::new();
            for owner in owned {
                if let Err(error) = close(owner) {
                    errors.push(error.to_string());
                }
            }
            return Err(format!(
                "native export setup/control message truncated or malformed; closure={errors:?}"
            )
            .into());
        }
        bytes.truncate(count as usize);
        Ok((bytes, owned))
    }
    pub fn send(peer: i32, bytes: &[u8], cutoff: u64) -> io::Result<()> {
        if bytes.len() > MAX_PACKET {
            return Err(io::Error::other("native receipt packet too large"));
        }
        let count = loop {
            let timeout = remaining(cutoff).map_err(|error| io::Error::other(error.to_string()))?;
            let mut ready = libc::pollfd {
                fd: peer,
                events: libc::POLLOUT,
                revents: 0,
            };
            // SAFETY: one initialized writable pollfd.
            if result(unsafe { libc::poll(&mut ready, 1, timeout) })? == 0 {
                continue;
            }
            // SAFETY: immutable bytes remain valid for the finite nonblocking send.
            let count = unsafe {
                libc::send(
                    peer,
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                )
            };
            if count < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::WouldBlock {
                    continue;
                }
                return Err(error);
            }
            break count;
        };
        if count as usize != bytes.len() {
            return Err(io::Error::other("native receipt send incomplete"));
        }
        Ok(())
    }
    pub fn append_read_write(fd: i32) -> io::Result<bool> {
        let flags = result(unsafe { libc::fcntl(fd, libc::F_GETFL) })?;
        Ok(flags & libc::O_ACCMODE == libc::O_RDWR && flags & libc::O_APPEND != 0)
    }
    pub fn cgroup2(fd: i32) -> io::Result<bool> {
        let mut output: libc::statfs = unsafe { std::mem::zeroed() };
        result(unsafe { libc::fstatfs(fd, &mut output) })?;
        Ok(output.f_type as u64 == 0x6367_7270)
    }
    pub fn pidfd(pid: u32) -> io::Result<OwnedFd> {
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(raw as i32) })
    }
    pub fn fanotify() -> io::Result<OwnedFd> {
        // FAN_CLASS_PRE_CONTENT|NONBLOCK|CLOEXEC|REPORT_PIDFD. Unsupported
        // kernels or privileges fail as prerequisites, never an export pass.
        let raw = result(unsafe {
            libc::fanotify_init(
                8 | 2 | 1 | REPORT_PIDFD,
                (libc::O_RDONLY | libc::O_CLOEXEC) as u32,
            )
        })?;
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }
    pub fn mark(group: i32, source: i32, add: bool) -> io::Result<()> {
        let path = std::ffi::CString::new(format!("/proc/self/fd/{source}"))?;
        // The exact file only; no FAN_MARK_MOUNT or filesystem-wide mark.
        let flags = if add { 1 } else { 2 };
        result(unsafe {
            libc::fanotify_mark(group, flags, ACCESS_PERM, libc::AT_FDCWD, path.as_ptr())
        })
        .map(|_| ())
    }
    pub fn answer(group: i32, event: i32) -> io::Result<()> {
        let mut bytes = [0_u8; 8];
        bytes[..4].copy_from_slice(&event.to_ne_bytes());
        bytes[4..].copy_from_slice(&ALLOW.to_ne_bytes());
        let count = unsafe { libc::write(group, bytes.as_ptr().cast(), bytes.len()) };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        if count != 8 {
            return Err(io::Error::other("FAN_ALLOW write incomplete"));
        }
        Ok(())
    }
    pub fn event(group: i32, cutoff: u64) -> Result<(OwnedFd, OwnedFd, u32), Box<dyn Error>> {
        while !poll(group, remaining(cutoff)?)? {}
        let mut bytes = [0_u8; 4096];
        let count = unsafe { libc::read(group, bytes.as_mut_ptr().cast(), bytes.len()) };
        if count < 0 {
            return Err(io::Error::last_os_error().into());
        }
        if count < 24 {
            return Err("fanotify event header truncated".into());
        }
        let u32_at = |offset: usize| {
            u32::from_ne_bytes(
                bytes[offset..offset + 4]
                    .try_into()
                    .expect("bounded native field"),
            )
        };
        let event_length = u32_at(0) as usize;
        let metadata_length = u16::from_ne_bytes([bytes[6], bytes[7]]) as usize;
        let mask = u64::from_ne_bytes(bytes[8..16].try_into().expect("bounded native mask"));
        let raw = i32::from_ne_bytes(bytes[16..20].try_into().expect("bounded native descriptor"));
        let pid = i32::from_ne_bytes(bytes[20..24].try_into().expect("bounded native PID"));
        // Adopt the delivered descriptor before any later fallible validation.
        let source = if raw >= 0 {
            Some(unsafe { OwnedFd::from_raw_fd(raw) })
        } else {
            None
        };
        let mut pidfd = None;
        let mut offset = metadata_length;
        let mut parse_errors = Vec::new();
        let bounded_metadata = bytes[4] == 3
            && metadata_length >= 24
            && metadata_length <= event_length
            && event_length <= count as usize;
        while bounded_metadata && offset + 4 <= event_length {
            let length = u16::from_ne_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
            if length < 4 || offset + length > event_length {
                break;
            }
            if bytes[offset] == 4 && length >= 8 {
                let raw = i32::from_ne_bytes(
                    bytes[offset + 4..offset + 8]
                        .try_into()
                        .expect("bounded native PIDFD"),
                );
                if raw >= 0 {
                    let owner = unsafe { OwnedFd::from_raw_fd(raw) };
                    if pidfd.is_some() {
                        parse_errors.push("duplicate kernel PIDFD".into());
                        if let Err(error) = close(owner) {
                            parse_errors.push(error.to_string());
                        }
                    } else {
                        pidfd = Some(owner);
                    }
                }
            }
            offset += length;
        }
        if !bounded_metadata
            || event_length != count as usize
            || bytes[4] != 3
            || metadata_length < 24
            || mask != ACCESS_PERM
            || pid <= 0
            || offset != event_length
            || source.is_none()
            || pidfd.is_none()
            || !parse_errors.is_empty()
        {
            let mut errors = parse_errors;
            if let Some(owner) = source {
                if let Err(error) = answer(group, owner.as_raw_fd()) {
                    errors.push(format!("answer: {error}"));
                }
                if let Err(error) = close(owner) {
                    errors.push(format!("event close: {error}"));
                }
            }
            if let Some(owner) = pidfd {
                if let Err(error) = close(owner) {
                    errors.push(format!("PIDFD close: {error}"));
                }
            }
            if bounded_metadata {
                if let Err(error) = settle_remaining(group, &bytes[..count as usize], event_length)
                {
                    errors.push(error.to_string());
                }
            } else {
                errors.push(
                    "native event metadata bounds unavailable; remaining descriptors uncertain"
                        .into(),
                );
            }
            return Err(format!("fanotify event is not exact owned access-permission/PIDFD observation; settlement={errors:?}").into());
        }
        Ok((
            source.expect("validated source"),
            pidfd.expect("validated PIDFD"),
            pid as u32,
        ))
    }
    fn settle_remaining(group: i32, bytes: &[u8], mut offset: usize) -> io::Result<()> {
        let mut errors = Vec::new();
        while offset < bytes.len() {
            if bytes.len() - offset < 24 {
                errors.push("trailing native event header truncated".into());
                break;
            }
            let length = u32::from_ne_bytes(
                bytes[offset..offset + 4]
                    .try_into()
                    .expect("bounded event length"),
            ) as usize;
            if length < 24 || length > bytes.len() - offset {
                errors.push("trailing native event length malformed".into());
                break;
            }
            let raw = i32::from_ne_bytes(
                bytes[offset + 16..offset + 20]
                    .try_into()
                    .expect("bounded event descriptor"),
            );
            if raw >= 0 {
                let owner = unsafe { OwnedFd::from_raw_fd(raw) };
                if let Err(error) = answer(group, owner.as_raw_fd()) {
                    errors.push(format!("trailing answer: {error}"));
                }
                if let Err(error) = close(owner) {
                    errors.push(format!("trailing event close: {error}"));
                }
            }
            let metadata = u16::from_ne_bytes([bytes[offset + 6], bytes[offset + 7]]) as usize;
            let mut information = metadata.max(24);
            while information + 4 <= length {
                let base = offset + information;
                let size = u16::from_ne_bytes([bytes[base + 2], bytes[base + 3]]) as usize;
                if size < 4 || information + size > length {
                    errors.push("trailing event information malformed".into());
                    break;
                }
                if bytes[base] == 4 && size >= 8 {
                    let raw = i32::from_ne_bytes(
                        bytes[base + 4..base + 8]
                            .try_into()
                            .expect("bounded trailing PIDFD"),
                    );
                    if raw >= 0 {
                        if let Err(error) = close(unsafe { OwnedFd::from_raw_fd(raw) }) {
                            errors.push(format!("trailing PIDFD close: {error}"));
                        }
                    }
                }
                information += size;
            }
            offset += length;
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(format!("{errors:?}")))
        }
    }
}
