//! Root observer read-only network namespace sampling, confined to a fresh
//! thread. No target process, route, address, sysctl or credential is changed.
use std::collections::BTreeMap;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;

fn read(path: &std::path::Path) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err(io::Error::other("network source exceeds reviewed bound"));
    }
    Ok(bytes)
}
fn start(bytes: &[u8], pid: u32) -> io::Result<u64> {
    let text = std::str::from_utf8(bytes).map_err(io::Error::other)?;
    let (number, tail) = text
        .split_once(' ')
        .ok_or_else(|| io::Error::other("network target stat prefix absent"))?;
    if number.parse::<u32>().map_err(io::Error::other)? != pid {
        return Err(io::Error::other("network source task identity differs"));
    }
    let (_, fields) = tail
        .rsplit_once(") ")
        .ok_or_else(|| io::Error::other("network target stat fields absent"))?;
    fields
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| io::Error::other("network target start absent"))?
        .parse()
        .map_err(io::Error::other)
}

pub(super) fn sample(pid: u32, ticks: u64) -> io::Result<BTreeMap<String, Vec<u8>>> {
    // SAFETY: geteuid has no pointer operands or state effects.
    if pid == 0 || ticks == 0 || unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::other(
            "network sampling requires held task and root observer",
        ));
    }
    let root = std::path::Path::new("/proc").join(pid.to_string());
    let before = read(&root.join("stat"))?;
    if start(&before, pid)? != ticks {
        return Err(io::Error::other("network target start changed"));
    }
    let target = std::fs::File::open(root.join("ns/net"))?;
    let target_inode = target.metadata()?.ino();
    let original = std::fs::File::open("/proc/thread-self/ns/net")?;
    let original_inode = original.metadata()?.ino();
    let joined=std::thread::spawn(move ||->io::Result<BTreeMap<String,Vec<u8>>>{
        let begin=crate::test_support::private_observer_monotonic_ns()?;
        // SAFETY: the exclusively owned namespace handle is retained; only
        // this fresh thread changes namespace, never the calling supervisor.
        if unsafe{libc::setns(target.as_raw_fd(),libc::CLONE_NEWNET)}!=0{return Err(io::Error::last_os_error());}
        let result=(||{
            if std::fs::metadata("/proc/thread-self/ns/net")?.ino()!=target_inode{return Err(io::Error::other("joined network namespace differs"));}
            let mut leaves=BTreeMap::new();
            leaves.insert("reader-stat.raw".into(),read(std::path::Path::new("/proc/thread-self/stat"))?);
            for (name,path) in [
                ("ip_unprivileged_port_start","/proc/sys/net/ipv4/ip_unprivileged_port_start"),
                ("ip_forward","/proc/sys/net/ipv4/ip_forward"),
                ("ip_local_port_range","/proc/sys/net/ipv4/ip_local_port_range"),
                ("ip_local_reserved_ports","/proc/sys/net/ipv4/ip_local_reserved_ports"),
            ]{leaves.insert(name.into(),read(std::path::Path::new(path))?);}
            for (label,request,response,body) in [("links",18u16,16u16,16usize),("addresses",22,20,8),("routes",26,24,12)]{
                let (sent,packets)=dump(request,response,body)?;
                leaves.insert(format!("{label}/request.raw"),sent);
                for (ordinal,packet) in packets.into_iter().enumerate(){leaves.insert(format!("{label}/{ordinal}.raw"),packet);}
            }
            leaves.insert("proc1-status.raw".into(),read(&root.join("root/proc/1/status"))?);
            leaves.insert("target-stat-before.raw".into(),before);
            let after=read(&root.join("stat"))?;
            if start(&after,pid)?!=ticks || std::fs::metadata(root.join("ns/net"))?.ino()!=target_inode{return Err(io::Error::other("held network task changed during sample"));}
            leaves.insert("target-stat-after.raw".into(),after);
            leaves.insert("reader-stat-after.raw".into(),read(std::path::Path::new("/proc/thread-self/stat"))?);
            leaves.insert("identity.json".into(),serde_json::to_vec(&serde_json::json!({"schema_version":1,"target_pid":pid,"target_start_ticks":ticks,"host_netns_inode":original_inode,"target_netns_inode":target_inode,"begin_monotonic_ns":begin,"end_monotonic_ns":crate::test_support::private_observer_monotonic_ns()?})).map_err(io::Error::other)?);
            Ok(leaves)
        })();
        // SAFETY: restore this thread's original held namespace before return.
        if unsafe{libc::setns(original.as_raw_fd(),libc::CLONE_NEWNET)}!=0{return Err(io::Error::other("network observer namespace restoration failed"));}
        if std::fs::metadata("/proc/thread-self/ns/net")?.ino()!=original_inode{return Err(io::Error::other("restored observer network namespace differs"));}
        result
    }).join().map_err(|_|io::Error::other("network observer thread panicked"))?;
    joined
}

/// Retain the real request and kernel-origin datagrams, including DONE. Pure
/// completed replay independently rechecks every header/sequence/attribute.
pub(super) fn dump(
    request: u16,
    response: u16,
    body: usize,
) -> io::Result<(Vec<u8>, Vec<Vec<u8>>)> {
    // SAFETY: native socket takes fixed scalar UAPI arguments.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful socket returns an exclusively owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: zero initialization supplies valid default sockaddr_nl fields.
    let mut local: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    local.nl_family = libc::AF_NETLINK as u16;
    // SAFETY: pointer borrows initialized address for the exact native size.
    if unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&raw const local).cast(),
            std::mem::size_of_val(&local) as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut length = std::mem::size_of_val(&local) as libc::socklen_t;
    // SAFETY: getsockname writes only the initialized local address and length.
    if unsafe { libc::getsockname(fd.as_raw_fd(), (&raw mut local).cast(), &raw mut length) } != 0
        || length as usize != std::mem::size_of_val(&local)
        || local.nl_pid == 0
    {
        return Err(io::Error::other("observer netlink port absent"));
    }
    let mut sent = vec![0u8; 16 + body];
    let sent_len = sent.len() as u32;
    sent[..4].copy_from_slice(&sent_len.to_le_bytes());
    sent[4..6].copy_from_slice(&request.to_le_bytes());
    sent[6..8].copy_from_slice(&0x301u16.to_le_bytes());
    sent[8..12].copy_from_slice(&1u32.to_le_bytes());
    sent[12..16].copy_from_slice(&local.nl_pid.to_le_bytes());
    // SAFETY: zero address selects the kernel netlink peer, not userspace.
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as u16;
    // SAFETY: sendto borrows the complete request and initialized kernel peer.
    if unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            sent.as_ptr().cast(),
            sent.len(),
            0,
            (&raw const kernel).cast(),
            std::mem::size_of_val(&kernel) as libc::socklen_t,
        )
    } != sent.len() as isize
    {
        return Err(io::Error::last_os_error());
    }
    let mut packets = Vec::new();
    let mut total = 0usize;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    for _ in 0..64 {
        let mut ready = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll borrows one retained socket with a bounded deadline.
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let timeout = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX);
        if timeout == 0
            || unsafe { libc::poll(&raw mut ready, 1, timeout) } != 1
            || ready.revents & libc::POLLIN == 0
        {
            return Err(io::Error::other("network dump deadline expired"));
        }
        let mut bytes = vec![0u8; 8192];
        // SAFETY: zero initialization gives a valid kernel sender address.
        let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut sender_len = std::mem::size_of_val(&sender) as libc::socklen_t;
        // SAFETY: recvfrom writes within the supplied vector and address sizes.
        let count = unsafe {
            libc::recvfrom(
                fd.as_raw_fd(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                libc::MSG_TRUNC,
                (&raw mut sender).cast(),
                &raw mut sender_len,
            )
        };
        if count <= 0
            || count as usize > bytes.len()
            || sender_len as usize != std::mem::size_of_val(&sender)
            || sender.nl_family != libc::AF_NETLINK as u16
            || sender.nl_pid != 0
            || sender.nl_groups != 0
        {
            return Err(io::Error::other("network dump sender/length differs"));
        }
        bytes.truncate(count as usize);
        total += bytes.len();
        if total > 512 * 1024 {
            return Err(io::Error::other("network dump byte bound exceeded"));
        }
        let mut cursor = 0usize;
        let mut done = false;
        while cursor < bytes.len() {
            if bytes.len() - cursor < 16 {
                return Err(io::Error::other("network dump partial header"));
            }
            let header = &bytes[cursor..cursor + 16];
            let length =
                u32::from_le_bytes(header[..4].try_into().expect("bounded header")) as usize;
            let kind = u16::from_le_bytes(header[4..6].try_into().expect("bounded header"));
            let flags = u16::from_le_bytes(header[6..8].try_into().expect("bounded header"));
            if length < 16
                || length > bytes.len() - cursor
                || u32::from_le_bytes(header[8..12].try_into().expect("bounded header")) != 1
                || u32::from_le_bytes(header[12..16].try_into().expect("bounded header"))
                    != local.nl_pid
                || flags & 0x10 != 0
            {
                return Err(io::Error::other(
                    "network dump sequence/length/interruption differs",
                ));
            }
            if kind == 3 {
                if length < 20 || bytes[cursor + 16..cursor + 20] != [0; 4] {
                    return Err(io::Error::other("network dump DONE status differs"));
                }
                done = true;
            } else if kind != response || done {
                return Err(io::Error::other("network dump message type/order differs"));
            }
            cursor += (length + 3) & !3;
            if cursor > bytes.len() {
                return Err(io::Error::other("network dump alignment differs"));
            }
        }
        packets.push(bytes);
        if done {
            return Ok((sent, packets));
        }
    }
    Err(io::Error::other("network dump lacks bounded DONE"))
}
