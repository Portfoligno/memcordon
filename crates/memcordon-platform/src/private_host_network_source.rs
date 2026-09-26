//! Root observer continuity sources. This only reads host objects and receives
//! kernel RTNETLINK notifications; it neither joins nor changes a namespace.
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::sync::mpsc::{self, Receiver, Sender};

const PATHS: [&str; 4] = [
    "/proc/sys/net/ipv4/ip_unprivileged_port_start",
    "/proc/sys/net/ipv4/ip_forward",
    "/proc/sys/net/ipv4/ip_local_port_range",
    "/proc/sys/net/ipv4/ip_local_reserved_ports",
];
const SOURCE_BOUND: usize = 8 * 1024 * 1024;
type Leaves = BTreeMap<String, Vec<u8>>;

/// Must be started before BPF arm and stopped after its measured detach. Pins
/// are independently opened host objects, not supplied paths or producer data.
pub struct HostNetworkWatchV1 {
    pins: [(u64, u64); 4],
    stop: Option<Sender<()>>,
    thread: Option<std::thread::JoinHandle<io::Result<Leaves>>>,
}
impl HostNetworkWatchV1 {
    pub fn start() -> io::Result<Self> {
        // SAFETY: geteuid is a read-only scalar native operation.
        if unsafe { libc::geteuid() } != 0 {
            return Err(io::Error::other("host continuity requires root observer"));
        }
        let files = PATHS
            .map(|path| {
                OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(path)
            })
            .into_iter()
            .collect::<io::Result<Vec<_>>>()?;
        let mut pins = [(0, 0); 4];
        for (slot, file) in files.iter().enumerate() {
            let metadata = file.metadata()?;
            pins[slot] = (metadata.dev(), metadata.ino());
            if pins[slot].0 == 0 || pins[slot].1 == 0 || pins[..slot].contains(&pins[slot]) {
                return Err(io::Error::other("host object pins differ"));
            }
        }
        let namespace = File::open("/proc/thread-self/ns/net")?;
        let netns = namespace.metadata()?.ino();
        let (stop, stopped) = mpsc::channel();
        let (ready, readiness) = mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            let result = run(files, pins, namespace, netns, stopped, &ready);
            if let Err(error) = &result {
                let _ = ready.try_send(Err(error.to_string()));
            }
            result
        });
        match readiness.recv().map_err(io::Error::other)? {
            Ok(()) => Ok(Self {
                pins,
                stop: Some(stop),
                thread: Some(thread),
            }),
            Err(message) => {
                let _ = thread.join();
                Err(io::Error::other(message))
            }
        }
    }
    pub fn object_pins(&self) -> &[(u64, u64); 4] {
        &self.pins
    }
    pub fn finish(mut self) -> io::Result<Leaves> {
        self.stop
            .take()
            .ok_or_else(|| io::Error::other("host watch already stopped"))?
            .send(())
            .map_err(io::Error::other)?;
        self.thread
            .take()
            .ok_or_else(|| io::Error::other("host watch thread absent"))?
            .join()
            .map_err(|_| io::Error::other("host watch thread panicked"))?
    }
}
impl Drop for HostNetworkWatchV1 {
    fn drop(&mut self) {
        // Dropping an unfinished observer cannot yield a successful source.
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
fn now() -> io::Result<u64> {
    crate::test_support::private_observer_monotonic_ns()
}
fn bounded(file: &File) -> io::Result<Vec<u8>> {
    use std::os::unix::fs::FileExt;
    let mut bytes = vec![0; 4097];
    let length = file.read_at(&mut bytes, 0)?;
    if length == 0 || length > 4096 {
        return Err(io::Error::other("host sysctl source bound differs"));
    }
    bytes.truncate(length);
    Ok(bytes)
}
fn read_stat() -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open("/proc/thread-self/stat")?
        .take(4097)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(io::Error::other("host reader stat bound differs"));
    }
    Ok(bytes)
}
fn queue_drops(fd: &OwnedFd) -> io::Result<(u64, Vec<u8>)> {
    // SAFETY: fstat writes one initialized metadata object for the held socket.
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &raw mut metadata) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut bytes = Vec::new();
    File::open("/proc/thread-self/net/netlink")?
        .take(128 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 128 * 1024 {
        return Err(io::Error::other("host netlink queue source bound exceeded"));
    }
    let text = std::str::from_utf8(&bytes).map_err(io::Error::other)?;
    let mut rows = text.lines();
    if rows
        .next()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        != Some(vec![
            "sk", "Eth", "Pid", "Groups", "Rmem", "Wmem", "Dump", "Locks", "Drops", "Inode",
        ])
    {
        return Err(io::Error::other("host netlink queue header differs"));
    }
    let mut matched = 0usize;
    for row in rows {
        let fields = row.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 10 {
            return Err(io::Error::other("host netlink queue row differs"));
        }
        if fields[9].parse::<u64>().map_err(io::Error::other)? == metadata.st_ino {
            matched += 1;
            if fields[1].parse::<u32>().map_err(io::Error::other)? != 0
                || fields[2].parse::<u32>().map_err(io::Error::other)? == 0
                || u32::from_str_radix(fields[3], 16).map_err(io::Error::other)? != 0x551
                || fields[8].parse::<u64>().map_err(io::Error::other)? != 0
            {
                return Err(io::Error::other("host netlink notifications dropped"));
            }
        }
    }
    if matched != 1 {
        return Err(io::Error::other(
            "host netlink held socket queue absent/duplicated",
        ));
    }
    Ok((metadata.st_ino, bytes))
}
fn snapshots(
    leaves: &mut Leaves,
    phase: &str,
    files: &[File],
    pins: &[(u64, u64); 4],
) -> io::Result<()> {
    for (slot, file) in files.iter().enumerate() {
        let metadata = file.metadata()?;
        if (metadata.dev(), metadata.ino()) != pins[slot] {
            return Err(io::Error::other("host held object changed"));
        }
        leaves.insert(format!("{phase}/sysctl-{slot}.raw"), bounded(file)?);
    }
    for (label, request, response, body) in [
        ("links", 18, 16, 16),
        ("addresses", 22, 20, 8),
        ("routes", 26, 24, 12),
    ] {
        let (sent, packets) = super::private_network_source::dump(request, response, body)?;
        let mut framed = b"MCHD\x01\0\0\0".to_vec();
        framed.extend_from_slice(&(packets.len() as u32).to_le_bytes());
        for packet in packets {
            framed.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            framed.extend_from_slice(&packet);
        }
        leaves.insert(format!("{phase}/{label}-request.raw"), sent);
        leaves.insert(format!("{phase}/{label}-dump.raw"), framed);
    }
    Ok(())
}
fn socket() -> io::Result<OwnedFd> {
    // SAFETY: fixed scalar native socket arguments; returned FD is owned once.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let overflow: libc::c_int = 1;
    // SAFETY: option borrows an initialized native integer of the exact size.
    if unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RXQ_OVFL,
            (&raw const overflow).cast(),
            std::mem::size_of_val(&overflow) as _,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: zeroed sockaddr_nl is a valid initialized native address.
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    // LINK, IPv4/IPv6 addresses and IPv4/IPv6 routes. No userspace groups.
    address.nl_groups = 1 | 0x10 | 0x40 | 0x100 | 0x400;
    // SAFETY: bind borrows the retained address for its exact native size.
    if unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&raw const address).cast(),
            std::mem::size_of_val(&address) as _,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}
fn drain(fd: &OwnedFd, framed: &mut Vec<u8>) -> io::Result<()> {
    loop {
        let mut bytes = vec![0u8; 65536];
        // SAFETY: zero initialization produces valid output storage for recvmsg.
        let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut control = [0usize; 16];
        let mut vector = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_name = (&raw mut sender).cast();
        message.msg_namelen = std::mem::size_of_val(&sender) as _;
        message.msg_iov = &raw mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control);
        // SAFETY: recvmsg writes only the initialized vectors/address/control buffers.
        let count = unsafe { libc::recvmsg(fd.as_raw_fd(), &raw mut message, libc::MSG_DONTWAIT) };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok(());
            }
            return Err(error);
        }
        if count == 0
            || count as usize > bytes.len()
            || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            || message.msg_namelen as usize != std::mem::size_of_val(&sender)
            || sender.nl_family != libc::AF_NETLINK as u16
            || sender.nl_pid != 0
        {
            return Err(io::Error::other(
                "host notification sender/truncation differs",
            ));
        }
        // SAFETY: libc ancillary traversal is confined to recvmsg's initialized
        // control buffer and each data read is guarded by exact CMSG_LEN.
        let mut ancillary = unsafe { libc::CMSG_FIRSTHDR(&raw const message) };
        while !ancillary.is_null() {
            let header = unsafe { &*ancillary };
            if header.cmsg_level != libc::SOL_SOCKET
                || header.cmsg_type != libc::SO_RXQ_OVFL
                || header.cmsg_len
                    != unsafe { libc::CMSG_LEN(std::mem::size_of::<u32>() as _) as usize }
            {
                return Err(io::Error::other("host notification ancillary differs"));
            }
            let lost =
                unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(ancillary).cast::<u32>()) };
            if lost != 0 {
                return Err(io::Error::other("host notification queue lost records"));
            }
            ancillary = unsafe { libc::CMSG_NXTHDR(&raw const message, ancillary) };
        }
        bytes.truncate(count as usize);
        if framed
            .len()
            .checked_add(bytes.len() + 12)
            .is_none_or(|length| length > 1024 * 1024)
        {
            return Err(io::Error::other("host notification source bound exceeded"));
        }
        framed.extend_from_slice(&now()?.to_le_bytes());
        framed.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        framed.extend_from_slice(&bytes);
    }
}
fn run(
    files: Vec<File>,
    pins: [(u64, u64); 4],
    namespace: File,
    netns: u64,
    stop: Receiver<()>,
    ready: &mpsc::SyncSender<Result<(), String>>,
) -> io::Result<Leaves> {
    if File::open("/proc/thread-self/ns/net")?.metadata()?.ino() != netns
        || namespace.metadata()?.ino() != netns
    {
        return Err(io::Error::other("host monitor namespace differs"));
    }
    let fd = socket()?;
    let begin = now()?;
    let before_stat = read_stat()?;
    let (socket_inode, queue_before) = queue_drops(&fd)?;
    let mut leaves = Leaves::new();
    snapshots(&mut leaves, "before", &files, &pins)?;
    let mut notifications = b"MCHN\x01\0\0\0".to_vec();
    drain(&fd, &mut notifications)?;
    ready.send(Ok(())).map_err(io::Error::other)?;
    loop {
        drain(&fd, &mut notifications)?;
        match stop.recv_timeout(std::time::Duration::from_millis(10)) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
    snapshots(&mut leaves, "after", &files, &pins)?;
    drain(&fd, &mut notifications)?;
    let (after_inode, queue_after) = queue_drops(&fd)?;
    if after_inode != socket_inode {
        return Err(io::Error::other("host retained netlink socket changed"));
    }
    let end = now()?;
    let after_stat = read_stat()?;
    if File::open("/proc/thread-self/ns/net")?.metadata()?.ino() != netns {
        return Err(io::Error::other("host monitor namespace changed"));
    }
    leaves.insert("notifications.raw".into(), notifications);
    leaves.insert("reader-stat-before.raw".into(), before_stat);
    leaves.insert("reader-stat-after.raw".into(), after_stat);
    leaves.insert("netlink-queue-before.raw".into(), queue_before);
    leaves.insert("netlink-queue-after.raw".into(), queue_after);
    leaves.insert("identity.json".into(),serde_json::to_vec(&serde_json::json!({"schema_version":1,"protocol":"private-host-continuity-v1","reader_pid":std::process::id(),"host_netns_inode":netns,"begin_monotonic_ns":begin,"end_monotonic_ns":end,"object_pins":pins,"socket_inode":socket_inode,"queue_overflow":0,"truncated":false})).map_err(io::Error::other)?);
    if leaves.len() > 256
        || leaves
            .values()
            .try_fold(0usize, |total, bytes| total.checked_add(bytes.len()))
            .is_none_or(|total| total > SOURCE_BOUND)
    {
        return Err(io::Error::other("host source carrier bound exceeded"));
    }
    Ok(leaves)
}
