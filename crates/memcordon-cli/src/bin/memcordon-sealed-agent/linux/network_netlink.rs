//! Bounded, sequence-checked NETLINK_ROUTE transport for private-netns setup.
//! A dump is not trusted until its explicit, uninterrupted NLMSG_DONE arrives.

use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const HEADER_LENGTH: usize = 16;
const MAX_PACKET: usize = 8192;
const MAX_MESSAGES: usize = 64;
const MAX_DATAGRAMS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DumpKind {
    Links,
    Addresses,
    Routes,
}

impl DumpKind {
    const fn request_type(self) -> u16 {
        match self {
            Self::Links => libc::RTM_GETLINK,
            Self::Addresses => libc::RTM_GETADDR,
            Self::Routes => libc::RTM_GETROUTE,
        }
    }

    const fn response_type(self) -> u16 {
        match self {
            Self::Links => libc::RTM_NEWLINK,
            Self::Addresses => libc::RTM_NEWADDR,
            Self::Routes => libc::RTM_NEWROUTE,
        }
    }

    const fn request_body_length(self) -> usize {
        match self {
            Self::Links => 16,
            Self::Addresses => 8,
            Self::Routes => 12,
        }
    }

    const fn max_objects(self) -> usize {
        match self {
            Self::Links => 8,
            Self::Addresses => 16,
            Self::Routes => 32,
        }
    }
}

#[derive(Debug)]
pub struct RouteNetlink {
    fd: OwnedFd,
    port_id: u32,
    sequence: u32,
}

impl RouteNetlink {
    pub fn open() -> Result<Self, String> {
        // SAFETY: socket receives fixed native address-family/type/protocol scalars.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(native_error("NETLINK_ROUTE socket"));
        }
        // SAFETY: successful socket returned a new owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: zero is the documented default for all sockaddr_nl fields.
        let mut local: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        local.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: local points to a live sockaddr_nl with its exact size.
        if unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const local).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        } < 0
        {
            return Err(native_error("NETLINK_ROUTE bind"));
        }
        // SAFETY: getsockname writes the bound local netlink address into live storage.
        let mut bound: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut bound_length = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        if unsafe {
            libc::getsockname(
                fd.as_raw_fd(),
                (&raw mut bound).cast(),
                &raw mut bound_length,
            )
        } < 0
            || bound_length != size_of::<libc::sockaddr_nl>() as libc::socklen_t
            || bound.nl_family != libc::AF_NETLINK as u16
            || bound.nl_pid == 0
            || bound.nl_groups != 0
        {
            return Err("MCSEALED-PRIVATE-NETLINK: local port identity absent".into());
        }
        let timeout = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        // SAFETY: timeout is a live timeval and its length is exact.
        if unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const timeout).cast(),
                size_of::<libc::timeval>() as libc::socklen_t,
            )
        } < 0
        {
            return Err(native_error("NETLINK_ROUTE receive timeout"));
        }
        Ok(Self {
            fd,
            port_id: bound.nl_pid,
            sequence: 0,
        })
    }

    pub fn dump(&mut self, kind: DumpKind) -> Result<Vec<Vec<u8>>, String> {
        let sequence = self.next_sequence()?;
        let mut request = header(
            HEADER_LENGTH + kind.request_body_length(),
            kind.request_type(),
            (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16,
            sequence,
        )?;
        request.resize(HEADER_LENGTH + kind.request_body_length(), 0);
        self.send(&request)?;
        let mut result = Vec::new();
        for _ in 0..MAX_DATAGRAMS {
            let packet = self.receive()?;
            let messages = parse_datagram(&packet, sequence, self.port_id)?;
            for (position, message) in messages.iter().enumerate() {
                match message.kind {
                    kind_code if kind_code == libc::NLMSG_DONE as u16 => {
                        if position + 1 != messages.len() {
                            return Err(
                                "MCSEALED-PRIVATE-NETLINK: data after dump completion".into()
                            );
                        }
                        if message.payload.len() < size_of::<i32>()
                            || i32::from_ne_bytes(
                                message.payload[..4].try_into().expect("checked length"),
                            ) != 0
                        {
                            return Err(
                                "MCSEALED-PRIVATE-NETLINK: dump terminated with error".into()
                            );
                        }
                        return Ok(result);
                    }
                    kind_code if kind_code == libc::NLMSG_ERROR as u16 => {
                        return Err(netlink_error(message.payload));
                    }
                    kind_code if kind_code == kind.response_type() => {
                        if message.flags & libc::NLM_F_MULTI as u16 == 0 {
                            return Err(
                                "MCSEALED-PRIVATE-NETLINK: non-multipart dump object".into()
                            );
                        }
                        if result.len() >= kind.max_objects() {
                            return Err("MCSEALED-PRIVATE-NETLINK: topology bound exceeded".into());
                        }
                        result.push(message.payload.to_vec());
                    }
                    _ => {
                        return Err("MCSEALED-PRIVATE-NETLINK: unexpected dump object".into());
                    }
                }
            }
        }
        Err("MCSEALED-PRIVATE-NETLINK: incomplete dump".into())
    }

    pub fn set_loopback_up(&mut self, interface_index: i32) -> Result<(), String> {
        if interface_index <= 0 {
            return Err("MCSEALED-PRIVATE-NETLINK: invalid loopback interface index".into());
        }
        let sequence = self.next_sequence()?;
        let mut request = header(
            HEADER_LENGTH + 16,
            libc::RTM_NEWLINK,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            sequence,
        )?;
        request.push(libc::AF_UNSPEC as u8);
        request.push(0);
        request.extend_from_slice(&libc::ARPHRD_LOOPBACK.to_ne_bytes());
        request.extend_from_slice(&interface_index.to_ne_bytes());
        request.extend_from_slice(&(libc::IFF_UP as u32).to_ne_bytes());
        request.extend_from_slice(&(libc::IFF_UP as u32).to_ne_bytes());
        self.send_ack(&request, sequence)
    }

    pub fn add_loopback_address(&mut self, interface_index: i32) -> Result<(), String> {
        let index = u32::try_from(interface_index)
            .map_err(|_| "MCSEALED-PRIVATE-NETLINK: invalid loopback interface index")?;
        if index == 0 {
            return Err("MCSEALED-PRIVATE-NETLINK: invalid loopback interface index".into());
        }
        let sequence = self.next_sequence()?;
        let mut request = header(
            HEADER_LENGTH + 8 + 16,
            libc::RTM_NEWADDR,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_EXCL) as u16,
            sequence,
        )?;
        request.extend_from_slice(&[libc::AF_INET as u8, 8, 0, libc::RT_SCOPE_HOST]);
        request.extend_from_slice(&index.to_ne_bytes());
        for attribute in [libc::IFA_ADDRESS, libc::IFA_LOCAL] {
            request.extend_from_slice(&(8_u16).to_ne_bytes());
            request.extend_from_slice(&attribute.to_ne_bytes());
            request.extend_from_slice(&[127, 0, 0, 1]);
        }
        self.send_ack(&request, sequence)
    }

    fn send_ack(&self, request: &[u8], sequence: u32) -> Result<(), String> {
        self.send(request)?;
        let packet = self.receive()?;
        let messages = parse_datagram(&packet, sequence, self.port_id)?;
        if messages.len() != 1 || messages[0].kind != libc::NLMSG_ERROR as u16 {
            return Err("MCSEALED-PRIVATE-NETLINK: missing exact mutation acknowledgment".into());
        }
        let payload = messages[0].payload;
        if payload.len() < size_of::<i32>() {
            return Err("MCSEALED-PRIVATE-NETLINK: short mutation acknowledgment".into());
        }
        let code = i32::from_ne_bytes(payload[..4].try_into().expect("checked length"));
        if code == 0 {
            return Ok(());
        }
        Err(format!(
            "MCSEALED-PRIVATE-NETLINK: mutation: {}",
            kernel_errno(code)
        ))
    }

    fn next_sequence(&mut self) -> Result<u32, String> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or("MCSEALED-PRIVATE-NETLINK: sequence exhausted")?;
        Ok(self.sequence)
    }

    fn send(&self, packet: &[u8]) -> Result<(), String> {
        // SAFETY: zeroed destination is kernel port ID zero; family is set below.
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: packet and kernel address remain live for the syscall.
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                0,
                (&raw const kernel).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent != packet.len() as isize {
            return Err(native_error("NETLINK_ROUTE send"));
        }
        Ok(())
    }

    fn receive(&self) -> Result<Vec<u8>, String> {
        let mut packet = [0_u8; MAX_PACKET];
        // SAFETY: zeroed source and message are initialized before recvmsg.
        let mut source: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: packet.as_mut_ptr().cast(),
            iov_len: packet.len(),
        };
        // SAFETY: all pointers refer to live stack storage for recvmsg.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_name = (&raw mut source).cast();
        message.msg_namelen = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        message.msg_iov = &raw mut iov;
        message.msg_iovlen = 1;
        // SAFETY: msg points to initialized writable buffers and bounded lengths.
        let received = unsafe { libc::recvmsg(self.fd.as_raw_fd(), &raw mut message, 0) };
        if received <= 0 {
            return Err(native_error("NETLINK_ROUTE receive"));
        }
        if message.msg_namelen != size_of::<libc::sockaddr_nl>() as libc::socklen_t
            || source.nl_family != libc::AF_NETLINK as u16
            || source.nl_pid != 0
            || source.nl_groups != 0
            || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        {
            return Err("MCSEALED-PRIVATE-NETLINK: sender or packet truncation mismatch".into());
        }
        Ok(packet[..received as usize].to_vec())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct NetlinkMessage<'a> {
    pub kind: u16,
    pub flags: u16,
    pub payload: &'a [u8],
}

pub fn parse_datagram(
    packet: &[u8],
    sequence: u32,
    recipient_port_id: u32,
) -> Result<Vec<NetlinkMessage<'_>>, String> {
    let mut offset = 0;
    let mut messages = Vec::new();
    while offset < packet.len() {
        let remaining = packet.len() - offset;
        if remaining < HEADER_LENGTH {
            return Err("MCSEALED-PRIVATE-NETLINK: short message header".into());
        }
        let bytes = &packet[offset..];
        let length = u32::from_ne_bytes(bytes[..4].try_into().expect("fixed header")) as usize;
        let aligned = length
            .checked_add(3)
            .map(|value| value & !3)
            .ok_or("MCSEALED-PRIVATE-NETLINK: message length overflow")?;
        if length < HEADER_LENGTH || length > remaining || aligned > remaining {
            return Err("MCSEALED-PRIVATE-NETLINK: invalid message length".into());
        }
        let kind = u16::from_ne_bytes(bytes[4..6].try_into().expect("fixed header"));
        let flags = u16::from_ne_bytes(bytes[6..8].try_into().expect("fixed header"));
        let observed_sequence = u32::from_ne_bytes(bytes[8..12].try_into().expect("fixed header"));
        let recipient = u32::from_ne_bytes(bytes[12..16].try_into().expect("fixed header"));
        if observed_sequence != sequence
            || recipient != recipient_port_id
            || flags & libc::NLM_F_DUMP_INTR as u16 != 0
        {
            return Err(
                "MCSEALED-PRIVATE-NETLINK: sequence, recipient, or dump integrity mismatch".into(),
            );
        }
        if messages.len() >= MAX_MESSAGES {
            return Err("MCSEALED-PRIVATE-NETLINK: message bound exceeded".into());
        }
        messages.push(NetlinkMessage {
            kind,
            flags,
            payload: &bytes[HEADER_LENGTH..length],
        });
        offset += aligned;
    }
    if messages.is_empty() {
        return Err("MCSEALED-PRIVATE-NETLINK: empty datagram".into());
    }
    Ok(messages)
}

fn header(length: usize, kind: u16, flags: u16, sequence: u32) -> Result<Vec<u8>, String> {
    let length =
        u32::try_from(length).map_err(|_| "MCSEALED-PRIVATE-NETLINK: request length overflow")?;
    let mut bytes = Vec::with_capacity(length as usize);
    bytes.extend_from_slice(&length.to_ne_bytes());
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(&flags.to_ne_bytes());
    bytes.extend_from_slice(&sequence.to_ne_bytes());
    bytes.extend_from_slice(&0_u32.to_ne_bytes());
    Ok(bytes)
}

fn netlink_error(payload: &[u8]) -> String {
    if payload.len() < size_of::<i32>() {
        return "MCSEALED-PRIVATE-NETLINK: short kernel error".into();
    }
    let code = i32::from_ne_bytes(payload[..4].try_into().expect("checked length"));
    format!(
        "MCSEALED-PRIVATE-NETLINK: kernel error: {}",
        kernel_errno(code)
    )
}

fn kernel_errno(code: i32) -> String {
    match code.checked_neg().filter(|value| *value > 0) {
        Some(errno) => std::io::Error::from_raw_os_error(errno).to_string(),
        None => "invalid kernel errno".into(),
    }
}

fn native_error(operation: &str) -> String {
    format!(
        "MCSEALED-PRIVATE-NETLINK: {operation}: {}",
        std::io::Error::last_os_error()
    )
}

/// A fresh network namespace must contain exactly one loopback link. Unknown
/// links are not ignored merely because the target's socket filter is narrow.
pub fn loopback_index(links: &[Vec<u8>], require_up: bool) -> Result<i32, String> {
    if links.len() != 1 {
        return Err("MCSEALED-PRIVATE-NETLINK: expected one loopback link".into());
    }
    let bytes = &links[0];
    if bytes.len() < 16 || bytes[0] != libc::AF_UNSPEC as u8 {
        return Err("MCSEALED-PRIVATE-NETLINK: invalid link header".into());
    }
    let kind = u16::from_ne_bytes(bytes[2..4].try_into().expect("checked length"));
    let index = i32::from_ne_bytes(bytes[4..8].try_into().expect("checked length"));
    let flags = u32::from_ne_bytes(bytes[8..12].try_into().expect("checked length"));
    if kind != libc::ARPHRD_LOOPBACK || index <= 0 || flags & libc::IFF_LOOPBACK as u32 == 0 {
        return Err("MCSEALED-PRIVATE-NETLINK: non-loopback link".into());
    }
    if require_up && flags & libc::IFF_UP as u32 == 0 {
        return Err("MCSEALED-PRIVATE-NETLINK: loopback not up".into());
    }
    let mut name_found = false;
    for (kind, value) in attributes(&bytes[16..])? {
        if kind == libc::IFLA_IFNAME {
            if name_found || value != b"lo\0" {
                return Err("MCSEALED-PRIVATE-NETLINK: loopback name mismatch".into());
            }
            name_found = true;
        }
    }
    if !name_found {
        return Err("MCSEALED-PRIVATE-NETLINK: loopback name absent".into());
    }
    Ok(index)
}

/// Return whether the exact IPv4 loopback address is already present. Every
/// IPv6 address and every alternate IPv4 address fails the complete dump.
pub fn verify_loopback_addresses(addresses: &[Vec<u8>], index: i32) -> Result<bool, String> {
    if addresses.len() > 1 {
        return Err("MCSEALED-PRIVATE-NETLINK: unexpected address count".into());
    }
    let Some(bytes) = addresses.first() else {
        return Ok(false);
    };
    if bytes.len() < 8
        || bytes[0] != libc::AF_INET as u8
        || bytes[1] != 8
        || bytes[3] != libc::RT_SCOPE_HOST
        || u32::from_ne_bytes(bytes[4..8].try_into().expect("checked length")) != index as u32
    {
        return Err("MCSEALED-PRIVATE-NETLINK: nonlocal or IPv6 address".into());
    }
    let mut address_seen = false;
    let mut local_seen = false;
    for (kind, value) in attributes(&bytes[8..])? {
        if kind == libc::IFA_ADDRESS || kind == libc::IFA_LOCAL {
            if value != [127, 0, 0, 1] {
                return Err("MCSEALED-PRIVATE-NETLINK: unexpected loopback address".into());
            }
            let seen = if kind == libc::IFA_ADDRESS {
                &mut address_seen
            } else {
                &mut local_seen
            };
            if *seen {
                return Err("MCSEALED-PRIVATE-NETLINK: duplicate address attribute".into());
            }
            *seen = true;
        }
    }
    if !address_seen || !local_seen {
        return Err("MCSEALED-PRIVATE-NETLINK: incomplete loopback address".into());
    }
    Ok(true)
}

/// Verify that every route is within 127/8, attached to the sole loopback,
/// and has no gateway or alternate route table. An empty dump is insufficient.
pub fn verify_loopback_routes(routes: &[Vec<u8>], index: i32) -> Result<(), String> {
    if routes.is_empty() || routes.len() > DumpKind::Routes.max_objects() {
        return Err("MCSEALED-PRIVATE-NETLINK: incomplete route inventory".into());
    }
    let mut link_route_seen = false;
    for bytes in routes {
        if bytes.len() < 12 || bytes[0] != libc::AF_INET as u8 {
            return Err("MCSEALED-PRIVATE-NETLINK: non-IPv4 route".into());
        }
        let prefix = bytes[1];
        let table = bytes[4];
        let route_kind = bytes[7];
        if !(8..=32).contains(&prefix)
            || bytes[2] != 0
            || !matches!(table, libc::RT_TABLE_LOCAL | libc::RT_TABLE_MAIN)
            || !matches!(
                route_kind,
                libc::RTN_LOCAL | libc::RTN_BROADCAST | libc::RTN_UNICAST
            )
        {
            return Err("MCSEALED-PRIVATE-NETLINK: route scope mismatch".into());
        }
        let mut destination = None;
        let mut output = None;
        for (kind, value) in attributes(&bytes[12..])? {
            match kind {
                libc::RTA_DST => {
                    if destination.replace(value).is_some() {
                        return Err("MCSEALED-PRIVATE-NETLINK: duplicate destination".into());
                    }
                }
                libc::RTA_OIF => {
                    if value.len() != 4
                        || output
                            .replace(u32::from_ne_bytes(
                                value.try_into().expect("checked length"),
                            ))
                            .is_some()
                    {
                        return Err("MCSEALED-PRIVATE-NETLINK: invalid output interface".into());
                    }
                }
                libc::RTA_PREFSRC => {
                    if value != [127, 0, 0, 1] {
                        return Err("MCSEALED-PRIVATE-NETLINK: nonlocal preferred source".into());
                    }
                }
                libc::RTA_TABLE => {
                    if value.len() != 4
                        || u32::from_ne_bytes(value.try_into().expect("checked length"))
                            != table as u32
                    {
                        return Err("MCSEALED-PRIVATE-NETLINK: route table mismatch".into());
                    }
                }
                libc::RTA_PRIORITY | libc::RTA_CACHEINFO => {}
                _ => return Err("MCSEALED-PRIVATE-NETLINK: unreviewed route attribute".into()),
            }
        }
        let Some(destination) = destination else {
            return Err("MCSEALED-PRIVATE-NETLINK: route destination absent".into());
        };
        if destination.len() != 4 || destination[0] != 127 || output != Some(index as u32) {
            return Err("MCSEALED-PRIVATE-NETLINK: route escapes loopback".into());
        }
        if prefix == 8 && destination == [127, 0, 0, 0] && route_kind == libc::RTN_UNICAST {
            link_route_seen = true;
        }
    }
    if !link_route_seen {
        return Err("MCSEALED-PRIVATE-NETLINK: 127/8 link route absent".into());
    }
    Ok(())
}

fn attributes(bytes: &[u8]) -> Result<Vec<(u16, &[u8])>, String> {
    let mut offset = 0;
    let mut parsed = Vec::new();
    while offset < bytes.len() {
        if bytes.len() - offset < 4 {
            return Err("MCSEALED-PRIVATE-NETLINK: short attribute header".into());
        }
        let record = &bytes[offset..];
        let length = u16::from_ne_bytes(record[..2].try_into().expect("fixed header")) as usize;
        let kind = u16::from_ne_bytes(record[2..4].try_into().expect("fixed header")) & 0x3fff;
        let aligned = length
            .checked_add(3)
            .map(|value| value & !3)
            .ok_or("MCSEALED-PRIVATE-NETLINK: attribute length overflow")?;
        if length < 4 || aligned > record.len() || parsed.len() >= 64 {
            return Err("MCSEALED-PRIVATE-NETLINK: invalid attribute length or count".into());
        }
        parsed.push((kind, &record[4..length]));
        offset += aligned;
    }
    Ok(parsed)
}
