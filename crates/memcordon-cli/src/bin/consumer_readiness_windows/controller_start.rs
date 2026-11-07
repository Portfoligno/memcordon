//! Fixture START permission on the sole controller-owned stdin stream.
//! A valid frame supplements, never replaces, the controller's native admission.
pub use memcordon_platform::windows_private_fixture_binding::{
    DirectoryExpectation, DirectoryReference, DirectoryRole, DirectoryTransfer,
    MAX_DIRECTORY_REFERENCES,
};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

pub const VERSION: u32 = 2;
pub const REGISTRY_VERSION: u32 = 3;
pub const PRIVATE_VERSION: u32 = 4;
pub const PRIVATE_FILE_VERSION: u32 = 5;

pub fn private_start_version(expected: &DirectoryExpectation) -> u32 {
    if expected.local_role == DirectoryRole::LocalMarkerFile {
        PRIVATE_FILE_VERSION
    } else {
        PRIVATE_VERSION
    }
}
const MAGIC: &[u8; 8] = b"MCSTART\0";
const HEADER: usize = 8 + 4 + 4 + 32 + 4 + 8 + 4;
pub const MAX_CHALLENGE: usize = 4096;
const REGISTRY_EXTENT: usize = 4 + 8 + 32;
const DIRECTORY_HEADER: usize = 4 + 4 + 32;
const DIRECTORY_ENTRY: usize = 4 + 4 + 8 + 4;
pub const MAX_FRAME_BYTES: usize = HEADER
    + REGISTRY_EXTENT
    + DIRECTORY_HEADER
    + MAX_DIRECTORY_REFERENCES * DIRECTORY_ENTRY
    + MAX_CHALLENGE;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerRecipient {
    pub handle: u64,
    pub pid: u32,
    pub birth: u64,
}
impl PeerRecipient {
    pub fn validate(&self) -> io::Result<()> {
        if self.handle == 0 || self.handle > i64::MAX as u64 || self.pid == 0 || self.birth == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid pending peer recipient",
            ));
        }
        Ok(())
    }
    fn bytes(&self) -> [u8; 20] {
        let mut bytes = [0; 20];
        bytes[..8].copy_from_slice(&self.handle.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.pid.to_le_bytes());
        bytes[12..].copy_from_slice(&self.birth.to_le_bytes());
        bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerAdmissionBinding {
    pub root_pid: u32,
    pub root_birth: u64,
    pub descriptor_sha256: [u8; 32],
    pub challenge_sha256: [u8; 32],
}
impl PeerAdmissionBinding {
    pub fn from_start(binding: &Binding) -> Self {
        Self {
            root_pid: binding.pid,
            root_birth: binding.birth,
            descriptor_sha256: binding.descriptor_sha256,
            challenge_sha256: descriptor_digest(&binding.challenge),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerPendingAdmission {
    pub version: u32,
    pub binding: PeerAdmissionBinding,
    pub recipient: PeerRecipient,
}
impl PeerPendingAdmission {
    pub fn validate(&self, binding: &Binding) -> io::Result<()> {
        binding.validate()?;
        self.recipient.validate()?;
        if self.version != 1
            || self.binding != PeerAdmissionBinding::from_start(binding)
            || self.recipient.pid == binding.pid
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pending peer binding differs",
            ));
        }
        Ok(())
    }
}

/// A target-local, non-inheritable, read-only key handle supplied by the native
/// owner. The codec binds its scalar; native readback verifies the held key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capability {
    pub version: u32,
    pub handle: u64,
    pub manifest_sha256: [u8; 32],
}
impl Capability {
    fn validate(&self) -> io::Result<()> {
        if self.version != 1 || !(1..=i64::MAX as u64).contains(&self.handle) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid registry capability version/handle",
            ));
        }
        Ok(())
    }
    fn bytes(&self) -> [u8; REGISTRY_EXTENT] {
        let mut bytes = [0; REGISTRY_EXTENT];
        bytes[..4].copy_from_slice(&self.version.to_le_bytes());
        bytes[4..12].copy_from_slice(&self.handle.to_le_bytes());
        bytes[12..].copy_from_slice(&self.manifest_sha256);
        bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Start = 1,
    ToolchainObserverRelease = 2,
    PeerRecipientHeld = 3,
}

struct Progress {
    expected: Option<Phase>,
    joint: bool,
    private_peer: bool,
    failed: bool,
}
impl Default for Progress {
    fn default() -> Self {
        Self {
            expected: Some(Phase::Start),
            joint: false,
            private_peer: false,
            failed: false,
        }
    }
}
impl Progress {
    fn joint() -> Self {
        Self {
            joint: true,
            ..Self::default()
        }
    }
    fn begin(&mut self, phase: Phase) -> io::Result<()> {
        let allowed = !self.failed && self.expected == Some(phase);
        self.failed = true;
        if !allowed {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fixture control phase repeated, out of order, or already failed",
            ));
        }
        Ok(())
    }
    fn complete(&mut self, phase: Phase) {
        self.failed = false;
        self.expected = if self.joint && phase == Phase::Start {
            Some(if self.private_peer {
                Phase::PeerRecipientHeld
            } else {
                Phase::ToolchainObserverRelease
            })
        } else if self.private_peer && phase == Phase::PeerRecipientHeld {
            Some(Phase::ToolchainObserverRelease)
        } else {
            None
        };
    }
}

#[derive(Clone)]
pub struct Binding {
    pub challenge: Vec<u8>,
    pub descriptor_sha256: [u8; 32],
    pub pid: u32,
    pub birth: u64,
}

pub fn descriptor_digest(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}

impl Binding {
    fn validate(&self) -> io::Result<()> {
        if self.challenge.is_empty()
            || self.challenge.len() > MAX_CHALLENGE
            || self.pid == 0
            || self.birth == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid START binding extent or native identity",
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct InterruptedAtCutoff {
    original: io::Error,
    cutoff: io::Error,
}
impl std::fmt::Display for InterruptedAtCutoff {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; original START cutoff: {}",
            self.original, self.cutoff
        )
    }
}
impl std::error::Error for InterruptedAtCutoff {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

fn transfer(
    mut operation: impl FnMut(&mut [u8]) -> io::Result<usize>,
    bytes: &mut [u8],
    check: &mut impl FnMut() -> io::Result<()>,
    eof: io::ErrorKind,
) -> io::Result<()> {
    let mut remaining = bytes;
    while !remaining.is_empty() {
        check()?;
        match operation(remaining) {
            Ok(0) => {
                return Err(io::Error::new(
                    eof,
                    "START frame ended before its exact extent",
                ));
            }
            Ok(count) => remaining = &mut remaining[count..],
            Err(original) if original.kind() == io::ErrorKind::Interrupted => {
                if let Err(cutoff) = check() {
                    return Err(io::Error::new(
                        original.kind(),
                        InterruptedAtCutoff { original, cutoff },
                    ));
                }
                continue;
            }
            Err(error) => return Err(error),
        }
        check()?;
    }
    Ok(())
}

pub fn send(
    writer: &mut impl Write,
    binding: &Binding,
    mut check: impl FnMut() -> io::Result<()>,
) -> io::Result<()> {
    send_phase(writer, binding, Phase::Start, &mut check)
}
pub fn send_phase(
    writer: &mut impl Write,
    binding: &Binding,
    phase: Phase,
    mut check: impl FnMut() -> io::Result<()>,
) -> io::Result<()> {
    send_bound(writer, binding, phase, None, None, None, &mut check)
}

fn send_bound(
    writer: &mut impl Write,
    binding: &Binding,
    phase: Phase,
    registry: Option<&Capability>,
    directories: Option<&(DirectoryExpectation, DirectoryTransfer)>,
    peer: Option<&PeerRecipient>,
    mut check: impl FnMut() -> io::Result<()>,
) -> io::Result<()> {
    binding.validate()?;
    if let Some(input) = registry {
        input.validate()?;
    }
    if let Some((expected, transfer)) = directories {
        transfer.validate(expected).map_err(io::Error::other)?;
        if registry.is_none_or(|registry| {
            transfer
                .references
                .iter()
                .any(|entry| entry.handle == registry.handle)
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private transfer requires distinct registry ownership",
            ));
        }
    }
    if (phase == Phase::PeerRecipientHeld) != peer.is_some()
        || (peer.is_some() && directories.is_none())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "peer recipient ACK extent differs",
        ));
    }
    if let Some(peer) = peer {
        peer.validate()?;
    }
    let mut bytes = Vec::with_capacity(HEADER + binding.challenge.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(
        &if let Some((expected, _)) = directories {
            private_start_version(expected)
        } else if registry.is_some() {
            REGISTRY_VERSION
        } else {
            VERSION
        }
        .to_le_bytes(),
    );
    bytes.extend_from_slice(&(binding.challenge.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&binding.descriptor_sha256);
    bytes.extend_from_slice(&binding.pid.to_le_bytes());
    bytes.extend_from_slice(&binding.birth.to_le_bytes());
    bytes.extend_from_slice(&(phase as u32).to_le_bytes());
    if let Some(input) = registry {
        bytes.extend_from_slice(&input.bytes());
    }
    if let (Phase::Start, Some((_, transfer))) = (phase, directories) {
        bytes.extend_from_slice(&transfer.version.to_le_bytes());
        bytes.extend_from_slice(&(transfer.references.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&transfer.manifest_sha256);
        for reference in &transfer.references {
            bytes.extend_from_slice(&(reference.role as u32).to_le_bytes());
            bytes.extend_from_slice(&reference.index.to_le_bytes());
            bytes.extend_from_slice(&reference.handle.to_le_bytes());
            bytes.extend_from_slice(&reference.access_mask.to_le_bytes());
        }
    }
    if let Some(peer) = peer {
        bytes.extend_from_slice(&peer.bytes());
    }
    bytes.extend_from_slice(&binding.challenge);
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(io::Error::other(
            "START frame exceeds finite transfer bound",
        ));
    }
    transfer(
        |part| writer.write(part),
        &mut bytes,
        &mut check,
        io::ErrorKind::WriteZero,
    )?;
    check()?;
    writer.flush()?;
    check()
}

#[derive(Default)]
pub struct Sender {
    progress: Progress,
    registry: Option<Capability>,
    directories: Option<(DirectoryExpectation, DirectoryTransfer)>,
}
impl Sender {
    pub fn joint() -> Self {
        Self {
            progress: Progress::joint(),
            registry: None,
            directories: None,
        }
    }
    pub fn with_registry(registry: Capability, joint: bool) -> Self {
        Self {
            progress: if joint {
                Progress::joint()
            } else {
                Progress::default()
            },
            registry: Some(registry),
            directories: None,
        }
    }
    pub fn with_directories(
        mut self,
        transfer: DirectoryTransfer,
        expected: DirectoryExpectation,
    ) -> io::Result<Self> {
        transfer.validate(&expected).map_err(io::Error::other)?;
        if self.registry.is_none()
            || self.progress.failed
            || self.progress.expected != Some(Phase::Start)
        {
            return Err(io::Error::other(
                "private transfer requires initial registry START",
            ));
        }
        self.progress.private_peer = self.progress.joint;
        self.directories = Some((expected, transfer));
        Ok(self)
    }
    pub fn completed(&self) -> bool {
        self.progress.expected.is_none() && !self.progress.failed
    }
    pub fn send(
        &mut self,
        writer: &mut impl Write,
        binding: &Binding,
        phase: Phase,
        check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.progress.begin(phase)?;
        send_bound(
            writer,
            binding,
            phase,
            self.registry.as_ref(),
            self.directories.as_ref(),
            None,
            check,
        )?;
        self.progress.complete(phase);
        Ok(())
    }
    pub fn send_peer_held(
        &mut self,
        writer: &mut impl Write,
        binding: &Binding,
        peer: &PeerRecipient,
        check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.progress.begin(Phase::PeerRecipientHeld)?;
        send_bound(
            writer,
            binding,
            Phase::PeerRecipientHeld,
            self.registry.as_ref(),
            self.directories.as_ref(),
            Some(peer),
            check,
        )?;
        self.progress.complete(Phase::PeerRecipientHeld);
        Ok(())
    }
}
#[derive(Default)]
pub struct Receiver {
    progress: Progress,
    expected_registry: Option<[u8; 32]>,
    registry: Option<Capability>,
    expected_directories: Option<DirectoryExpectation>,
    directories: Option<DirectoryTransfer>,
}

impl Receiver {
    pub fn joint() -> Self {
        Self {
            progress: Progress::joint(),
            ..Self::default()
        }
    }
    pub fn with_registry(expected: [u8; 32], joint: bool) -> Self {
        Self {
            progress: if joint {
                Progress::joint()
            } else {
                Progress::default()
            },
            expected_registry: Some(expected),
            registry: None,
            expected_directories: None,
            directories: None,
        }
    }
    pub fn with_directories(
        registry: [u8; 32],
        expected: DirectoryExpectation,
        joint: bool,
    ) -> io::Result<Self> {
        expected.validate().map_err(io::Error::other)?;
        let mut receiver = Self::with_registry(registry, joint);
        receiver.progress.private_peer = joint;
        receiver.expected_directories = Some(expected);
        Ok(receiver)
    }
    pub fn directory_transfer(&self) -> Option<&DirectoryTransfer> {
        if self.progress.failed {
            None
        } else {
            self.directories.as_ref()
        }
    }
    pub fn registry_capability(&self) -> Option<&Capability> {
        if self.progress.failed {
            None
        } else {
            self.registry.as_ref()
        }
    }
    pub fn receive(
        &mut self,
        reader: &mut impl Read,
        binding: &Binding,
        mut check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.receive_phase(reader, binding, Phase::Start, &mut check)
    }
    pub fn receive_phase(
        &mut self,
        reader: &mut impl Read,
        binding: &Binding,
        phase: Phase,
        check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.receive_bound(reader, binding, phase, None, check)
    }
    pub fn receive_peer_held(
        &mut self,
        reader: &mut impl Read,
        binding: &Binding,
        peer: &PeerRecipient,
        check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.receive_bound(reader, binding, Phase::PeerRecipientHeld, Some(peer), check)
    }
    fn receive_bound(
        &mut self,
        reader: &mut impl Read,
        binding: &Binding,
        phase: Phase,
        peer: Option<&PeerRecipient>,
        mut check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.progress.begin(phase)?;
        binding.validate()?;
        if (phase == Phase::PeerRecipientHeld) != peer.is_some()
            || (peer.is_some() && self.expected_directories.is_none())
        {
            return Err(io::Error::other(
                "private peer admission phase is not bound",
            ));
        }
        if let Some(peer) = peer {
            peer.validate()?;
        }
        let mut header = [0_u8; HEADER];
        transfer(
            |part| reader.read(part),
            &mut header,
            &mut check,
            io::ErrorKind::UnexpectedEof,
        )?;
        let mut expected = Vec::with_capacity(HEADER);
        expected.extend_from_slice(MAGIC);
        expected.extend_from_slice(
            &if let Some(expected) = &self.expected_directories {
                private_start_version(expected)
            } else if self.expected_registry.is_some() {
                REGISTRY_VERSION
            } else {
                VERSION
            }
            .to_le_bytes(),
        );
        expected.extend_from_slice(&(binding.challenge.len() as u32).to_le_bytes());
        expected.extend_from_slice(&binding.descriptor_sha256);
        expected.extend_from_slice(&binding.pid.to_le_bytes());
        expected.extend_from_slice(&binding.birth.to_le_bytes());
        expected.extend_from_slice(&(phase as u32).to_le_bytes());
        if header != expected.as_slice() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "START version, extent, descriptor or native identity differs",
            ));
        }
        let registry = if let Some(expected) = self.expected_registry {
            let mut bytes = [0; REGISTRY_EXTENT];
            transfer(
                |part| reader.read(part),
                &mut bytes,
                &mut check,
                io::ErrorKind::UnexpectedEof,
            )?;
            let input = Capability {
                version: u32::from_le_bytes(
                    bytes[..4].try_into().expect("fixed capability version"),
                ),
                handle: u64::from_le_bytes(bytes[4..12].try_into().expect("fixed target handle")),
                manifest_sha256: bytes[12..].try_into().expect("fixed manifest digest"),
            };
            input.validate()?;
            if input.manifest_sha256 != expected
                || (phase != Phase::Start && self.registry != Some(input))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "registry dependency/session binding differs",
                ));
            }
            Some(input)
        } else {
            None
        };
        let directories = if phase == Phase::Start {
            if let Some(expected) = &self.expected_directories {
                let mut header = [0; DIRECTORY_HEADER];
                transfer(
                    |part| reader.read(part),
                    &mut header,
                    &mut check,
                    io::ErrorKind::UnexpectedEof,
                )?;
                let version =
                    u32::from_le_bytes(header[..4].try_into().expect("directory version"));
                let count =
                    u32::from_le_bytes(header[4..8].try_into().expect("directory count")) as usize;
                if count != expected.roles().map_err(io::Error::other)?.len()
                    || count > MAX_DIRECTORY_REFERENCES
                {
                    return Err(io::Error::other("private directory frame count differs"));
                }
                let mut body = vec![0; count * DIRECTORY_ENTRY];
                transfer(
                    |part| reader.read(part),
                    &mut body,
                    &mut check,
                    io::ErrorKind::UnexpectedEof,
                )?;
                let mut references = Vec::with_capacity(count);
                for bytes in body.chunks_exact(DIRECTORY_ENTRY) {
                    let role =
                        match u32::from_le_bytes(bytes[..4].try_into().expect("directory role")) {
                            1 => DirectoryRole::InputAncestor,
                            2 => DirectoryRole::LocalDirectory,
                            3 => DirectoryRole::OutputAncestor,
                            4 => DirectoryRole::LocalMarkerFile,
                            _ => return Err(io::Error::other("unknown directory reference role")),
                        };
                    references.push(DirectoryReference {
                        role,
                        index: u32::from_le_bytes(bytes[4..8].try_into().expect("directory index")),
                        handle: u64::from_le_bytes(
                            bytes[8..16].try_into().expect("directory handle"),
                        ),
                        access_mask: u32::from_le_bytes(
                            bytes[16..20].try_into().expect("directory access"),
                        ),
                    });
                }
                let directory_transfer = DirectoryTransfer {
                    version,
                    manifest_sha256: header[8..].try_into().expect("directory manifest"),
                    references,
                };
                directory_transfer
                    .validate(expected)
                    .map_err(io::Error::other)?;
                if registry.as_ref().is_none_or(|registry| {
                    directory_transfer
                        .references
                        .iter()
                        .any(|entry| entry.handle == registry.handle)
                }) {
                    return Err(io::Error::other(
                        "directory and registry scalar ownership overlaps",
                    ));
                }
                Some(directory_transfer)
            } else {
                None
            }
        } else {
            None
        };
        if let Some(peer) = peer {
            let mut actual = [0; 20];
            transfer(
                |part| reader.read(part),
                &mut actual,
                &mut check,
                io::ErrorKind::UnexpectedEof,
            )?;
            if actual != peer.bytes() {
                return Err(io::Error::other("held peer recipient echo differs"));
            }
        }
        let mut challenge = vec![0_u8; binding.challenge.len()];
        transfer(
            |part| reader.read(part),
            &mut challenge,
            &mut check,
            io::ErrorKind::UnexpectedEof,
        )?;
        if challenge != binding.challenge {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "START challenge differs",
            ));
        }
        check()?;
        self.registry = registry;
        if phase == Phase::Start {
            self.directories = directories;
        }
        self.progress.complete(phase);
        Ok(())
    }
}
