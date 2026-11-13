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
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    pub version: u32,
    pub handle: u64,
    pub manifest_sha256: [u8; 32],
}

pub const MAX_BROKER_REGISTRY_BYTES: usize = 32 * 1024;
pub const BROKER_REGISTRY_RIGHTS: u32 = 0x0002_0019; // KEY_READ

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerIdentity {
    pub pid: u32,
    pub birth: u64,
}

pub struct BrokerRegistryBinding {
    pub broker: BrokerIdentity,
    pub pair_sha256: [u8; 32],
    pub input_sha256: [u8; 32],
    pub descriptor_sha256: [u8; 32],
    pub manifest_sha256: [u8; 32],
    pub qpc_frequency: u64,
    pub cutoff_qpc: u64,
}

/// Fixture-only delivery to the original broker. The installed frame remains
/// a separate target-relative byte string, never a broker-owned capability.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerRegistryEnvelope {
    pub revision: u32,
    pub broker: BrokerIdentity,
    pub pair_sha256: [u8; 32],
    pub input_sha256: [u8; 32],
    pub descriptor_sha256: [u8; 32],
    pub manifest_sha256: [u8; 32],
    pub qpc_frequency: u64,
    pub cutoff_qpc: u64,
    pub registry: Capability,
    pub rights: u32,
    pub installed_start: Vec<u8>,
}
impl BrokerRegistryEnvelope {
    pub fn validate_binding(&self, expected: &BrokerRegistryBinding) -> io::Result<()> {
        let BrokerRegistryBinding {
            broker,
            pair_sha256: pair,
            input_sha256: input,
            descriptor_sha256: descriptor,
            manifest_sha256: manifest,
            qpc_frequency: frequency,
            cutoff_qpc: cutoff,
        } = *expected;
        if broker.pid == 0 || broker.birth == 0 {
            return Err(io::Error::other("broker identity unavailable"));
        }
        self.registry.validate()?;
        if self.revision != 1
            || self.broker != broker
            || self.pair_sha256 != pair
            || self.rights != BROKER_REGISTRY_RIGHTS
            || self.input_sha256 != input
            || self.descriptor_sha256 != descriptor
            || self.manifest_sha256 != manifest
            || self.registry.manifest_sha256 != manifest
            || frequency == 0
            || cutoff == 0
            || self.qpc_frequency != frequency
            || self.cutoff_qpc != cutoff
        {
            return Err(io::Error::other(
                "broker registry delivery differs from original binding",
            ));
        }
        Ok(())
    }
    pub fn validate_installed(&self, binding: &Binding) -> io::Result<()> {
        let mut source = io::Cursor::new(&self.installed_start);
        Receiver::with_registry(self.manifest_sha256, false).receive(
            &mut source,
            binding,
            || Ok(()),
        )?;
        if source.position() as usize != self.installed_start.len() {
            return Err(io::Error::other("broker installed START has trailing data"));
        }
        Ok(())
    }
    pub fn write(
        &self,
        target: &mut impl Write,
        mut live: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        live()?;
        let bytes = serde_json::to_vec(self).map_err(io::Error::other)?;
        if bytes.is_empty() || bytes.len() > MAX_BROKER_REGISTRY_BYTES {
            return Err(io::Error::other("broker registry envelope exceeds32KiB"));
        }
        target.write_all(&(bytes.len() as u32).to_le_bytes())?;
        target.write_all(&bytes)?;
        target.flush()?;
        live()
    }
    pub fn read(
        source: &mut impl Read,
        mut live: impl FnMut() -> io::Result<()>,
    ) -> io::Result<Self> {
        live()?;
        let mut length = [0; 4];
        source.read_exact(&mut length)?;
        let length = u32::from_le_bytes(length) as usize;
        if length == 0 || length > MAX_BROKER_REGISTRY_BYTES {
            return Err(io::Error::other("broker registry envelope exceeds32KiB"));
        }
        let mut bytes = vec![0; length];
        source.read_exact(&mut bytes)?;
        live()?;
        let mut extra = [0];
        if source.read(&mut extra)? != 0 {
            return Err(io::Error::other("broker registry envelope has extra data"));
        }
        live()?;
        let envelope: Self = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        let wire: serde_json::Value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        if wire != serde_json::to_value(&envelope).map_err(io::Error::other)? {
            return Err(io::Error::other(
                "broker registry envelope has missing fields",
            ));
        }
        Ok(envelope)
    }
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
    ProviderPreludeRelease = 4,
}

pub const MAX_PROVIDER_READY_BYTES: usize = 8 * 1024;
pub const MAX_PROVIDER_LANE_FRAME_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderControlScope {
    ListenerSelection,
}

pub struct ProviderReadyBinding {
    pub broker: BrokerIdentity,
    pub pair_sha256: [u8; 32],
    pub input_sha256: [u8; 32],
    pub direct_descriptor_sha256: [u8; 32],
    pub qpc_frequency: u64,
    pub cutoff_qpc: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDirectReady {
    pub revision: u32,
    pub scope: ProviderControlScope,
    pub broker: BrokerIdentity,
    pub direct: BrokerIdentity,
    pub pair_sha256: [u8; 32],
    pub input_sha256: [u8; 32],
    pub direct_descriptor_sha256: [u8; 32],
    pub selected_token_sha256: [u8; 32],
    pub original_process_reference: u64,
    pub qpc_frequency: u64,
    pub cutoff_qpc: u64,
}
impl std::fmt::Debug for ProviderDirectReady {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderDirectReady")
            .field("broker", &self.broker)
            .field("direct", &self.direct)
            .field("original_process_reference", &"private control capability")
            .finish_non_exhaustive()
    }
}
impl ProviderDirectReady {
    pub fn validate(&self, expected: &ProviderReadyBinding) -> io::Result<()> {
        if self.revision != 1
            || self.broker != expected.broker
            || self.broker.pid == 0
            || self.broker.birth == 0
            || self.direct.pid == 0
            || self.direct.birth < self.broker.birth
            || self.direct.pid == self.broker.pid
            || self.pair_sha256 != expected.pair_sha256
            || self.input_sha256 != expected.input_sha256
            || self.direct_descriptor_sha256 != expected.direct_descriptor_sha256
            || self.qpc_frequency == 0
            || self.qpc_frequency != expected.qpc_frequency
            || self.cutoff_qpc == 0
            || self.cutoff_qpc != expected.cutoff_qpc
            || !(1..=i64::MAX as u64).contains(&self.original_process_reference)
        {
            return Err(io::Error::other(
                "provider direct recipient differs from original broker/plan/clock",
            ));
        }
        Ok(())
    }
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self).map_err(io::Error::other)?;
        if bytes.len() > MAX_PROVIDER_READY_BYTES {
            return Err(io::Error::other("provider ready frame exceeds8KiB"));
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > MAX_PROVIDER_READY_BYTES {
            return Err(io::Error::other("provider ready frame exceeds8KiB"));
        }
        serde_json::from_slice(bytes).map_err(io::Error::other)
    }
    pub fn committed_bytes(&self) -> io::Result<Vec<u8>> {
        let payload = self.encode()?;
        let mut frame = Vec::with_capacity(payload.len() + 44);
        frame.extend_from_slice(
            &u32::try_from(payload.len())
                .map_err(io::Error::other)?
                .to_le_bytes(),
        );
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(&descriptor_digest(&payload));
        frame.extend_from_slice(b"RDPDONE1");
        Ok(frame)
    }
    /// Only an incomplete physical publication is pending. A complete malformed
    /// record is an error, and this codec never establishes native ownership.
    pub fn from_committed_prefix(bytes: &[u8]) -> io::Result<Option<Self>> {
        if bytes.len() > MAX_PROVIDER_READY_BYTES + 44 {
            return Err(io::Error::other(
                "provider Ready committed extent exceeds bound",
            ));
        }
        let Some(header) = bytes.get(..4) else {
            return Ok(None);
        };
        let length = u32::from_le_bytes(header.try_into().expect("four-byte header")) as usize;
        if length == 0 || length > MAX_PROVIDER_READY_BYTES {
            return Err(io::Error::other("provider Ready declared extent invalid"));
        }
        let extent = length + 44;
        if bytes.len() < extent {
            return Ok(None);
        }
        if bytes.len() != extent {
            return Err(io::Error::other(
                "provider Ready has trailing committed data",
            ));
        }
        let payload = &bytes[4..4 + length];
        if bytes[4 + length..4 + length + 32] != descriptor_digest(payload)
            || &bytes[extent - 8..] != b"RDPDONE1"
        {
            return Err(io::Error::other(
                "provider Ready complete publication hash/commit differs",
            ));
        }
        Self::decode(payload).map(Some)
    }
    #[cfg(windows)]
    #[allow(unsafe_code)] // Fixed private Ready receipt: owned rename and exact native file identity/readback only.
    pub fn publish(
        &self,
        path: &std::path::Path,
        mut live: impl FnMut() -> io::Result<()>,
    ) -> io::Result<std::fs::File> {
        use std::{
            fs::{File, OpenOptions},
            io::{Read, Seek, SeekFrom, Write},
            os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
        };
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle, MOVEFILE_WRITE_THROUGH,
            MoveFileExW,
        };
        let pending_path = path.with_extension("ready-pending");
        let wide = |path: &std::path::Path| -> io::Result<Vec<u16>> {
            let mut bytes: Vec<_> = path.as_os_str().encode_wide().collect();
            if !path.is_absolute() || bytes.len() > 32767 || bytes.contains(&0) {
                return Err(io::Error::other(
                    "Ready publication path is not bounded absolute UTF16",
                ));
            }
            bytes.push(0);
            Ok(bytes)
        };
        let source = wide(&pending_path)?;
        let destination = wide(path)?;
        let bytes = self.committed_bytes()?;
        let identity = |file: &File| -> io::Result<(u32, u64)> {
            let mut info = BY_HANDLE_FILE_INFORMATION::default();
            if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
                return Err(io::Error::last_os_error());
            }
            if info.dwFileAttributes & (0x400 | 0x10) != 0 || info.nNumberOfLinks != 1 {
                return Err(io::Error::other(
                    "Ready publication is not a single-link regular object",
                ));
            }
            Ok((
                info.dwVolumeSerialNumber,
                (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
            ))
        };
        live()?;
        let mut writer = Some(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .share_mode(1 | 4)
                .custom_flags(0x0020_0000)
                .open(&pending_path)?,
        );
        let mut anchor = None;
        let mut final_owner = None;
        let result = (|| {
            let original = writer.as_mut().expect("original Ready create owner");
            original.write_all(&bytes)?;
            original.sync_all()?;
            live()?;
            let expected = identity(original)?;
            // No replacement flag: existing final objects are never removed.
            if unsafe {
                MoveFileExW(
                    source.as_ptr(),
                    destination.as_ptr(),
                    MOVEFILE_WRITE_THROUGH,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            live()?;
            anchor = Some(
                OpenOptions::new()
                    .read(true)
                    .share_mode(1 | 2)
                    .custom_flags(0x0020_0000)
                    .open(path)?,
            );
            if identity(original)? != expected
                || identity(anchor.as_ref().expect("named Ready anchor"))? != expected
            {
                return Err(io::Error::other("Ready rename native identity differs"));
            }
            drop(writer.take());
            // The intermediate read owner forbids deletion while relinquishing
            // the writer; final custody also refuses every subsequent writer.
            final_owner = Some(
                OpenOptions::new()
                    .read(true)
                    .share_mode(1)
                    .custom_flags(0x0020_0000)
                    .open(path)?,
            );
            let held = final_owner.as_mut().expect("final Ready owner");
            if identity(held)? != expected {
                return Err(io::Error::other("Ready final native identity differs"));
            }
            held.seek(SeekFrom::Start(0))?;
            let mut observed = Vec::new();
            (&mut *held)
                .take((MAX_PROVIDER_READY_BYTES + 45) as u64)
                .read_to_end(&mut observed)?;
            if observed != bytes || Self::from_committed_prefix(&observed)?.is_none() {
                return Err(io::Error::other(
                    "Ready final exact committed readback differs",
                ));
            }
            live()?;
            Ok(final_owner.take().expect("final Ready owner"))
        })();
        result.map_err(|primary| {
            let owners = [writer.take(), anchor.take(), final_owner.take()]
                .into_iter()
                .flatten()
                .collect();
            io::Error::new(
                primary.kind(),
                ReadyPublicationFailure {
                    primary,
                    _owners: owners,
                },
            )
        })
    }
}

#[cfg(windows)]
pub struct ReadyPublicationFailure {
    primary: io::Error,
    _owners: Vec<std::fs::File>,
}
#[cfg(windows)]
impl ReadyPublicationFailure {
    pub fn native_error(&self) -> &io::Error {
        &self.primary
    }
}
#[cfg(windows)]
impl std::fmt::Display for ReadyPublicationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.primary.fmt(f)
    }
}
#[cfg(windows)]
impl std::fmt::Debug for ReadyPublicationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadyPublicationFailure")
            .field("primary", &self.primary)
            .finish_non_exhaustive()
    }
}
#[cfg(windows)]
impl std::error::Error for ReadyPublicationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.native_error())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderPairBinding {
    pub broker: BrokerIdentity,
    pub direct: BrokerIdentity,
    pub installed: BrokerIdentity,
    pub pair_sha256: [u8; 32],
    pub input_sha256: [u8; 32],
    pub direct_descriptor_sha256: [u8; 32],
    pub installed_descriptor_sha256: [u8; 32],
    pub qpc_frequency: u64,
    pub cutoff_qpc: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderLanePhase {
    DirectAdmitted,
    StartInstalled,
    ReleaseOriginal,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderLaneFrame {
    pub revision: u32,
    pub scope: ProviderControlScope,
    pub binding: ProviderPairBinding,
    pub phase: ProviderLanePhase,
    pub direct_frame: Vec<u8>,
    pub installed_frame: Vec<u8>,
}
impl std::fmt::Debug for ProviderLaneFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderLaneFrame")
            .field("phase", &self.phase)
            .field("binding", &self.binding)
            .field("direct_frame_bytes", &self.direct_frame.len())
            .field("installed_frame_bytes", &self.installed_frame.len())
            .finish()
    }
}
impl ProviderLaneFrame {
    pub fn validate(
        &self,
        expected: &ProviderPairBinding,
        phase: ProviderLanePhase,
    ) -> io::Result<()> {
        if self.revision != 1
            || self.binding != *expected
            || self.phase != phase
            || expected.qpc_frequency == 0
            || expected.cutoff_qpc == 0
            || [expected.broker, expected.direct, expected.installed]
                .iter()
                .any(|identity| identity.pid == 0 || identity.birth == 0)
            || expected.broker.pid == expected.direct.pid
            || expected.broker.pid == expected.installed.pid
            || expected.direct.pid == expected.installed.pid
            || self.direct_frame.len() > MAX_FRAME_BYTES
            || self.installed_frame.len() > MAX_FRAME_BYTES
            || match phase {
                ProviderLanePhase::DirectAdmitted => {
                    self.direct_frame.is_empty() || !self.installed_frame.is_empty()
                }
                ProviderLanePhase::StartInstalled => {
                    !self.direct_frame.is_empty() || self.installed_frame.is_empty()
                }
                ProviderLanePhase::ReleaseOriginal => {
                    self.direct_frame.is_empty() || self.installed_frame.is_empty()
                }
            }
        {
            return Err(io::Error::other(
                "provider lane frame owner/phase/extent differs",
            ));
        }
        Ok(())
    }
    pub fn write(
        &self,
        writer: &mut impl Write,
        mut live: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        live()?;
        let bytes = serde_json::to_vec(self).map_err(io::Error::other)?;
        if bytes.len() > MAX_PROVIDER_LANE_FRAME_BYTES {
            return Err(io::Error::other("provider lane frame exceeds64KiB"));
        }
        writer.write_all(&(bytes.len() as u32).to_le_bytes())?;
        writer.write_all(&bytes)?;
        writer.flush()?;
        live()
    }
    pub fn read(
        reader: &mut impl Read,
        mut live: impl FnMut() -> io::Result<()>,
    ) -> io::Result<Self> {
        live()?;
        let mut length = [0; 4];
        reader.read_exact(&mut length)?;
        let length = u32::from_le_bytes(length) as usize;
        if length == 0 || length > MAX_PROVIDER_LANE_FRAME_BYTES {
            return Err(io::Error::other("provider lane frame exceeds64KiB"));
        }
        let mut bytes = vec![0; length];
        reader.read_exact(&mut bytes)?;
        live()?;
        serde_json::from_slice(&bytes).map_err(io::Error::other)
    }
}

pub struct ProviderLaneReceiver {
    binding: ProviderPairBinding,
    phase: Option<ProviderLanePhase>,
    failed: bool,
    direct: Receiver,
    installed: Receiver,
    direct_binding: Binding,
    installed_binding: Binding,
}
impl ProviderLaneReceiver {
    pub fn new(
        binding: ProviderPairBinding,
        manifest: [u8; 32],
        direct_expected: DirectoryExpectation,
        installed_expected: DirectoryExpectation,
        challenge: Vec<u8>,
    ) -> io::Result<Self> {
        let direct_binding = Binding {
            challenge: challenge.clone(),
            descriptor_sha256: binding.direct_descriptor_sha256,
            pid: binding.direct.pid,
            birth: binding.direct.birth,
        };
        let installed_binding = Binding {
            challenge,
            descriptor_sha256: binding.installed_descriptor_sha256,
            pid: binding.installed.pid,
            birth: binding.installed.birth,
        };
        Ok(Self {
            binding,
            phase: Some(ProviderLanePhase::DirectAdmitted),
            failed: false,
            direct: Receiver::provider_root(manifest, direct_expected)?,
            installed: Receiver::provider_root(manifest, installed_expected)?,
            direct_binding,
            installed_binding,
        })
    }
    pub fn accept(
        &mut self,
        frame: &ProviderLaneFrame,
        mut live: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other("provider lane exchange already failed"));
        }
        self.failed = true;
        let phase = self
            .phase
            .take()
            .ok_or_else(|| io::Error::other("provider lane exchange repeated or already failed"))?;
        frame.validate(&self.binding, phase)?;
        let receive = |receiver: &mut Receiver,
                       bytes: &[u8],
                       binding: &Binding,
                       phase,
                       live: &mut dyn FnMut() -> io::Result<()>|
         -> io::Result<()> {
            let mut source = io::Cursor::new(bytes);
            receiver.receive_phase(&mut source, binding, phase, live)?;
            if source.position() as usize != bytes.len() {
                return Err(io::Error::other(
                    "provider lane embedded frame has trailing bytes",
                ));
            }
            Ok(())
        };
        match phase {
            ProviderLanePhase::DirectAdmitted => {
                receive(
                    &mut self.direct,
                    &frame.direct_frame,
                    &self.direct_binding,
                    Phase::Start,
                    &mut live,
                )?;
                self.phase = Some(ProviderLanePhase::StartInstalled);
            }
            ProviderLanePhase::StartInstalled => {
                receive(
                    &mut self.installed,
                    &frame.installed_frame,
                    &self.installed_binding,
                    Phase::Start,
                    &mut live,
                )?;
                self.phase = Some(ProviderLanePhase::ReleaseOriginal);
            }
            ProviderLanePhase::ReleaseOriginal => {
                receive(
                    &mut self.direct,
                    &frame.direct_frame,
                    &self.direct_binding,
                    Phase::ProviderPreludeRelease,
                    &mut live,
                )?;
                receive(
                    &mut self.installed,
                    &frame.installed_frame,
                    &self.installed_binding,
                    Phase::ProviderPreludeRelease,
                    &mut live,
                )?;
            }
        }
        live()?;
        self.failed = false;
        Ok(())
    }
    pub fn completed(&self) -> bool {
        !self.failed
            && self.phase.is_none()
            && !self.direct.progress.failed
            && !self.installed.progress.failed
            && self.direct.progress.expected.is_none()
            && self.installed.progress.expected.is_none()
    }
}

struct Progress {
    expected: Option<Phase>,
    joint: bool,
    private_peer: bool,
    provider_root: bool,
    failed: bool,
}
impl Default for Progress {
    fn default() -> Self {
        Self {
            expected: Some(Phase::Start),
            joint: false,
            private_peer: false,
            provider_root: false,
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
        self.expected = if self.provider_root && phase == Phase::Start {
            Some(Phase::ProviderPreludeRelease)
        } else if self.joint && phase == Phase::Start {
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
    pub fn provider_root(mut self) -> io::Result<Self> {
        if self.registry.is_none()
            || self.directories.is_none()
            || self.progress.expected != Some(Phase::Start)
            || self.progress.failed
            || self.progress.joint
        {
            return Err(io::Error::other(
                "provider root requires initial metadata-only START",
            ));
        }
        self.progress.provider_root = true;
        Ok(self)
    }
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
    pub fn provider_root(registry: [u8; 32], expected: DirectoryExpectation) -> io::Result<Self> {
        let mut receiver = Self::with_directories(registry, expected, false)?;
        receiver.progress.provider_root = true;
        Ok(receiver)
    }
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
