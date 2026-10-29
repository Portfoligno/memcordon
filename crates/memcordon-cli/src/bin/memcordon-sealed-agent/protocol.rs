use std::io::{self, Read, Write};

use sha2::{Digest, Sha256};

pub const PROTOCOL_VERSION: u16 = 3;
pub const WORKLOAD_PROTOCOL_VERSION: u16 = 5;
pub const MAX_FRAME_LENGTH: usize = 1024 * 1024;
const DIGEST_LENGTH: usize = 32;
const HEADER_LENGTH: usize = 2 + 2 + 4 + 16 + 16 + DIGEST_LENGTH;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum MessageKind {
    Probe = 1,
    Launch = 2,
    Cancel = 3,
    Query = 4,
    BrokerProbe = 5,
    BrokerLaunch = 6,
    BrokerAuthenticate = 7,
    WorkloadStart = 30,
    WorkloadBrokerStart = 31,
    WorkloadManifestChunk = 32,
    WorkloadMemberChunk = 33,
    WorkloadInputComplete = 34,
    WorkloadCancel = 35,
    WorkloadProgress = 36,
    WorkloadOutputInventory = 37,
    WorkloadOutputChunk = 38,
    WorkloadTerminal = 39,
    WorkloadRecover = 40,
    WorkloadRecovery = 41,
    WorkloadPrepared = 42,
    WorkloadBrokerRecover = 43,
    WorkloadRejected = 44,
    WorkloadAcknowledge = 45,
    WorkloadBrokerAcknowledge = 46,
    WorkloadAcknowledgment = 47,
    WorkloadPreparedAck = 48,
    ProbeReceipt = 101,
    LaunchPrepared = 102,
    Authorized = 103,
    Progress = 104,
    Terminal = 105,
    Rejected = 106,
    BrokerAuthenticated = 107,
}

impl TryFrom<u16> for MessageKind {
    type Error = ProtocolError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Probe),
            2 => Ok(Self::Launch),
            3 => Ok(Self::Cancel),
            4 => Ok(Self::Query),
            5 => Ok(Self::BrokerProbe),
            6 => Ok(Self::BrokerLaunch),
            7 => Ok(Self::BrokerAuthenticate),
            30 => Ok(Self::WorkloadStart),
            31 => Ok(Self::WorkloadBrokerStart),
            32 => Ok(Self::WorkloadManifestChunk),
            33 => Ok(Self::WorkloadMemberChunk),
            34 => Ok(Self::WorkloadInputComplete),
            35 => Ok(Self::WorkloadCancel),
            36 => Ok(Self::WorkloadProgress),
            37 => Ok(Self::WorkloadOutputInventory),
            38 => Ok(Self::WorkloadOutputChunk),
            39 => Ok(Self::WorkloadTerminal),
            40 => Ok(Self::WorkloadRecover),
            41 => Ok(Self::WorkloadRecovery),
            42 => Ok(Self::WorkloadPrepared),
            43 => Ok(Self::WorkloadBrokerRecover),
            45 => Ok(Self::WorkloadAcknowledge),
            46 => Ok(Self::WorkloadBrokerAcknowledge),
            47 => Ok(Self::WorkloadAcknowledgment),
            48 => Ok(Self::WorkloadPreparedAck),
            44 => Ok(Self::WorkloadRejected),
            101 => Ok(Self::ProbeReceipt),
            102 => Ok(Self::LaunchPrepared),
            103 => Ok(Self::Authorized),
            104 => Ok(Self::Progress),
            105 => Ok(Self::Terminal),
            106 => Ok(Self::Rejected),
            107 => Ok(Self::BrokerAuthenticated),
            _ => Err(ProtocolError::UnknownKind(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub kind: MessageKind,
    pub nonce: [u8; 16],
    pub attempt_id: [u8; 16],
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    Io(io::ErrorKind),
    UnsupportedVersion(u16),
    UnknownKind(u16),
    FrameTooLarge(usize),
    InvalidLength(usize),
    PayloadDigestMismatch,
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(kind) => write!(formatter, "protocol I/O failed: {kind:?}"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported protocol version {version}")
            }
            Self::UnknownKind(kind) => write!(formatter, "unknown message kind {kind}"),
            Self::FrameTooLarge(length) => write!(formatter, "frame length {length} exceeds limit"),
            Self::InvalidLength(length) => write!(formatter, "invalid frame length {length}"),
            Self::PayloadDigestMismatch => formatter.write_str("payload digest mismatch"),
        }
    }
}

impl std::error::Error for ProtocolError {}

pub fn read_frame(reader: &mut impl Read) -> Result<Frame, ProtocolError> {
    read_frame_version(reader, PROTOCOL_VERSION)
}

pub(crate) fn read_frame_version(
    reader: &mut impl Read,
    expected_version: u16,
) -> Result<Frame, ProtocolError> {
    let mut header = [0_u8; HEADER_LENGTH];
    reader
        .read_exact(&mut header)
        .map_err(|error| ProtocolError::Io(error.kind()))?;
    let version = u16::from_be_bytes([header[0], header[1]]);
    if version != expected_version {
        return Err(ProtocolError::UnsupportedVersion(version));
    }
    let kind = MessageKind::try_from(u16::from_be_bytes([header[2], header[3]]))?;
    if version != kind.protocol_version() {
        return Err(ProtocolError::UnsupportedVersion(version));
    }
    let total = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if total < HEADER_LENGTH {
        return Err(ProtocolError::InvalidLength(total));
    }
    if total > MAX_FRAME_LENGTH {
        return Err(ProtocolError::FrameTooLarge(total));
    }
    if matches!(
        kind,
        MessageKind::WorkloadManifestChunk
            | MessageKind::WorkloadMemberChunk
            | MessageKind::WorkloadOutputChunk
    ) && total > HEADER_LENGTH + memcordon_core::workload_bundle::STREAM_BYTES
    {
        return Err(ProtocolError::FrameTooLarge(total));
    }
    let mut nonce = [0_u8; 16];
    nonce.copy_from_slice(&header[8..24]);
    let mut attempt_id = [0_u8; 16];
    attempt_id.copy_from_slice(&header[24..40]);
    let expected_digest = &header[40..HEADER_LENGTH];
    let mut payload = vec![0_u8; total - HEADER_LENGTH];
    reader
        .read_exact(&mut payload)
        .map_err(|error| ProtocolError::Io(error.kind()))?;
    if Sha256::digest(&payload).as_slice() != expected_digest {
        return Err(ProtocolError::PayloadDigestMismatch);
    }
    Ok(Frame {
        kind,
        nonce,
        attempt_id,
        payload,
    })
}

pub fn write_frame(writer: &mut impl Write, frame: &Frame) -> Result<(), ProtocolError> {
    write_frame_version(writer, frame, frame.kind.protocol_version())
}

impl MessageKind {
    pub(crate) fn protocol_version(self) -> u16 {
        match self {
            Self::WorkloadStart
            | Self::WorkloadBrokerStart
            | Self::WorkloadManifestChunk
            | Self::WorkloadMemberChunk
            | Self::WorkloadInputComplete
            | Self::WorkloadCancel
            | Self::WorkloadProgress
            | Self::WorkloadOutputInventory
            | Self::WorkloadOutputChunk
            | Self::WorkloadTerminal
            | Self::WorkloadRecover
            | Self::WorkloadRecovery
            | Self::WorkloadPrepared
            | Self::WorkloadBrokerRecover
            | Self::WorkloadAcknowledge
            | Self::WorkloadBrokerAcknowledge
            | Self::WorkloadAcknowledgment
            | Self::WorkloadPreparedAck
            | Self::WorkloadRejected => WORKLOAD_PROTOCOL_VERSION,
            _ => PROTOCOL_VERSION,
        }
    }
}

fn write_frame_version(
    writer: &mut impl Write,
    frame: &Frame,
    version: u16,
) -> Result<(), ProtocolError> {
    let total = HEADER_LENGTH
        .checked_add(frame.payload.len())
        .ok_or(ProtocolError::FrameTooLarge(usize::MAX))?;
    if total > MAX_FRAME_LENGTH {
        return Err(ProtocolError::FrameTooLarge(total));
    }
    if matches!(
        frame.kind,
        MessageKind::WorkloadManifestChunk
            | MessageKind::WorkloadMemberChunk
            | MessageKind::WorkloadOutputChunk
    ) && frame.payload.len() > memcordon_core::workload_bundle::STREAM_BYTES
    {
        return Err(ProtocolError::FrameTooLarge(total));
    }
    let total = u32::try_from(total).map_err(|_| ProtocolError::FrameTooLarge(total))?;
    let payload_digest = Sha256::digest(&frame.payload);
    writer
        .write_all(&version.to_be_bytes())
        .and_then(|()| writer.write_all(&(frame.kind as u16).to_be_bytes()))
        .and_then(|()| writer.write_all(&total.to_be_bytes()))
        .and_then(|()| writer.write_all(&frame.nonce))
        .and_then(|()| writer.write_all(&frame.attempt_id))
        .and_then(|()| writer.write_all(&payload_digest))
        .and_then(|()| writer.write_all(&frame.payload))
        .map_err(|error| ProtocolError::Io(error.kind()))
}
