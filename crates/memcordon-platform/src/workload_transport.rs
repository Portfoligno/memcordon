//! Bounded byte transport for caller-owned workload input and output.
//!
//! These frames identify a connection and an attempt. They carry no native
//! authority and cannot reconstruct a prepared attempt after disconnection.
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};

pub const WORKLOAD_PROTOCOL_VERSION: u16 = 5;
pub const STREAM_CHUNK_BYTES: usize = 64 * 1024;
pub const MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
pub const INITIAL_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum WorkloadFrameKind {
    RequestStart = 30,
    ManifestChunk = 32,
    MemberChunk = 33,
    InputComplete = 34,
    Cancel = 35,
    Progress = 36,
    OutputInventory = 37,
    OutputChunk = 38,
    Terminal = 39,
    Recover = 40,
    Recovery = 41,
    Prepared = 42,
    Rejected = 44,
    Acknowledge = 45,
    Acknowledgment = 47,
    PreparedAck = 48,
}

impl TryFrom<u16> for WorkloadFrameKind {
    type Error = io::Error;
    fn try_from(value: u16) -> io::Result<Self> {
        match value {
            30 => Ok(Self::RequestStart),
            32 => Ok(Self::ManifestChunk),
            33 => Ok(Self::MemberChunk),
            34 => Ok(Self::InputComplete),
            35 => Ok(Self::Cancel),
            36 => Ok(Self::Progress),
            37 => Ok(Self::OutputInventory),
            38 => Ok(Self::OutputChunk),
            39 => Ok(Self::Terminal),
            40 => Ok(Self::Recover),
            41 => Ok(Self::Recovery),
            42 => Ok(Self::Prepared),
            44 => Ok(Self::Rejected),
            45 => Ok(Self::Acknowledge),
            47 => Ok(Self::Acknowledgment),
            48 => Ok(Self::PreparedAck),
            _ => Err(invalid("unknown workload frame kind")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkloadConnectionBinding {
    pub challenge: [u8; 16],
    pub attempt: [u8; 16],
}

#[derive(Debug, Eq, PartialEq)]
pub struct WorkloadFrame {
    pub kind: WorkloadFrameKind,
    pub binding: WorkloadConnectionBinding,
    pub payload: Vec<u8>,
}

impl WorkloadFrame {
    pub fn write(&self, output: &mut impl Write) -> io::Result<()> {
        let header_bytes =
            2 + 2 + 4 + self.binding.challenge.len() + self.binding.attempt.len() + 32;
        let payload_limit = if matches!(
            self.kind,
            WorkloadFrameKind::RequestStart
                | WorkloadFrameKind::Terminal
                | WorkloadFrameKind::Recovery
                | WorkloadFrameKind::OutputInventory
        ) {
            INITIAL_FRAME_BYTES - header_bytes
        } else {
            STREAM_CHUNK_BYTES
        };
        if self.payload.len() > payload_limit {
            return Err(invalid("workload frame exceeds streaming bound"));
        }
        let total = u32::try_from(header_bytes + self.payload.len())
            .map_err(|_| invalid("frame length overflow"))?;
        output.write_all(&WORKLOAD_PROTOCOL_VERSION.to_be_bytes())?;
        output.write_all(&(self.kind as u16).to_be_bytes())?;
        output.write_all(&total.to_be_bytes())?;
        output.write_all(&self.binding.challenge)?;
        output.write_all(&self.binding.attempt)?;
        output.write_all(&Sha256::digest(&self.payload))?;
        output.write_all(&self.payload)
    }

    pub fn read(input: &mut impl Read, expected: WorkloadConnectionBinding) -> io::Result<Self> {
        Self::read_inner(input, Some(expected))
    }

    /// Only the first response on an authenticated native connection may use
    /// this method. Validate the provider-assigned association before intake.
    pub fn read_initial(input: &mut impl Read) -> io::Result<Self> {
        Self::read_inner(input, None)
    }

    fn read_inner(
        input: &mut impl Read,
        expected: Option<WorkloadConnectionBinding>,
    ) -> io::Result<Self> {
        let mut word = [0; 2];
        input.read_exact(&mut word)?;
        if u16::from_be_bytes(word) != WORKLOAD_PROTOCOL_VERSION {
            return Err(invalid("incompatible workload protocol version"));
        }
        input.read_exact(&mut word)?;
        let kind = WorkloadFrameKind::try_from(u16::from_be_bytes(word))?;
        let mut total = [0; 4];
        input.read_exact(&mut total)?;
        let mut challenge = [0; 16];
        let mut attempt = [0; 16];
        input.read_exact(&mut challenge)?;
        input.read_exact(&mut attempt)?;
        let binding = WorkloadConnectionBinding { challenge, attempt };
        if expected.is_some_and(|expected| binding != expected) {
            return Err(invalid(
                "workload frame differs from authenticated connection",
            ));
        }
        let mut digest = [0; 32];
        input.read_exact(&mut digest)?;
        let header_bytes =
            word.len() + word.len() + total.len() + challenge.len() + attempt.len() + digest.len();
        let size = (u32::from_be_bytes(total) as usize)
            .checked_sub(header_bytes)
            .ok_or_else(|| invalid("frame smaller than header"))?;
        let payload_limit = if matches!(
            kind,
            WorkloadFrameKind::RequestStart
                | WorkloadFrameKind::Terminal
                | WorkloadFrameKind::Recovery
                | WorkloadFrameKind::OutputInventory
        ) {
            INITIAL_FRAME_BYTES - header_bytes
        } else {
            STREAM_CHUNK_BYTES
        };
        if size > payload_limit {
            return Err(invalid("workload frame exceeds streaming bound"));
        }
        let mut payload = vec![0; size];
        input.read_exact(&mut payload)?;
        if Sha256::digest(&payload).as_slice() != digest {
            return Err(invalid("workload frame digest differs"));
        }
        Ok(Self {
            kind,
            binding,
            payload,
        })
    }
}

/// Tracks one declared byte object. A duplicate, gap, overflow or incomplete
/// stream is rejected before bytes can be treated as a complete input object.
#[derive(Debug)]
pub struct OrderedByteStream {
    declared: u64,
    next: u64,
    poisoned: bool,
}

impl OrderedByteStream {
    pub fn new(declared: u64, maximum: u64) -> io::Result<Self> {
        if declared > maximum {
            return Err(invalid("declared byte object exceeds bound"));
        }
        Ok(Self {
            declared,
            next: 0,
            poisoned: false,
        })
    }

    pub fn append(
        &mut self,
        offset: u64,
        bytes: &[u8],
        destination: &mut impl Write,
    ) -> io::Result<()> {
        let next = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| invalid("byte stream length overflow"))?;
        if self.poisoned
            || offset != self.next
            || bytes.is_empty()
            || bytes.len() > STREAM_CHUNK_BYTES
            || next > self.declared
        {
            return Err(invalid("duplicate, gapped or excessive byte stream chunk"));
        }
        // On a partial write failure this object remains incomplete. The owner
        // must discard its staging object instead of retrying the same chunk.
        self.poisoned = true;
        destination.write_all(bytes)?;
        self.next = next;
        self.poisoned = false;
        Ok(())
    }

    pub fn finish(self) -> io::Result<()> {
        if self.poisoned || self.next != self.declared {
            return Err(invalid("truncated byte object"));
        }
        Ok(())
    }
}

fn invalid(detail: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, detail)
}
