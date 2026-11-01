//! Fixture START permission on the sole controller-owned stdin stream.
//! A valid frame supplements, never replaces, the controller's native admission.
use std::io::{self, Read, Write};

pub const VERSION: u32 = 2;
const MAGIC: &[u8; 8] = b"MCSTART\0";
const HEADER: usize = 8 + 4 + 4 + 32 + 4 + 8 + 4;
pub const MAX_CHALLENGE: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Start = 1,
    ToolchainObserverRelease = 2,
}

struct Progress {
    expected: Option<Phase>,
    joint: bool,
    failed: bool,
}
impl Default for Progress {
    fn default() -> Self {
        Self {
            expected: Some(Phase::Start),
            joint: false,
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
    binding.validate()?;
    let mut bytes = Vec::with_capacity(HEADER + binding.challenge.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    bytes.extend_from_slice(&(binding.challenge.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&binding.descriptor_sha256);
    bytes.extend_from_slice(&binding.pid.to_le_bytes());
    bytes.extend_from_slice(&binding.birth.to_le_bytes());
    bytes.extend_from_slice(&(phase as u32).to_le_bytes());
    bytes.extend_from_slice(&binding.challenge);
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
}
impl Sender {
    pub fn joint() -> Self {
        Self {
            progress: Progress::joint(),
        }
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
        match phase {
            Phase::Start => send(writer, binding, check)?,
            Phase::ToolchainObserverRelease => send_phase(writer, binding, phase, check)?,
        }
        self.progress.complete(phase);
        Ok(())
    }
}
#[derive(Default)]
pub struct Receiver {
    progress: Progress,
}

impl Receiver {
    pub fn joint() -> Self {
        Self {
            progress: Progress::joint(),
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
        mut check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.progress.begin(phase)?;
        binding.validate()?;
        let mut header = [0_u8; HEADER];
        transfer(
            |part| reader.read(part),
            &mut header,
            &mut check,
            io::ErrorKind::UnexpectedEof,
        )?;
        let mut expected = Vec::with_capacity(HEADER);
        expected.extend_from_slice(MAGIC);
        expected.extend_from_slice(&VERSION.to_le_bytes());
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
        self.progress.complete(phase);
        Ok(())
    }
}
