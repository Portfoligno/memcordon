//! Fixture START permission on the sole controller-owned stdin stream.
//! A valid frame supplements, never replaces, the controller's native admission.
use std::io::{self, Read, Write};

pub const VERSION: u32 = 1;
const MAGIC: &[u8; 8] = b"MCSTART\0";
const HEADER: usize = 8 + 4 + 4 + 32 + 4 + 8;
pub const MAX_CHALLENGE: usize = 4096;

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
    binding.validate()?;
    let mut bytes = Vec::with_capacity(HEADER + binding.challenge.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    bytes.extend_from_slice(&(binding.challenge.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&binding.descriptor_sha256);
    bytes.extend_from_slice(&binding.pid.to_le_bytes());
    bytes.extend_from_slice(&binding.birth.to_le_bytes());
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
pub struct Receiver {
    attempted: bool,
}

impl Receiver {
    pub fn receive(
        &mut self,
        reader: &mut impl Read,
        binding: &Binding,
        mut check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        if std::mem::replace(&mut self.attempted, true) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "START release already attempted",
            ));
        }
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
        check()
    }
}
