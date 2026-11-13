//! Bounded streaming observations and exact byte operands, never native custody.
use serde_json::{Value, json};
use std::{collections::VecDeque, time::Instant};

const X64: u32 = 0xc000003e;
const ARM64: u32 = 0xc00000b7;
const PATH_BYTES: usize = 256;

#[derive(Debug, Eq, PartialEq)]
pub struct Rename {
    pub architecture: u32,
    pub number: u64,
    pub source_address: u64,
    pub target_address: u64,
    pub source_fd: i32,
    pub target_fd: i32,
    pub flags: u64,
}
fn arch(packet: &[u8], expected: u32) -> Result<u32, String> {
    if packet.len() < 24 || packet.len() > 128 {
        return Err("native syscall packet extent differs".into());
    }
    let actual = u32::from_ne_bytes(packet[4..8].try_into().unwrap());
    if ![X64, ARM64].contains(&expected) || actual != expected {
        return Err("native syscall architecture differs".into());
    }
    Ok(actual)
}
fn word(packet: &[u8], offset: usize) -> u64 {
    u64::from_ne_bytes(packet[offset..offset + 8].try_into().unwrap())
}
pub fn rename_entry(packet: &[u8], expected_arch: u32) -> Result<Option<Rename>, String> {
    let architecture = arch(packet, expected_arch)?;
    if packet[0] != 1 {
        return Ok(None);
    }
    if packet.len() < 80 {
        return Err("native syscall entry shortened".into());
    }
    let number = word(packet, 24);
    if !((architecture == X64 && [82, 264, 316].contains(&number))
        || (architecture == ARM64 && [38, 276].contains(&number)))
    {
        return Ok(None);
    }
    let argument = |index: usize| word(packet, 32 + index * 8);
    let (source_address, target_address, source_fd, target_fd) =
        if architecture == X64 && number == 82 {
            (argument(0), argument(1), -100, -100)
        } else {
            (
                argument(1),
                argument(3),
                argument(0) as u32 as i32,
                argument(2) as u32 as i32,
            )
        };
    Ok(Some(Rename {
        architecture,
        number,
        source_address,
        target_address,
        source_fd,
        target_fd,
        flags: if (architecture == X64 && number == 316) || (architecture == ARM64 && number == 276)
        {
            argument(4)
        } else {
            0
        },
    }))
}
pub fn successful_exit(packet: &[u8], expected_arch: u32) -> Result<i64, String> {
    arch(packet, expected_arch)?;
    if packet[0] != 2 || packet.len() < 33 || packet[32] != 0 {
        return Err("selected native syscall lacks successful exit".into());
    }
    let result = word(packet, 24) as i64;
    if result < 0 {
        return Err("selected native syscall returned failure".into());
    }
    Ok(result)
}

#[derive(Debug, Eq, PartialEq)]
pub enum Parent {
    Absolute(Vec<u8>),
    Descriptor(i32),
}
#[derive(Debug, Eq, PartialEq)]
pub struct Operand {
    pub leaf: Vec<u8>,
    pub parent: Parent,
}
#[derive(Debug, Eq, PartialEq)]
pub struct Candidate {
    pub source: Operand,
    pub target: Operand,
}
fn leaf(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && !bytes.contains(&0)
        && !bytes.contains(&b'/')
        && bytes != b"."
        && bytes != b".."
}
fn operand(bytes: &[u8], descriptor: i32) -> Result<Operand, String> {
    if bytes.is_empty() || bytes.len() > PATH_BYTES || bytes.contains(&0) {
        return Err("native pathname extent differs".into());
    }
    if bytes.starts_with(b"/") {
        let parts: Vec<_> = bytes[1..].split(|byte| *byte == b'/').collect();
        if parts.iter().any(|part| !leaf(part)) {
            return Err("absolute native pathname is not normalized".into());
        }
        let name = parts.last().unwrap();
        let parent_end = bytes.len() - name.len();
        let parent = if parent_end == 1 {
            b"/".to_vec()
        } else {
            bytes[..parent_end - 1].to_vec()
        };
        Ok(Operand {
            leaf: name.to_vec(),
            parent: Parent::Absolute(parent),
        })
    } else {
        if !leaf(bytes) || (descriptor < 0 && descriptor != -100) {
            return Err("relative native pathname is not a direct dirfd leaf".into());
        }
        Ok(Operand {
            leaf: bytes.to_vec(),
            parent: Parent::Descriptor(descriptor),
        })
    }
}
fn leaf_hint(bytes: &[u8]) -> Option<&[u8]> {
    bytes
        .rsplit(|byte| *byte == b'/')
        .find(|part| !part.is_empty())
}
pub fn select(
    source: &[u8],
    target: &[u8],
    selector: &[u8],
    final_leaf: &[u8],
    prefix: bool,
    source_fd: i32,
    target_fd: i32,
) -> Result<Option<Candidate>, String> {
    if !leaf(selector) || !leaf(final_leaf) {
        return Err("native transaction selector is not a direct nonempty leaf".into());
    }
    for bytes in [source, target] {
        if bytes.len() > PATH_BYTES || bytes.contains(&0) {
            return Err("native pathname extent differs".into());
        }
    }
    if source.is_empty() || target.is_empty() {
        return Ok(None);
    }
    // A lexical hint can only reject unrelated activity. It cannot accept a
    // path: every possible match still undergoes full operand validation and
    // the caller's native resolution of both actual parents.
    let source_hint = leaf_hint(source).unwrap_or_default();
    let matches = if prefix {
        source_hint.starts_with(selector) && source_hint.len() > selector.len()
    } else {
        source_hint == selector
    };
    if !matches || leaf_hint(target) != Some(final_leaf) {
        return Ok(None);
    }
    let source = operand(source, source_fd)?;
    let target = operand(target, target_fd)?;
    let matched = if prefix {
        source.leaf.starts_with(selector) && source.leaf.len() > selector.len()
    } else {
        source.leaf == selector
    };
    if !matched || target.leaf != final_leaf {
        return Ok(None);
    }
    Ok(Some(Candidate { source, target }))
}
pub fn require_parents(
    expected: (u64, u64),
    source: (u64, u64),
    target: (u64, u64),
) -> Result<(), String> {
    if source != expected || target != expected {
        Err("native rename uses another held transaction directory".into())
    } else {
        Ok(())
    }
}

#[derive(Default)]
pub struct TraceWindow {
    stops: u64,
    entries: u64,
    exits: u64,
    candidates: u64,
    rejections: u64,
    recent: VecDeque<Value>,
    last_rejection: Option<&'static str>,
    source: Vec<u8>,
    target: Vec<u8>,
}
impl TraceWindow {
    pub fn record(&mut self, packet: &[u8]) -> Result<(), String> {
        if packet.len() < 24 || packet.len() > 128 {
            return Err("native syscall diagnostic packet extent differs".into());
        }
        self.stops = self.stops.saturating_add(1);
        let operation = packet[0];
        if operation == 1 {
            self.entries = self.entries.saturating_add(1);
        }
        if operation == 2 {
            self.exits = self.exits.saturating_add(1);
        }
        let architecture = u32::from_ne_bytes(packet[4..8].try_into().unwrap());
        let scalar = (packet.len() >= 32).then(|| word(packet, 24));
        if self.recent.len() == 8 {
            self.recent.pop_front();
        }
        self.recent.push_back(
            json!({"operation":operation,"architecture":architecture,"number_or_return":scalar}),
        );
        Ok(())
    }
    pub fn candidate(&mut self) {
        self.candidates = self.candidates.saturating_add(1);
    }
    pub fn reject(&mut self, reason: &'static str) {
        self.rejections = self.rejections.saturating_add(1);
        self.last_rejection = Some(reason);
    }
    pub fn operands(&mut self, source: &[u8], target: &[u8]) {
        self.source = source[..source.len().min(PATH_BYTES)].to_vec();
        self.target = target[..target.len().min(PATH_BYTES)].to_vec();
    }
    pub fn check(&self, now: Instant, cutoff: Instant) -> Result<(), String> {
        if now >= cutoff {
            Err("original native trace cutoff exhausted".into())
        } else {
            Ok(())
        }
    }
    pub fn diagnostic(&self) -> Value {
        json!({"stops":self.stops,"entries":self.entries,"exits":self.exits,"candidates":self.candidates,"rejections":self.rejections,"recent":self.recent,"last_rejection":self.last_rejection,"last_source_bytes":self.source,"last_target_bytes":self.target})
    }
}
