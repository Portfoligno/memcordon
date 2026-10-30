//! Pure planning for one explicitly instrumented diagnostic replay. No OS calls.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io;
#[path = "fixture_namespace_helper_profile.rs"]
pub mod helper_profile;

pub const IMAGE_SHA256: &str = "96c0459f0d73d728e5c13a10d83d840f56913ef7281d17370a5e1eb197faa450";
pub const FILE_LEN: usize = 4_171_392;
pub const MACHINE: u16 = 0x8664;
pub const MAGIC: u16 = 0x20b;
pub const SIZE_OF_IMAGE: u32 = 0x003e_d000;
pub const OUTPUT_LIMIT: usize = 64 * 1024;
pub const EVENT_LIMIT: usize = 128;
pub const SINGLE_STEP: u32 = 0x8000_0004;

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}
fn extent(bytes: &[u8], start: usize, length: usize) -> io::Result<&[u8]> {
    bytes
        .get(
            start
                ..start
                    .checked_add(length)
                    .ok_or_else(|| invalid("extent overflow"))?,
        )
        .ok_or_else(|| invalid("truncated extent"))
}
fn word(bytes: &[u8], start: usize) -> io::Result<u16> {
    Ok(u16::from_le_bytes(
        extent(bytes, start, 2)?.try_into().unwrap(),
    ))
}
fn dword(bytes: &[u8], start: usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(
        extent(bytes, start, 4)?.try_into().unwrap(),
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Site {
    Entry,
    Native,
    Initialization,
    InitEnter,
    ProcessTokenReturn,
    ThreadTokenReturn,
    ClearThreadTokenReturn,
    DirectoryInitializationReturn,
    RestoreThreadTokenReturn,
    Helper { rva: u32, slot: usize },
}
impl Site {
    pub const ALL: [Self; 9] = [
        Self::Entry,
        Self::Native,
        Self::Initialization,
        Self::InitEnter,
        Self::ProcessTokenReturn,
        Self::ThreadTokenReturn,
        Self::ClearThreadTokenReturn,
        Self::DirectoryInitializationReturn,
        Self::RestoreThreadTokenReturn,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::Entry => "entry",
            Self::Native => "native",
            Self::Initialization => "initialization",
            Self::InitEnter => "initializer-enter",
            Self::ProcessTokenReturn => "process-token-return",
            Self::ThreadTokenReturn => "thread-token-return",
            Self::ClearThreadTokenReturn => "clear-thread-token-return",
            Self::DirectoryInitializationReturn => "directory-initialization-return",
            Self::RestoreThreadTokenReturn => "restore-thread-token-return",
            Self::Helper { .. } => "helper-checkpoint",
        }
    }
    pub fn rva(self) -> u32 {
        match self {
            Self::Entry => 0x87700,
            Self::Native => 0x877c1,
            Self::Initialization => 0x878d1,
            Self::InitEnter => 0x8780c,
            Self::ProcessTokenReturn => 0x8784c,
            Self::ThreadTokenReturn => 0x87908,
            Self::ClearThreadTokenReturn => 0x87930,
            Self::DirectoryInitializationReturn => 0x8786f,
            Self::RestoreThreadTokenReturn => 0x8796c,
            Self::Helper { rva, .. } => rva,
        }
    }
    pub fn bytes(self) -> &'static [u8] {
        match self {
            Self::Entry => &[0x48, 0x8b, 0xc4, 0x55, 0x56, 0x57, 0x41, 0x54],
            Self::Native => &[0x85, 0xc0, 0x78, 0x22],
            Self::Initialization => &[0x45, 0x85, 0xf6, 0x0f, 0x89, 0x97, 0xfe, 0xff, 0xff],
            Self::InitEnter => &[0x65, 0x48, 0x8b, 0x04, 0x25, 0x30, 0, 0, 0],
            Self::ProcessTokenReturn => &[0x44, 0x8b, 0xf0, 0x85, 0xc0, 0x78, 0x3f],
            Self::ThreadTokenReturn => &[0x44, 0x8b, 0xf0, 0x85, 0xc0, 0x78, 0x83],
            Self::ClearThreadTokenReturn => &[
                0x44, 0x8b, 0xf0, 0x85, 0xc0, 0x0f, 0x88, 0x57, 0xff, 0xff, 0xff,
            ],
            Self::DirectoryInitializationReturn => &[0x44, 0x8b, 0xf0, 0x85, 0xc0, 0x78, 0x1c],
            Self::RestoreThreadTokenReturn => &[
                0x48, 0x8b, 0x4d, 0x77, 0x48, 0xff, 0x15, 0xa9, 0x63, 0x20, 0,
            ],
            Self::Helper { rva, .. } => {
                &helper_profile::checkpoint(rva)
                    .expect("admitted helper checkpoint")
                    .bytes
            }
        }
    }
    pub fn slot(self) -> usize {
        match self {
            Self::Entry
            | Self::InitEnter
            | Self::ProcessTokenReturn
            | Self::ClearThreadTokenReturn
            | Self::DirectoryInitializationReturn
            | Self::RestoreThreadTokenReturn => 0,
            Self::Native | Self::ThreadTokenReturn => 1,
            Self::Initialization => 2,
            Self::Helper { slot, .. } => slot,
        }
    }
}
pub fn sites() -> impl Iterator<Item = Site> {
    Site::ALL.into_iter().chain(
        helper_profile::checkpoints()
            .iter()
            .map(|node| Site::Helper {
                rva: node.rva,
                slot: 0,
            }),
    )
}
pub fn site_address(base: u64, site: Site) -> io::Result<u64> {
    if base == 0
        || (site.rva() as usize)
            .checked_add(site.bytes().len())
            .is_none_or(|end| end > SIZE_OF_IMAGE as usize)
    {
        return Err(invalid("site image extent"));
    }
    base.checked_add(u64::from(site.rva()))
        .filter(|_| base.checked_add(u64::from(SIZE_OF_IMAGE)).is_some())
        .ok_or_else(|| invalid("runtime address overflow"))
}
pub fn validate_site_bytes(site: Site, actual: &[u8]) -> io::Result<()> {
    if actual != site.bytes() {
        return Err(invalid("mapped site preimage mismatch"));
    }
    Ok(())
}
fn headers(bytes: &[u8]) -> io::Result<(usize, usize)> {
    if extent(bytes, 0, 2)? != b"MZ" {
        return Err(invalid("DOS signature"));
    }
    let pe = dword(bytes, 0x3c)? as usize;
    if pe != 0x108 || extent(bytes, pe, 4)? != b"PE\0\0" || word(bytes, pe + 4)? != MACHINE {
        return Err(invalid("unsupported PE profile"));
    }
    let optional = pe.checked_add(24).ok_or_else(|| invalid("PE offset"))?;
    if word(bytes, optional)? != MAGIC || dword(bytes, optional + 56)? != SIZE_OF_IMAGE {
        return Err(invalid("optional header profile"));
    }
    Ok((pe, optional))
}
pub fn validate_runtime_header(bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > 4096 {
        return Err(invalid("runtime header bound"));
    }
    headers(bytes).map(|_| ())
}
pub fn validate_file(bytes: &[u8]) -> io::Result<()> {
    if bytes.len() != FILE_LEN {
        return Err(invalid("host file length"));
    }
    let hash: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if hash != IMAGE_SHA256 {
        return Err(invalid("host file hash"));
    }
    validate_pe_profile(bytes)
}
/// Structural checks are separate so malformed PE fixtures need no approved OS image.
pub fn validate_pe_profile(bytes: &[u8]) -> io::Result<()> {
    let (pe, optional) = headers(bytes)?;
    let count = word(bytes, pe + 6)? as usize;
    let optional_size = word(bytes, pe + 20)? as usize;
    if count == 0 || count > 96 || optional_size < 120 {
        return Err(invalid("PE table bound"));
    }
    extent(bytes, optional, optional_size)?;
    let table = optional
        .checked_add(optional_size)
        .ok_or_else(|| invalid("section offset"))?;
    extent(
        bytes,
        table,
        count
            .checked_mul(40)
            .ok_or_else(|| invalid("section count"))?,
    )?;
    let map = |rva: u32, len: usize, executable: bool| -> io::Result<usize> {
        let end = u64::from(rva)
            .checked_add(len as u64)
            .ok_or_else(|| invalid("RVA overflow"))?;
        if end > u64::from(SIZE_OF_IMAGE) {
            return Err(invalid("RVA outside image"));
        }
        let mut found = None;
        for index in 0..count {
            let section = table + index * 40;
            let start = dword(bytes, section + 12)?;
            let raw_size = dword(bytes, section + 16)?;
            let raw = dword(bytes, section + 20)?;
            extent(bytes, raw as usize, raw_size as usize)?;
            if rva >= start && end <= u64::from(start) + u64::from(raw_size) {
                if executable && dword(bytes, section + 36)? & 0x2000_0000 == 0 {
                    return Err(invalid("site not executable"));
                }
                let offset = (raw as usize)
                    .checked_add((rva - start) as usize)
                    .ok_or_else(|| invalid("file offset"))?;
                extent(bytes, offset, len)?;
                if found.replace(offset).is_some() {
                    return Err(invalid("ambiguous sections"));
                }
            }
        }
        found.ok_or_else(|| invalid("unmapped RVA"))
    };
    for site in sites() {
        validate_site_bytes(
            site,
            extent(
                bytes,
                map(site.rva(), site.bytes().len(), true)?,
                site.bytes().len(),
            )?,
        )?;
    }
    for range in helper_profile::byte_extents() {
        if extent(bytes, map(range.rva, range.length, true)?, range.length)? != range.bytes {
            return Err(invalid("helper full-range preimage mismatch"));
        }
    }
    if dword(bytes, optional + 108)? == 0 {
        return Err(invalid("missing export directory"));
    }
    let export_rva = dword(bytes, optional + 112)?;
    let export_size = dword(bytes, optional + 116)?;
    let export = map(export_rva, 40, false)?;
    let functions = dword(bytes, export + 20)? as usize;
    let names = dword(bytes, export + 24)? as usize;
    if functions == 0 || names == 0 || functions > 65536 || names > 65536 {
        return Err(invalid("export count bound"));
    }
    let addresses = map(dword(bytes, export + 28)?, functions * 4, false)?;
    let strings = map(dword(bytes, export + 32)?, names * 4, false)?;
    let ordinals = map(dword(bytes, export + 36)?, names * 2, false)?;
    let mut matches = 0;
    for index in 0..names {
        let name = dword(bytes, strings + index * 4)?;
        let mut observed = Vec::new();
        for offset in 0..256u32 {
            let next = map(
                name.checked_add(offset)
                    .ok_or_else(|| invalid("export name overflow"))?,
                1,
                false,
            )?;
            if bytes[next] == 0 {
                break;
            }
            observed.push(bytes[next]);
        }
        if observed == b"OpenEventW" {
            let ordinal = word(bytes, ordinals + index * 2)? as usize;
            if ordinal >= functions {
                return Err(invalid("export ordinal"));
            }
            let address = dword(bytes, addresses + ordinal * 4)?;
            if address != Site::Entry.rva()
                || (u64::from(address) >= u64::from(export_rva)
                    && u64::from(address) < u64::from(export_rva) + u64::from(export_size))
            {
                return Err(invalid("OpenEventW export mismatch"));
            }
            matches += 1;
        }
    }
    if matches != 1 {
        return Err(invalid("OpenEventW export cardinality"));
    }
    Ok(())
}

pub fn validate_entry(
    access: u64,
    inherit: u64,
    name_pointer: u64,
    expected_access: u32,
    expected_units: &[u16],
    actual_bytes: &[u8],
) -> io::Result<()> {
    let size = expected_units
        .len()
        .checked_mul(2)
        .ok_or_else(|| invalid("name size overflow"))?;
    if access as u32 != expected_access
        || inherit as u32 != 0
        || name_pointer == 0
        || expected_units.is_empty()
        || expected_units.len() > 4096
        || expected_units.last() != Some(&0)
        || expected_units[..expected_units.len() - 1].contains(&0)
        || name_pointer.checked_add(size as u64).is_none()
        || actual_bytes.len() != size
    {
        return Err(invalid("replay entry argument mismatch"));
    }
    if !actual_bytes
        .chunks_exact(2)
        .zip(expected_units)
        .all(|(bytes, expected)| u16::from_le_bytes([bytes[0], bytes[1]]) == *expected)
    {
        return Err(invalid("replay entry name mismatch"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct DebugRegisters {
    pub dr: [u64; 4],
    pub dr6: u64,
    pub dr7: u64,
    pub eflags: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum State {
    ArmedEntry,
    AwaitResult,
    AwaitNative,
    AwaitTokenOpen,
    AwaitClearThreadToken,
    AwaitProcessToken,
    AwaitRestoreThreadToken,
    AwaitInitialization,
    InHelper,
    Observed,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Stop {
    pub pid: u32,
    pub tid: u32,
    pub exception: u32,
    pub first_chance: bool,
    pub exception_address: u64,
    pub rip: u64,
    pub registers: DebugRegisters,
    pub rax: u64,
    pub r14: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub r8: u64,
    pub r9: u64,
    pub rsp: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Observation {
    pub site: Site,
    pub status: Option<i32>,
    pub slot: usize,
}
const OWNED_DR7: u64 = 0x3f | (0xfff << 16);
/// Intel SDM's DR7 fixed-one bit may differ between API and executed contexts.
pub const DR7_FIXED_ONE_MASK: u64 = 1 << 10;

/// Compare every control bit except the architectural fixed-one representation.
pub fn dr7_equivalent(actual: u64, expected: u64) -> bool {
    (actual ^ expected) & !DR7_FIXED_ONE_MASK == 0
}
const UNRELATED_STATUS: u64 = 8 | (7 << 13);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HitRejection {
    AddressRegisters,
    ControlRegister,
    UnrelatedStatus,
    TrapFlag,
    HitState,
    OwnerProcess,
    OwnerThread,
    ExceptionCode,
    FirstChance,
    InstructionPointer,
    ExceptionAddress,
    AddressOverflow,
    ReadbackStatus,
    MissingPlanner,
}
impl HitRejection {
    pub fn io_error(self) -> io::Error {
        invalid(match self {
            Self::AddressRegisters
            | Self::ControlRegister
            | Self::UnrelatedStatus
            | Self::TrapFlag => "unexpected debug state change",
            Self::HitState => "unowned breakpoint state",
            Self::AddressOverflow => "runtime address overflow",
            Self::ReadbackStatus => "debug status readback",
            Self::MissingPlanner => "single step before profile arm",
            _ => "unowned debug exception",
        })
    }
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct OwnershipFacts {
    pub address_registers_equal: bool,
    pub control_register_equal: bool,
    pub control_register_raw_equal: bool,
    pub dr7_fixed_one_equivalence_mask: u64,
    pub unrelated_status_clear: bool,
    pub trap_flag_clear: bool,
    pub unrelated_status_mask: u64,
    pub unrelated_status_value: u64,
    pub trap_flag_mask: u32,
    pub trap_flag_value: u32,
    pub owned_dr7_mask: u64,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Expectation {
    pub registers: DebugRegisters,
    pub state: State,
    pub base: u64,
    pub pid: u32,
    pub tid: u32,
    pub addresses: [Option<ExpectedSite>; 3],
    pub exception: u32,
    pub ownership: OwnershipFacts,
    pub initializer_source: Option<&'static str>,
    pub initializer_status: Option<i32>,
    pub thread_token_cleared: bool,
    pub helper_selected: Option<helper_profile::Selected>,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct ExpectedSite {
    pub site: &'static str,
    pub slot: usize,
    pub rva: u32,
    pub address: Option<u64>,
}
#[derive(Clone)]
pub struct Planner {
    saved: DebugRegisters,
    expected: DebugRegisters,
    base: u64,
    pid: u32,
    tid: u32,
    state: State,
    thread_cleared: bool,
    initializer_status: Option<i32>,
    initializer_source: Option<Site>,
    helper: Option<helper_profile::Machine>,
}
impl Planner {
    pub fn arm(saved: DebugRegisters, base: u64, pid: u32, tid: u32) -> io::Result<Self> {
        if pid == 0
            || tid == 0
            || saved.dr7 & (0xff | (1 << 13)) != 0
            || saved.dr6 & (0xf | (7 << 13)) != 0
            || saved.eflags & (1 << 8) != 0
        {
            return Err(invalid("existing debug state"));
        }
        let mut expected = saved;
        expected.dr[0] = site_address(base, Site::Entry)?;
        expected.dr7 = (saved.dr7 & !OWNED_DR7) | 1;
        expected.dr6 &= !7;
        Ok(Self {
            saved,
            expected,
            base,
            pid,
            tid,
            state: State::ArmedEntry,
            thread_cleared: false,
            initializer_status: None,
            initializer_source: None,
            helper: None,
        })
    }
    pub fn registers(&self) -> DebugRegisters {
        self.expected
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn snapshot(&self, current: DebugRegisters) -> Expectation {
        Expectation {
            registers: self.expected,
            state: self.state,
            base: self.base,
            pid: self.pid,
            tid: self.tid,
            addresses: std::array::from_fn(|slot| {
                self.active_sites()[slot].map(|site| ExpectedSite {
                    site: site.name(),
                    slot,
                    rva: site.rva(),
                    address: self.base.checked_add(u64::from(site.rva())),
                })
            }),
            exception: SINGLE_STEP,
            initializer_source: self.initializer_source.map(Site::name),
            initializer_status: self.initializer_status,
            thread_token_cleared: self.thread_cleared,
            helper_selected: self.helper.as_ref().and_then(|machine| machine.selected),
            ownership: OwnershipFacts {
                address_registers_equal: current.dr == self.expected.dr,
                control_register_equal: dr7_equivalent(current.dr7, self.expected.dr7),
                control_register_raw_equal: current.dr7 == self.expected.dr7,
                dr7_fixed_one_equivalence_mask: DR7_FIXED_ONE_MASK,
                unrelated_status_clear: current.dr6 & UNRELATED_STATUS == 0,
                trap_flag_clear: current.eflags & (1 << 8) == 0,
                unrelated_status_mask: UNRELATED_STATUS,
                unrelated_status_value: current.dr6 & UNRELATED_STATUS,
                trap_flag_mask: 1 << 8,
                trap_flag_value: current.eflags & (1 << 8),
                owned_dr7_mask: OWNED_DR7,
            },
        }
    }
    fn verify_owned(&self, current: DebugRegisters) -> Result<(), HitRejection> {
        let facts = self.snapshot(current).ownership;
        if !facts.address_registers_equal {
            return Err(HitRejection::AddressRegisters);
        }
        if !facts.control_register_equal {
            return Err(HitRejection::ControlRegister);
        }
        if !facts.unrelated_status_clear {
            return Err(HitRejection::UnrelatedStatus);
        }
        if !facts.trap_flag_clear {
            return Err(HitRejection::TrapFlag);
        }
        Ok(())
    }
    pub fn verify_readback(&self, current: DebugRegisters) -> io::Result<()> {
        self.verify_readback_typed(current)
            .map_err(HitRejection::io_error)
    }
    pub fn verify_readback_typed(&self, current: DebugRegisters) -> Result<(), HitRejection> {
        self.verify_owned(current)?;
        if current.dr6 & 7 != self.expected.dr6 & 7 {
            return Err(HitRejection::ReadbackStatus);
        }
        Ok(())
    }
    pub fn restore(&self, current: DebugRegisters) -> io::Result<DebugRegisters> {
        self.restore_checked(current)
            .map_err(HitRejection::io_error)
    }
    fn restore_checked(&self, current: DebugRegisters) -> Result<DebugRegisters, HitRejection> {
        self.verify_owned(current)?;
        let mut restored = current;
        restored.dr[..3].copy_from_slice(&self.saved.dr[..3]);
        restored.dr7 = (current.dr7 & !OWNED_DR7) | (self.saved.dr7 & OWNED_DR7);
        restored.dr6 = (current.dr6 & !7) | (self.saved.dr6 & 7);
        Ok(restored)
    }
    pub fn on_hit(&mut self, stop: Stop) -> Result<Observation, HitRejection> {
        self.verify_owned(stop.registers)?;
        let site = match (self.state, stop.registers.dr6 & 0xf) {
            (State::InHelper, 1 | 2) => {
                let slot = if stop.registers.dr6 & 0xf == 1 { 0 } else { 1 };
                let rva = *self
                    .helper
                    .as_ref()
                    .and_then(|machine| machine.frontier.get(slot))
                    .ok_or(HitRejection::HitState)?;
                Site::Helper { rva, slot }
            }
            (State::InHelper, 4) => Site::DirectoryInitializationReturn,
            (State::ArmedEntry, 1) => Site::Entry,
            (State::AwaitResult, 1) => Site::InitEnter,
            (State::AwaitTokenOpen, 1) | (State::AwaitProcessToken, 1) => Site::ProcessTokenReturn,
            (State::AwaitTokenOpen, 2) => Site::ThreadTokenReturn,
            (State::AwaitClearThreadToken, 1) => Site::ClearThreadTokenReturn,
            (State::AwaitRestoreThreadToken, 1) => Site::RestoreThreadTokenReturn,
            (State::AwaitInitialization, 4) => Site::Initialization,
            (State::AwaitResult | State::AwaitNative, 2) => Site::Native,
            _ => return Err(HitRejection::HitState),
        };
        let address = site_address(self.base, site).map_err(|_| HitRejection::AddressOverflow)?;
        if stop.pid != self.pid {
            return Err(HitRejection::OwnerProcess);
        }
        if stop.tid != self.tid {
            return Err(HitRejection::OwnerThread);
        }
        if stop.exception != SINGLE_STEP {
            return Err(HitRejection::ExceptionCode);
        }
        if !stop.first_chance {
            return Err(HitRejection::FirstChance);
        }
        if stop.rip != address {
            return Err(HitRejection::InstructionPointer);
        }
        if stop.exception_address != address {
            return Err(HitRejection::ExceptionAddress);
        }
        if site == Site::Initialization && self.initializer_status != Some(stop.r14 as u32 as i32) {
            return Err(HitRejection::HitState);
        }
        if site == Site::DirectoryInitializationReturn
            && self
                .helper
                .as_ref()
                .and_then(|machine| machine.selected)
                .is_none_or(|selected| selected.status != stop.rax as u32 as i32)
        {
            return Err(HitRejection::HitState);
        }
        let mut next = stop.registers;
        next.dr6 = (next.dr6 & !7) | (self.saved.dr6 & 7);
        if let Site::Helper { rva, slot } = site {
            let mut machine = self
                .helper
                .as_ref()
                .expect("helper state owns machine")
                .clone();
            let status = machine
                .hit(rva, slot, stop.rax, stop.rbx)
                .map_err(|_| HitRejection::HitState)?;
            for slot in 0..2 {
                Self::retire_slot(&mut next, self.saved, slot);
                if let Some(rva) = machine.frontier.get(slot) {
                    Self::set_site(&mut next, self.base, Site::Helper { rva: *rva, slot })?;
                }
            }
            self.helper = Some(machine);
            self.expected = next;
            return Ok(Observation { site, status, slot });
        }
        let status = match site {
            Site::Entry => {
                next.dr[0] = site_address(self.base, Site::InitEnter)
                    .map_err(|_| HitRejection::AddressOverflow)?;
                next.dr[1] = site_address(self.base, Site::Native)
                    .map_err(|_| HitRejection::AddressOverflow)?;
                next.dr[2] = site_address(self.base, Site::Initialization)
                    .map_err(|_| HitRejection::AddressOverflow)?;
                next.dr7 = (next.dr7 & !OWNED_DR7) | 1 | (1 << 2) | (1 << 4);
                self.state = State::AwaitResult;
                None
            }
            Site::Initialization => {
                let status = stop.r14 as u32 as i32;
                if status >= 0 {
                    next.dr[2] = self.saved.dr[2];
                    next.dr7 &= !((3 << 4) | (0xf << 24));
                    self.state = State::AwaitNative;
                } else {
                    next = self.restore_checked(next)?;
                    self.state = State::Observed;
                }
                Some(status)
            }
            Site::InitEnter => {
                Self::set_site(&mut next, self.base, Site::ProcessTokenReturn)?;
                Self::set_site(&mut next, self.base, Site::ThreadTokenReturn)?;
                self.state = State::AwaitTokenOpen;
                None
            }
            Site::ThreadTokenReturn
            | Site::ClearThreadTokenReturn
            | Site::ProcessTokenReturn
            | Site::DirectoryInitializationReturn => {
                let status = stop.rax as u32 as i32;
                if site == Site::DirectoryInitializationReturn {
                    Self::set_site(&mut next, self.base, Site::Initialization)?;
                }
                Self::retire_slot(&mut next, self.saved, 1);
                if status < 0 || site == Site::DirectoryInitializationReturn {
                    self.initializer_status = Some(status);
                    self.initializer_source = Some(site);
                    Self::set_site(&mut next, self.base, Site::Native)?;
                    if self.thread_cleared {
                        Self::set_site(&mut next, self.base, Site::RestoreThreadTokenReturn)?;
                        self.state = State::AwaitRestoreThreadToken;
                    } else {
                        Self::retire_slot(&mut next, self.saved, 0);
                        self.state = State::AwaitInitialization;
                    }
                } else {
                    let (site, state) = match site {
                        Site::ThreadTokenReturn => {
                            (Site::ClearThreadTokenReturn, State::AwaitClearThreadToken)
                        }
                        Site::ClearThreadTokenReturn => {
                            self.thread_cleared = true;
                            (Site::ProcessTokenReturn, State::AwaitProcessToken)
                        }
                        Site::ProcessTokenReturn => {
                            self.helper = Some(helper_profile::Machine::default());
                            Self::retire_slot(&mut next, self.saved, 2);
                            next.dr[2] =
                                site_address(self.base, Site::DirectoryInitializationReturn)
                                    .map_err(|_| HitRejection::AddressOverflow)?;
                            next.dr7 |= 1 << 4;
                            (
                                Site::Helper {
                                    rva: 0x86450,
                                    slot: 0,
                                },
                                State::InHelper,
                            )
                        }
                        _ => unreachable!(),
                    };
                    Self::set_site(&mut next, self.base, site)?;
                    self.state = state;
                }
                Some(status)
            }
            Site::RestoreThreadTokenReturn => {
                Self::retire_slot(&mut next, self.saved, 0);
                self.state = State::AwaitInitialization;
                Some(stop.rax as u32 as i32)
            }
            Site::Native => {
                let status = stop.rax as u32 as i32;
                next = self.restore_checked(next)?;
                self.state = State::Observed;
                Some(status)
            }
            Site::Helper { .. } => unreachable!("helper handled before outer transition"),
        };
        self.expected = next;
        Ok(Observation {
            site,
            status,
            slot: if self.helper.is_some() && site == Site::DirectoryInitializationReturn {
                2
            } else {
                site.slot()
            },
        })
    }
    fn active_sites(&self) -> [Option<Site>; 3] {
        std::array::from_fn(|slot| {
            if self.expected.dr7 & (3 << (slot * 2)) == 0 {
                return None;
            }
            if self.state == State::InHelper {
                if slot == 2 {
                    return Some(Site::DirectoryInitializationReturn);
                }
                return self
                    .helper
                    .as_ref()
                    .and_then(|machine| machine.frontier.get(slot))
                    .map(|rva| Site::Helper { rva: *rva, slot });
            }
            Site::ALL.into_iter().find(|site| {
                site.slot() == slot
                    && self.base.checked_add(u64::from(site.rva())) == Some(self.expected.dr[slot])
            })
        })
    }
    fn set_site(registers: &mut DebugRegisters, base: u64, site: Site) -> Result<(), HitRejection> {
        let slot = site.slot();
        registers.dr[slot] = site_address(base, site).map_err(|_| HitRejection::AddressOverflow)?;
        registers.dr7 =
            (registers.dr7 & !((3 << (slot * 2)) | (0xf << (16 + slot * 4)))) | (1 << (slot * 2));
        Ok(())
    }
    fn retire_slot(registers: &mut DebugRegisters, saved: DebugRegisters, slot: usize) {
        registers.dr[slot] = saved.dr[slot];
        let mask = (3 << (slot * 2)) | (0xf << (16 + slot * 4));
        registers.dr7 = (registers.dr7 & !mask) | (saved.dr7 & mask);
    }
}

pub fn stop_qpc(now: u64, hard: u64) -> io::Result<u64> {
    let remaining = hard
        .checked_sub(now)
        .filter(|v| *v > 1)
        .ok_or_else(|| invalid("no replay budget"))?;
    now.checked_add(remaining / 2)
        .ok_or_else(|| invalid("cutoff overflow"))
}
pub fn wait_millis(now: u64, cutoff: u64, frequency: u64) -> io::Result<u32> {
    if frequency == 0 {
        return Err(invalid("zero QPC frequency"));
    }
    let left = cutoff.saturating_sub(now);
    Ok(((u128::from(left) * 1000 / u128::from(frequency)).min(10)) as u32)
}
#[derive(Default)]
pub struct Limit {
    observed: usize,
    teardown: usize,
    bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CleanupFacts {
    pub exit_continued: bool,
    pub process_signaled: bool,
    pub reader_joined: bool,
    pub watchdog_joined: bool,
    pub pending_event: bool,
    pub registers_live: bool,
    pub restore_verified: bool,
}
impl CleanupFacts {
    pub fn complete(self) -> bool {
        self.exit_continued
            && self.process_signaled
            && self.reader_joined
            && self.watchdog_joined
            && !self.pending_event
            && (!self.registers_live || self.restore_verified)
    }
}
impl Limit {
    pub fn event(&mut self, teardown: bool) -> io::Result<()> {
        let value = if teardown {
            &mut self.teardown
        } else {
            &mut self.observed
        };
        *value = value
            .checked_add(1)
            .ok_or_else(|| invalid("event overflow"))?;
        if *value >= EVENT_LIMIT {
            return Err(invalid("debug event bound"));
        }
        Ok(())
    }
    pub fn output(&mut self, bytes: usize) -> io::Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| invalid("output overflow"))?;
        if self.bytes >= OUTPUT_LIMIT {
            return Err(invalid("debug output bound"));
        }
        Ok(())
    }
}
