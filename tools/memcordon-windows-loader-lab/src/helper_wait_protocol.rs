//! Closed, bounded diagnostic transport. These records grant no workload authority.
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, io};

pub const ROLE: &str = "observe-toolchain-wait";
pub const VERSION: u32 = 2;
pub const MAPPING_BOUND: usize = 16 * 1024;
pub const REQUEST_BOUND: usize = MAPPING_BOUND - std::mem::size_of::<u32>();
pub const FRAME_BOUND: usize = 8 * 1024;
pub const OUTPUT_BOUND: usize = 128 * 1024;
pub const THREAD_BOUND: usize = 64;
pub const NODE_BOUND: usize = 16;
const REQUEST_MAGIC: &[u8] = b"MCWCTREQ";
const FRAME_MAGIC: &[u8] = b"MCWCTRES";

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct Identity {
    pub pid: u32,
    #[serde(serialize_with = "serialize_birth")]
    pub birth: u128,
}
fn serialize_birth<S: serde::Serializer>(value: &u128, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.to_string())
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Thread {
    pub handle: u64,
    pub tid: u32,
    pub birth: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub nonce: [u8; 32],
    pub challenge_sha256: [u8; 32],
    pub observer_sha256: [u8; 32],
    pub helper_sha256: [u8; 32],
    pub target_machine: u16,
    pub root: Identity,
    pub compiler: Identity,
    pub helper: Identity,
    pub helper_parent: Identity,
    pub process_handle: u64,
    pub threads: Vec<Thread>,
    pub omitted_threads: u32,
    pub frequency: u64,
    pub trigger_qpc: u64,
    pub launch_qpc: u64,
    pub work_cutoff_qpc: u64,
    pub cleanup_cutoff_qpc: u64,
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "closed helper-wait protocol differs",
    )
}
impl Request {
    pub fn digest(&self) -> io::Result<[u8; 32]> {
        Ok(Sha256::digest(self.encode()?).into())
    }
    pub fn validate(&self) -> io::Result<()> {
        let mut handles = BTreeSet::from([self.process_handle]);
        let mut tids = BTreeSet::new();
        if !matches!(self.target_machine, 0x8664 | 0xaa64)
            || [self.root, self.compiler, self.helper, self.helper_parent]
                .iter()
                .any(|id| id.pid == 0 || id.birth == 0)
            || self.process_handle == 0
            || self.threads.is_empty()
            || self.threads.len() > THREAD_BOUND
            || self.frequency == 0
            || self.trigger_qpc == 0
            || self.trigger_qpc > self.launch_qpc
            || self.launch_qpc >= self.work_cutoff_qpc
            || self.work_cutoff_qpc >= self.cleanup_cutoff_qpc
            || self.threads.iter().any(|thread| {
                thread.handle == 0
                    || thread.tid == 0
                    || thread.birth == 0
                    || !handles.insert(thread.handle)
                    || !tids.insert(thread.tid)
            })
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        self.validate()?;
        let mut out = REQUEST_MAGIC.to_vec();
        put(&mut out, VERSION.to_le_bytes());
        for hash in [
            self.nonce,
            self.challenge_sha256,
            self.observer_sha256,
            self.helper_sha256,
        ] {
            put(&mut out, hash);
        }
        put(&mut out, self.target_machine.to_le_bytes());
        for id in [self.root, self.compiler, self.helper, self.helper_parent] {
            put_identity(&mut out, id);
        }
        put(&mut out, self.process_handle.to_le_bytes());
        put(&mut out, self.omitted_threads.to_le_bytes());
        for value in [
            self.frequency,
            self.trigger_qpc,
            self.launch_qpc,
            self.work_cutoff_qpc,
            self.cleanup_cutoff_qpc,
        ] {
            put(&mut out, value.to_le_bytes());
        }
        put(
            &mut out,
            u32::try_from(self.threads.len())
                .map_err(|_| invalid())?
                .to_le_bytes(),
        );
        for thread in &self.threads {
            put(&mut out, thread.handle.to_le_bytes());
            put(&mut out, thread.tid.to_le_bytes());
            put(&mut out, thread.birth.to_le_bytes());
        }
        if out.len() > REQUEST_BOUND {
            return Err(invalid());
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > REQUEST_BOUND {
            return Err(invalid());
        }
        let mut input = Input(bytes);
        input.magic(REQUEST_MAGIC)?;
        if input.u32()? != VERSION {
            return Err(invalid());
        }
        let nonce = input.array()?;
        let challenge_sha256 = input.array()?;
        let observer_sha256 = input.array()?;
        let helper_sha256 = input.array()?;
        let target_machine = u16::from_le_bytes(input.array()?);
        let root = input.identity()?;
        let compiler = input.identity()?;
        let helper = input.identity()?;
        let helper_parent = input.identity()?;
        let process_handle = input.u64()?;
        let omitted_threads = input.u32()?;
        let frequency = input.u64()?;
        let trigger_qpc = input.u64()?;
        let launch_qpc = input.u64()?;
        let work_cutoff_qpc = input.u64()?;
        let cleanup_cutoff_qpc = input.u64()?;
        let count = usize::try_from(input.u32()?).map_err(|_| invalid())?;
        if count > THREAD_BOUND {
            return Err(invalid());
        }
        let mut threads = Vec::with_capacity(count);
        for _ in 0..count {
            threads.push(Thread {
                handle: input.u64()?,
                tid: input.u32()?,
                birth: input.u64()?,
            });
        }
        input.end()?;
        let request = Self {
            nonce,
            challenge_sha256,
            observer_sha256,
            helper_sha256,
            target_machine,
            root,
            compiler,
            helper,
            helper_parent,
            process_handle,
            threads,
            omitted_threads,
            frequency,
            trigger_qpc,
            launch_qpc,
            work_cutoff_qpc,
            cleanup_cutoff_qpc,
        };
        request.validate()?;
        Ok(request)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[repr(u32)]
pub enum Stage {
    Clock = 1,
    Privilege = 2,
    Binding = 3,
    Watchdog = 4,
    OpenSession = 5,
    Query = 6,
    CloseSession = 7,
    Output = 8,
    UnknownNode = 9,
}
impl Stage {
    fn decode(value: u32) -> io::Result<Self> {
        match value {
            1 => Ok(Self::Clock),
            2 => Ok(Self::Privilege),
            3 => Ok(Self::Binding),
            4 => Ok(Self::Watchdog),
            5 => Ok(Self::OpenSession),
            6 => Ok(Self::Query),
            7 => Ok(Self::CloseSession),
            8 => Ok(Self::Output),
            9 => Ok(Self::UnknownNode),
            _ => Err(invalid()),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct Node {
    pub object_type: u32,
    pub status: u32,
    pub process_id: u32,
    pub thread_id: u32,
    pub wait_time: u32,
    pub context_switches: u32,
}
impl Node {
    fn validate(&self) -> io::Result<()> {
        if !(1..13).contains(&self.object_type)
            || !(1..11).contains(&self.status)
            || (self.object_type != 8
                && (self.process_id != 0
                    || self.thread_id != 0
                    || self.wait_time != 0
                    || self.context_switches != 0))
        {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ThreadResult {
    pub ordinal: u32,
    pub lifecycle: ThreadLifecycle,
    pub exit_status: Option<u32>,
    pub tid: u32,
    pub birth: u64,
    pub before_qpc: u64,
    pub after_qpc: u64,
    pub binding_before: bool,
    pub binding_after: bool,
    pub cycle: Option<bool>,
    pub complete: bool,
    pub native_error: Option<u32>,
    pub reported_nodes: Option<u32>,
    pub nodes: Vec<Node>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[repr(u32)]
pub enum ThreadLifecycle {
    QueriedLive = 1,
    ExitedBeforeQuery = 2,
    ExitedAfterQuery = 3,
}
impl ThreadLifecycle {
    fn decode(value: u32) -> io::Result<Self> {
        match value {
            1 => Ok(Self::QueriedLive),
            2 => Ok(Self::ExitedBeforeQuery),
            3 => Ok(Self::ExitedAfterQuery),
            _ => Err(invalid()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[repr(u32)]
pub enum BindingScope {
    Process = 1,
    Thread = 2,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[repr(u32)]
pub enum BindingBoundary {
    BeforeQuery = 1,
    AfterQuery = 2,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[repr(u32)]
pub enum BindingOperation {
    Wait = 1,
    GetId = 2,
    GetOwner = 3,
    GetTimes = 4,
    CompareIdentity = 5,
    GetExitCode = 6,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[repr(u32)]
pub enum BindingReason {
    Exited = 1,
    NativeError = 2,
    IdentityMismatch = 3,
    UnexpectedWait = 4,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct BindingIdentity {
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    #[serde(serialize_with = "serialize_optional_birth")]
    pub birth: Option<u128>,
}
fn serialize_optional_birth<S: serde::Serializer>(
    value: &Option<u128>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => serializer.serialize_some(&value.to_string()),
        None => serializer.serialize_none(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct BindingFailure {
    pub scope: BindingScope,
    pub boundary: BindingBoundary,
    pub operation: BindingOperation,
    pub reason: BindingReason,
    pub ordinal: Option<u32>,
    pub expected: BindingIdentity,
    pub observed: BindingIdentity,
    pub wait_status: Option<u32>,
    pub native_error: Option<u32>,
    pub before_qpc: u64,
    pub after_qpc: u64,
}
impl BindingFailure {
    fn validate(
        &self,
        request: &Request,
        processed: usize,
        last_qpc: u64,
        qpc: u64,
    ) -> io::Result<()> {
        if self.before_qpc < last_qpc || self.after_qpc < self.before_qpc || self.after_qpc > qpc {
            return Err(invalid());
        }
        if self.ordinal.is_some_and(|ordinal| {
            ordinal as usize != processed || processed >= request.threads.len()
        }) || (self.ordinal.is_none()
            && (processed != 0
                || self.scope != BindingScope::Process
                || self.boundary != BindingBoundary::BeforeQuery))
        {
            return Err(invalid());
        }
        let expected = match self.scope {
            BindingScope::Process => BindingIdentity {
                pid: Some(request.helper.pid),
                tid: None,
                birth: Some(request.helper.birth),
            },
            BindingScope::Thread => {
                let thread = request
                    .threads
                    .get(self.ordinal.ok_or_else(invalid)? as usize)
                    .ok_or_else(invalid)?;
                BindingIdentity {
                    pid: Some(request.helper.pid),
                    tid: Some(thread.tid),
                    birth: Some(u128::from(thread.birth)),
                }
            }
        };
        if self.expected != expected
            || (self.scope == BindingScope::Process && self.observed.tid.is_some())
            || (self.scope == BindingScope::Process
                && matches!(
                    self.operation,
                    BindingOperation::GetOwner | BindingOperation::GetExitCode
                ))
        {
            return Err(invalid());
        }
        let mismatch = self.observed.pid.is_some_and(|v| Some(v) != expected.pid)
            || self.observed.tid.is_some_and(|v| Some(v) != expected.tid)
            || self
                .observed
                .birth
                .is_some_and(|v| Some(v) != expected.birth);
        let valid = match self.reason {
            BindingReason::Exited => {
                self.scope == BindingScope::Process
                    && self.operation == BindingOperation::Wait
                    && self.observed == expected
                    && self.wait_status == Some(0)
                    && self.native_error.is_none()
            }
            BindingReason::IdentityMismatch => {
                self.operation == BindingOperation::CompareIdentity
                    && mismatch
                    && self.native_error.is_none()
                    && self.wait_status.is_none()
            }
            BindingReason::NativeError => {
                self.operation != BindingOperation::CompareIdentity
                    && self.native_error.is_some()
                    && (self.operation != BindingOperation::Wait
                        || self.wait_status == Some(u32::MAX))
            }
            BindingReason::UnexpectedWait => {
                self.operation == BindingOperation::Wait
                    && self.native_error.is_none()
                    && self.observed == expected
                    && self
                        .wait_status
                        .is_some_and(|status| !matches!(status, 0 | 258 | u32::MAX))
            }
        };
        if valid { Ok(()) } else { Err(invalid()) }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub enum ResultKind {
    Begin {
        observer: Identity,
        threads: u32,
        omitted: u32,
    },
    Thread(ThreadResult),
    Refused {
        stage: Stage,
        native_error: Option<u32>,
        binding_failure: Option<BindingFailure>,
    },
    End {
        processed: u32,
        queried: u32,
        complete: bool,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct Frame {
    pub binding: [u8; 32],
    pub sequence: u32,
    pub qpc: u64,
    pub result: ResultKind,
}
impl Frame {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut out = FRAME_MAGIC.to_vec();
        put(&mut out, VERSION.to_le_bytes());
        put(&mut out, self.binding);
        put(&mut out, self.sequence.to_le_bytes());
        put(&mut out, self.qpc.to_le_bytes());
        match &self.result {
            ResultKind::Begin {
                observer,
                threads,
                omitted,
            } => {
                put(&mut out, 1u32.to_le_bytes());
                put_identity(&mut out, *observer);
                put(&mut out, threads.to_le_bytes());
                put(&mut out, omitted.to_le_bytes());
            }
            ResultKind::Thread(value) => {
                if value.nodes.len() > NODE_BOUND {
                    return Err(invalid());
                }
                put(&mut out, 2u32.to_le_bytes());
                put(&mut out, value.ordinal.to_le_bytes());
                put(&mut out, (value.lifecycle as u32).to_le_bytes());
                put_error(&mut out, value.exit_status);
                put(&mut out, value.tid.to_le_bytes());
                put(&mut out, value.birth.to_le_bytes());
                put(&mut out, value.before_qpc.to_le_bytes());
                put(&mut out, value.after_qpc.to_le_bytes());
                for flag in [value.binding_before, value.binding_after, value.complete] {
                    out.push(u8::from(flag));
                }
                out.push(match value.cycle {
                    None => 0,
                    Some(false) => 1,
                    Some(true) => 2,
                });
                put_error(&mut out, value.native_error);
                put_error(&mut out, value.reported_nodes);
                put(
                    &mut out,
                    u32::try_from(value.nodes.len())
                        .map_err(|_| invalid())?
                        .to_le_bytes(),
                );
                for node in &value.nodes {
                    node.validate()?;
                    for value in [
                        node.object_type,
                        node.status,
                        node.process_id,
                        node.thread_id,
                        node.wait_time,
                        node.context_switches,
                    ] {
                        put(&mut out, value.to_le_bytes());
                    }
                }
            }
            ResultKind::Refused {
                stage,
                native_error,
                binding_failure,
            } => {
                put(&mut out, 3u32.to_le_bytes());
                put(&mut out, (*stage as u32).to_le_bytes());
                put_error(&mut out, *native_error);
                put_failure(&mut out, *binding_failure);
            }
            ResultKind::End {
                processed,
                queried,
                complete,
            } => {
                put(&mut out, 4u32.to_le_bytes());
                put(&mut out, processed.to_le_bytes());
                put(&mut out, queried.to_le_bytes());
                out.push(u8::from(*complete));
            }
        }
        if out.len() > FRAME_BOUND {
            return Err(invalid());
        }
        let mut framed = Vec::with_capacity(out.len() + std::mem::size_of::<u32>());
        put(
            &mut framed,
            u32::try_from(out.len())
                .map_err(|_| invalid())?
                .to_le_bytes(),
        );
        framed.extend(out);
        Ok(framed)
    }
    pub fn decode(payload: &[u8]) -> io::Result<Self> {
        if payload.len() > FRAME_BOUND {
            return Err(invalid());
        }
        let mut input = Input(payload);
        input.magic(FRAME_MAGIC)?;
        if input.u32()? != VERSION {
            return Err(invalid());
        }
        let binding = input.array()?;
        let sequence = input.u32()?;
        let qpc = input.u64()?;
        let result = match input.u32()? {
            1 => ResultKind::Begin {
                observer: input.identity()?,
                threads: input.u32()?,
                omitted: input.u32()?,
            },
            2 => {
                let ordinal = input.u32()?;
                let lifecycle = ThreadLifecycle::decode(input.u32()?)?;
                let exit_status = input.error()?;
                let tid = input.u32()?;
                let birth = input.u64()?;
                let before_qpc = input.u64()?;
                let after_qpc = input.u64()?;
                let binding_before = input.boolean()?;
                let binding_after = input.boolean()?;
                let complete = input.boolean()?;
                let cycle = match input.array::<1>()?[0] {
                    0 => None,
                    1 => Some(false),
                    2 => Some(true),
                    _ => return Err(invalid()),
                };
                let native_error = input.error()?;
                let reported_nodes = input.error()?;
                let count = usize::try_from(input.u32()?).map_err(|_| invalid())?;
                if count > NODE_BOUND {
                    return Err(invalid());
                }
                let mut nodes = Vec::with_capacity(count);
                for _ in 0..count {
                    let node = Node {
                        object_type: input.u32()?,
                        status: input.u32()?,
                        process_id: input.u32()?,
                        thread_id: input.u32()?,
                        wait_time: input.u32()?,
                        context_switches: input.u32()?,
                    };
                    node.validate()?;
                    nodes.push(node);
                }
                ResultKind::Thread(ThreadResult {
                    ordinal,
                    lifecycle,
                    exit_status,
                    tid,
                    birth,
                    before_qpc,
                    after_qpc,
                    binding_before,
                    binding_after,
                    cycle,
                    complete,
                    native_error,
                    reported_nodes,
                    nodes,
                })
            }
            3 => ResultKind::Refused {
                stage: Stage::decode(input.u32()?)?,
                native_error: input.error()?,
                binding_failure: input.binding_failure()?,
            },
            4 => ResultKind::End {
                processed: input.u32()?,
                queried: input.u32()?,
                complete: input.boolean()?,
            },
            _ => return Err(invalid()),
        };
        input.end()?;
        Ok(Self {
            binding,
            sequence,
            qpc,
            result,
        })
    }
}

/// Incremental input admission. A final frame is never native retirement proof.
pub struct Stream {
    request: Request,
    observer: Identity,
    binding: [u8; 32],
    pending: Vec<u8>,
    received: usize,
    frames: Vec<Frame>,
    results: usize,
    queried: usize,
    begun: bool,
    refused: bool,
    ended: bool,
    last_qpc: u64,
    failed: bool,
}
impl Stream {
    pub fn new(request: Request, observer: Identity) -> io::Result<Self> {
        let binding = request.digest()?;
        if observer.pid == 0 || observer.birth == 0 {
            return Err(invalid());
        }
        Ok(Self {
            last_qpc: request.launch_qpc,
            request,
            observer,
            binding,
            pending: Vec::new(),
            received: 0,
            frames: Vec::new(),
            results: 0,
            queried: 0,
            begun: false,
            refused: false,
            ended: false,
            failed: false,
        })
    }
    pub fn push(&mut self, bytes: &[u8], observed_qpc: u64) -> io::Result<()> {
        if self.failed {
            return Err(invalid());
        }
        let result = self.push_inner(bytes, observed_qpc);
        self.failed = result.is_err();
        result
    }
    fn push_inner(&mut self, bytes: &[u8], observed_qpc: u64) -> io::Result<()> {
        if observed_qpc >= self.request.work_cutoff_qpc
            || self
                .received
                .checked_add(bytes.len())
                .is_none_or(|n| n > OUTPUT_BOUND)
        {
            return Err(invalid());
        }
        self.received += bytes.len();
        self.pending.extend_from_slice(bytes);
        loop {
            let prefix = std::mem::size_of::<u32>();
            if self.pending.len() < prefix {
                return Ok(());
            }
            let length = usize::try_from(u32::from_le_bytes(
                self.pending[..prefix].try_into().map_err(|_| invalid())?,
            ))
            .map_err(|_| invalid())?;
            if length == 0 || length > FRAME_BOUND {
                return Err(invalid());
            }
            if self.pending.len() < prefix + length {
                return Ok(());
            }
            let frame = Frame::decode(&self.pending[prefix..prefix + length])?;
            if self.ended
                || self.frames.len() >= THREAD_BOUND + 3
                || frame.binding != self.binding
                || frame.sequence as usize != self.frames.len()
                || frame.qpc < self.last_qpc
                || frame.qpc > observed_qpc
                || frame.qpc >= self.request.work_cutoff_qpc
            {
                return Err(invalid());
            }
            match &frame.result {
                ResultKind::Begin {
                    observer,
                    threads,
                    omitted,
                } if *observer == self.observer
                    && !self.begun
                    && !self.refused
                    && self.frames.is_empty()
                    && *threads as usize == self.request.threads.len()
                    && *omitted == self.request.omitted_threads =>
                {
                    self.begun = true
                }
                ResultKind::Thread(value) if self.begun && !self.refused => {
                    let expected = self.request.threads.get(self.results).ok_or_else(invalid)?;
                    if value.ordinal as usize != self.results
                        || value.tid != expected.tid
                        || value.birth != expected.birth
                        || value.before_qpc < self.last_qpc
                        || value.after_qpc < value.before_qpc
                        || value.after_qpc > frame.qpc
                        || value
                            .reported_nodes
                            .is_some_and(|n| n < value.nodes.len() as u32)
                        || value.reported_nodes.is_some() != value.cycle.is_some()
                        || (value.reported_nodes.is_some()
                            && value
                                .native_error
                                .is_some_and(|error| !matches!(error, 234 | 565)))
                        || (value.reported_nodes.is_none()
                            && (!value.nodes.is_empty() || value.complete))
                        || (value.complete
                            && (!value.binding_before
                                || !value.binding_after
                                || value.native_error.is_some()
                                || value.nodes.is_empty()
                                || value.reported_nodes.map(|n| n as usize)
                                    != Some(value.nodes.len())))
                    {
                        return Err(invalid());
                    }
                    let valid_lifecycle = match value.lifecycle {
                        ThreadLifecycle::QueriedLive => {
                            value.exit_status.is_none()
                                && value.binding_before
                                && value.binding_after
                        }
                        ThreadLifecycle::ExitedBeforeQuery => {
                            value.exit_status.is_some()
                                && !value.binding_before
                                && !value.binding_after
                                && !value.complete
                                && value.native_error.is_none()
                                && value.reported_nodes.is_none()
                                && value.cycle.is_none()
                                && value.nodes.is_empty()
                        }
                        ThreadLifecycle::ExitedAfterQuery => {
                            value.exit_status.is_some()
                                && value.binding_before
                                && !value.binding_after
                                && !value.complete
                        }
                    };
                    if !valid_lifecycle {
                        return Err(invalid());
                    }
                    if value.lifecycle != ThreadLifecycle::ExitedBeforeQuery {
                        self.queried += 1;
                    }
                    self.results += 1;
                }
                ResultKind::Refused {
                    stage,
                    native_error,
                    binding_failure,
                } if self.begun && !self.refused => {
                    if *stage == Stage::Binding {
                        let failure = binding_failure.as_ref().ok_or_else(invalid)?;
                        if *native_error != failure.native_error {
                            return Err(invalid());
                        }
                        failure.validate(&self.request, self.results, self.last_qpc, frame.qpc)?;
                        if failure.boundary == BindingBoundary::AfterQuery {
                            if failure.ordinal.is_none() {
                                return Err(invalid());
                            }
                            self.queried += 1;
                        }
                    } else if binding_failure.is_some() {
                        return Err(invalid());
                    }
                    self.refused = true;
                }
                ResultKind::End {
                    processed,
                    queried,
                    complete,
                } if (self.begun || self.refused)
                    && *processed as usize == self.results
                    && *queried as usize == self.queried =>
                {
                    if self.results != self.request.threads.len() && !self.refused {
                        return Err(invalid());
                    }
                    if *complete
                        && (self.refused
                            || self.results != self.request.threads.len()
                            || self.queried != self.results
                            || self.request.omitted_threads != 0
                            || self
                                .frames
                                .iter()
                                .any(|f| matches!(&f.result,ResultKind::Thread(t) if !t.complete)))
                    {
                        return Err(invalid());
                    }
                    self.ended = true;
                }
                _ => return Err(invalid()),
            }
            self.last_qpc = frame.qpc;
            self.pending.drain(..prefix + length);
            self.frames.push(frame);
        }
    }
    pub fn frames(&self) -> &[Frame] {
        &self.frames
    }
    pub fn ended(&self) -> bool {
        self.ended && !self.failed && self.pending.is_empty()
    }
    pub fn finish_input(&self) -> io::Result<()> {
        if self.ended() { Ok(()) } else { Err(invalid()) }
    }
}

fn put<const N: usize>(out: &mut Vec<u8>, bytes: [u8; N]) {
    out.extend_from_slice(&bytes);
}
fn put_identity(out: &mut Vec<u8>, id: Identity) {
    put(out, id.pid.to_le_bytes());
    put(out, id.birth.to_le_bytes());
}
fn put_error(out: &mut Vec<u8>, error: Option<u32>) {
    out.push(u8::from(error.is_some()));
    put(out, error.unwrap_or(0).to_le_bytes());
}
fn put_binding_identity(out: &mut Vec<u8>, identity: BindingIdentity) {
    put_error(out, identity.pid);
    put_error(out, identity.tid);
    out.push(u8::from(identity.birth.is_some()));
    put(out, identity.birth.unwrap_or(0).to_le_bytes());
}
fn put_failure(out: &mut Vec<u8>, failure: Option<BindingFailure>) {
    out.push(u8::from(failure.is_some()));
    if let Some(failure) = failure {
        for value in [
            failure.scope as u32,
            failure.boundary as u32,
            failure.operation as u32,
            failure.reason as u32,
        ] {
            put(out, value.to_le_bytes());
        }
        put_error(out, failure.ordinal);
        put_binding_identity(out, failure.expected);
        put_binding_identity(out, failure.observed);
        put_error(out, failure.wait_status);
        put_error(out, failure.native_error);
        put(out, failure.before_qpc.to_le_bytes());
        put(out, failure.after_qpc.to_le_bytes());
    }
}
struct Input<'a>(&'a [u8]);
impl Input<'_> {
    fn binding_identity(&mut self) -> io::Result<BindingIdentity> {
        let pid = self.error()?;
        let tid = self.error()?;
        let present = self.boolean()?;
        let birth = u128::from_le_bytes(self.array()?);
        if !present && birth != 0 {
            return Err(invalid());
        }
        Ok(BindingIdentity {
            pid,
            tid,
            birth: present.then_some(birth),
        })
    }
    fn binding_failure(&mut self) -> io::Result<Option<BindingFailure>> {
        if !self.boolean()? {
            return Ok(None);
        }
        let scope = match self.u32()? {
            1 => BindingScope::Process,
            2 => BindingScope::Thread,
            _ => return Err(invalid()),
        };
        let boundary = match self.u32()? {
            1 => BindingBoundary::BeforeQuery,
            2 => BindingBoundary::AfterQuery,
            _ => return Err(invalid()),
        };
        let operation = match self.u32()? {
            1 => BindingOperation::Wait,
            2 => BindingOperation::GetId,
            3 => BindingOperation::GetOwner,
            4 => BindingOperation::GetTimes,
            5 => BindingOperation::CompareIdentity,
            6 => BindingOperation::GetExitCode,
            _ => return Err(invalid()),
        };
        let reason = match self.u32()? {
            1 => BindingReason::Exited,
            2 => BindingReason::NativeError,
            3 => BindingReason::IdentityMismatch,
            4 => BindingReason::UnexpectedWait,
            _ => return Err(invalid()),
        };
        Ok(Some(BindingFailure {
            scope,
            boundary,
            operation,
            reason,
            ordinal: self.error()?,
            expected: self.binding_identity()?,
            observed: self.binding_identity()?,
            wait_status: self.error()?,
            native_error: self.error()?,
            before_qpc: self.u64()?,
            after_qpc: self.u64()?,
        }))
    }
    fn array<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        let bytes = self.0.get(..N).ok_or_else(invalid)?;
        let out = bytes.try_into().map_err(|_| invalid())?;
        self.0 = &self.0[N..];
        Ok(out)
    }
    fn magic(&mut self, expected: &[u8]) -> io::Result<()> {
        if !self.0.starts_with(expected) {
            return Err(invalid());
        }
        self.0 = &self.0[expected.len()..];
        Ok(())
    }
    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn boolean(&mut self) -> io::Result<bool> {
        match self.array::<1>()?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid()),
        }
    }
    fn error(&mut self) -> io::Result<Option<u32>> {
        let present = self.boolean()?;
        let value = self.u32()?;
        if !present && value != 0 {
            return Err(invalid());
        }
        Ok(present.then_some(value))
    }
    fn identity(&mut self) -> io::Result<Identity> {
        Ok(Identity {
            pid: self.u32()?,
            birth: u128::from_le_bytes(self.array()?),
        })
    }
    fn end(self) -> io::Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}
