//! Typed, bounded launch-request payload codec.

pub const MAX_NATIVE_VALUE_LENGTH: usize = 64 * 1024;
pub const MAX_ARGUMENTS: usize = 4096;
pub const MAX_ENVIRONMENT_ENTRIES: usize = 8192;
use sha2::{Digest, Sha256};

pub const LAUNCH_REQUEST_VERSION: u16 = 2;
pub const LAUNCH_BROKER_REQUEST_VERSION: u16 = 2;
const MAX_SUPPLEMENTARY_GROUPS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DeadlineScope {
    Attempt = 1,
    Supervision = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Lifetime {
    Command = 1,
    Workload = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwapLimit {
    Bytes(u64),
    Unlimited,
    Host,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchPolicyV2 {
    pub memory_limit_bytes: Option<u64>,
    pub swap_limit: SwapLimit,
    pub absolute_deadline_millis: Option<u64>,
    pub deadline_scope: DeadlineScope,
    pub lifetime: Lifetime,
    pub poll_interval_millis: u64,
    pub signal_grace_millis: u64,
    pub command_exit_grace_millis: u64,
    pub limit_grace_millis: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchRequestV2 {
    pub program: Vec<u8>,
    pub arguments: Vec<Vec<u8>>,
    pub environment: Vec<(Vec<u8>, Vec<u8>)>,
    pub policy: LaunchPolicyV2,
    /// Exact out-of-band descriptor purposes, in transfer order.
    pub descriptors: Vec<DescriptorPurpose>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DescriptorPurpose {
    CurrentDirectory = 1,
    Stdin = 2,
    Stdout = 3,
    Stderr = 4,
    FrontendLiveness = 5,
    CallerMountNamespace = 6,
    CallerRoot = 7,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallerExecutionEnvelopeV2 {
    pub pid: i32,
    pub process_start_time: u64,
    pub uid: u32,
    pub gid: u32,
    pub supplementary_groups: Vec<u32>,
    pub no_new_privs: bool,
    pub capability_bounding_set: u64,
    pub mount_namespace_identity: NamespaceIdentity,
    pub pid_namespace_identity: NamespaceIdentity,
    pub user_namespace_identity: NamespaceIdentity,
    pub network_namespace_identity: NamespaceIdentity,
    pub ipc_namespace_identity: NamespaceIdentity,
    pub uts_namespace_identity: NamespaceIdentity,
    pub time_namespace_identity: NamespaceIdentity,
    pub current_directory_identity: FileIdentity,
    pub root_identity: FileIdentity,
}

impl CallerExecutionEnvelopeV2 {
    pub fn digest(&self) -> [u8; 32] {
        let mut encoded = Vec::new();
        encode_caller_envelope(&mut encoded, self)
            .expect("validated caller envelope always has a bounded encoding");
        Sha256::digest(encoded).into()
    }

    pub fn digest_hex(&self) -> String {
        self.digest()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordIdentityV2 {
    pub attempt_id: [u8; 16],
    pub caller_envelope_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchBrokerRequestV2 {
    pub attempt_id: [u8; 16],
    pub request_digest: [u8; 32],
    pub control_process_id: i32,
    pub control_process_start_time: u64,
    pub launch: LaunchRequestV2,
    pub caller: CallerExecutionEnvelopeV2,
    pub descriptor_manifest: Vec<DescriptorPurpose>,
    pub record_identity: RecordIdentityV2,
    pub request_authentication_binding: [u8; 32],
}

impl LaunchBrokerRequestV2 {
    pub fn authenticated(
        attempt_id: [u8; 16],
        request_digest: [u8; 32],
        control_process_id: i32,
        control_process_start_time: u64,
        launch: LaunchRequestV2,
        caller: CallerExecutionEnvelopeV2,
        descriptor_manifest: Vec<DescriptorPurpose>,
    ) -> Result<Self, RequestCodecError> {
        let record_identity = RecordIdentityV2 {
            attempt_id,
            caller_envelope_digest: caller.digest(),
        };
        let mut request = Self {
            attempt_id,
            request_digest,
            control_process_id,
            control_process_start_time,
            launch,
            caller,
            descriptor_manifest,
            record_identity,
            request_authentication_binding: [0; 32],
        };
        request.request_authentication_binding = request.expected_authentication_binding();
        validate_broker_request(&request)?;
        Ok(request)
    }

    fn expected_authentication_binding(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"memcordon-launch-broker-request-v2\0");
        digest.update(self.attempt_id);
        digest.update(self.request_digest);
        digest.update(self.control_process_id.to_be_bytes());
        digest.update(self.control_process_start_time.to_be_bytes());
        digest.update(self.caller.digest());
        digest.update(self.record_identity.attempt_id);
        digest.update(self.record_identity.caller_envelope_digest);
        digest.update(
            self.descriptor_manifest
                .iter()
                .map(|purpose| *purpose as u8)
                .collect::<Vec<_>>(),
        );
        digest.finalize().into()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestCodecError {
    Truncated,
    UnsupportedVersion(u16),
    InvalidValue,
    ValueTooLarge,
    TooManyArguments,
    TooManyEnvironmentEntries,
    TrailingBytes,
}

pub fn encode_launch_request(request: &LaunchRequestV2) -> Result<Vec<u8>, RequestCodecError> {
    validate_request(request)?;
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&LAUNCH_REQUEST_VERSION.to_be_bytes());
    put_bytes(&mut encoded, &request.program)?;
    put_count(&mut encoded, request.arguments.len())?;
    for argument in &request.arguments {
        put_bytes(&mut encoded, argument)?;
    }
    put_count(&mut encoded, request.environment.len())?;
    for (name, value) in &request.environment {
        put_bytes(&mut encoded, name)?;
        put_bytes(&mut encoded, value)?;
    }
    put_optional_u64(&mut encoded, request.policy.memory_limit_bytes);
    match request.policy.swap_limit {
        SwapLimit::Bytes(bytes) => {
            encoded.push(1);
            encoded.extend_from_slice(&bytes.to_be_bytes());
        }
        SwapLimit::Unlimited => encoded.push(2),
        SwapLimit::Host => encoded.push(3),
    }
    put_optional_u64(&mut encoded, request.policy.absolute_deadline_millis);
    encoded.push(request.policy.deadline_scope as u8);
    encoded.push(request.policy.lifetime as u8);
    encoded.extend_from_slice(&request.policy.poll_interval_millis.to_be_bytes());
    encoded.extend_from_slice(&request.policy.signal_grace_millis.to_be_bytes());
    encoded.extend_from_slice(&request.policy.command_exit_grace_millis.to_be_bytes());
    encoded.extend_from_slice(&request.policy.limit_grace_millis.to_be_bytes());
    put_count(&mut encoded, request.descriptors.len())?;
    encoded.extend(request.descriptors.iter().map(|purpose| *purpose as u8));
    Ok(encoded)
}

pub fn decode_launch_request(payload: &[u8]) -> Result<LaunchRequestV2, RequestCodecError> {
    let mut cursor = Cursor::new(payload);
    let version = cursor.u16()?;
    if version != LAUNCH_REQUEST_VERSION {
        return Err(RequestCodecError::UnsupportedVersion(version));
    }
    let program = cursor.bytes()?;
    let argument_count = cursor.count()?;
    if argument_count > MAX_ARGUMENTS {
        return Err(RequestCodecError::TooManyArguments);
    }
    let mut arguments = Vec::with_capacity(argument_count);
    for _ in 0..argument_count {
        arguments.push(cursor.bytes()?);
    }
    let environment_count = cursor.count()?;
    if environment_count > MAX_ENVIRONMENT_ENTRIES {
        return Err(RequestCodecError::TooManyEnvironmentEntries);
    }
    let mut environment = Vec::with_capacity(environment_count);
    for _ in 0..environment_count {
        environment.push((cursor.bytes()?, cursor.bytes()?));
    }
    let memory_limit_bytes = cursor.optional_u64()?;
    let swap_limit = match cursor.u8()? {
        1 => SwapLimit::Bytes(cursor.u64()?),
        2 => SwapLimit::Unlimited,
        3 => SwapLimit::Host,
        _ => return Err(RequestCodecError::InvalidValue),
    };
    let absolute_deadline_millis = cursor.optional_u64()?;
    let deadline_scope = match cursor.u8()? {
        1 => DeadlineScope::Attempt,
        2 => DeadlineScope::Supervision,
        _ => return Err(RequestCodecError::InvalidValue),
    };
    let lifetime = match cursor.u8()? {
        1 => Lifetime::Command,
        2 => Lifetime::Workload,
        _ => return Err(RequestCodecError::InvalidValue),
    };
    let poll_interval_millis = cursor.u64()?;
    let signal_grace_millis = cursor.u64()?;
    let command_exit_grace_millis = cursor.u64()?;
    let limit_grace_millis = cursor.u64()?;
    let descriptor_count = cursor.count()?;
    if descriptor_count > 5 {
        return Err(RequestCodecError::InvalidValue);
    }
    let mut descriptors = Vec::with_capacity(descriptor_count);
    for _ in 0..descriptor_count {
        descriptors.push(match cursor.u8()? {
            1 => DescriptorPurpose::CurrentDirectory,
            2 => DescriptorPurpose::Stdin,
            3 => DescriptorPurpose::Stdout,
            4 => DescriptorPurpose::Stderr,
            5 => DescriptorPurpose::FrontendLiveness,
            _ => return Err(RequestCodecError::InvalidValue),
        });
    }
    if !cursor.is_empty() {
        return Err(RequestCodecError::TrailingBytes);
    }
    let request = LaunchRequestV2 {
        program,
        arguments,
        environment,
        policy: LaunchPolicyV2 {
            memory_limit_bytes,
            swap_limit,
            absolute_deadline_millis,
            deadline_scope,
            lifetime,
            poll_interval_millis,
            signal_grace_millis,
            command_exit_grace_millis,
            limit_grace_millis,
        },
        descriptors,
    };
    validate_request(&request)?;
    Ok(request)
}

pub fn encode_launch_broker_request(
    request: &LaunchBrokerRequestV2,
) -> Result<Vec<u8>, RequestCodecError> {
    validate_request(&request.launch)?;
    validate_broker_request(request)?;
    let public = encode_launch_request(&request.launch)?;
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&LAUNCH_BROKER_REQUEST_VERSION.to_be_bytes());
    encoded.extend_from_slice(&request.attempt_id);
    encoded.extend_from_slice(&request.request_digest);
    encoded.extend_from_slice(&request.control_process_id.to_be_bytes());
    encoded.extend_from_slice(&request.control_process_start_time.to_be_bytes());
    put_bytes(&mut encoded, &public)?;
    encode_caller_envelope(&mut encoded, &request.caller)?;
    put_count(&mut encoded, request.descriptor_manifest.len())?;
    encoded.extend(
        request
            .descriptor_manifest
            .iter()
            .map(|purpose| *purpose as u8),
    );
    encoded.extend_from_slice(&request.record_identity.attempt_id);
    encoded.extend_from_slice(&request.record_identity.caller_envelope_digest);
    encoded.extend_from_slice(&request.request_authentication_binding);
    Ok(encoded)
}

pub fn decode_launch_broker_request(
    payload: &[u8],
) -> Result<LaunchBrokerRequestV2, RequestCodecError> {
    let mut cursor = Cursor::new(payload);
    let version = cursor.u16()?;
    if version != LAUNCH_BROKER_REQUEST_VERSION {
        return Err(RequestCodecError::UnsupportedVersion(version));
    }
    let attempt_id = cursor
        .take(16)?
        .try_into()
        .expect("attempt identity length is exact");
    let request_digest = cursor
        .take(32)?
        .try_into()
        .expect("request digest length is exact");
    let control_process_id = cursor.i32()?;
    let control_process_start_time = cursor.u64()?;
    let launch = decode_launch_request(&cursor.bytes()?)?;
    let caller = decode_caller_envelope(&mut cursor)?;
    let descriptor_count = cursor.count()?;
    if descriptor_count > 7 {
        return Err(RequestCodecError::InvalidValue);
    }
    let mut descriptor_manifest = Vec::with_capacity(descriptor_count);
    for _ in 0..descriptor_count {
        descriptor_manifest.push(match cursor.u8()? {
            1 => DescriptorPurpose::CurrentDirectory,
            2 => DescriptorPurpose::Stdin,
            3 => DescriptorPurpose::Stdout,
            4 => DescriptorPurpose::Stderr,
            5 => DescriptorPurpose::FrontendLiveness,
            6 => DescriptorPurpose::CallerMountNamespace,
            7 => DescriptorPurpose::CallerRoot,
            _ => return Err(RequestCodecError::InvalidValue),
        });
    }
    let record_identity = RecordIdentityV2 {
        attempt_id: cursor
            .take(16)?
            .try_into()
            .expect("record attempt identity length is exact"),
        caller_envelope_digest: cursor
            .take(32)?
            .try_into()
            .expect("record caller digest length is exact"),
    };
    let request_authentication_binding: [u8; 32] = cursor
        .take(32)?
        .try_into()
        .expect("request authentication binding length is exact");
    if !cursor.is_empty() {
        return Err(RequestCodecError::TrailingBytes);
    }
    let request = LaunchBrokerRequestV2 {
        attempt_id,
        request_digest,
        control_process_id,
        control_process_start_time,
        launch,
        caller,
        descriptor_manifest,
        record_identity,
        request_authentication_binding,
    };
    validate_broker_request(&request)?;
    Ok(request)
}

fn encode_caller_envelope(
    encoded: &mut Vec<u8>,
    caller: &CallerExecutionEnvelopeV2,
) -> Result<(), RequestCodecError> {
    if caller.pid <= 0 || caller.supplementary_groups.len() > MAX_SUPPLEMENTARY_GROUPS {
        return Err(RequestCodecError::InvalidValue);
    }
    encoded.extend_from_slice(&caller.pid.to_be_bytes());
    encoded.extend_from_slice(&caller.process_start_time.to_be_bytes());
    encoded.extend_from_slice(&caller.uid.to_be_bytes());
    encoded.extend_from_slice(&caller.gid.to_be_bytes());
    put_count(encoded, caller.supplementary_groups.len())?;
    for group in &caller.supplementary_groups {
        encoded.extend_from_slice(&group.to_be_bytes());
    }
    encoded.push(u8::from(caller.no_new_privs));
    encoded.extend_from_slice(&caller.capability_bounding_set.to_be_bytes());
    for identity in [
        caller.mount_namespace_identity,
        caller.pid_namespace_identity,
        caller.user_namespace_identity,
        caller.network_namespace_identity,
        caller.ipc_namespace_identity,
        caller.uts_namespace_identity,
        caller.time_namespace_identity,
    ] {
        encoded.extend_from_slice(&identity.device.to_be_bytes());
        encoded.extend_from_slice(&identity.inode.to_be_bytes());
    }
    for identity in [caller.current_directory_identity, caller.root_identity] {
        encoded.extend_from_slice(&identity.device.to_be_bytes());
        encoded.extend_from_slice(&identity.inode.to_be_bytes());
    }
    Ok(())
}

fn decode_caller_envelope(
    cursor: &mut Cursor<'_>,
) -> Result<CallerExecutionEnvelopeV2, RequestCodecError> {
    let pid = cursor.i32()?;
    let process_start_time = cursor.u64()?;
    let uid = cursor.u32()?;
    let gid = cursor.u32()?;
    let group_count = cursor.count()?;
    if pid <= 0 || group_count > MAX_SUPPLEMENTARY_GROUPS {
        return Err(RequestCodecError::InvalidValue);
    }
    let mut supplementary_groups = Vec::with_capacity(group_count);
    for _ in 0..group_count {
        supplementary_groups.push(cursor.u32()?);
    }
    let no_new_privs = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => return Err(RequestCodecError::InvalidValue),
    };
    let capability_bounding_set = cursor.u64()?;
    let mut namespace = || {
        Ok(NamespaceIdentity {
            device: cursor.u64()?,
            inode: cursor.u64()?,
        })
    };
    let mount_namespace_identity = namespace()?;
    let pid_namespace_identity = namespace()?;
    let user_namespace_identity = namespace()?;
    let network_namespace_identity = namespace()?;
    let ipc_namespace_identity = namespace()?;
    let uts_namespace_identity = namespace()?;
    let time_namespace_identity = namespace()?;
    let current_directory_identity = FileIdentity {
        device: cursor.u64()?,
        inode: cursor.u64()?,
    };
    let root_identity = FileIdentity {
        device: cursor.u64()?,
        inode: cursor.u64()?,
    };
    Ok(CallerExecutionEnvelopeV2 {
        pid,
        process_start_time,
        uid,
        gid,
        supplementary_groups,
        no_new_privs,
        capability_bounding_set,
        mount_namespace_identity,
        pid_namespace_identity,
        user_namespace_identity,
        network_namespace_identity,
        ipc_namespace_identity,
        uts_namespace_identity,
        time_namespace_identity,
        current_directory_identity,
        root_identity,
    })
}

fn validate_broker_request(request: &LaunchBrokerRequestV2) -> Result<(), RequestCodecError> {
    let required = [
        DescriptorPurpose::CurrentDirectory,
        DescriptorPurpose::Stdin,
        DescriptorPurpose::Stdout,
        DescriptorPurpose::Stderr,
        DescriptorPurpose::FrontendLiveness,
        DescriptorPurpose::CallerMountNamespace,
        DescriptorPurpose::CallerRoot,
    ];
    let encoded_launch = encode_launch_request(&request.launch)?;
    let launch_digest: [u8; 32] = Sha256::digest(encoded_launch).into();
    if request.descriptor_manifest.as_slice() != required
        || request.caller.pid <= 0
        || request.caller.supplementary_groups.len() > MAX_SUPPLEMENTARY_GROUPS
        || request.control_process_id <= 0
        || request.control_process_start_time == 0
        || request.request_digest != launch_digest
        || request.record_identity.attempt_id != request.attempt_id
        || request.record_identity.caller_envelope_digest != request.caller.digest()
        || request.request_authentication_binding != request.expected_authentication_binding()
    {
        Err(RequestCodecError::InvalidValue)
    } else {
        Ok(())
    }
}

fn validate_request(request: &LaunchRequestV2) -> Result<(), RequestCodecError> {
    if request.program.is_empty()
        || request.program.contains(&0)
        || request.arguments.iter().any(|value| value.contains(&0))
        || request.environment.iter().any(|(name, value)| {
            name.is_empty() || name.contains(&0) || name.contains(&b'=') || value.contains(&0)
        })
    {
        return Err(RequestCodecError::InvalidValue);
    }
    if request.arguments.len() > MAX_ARGUMENTS {
        return Err(RequestCodecError::TooManyArguments);
    }
    if request.environment.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err(RequestCodecError::TooManyEnvironmentEntries);
    }
    let required = [
        DescriptorPurpose::CurrentDirectory,
        DescriptorPurpose::Stdin,
        DescriptorPurpose::Stdout,
        DescriptorPurpose::Stderr,
        DescriptorPurpose::FrontendLiveness,
    ];
    if request.descriptors.as_slice() != required {
        return Err(RequestCodecError::InvalidValue);
    }
    Ok(())
}

fn put_count(encoded: &mut Vec<u8>, count: usize) -> Result<(), RequestCodecError> {
    let count = u32::try_from(count).map_err(|_| RequestCodecError::ValueTooLarge)?;
    encoded.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

fn put_bytes(encoded: &mut Vec<u8>, value: &[u8]) -> Result<(), RequestCodecError> {
    if value.len() > MAX_NATIVE_VALUE_LENGTH {
        return Err(RequestCodecError::ValueTooLarge);
    }
    put_count(encoded, value.len())?;
    encoded.extend_from_slice(value);
    Ok(())
}

fn put_optional_u64(encoded: &mut Vec<u8>, value: Option<u64>) {
    encoded.push(u8::from(value.is_some()));
    if let Some(value) = value {
        encoded.extend_from_slice(&value.to_be_bytes());
    }
}

struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    const fn new(remaining: &'a [u8]) -> Self {
        Self { remaining }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], RequestCodecError> {
        let (value, remaining) = self
            .remaining
            .split_at_checked(length)
            .ok_or(RequestCodecError::Truncated)?;
        self.remaining = remaining;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, RequestCodecError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, RequestCodecError> {
        let value = self.take(2)?;
        Ok(u16::from_be_bytes([value[0], value[1]]))
    }

    fn u32(&mut self) -> Result<u32, RequestCodecError> {
        let value = self.take(4)?;
        Ok(u32::from_be_bytes(value.try_into().expect("exact length")))
    }

    fn i32(&mut self) -> Result<i32, RequestCodecError> {
        let value = self.take(4)?;
        Ok(i32::from_be_bytes(value.try_into().expect("exact length")))
    }

    fn count(&mut self) -> Result<usize, RequestCodecError> {
        let value = self.take(4)?;
        Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]) as usize)
    }

    fn u64(&mut self) -> Result<u64, RequestCodecError> {
        let value = self.take(8)?;
        Ok(u64::from_be_bytes(value.try_into().expect("exact length")))
    }

    fn bytes(&mut self) -> Result<Vec<u8>, RequestCodecError> {
        let length = self.count()?;
        if length > MAX_NATIVE_VALUE_LENGTH {
            return Err(RequestCodecError::ValueTooLarge);
        }
        Ok(self.take(length)?.to_vec())
    }

    fn optional_u64(&mut self) -> Result<Option<u64>, RequestCodecError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(RequestCodecError::InvalidValue),
        }
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}
