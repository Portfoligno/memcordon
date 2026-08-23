//! Typed, bounded launch-request payload codec.

pub const MAX_NATIVE_VALUE_LENGTH: usize = 64 * 1024;
pub const MAX_ARGUMENTS: usize = 4096;
pub const MAX_ENVIRONMENT_ENTRIES: usize = 8192;
pub const LAUNCH_REQUEST_VERSION: u16 = 1;

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
pub struct LaunchPolicyV1 {
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
pub struct LaunchRequestV1 {
    pub program: Vec<u8>,
    pub arguments: Vec<Vec<u8>>,
    pub environment: Vec<(Vec<u8>, Vec<u8>)>,
    pub policy: LaunchPolicyV1,
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

pub fn encode_launch_request(request: &LaunchRequestV1) -> Result<Vec<u8>, RequestCodecError> {
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

pub fn decode_launch_request(payload: &[u8]) -> Result<LaunchRequestV1, RequestCodecError> {
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
    let request = LaunchRequestV1 {
        program,
        arguments,
        environment,
        policy: LaunchPolicyV1 {
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

fn validate_request(request: &LaunchRequestV1) -> Result<(), RequestCodecError> {
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
