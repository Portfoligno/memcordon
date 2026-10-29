//! Independent decoding of the actual caller start bytes retained before release.
use crate::{NativeArguments, VerificationResult};
use serde_json::Value;
use sha2::{Digest, Sha256};

struct Cursor<'a> {
    raw: &'a [u8],
    position: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> VerificationResult<&'a [u8]> {
        let end = self
            .position
            .checked_add(count)
            .ok_or("native cursor overflow")?;
        let value = self
            .raw
            .get(self.position..end)
            .ok_or("truncated native launch")?;
        self.position = end;
        Ok(value)
    }
    fn byte(&mut self) -> VerificationResult<u8> {
        Ok(self.take(1)?[0])
    }
    fn word(&mut self) -> VerificationResult<usize> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| "native word width")?) as usize)
    }
    fn scalar(&mut self) -> VerificationResult<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| "native scalar width")?,
        ))
    }
    fn value(&mut self) -> VerificationResult<Vec<u8>> {
        let length = self.word()?;
        if length > 65536 {
            return Err("native value exceeds bound".into());
        }
        let value = self.take(length)?;
        if value.contains(&0) {
            return Err("native argument/environment contains NUL".into());
        }
        Ok(value.to_vec())
    }
    fn optional(&mut self) -> VerificationResult<Option<u64>> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(self.scalar()?)),
            _ => Err("unknown native optional tag".into()),
        }
    }
}

pub fn verify_start(
    bytes: &[u8],
    request: &Value,
    binding: &Value,
    input: &Value,
) -> VerificationResult<()> {
    if bytes.len() > 1024 * 1024 - 72 {
        return Err("original start payload exceeds native frame bound".into());
    }
    let start = crate::validate_json_document(bytes)?;
    let fields = [
        "format",
        "revision",
        "request",
        "native_launch",
        "working_directory",
        "attempt_deadline_millis",
    ];
    let object = start.as_object().ok_or("original start is not an object")?;
    if object.len() != fields.len()
        || object.keys().any(|name| !fields.contains(&name.as_str()))
        || start["format"] != "memcordon.workload-start"
        || start["revision"] != 1
        || start["request"] != *request
        || start["working_directory"] != input["working_directory"]
    {
        return Err(
            "actual start header/request/working directory differs from original caller request"
                .into(),
        );
    }
    let native: Vec<u8> = serde_json::from_value(start["native_launch"].clone())
        .map_err(|error| error.to_string())?;
    if native.len() > 1024 * 1024 - 72 {
        return Err("native invocation exceeds bound".into());
    }
    let cwd = if start["working_directory"].is_null() {
        None
    } else {
        let cwd = start["working_directory"]
            .as_str()
            .ok_or("private cwd is not a string")?;
        if cwd.is_empty()
            || cwd.len() > 4096
            || cwd.starts_with('/')
            || cwd.contains('\0')
            || cwd
                .split('/')
                .any(|part| part.is_empty() || matches!(part, "." | ".."))
        {
            return Err("private cwd escapes the constructed root".into());
        }
        Some(cwd)
    };
    let mut invocation = Sha256::new();
    invocation.update(b"memcordon.native-invocation/version1\0");
    invocation.update(
        u64::try_from(native.len())
            .map_err(|error| error.to_string())?
            .to_be_bytes(),
    );
    invocation.update(&native);
    invocation.update([u8::from(cwd.is_some())]);
    if let Some(cwd) = cwd {
        invocation.update(
            u64::try_from(cwd.len())
                .map_err(|error| error.to_string())?
                .to_be_bytes(),
        );
        invocation.update(cwd.as_bytes());
    }
    if binding["invocation_sha256"] != hex::encode(invocation.finalize()) {
        return Err("native invocation digest differs from exact original wire/cwd bytes".into());
    }
    let mut cursor = Cursor {
        raw: &native,
        position: 0,
    };
    if cursor.take(2)? != 3_u16.to_be_bytes() {
        return Err("native invocation codec revision differs".into());
    }
    cursor.scalar()?;
    let program = cursor.value()?;
    let count = cursor.word()?;
    if count > 4096 {
        return Err("native argv count exceeds bound".into());
    }
    let mut arguments = Vec::with_capacity(count);
    for _ in 0..count {
        arguments.push(cursor.value()?);
    }
    let expected: NativeArguments =
        serde_json::from_value(input["target_argv"].clone()).map_err(|error| error.to_string())?;
    if !matches!(expected,NativeArguments::UnixBytes(expected)if expected==arguments)
        || program != b"owned-readiness"
    {
        return Err("native program/argv differ from actual prelaunch operands".into());
    }
    let count = cursor.word()?;
    if count > 8192 {
        return Err("native environment count exceeds bound".into());
    }
    let mut names = std::collections::BTreeSet::new();
    for _ in 0..count {
        let name = cursor.value()?;
        if name.is_empty() || name.contains(&b'=') || !names.insert(name) {
            return Err("native environment key invalid or duplicated".into());
        }
        cursor.value()?;
    }
    let resource_start = cursor.position;
    let memory = cursor.optional()?;
    match cursor.byte()? {
        1 => {
            cursor.scalar()?;
        }
        2 | 3 => {}
        _ => return Err("unknown native swap policy".into()),
    }
    let absolute_deadline = cursor.optional()?;
    let scope = cursor.byte()?;
    let lifetime = cursor.byte()?;
    if !matches!(scope, 1 | 2) || !matches!(lifetime, 1 | 2) {
        return Err("unknown native deadline scope/lifetime".into());
    }
    for _ in 0..4 {
        cursor.scalar()?;
    }
    let resource_end = cursor.position;
    // The native body declares exactly the five fixed transport purposes;
    // no additional inherited descriptor or historical contract is accepted.
    if cursor.word()? != 5
        || cursor.take(5)? != [1, 2, 3, 4, 5]
        || cursor.byte()? != 0
        || cursor.position != native.len()
    {
        return Err(
            "current start contains another descriptor manifest or historical authority data"
                .into(),
        );
    }
    let duration = if start["attempt_deadline_millis"].is_null() {
        None
    } else {
        Some(
            start["attempt_deadline_millis"]
                .as_u64()
                .ok_or("native attempt duration is not an integer")?,
        )
    };
    let mut hash = Sha256::new();
    hash.update(b"memcordon.native-resource-policy/version1\0");
    hash.update(
        u64::try_from(resource_end - resource_start)
            .map_err(|error| error.to_string())?
            .to_be_bytes(),
    );
    hash.update(&native[resource_start..resource_end]);
    hash.update([u8::from(duration.is_some())]);
    if let Some(duration) = duration {
        hash.update(duration.to_be_bytes());
    }
    if binding["resource_policy_sha256"] != hex::encode(hash.finalize()) {
        return Err("resource-policy digest differs from actual original native bytes".into());
    }
    if input["memory_bytes"].as_u64() != memory
        || input["deadline_millis"].as_u64() != duration
        || scope != 1
        || absolute_deadline.is_some()
    {
        return Err(
            "actual native resource values differ from original attempt-scoped budgets".into(),
        );
    }
    let expected_lifetime = match input["lifetime"].as_str() {
        Some("command") => 1,
        Some("workload") => 2,
        _ => return Err("original prelaunch lifetime absent".into()),
    };
    if lifetime != expected_lifetime {
        return Err("actual native lifetime differs from original caller selection".into());
    }
    Ok(())
}
