//! Fixed client-thread observations, separate from launch authority and equality.
use memcordon_core::{
    PublicProviderBindingV1, WindowsProcessIdentityV1, WindowsWorkloadAcceptedV1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_BYTES: usize = 64 * 1024;
pub const MAX_PRIVILEGES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PrivilegeTuple {
    pub high: i32,
    pub low: u32,
    pub attributes: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DigestKind {
    LengthPrefixedLeLuidAttributesV1,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Privileges {
    pub digest_kind: DigestKind,
    pub total_count: u32,
    pub enabled_count: u32,
    pub all_sha256: [u8; 32],
    pub enabled_sha256: [u8; 32],
}
pub fn summarize(values: &[PrivilegeTuple]) -> Result<Privileges, Stage> {
    if values.len() > MAX_PRIVILEGES {
        return Err(Stage::CountBound);
    }
    let mut sorted = Vec::new();
    sorted
        .try_reserve_exact(values.len())
        .map_err(|_| Stage::Allocation)?;
    sorted.extend_from_slice(values);
    sorted.sort();
    let mut all = Sha256::new();
    let mut enabled = Sha256::new();
    let length =
        u32::try_from(size_of::<i32>() + 2 * size_of::<u32>()).map_err(|_| Stage::Encoding)?;
    let mut enabled_count = 0;
    for value in &sorted {
        let append = |hash: &mut Sha256| {
            hash.update(length.to_le_bytes());
            hash.update(value.high.to_le_bytes());
            hash.update(value.low.to_le_bytes());
            hash.update(value.attributes.to_le_bytes());
        };
        append(&mut all);
        // SE_PRIVILEGE_ENABLED selects entries; every attribute bit is retained.
        if value.attributes & 0x2 != 0 {
            enabled_count += 1;
            append(&mut enabled);
        }
    }
    Ok(Privileges {
        digest_kind: DigestKind::LengthPrefixedLeLuidAttributesV1,
        total_count: values.len() as u32,
        enabled_count,
        all_sha256: all.finalize().into(),
        enabled_sha256: enabled.finalize().into(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    ThreadToken,
    ProcessPrimaryAfterNoThreadToken,
}
pub fn permits_process_fallback(native_error: Option<i32>) -> bool {
    native_error == Some(1008) // ERROR_NO_TOKEN, never an access-denied fallback.
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    Cutoff,
    ProcessIdentity,
    ThreadTokenOpen,
    ProcessTokenOpen,
    Statistics,
    PrivilegesQuery,
    Extent,
    CountBound,
    Allocation,
    Encoding,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenFacts {
    pub source: Source,
    pub token_id: u64,
    pub modified_id: u64,
    pub authentication_id: u64,
    pub token_type: u32,
    /// Native level is undefined for primary tokens and is deliberately absent.
    pub impersonation_level: Option<u32>,
    pub statistics_group_count: u32,
    pub statistics_privilege_count: u32,
    pub privileges: Privileges,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Token {
    Unavailable {
        stage: Stage,
        native_win32_error: Option<i32>,
    },
    Observed {
        facts: Box<TokenFacts>,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Sample {
    Missing {},
    Unavailable {
        stage: Stage,
        native_win32_error: Option<i32>,
    },
    Observed {
        process: WindowsProcessIdentityV1,
        thread_id: u32,
        started_tick_ms: u64,
        finished_tick_ms: u64,
        token: Token,
    },
}
impl Default for Sample {
    fn default() -> Self {
        Self::Missing {}
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FrameResult {
    NotReached,
    ReturnedOk,
    ReturnedError,
}
/// The original result is materialized before any post-write native query.
pub fn after_io<T, E>(result: Result<T, E>, observe: impl FnOnce(FrameResult)) -> Result<T, E> {
    observe(if result.is_ok() {
        FrameResult::ReturnedOk
    } else {
        FrameResult::ReturnedError
    });
    result
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Connection {
    pub attempt_ordinal: u32,
    pub desired_access: u32,
    pub share_mode: u32,
    pub creation_disposition: u32,
    pub flags_and_attributes: u32,
    pub before_create_file: Sample,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    #[serde(deserialize_with = "memcordon_core::deserialize_bounded_record_text::<_,128>")]
    pub nonce: String,
    #[serde(deserialize_with = "memcordon_core::deserialize_bounded_record_text::<_,64>")]
    pub request_sha256: String,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Binding {
    RequestMissing,
    AcceptedMissing,
    AcceptedReceipt,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BindingError {
    RequestCustodyUnavailable,
    ReceiptMismatch,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TokenScope {
    PrivilegeTuplesAndTokenStatistics,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    #[serde(deserialize_with = "memcordon_core::deserialize_bounded_record_text::<_,128>")]
    pub format: String,
    pub revision: u32,
    pub token_scope: TokenScope,
    pub expected_provider: PublicProviderBindingV1,
    pub connection: Option<Connection>,
    pub before_launch_frame_call: Sample,
    pub after_launch_frame_call: Sample,
    pub frame_result: FrameResult,
    pub request: Option<Request>,
    pub accepted: Option<WindowsWorkloadAcceptedV1>,
    pub binding: Binding,
    pub binding_error: Option<BindingError>,
}
impl Record {
    pub fn new(provider: PublicProviderBindingV1) -> Self {
        Self {
            format: "memcordon.windows-client-input-observation".into(),
            revision: 1,
            token_scope: TokenScope::PrivilegeTuplesAndTokenStatistics,
            expected_provider: provider,
            connection: None,
            before_launch_frame_call: Sample::default(),
            after_launch_frame_call: Sample::default(),
            frame_result: FrameResult::NotReached,
            request: None,
            accepted: None,
            binding: Binding::RequestMissing,
            binding_error: None,
        }
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.format != "memcordon.windows-client-input-observation"
            || self.revision != 1
            || !self.expected_provider.is_consistent()
        {
            return Err("client observation provider differs");
        }
        if let Some(connection) = &self.connection {
            if connection.attempt_ordinal == 0 || connection.attempt_ordinal > 100 {
                return Err("client connection ordinal differs");
            }
        }
        for sample in self
            .connection
            .iter()
            .map(|value| &value.before_create_file)
            .chain([
                &self.before_launch_frame_call,
                &self.after_launch_frame_call,
            ])
        {
            if let Sample::Observed {
                process,
                thread_id,
                started_tick_ms,
                finished_tick_ms,
                token,
            } = sample
            {
                if process.process_id == 0
                    || process.creation_time_100ns == 0
                    || *thread_id == 0
                    || finished_tick_ms < started_tick_ms
                {
                    return Err("client sample identity or clock differs");
                }
                if let Token::Observed { facts } = token {
                    if !matches!(
                        (facts.token_type, facts.impersonation_level),
                        (1, None) | (2, Some(0..=3))
                    ) || facts.privileges.total_count > MAX_PRIVILEGES as u32
                        || facts.privileges.enabled_count > facts.privileges.total_count
                    {
                        return Err("client token observation differs");
                    }
                }
                if self
                    .accepted
                    .as_ref()
                    .is_some_and(|accepted| accepted.frontend != *process)
                {
                    return Err("client sample differs from accepted frontend");
                }
            }
        }
        if let Some(request) = &self.request {
            if request.nonce.is_empty()
                || request.nonce.len() > 128
                || request.request_sha256.len() != size_of::<[u8; 32]>() * 2
                || !request
                    .request_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                return Err("client request binding differs");
            }
        }
        match (self.binding, self.request.as_ref(), self.accepted.as_ref()) {
            (Binding::RequestMissing, None, None) | (Binding::AcceptedMissing, Some(_), None) => {}
            (Binding::AcceptedReceipt, Some(request), Some(accepted)) => {
                accepted.validate()?;
                if accepted.provider != self.expected_provider
                    || accepted.nonce != request.nonce
                    || accepted.request_sha256 != request.request_sha256
                    || self.frame_result != FrameResult::ReturnedOk
                    || self.binding_error.is_some()
                {
                    return Err("client accepted receipt differs");
                }
            }
            _ => return Err("client observation binding state differs"),
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate().map_err(str::to_owned)?;
        memcordon_core::bounded_json_bytes(self, MAX_BYTES, false)
            .map_err(|error| error.to_string())
    }
}
