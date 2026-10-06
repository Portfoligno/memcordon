//! Hidden original-binary transaction interface restricted to owned loopback fixtures.
use super::{
    http::{self, Response, Transport},
    publish::{Credentials, Publisher},
    rehearsal_input::RehearsalInput,
};
use crate::{CiError, Result, rehearsal_support::protocol::*};
use std::{
    fs,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use url::Url;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum TransactionResult {
    Complete {
        summary: super::publish::PublicationSummary,
    },
    Incomplete {
        summary: super::publish::PublicationSummary,
    },
    ObservationRejected {
        detail: String,
    },
}

pub struct LoopbackTransport {
    endpoint: FixtureRecord,
}
impl LoopbackTransport {
    pub fn new(endpoint: FixtureRecord) -> Result<Self> {
        if endpoint.revision != REVISION
            || !endpoint.address.ip().is_loopback()
            || endpoint.address.port() == 0
            || endpoint.session.is_empty()
            || endpoint.session.len() > 128
            || !endpoint
                .session
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(CiError::Message(
                "invalid numeric loopback fixture record".into(),
            ));
        }
        Ok(Self { endpoint })
    }
    pub fn deadline(&self) -> Result<Instant> {
        let now = unix_ms()?;
        let remaining = self
            .endpoint
            .expires_unix_ms
            .checked_sub(now)
            .filter(|value| *value > 0)
            .ok_or_else(|| CiError::Message("fixture operation deadline expired".into()))?;
        if remaining > self.endpoint.budget.seconds() * 1000 {
            return Err(CiError::Message(
                "fixture budget exceeds finite preset".into(),
            ));
        }
        Ok(Instant::now() + Duration::from_millis(remaining))
    }
}
pub fn unix_ms() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CiError::Message("system clock precedes epoch".into()))?
            .as_millis(),
    )
    .map_err(|_| CiError::Message("system clock exceeds bound".into()))
}
pub fn service(logical: &Url) -> Result<FixtureService> {
    http::validate_https(logical)?;
    if logical.port_or_known_default() != Some(443) {
        return Err(CiError::Message(
            "fixture logical service port differs".into(),
        ));
    }
    match logical.host_str() {
        Some("api.github.com") => Ok(FixtureService::GithubApi),
        Some("uploads.github.com") => Ok(FixtureService::GithubUpload),
        Some("crates.io") if logical.path() == "/api/v1/crates/new" => {
            Ok(FixtureService::RegistryUpload)
        }
        Some("index.crates.io") => Ok(FixtureService::RegistryIndex),
        Some("static.crates.io") => Ok(FixtureService::RegistryDownload),
        Some("memcordon-rehearsal.invalid") => Ok(FixtureService::Redirect),
        _ => Err(CiError::Message(
            "logical destination outside fixture allowlist".into(),
        )),
    }
}
impl Transport for LoopbackTransport {
    fn request(
        &self,
        method: &str,
        logical: &Url,
        headers: &[(String, String)],
        body: &[u8],
        deadline: Instant,
        maximum: u64,
    ) -> Result<Response> {
        let role = service(logical)?;
        let mut physical = Url::parse("http://127.0.0.1").expect("constant URL");
        physical
            .set_ip_host((*self.endpoint.address.ip()).into())
            .map_err(|_| CiError::Message("fixture address differs".into()))?;
        physical
            .set_port(Some(self.endpoint.address.port()))
            .map_err(|_| CiError::Message("fixture port differs".into()))?;
        physical.set_path(logical.path());
        physical.set_query(logical.query());
        let mut selected = headers.to_vec();
        if selected.iter().any(|(name, _)| {
            name.eq_ignore_ascii_case(SERVICE_HEADER) || name.eq_ignore_ascii_case(SESSION_HEADER)
        }) {
            return Err(CiError::Message(
                "fixture admission header collision".into(),
            ));
        }
        selected.push((SERVICE_HEADER.into(), role.as_str().into()));
        selected.push((SESSION_HEADER.into(), self.endpoint.session.clone()));
        http::wire_request(
            method,
            &physical,
            &selected,
            body,
            deadline.min(self.deadline()?),
            maximum,
            true,
        )
    }
}

pub fn transaction(input: &Path, fixture: &Path, result: &Path) -> Result<()> {
    // Local validation precedes transport and credentials; never promote candidates.
    let loaded = RehearsalInput::load(input)?;
    let bytes = super::artifacts::read_file(fixture)?;
    if bytes.len() > 16 * 1024 {
        return Err(CiError::Message("fixture record exceeds bound".into()));
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).map_err(CiError::Message)?;
    let endpoint: FixtureRecord = serde_json::from_slice(&bytes)?;
    let transport = LoopbackTransport::new(endpoint)?;
    let credentials = Credentials::for_transport(GITHUB_TOKEN.into(), Some(REGISTRY_TOKEN.into()))?;
    let fixture_ref = format!("refs/tags/{}", loaded.version());
    let observed = Publisher::from_view(
        &transport,
        &credentials,
        loaded.view(&fixture_ref),
        transport.deadline()?,
    )
    .publish();
    let (verdict, complete) = match observed {
        Ok(summary) if summary.complete => (TransactionResult::Complete { summary }, true),
        Ok(summary) => (TransactionResult::Incomplete { summary }, false),
        Err(error) => (
            TransactionResult::ObservationRejected {
                detail: error.to_string(),
            },
            false,
        ),
    };
    let bytes = serde_json::to_vec_pretty(&verdict)?;
    if bytes.len() > 1024 * 1024 {
        return Err(CiError::Message("transaction summary exceeds bound".into()));
    }
    if result.exists() {
        return Err(CiError::Message("transaction result must be fresh".into()));
    }
    fs::write(result, bytes)?;
    if !complete {
        return Err(CiError::Message(
            "fixture publication rejected or remains incomplete".into(),
        ));
    }
    Ok(())
}
