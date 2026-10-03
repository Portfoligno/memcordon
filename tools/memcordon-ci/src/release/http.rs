//! Bounded HTTPS reads share one absolute budget and throttling state.
use crate::{CiError, Result};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use url::Url;

#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

pub trait Transport: Sync {
    fn request(
        &self,
        method: &str,
        url: &Url,
        headers: &[(String, String)],
        body: &[u8],
        deadline: Instant,
        maximum: u64,
    ) -> Result<Response>;
}

#[derive(Clone, Default)]
pub struct HttpsTransport;
impl Transport for HttpsTransport {
    fn request(
        &self,
        method: &str,
        url: &Url,
        headers: &[(String, String)],
        body: &[u8],
        deadline: Instant,
        maximum: u64,
    ) -> Result<Response> {
        validate_https(url)?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
            .ok_or_else(|| CiError::Message("HTTPS operation deadline expired".into()))?;
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .timeout_global(Some(remaining))
            .timeout_connect(Some(remaining.min(Duration::from_secs(30))))
            .build()
            .into();
        let mut request = ureq::http::Request::builder()
            .method(method)
            .uri(url.as_str());
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let request = request
            .body(body)
            .map_err(|_| CiError::Message("invalid HTTPS request fields".into()))?;
        // Never include underlying HTTP errors: those may contain a URL or authorization data.
        let mut response = agent
            .run(request)
            .map_err(|_| CiError::Message("HTTPS transport failed or timed out".into()))?;
        let status = response.status().as_u16();
        let mut observed = BTreeMap::new();
        for name in [
            "location",
            "retry-after",
            "x-ratelimit-remaining",
            "x-ratelimit-reset",
            "link",
        ] {
            if let Some(value) = response.headers().get(name) {
                observed.insert(
                    name.into(),
                    value
                        .to_str()
                        .map_err(|_| CiError::Message("invalid HTTP response header".into()))?
                        .into(),
                );
            }
        }
        let bytes = response
            .body_mut()
            .with_config()
            .limit(maximum)
            .read_to_vec()
            .map_err(|_| {
                CiError::Message("HTTPS body exceeds bound or could not be read".into())
            })?;
        Ok(Response {
            status,
            headers: observed,
            body: bytes,
        })
    }
}

pub fn validate_https(url: &Url) -> Result<()> {
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port().is_some()
    {
        return Err(CiError::Message("unsupported HTTPS destination".into()));
    }
    Ok(())
}

#[derive(Clone)]
pub struct ReadBudget {
    pub deadline: Instant,
    throttle: Arc<Mutex<Instant>>,
}
impl ReadBudget {
    pub fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            throttle: Arc::new(Mutex::new(Instant::now())),
        }
    }
    fn wait(&self) -> Result<()> {
        loop {
            let next = *self
                .throttle
                .lock()
                .map_err(|_| CiError::Message("HTTP throttle owner failed".into()))?;
            let now = Instant::now();
            if now >= self.deadline {
                return Err(CiError::Message("HTTP phase deadline expired".into()));
            }
            if next <= now {
                return Ok(());
            }
            if next >= self.deadline {
                return Err(CiError::Message("HTTP retry exceeds phase deadline".into()));
            }
            std::thread::sleep((next - now).min(Duration::from_millis(100)));
        }
    }
    fn delay(&self, wait: Duration) -> Result<()> {
        let next = Instant::now()
            .checked_add(wait)
            .ok_or_else(|| CiError::Message("HTTP retry overflow".into()))?;
        let mut state = self
            .throttle
            .lock()
            .map_err(|_| CiError::Message("HTTP throttle owner failed".into()))?;
        *state = (*state).max(next);
        Ok(())
    }
    pub fn read(
        &self,
        transport: &impl Transport,
        url: &Url,
        headers: &[(String, String)],
        maximum: u64,
    ) -> Result<Response> {
        for attempt in 0..4 {
            self.wait()?;
            let response = transport.request("GET", url, headers, &[], self.deadline, maximum)?;
            if response.status != 429
                && !(response.status == 403
                    && response
                        .headers
                        .get("x-ratelimit-remaining")
                        .is_some_and(|remaining| remaining == "0"))
            {
                return Ok(response);
            }
            let delay = retry_hint(&response).unwrap_or(Duration::from_secs(1 << attempt));
            self.delay(delay)?;
        }
        Err(CiError::Message("HTTP throttle retry limit reached".into()))
    }
}

fn retry_hint(response: &Response) -> Option<Duration> {
    if let Some(value) = response.headers.get("retry-after") {
        if let Ok(seconds) = value.parse::<u64>() {
            return Some(Duration::from_secs(seconds));
        }
        if let Ok(date) =
            time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc2822)
        {
            let seconds = date
                .unix_timestamp()
                .saturating_sub(time::OffsetDateTime::now_utc().unix_timestamp());
            return Some(Duration::from_secs(u64::try_from(seconds.max(0)).ok()?));
        }
    }
    let reset = response
        .headers
        .get("x-ratelimit-reset")?
        .parse::<i64>()
        .ok()?;
    Some(Duration::from_secs(
        u64::try_from(
            reset
                .saturating_sub(time::OffsetDateTime::now_utc().unix_timestamp())
                .max(0),
        )
        .ok()?,
    ))
}

/// Artifact redirects never carry the caller's token to the storage destination.
pub fn download(
    transport: &impl Transport,
    budget: &ReadBudget,
    original: &Url,
    headers: &[(String, String)],
    maximum: u64,
) -> Result<Vec<u8>> {
    let mut url = original.clone();
    let mut visited = std::collections::BTreeSet::new();
    for redirect in 0..=5 {
        validate_https(&url)?;
        if !visited.insert(url.as_str().to_owned()) {
            return Err(CiError::Message("HTTPS redirect cycle".into()));
        }
        let response = budget.read(
            transport,
            &url,
            if redirect == 0 { headers } else { &[] },
            maximum,
        )?;
        match response.status {
            200 => return Ok(response.body),
            301 | 302 | 303 | 307 | 308 => {
                url = url
                    .join(
                        response.headers.get("location").ok_or_else(|| {
                            CiError::Message("HTTPS redirect lacks location".into())
                        })?,
                    )
                    .map_err(|_| CiError::Message("invalid HTTPS redirect".into()))?;
            }
            _ => return Err(CiError::Message("HTTPS artifact unavailable".into())),
        }
    }
    Err(CiError::Message("HTTPS redirect limit exceeded".into()))
}

pub fn json(response: &Response) -> Result<serde_json::Value> {
    memcordon_core::canonical_json::reject_duplicate_json_keys(&response.body)
        .map_err(CiError::Message)?;
    Ok(serde_json::from_slice(&response.body)?)
}

pub fn github_url(repository: &str, parts: &[&str]) -> Result<Url> {
    super::source::validate_repository(repository)?;
    let mut url = Url::parse("https://api.github.com").expect("constant HTTPS URL");
    {
        let mut path = url
            .path_segments_mut()
            .map_err(|_| CiError::Message("invalid API base".into()))?;
        path.push("repos");
        for component in repository.split('/') {
            path.push(component);
        }
        for part in parts {
            path.push(part);
        }
    }
    Ok(url)
}
