//! Reconcile provider state and upload only absent exact prepared bytes.
use super::{
    artifacts,
    bundle::{LoadedBundle, PreparedBundle},
    http::{self, ReadBudget, Transport},
};
use crate::{CiError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{Duration, Instant},
};
use url::Url;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum RemoteState {
    Absent,
    Matching,
    Conflicting { detail: String },
    Unknown { detail: String },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjectObservation {
    pub name: String,
    pub destination: String,
    pub observation: RemoteState,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicationSummary {
    pub source_commit: String,
    pub objects: Vec<ObjectObservation>,
    pub complete: bool,
    pub public: Option<bool>,
    #[serde(default)]
    pub writes: Vec<WriteObservation>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WriteObservation {
    pub method: String,
    pub status: Option<u16>,
    pub transport_failed: bool,
}

/// Borrowed transaction input. Candidate fixture selections never become a tagged envelope.
pub(crate) struct PublicationView<'a> {
    pub version: &'a semver::Version,
    pub commit: &'a str,
    pub repository: &'a str,
    pub tag_ref: &'a str,
    pub notes: &'a str,
    pub files: &'a [artifacts::FileRecord],
    pub payloads: &'a [Vec<u8>],
}

#[derive(Clone)]
pub struct Credentials {
    github: String,
    registry: Option<String>,
}
impl Credentials {
    pub fn from_environment(write: bool) -> Result<Self> {
        let github = std::env::var("GH_TOKEN")
            .or_else(|_| std::env::var("GITHUB_TOKEN"))
            .map_err(|_| CiError::Message("GitHub read/write credential missing".into()))?;
        let registry = if write {
            Some(
                std::env::var("CARGO_REGISTRY_TOKEN")
                    .or_else(|_| std::env::var("CARGO_REGISTRIES_CRATES_IO_TOKEN"))
                    .map_err(|_| CiError::Message("registry credential missing".into()))?,
            )
        } else {
            None
        };
        if std::iter::once(&github)
            .chain(registry.iter())
            .any(|token| token.is_empty() || token.bytes().any(|byte| byte.is_ascii_control()))
        {
            return Err(CiError::Message("invalid publication credential".into()));
        }
        Ok(Self { github, registry })
    }
    pub fn for_transport(github: String, registry: Option<String>) -> Result<Self> {
        if std::iter::once(&github)
            .chain(registry.iter())
            .any(|token| token.is_empty() || token.bytes().any(|byte| byte.is_ascii_control()))
        {
            return Err(CiError::Message("invalid credential".into()));
        }
        Ok(Self { github, registry })
    }
    fn github_headers(&self) -> Vec<(String, String)> {
        vec![
            ("Authorization".into(), format!("Bearer {}", self.github)),
            ("Accept".into(), "application/vnd.github+json".into()),
            ("X-GitHub-Api-Version".into(), "2022-11-28".into()),
            ("User-Agent".into(), "memcordon-ci".into()),
        ]
    }
}

pub struct Publisher<'a, T: Transport> {
    transport: &'a T,
    credentials: &'a Credentials,
    budget: ReadBudget,
    view: PublicationView<'a>,
    verified_registry_bytes: std::sync::Mutex<BTreeSet<String>>,
    writes: std::sync::Mutex<Vec<WriteObservation>>,
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| CiError::Message(format!("provider response lacks {name}")))
}
fn id(value: &Value) -> Result<u64> {
    value
        .get("id")
        .and_then(Value::as_u64)
        .filter(|id| *id != 0)
        .ok_or_else(|| CiError::Message("provider object ID missing".into()))
}
fn object_failure(error: CiError) -> RemoteState {
    RemoteState::Unknown {
        detail: error.to_string(),
    }
}

impl<'a, T: Transport> Publisher<'a, T> {
    pub fn new(
        transport: &'a T,
        credentials: &'a Credentials,
        bundle: &'a LoadedBundle,
        deadline: Instant,
    ) -> Self {
        Self::from_view(
            transport,
            credentials,
            PublicationView {
                version: &bundle.metadata.source.version,
                commit: &bundle.metadata.source.commit,
                repository: &bundle.metadata.source.repository,
                tag_ref: &bundle.metadata.source.tag_ref,
                notes: &bundle.metadata.notes,
                files: &bundle.metadata.files,
                payloads: &bundle.payloads,
            },
            deadline,
        )
    }
    pub(crate) fn from_view(
        transport: &'a T,
        credentials: &'a Credentials,
        view: PublicationView<'a>,
        deadline: Instant,
    ) -> Self {
        Self {
            transport,
            credentials,
            view,
            budget: ReadBudget::new(deadline),
            verified_registry_bytes: std::sync::Mutex::new(BTreeSet::new()),
            writes: std::sync::Mutex::new(Vec::new()),
        }
    }
    fn get(&self, url: &Url) -> Result<http::Response> {
        self.budget.read(
            self.transport,
            url,
            &self.credentials.github_headers(),
            4 * 1024 * 1024,
        )
    }
    fn api(&self, parts: &[&str]) -> Result<Url> {
        http::github_url(self.view.repository, parts)
    }
    fn write(
        &self,
        method: &str,
        url: &Url,
        body: &[u8],
        content_type: &str,
    ) -> Result<http::Response> {
        let mut headers = self.credentials.github_headers();
        headers.push(("Content-Type".into(), content_type.into()));
        let reply = self.transport.request(
            method,
            url,
            &headers,
            body,
            self.budget.deadline,
            4 * 1024 * 1024,
        );
        self.observe_write(method, &reply)?;
        reply
    }
    fn observe_write(&self, method: &str, reply: &Result<http::Response>) -> Result<()> {
        let mut observations = self
            .writes
            .lock()
            .map_err(|_| CiError::Message("write observation owner failed".into()))?;
        if observations.len() >= 4096 {
            return Err(CiError::Message("write observation bound exceeded".into()));
        }
        observations.push(WriteObservation {
            method: method.to_owned(),
            status: reply.as_ref().ok().map(|response| response.status),
            transport_failed: reply.is_err(),
        });
        Ok(())
    }

    /// Bind destination access and its current tag once, before any mutation.
    fn destination(&self) -> Result<bool> {
        let repository = self.get(&self.api(&[])?)?;
        if repository.status != 200 {
            return Err(CiError::Message(
                "destination access could not be established".into(),
            ));
        }
        let repository = http::json(&repository)?;
        if field(&repository, "full_name")? != self.view.repository {
            return Err(CiError::Message("destination repository differs".into()));
        }
        let private = repository
            .get("private")
            .and_then(Value::as_bool)
            .ok_or_else(|| CiError::Message("repository visibility unknown".into()))?;
        let tag = self
            .view
            .tag_ref
            .strip_prefix("refs/tags/")
            .ok_or_else(|| CiError::Message("selected full tag missing".into()))?;
        let response = self.get(&self.api(&["git", "ref", "tags", tag])?)?;
        if response.status != 200 {
            return Err(CiError::Message(
                "destination tag absent or inaccessible".into(),
            ));
        }
        let mut object = http::json(&response)?
            .get("object")
            .cloned()
            .ok_or_else(|| CiError::Message("tag object absent".into()))?;
        let mut seen = BTreeSet::new();
        for _ in 0..8 {
            let sha = field(&object, "sha")?;
            super::source::validate_oid(sha)?;
            if !seen.insert(sha.to_owned()) {
                return Err(CiError::Message("cyclic destination tag".into()));
            }
            match field(&object, "type")? {
                "commit" if sha == self.view.commit => return Ok(!private),
                "commit" => {
                    return Err(CiError::Message(
                        "destination tag selects a different commit".into(),
                    ));
                }
                "tag" => {
                    let response = self.get(&self.api(&["git", "tags", sha])?)?;
                    if response.status != 200 {
                        return Err(CiError::Message(
                            "annotated tag readback unavailable".into(),
                        ));
                    }
                    object = http::json(&response)?
                        .get("object")
                        .cloned()
                        .ok_or_else(|| CiError::Message("nested tag object absent".into()))?;
                }
                _ => {
                    return Err(CiError::Message(
                        "destination tag does not select a commit".into(),
                    ));
                }
            }
        }
        Err(CiError::Message("destination tag depth exceeded".into()))
    }

    fn release(&self) -> Result<Option<Value>> {
        let tag = self.view.version.to_string();
        // List drafts as well as public releases; a by-tag 404 alone cannot establish
        // that an interrupted draft creation had no effect.
        let mut selected = None;
        let mut ids = BTreeSet::new();
        for page in 1_u16..=8 {
            let mut url = self.api(&["releases"])?;
            url.query_pairs_mut()
                .append_pair("per_page", "100")
                .append_pair("page", &page.to_string());
            let response = self.get(&url)?;
            if response.status != 200 {
                return Err(CiError::Message("release observation incomplete".into()));
            }
            let values = http::json(&response)?;
            let values = values
                .as_array()
                .ok_or_else(|| CiError::Message("release listing absent".into()))?;
            for value in values {
                if !ids.insert(id(value)?) {
                    return Err(CiError::Message("duplicate release object ID".into()));
                }
                if value.get("name").and_then(Value::as_str) == Some(tag.as_str())
                    && field(value, "tag_name")? != tag
                {
                    return Err(CiError::Message(
                        "managed release name/tag identity is ambiguous".into(),
                    ));
                }
                if field(value, "tag_name")? == tag
                    && (value.get("draft").and_then(Value::as_bool).is_none()
                        || selected.replace(value.clone()).is_some())
                {
                    return Err(CiError::Message(
                        "duplicate release tag or unknown state".into(),
                    ));
                }
            }
            if values.len() < 100
                && !response
                    .headers
                    .get("link")
                    .is_some_and(|link| link.contains("rel=\"next\""))
            {
                if let Some(release) = &selected
                    && (field(release, "body")? != self.view.notes
                        || release.get("prerelease").and_then(Value::as_bool)
                            != Some(!self.view.version.pre.is_empty()))
                {
                    return Err(CiError::Message("managed release metadata differs".into()));
                }
                return Ok(selected);
            }
        }
        Err(CiError::Message(
            "release pagination ceiling reached".into(),
        ))
    }

    fn assets(&self, release: &Value) -> Result<BTreeMap<String, Value>> {
        let release_id = id(release)?.to_string();
        let mut assets = BTreeMap::new();
        let mut ids = BTreeSet::new();
        for page in 1_u16..=8 {
            let mut url = self.api(&["releases", &release_id, "assets"])?;
            url.query_pairs_mut()
                .append_pair("per_page", "100")
                .append_pair("page", &page.to_string());
            let response = self.get(&url)?;
            if response.status != 200 {
                return Err(CiError::Message(
                    "release asset pagination incomplete".into(),
                ));
            }
            let rows = http::json(&response)?;
            let rows = rows
                .as_array()
                .ok_or_else(|| CiError::Message("asset list absent".into()))?;
            for asset in rows {
                let name = field(asset, "name")?;
                artifacts::safe_basename(name)?;
                if assets.len() >= 128
                    || !ids.insert(id(asset)?)
                    || assets.insert(name.into(), asset.clone()).is_some()
                {
                    return Err(CiError::Message(
                        "duplicate/oversized release asset listing".into(),
                    ));
                }
            }
            if rows.len() < 100
                && !response
                    .headers
                    .get("link")
                    .is_some_and(|link| link.contains("rel=\"next\""))
            {
                return Ok(assets);
            }
        }
        Err(CiError::Message(
            "release asset pagination ceiling reached".into(),
        ))
    }

    fn asset_state(
        &self,
        record: &artifacts::FileRecord,
        asset: Option<&Value>,
        public: bool,
    ) -> RemoteState {
        let Some(asset) = asset else {
            return RemoteState::Absent;
        };
        let check = || -> Result<RemoteState> {
            if field(asset, "name")? != record.name
                || asset.get("size").and_then(Value::as_u64) != Some(record.byte_len)
                || field(asset, "state")? != "uploaded"
            {
                return Ok(RemoteState::Conflicting {
                    detail: "asset name/size/state differs".into(),
                });
            }
            if let Some(digest) = asset.get("digest").and_then(Value::as_str)
                && let Some(digest) = digest.strip_prefix("sha256:")
            {
                return Ok(if digest == record.sha256 {
                    RemoteState::Matching
                } else {
                    RemoteState::Conflicting {
                        detail: "asset digest differs".into(),
                    }
                });
            }
            let url = self.api(&["releases", "assets", &id(asset)?.to_string()])?;
            let headers = if public {
                vec![
                    ("Accept".into(), "application/octet-stream".into()),
                    ("User-Agent".into(), "memcordon-ci".into()),
                ]
            } else {
                let mut headers = self.credentials.github_headers();
                headers.retain(|(name, _)| name != "Accept");
                headers.push(("Accept".into(), "application/octet-stream".into()));
                headers
            };
            let bytes = http::download(
                self.transport,
                &self.budget,
                &url,
                &headers,
                record.byte_len,
            )?;
            Ok(if artifacts::check_bytes(record, &bytes).is_ok() {
                RemoteState::Matching
            } else {
                RemoteState::Conflicting {
                    detail: "asset downloaded bytes differ".into(),
                }
            })
        };
        check().unwrap_or_else(object_failure)
    }

    fn registry_state(&self, record: &artifacts::FileRecord) -> RemoteState {
        let check = || -> Result<RemoteState> {
            let package = record
                .package
                .as_deref()
                .ok_or_else(|| CiError::Message("registry package absent".into()))?;
            if !super::source::PUBLIC_PACKAGES.contains(&package) {
                return Err(CiError::Message("unselected registry package".into()));
            }
            let mut index = Url::parse("https://index.crates.io").expect("constant URL");
            // Every selected public name uses the crates.io me/mc index shard.
            index
                .path_segments_mut()
                .expect("HTTPS base")
                .extend(["me", "mc", package]);
            let response = self
                .budget
                .read(self.transport, &index, &[], 8 * 1024 * 1024)?;
            if response.status == 404 {
                return Ok(RemoteState::Absent);
            }
            if response.status != 200 {
                return Err(CiError::Message(
                    "registry index observation unavailable".into(),
                ));
            }
            let text = std::str::from_utf8(&response.body)
                .map_err(|_| CiError::Message("invalid registry index text".into()))?;
            let mut row = None;
            for line in text.lines() {
                memcordon_core::canonical_json::reject_duplicate_json_keys(line.as_bytes())
                    .map_err(CiError::Message)?;
                let value: Value = serde_json::from_str(line)?;
                if field(&value, "name")? != package {
                    return Err(CiError::Message("registry index package differs".into()));
                }
                if field(&value, "vers")? == self.view.version.to_string()
                    && row.replace(value).is_some()
                {
                    return Err(CiError::Message("duplicate registry version row".into()));
                }
            }
            let Some(row) = row else {
                return Ok(RemoteState::Absent);
            };
            if row.get("yanked").and_then(Value::as_bool) != Some(false)
                || field(&row, "cksum")? != record.sha256
            {
                return Ok(RemoteState::Conflicting {
                    detail: "registry checksum/yank state differs".into(),
                });
            }
            if self
                .verified_registry_bytes
                .lock()
                .map_err(|_| CiError::Message("registry byte cache owner failed".into()))?
                .contains(&record.sha256)
            {
                return Ok(RemoteState::Matching);
            }
            let mut url = Url::parse("https://static.crates.io").expect("constant URL");
            url.path_segments_mut().expect("HTTPS base").extend([
                "crates",
                package,
                &format!("{}-{}.crate", package, self.view.version),
            ]);
            let bytes = http::download(self.transport, &self.budget, &url, &[], record.byte_len)?;
            Ok(if artifacts::check_bytes(record, &bytes).is_ok() {
                self.verified_registry_bytes
                    .lock()
                    .map_err(|_| CiError::Message("registry byte cache owner failed".into()))?
                    .insert(record.sha256.clone());
                RemoteState::Matching
            } else {
                RemoteState::Conflicting {
                    detail: "registry downloaded bytes differ".into(),
                }
            })
        };
        check().unwrap_or_else(object_failure)
    }

    pub fn inspect(&self) -> Result<PublicationSummary> {
        let public = self.destination()?;
        let release = self.release()?;
        let assets = release
            .as_ref()
            .map(|release| self.assets(release))
            .transpose()?
            .unwrap_or_default();
        let reads: Vec<_> = self
            .view
            .files
            .iter()
            .flat_map(|record| {
                let mut destinations = vec![(record, "github")];
                if record.kind == "crate" {
                    destinations.push((record, "crates.io"));
                }
                destinations
            })
            .collect();
        let objects = crate::public_reads::map_public_reads_ordered(
            &reads,
            std::num::NonZeroUsize::new(4).expect("positive fixed worker ceiling"),
            self.budget.deadline,
            |_, (record, destination), _| {
                Ok(ObjectObservation {
                    name: record.name.clone(),
                    destination: (*destination).into(),
                    observation: if *destination == "github" {
                        self.asset_state(record, assets.get(&record.name), false)
                    } else {
                        self.registry_state(record)
                    },
                })
            },
        )?;
        let complete = objects
            .iter()
            .all(|object| object.observation == RemoteState::Matching)
            && release.as_ref().is_some_and(|release| {
                release.get("draft").and_then(Value::as_bool) == Some(false)
            });
        Ok(PublicationSummary {
            source_commit: self.view.commit.to_owned(),
            objects,
            complete,
            public: Some(public),
            writes: self
                .writes
                .lock()
                .map_err(|_| CiError::Message("write observation owner failed".into()))?
                .clone(),
        })
    }

    pub fn publish(&self) -> Result<PublicationSummary> {
        let initial = self.inspect()?;
        if initial.objects.iter().any(|object| {
            matches!(
                object.observation,
                RemoteState::Conflicting { .. } | RemoteState::Unknown { .. }
            )
        }) {
            return Ok(initial);
        }
        let mut release = match self.release()? {
            Some(release) => release,
            None => {
                let body = serde_json::to_vec(
                    &json!({"tag_name":self.view.version,"target_commitish":self.view.commit,"name":self.view.version,"body":self.view.notes,"draft":true,"prerelease":!self.view.version.pre.is_empty()}),
                )?;
                let _reply =
                    self.write("POST", &self.api(&["releases"])?, &body, "application/json");
                let Some(release) = self.release()? else {
                    return self.inspect();
                };
                release
            }
        };
        for (record, bytes) in self.view.files.iter().zip(self.view.payloads) {
            let assets = self.assets(&release)?;
            match self.asset_state(record, assets.get(&record.name), false) {
                RemoteState::Matching => continue,
                RemoteState::Absent => {}
                _ => return self.inspect(),
            }
            let mut upload = Url::parse("https://uploads.github.com").expect("constant URL");
            upload
                .path_segments_mut()
                .expect("HTTPS base")
                .push("repos")
                .extend(self.view.repository.split('/'))
                .extend(["releases", &id(&release)?.to_string(), "assets"]);
            upload.query_pairs_mut().append_pair("name", &record.name);
            let _reply = self.write("POST", &upload, bytes, "application/octet-stream");
            let assets = self.assets(&release)?;
            if self.asset_state(record, assets.get(&record.name), false) != RemoteState::Matching {
                return self.inspect();
            }
        }
        for (record, bytes) in self
            .view
            .files
            .iter()
            .zip(self.view.payloads)
            .filter(|(record, _)| record.kind == "crate")
        {
            match self.registry_state(record) {
                RemoteState::Matching => continue,
                RemoteState::Absent => {}
                _ => return self.inspect(),
            }
            let token = self
                .credentials
                .registry
                .as_ref()
                .ok_or_else(|| CiError::Message("registry write credential absent".into()))?;
            let wire = super::registry::render_upload(
                record.package.as_deref().expect("validated package"),
                &self.view.version.to_string(),
                bytes,
                &record.sha256,
            )?;
            let url = Url::parse("https://crates.io/api/v1/crates/new").expect("constant URL");
            let reply = self.transport.request(
                "PUT",
                &url,
                &[
                    ("Authorization".into(), token.clone()),
                    ("Content-Type".into(), "application/octet-stream".into()),
                    ("User-Agent".into(), "memcordon-ci".into()),
                ],
                &wire,
                self.budget.deadline,
                1024 * 1024,
            );
            self.observe_write("PUT", &reply)?;
            let slot_deadline =
                (Instant::now() + Duration::from_secs(300)).min(self.budget.deadline);
            let mut delay = Duration::from_millis(500);
            loop {
                match self.registry_state(record) {
                    RemoteState::Matching => break,
                    RemoteState::Conflicting { .. } => return self.inspect(),
                    _ => {}
                }
                if Instant::now()
                    .checked_add(delay)
                    .is_none_or(|next| next >= slot_deadline)
                {
                    return self.inspect();
                }
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_secs(8));
            }
        }
        if release.get("draft").and_then(Value::as_bool) == Some(true) {
            let assets = self.assets(&release)?;
            if !self.view.files.iter().all(|file| {
                self.asset_state(file, assets.get(&file.name), false) == RemoteState::Matching
            }) {
                return self.inspect();
            }
            self.destination()?;
            let _reply = self.write(
                "PATCH",
                &self.api(&["releases", &id(&release)?.to_string()])?,
                &serde_json::to_vec(&json!({"draft":false}))?,
                "application/json",
            );
            release = self
                .release()?
                .ok_or_else(|| CiError::Message("release disappeared during publication".into()))?;
        }
        let mut result = self.inspect()?;
        if result.complete {
            let assets = self.assets(&release)?;
            let records: Vec<_> = self.view.files.iter().collect();
            let observations = crate::public_reads::map_public_reads_ordered(
                &records,
                std::num::NonZeroUsize::new(4).expect("positive fixed worker ceiling"),
                self.budget.deadline,
                |_, record, _| {
                    // Anonymous final content read even when provider digest is present.
                    let mut asset = assets
                        .get(&record.name)
                        .cloned()
                        .ok_or_else(|| CiError::Message("published managed asset absent".into()))?;
                    if let Some(asset) = asset.as_object_mut() {
                        asset.remove("digest");
                    }
                    Ok(self.asset_state(record, Some(&asset), result.public == Some(true)))
                },
            )?;
            for (record, observation) in records.into_iter().zip(observations) {
                result
                    .objects
                    .iter_mut()
                    .find(|object| object.destination == "github" && object.name == record.name)
                    .expect("validated managed object")
                    .observation = observation;
            }
            result.complete = result
                .objects
                .iter()
                .all(|object| object.observation == RemoteState::Matching);
        }
        Ok(result)
    }
}

pub fn run(directory: &Path, write: bool) -> Result<()> {
    // Read/hash/validate every intended local file and dependency order before credentials.
    let bundle = PreparedBundle::load(directory)?;
    let credentials = Credentials::from_environment(write)?;
    let transport = http::HttpsTransport;
    let publisher = Publisher::new(
        &transport,
        &credentials,
        &bundle,
        Instant::now() + Duration::from_secs(20 * 60),
    );
    let result = if write {
        publisher.publish()?
    } else {
        publisher.inspect()?
    };
    println!("{}", serde_json::to_string_pretty(&result)?);
    if write && !result.complete {
        return Err(CiError::Message("publication is partial, conflicting or uncertain; inspect original prepared bytes before retry".into()));
    }
    Ok(())
}
