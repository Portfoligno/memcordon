//! Finite, local-only fixture records. None of these records authorizes publication.
use serde::{Deserialize, Serialize};
use std::net::SocketAddrV4;

pub const REVISION: u32 = 1;
pub const GITHUB_TOKEN: &str = "memcordon-rehearsal-github";
pub const REGISTRY_TOKEN: &str = "memcordon-rehearsal-registry";
pub const SERVICE_HEADER: &str = "x-memcordon-fixture-service";
pub const SESSION_HEADER: &str = "x-memcordon-fixture-session";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FixtureService {
    GithubApi,
    GithubUpload,
    RegistryUpload,
    RegistryIndex,
    RegistryDownload,
    Redirect,
}
impl FixtureService {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GithubApi => "github-api",
            Self::GithubUpload => "github-upload",
            Self::RegistryUpload => "registry-upload",
            Self::RegistryIndex => "registry-index",
            Self::RegistryDownload => "registry-download",
            Self::Redirect => "redirect",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        [
            Self::GithubApi,
            Self::GithubUpload,
            Self::RegistryUpload,
            Self::RegistryIndex,
            Self::RegistryDownload,
            Self::Redirect,
        ]
        .into_iter()
        .find(|service| service.as_str() == value)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BudgetPreset {
    Normal20min,
    Short5s,
}
impl BudgetPreset {
    pub fn seconds(self) -> u64 {
        match self {
            Self::Normal20min => 1200,
            Self::Short5s => 5,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureRecord {
    pub revision: u32,
    pub address: SocketAddrV4,
    pub session: String,
    pub budget: BudgetPreset,
    pub expires_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedFile {
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub package: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureSelection {
    pub version: String,
    pub commit: String,
    pub repository: String,
    pub notes: String,
    pub prerelease: bool,
    pub files: Vec<ExpectedFile>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Setup {
    pub revision: u32,
    pub case_id: String,
    pub selection: FixtureSelection,
    pub fault: Fault,
    pub budget: BudgetPreset,
    pub work_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Boundary {
    Draft,
    Asset(u32),
    Registry(u32),
    Visibility,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ReadFault {
    Forbidden,
    ServerError,
    MalformedJson,
    DuplicateKeys,
    DuplicateIds,
    MissingFields,
    Truncated,
    NonterminatingPages,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RedirectKind {
    Controlled,
    Loop,
    UnknownOrigin,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum MetadataField {
    Notes,
    Prerelease,
    Tag,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Fault {
    None,
    Loss { boundary: Boundary },
    Barrier { boundary: Boundary },
    ConflictAsset,
    ConflictRegistry,
    Yanked,
    UnknownRead { kind: ReadFault, after_effect: bool },
    VisibilityDelay { polls: u32, expire: bool },
    CorruptAsset { truncate: bool },
    CorruptRegistry,
    Redirect { kind: RedirectKind },
    SourceDrift { before_visibility: bool },
    AnnotatedTag,
    CyclicTag,
    MetadataDrift { field: MetadataField },
    Private,
    StarterResidue,
    RateLimit { excessive: bool },
    Stall,
    FixtureLoss { boundary: Boundary },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseState {
    pub id: u64,
    pub tag_name: String,
    pub body: String,
    pub prerelease: bool,
    pub draft: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AssetState {
    pub id: u64,
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub path: String,
    pub state: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CrateState {
    pub name: String,
    pub version: String,
    pub sha256: String,
    pub path: String,
    pub index: serde_json::Value,
    pub visible: bool,
    pub yanked: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RequestObservation {
    pub method: String,
    pub service: FixtureService,
    pub path: String,
    pub credential_role: String,
    pub body_len: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EffectObservation {
    pub boundary: Boundary,
    pub id: u64,
    pub name: String,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Snapshot {
    pub release: Option<ReleaseState>,
    pub assets: Vec<AssetState>,
    pub crates: Vec<CrateState>,
    pub requests: Vec<RequestObservation>,
    pub effects: Vec<EffectObservation>,
    pub fault_reached: bool,
    #[serde(default)]
    pub fault_boundary: Option<Boundary>,
    pub credential_errors: u64,
    pub max_active_reads: u32,
    pub max_active_connections: u32,
    pub max_active_writes: u32,
    pub complete_requests: u64,
    pub body_downloads: u64,
    pub omitted_requests: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ControlEvent {
    pub event: String,
    pub boundary: Boundary,
    pub ordinal: u64,
    pub barrier: bool,
}
