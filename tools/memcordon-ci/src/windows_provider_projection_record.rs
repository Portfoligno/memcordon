//! Finite declared inputs for a separate owned-provider experiment, never policy.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const CATALOG_ENTRIES: usize = 64;
pub const PROVIDER_FILES: usize = 8;
pub const PATH_UNITS: usize = 2048;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogProvider {
    pub catalog_id: u32,
    pub provider_id: [u8; 16],
    pub address_family: i32,
    pub socket_type: i32,
    pub protocol: i32,
    pub chain_length: i32,
    pub chain_entries: Vec<u32>,
    pub configured_path: Vec<u16>,
    pub expanded_path: Vec<u16>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogSnapshot {
    pub version: u32,
    /// Digest of the exact sealed registry declaration transferred to the helper.
    pub declaration_sha256: String,
    pub complete: bool,
    pub catalog_entries: u32,
    pub matching_providers: Vec<CatalogProvider>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Candidate {
    pub expanded_path: Vec<u16>,
    pub basename: String,
    pub catalog_ids: Vec<u32>,
    pub provider_ids: Vec<[u8; 16]>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PrivateInput {
    pub original_path: Vec<u16>,
    pub private_native_path: Vec<u16>,
    pub volume_serial: u32,
    pub file_index: u64,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OriginalSelectionState {
    PrivateSelected,
    CompleteNonPrivateMapping,
}

#[derive(Clone, Debug, Serialize)]
pub struct OriginalSelectionRow {
    pub state: OriginalSelectionState,
    pub private_input: PrivateInput,
    pub dependency_sequence: u64,
    pub returned_base: u64,
    pub original_thread: u32,
    pub mapped_path_utf16: Vec<u16>,
}

/// Constructed only by the complete original-return validator. Serialization
/// is diagnostic data; it does not establish live process or input ownership.
#[derive(Clone, Debug, Serialize)]
pub struct OriginalSelection {
    pid: u32,
    birth: u64,
    peer: bool,
    rows: Vec<OriginalSelectionRow>,
}
impl OriginalSelection {
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn birth(&self) -> u64 {
        self.birth
    }
    pub fn peer(&self) -> bool {
        self.peer
    }
    pub fn rows(&self) -> &[OriginalSelectionRow] {
        &self.rows
    }
}
pub struct BindingExpectation {
    pub pid: u32,
    pub birth: u64,
    pub descriptor_sha256: [u8; 32],
    pub challenge_sha256: [u8; 32],
    pub token_sha256: [u8; 32],
    pub peer: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderScenario {
    Ordinary,
    Restricted,
}

/// Availability covers only the invoked original operations and their rows.
/// Configured inputs absent from those rows remain unmeasured.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrivateAvailability {
    Available,
    Unavailable,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScenarioSelectionAssessment {
    scenario: ProviderScenario,
    original_selections: Vec<OriginalSelection>,
    private_availability: PrivateAvailability,
}

impl ScenarioSelectionAssessment {
    pub fn assess(
        scenario: ProviderScenario,
        original_selections: Vec<OriginalSelection>,
    ) -> Result<Self, String> {
        if original_selections.len() != 2
            || original_selections.iter().filter(|row| row.peer).count() != 1
        {
            return Err("provider scenario requires exactly one original root and peer".into());
        }
        let private_availability = if original_selections.iter().all(|selection| {
            selection
                .rows
                .iter()
                .all(|row| row.state == OriginalSelectionState::PrivateSelected)
        }) {
            PrivateAvailability::Available
        } else {
            PrivateAvailability::Unavailable
        };
        Ok(Self {
            scenario,
            original_selections,
            private_availability,
        })
    }

    pub fn private_availability(&self) -> PrivateAvailability {
        self.private_availability
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ExperimentSelectionAssessment {
    scenarios: Vec<ScenarioSelectionAssessment>,
    private_availability: PrivateAvailability,
}

impl ExperimentSelectionAssessment {
    pub fn assess(scenarios: Vec<ScenarioSelectionAssessment>) -> Result<Self, String> {
        if scenarios.len() != 2
            || scenarios
                .iter()
                .filter(|row| row.scenario == ProviderScenario::Ordinary)
                .count()
                != 1
        {
            return Err(
                "provider experiment requires exactly ordinary and restricted scenarios".into(),
            );
        }
        let private_availability = if scenarios
            .iter()
            .all(|scenario| scenario.private_availability == PrivateAvailability::Available)
        {
            PrivateAvailability::Available
        } else {
            PrivateAvailability::Unavailable
        };
        Ok(Self {
            scenarios,
            private_availability,
        })
    }

    pub fn private_availability(&self) -> PrivateAvailability {
        self.private_availability
    }
}

/// Join actual original-return mapping to separately held immutable private bytes.
/// This never upgrades a missing/omitted/partial observer into a selected image.
pub fn image_witness(
    value: &serde_json::Value,
    expected: &BindingExpectation,
    inputs: &[PrivateInput],
) -> Result<serde_json::Value, String> {
    let observed = observe_original_selection(value, expected, inputs)?;
    // A complete nonprivate mapping remains insufficient for this exact
    // positive witness. Preserve its original wire shape and meaning.
    if observed
        .rows
        .iter()
        .any(|row| row.state != OriginalSelectionState::PrivateSelected)
    {
        return Err("original provider return does not resolve to exact held private input".into());
    }
    let selected = observed.rows.iter().map(|row| serde_json::json!({
        "dependency_sequence":row.dependency_sequence,"returned_base":row.returned_base,
        "private_input":row.private_input,"call_time_mapping_complete":true,
        "held_input_identity_and_content_bound":true,"historical_host_file_identity_proved":false
    })).collect::<Vec<_>>();
    Ok(
        serde_json::json!({"pid":expected.pid,"birth":expected.birth,"peer":expected.peer,
        "selected":selected,"continuous_token_equality_proved":false,"acceptance_authority":false}),
    )
}

pub fn observe_original_selection(
    value: &serde_json::Value,
    expected: &BindingExpectation,
    inputs: &[PrivateInput],
) -> Result<OriginalSelection, String> {
    let binding = &value["original_binding"];
    let trace = &value["trace"];
    let mut input_names = BTreeSet::new();
    if inputs.iter().any(|input| {
        input.original_path.is_empty()
            || input.original_path.len() > PATH_UNITS
            || input.original_path.contains(&0)
            || input.private_native_path.is_empty()
            || input.private_native_path.len() > PATH_UNITS
            || input.private_native_path.contains(&0)
            || !input_names.insert(&input.original_path)
    }) {
        return Err("held configured provider names invalid or ambiguous".into());
    }
    if expected.pid == 0
        || expected.birth == 0
        || inputs.is_empty()
        || inputs.len() > PROVIDER_FILES
        || value["format"] != "memcordon.original-rust-listener-trace"
        || binding["pid"] != expected.pid
        || binding["creation_time_100ns"] != expected.birth
        || binding["descriptor_sha256"] != serde_json::json!(expected.descriptor_sha256)
        || binding["challenge_sha256"] != serde_json::json!(expected.challenge_sha256)
        || binding["prior_token_observation_sha256"] != serde_json::json!(expected.token_sha256)
        || binding["current_process_token"]["sha256"] != serde_json::json!(expected.token_sha256)
        || binding["current_effective_token"]["sha256"] != serde_json::json!(expected.token_sha256)
        || !binding["current_process_token"]["error"].is_null()
        || !binding["current_effective_token"]["error"].is_null()
        || trace["invalid_packet"] != false
        || trace["original_rust_operation"]
            != if expected.peer {
                "TcpStream::connect"
            } else {
                "TcpListener::bind"
            }
        || trace["returned_images"]["complete"] != true
    {
        return Err(
            "original image observation is incomplete or differs from held process/request/caller"
                .into(),
        );
    }
    if expected.peer {
        if binding["prior_token_observation_scope"] != "peer-before-authenticated-start"
            || !binding["prior_admitted_token_envelope_sha256"].is_null()
        {
            return Err("peer token observation scope was relabeled".into());
        }
    } else if binding["prior_token_observation_scope"] != "root-admitted-token-envelope"
        || binding["prior_admitted_token_envelope_sha256"]
            != serde_json::json!(expected.token_sha256)
    {
        return Err("root admitted caller binding differs".into());
    }
    let images = trace["returned_images"]["rows"]
        .as_array()
        .filter(|rows| !rows.is_empty() && rows.len() <= 8)
        .ok_or("complete original image rows unavailable")?;
    let entries = trace["dependencies"]["recent_entries"].as_array();
    let mut selected = Vec::new();
    let mut sequences = BTreeSet::new();
    let mut providers = BTreeSet::new();
    for image in images {
        if image["complete"] != true || image["invalid_row"] != false {
            return Err("original returned image row incomplete".into());
        }
        let from_row = &image["original_load"];
        let source = entries
            .into_iter()
            .flatten()
            .filter(|entry| entry["sequence"] == image["dependency_sequence"])
            .collect::<Vec<_>>();
        if source.len() > 1 {
            return Err("original image source link ambiguous".into());
        }
        let source = if from_row["complete"] == true {
            if source.first().is_some_and(|source| {
                [
                    "operation_code",
                    "sequence",
                    "name_utf16",
                    "raw_flags",
                    "raw_root",
                    "raw_output",
                    "name_flags",
                    "reported_name_bytes",
                    "copied_name_units",
                    "thread_id",
                    "entered",
                    "returned",
                    "output_flags",
                    "native_status_or_adapter_marker",
                ]
                .iter()
                .any(|key| source[*key] != from_row[*key])
            }) {
                return Err(
                    "retained original source details contradict the full source entry".into(),
                );
            }
            from_row
        } else {
            *source
                .first()
                .ok_or("original image source link evicted without complete row facts")?
        };
        let name: Vec<u16> = serde_json::from_value(source["name_utf16"].clone())
            .map_err(|_| "original image source name unavailable")?;
        let input = inputs
            .iter()
            .filter(|input| input.original_path == name)
            .collect::<Vec<_>>();
        if input.is_empty() {
            continue;
        }
        if input.len() != 1
            || source["operation_code"] != 12
            || source["sequence"] != image["dependency_sequence"]
            || source["entered"] != true && source["entered"] != 1
            || source["returned"] != true && source["returned"] != 1
            || source["thread_id"] != image["original_thread"]
            || source["output_flags"] != 3
            || source["native_status_or_adapter_marker"] != 0
            || source["raw_output"] != image["returned_base"]
            || source["raw_flags"] != 0
            || source["raw_root"] != 0
            || source["name_flags"] != 1
            || source["reported_name_bytes"] != name.len() * 2
            || source["copied_name_units"] != name.len()
            || image["allocation_base"] != image["returned_base"]
            || image["memory_type"] != 0x0100_0000u32
            || image["original_thread"] != trace["original_thread"]
            || image["domain"] != 0
            || image["state"] != 1
            || image["flags"] != 7
            || image["virtual_query_error"] != 0
            || image["mapped_name_error"] != 0
        {
            return Err(
                "original provider return does not resolve to exact held private input".into(),
            );
        }
        let mapped_path_utf16: Vec<u16> =
            serde_json::from_value(image["mapped_path_utf16"].clone())
                .map_err(|_| "original mapped native path unavailable")?;
        let sequence = image["dependency_sequence"]
            .as_u64()
            .filter(|value| *value != 0)
            .ok_or("original image sequence unavailable")?;
        let returned_base = image["returned_base"]
            .as_u64()
            .filter(|value| *value != 0)
            .ok_or("original image base unavailable")?;
        let original_thread = image["original_thread"]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value != 0)
            .ok_or("original image thread unavailable")?;
        let started = image["started_qpc"]
            .as_u64()
            .ok_or("original image start unavailable")?;
        let finished = image["finished_qpc"]
            .as_u64()
            .ok_or("original image finish unavailable")?;
        let cutoff = trace["cutoff_qpc"]
            .as_u64()
            .ok_or("original image cutoff unavailable")?;
        if mapped_path_utf16.is_empty()
            || mapped_path_utf16.len() > PATH_UNITS
            || mapped_path_utf16.contains(&0)
            || !sequences.insert(sequence)
            || !providers.insert(input[0].original_path.clone())
            || started > finished
            || finished >= cutoff
        {
            return Err(
                "original configured image rows duplicate or mapping extent invalid".into(),
            );
        }
        selected.push(OriginalSelectionRow {
            state: if mapped_path_utf16 == input[0].private_native_path {
                OriginalSelectionState::PrivateSelected
            } else {
                OriginalSelectionState::CompleteNonPrivateMapping
            },
            private_input: input[0].clone(),
            dependency_sequence: sequence,
            returned_base,
            original_thread,
            mapped_path_utf16,
        });
    }
    if selected.is_empty() {
        return Err(
            "no original configured provider load is positively bound to private input".into(),
        );
    }
    Ok(OriginalSelection {
        pid: expected.pid,
        birth: expected.birth,
        peer: expected.peer,
        rows: selected,
    })
}

pub fn mutation_witness(
    value: &serde_json::Value,
    pid: u32,
    peer: bool,
    restricted: bool,
    paths: &[String],
) -> Result<(), String> {
    mutation_witness_for_layout(value, pid, peer, restricted, paths, false)
}

pub fn mutation_witness_for_layout(
    value: &serde_json::Value,
    pid: u32,
    peer: bool,
    restricted: bool,
    paths: &[String],
    file_layout: bool,
) -> Result<(), String> {
    if pid == 0
        || value["format"] != "memcordon.private-provider-input-mutation-probes"
        || value["revision"] != 1
        || value["pid"] != pid
        || value["peer"] != peer
        || value["restricted"] != restricted
    {
        return Err("private mutation probe process/caller binding differs".into());
    }
    if !restricted {
        if value["performed"] != false
            || value["complete"] != false
            || value["state"] != "not-required-for-ordinary-baseline"
        {
            return Err("ordinary baseline was relabeled as restricted mutation proof".into());
        }
        return Ok(());
    }
    let rows = value["rows"]
        .as_array()
        .ok_or("restricted private mutation rows unavailable")?;
    if value["performed"] != true
        || value["complete"] != true
        || rows.len() != paths.len()
        || rows.len() < if file_layout { 3 } else { 2 }
        || rows.len() > if file_layout { 10 } else { 9 }
    {
        return Err("restricted private mutation probes incomplete".into());
    }
    let mut observed = BTreeSet::new();
    for row in rows {
        let path = row["path_sha256"]
            .as_str()
            .ok_or("mutation input hash absent")?;
        if !observed.insert(path.to_owned())
            || row["all_mutations_refused"] != true
            || row["write_dac_error"] != 5
            || row["write_owner_error"] != 5
            || [
                "write_error",
                "delete_error",
                "rename_error",
                "substitution_error",
            ]
            .iter()
            .any(|key| !matches!(row[*key].as_i64(), Some(5 | 32)))
        {
            return Err("private mutation authority or actual operation denial unproved".into());
        }
    }
    if observed != paths.iter().cloned().collect() {
        return Err("private mutation probe input set differs".into());
    }
    let dirs = value["directory_authority"]
        .as_array()
        .ok_or("private directory security probes unavailable")?;
    if dirs.len() != if file_layout { 1 } else { 2 }
        || dirs
            .iter()
            .any(|row| row["write_dac_error"] != 5 || row["write_owner_error"] != 5)
    {
        return Err("private directory owner security bypass was not denied".into());
    }
    Ok(())
}

fn text(units: &[u16]) -> Result<String, String> {
    if units.is_empty() || units.len() > PATH_UNITS || units.contains(&0) {
        return Err("provider path extent or embedded NUL is unsupported".into());
    }
    String::from_utf16(units).map_err(|_| "provider path UTF16 is malformed".into())
}

fn basename(units: &[u16]) -> Result<String, String> {
    let path = text(units)?;
    if path.contains('%') {
        return Err("expanded provider path contains unresolved environment syntax".into());
    }
    let (drive, rest) = path
        .split_once(":\\")
        .ok_or("provider path is not an absolute drive path")?;
    if drive.len() != "C".len() || !drive.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return Err("provider drive is unsupported".into());
    }
    let parts = rest.split('\\').collect::<Vec<_>>();
    if parts.is_empty()
        || parts.iter().any(|part| {
            part.is_empty()
                || *part == "."
                || *part == ".."
                || part.contains([':', '/'])
                || part.ends_with([' ', '.'])
        })
    {
        return Err("provider path components are ambiguous".into());
    }
    let leaf = parts.last().unwrap();
    // The first experiment refuses unproved native case/alias equivalences.
    if !leaf.is_ascii() || !leaf.to_ascii_lowercase().ends_with(".dll") {
        return Err("provider basename or DLL suffix is unsupported".into());
    }
    Ok((*leaf).to_owned())
}

/// Compare native expansion with the eventual fixture's explicit SystemRoot.
/// No other ambient variable is an input to this declared first experiment.
pub fn verify_expansion(snapshot: &CatalogSnapshot, system_root: &[u16]) -> Result<(), String> {
    let root = text(system_root)?;
    for provider in &snapshot.matching_providers {
        let configured = text(&provider.configured_path)?;
        let mut pieces = configured.split('%');
        let mut expanded = pieces.next().unwrap_or_default().to_owned();
        while let Some(variable) = pieces.next() {
            let tail = pieces
                .next()
                .ok_or("unterminated provider environment variable")?;
            if !variable.eq_ignore_ascii_case("SystemRoot") {
                return Err(
                    "provider expansion depends on an undeclared environment variable".into(),
                );
            }
            expanded.push_str(&root);
            expanded.push_str(tail);
        }
        if expanded.encode_utf16().collect::<Vec<_>>() != provider.expanded_path {
            return Err(
                "native provider expansion differs from declared fixture environment".into(),
            );
        }
    }
    Ok(())
}

/// Select only complete documented API observations from one exact capability.
/// This does not prove any source is readable, safe to copy, or actually loaded.
pub fn select(
    snapshot: &CatalogSnapshot,
    expected_declaration_sha256: &str,
) -> Result<Vec<Candidate>, String> {
    if snapshot.version != 1
        || !snapshot.complete
        || snapshot.declaration_sha256 != expected_declaration_sha256
        || expected_declaration_sha256.len() != 64
        || !expected_declaration_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || snapshot.catalog_entries == 0
        || snapshot.catalog_entries as usize > CATALOG_ENTRIES
        || snapshot.matching_providers.is_empty()
        || snapshot.matching_providers.len() > PROVIDER_FILES
        || snapshot.matching_providers.len() > snapshot.catalog_entries as usize
    {
        return Err("catalog observation is incomplete, unbound or outside finite limits".into());
    }
    let mut ids = BTreeSet::new();
    let mut paths = BTreeMap::<Vec<u16>, Candidate>::new();
    let mut names = BTreeMap::<String, Vec<u16>>::new();
    for provider in &snapshot.matching_providers {
        if provider.address_family != 2
            || provider.socket_type != 1
            || provider.protocol != 6
            || provider.chain_length != 1
            || provider.chain_entries.len() != 1
            || provider.catalog_id == 0
            || !ids.insert(provider.catalog_id)
            || provider.provider_id == [0; 16]
        {
            return Err("provider is not a unique observed IPv4 TCP catalog entry".into());
        }
        text(&provider.configured_path)?;
        let basename = basename(&provider.expanded_path)?;
        let folded = basename.to_ascii_lowercase();
        if names
            .get(&folded)
            .is_some_and(|path| path != &provider.expanded_path)
        {
            return Err("distinct provider source paths collide in the private directory".into());
        }
        names.insert(folded, provider.expanded_path.clone());
        let candidate = paths
            .entry(provider.expanded_path.clone())
            .or_insert_with(|| Candidate {
                expanded_path: provider.expanded_path.clone(),
                basename,
                catalog_ids: Vec::new(),
                provider_ids: Vec::new(),
            });
        candidate.catalog_ids.push(provider.catalog_id);
        if !candidate.provider_ids.contains(&provider.provider_id) {
            candidate.provider_ids.push(provider.provider_id);
        }
    }
    Ok(paths.into_values().collect())
}
