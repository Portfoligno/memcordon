//! Revision2 removal receipt shared by the native producer and strict consumer.
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};
pub const CENSUS_API: &str = "CreateToolhelp32Snapshot/Process32FirstW/Process32NextW";
pub const MAX_PROCESS_ENTRIES: u32 = 32768;
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum NoMatchingProcess {}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentCensus {
    pub api: String,
    pub entries_observed: u32,
    pub terminal_native_code: u32,
    pub required_image_names_utf16: Vec<Vec<u16>>,
    pub matching_processes: Vec<NoMatchingProcess>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceAbsence {
    pub service_name: String,
    pub api: String,
    pub native_domain: String,
    pub native_code: u32,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PathAbsence {
    pub path: PathBuf,
    pub native_domain: String,
    pub native_code: i32,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemovalReceipt {
    pub format: String,
    pub revision: u32,
    pub provider_generation: String,
    pub absent_services: Vec<String>,
    pub absent_paths: Vec<PathBuf>,
    pub fixture_processes_absent: bool,
    pub installed_image_processes_absent: bool,
    pub native_component_census: ComponentCensus,
    pub service_observations: Vec<ServiceAbsence>,
    pub path_observations: Vec<PathAbsence>,
}
pub fn fold_name(units: &[u16]) -> Vec<u16> {
    units
        .iter()
        .map(|unit| {
            if (65..=90).contains(unit) {
                unit + 32
            } else {
                *unit
            }
        })
        .collect()
}
pub fn image_names<'a>(paths: impl IntoIterator<Item = &'a Path>) -> Result<Vec<Vec<u16>>, String> {
    let mut names = BTreeSet::new();
    for path in paths {
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or("selected image name missing or not Unicode")?;
        if name.is_empty() || !name.is_ascii() {
            return Err("native component census requires exact ASCII package image names".into());
        }
        names.insert(fold_name(&name.encode_utf16().collect::<Vec<_>>()));
    }
    if names.is_empty() {
        return Err("selected image inventory empty".into());
    }
    Ok(names.into_iter().collect())
}
impl RemovalReceipt {
    pub fn validate(
        &self,
        generation: &str,
        paths: &[PathBuf],
        services: &[String],
        images: &[Vec<u16>],
    ) -> Result<(), String> {
        let census = &self.native_component_census;
        if self.format != "memcordon.windows-native-removal"
            || self.revision != 2
            || self.provider_generation != generation
            || self.absent_paths != paths
            || self.absent_services != services
            || !self.fixture_processes_absent
            || !self.installed_image_processes_absent
            || census.api != CENSUS_API
            || census.entries_observed > MAX_PROCESS_ENTRIES
            || census.terminal_native_code != 18
            || census.required_image_names_utf16 != images
            || !census.matching_processes.is_empty()
            || self.service_observations.len() != services.len()
            || self.path_observations.len() != paths.len()
            || self
                .service_observations
                .iter()
                .zip(services)
                .any(|(value, name)| {
                    value.service_name != *name
                        || value.api != "OpenServiceW"
                        || value.native_domain != "win32"
                        || value.native_code != 1060
                })
            || self
                .path_observations
                .iter()
                .zip(paths)
                .any(|(value, path)| {
                    value.path != *path
                        || value.native_domain != "win32"
                        || ![2, 3].contains(&value.native_code)
                })
        {
            return Err(
                "original native removal receipt layout/census/SCM/file observations differ".into(),
            );
        }
        Ok(())
    }
}
