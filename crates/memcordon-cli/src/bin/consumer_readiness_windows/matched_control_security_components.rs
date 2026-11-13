//! Bounded component fingerprints; separate from stream input comparison.
use serde::{Deserialize, Serialize};

pub const MAX_SIDECAR_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    Stdin,
    Stdout,
    Stderr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    BufferBounds,
    Header,
    ValidatorUnavailable,
    RelativeValidation,
    NativeValidation,
    NativeLength,
    Control,
    Owner,
    Group,
    SidValidity,
    SidLength,
    Dacl,
    LabelSaclSubset,
    AclValidity,
    AclInformation,
    ComponentBounds,
    Cutoff,
    Encoding,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Sid {
    Absent {},
    Observed {
        defaulted: bool,
        bytes: u32,
        sha256: [u8; 32],
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Acl {
    Absent {},
    Null {
        defaulted: bool,
    },
    Observed {
        defaulted: bool,
        ace_count: u32,
        bytes_in_use: u32,
        bytes_free: u32,
        used_sha256: [u8; 32],
        total_sha256: [u8; 32],
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Components {
    Unavailable {
        stage: Stage,
        native_win32_error: Option<i32>,
    },
    Observed(Box<ObservedComponents>),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedComponents {
    pub revision: u32,
    pub control: u16,
    pub native_bytes: u32,
    pub owner: Sid,
    pub group: Sid,
    pub dacl: Acl,
    pub label_sacl_subset: Acl,
}
impl Components {
    pub fn unavailable(stage: Stage, native_win32_error: Option<i32>) -> Self {
        Self::Unavailable {
            stage,
            native_win32_error,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub role: Role,
    pub security_information: u32,
    pub full_bytes: usize,
    pub full_sha256: [u8; 32],
    pub components: Components,
}

pub fn component_offset(base: usize, extent: usize, pointer: usize) -> Result<usize, Stage> {
    base.checked_add(extent).ok_or(Stage::ComponentBounds)?;
    pointer
        .checked_sub(base)
        .filter(|offset| *offset < extent)
        .ok_or(Stage::ComponentBounds)
}

pub fn component_bytes(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], Stage> {
    if length == 0 {
        return Err(Stage::ComponentBounds);
    }
    let end = offset.checked_add(length).ok_or(Stage::ComponentBounds)?;
    bytes.get(offset..end).ok_or(Stage::ComponentBounds)
}
