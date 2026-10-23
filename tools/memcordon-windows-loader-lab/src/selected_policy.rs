//! Strict selected OWNER/GROUP/DACL/LABEL policy, independent of relative layout.
//! LABEL does not attest auditing ACEs. Selected label ACLs are label-only.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct Ace {
    kind: u8,
    flags: u8,
    mask: u32,
    sid: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct Acl {
    present: bool,
    defaulted: bool,
    value: Option<(u8, Vec<Ace>)>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct Policy {
    revision: u8,
    resource_manager: u8,
    control: u16,
    owner: Option<Vec<u8>>,
    group: Option<Vec<u8>>,
    dacl: Acl,
    label: Acl,
}
#[derive(Debug)]
pub struct Snapshot {
    pub raw_sha256: String,
    pub length: usize,
    pub selection: u32,
    policy: Policy,
}

fn span(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], String> {
    bytes
        .get(
            offset
                ..offset
                    .checked_add(length)
                    .ok_or("descriptor extent overflow")?,
        )
        .ok_or_else(|| "descriptor component truncated".into())
}
fn word(bytes: &[u8], offset: usize) -> Result<u16, String> {
    Ok(u16::from_le_bytes(
        span(bytes, offset, 2)?.try_into().expect("word extent"),
    ))
}
fn dword(bytes: &[u8], offset: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(
        span(bytes, offset, 4)?.try_into().expect("DWORD extent"),
    ))
}
fn sid(bytes: &[u8], offset: usize) -> Result<Vec<u8>, String> {
    let header = span(bytes, offset, 8)?;
    if header[0] != 1 || header[1] > 15 {
        return Err("unsupported SID revision/subauthority count".into());
    }
    Ok(span(bytes, offset, 8 + usize::from(header[1]) * 4)?.to_vec())
}
fn component_offset(bytes: &[u8], field: usize) -> Result<usize, String> {
    let offset = dword(bytes, field)? as usize;
    if offset != 0 && (offset < 20 || offset % 4 != 0) {
        return Err("relative component offset is not aligned outside header".into());
    }
    Ok(offset)
}
fn owner(bytes: &[u8], field: usize) -> Result<Option<Vec<u8>>, String> {
    let offset = component_offset(bytes, field)?;
    if offset == 0 {
        Ok(None)
    } else {
        sid(bytes, offset).map(Some)
    }
}
fn acl(
    bytes: &[u8],
    field: usize,
    present: bool,
    defaulted: bool,
    label: bool,
) -> Result<Acl, String> {
    let offset = component_offset(bytes, field)?;
    if !present && offset != 0 {
        return Err("absent ACL has a component offset".into());
    }
    if offset == 0 {
        return Ok(Acl {
            present,
            defaulted,
            value: None,
        });
    }
    let header = span(bytes, offset, 8)?;
    let revision = header[0];
    if ![2, 4].contains(&revision) || header[1] != 0 || word(header, 6)? != 0 {
        return Err("unsupported ACL revision/reserved header".into());
    }
    let size = usize::from(word(header, 2)?);
    if size < 8 || size % 4 != 0 {
        return Err("ACL size is shorter than header".into());
    }
    let raw = span(bytes, offset, size)?;
    let count = usize::from(word(header, 4)?);
    if count > (size - 8) / 4 {
        return Err("ACL ACE count exceeds owned extent".into());
    }
    let mut cursor = 8;
    let mut aces = Vec::with_capacity(count);
    for index in 0..count {
        let header = span(raw, cursor, 4)?;
        let kind = header[0];
        if if label {
            kind != 17
        } else {
            ![0, 1].contains(&kind)
        } {
            return Err(format!(
                "unsupported selected ACE kind={kind} index={index} label={label}"
            ));
        }
        let size = usize::from(word(header, 2)?);
        if size < 16 || size % 4 != 0 {
            return Err("ACE extent invalid".into());
        }
        let ace = span(raw, cursor, size)?;
        let trustee = sid(ace, 8)?;
        if size != 8 + trustee.len() {
            return Err("unsupported ACE payload or padding".into());
        }
        aces.push(Ace {
            kind,
            flags: header[1],
            mask: dword(ace, 4)?,
            sid: trustee,
        });
        cursor = cursor.checked_add(size).ok_or("ACE cursor overflow")?;
    }
    Ok(Acl {
        present,
        defaulted,
        value: Some((revision, aces)),
    })
}
pub fn capture(bytes: &[u8]) -> Result<Snapshot, String> {
    capture_selected(bytes, 0x17)
}

pub fn capture_selected(bytes: &[u8], selection: u32) -> Result<Snapshot, String> {
    if ![0x7, 0x17].contains(&selection) {
        return Err("unsupported selected policy information mask".into());
    }
    if !(20..=64 * 1024).contains(&bytes.len()) {
        return Err("descriptor length outside bound".into());
    }
    let control = word(bytes, 2)?;
    if bytes[0] != 1 || control & 0x8000 == 0 {
        return Err("descriptor is not revision1 self-relative".into());
    }
    let mut policy = Policy {
        revision: bytes[0],
        resource_manager: bytes[1],
        control,
        owner: owner(bytes, 4).map_err(|error| format!("owner control={control:#x}: {error}"))?,
        group: owner(bytes, 8).map_err(|error| format!("group control={control:#x}: {error}"))?,
        dacl: acl(bytes, 16, control & 4 != 0, control & 8 != 0, false)
            .map_err(|error| format!("DACL control={control:#x}: {error}"))?,
        label: acl(bytes, 12, control & 0x10 != 0, control & 0x20 != 0, true)
            .map_err(|error| format!("mandatory label control={control:#x}: {error}"))?,
    };
    // Validate all represented component extents above before projection. A
    // subsequent native validity query must never walk an unchecked offset.
    if selection == 0x7 {
        policy.control &= !(0x10 | 0x20 | 0x200 | 0x800 | 0x2000);
        policy.label = Acl {
            present: false,
            defaulted: false,
            value: None,
        };
    }
    Ok(Snapshot {
        raw_sha256: hex::encode(Sha256::digest(bytes)),
        length: bytes.len(),
        selection,
        policy,
    })
}
pub fn describe(snapshot: &Snapshot) -> String {
    let mut detail = format!(
        "selection={:#x} length={} raw={} policy={:?}",
        snapshot.selection, snapshot.length, snapshot.raw_sha256, snapshot.policy
    );
    if detail.len() > 4096 {
        detail.truncate(4096);
        detail.push_str(" [truncated]");
    }
    detail
}
pub fn compare(expected: &Snapshot, actual: &Snapshot) -> Result<(), String> {
    if expected.selection == actual.selection && expected.policy == actual.policy {
        return Ok(());
    }
    let fields = [
        ("selection", expected.selection != actual.selection),
        (
            "revision",
            expected.policy.revision != actual.policy.revision,
        ),
        (
            "resource_manager",
            expected.policy.resource_manager != actual.policy.resource_manager,
        ),
        ("control", expected.policy.control != actual.policy.control),
        ("owner", expected.policy.owner != actual.policy.owner),
        ("group", expected.policy.group != actual.policy.group),
        ("ordered DACL", expected.policy.dacl != actual.policy.dacl),
        (
            "ordered mandatory label",
            expected.policy.label != actual.policy.label,
        ),
    ]
    .into_iter()
    .filter_map(|(field, changed)| changed.then_some(field))
    .collect::<Vec<_>>();
    let mut detail = format!(
        "fields={fields:?}; control expected={:#x} actual={:#x} xor={:#x}; expected={}; actual={}",
        expected.policy.control,
        actual.policy.control,
        expected.policy.control ^ actual.policy.control,
        describe(expected),
        describe(actual)
    );
    if detail.len() > 8192 {
        detail.truncate(8192);
        detail.push_str(" [truncated]");
    }
    Err(detail)
}

#[derive(Debug, Eq, PartialEq)]
pub enum DesktopResult {
    Exact,
    DesktopSaclAutoInherited,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Domain {
    Station,
    Desktop,
    Gate,
}

impl Domain {
    pub fn selection(self) -> u32 {
        match self {
            Self::Station | Self::Desktop => 0x17,
            Self::Gate => 0x7,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFingerprint {
    pub schema_version: u32,
    pub selection: u32,
    pub domain: Domain,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComparisonOutcome {
    Exact,
    DesktopSaclAutoInherited,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedPolicy {
    pub fingerprint: PolicyFingerprint,
    pub comparison: ComparisonOutcome,
    pub observed_control: u16,
}

impl VerifiedPolicy {
    /// Wire-shape checks only. Admission also requires validate_verified against
    /// the parent's independently bound expected descriptor.
    pub fn validate_shape(&self, domain: Domain) -> Result<(), String> {
        let fingerprint = &self.fingerprint;
        if fingerprint.schema_version != 1
            || fingerprint.domain != domain
            || fingerprint.selection != domain.selection()
            || fingerprint.sha256.len() != Sha256::output_size() * 2
            || !fingerprint
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || self.observed_control & 0x8000 == 0
        {
            return Err(
                "selected policy fingerprint schema/domain/selection/digest/control differs".into(),
            );
        }
        if domain == Domain::Gate
            && self.observed_control & (0x10 | 0x20 | 0x200 | 0x800 | 0x2000) != 0
        {
            return Err("gate fingerprint claims unselected label controls".into());
        }
        match self.comparison {
            ComparisonOutcome::Exact if domain == Domain::Desktop => {
                if self.observed_control & (0x10 | 0x2000) != (0x10 | 0x2000)
                    || self.observed_control & (0x200 | 0x800) != 0
                {
                    return Err("exact desktop policy has invalid resultant control".into());
                }
            }
            ComparisonOutcome::DesktopSaclAutoInherited => {
                if domain != Domain::Desktop
                    || self.observed_control & (0x10 | 0x2000 | 0x800) != (0x10 | 0x2000 | 0x800)
                    || self.observed_control & 0x200 != 0
                {
                    return Err("desktop resultant claim has wrong domain/control".into());
                }
            }
            ComparisonOutcome::Exact => {}
        }
        Ok(())
    }
}

fn fingerprint(
    domain: Domain,
    selection: u32,
    policy: &Policy,
) -> Result<PolicyFingerprint, String> {
    #[derive(Serialize)]
    struct Encoding<'a> {
        format: &'static str,
        schema_version: u32,
        domain: Domain,
        selection: u32,
        policy: &'a Policy,
    }
    let encoding = Encoding {
        format: "memcordon.windows-selected-policy",
        schema_version: 1,
        domain,
        selection,
        policy,
    };
    let bytes = serde_json::to_vec(&encoding).map_err(|error| error.to_string())?;
    Ok(PolicyFingerprint {
        schema_version: 1,
        selection,
        domain,
        sha256: hex::encode(Sha256::digest(bytes)),
    })
}

pub fn expected_fingerprint(
    domain: Domain,
    expected: &Snapshot,
) -> Result<PolicyFingerprint, String> {
    if expected.selection != domain.selection() {
        return Err("expected policy selection/domain differs".into());
    }
    if domain == Domain::Desktop {
        compare_desktop_resultant(expected, expected)?;
    }
    fingerprint(domain, expected.selection, &expected.policy)
}

pub fn verify_and_fingerprint(
    domain: Domain,
    expected: &Snapshot,
    actual: &Snapshot,
) -> Result<VerifiedPolicy, String> {
    expected_fingerprint(domain, expected)?;
    if actual.selection != domain.selection() {
        return Err("observed policy selection/domain differs".into());
    }
    let comparison = match domain {
        Domain::Desktop => match compare_desktop_resultant(expected, actual)? {
            DesktopResult::Exact => ComparisonOutcome::Exact,
            DesktopResult::DesktopSaclAutoInherited => ComparisonOutcome::DesktopSaclAutoInherited,
        },
        Domain::Station | Domain::Gate => {
            compare(expected, actual)?;
            ComparisonOutcome::Exact
        }
    };
    let mut admitted = actual.policy.clone();
    if comparison == ComparisonOutcome::DesktopSaclAutoInherited {
        admitted.control &= !0x800;
    }
    let verified = VerifiedPolicy {
        fingerprint: fingerprint(domain, actual.selection, &admitted)?,
        comparison,
        observed_control: actual.policy.control,
    };
    verified.validate_shape(domain)?;
    Ok(verified)
}

pub fn validate_verified(
    domain: Domain,
    expected: &Snapshot,
    verified: &VerifiedPolicy,
) -> Result<(), String> {
    verified.validate_shape(domain)?;
    if verified.fingerprint != expected_fingerprint(domain, expected)? {
        return Err("verified policy fingerprint differs from bound expected policy".into());
    }
    let control = match verified.comparison {
        ComparisonOutcome::Exact => expected.policy.control,
        ComparisonOutcome::DesktopSaclAutoInherited => expected.policy.control | 0x800,
    };
    if verified.observed_control != control {
        return Err("verified policy resultant claim differs from bound expected control".into());
    }
    Ok(())
}

/// Match the existing protected desktop resultant contract, never stations.
/// Raw snapshots and the strict comparison remain unchanged.
pub fn compare_desktop_resultant(
    expected: &Snapshot,
    actual: &Snapshot,
) -> Result<DesktopResult, String> {
    if expected.selection != 0x17 || actual.selection != 0x17 {
        return Err("desktop resultant requires selection0x17".into());
    }
    const PRESENT: u16 = 0x0010;
    const REQUEST: u16 = 0x0200;
    const INHERITED: u16 = 0x0800;
    const PROTECTED: u16 = 0x2000;
    let selected_label = |policy: &Policy| {
        (policy.control & (PRESENT | PROTECTED)) == (PRESENT | PROTECTED)
            && policy.control & REQUEST == 0
            && policy.label.present
            && policy
                .label
                .value
                .as_ref()
                .is_some_and(|(_, aces)| aces.len() == 1)
    };
    if !selected_label(&expected.policy)
        || expected.policy.control & INHERITED != 0
        || !selected_label(&actual.policy)
    {
        return Err(format!(
            "desktop protected creation/resultant precondition differs; expected={}; actual={}",
            describe(expected),
            describe(actual)
        ));
    }
    if expected.policy == actual.policy {
        return Ok(DesktopResult::Exact);
    }
    if (expected.policy.control ^ actual.policy.control) == INHERITED
        && actual.policy.control & INHERITED != 0
    {
        let mut resultant = actual.policy.clone();
        resultant.control &= !INHERITED;
        if resultant == expected.policy {
            return Ok(DesktopResult::DesktopSaclAutoInherited);
        }
    }
    compare(expected, actual)?;
    unreachable!("unequal desktop policy cannot pass strict comparison")
}
