//! Bounded diagnostic projections for the original first library compiler.
use memcordon_core::{WindowsProcessIdentityV1, parse_windows_pe_imports};
use serde::Deserialize;
use serde_json::{Value, json};
pub const REPORT_EXTENSION: &str = "toolchain-loader-lookup.json";
pub const REPORT_BYTES: usize = 64 * 1024;
pub const RECEIPT_BYTES: usize = 16 * 1024;
pub const ARM64_TARGET: &str = "aarch64-pc-windows-msvc";

pub fn direct_compiler_disposition(outcome: &Value, original_status: u32) -> &'static str {
    let status = outcome["native_status"]
        .as_u64()
        .and_then(|status| u32::try_from(status).ok());
    let product = &outcome["product"];
    let valid_product = product["bytes"]
        .as_u64()
        .is_some_and(|bytes| (9..=16 * 1024 * 1024).contains(&bytes))
        && product["sha256"].as_str().is_some_and(|hash| {
            hash.len() == 64
                && hash
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        });
    match (outcome["state"].as_str(), status) {
        (Some("retired"), Some(0)) if valid_product => "direct-compiler-produced-library",
        (Some("retired"), Some(status)) if status != 0 && status == original_status => {
            "direct-compiler-reproduced-original-native-status"
        }
        _ => "direct-baseline-inconclusive",
    }
}

#[derive(Deserialize)]
struct Receipt {
    format: String,
    revision: u32,
    role: String,
    challenge: Vec<u8>,
    parent: WindowsProcessIdentityV1,
    child: WindowsProcessIdentityV1,
    image_sha256: String,
    held_from_process_creation: bool,
    held_live_before_wait: bool,
    native_parent_edge_observed: bool,
    #[serde(default)]
    native_wait_completed: bool,
    native_status: Option<i32>,
}

pub fn first_library_receipts(
    created: &[u8],
    retired: &[u8],
    challenge: &[u8],
    root: &WindowsProcessIdentityV1,
    compiler_sha256: &str,
) -> Option<(WindowsProcessIdentityV1, u32)> {
    if created.len() > RECEIPT_BYTES || retired.len() > RECEIPT_BYTES {
        return None;
    }
    let created: Receipt = serde_json::from_slice(created).ok()?;
    let retired: Receipt = serde_json::from_slice(retired).ok()?;
    for (receipt, kind) in [
        (&created, "memcordon.windows-fixture-owned-child-created"),
        (&retired, "memcordon.windows-fixture-owned-child-retired"),
    ] {
        if receipt.format != kind
            || receipt.revision != 1
            || receipt.role != "readiness.rlib"
            || receipt.challenge != challenge
            || &receipt.parent != root
            || receipt.image_sha256 != compiler_sha256
            || receipt.child.process_id == 0
            || receipt.child.process_id == root.process_id
            || root.process_id == 0
            || root.creation_time_100ns == 0
            || receipt.child.creation_time_100ns < root.creation_time_100ns
            || !receipt.held_from_process_creation
            || !receipt.held_live_before_wait
            || !receipt.native_parent_edge_observed
        {
            return None;
        }
    }
    if created.child != retired.child
        || created.native_wait_completed
        || created.native_status.is_some()
        || !retired.native_wait_completed
    {
        return None;
    }
    Some((retired.child, retired.native_status? as u32))
}

pub fn dll_basename(name: &str) -> bool {
    name.len() <= 128
        && name.to_ascii_lowercase().ends_with(".dll")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub fn static_image(
    role: &str,
    expected_sha256: &str,
    bytes: &[u8],
    staged: &[(String, String)],
) -> Value {
    let unavailable =
        |reason| json!({"role":role,"sha256":expected_sha256,"state":"incomplete","reason":reason});
    if crate::windows_causal_acceptance::sha256(bytes) != expected_sha256 {
        return unavailable("measured-image-digest-differs");
    }
    let Ok(imports) = parse_windows_pe_imports(bytes) else {
        return unavailable("unsupported-or-malformed-pe-import-table");
    };
    if imports.machine != memcordon_core::WINDOWS_PE_MACHINE_ARM64 {
        return json!({"role":role,"sha256":expected_sha256,"state":"incomplete",
            "reason":"unexpected-pe-machine","machine":imports.machine});
    }
    if imports.normal.len() + imports.delayed.len() > 128 {
        return unavailable("import-edge-bound-exceeded");
    }
    let mut imports_out = Vec::new();
    let mut redacted_edges = 0;
    for (kind, names) in [("normal", imports.normal), ("delay", imports.delayed)] {
        for name in names {
            if !dll_basename(&name) {
                redacted_edges += 1;
                continue;
            }
            let matching: Vec<_> = staged
                .iter()
                .filter(|(basename, _)| name.eq_ignore_ascii_case(basename))
                .map(|(_, digest)| digest)
                .collect();
            let upper = name.to_ascii_uppercase();
            imports_out.push(json!({"kind":kind,"basename":name.to_ascii_lowercase(),
                "api_set_contract":upper.starts_with("API-MS-") || upper.starts_with("EXT-MS-"),
                "same_staged_directory_sha256":matching}));
        }
    }
    json!({"role":role,"sha256":expected_sha256,"machine":imports.machine,
        "state":if redacted_edges == 0 { "complete" } else { "incomplete" },
        "redacted_edges":redacted_edges,"imports":imports_out})
}
