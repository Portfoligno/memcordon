use memcordon_ci::{
    windows_provider_catalog::{Spec, checked_ready, checked_response, digest, frames},
    windows_provider_projection_record::{CatalogProvider, CatalogSnapshot},
};
use memcordon_platform::windows_registry_manifest::{Declaration, VERSION, View};
use serde_json::json;

fn spec() -> Spec {
    let declaration = Declaration {
        version: VERSION,
        view: View::Native,
        sha256: [7; 32],
    };
    Spec {
        version: 1,
        declaration_sha256: digest(&declaration).unwrap(),
        declaration,
        challenge_sha256: "a".repeat(64),
        cutoff_qpc: 12345,
        frequency: 10_000_000,
    }
}
fn output(spec: &Spec) -> Vec<u8> {
    let provider = CatalogProvider {
        catalog_id: 1003,
        provider_id: [9; 16],
        address_family: 2,
        socket_type: 1,
        protocol: 6,
        chain_length: 1,
        chain_entries: vec![1003],
        configured_path: "%SystemRoot%\\system32\\provider.dll"
            .encode_utf16()
            .collect(),
        expanded_path: r"C:\Windows\system32\provider.dll".encode_utf16().collect(),
    };
    let snapshot = CatalogSnapshot {
        version: 1,
        declaration_sha256: spec.declaration_sha256.clone(),
        complete: true,
        catalog_entries: 14,
        matching_providers: vec![provider],
    };
    let binding = digest(spec).unwrap();
    let ready = json!({"version":1,"pid":42,"birth":123,"spec_sha256":binding});
    let response =
        json!({"version":1,"pid":42,"birth":123,"spec_sha256":binding,"snapshot":snapshot});
    let mut bytes = serde_json::to_vec(&ready).unwrap();
    bytes.push(b'\n');
    bytes.extend(serde_json::to_vec(&response).unwrap());
    bytes.push(b'\n');
    bytes
}

#[test]
fn same_capability_input_and_original_held_helper_binding_survive_both_frames() {
    let spec = spec();
    let bytes = output(&spec);
    let snapshot = checked_response(&bytes, &spec, 42, 123).unwrap();
    assert_eq!(snapshot.declaration_sha256, spec.declaration_sha256);
    assert_eq!(snapshot.matching_providers[0].catalog_id, 1003);
    assert!(checked_response(&bytes, &spec, 43, 123).is_err());
    assert!(checked_response(&bytes, &spec, 42, 124).is_err());
    let mut foreign = spec.clone();
    foreign.challenge_sha256 = "b".repeat(64);
    assert!(checked_response(&bytes, &foreign, 42, 123).is_err());
}

#[test]
fn malformed_unknown_partial_and_unbound_frames_never_select_provider_inputs() {
    let spec = spec();
    let bytes = output(&spec);
    assert!(frames(&bytes[..bytes.len() - 1]).is_err());
    assert!(frames(b"{}\n\n").is_err());
    assert!(frames(b"{\"version\":1,\"version\":2}\n").is_err());
    assert!(frames(&vec![b'x'; 128 * 1024 + 1]).is_err());
    let mut observed = frames(&bytes).unwrap();
    observed[0]["handle"] = json!(123);
    assert!(checked_ready(observed[0].clone(), &spec, 42).is_err());
    let mut observed = frames(&bytes).unwrap();
    observed[1]["snapshot"]["complete"] = json!(false);
    let mut changed = Vec::new();
    for value in observed {
        changed.extend(serde_json::to_vec(&value).unwrap());
        changed.push(b'\n');
    }
    assert!(checked_response(&changed, &spec, 42, 123).is_err());
    let mut invalid = spec;
    invalid.declaration_sha256 = "0".repeat(64);
    assert!(invalid.validate().is_err());
}

#[test]
fn original_helper_failure_remains_primary_when_retirement_is_unavailable() {
    use memcordon_ci::windows_provider_catalog::{HelperFailure, preserve};
    let error = preserve::<(), ()>(
        Err(std::io::Error::from_raw_os_error(5)),
        Err(std::io::Error::other("retirement unknown")),
    )
    .unwrap_err();
    let source = error
        .get_ref()
        .unwrap()
        .downcast_ref::<HelperFailure>()
        .unwrap();
    assert_eq!(source.primary.raw_os_error(), Some(5));
    assert!(source.secondary.to_string().contains("retirement unknown"));
    assert!(preserve::<(), ()>(Ok(()), Err(std::io::Error::other("retirement unknown"))).is_err());
}
