use memcordon_ci::windows_toolchain_lookup_record::{
    RECEIPT_BYTES, direct_compiler_disposition, dll_basename, first_library_receipts, static_image,
};
use memcordon_core::WindowsProcessIdentityV1;
use serde_json::{Value, json};

const DIGEST: &str = "2521ce928e557f314fbe62e22f7285abbab5fca2224dc18b0808e2e64cf34aaab";
const CHALLENGE: &[u8] = &[9, 3, 7];
const ROOT: WindowsProcessIdentityV1 = WindowsProcessIdentityV1 {
    process_id: 10,
    creation_time_100ns: 12,
};
const CHILD: WindowsProcessIdentityV1 = WindowsProcessIdentityV1 {
    process_id: 11,
    creation_time_100ns: 24,
};

#[test]
fn direct_comparison_requires_retirement_and_a_product_for_success() {
    let original_status = 0xc000_0135_u32;
    let mut outcome = json!({"state":"retired","native_status":original_status,"product":null});
    assert_eq!(
        direct_compiler_disposition(&outcome, original_status),
        "direct-compiler-reproduced-original-native-status"
    );
    outcome["native_status"] = json!(0);
    assert_eq!(
        direct_compiler_disposition(&outcome, original_status),
        "direct-baseline-inconclusive"
    );
    let product = b"!<arch>\nsynthetic product";
    outcome["product"] = json!({"bytes":product.len(),
        "sha256":memcordon_ci::windows_causal_acceptance::sha256(product)});
    assert_eq!(
        direct_compiler_disposition(&outcome, original_status),
        "direct-compiler-produced-library"
    );
    outcome["state"] = json!("spawn-error");
    assert_eq!(
        direct_compiler_disposition(&outcome, original_status),
        "direct-baseline-inconclusive"
    );
}

fn receipts() -> (Value, Value) {
    let created = json!({
        "format":"memcordon.windows-fixture-owned-child-created","revision":1,
        "role":"readiness.rlib","challenge":CHALLENGE,"parent":ROOT,"child":CHILD,"image_sha256":DIGEST,
        "held_from_process_creation":true,"held_live_before_wait":true,"native_parent_edge_observed":true,
    });
    let mut retired = created.clone();
    retired["format"] = json!("memcordon.windows-fixture-owned-child-retired");
    retired["native_wait_completed"] = json!(true);
    retired["native_status"] = json!(0xC000_0135_u32 as i32);
    (created, retired)
}

fn bind(created: &Value, retired: &Value) -> Option<(WindowsProcessIdentityV1, u32)> {
    first_library_receipts(
        &serde_json::to_vec(created).unwrap(),
        &serde_json::to_vec(retired).unwrap(),
        CHALLENGE,
        &ROOT,
        DIGEST,
    )
}

#[test]
fn first_library_receipts_require_the_original_generation_and_signed_native_status() {
    let (created, retired) = receipts();
    assert_eq!(bind(&created, &retired), Some((CHILD, 0xC000_0135)));
    for (key, replacement) in [
        ("child", json!({"process_id":11,"creation_time_100ns":25})),
        ("challenge", json!([9, 3, 8])),
        ("role", json!("readiness-dll.dll")),
        ("held_live_before_wait", json!(false)),
        ("native_wait_completed", json!(false)),
        ("native_status", Value::Null),
    ] {
        let mut mismatched = retired.clone();
        mismatched[key] = replacement;
        assert!(bind(&created, &mismatched).is_none(), "{key}");
    }
    let oversize = vec![b' '; RECEIPT_BYTES + 1];
    assert!(first_library_receipts(&oversize, b"", CHALLENGE, &ROOT, DIGEST).is_none());
}

#[test]
fn static_candidate_projection_does_not_expose_paths_or_unmeasured_imports() {
    assert!(dll_basename("RuStC_DrIvEr-123.DlL"));
    for name in [
        r"C:\private\bad.dll",
        "system/bad.dll",
        "bad:stream.dll",
        "work.exe",
    ] {
        assert!(!dll_basename(name));
    }
    let rejected = static_image("compiler", DIGEST, b"data", &[]);
    assert_eq!(rejected["reason"], "measured-image-digest-differs");
    assert!(rejected.get("imports").is_none());
    let digest = memcordon_ci::windows_causal_acceptance::sha256(b"data");
    let rejected = static_image("compiler", &digest, b"data", &[]);
    assert_eq!(
        rejected["reason"],
        "unsupported-or-malformed-pe-import-table"
    );
    assert!(rejected.get("imports").is_none());
}
