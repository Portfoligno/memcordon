#[path = "../src/release/linux_fixture_memory_budget.rs"]
mod budget;

use budget::FrozenImageMemoryBudget;
use memcordon_core::workload_registry_v3::RuntimeImageDefinitionV1;

fn image(id: &str, sizes: &[u64]) -> RuntimeImageDefinitionV1 {
    let mut entries: Vec<_> = sizes
        .iter()
        .enumerate()
        .map(|(index, size)| {
            serde_json::json!({"kind":"regular", "path":format!("{id}/file-{index}"),
            "sha256":"00".repeat(32), "size":size, "executable":false})
        })
        .collect();
    entries.push(
        serde_json::json!({"kind":"symlink", "path":format!("{id}/alias"),
        "target":format!("{id}/file-0")}),
    );
    RuntimeImageDefinitionV1::parse(
        &serde_json::to_vec(&serde_json::json!({
            "format":"memcordon.runtime-image", "revision":1, "image_id":id,
            "target":"aarch64-unknown-linux-gnu", "entries":entries,
            "entrypoints":[], "library_directories":[], "startup_environment":[]
        }))
        .unwrap(),
    )
    .unwrap()
}

fn derive(
    runtime: &RuntimeImageDefinitionV1,
    input: &RuntimeImageDefinitionV1,
    pages: u64,
    headroom: u64,
) -> Result<FrozenImageMemoryBudget, String> {
    FrozenImageMemoryBudget::for_images(
        runtime,
        input,
        &runtime.reference()?,
        &input.reference()?,
        pages,
        headroom,
    )
}

#[test]
fn materialized_pages_and_existing_headroom_determine_the_enforced_request() {
    let runtime = image("runtime", &[4097, 0]);
    let input = image("input", &[1]);
    let frozen = derive(&runtime, &input, 4096, 128 * 1024 * 1024).unwrap();
    assert_eq!(frozen.image_bytes, 4098);
    assert_eq!(frozen.rounded_image_bytes, 3 * 4096);
    assert_eq!(frozen.limit_bytes, 3 * 4096 + 128 * 1024 * 1024);
    assert_eq!(frozen.token(), format!("+{}B", frozen.limit_bytes));
    frozen.require_maximum(frozen.limit_bytes).unwrap();
    assert!(frozen.require_maximum(128 * 1024 * 1024).is_err());
    let larger = derive(
        &image("runtime", &[8193, 0]),
        &input,
        4096,
        128 * 1024 * 1024,
    )
    .unwrap();
    assert_eq!(larger.limit_bytes - frozen.limit_bytes, 4096);
    assert_ne!(larger.runtime_image, frozen.runtime_image);
}

#[test]
fn original_image_references_cannot_authorize_a_changed_inventory() {
    let runtime = image("runtime", &[4096]);
    let input = image("input", &[1]);
    let changed = image("runtime", &[4097]);
    assert!(
        FrozenImageMemoryBudget::for_images(
            &changed,
            &input,
            &runtime.reference().unwrap(),
            &input.reference().unwrap(),
            4096,
            1
        )
        .is_err()
    );
    let mut invalid = runtime.clone();
    invalid.revision = 2;
    assert!(
        FrozenImageMemoryBudget::for_images(
            &invalid,
            &input,
            &runtime.reference().unwrap(),
            &input.reference().unwrap(),
            4096,
            1
        )
        .is_err()
    );
}

#[test]
fn invalid_native_page_sizes_and_arithmetic_overflow_fail_before_launch() {
    let runtime = image("runtime", &[1]);
    let input = image("input", &[1]);
    for pages in [0, 3, u64::MAX] {
        assert!(derive(&runtime, &input, pages, 1).is_err());
    }
    assert!(derive(&runtime, &input, 4096, 0).is_err());
    assert!(derive(&runtime, &input, 4096, u64::MAX).is_err());
    assert!(derive(&runtime, &input, 1_u64 << 63, 1).is_err());
}

#[test]
fn immutable_compiler_image_is_included_before_memory_pressure_headroom() {
    let runtime = image("runtime", &[928_191_125]);
    let input = image("input", &[7799]);
    for headroom in [128, 256, 512].map(|mib| mib * 1024 * 1024) {
        let frozen = derive(&runtime, &input, 4096, headroom).unwrap();
        assert!(frozen.rounded_image_bytes >= 928_198_924);
        assert_eq!(frozen.limit_bytes - frozen.rounded_image_bytes, headroom);
        assert!(frozen.require_maximum(headroom).is_err());
    }
}

#[test]
fn retained_public_and_completed_invocation_join_the_original_frozen_budget() {
    let frozen = derive(
        &image("runtime", &[4097]),
        &image("input", &[1]),
        4096,
        128 * 1024 * 1024,
    )
    .unwrap();
    let token = frozen.token();
    assert_eq!(
        frozen
            .require_invocation_tokens(Some(&token), Some(&token))
            .unwrap(),
        frozen.limit_bytes
    );
    assert!(
        frozen
            .require_invocation_tokens(None, Some(&token))
            .is_err()
    );
    assert!(
        frozen
            .require_invocation_tokens(Some(&token), Some("+128MiB"))
            .is_err()
    );
    assert!(
        frozen
            .require_invocation_tokens(Some("+128MiB"), Some("+128MiB"))
            .is_err()
    );
    let substituted = derive(
        &image("runtime", &[8193]),
        &image("input", &[1]),
        4096,
        128 * 1024 * 1024,
    )
    .unwrap();
    let changed = substituted.token();
    assert!(
        frozen
            .require_invocation_tokens(Some(&changed), Some(&changed))
            .is_err()
    );
}
