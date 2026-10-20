use memcordon_core::{WindowsLoaderDebugEventV1, WindowsLoaderDebugImagePathSourceV1};
use serde_json::json;

#[test]
fn legacy_hosted_debug_event_keeps_its_wire_shape_without_provenance() {
    // Actual hosted 406 ARM capture's first CREATE_PROCESS event. This proves
    // compatibility of diagnostic schema only, not process or loader authority.
    let original = json!({
        "code":3, "process_id":21352, "thread_id":21360,
        "exception_code":null, "first_chance":null, "address":140695765778432_u64,
        "native_exit_code":null,
        "image_path":r"\\?\C:\Program Files\MemCordon\memcordon-target-desktop-bootstrap.exe",
        "image_path_error":null, "continuation":65538, "continuation_error":null,
    });
    let event: WindowsLoaderDebugEventV1 = serde_json::from_value(original.clone()).unwrap();
    assert_eq!(event.image_path_source, None);
    assert_eq!(serde_json::to_value(event).unwrap(), original);
}

#[test]
fn debug_image_path_provenance_is_typed_and_does_not_add_authority_fields() {
    for (source, expected) in [
        (WindowsLoaderDebugImagePathSourceV1::EventFile, "event-file"),
        (
            WindowsLoaderDebugImagePathSourceV1::MappedImage,
            "mapped-image",
        ),
    ] {
        let value = json!({
            "code":6, "process_id":21352, "thread_id":21360,
            "exception_code":null, "first_chance":null, "address":140708381130752_u64,
            "native_exit_code":null, "image_path":r"\Device\HarddiskVolume3\Windows\System32\module.dll",
            "image_path_error":null, "continuation":65538, "continuation_error":null,
        });
        let mut event: WindowsLoaderDebugEventV1 = serde_json::from_value(value).unwrap();
        event.image_path_source = Some(source);
        let encoded = serde_json::to_value(&event).unwrap();
        assert_eq!(encoded["image_path_source"], expected);
        assert!(encoded.get("authority").is_none());
        assert!(encoded.get("target_authorized").is_none());
        assert_eq!(
            serde_json::from_value::<WindowsLoaderDebugEventV1>(encoded).unwrap(),
            event
        );
    }
    assert!(
        serde_json::from_value::<WindowsLoaderDebugImagePathSourceV1>(json!("unknown-source"))
            .is_err()
    );
}
