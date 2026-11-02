#![cfg(feature = "test-support")]
use memcordon_platform::windows_registry_error::{
    RegistryFailures, at, failures, require_access_denied,
};
use std::{
    error::Error,
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

fn raw_code(error: &(dyn Error + 'static)) -> Option<i32> {
    if let Some(error) = error.downcast_ref::<io::Error>() {
        if let Some(code) = error.raw_os_error() {
            return Some(code);
        }
        if let Some(inner) = error.get_ref() {
            if let Some(code) = raw_code(inner) {
                return Some(code);
            }
        }
    }
    error.source().and_then(raw_code)
}

#[test]
fn unexpected_native_errors_retain_kind_and_exact_original_source() {
    let error = at::<()>(
        Err(io::Error::from_raw_os_error(87)),
        "capture",
        "RegQueryInfoKeyW",
        "LSTATUS",
        Some(0x20019),
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::Error::from_raw_os_error(87).kind());
    assert_eq!(raw_code(&error), Some(87));
    let rendered = error.to_string();
    for expected in ["capture", "RegQueryInfoKeyW", "LSTATUS", "Some(87)"] {
        assert!(rendered.contains(expected));
    }
    let nested = at::<()>(
        Err(io::Error::other(io::Error::from_raw_os_error(87))),
        "token",
        "query_token_envelope",
        "Win32",
        None,
    )
    .unwrap_err();
    assert_eq!(nested.kind(), io::ErrorKind::Other);
    assert_eq!(raw_code(&nested), Some(87));
    assert!(nested.to_string().contains("native-code=Some(87)"));
}

#[test]
fn only_raw_expected_denial_is_accepted_and_successful_resources_drop() {
    require_access_denied::<()>(
        Err(io::Error::from_raw_os_error(5)),
        "immutable",
        "RegOpenKeyExW",
        Some(2),
    )
    .unwrap();
    let contextual = at::<()>(
        Err(io::Error::from_raw_os_error(5)),
        "earlier",
        "RegOpenKeyExW",
        "LSTATUS",
        None,
    );
    let error =
        require_access_denied(contextual, "immutable", "RegOpenKeyExW", Some(2)).unwrap_err();
    assert_eq!(raw_code(&error), Some(5));
    assert!(error.to_string().contains("earlier"));
    let wrong = require_access_denied::<()>(
        Err(io::Error::from_raw_os_error(6)),
        "immutable",
        "RegOpenKeyExW",
        None,
    )
    .unwrap_err();
    assert_eq!(raw_code(&wrong), Some(6));
    struct Owned(Arc<AtomicUsize>);
    impl Drop for Owned {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let drops = Arc::new(AtomicUsize::new(0));
    assert!(
        require_access_denied(
            Ok(Owned(drops.clone())),
            "immutable",
            "RegOpenKeyExW",
            Some(2)
        )
        .is_err()
    );
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn cleanup_retains_both_typed_errors_and_primary_precedence() {
    let primary = at::<()>(
        Err(io::Error::from_raw_os_error(5)),
        "mapping",
        "RegOverridePredefKey",
        "LSTATUS",
        None,
    )
    .unwrap_err();
    let secondary = at::<()>(
        Err(io::Error::from_raw_os_error(87)),
        "retirement",
        "NtDeleteKey",
        "Win32",
        None,
    )
    .unwrap_err();
    let kind = primary.kind();
    let combined = failures(primary, secondary);
    assert_eq!(combined.kind(), kind);
    let lanes = combined
        .get_ref()
        .unwrap()
        .downcast_ref::<RegistryFailures>()
        .unwrap();
    assert_eq!(raw_code(&lanes.primary), Some(5));
    assert_eq!(raw_code(&lanes.secondary), Some(87));
    let text = combined.to_string();
    assert!(text.find("mapping").unwrap() < text.find("retirement").unwrap());
    assert_eq!(raw_code(&combined), Some(5));
}

#[test]
fn diagnostic_text_is_bounded_without_losing_full_unicode_source() {
    let original = "界".repeat(10000);
    let error = at::<()>(
        Err(io::Error::other(original.clone())),
        "readback",
        "RegGetValueW",
        "LSTATUS",
        None,
    )
    .unwrap_err();
    let display = error.to_string();
    assert!(display.len() < 4600);
    assert!(display.ends_with("[truncated]"));
    let context = error.get_ref().unwrap();
    let retained = context
        .source()
        .unwrap()
        .downcast_ref::<io::Error>()
        .unwrap();
    assert_eq!(retained.to_string(), original);
    let medium = "x".repeat(2086);
    let error = at::<()>(
        Err(io::Error::other(medium.clone())),
        "network",
        "WSAStartup",
        "Win32",
        None,
    )
    .unwrap_err();
    assert!(error.to_string().contains(&medium));
    assert!(!error.to_string().contains("[truncated]"));
}
