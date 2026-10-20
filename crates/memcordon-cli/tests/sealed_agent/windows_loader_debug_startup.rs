use super::{decode_debug_image_path, validate_startup_order, validate_startup_process};
use memcordon_core::WindowsProcessIdentityV1;
use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_DATA, ERROR_NO_UNICODE_TRANSLATION,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
    LOAD_DLL_DEBUG_EVENT,
};

#[test]
fn initial_debug_sequence_requires_exactly_one_leading_process_event() {
    validate_startup_order(false, CREATE_PROCESS_DEBUG_EVENT).unwrap();
    for code in [
        CREATE_THREAD_DEBUG_EVENT,
        LOAD_DLL_DEBUG_EVENT,
        EXIT_PROCESS_DEBUG_EVENT,
    ] {
        assert!(validate_startup_order(false, code).is_err());
        validate_startup_order(true, code).unwrap();
    }
    assert!(validate_startup_order(true, CREATE_PROCESS_DEBUG_EVENT).is_err());
}

#[test]
fn initial_debug_event_requires_the_selected_held_birth_and_primary_thread() {
    let selected = WindowsProcessIdentityV1 {
        process_id: 410,
        creation_time_100ns: 810,
    };
    validate_startup_process(&selected, 510, 410, 510, &selected).unwrap();
    for (primary, event_pid, event_tid, held) in [
        (0, 410, 510, selected.clone()),
        (510, 411, 510, selected.clone()),
        (510, 410, 511, selected.clone()),
        (
            510,
            410,
            510,
            WindowsProcessIdentityV1 {
                process_id: 410,
                creation_time_100ns: 811,
            },
        ),
        (
            510,
            410,
            510,
            WindowsProcessIdentityV1 {
                process_id: 411,
                creation_time_100ns: 810,
            },
        ),
    ] {
        assert!(validate_startup_process(&selected, primary, event_pid, event_tid, &held).is_err());
    }
}

#[test]
fn debug_image_path_decodes_only_returned_characters_and_keeps_unicode() {
    for path in [
        r"\Device\HarddiskVolume3\Windows\System32\ntdll.dll".to_owned(),
        "C:\\módulo\\😀.dll".to_owned(),
        "x".repeat(511),
    ] {
        let mut buffer: Vec<u16> = path.encode_utf16().collect();
        let length = u32::try_from(buffer.len()).unwrap();
        buffer.extend([0, b'z' as u16]);
        assert_eq!(decode_debug_image_path(&buffer, length).unwrap(), path);
    }
}

#[test]
fn debug_image_path_rejects_zero_truncation_invalid_unicode_and_byte_overrun() {
    assert_eq!(
        decode_debug_image_path(&[0; 512], 0),
        Err(ERROR_INVALID_DATA)
    );
    assert_eq!(
        decode_debug_image_path(&[0; 512], 512),
        Err(ERROR_INSUFFICIENT_BUFFER)
    );
    assert_eq!(
        decode_debug_image_path(&[0; 512], 513),
        Err(ERROR_INSUFFICIENT_BUFFER)
    );
    assert_eq!(
        decode_debug_image_path(&[0xd800, 0], 1),
        Err(ERROR_NO_UNICODE_TRANSLATION)
    );
    assert_eq!(
        decode_debug_image_path(&[0xdc00, 0], 1),
        Err(ERROR_NO_UNICODE_TRANSLATION)
    );
    let expanded = vec![0x0800; 1_025];
    assert_eq!(
        decode_debug_image_path(&expanded, 1_024),
        Err(ERROR_INSUFFICIENT_BUFFER)
    );
}
