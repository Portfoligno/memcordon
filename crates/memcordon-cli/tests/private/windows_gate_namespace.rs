use super::*;
use std::time::{Duration, Instant};

fn owned_event(name: Option<&[u16]>) -> OwnedHandle {
    use windows_sys::Win32::System::Threading::CreateEventW;
    unsafe {
        windows_sys::Win32::Foundation::SetLastError(0);
    }
    let raw = unsafe { CreateEventW(ptr::null(), 1, 0, name.map_or(ptr::null(), |n| n.as_ptr())) };
    let error = unsafe { GetLastError() };
    assert!(!raw.is_null(), "controlled event creation failed: {error}");
    let owner = unsafe { OwnedHandle::from_raw_handle(raw) };
    if name.is_some() {
        assert_ne!(error, windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS);
    }
    owner
}

#[test]
fn local_reference_comparator_distinguishes_actual_owned_events() {
    let deadline = Instant::now() + Duration::from_secs(20);
    let check = || {
        if Instant::now() < deadline {
            Ok(())
        } else {
            Err(io::ErrorKind::TimedOut.into())
        }
    };
    let first = owned_event(None);
    let second = owned_event(None);
    for (other, expected) in [(&first, true), (&second, false)] {
        let mut value = unprefixed_observation("test-not-started");
        assert!(compare_reference(&first, other, &check, &mut value).is_ok());
        assert_eq!(value["comparison_attempted"], true);
        assert_eq!(value["same_native_reference"], expected);
        assert_eq!(value["acceptance_authority"], false);
    }
}

#[test]
fn unprefixed_open_matches_independent_current_context_oracle() {
    let random = tempfile::tempdir().unwrap();
    let leaf: Vec<u16> = random
        .path()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .encode_utf16()
        .collect();
    let terminated: Vec<u16> = leaf.iter().copied().chain(Some(0)).collect();
    let native = owned_event(Some(&terminated));
    let deadline = Instant::now() + Duration::from_secs(20);
    let check = || {
        if Instant::now() < deadline {
            Ok(())
        } else {
            Err(io::ErrorKind::TimedOut.into())
        }
    };
    for candidate in [
        leaf.clone(),
        leaf.iter()
            .copied()
            .chain("-missing".encode_utf16())
            .collect(),
    ] {
        let name: Vec<u16> = candidate.iter().copied().chain(Some(0)).collect();
        check().unwrap();
        let raw = unsafe { OpenEventW(SYNCHRONIZE, 0, name.as_ptr()) };
        let error = if raw.is_null() {
            Some(unsafe { GetLastError() })
        } else {
            None
        };
        let oracle = if raw.is_null() {
            None
        } else {
            Some(unsafe { OwnedHandle::from_raw_handle(raw) })
        };
        check().unwrap();
        let value = unprefixed_comparison(&native, &candidate, &check);
        assert_eq!(value["open_succeeded"], oracle.is_some());
        assert_eq!(value["raw_os_error"], json!(error));
        assert_eq!(value["comparison_attempted"], oracle.is_some());
        if let Some(oracle) = oracle.as_ref() {
            check().unwrap();
            let same =
                unsafe { CompareObjectHandles(native.as_raw_handle(), oracle.as_raw_handle()) }
                    != 0;
            check().unwrap();
            assert_eq!(value["same_native_reference"], same);
        } else {
            assert!(value["same_native_reference"].is_null());
        }
        assert_eq!(value["work_confirmed"], true);
        assert!(value["source_confirmed"].is_null());
    }
    let calls = std::cell::Cell::new(0);
    let value = unprefixed_comparison(&native, &leaf, &|| {
        calls.set(calls.get() + 1);
        if calls.get() == 3 {
            Err(io::ErrorKind::TimedOut.into())
        } else {
            check()
        }
    });
    assert_eq!(calls.get(), 3);
    assert_eq!(value["attempted"], true);
    assert!(value["open_succeeded"].is_boolean());
    assert_eq!(value["comparison_attempted"], false);
    assert_eq!(value["work_confirmed"], false);
    for bad in [vec![], vec![0], "bad\\leaf".encode_utf16().collect()] {
        check().unwrap();
        let value = unprefixed_comparison(&native, &bad, &check);
        assert_eq!(value["attempted"], false);
        assert_eq!(value["comparison_attempted"], false);
    }
    let value = unprefixed_comparison(&native, &leaf, &|| Err(io::ErrorKind::TimedOut.into()));
    assert_eq!(value["attempted"], false);
    assert_eq!(value["comparison_attempted"], false);
}

#[test]
fn native_directory_open_matches_direct_same_context_status_without_assuming_access() {
    let deadline = Instant::now() + Duration::from_secs(20);
    let check = || {
        if Instant::now() < deadline {
            Ok(())
        } else {
            Err(io::ErrorKind::TimedOut.into())
        }
    };
    let api = Api::load(&check)
        .unwrap_or_else(|_| panic!("documented directory APIs unavailable in native fixture"));
    let name = [u16::from(b'\\')];
    let bytes = u16::try_from(size_of_val(&name)).unwrap();
    let string = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: name.as_ptr().cast_mut(),
    };
    let attributes = Attributes {
        length: size_of::<Attributes>() as u32,
        root: ptr::null_mut(),
        name: &string,
        attributes: OBJ_DONT_REPARSE,
        descriptor: ptr::null(),
        quality: ptr::null(),
    };
    let mut raw = ptr::null_mut();
    check().unwrap();
    let direct = unsafe { (api.directory)(&mut raw, 3, &attributes) };
    let original = if direct == 0 {
        assert!(!raw.is_null());
        Some(unsafe { OwnedHandle::from_raw_handle(raw) })
    } else {
        None
    };
    check().unwrap();
    let mut observed = None;
    let result = api.open_recorded(false, ptr::null_mut(), &name, 3, &check, &mut observed);
    assert_eq!(observed, Some(direct));
    assert_eq!(result.is_ok(), original.is_some());
    if let Err(error) = result {
        assert_eq!(error.status, Some(direct));
    }
    drop(original);
    check().unwrap();
}

#[test]
fn expired_and_out_of_contract_opens_never_issue_a_native_call() {
    let check = || Ok(());
    let api = Api::load(&check)
        .unwrap_or_else(|_| panic!("documented directory APIs unavailable in native fixture"));
    let root = [u16::from(b'\\')];
    let mut observed = None;
    let result = api.open_recorded(
        false,
        ptr::null_mut(),
        &root,
        3,
        &|| Err(io::ErrorKind::TimedOut.into()),
        &mut observed,
    );
    assert!(result.is_err() && observed.is_none());
    let result = api.open_recorded(
        true,
        ptr::null_mut(),
        &root,
        u32::MAX,
        &check,
        &mut observed,
    );
    assert!(result.is_err() && observed.is_none());
    let proof = Proof {
        revision: 1,
        components: vec!["test-only-unqueried".encode_utf16().collect()],
        path_sha256: String::new(),
        challenge_sha256: String::new(),
        name_utf16_sha256: String::new(),
        descriptor_sha256: String::new(),
        work_cutoff_qpc: 1,
        qpc_frequency: 1,
        controller_same_original: true,
        controller_absolute_same_original: true,
        complete: true,
    };
    let value = probe(&proof, || Err(io::ErrorKind::TimedOut.into()));
    assert_eq!(value["attempted"], false);
    assert!(value["native_event_status"].is_null());
    assert!(value["native_event_opened"].is_null());
    assert_eq!(value["same_original_event_identity_proved"], false);
}
