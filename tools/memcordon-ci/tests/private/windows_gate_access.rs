//! Actual production event snapshot and source-used comparison, not installed acceptance.
#[path = "../../../../crates/memcordon-cli/src/bin/consumer_readiness_windows/controller_gate_access.rs"]
mod controller_gate_access;
#[path = "../../../../crates/memcordon-cli/src/bin/consumer_readiness_windows/controller_gate_control_publication.rs"]
mod controller_gate_control_publication;
#[path = "../../../../crates/memcordon-cli/src/bin/consumer_readiness_windows/controller_gate_diagnostic.rs"]
mod controller_gate_diagnostic;
#[path = "../../../../crates/memcordon-cli/src/bin/consumer_readiness_windows/controller_gate_thread_control.rs"]
mod controller_gate_thread_control;
#[path = "../../../../crates/memcordon-cli/src/bin/consumer_readiness_windows/controller_gate_token.rs"]
mod controller_gate_token;
mod descriptor {
    pub use crate::windows_consumer_readiness::descriptor::gate_access;
}
use std::{
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{GetLastError, HANDLE},
    Security::{
        CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, DuplicateTokenEx, SID_AND_ATTRIBUTES,
        SecurityImpersonation, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY, TokenImpersonation,
    },
    System::Threading::{
        GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken, SetThreadToken,
    },
};

struct Restore {
    prior: Option<OwnedHandle>,
}

#[test]
fn supported_gate_resolution_probes_keep_controller_identity_separate_from_zero_rights() {
    use crate::windows_consumer_readiness::{gate_resolution, workload_diagnostic};
    let deadline = Instant::now() + Duration::from_secs(30);
    let name = super::name();
    let original = super::super::native::event_create(&name).unwrap();
    let other = super::super::native::event_create(&super::name()).unwrap();
    let terminated: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let before = workload_diagnostic::gate_security_snapshot(&original, deadline).unwrap();
    let thread_before = thread_identity();
    let live = || {
        if Instant::now() < deadline {
            Ok(())
        } else {
            Err(std::io::ErrorKind::TimedOut.into())
        }
    };
    let same = gate_resolution::query(&terminated, Some(&original), live);
    assert_eq!(
        (same.open_succeeded, same.same_original_event),
        (Some(true), Some(true))
    );
    let different = gate_resolution::query(&terminated, Some(&other), live);
    assert_eq!(
        (different.open_succeeded, different.same_original_event),
        (Some(true), Some(false))
    );
    assert_eq!(thread_identity(), thread_before);
    assert!(Instant::now() < deadline);
    // Independent native oracle: no production projection supplies this expectation.
    let raw =
        unsafe { windows_sys::Win32::System::Threading::OpenEventW(0, 0, terminated.as_ptr()) };
    let (oracle_success, oracle_error) = if raw.is_null() {
        (false, std::io::Error::last_os_error().raw_os_error())
    } else {
        let owner = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
        drop(owner);
        (true, None)
    };
    assert!(Instant::now() < deadline);
    let zero = gate_resolution::query(&terminated, None, live);
    assert_eq!(
        (zero.open_succeeded, zero.raw_os_error),
        (Some(oracle_success), oracle_error),
        "direct zero-access native result=({oracle_success:?},{oracle_error:?}); production={zero:?}"
    );
    assert_eq!(zero.desired_access, 0);
    assert!(matches!(
        zero.context,
        gate_resolution::Context::FailedFixture
    ));
    assert!(zero.diagnostic_only && zero.attempted && zero.original_work_live);
    assert_eq!(zero.unavailable, None);
    assert_eq!(zero.same_original_event, None);
    let expired = gate_resolution::query(&terminated, None, || {
        Err(std::io::ErrorKind::TimedOut.into())
    });
    assert!(!expired.attempted && expired.open_succeeded.is_none());
    let missing: Vec<u16> = super::name().encode_utf16().chain(Some(0)).collect();
    let missing = gate_resolution::query(&missing, None, live);
    assert_eq!(missing.open_succeeded, Some(false));
    assert!(missing.raw_os_error.is_some());
    assert_eq!(thread_identity(), thread_before);
    assert_eq!(
        workload_diagnostic::gate_security_snapshot(&original, deadline)
            .unwrap()
            .descriptor_sha256,
        before.descriptor_sha256
    );
}
impl Restore {
    fn install(token: HANDLE) -> Self {
        let mut raw = ptr::null_mut();
        let status = unsafe {
            OpenThreadToken(
                GetCurrentThread(),
                TOKEN_QUERY | TOKEN_IMPERSONATE,
                1,
                &mut raw,
            )
        };
        let prior = if status != 0 {
            Some(unsafe { OwnedHandle::from_raw_handle(raw) })
        } else {
            let code = unsafe { GetLastError() };
            assert_eq!(code, 1008);
            None
        };
        let owner = Self { prior };
        assert_ne!(unsafe { SetThreadToken(ptr::null(), token) }, 0);
        owner
    }
}
impl Drop for Restore {
    fn drop(&mut self) {
        if unsafe {
            SetThreadToken(
                ptr::null(),
                self.prior
                    .as_ref()
                    .map_or(ptr::null_mut(), AsRawHandle::as_raw_handle),
            )
        } == 0
        {
            std::process::abort();
        }
    }
}
fn source() -> OwnedHandle {
    let mut raw = ptr::null_mut();
    assert_ne!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut raw) },
        0
    );
    unsafe { OwnedHandle::from_raw_handle(raw) }
}
fn restricted(source: &OwnedHandle) -> OwnedHandle {
    let sid = [1_u8, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0];
    let mut aligned = [0_u64; 2];
    unsafe { ptr::copy_nonoverlapping(sid.as_ptr(), aligned.as_mut_ptr().cast(), sid.len()) };
    let entry = SID_AND_ATTRIBUTES {
        Sid: aligned.as_mut_ptr().cast(),
        Attributes: 0,
    };
    let mut raw = ptr::null_mut();
    assert_ne!(
        unsafe {
            CreateRestrictedToken(
                source.as_raw_handle(),
                DISABLE_MAX_PRIVILEGE,
                0,
                ptr::null(),
                0,
                ptr::null(),
                1,
                &entry,
                &mut raw,
            )
        },
        0
    );
    let primary = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut raw = ptr::null_mut();
    assert_ne!(
        unsafe {
            DuplicateTokenEx(
                primary.as_raw_handle(),
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                ptr::null(),
                SecurityImpersonation,
                TokenImpersonation,
                &mut raw,
            )
        },
        0
    );
    unsafe { OwnedHandle::from_raw_handle(raw) }
}
fn thread_identity() -> Option<(u64, memcordon_core::WindowsCallerTokenEnvelopeV1)> {
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_STATISTICS, TokenStatistics};
    let mut raw = ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) } == 0 {
        let code = unsafe { GetLastError() };
        assert_eq!(code, 1008);
        return None;
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut statistics: TOKEN_STATISTICS = unsafe { std::mem::zeroed() };
    let mut length = 0;
    assert_ne!(
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenStatistics,
                (&mut statistics as *mut TOKEN_STATISTICS).cast(),
                size_of::<TOKEN_STATISTICS>() as u32,
                &mut length,
            )
        },
        0
    );
    assert_eq!(length as usize, size_of::<TOKEN_STATISTICS>());
    let id = (u64::from(statistics.TokenId.HighPart as u32) << u32::BITS)
        | u64::from(statistics.TokenId.LowPart);
    Some((
        id,
        memcordon_windows_launch_core::query_token_envelope(token.as_raw_handle()).unwrap(),
    ))
}

#[test]
fn selected_waiter_production_start_gate_grants_wait_and_denies_modify_without_source_mutation() {
    use windows_sys::Win32::System::Threading::{OpenEventW, WaitForSingleObject};
    let deadline = Instant::now() + Duration::from_secs(30);
    let source = source();
    let before =
        memcordon_windows_launch_core::query_token_envelope(source.as_raw_handle()).unwrap();
    let original_thread = thread_identity();
    let restricted = restricted(&source);
    let selected_user = {
        let restore = Restore::install(restricted.as_raw_handle());
        let observed = controller_gate_token::capture(None);
        let user = hex::decode(
            observed["user"]["value"]["binary_hex"]
                .as_str()
                .expect("actual effective user SID observed"),
        )
        .unwrap();
        drop(restore);
        user
    };
    assert_eq!(thread_identity(), original_thread);
    let name = super::name();
    let (gate, policy) =
        super::super::native::start_gate_create(&name, &selected_user, deadline).unwrap();
    assert!(policy.contains("(A;;0x00100000;;;S-1-"));
    let label =
        crate::windows_consumer_readiness::workload_diagnostic::gate_mandatory_label_snapshot(
            &gate, deadline,
        )
        .unwrap();
    assert_eq!(label.information, 0x10);
    assert_eq!(
        crate::windows_consumer_readiness::workload_diagnostic::gate_mandatory_label_snapshot(
            &gate,
            Instant::now()
        )
        .unwrap_err()
        .kind(),
        std::io::ErrorKind::TimedOut
    );
    let snapshot = crate::windows_consumer_readiness::workload_diagnostic::gate_security_snapshot(
        &gate, deadline,
    )
    .unwrap();
    assert_eq!(snapshot.declared_ace_count, Some(4));
    assert!(
        snapshot
            .aces
            .iter()
            .all(|ace| ace.flags == 0 && ace.native_type == 0)
    );
    assert_eq!(
        snapshot
            .aces
            .iter()
            .map(|ace| ace.raw_u32_at_offset_four)
            .collect::<Vec<_>>(),
        vec![
            Some(0x001f0003),
            Some(0x001f0003),
            Some(0x00100000),
            Some(0x00100000)
        ]
    );
    let bytes = hex::decode(&snapshot.descriptor_bytes_hex).unwrap();
    let acl = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
    let mut at = acl + 8;
    for _ in 0..3 {
        at += usize::from(u16::from_le_bytes(
            bytes[at + 2..at + 4].try_into().unwrap(),
        ));
    }
    let size = usize::from(u16::from_le_bytes(
        bytes[at + 2..at + 4].try_into().unwrap(),
    ));
    assert_eq!(&bytes[at + 8..at + size], selected_user);
    let name_units = name.encode_utf16().collect::<Vec<_>>();
    let challenge = b"selected-start-gate-wait-contract";
    let (work_cutoff_qpc, qpc_frequency) =
        memcordon_testkit::windows_native_work_cutoff(deadline).unwrap();
    let input = descriptor::gate_access::Input {
        revision: 1,
        descriptor: bytes,
        descriptor_sha256: snapshot.descriptor_sha256.clone(),
        name_utf16_sha256: descriptor::gate_access::name_sha256(&name_units),
        challenge_sha256: descriptor::gate_access::sha256(challenge),
        work_cutoff_qpc,
        qpc_frequency,
        namespace: None,
    };
    super::super::native::signal(&gate).unwrap();
    {
        let restore = Restore::install(restricted.as_raw_handle());
        assert!(Instant::now() < deadline);
        let observed = controller_gate_token::capture(Some(controller_gate_token::AccessRequest {
            input: &input,
            name: &name_units,
            challenge,
        }));
        assert_eq!(observed["access_check"]["api_return"], true, "{observed}");
        assert_eq!(
            observed["access_check"]["access_status"], true,
            "{observed}"
        );
        assert_eq!(
            observed["access_check"]["granted_access"], 0x0010_0000_u32,
            "{observed}"
        );
        let terminated = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let raw = unsafe { OpenEventW(0x0010_0000, 0, terminated.as_ptr()) };
        assert!(
            !raw.is_null(),
            "wait-only OpenEventW failed: {}",
            std::io::Error::last_os_error()
        );
        let wait = unsafe { OwnedHandle::from_raw_handle(raw) };
        assert_eq!(unsafe { WaitForSingleObject(wait.as_raw_handle(), 0) }, 0);
        let raw = unsafe { OpenEventW(2, 0, terminated.as_ptr()) };
        let error = if raw.is_null() {
            Some(unsafe { GetLastError() })
        } else {
            drop(unsafe { OwnedHandle::from_raw_handle(raw) });
            None
        };
        assert_eq!(
            error,
            Some(5),
            "restricted waiter must not acquire EVENT_MODIFY_STATE"
        );
        assert!(Instant::now() < deadline);
        drop(restore);
    }
    assert_eq!(thread_identity(), original_thread);
    let installed = std::cell::Cell::new(false);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _restore = Restore::install(restricted.as_raw_handle());
        installed.set(true);
        panic!("injected waiter restoration failure");
    }));
    assert!(panic.is_err() && installed.get());
    assert_eq!(thread_identity(), original_thread);
    assert_eq!(
        memcordon_windows_launch_core::query_token_envelope(source.as_raw_handle()).unwrap(),
        before
    );
    let after = crate::windows_consumer_readiness::workload_diagnostic::gate_security_snapshot(
        &gate, deadline,
    )
    .unwrap();
    assert_eq!(after.descriptor_sha256, snapshot.descriptor_sha256);
    let label_after =
        crate::windows_consumer_readiness::workload_diagnostic::gate_mandatory_label_snapshot(
            &gate, deadline,
        )
        .unwrap();
    assert_eq!(label_after.descriptor_sha256, label.descriptor_sha256);
}
#[test]
fn original_production_gate_comparison_uses_real_restricted_self_token_without_promoting_grant() {
    let deadline = Instant::now() + Duration::from_secs(30);
    let name = super::name();
    let gate = super::super::native::event_create(&name).unwrap();
    let snapshot = crate::windows_consumer_readiness::workload_diagnostic::gate_security_snapshot(
        &gate, deadline,
    )
    .unwrap();
    let name = name.encode_utf16().collect::<Vec<_>>();
    let challenge = b"owned-native-comparison";
    let (work_cutoff_qpc, qpc_frequency) =
        memcordon_testkit::windows_native_work_cutoff(deadline).unwrap();
    let input = descriptor::gate_access::Input {
        revision: 1,
        descriptor: hex::decode(&snapshot.descriptor_bytes_hex).unwrap(),
        descriptor_sha256: snapshot.descriptor_sha256.clone(),
        name_utf16_sha256: descriptor::gate_access::name_sha256(&name),
        challenge_sha256: descriptor::gate_access::sha256(challenge),
        work_cutoff_qpc,
        qpc_frequency,
        namespace: None,
    };
    input.validate(&name, challenge).unwrap();
    let source = source();
    let before =
        memcordon_windows_launch_core::query_token_envelope(source.as_raw_handle()).unwrap();
    let restricted = restricted(&source);
    let original_thread = thread_identity();
    let restore = Restore::install(restricted.as_raw_handle());
    let capture = |value: &descriptor::gate_access::Input| {
        controller_gate_token::capture(Some(controller_gate_token::AccessRequest {
            input: value,
            name: &name,
            challenge,
        }))
    };
    let observed = capture(&input);
    let access = &observed["access_check"];
    assert_eq!(access["observed"], true, "{observed}");
    assert_eq!(access["api_return"], true, "{observed}");
    assert_eq!(access["requested_access"], 0x0010_0000_u32);
    assert!(access["access_status"].is_boolean()); // Denial is still a truthful diagnostic decision.
    assert_eq!(access["source_token_unchanged"], true);
    assert_eq!(access["duplicate_full_semantics_match"], true);
    assert_eq!(observed["origin"], "thread");
    assert_eq!(
        controller_gate_token::capture(None)["access_check"]["observed"],
        false
    );
    let mut expired = input.clone();
    expired.work_cutoff_qpc = 1;
    assert_eq!(capture(&expired)["access_check"]["observed"], false);
    let mut malformed = input.clone();
    malformed.descriptor[0] = 0;
    malformed.descriptor_sha256 = descriptor::gate_access::sha256(&malformed.descriptor);
    assert_eq!(capture(&malformed)["access_check"]["observed"], false);
    let wrong_object = controller_gate_access::observe(
        &controller_gate_token::AccessRequest {
            input: &input,
            name: &name,
            challenge,
        },
        gate.as_raw_handle(),
        controller_gate_token::TokenOrigin::Thread,
    );
    assert_eq!(wrong_object["observed"], false);
    assert_eq!(
        wrong_object["operation"],
        "GetTokenInformation-TokenStatistics"
    );
    assert!(
        controller_gate_diagnostic::encode(&observed).unwrap().len()
            < controller_gate_diagnostic::RECORD_BOUND
    );
    drop(restore);
    assert_eq!(thread_identity(), original_thread);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _restore = Restore::install(restricted.as_raw_handle());
        panic!("injected scoped test-token failure");
    }));
    assert!(panic.is_err());
    assert_eq!(thread_identity(), original_thread);
    assert_eq!(
        memcordon_windows_launch_core::query_token_envelope(source.as_raw_handle()).unwrap(),
        before
    );
    let after = crate::windows_consumer_readiness::workload_diagnostic::gate_security_snapshot(
        &gate, deadline,
    )
    .unwrap();
    assert_eq!(after.descriptor_sha256, input.descriptor_sha256);
    // Change only this test-owned event after all identity restoration/source proofs.
    use windows_sys::Win32::Security::{
        ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, SetKernelObjectSecurity,
    };
    let mut drift = input.descriptor.clone();
    let acl = u32::from_le_bytes(drift[16..20].try_into().unwrap()) as usize;
    let mask = acl + size_of::<ACL>() + size_of::<ACE_HEADER>();
    drift[mask] ^= 2; // Remove EVENT_MODIFY_STATE from the first original allow ACE.
    let mut aligned = vec![0_u64; drift.len().div_ceil(size_of::<u64>())];
    unsafe { ptr::copy_nonoverlapping(drift.as_ptr(), aligned.as_mut_ptr().cast(), drift.len()) };
    assert_ne!(
        unsafe {
            SetKernelObjectSecurity(
                gate.as_raw_handle(),
                DACL_SECURITY_INFORMATION,
                aligned.as_mut_ptr().cast(),
            )
        },
        0
    );
    let changed = crate::windows_consumer_readiness::workload_diagnostic::gate_security_snapshot(
        &gate, deadline,
    )
    .unwrap();
    assert_ne!(changed.descriptor_sha256, input.descriptor_sha256);
}
#[path = "windows_gate_thread_control.rs"]
mod thread_control_tests;
