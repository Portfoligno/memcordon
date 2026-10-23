use super::*;
use crate::selected_policy as user_policy_snapshot;
use crate::selected_policy_native;
use windows_sys::Win32::System::StationsAndDesktops::*;

// Documented access-token SID flags; no additional native API feature needed.
const GROUP_ENABLED: u32 = 0x4;
const GROUP_DENY_ONLY: u32 = 0x10;

#[test]
fn security_only_carrier_restores_primary_and_rejects_missing_privilege() {
    absent_thread().unwrap();
    let source = primary().unwrap();
    let before = snapshot(source.as_raw_handle().cast()).unwrap();
    let source_history =
        historical_filtering(source.as_raw_handle().cast(), "test-source").unwrap();
    require_no_deny_only(source.as_raw_handle().cast()).unwrap();
    let carrier = SecurityCreationCarrier::attach(
        source.as_raw_handle().cast(),
        snapshot(source.as_raw_handle().cast()).unwrap(),
    )
    .unwrap();
    let mut effective = ptr::null_mut();
    assert_ne!(
        unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut effective) },
        0
    );
    let effective = own(effective).unwrap();
    eprintln!(
        "creation history source={source_history} effective={}",
        historical_filtering(effective.as_raw_handle().cast(), "test-effective").unwrap()
    );
    attest_access(effective.as_raw_handle().cast(), TOKEN_QUERY).unwrap();
    attest(effective.as_raw_handle().cast(), &before.envelope).unwrap();
    assert!(
        SecurityCreationCarrier::enter(before.envelope.session_id).is_err(),
        "nested impersonation must fail"
    );
    carrier.finish().unwrap();
    absent_thread().unwrap();
    assert_eq!(snapshot(source.as_raw_handle().cast()).unwrap(), before);

    let missing = duplicate(
        source.as_raw_handle().cast(),
        TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_PRIVILEGES,
    )
    .unwrap();
    adjust(
        missing.as_raw_handle().cast(),
        security_luid().unwrap(),
        SE_PRIVILEGE_REMOVED,
    )
    .unwrap();
    assert!(
        derive_security_only(missing.as_raw_handle().cast())
            .unwrap_err()
            .contains("1300")
    );
    assert_eq!(snapshot(source.as_raw_handle().cast()).unwrap(), before);
    absent_thread().unwrap();
    assert!(SecurityCreationCarrier::enter(before.envelope.session_id.wrapping_add(1)).is_err());
    if before.envelope.user_sid != "S-1-5-18" {
        assert!(SecurityCreationCarrier::enter(before.envelope.session_id).is_err());
    }
}

struct Objects {
    original: HWINSTA,
    station: HWINSTA,
    desktop: HDESK,
}

fn filtered(
    source: HANDLE,
    disabled: &[SID_AND_ATTRIBUTES],
    deleted: &[LUID_AND_ATTRIBUTES],
    restricting: &[SID_AND_ATTRIBUTES],
) -> OwnedHandle {
    let mut raw = ptr::null_mut();
    let result = unsafe {
        CreateRestrictedToken(
            source,
            0,
            u32::try_from(disabled.len()).unwrap(),
            if disabled.is_empty() {
                ptr::null()
            } else {
                disabled.as_ptr()
            },
            u32::try_from(deleted.len()).unwrap(),
            if deleted.is_empty() {
                ptr::null()
            } else {
                deleted.as_ptr()
            },
            u32::try_from(restricting.len()).unwrap(),
            if restricting.is_empty() {
                ptr::null()
            } else {
                restricting.as_ptr()
            },
            &mut raw,
        )
    };
    let code = unsafe { GetLastError() };
    assert_ne!(result, 0, "CreateRestrictedToken native_code={code}");
    own(raw).unwrap()
}

fn well_known(kind: WELL_KNOWN_SID_TYPE) -> Vec<u64> {
    let mut sid = vec![0u64; (SECURITY_MAX_SID_SIZE as usize).div_ceil(size_of::<u64>())];
    let mut length = SECURITY_MAX_SID_SIZE;
    assert_ne!(
        unsafe { CreateWellKnownSid(kind, ptr::null_mut(), sid.as_mut_ptr().cast(), &mut length) },
        0
    );
    sid
}

fn admin_enabled(token: HANDLE) -> bool {
    let admin = well_known(WinBuiltinAdministratorsSid);
    let token = duplicate(token, TOKEN_QUERY).unwrap();
    let mut member = 0;
    assert_ne!(
        unsafe {
            CheckTokenMembership(
                token.as_raw_handle().cast(),
                admin.as_ptr().cast_mut().cast(),
                &mut member,
            )
        },
        0
    );
    member != 0
}

#[test]
fn privilege_only_filtering_preserves_the_exact_creation_role_and_primary() {
    absent_thread().unwrap();
    let source = primary().unwrap();
    let before = snapshot(source.as_raw_handle().cast()).unwrap();
    let security = security_luid().unwrap();
    let removed = entries(source.as_raw_handle().cast())
        .unwrap()
        .into_iter()
        .find(|entry| !same_luid(entry.Luid, security))
        .expect("fixture needs one removable non-Security privilege");
    let copy = filtered(source.as_raw_handle().cast(), &[], &[removed], &[]);
    let source_history =
        historical_filtering(source.as_raw_handle().cast(), "test-original-source").unwrap();
    let filtered_history =
        historical_filtering(copy.as_raw_handle().cast(), "test-privilege-only-source").unwrap();
    assert_ne!(
        filtered_history, 0,
        "fixture must prove historical filtering"
    );
    assert!(
        !entries(copy.as_raw_handle().cast())
            .unwrap()
            .iter()
            .any(|entry| same_luid(entry.Luid, removed.Luid))
    );
    require_no_deny_only(copy.as_raw_handle().cast()).unwrap();
    let mut expected = before.envelope.clone();
    let filtered_envelope = query_token_envelope(copy.as_raw_handle().cast()).unwrap();
    expected.privileges_sha256 = filtered_envelope.privileges_sha256.clone();
    assert_eq!(filtered_envelope, expected);
    // The restoration witness is the actual process primary, never the
    // disposable filtered copy. Only its allowed privilege history differs.
    let carrier = SecurityCreationCarrier::attach(
        copy.as_raw_handle().cast(),
        snapshot(source.as_raw_handle().cast()).unwrap(),
    )
    .unwrap();
    let final_history =
        historical_filtering(carrier.token.as_raw_handle().cast(), "test-final-carrier").unwrap();
    attest(carrier.token.as_raw_handle().cast(), &before.envelope).unwrap();
    eprintln!(
        "creation privilege-only history original={source_history} filtered={filtered_history} final={final_history}"
    );
    carrier.finish().unwrap();
    absent_thread().unwrap();
    assert_eq!(snapshot(source.as_raw_handle().cast()).unwrap(), before);
}

#[test]
fn creation_role_rejects_deny_only_restrictions_and_wrong_handle_authority() {
    let source = primary().unwrap();
    let narrowed = derive_security_only(source.as_raw_handle().cast()).unwrap();
    assert!(attest_access(narrowed.as_raw_handle().cast(), TOKEN_QUERY).is_err());
    let mut admin = [0u64; (SECURITY_MAX_SID_SIZE as usize).div_ceil(8)];
    let mut length = SECURITY_MAX_SID_SIZE;
    assert_ne!(
        unsafe {
            CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                ptr::null_mut(),
                admin.as_mut_ptr().cast(),
                &mut length,
            )
        },
        0
    );
    let disabled = SID_AND_ATTRIBUTES {
        Sid: admin.as_mut_ptr().cast(),
        Attributes: 0,
    };
    let mut raw = ptr::null_mut();
    assert_ne!(
        unsafe {
            CreateRestrictedToken(
                source.as_raw_handle().cast(),
                0,
                1,
                &disabled,
                0,
                ptr::null(),
                0,
                ptr::null(),
                &mut raw,
            )
        },
        0
    );
    let restricted = own(raw).unwrap();
    assert_eq!(
        unsafe { IsTokenRestricted(restricted.as_raw_handle().cast()) },
        0
    );
    assert_ne!(
        historical_filtering(restricted.as_raw_handle().cast(), "test-admin-deny-only").unwrap(),
        0
    );
    let restricted_envelope = query_token_envelope(restricted.as_raw_handle().cast()).unwrap();
    let carrier = derive_security_only(restricted.as_raw_handle().cast()).unwrap();
    assert!(
        attest(carrier.as_raw_handle().cast(), &restricted_envelope)
            .unwrap_err()
            .contains("deny-only group SID")
    );
    absent_thread().unwrap();
}

#[test]
fn creation_role_rejects_non_admin_and_user_deny_only_and_restricting_sids() {
    absent_thread().unwrap();
    let source = primary().unwrap();
    let before = snapshot(source.as_raw_handle().cast()).unwrap();
    let mut admin = well_known(WinBuiltinAdministratorsSid);
    let user = query(source.as_raw_handle().cast(), TokenUser).unwrap();
    assert!(*user.last().unwrap() >= size_of::<TOKEN_USER>() as u64);
    let user_sid = unsafe { user.as_ptr().cast::<TOKEN_USER>().read_unaligned().User.Sid };
    let groups = query(source.as_raw_handle().cast(), TokenGroups).unwrap();
    let extent = *groups.last().unwrap() as usize;
    let offset = std::mem::offset_of!(TOKEN_GROUPS, Groups);
    assert!(extent >= offset);
    let count = unsafe { groups.as_ptr().cast::<u32>().read_unaligned() } as usize;
    assert!(
        count
            .checked_mul(size_of::<SID_AND_ATTRIBUTES>())
            .and_then(|bytes| offset.checked_add(bytes))
            .is_some_and(|end| end <= extent)
    );
    let base = unsafe {
        groups
            .as_ptr()
            .cast::<u8>()
            .add(offset)
            .cast::<SID_AND_ATTRIBUTES>()
    };
    let selected = (0..count)
        .map(|index| unsafe { base.add(index).read_unaligned() })
        .find(|group| {
            group.Attributes & GROUP_ENABLED != 0
                && group.Attributes & GROUP_DENY_ONLY == 0
                && unsafe { EqualSid(group.Sid, admin.as_mut_ptr().cast()) } == 0
                && unsafe { EqualSid(group.Sid, user_sid) } == 0
        })
        .expect("fixture needs an enabled non-Administrator, non-user group");
    let non_admin = filtered(source.as_raw_handle().cast(), &[selected], &[], &[]);
    let (user_attributes, group_attributes) =
        sid_attributes(non_admin.as_raw_handle().cast()).unwrap();
    assert_eq!(user_attributes & GROUP_DENY_ONLY, 0);
    assert!(
        group_attributes
            .iter()
            .any(|attributes| attributes & GROUP_DENY_ONLY != 0)
    );
    assert!(
        admin_enabled(non_admin.as_raw_handle().cast()),
        "Administrators must remain enabled in this fixture"
    );
    assert!(
        attest_sid_state(non_admin.as_raw_handle().cast(), "test-non-admin-deny-only")
            .unwrap_err()
            .contains("deny-only group SID")
    );

    let deny_user = filtered(
        source.as_raw_handle().cast(),
        &[SID_AND_ATTRIBUTES {
            Sid: user_sid,
            Attributes: 0,
        }],
        &[],
        &[],
    );
    let (user_attributes, _) = sid_attributes(deny_user.as_raw_handle().cast()).unwrap();
    assert_ne!(
        user_attributes & GROUP_DENY_ONLY,
        0,
        "native fixture must mark the USER SID deny-only"
    );
    assert!(
        attest_sid_state(deny_user.as_raw_handle().cast(), "test-user-deny-only")
            .unwrap_err()
            .contains("deny-only user SID")
    );

    let mut everyone = well_known(WinWorldSid);
    let restricted = filtered(
        source.as_raw_handle().cast(),
        &[],
        &[],
        &[SID_AND_ATTRIBUTES {
            Sid: everyone.as_mut_ptr().cast(),
            Attributes: 0,
        }],
    );
    assert_ne!(
        unsafe { IsTokenRestricted(restricted.as_raw_handle().cast()) },
        0
    );
    assert_eq!(
        attest_sid_state(restricted.as_raw_handle().cast(), "test-restricting-sid").unwrap_err(),
        "creation carrier is restricted"
    );
    assert_eq!(snapshot(source.as_raw_handle().cast()).unwrap(), before);
    absent_thread().unwrap();
}
impl Drop for Objects {
    fn drop(&mut self) {
        unsafe {
            if !self.original.is_null() {
                assert_ne!(SetProcessWindowStation(self.original), 0);
            }
            if !self.desktop.is_null() {
                assert_ne!(CloseDesktop(self.desktop), 0);
            }
            if !self.station.is_null() {
                assert_ne!(CloseWindowStation(self.station), 0);
            }
        }
    }
}

fn expected_descriptor(
    policy: &NativeSecurityDescriptorV1,
) -> Result<user_policy_snapshot::Snapshot, String> {
    selected_policy_native::expected(policy, 0x17)
}

fn observed_descriptor(handle: HANDLE) -> Result<user_policy_snapshot::Snapshot, String> {
    unsafe { selected_policy_native::read_user(handle) }
}

#[test]
fn security_only_role_creates_sacl_user_objects_with_original_policy() {
    // Exercise the private native mechanism under the hosted administrator;
    // the public holder entry independently requires SYSTEM and exact session.
    absent_thread().unwrap();
    let source = primary().unwrap();
    let before = snapshot(source.as_raw_handle().cast()).unwrap();
    let sddl = format!(
        "O:{}G:{}D:P(A;;0xf016f;;;OW)(A;;0xf016f;;;SY)S:P(ML;;NW;;;{})",
        before.envelope.user_sid,
        before.envelope.primary_group_sid,
        before.envelope.integrity_level
    );
    let policy = NativeSecurityDescriptorV1::from_sddl(&sddl).unwrap();
    let creation = CreationSecurity::new(&policy).unwrap();
    let attributes = creation.attributes();
    let desktop_policy =
        NativeSecurityDescriptorV1::from_sddl(&sddl.replace("0xf016f", "0xf01ff")).unwrap();
    let desktop_creation = CreationSecurity::new(&desktop_policy).unwrap();
    let desktop_attributes = desktop_creation.attributes();
    let mut nonce = [0u8; 16];
    assert_eq!(
        unsafe {
            windows_sys::Win32::Security::Cryptography::BCryptGenRandom(
                ptr::null_mut(),
                nonce.as_mut_ptr(),
                nonce.len() as u32,
                windows_sys::Win32::Security::Cryptography::BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        },
        0
    );
    let station_name = format!("memcordon-creation-{}", hex::encode(nonce))
        .encode_utf16()
        .chain([0])
        .collect::<Vec<_>>();
    let desktop_name = "probe".encode_utf16().chain([0]).collect::<Vec<_>>();
    let mut objects = Objects {
        original: unsafe { GetProcessWindowStation() },
        station: ptr::null_mut(),
        desktop: ptr::null_mut(),
    };
    assert!(!objects.original.is_null());
    let carrier = SecurityCreationCarrier::attach(
        source.as_raw_handle().cast(),
        snapshot(source.as_raw_handle().cast()).unwrap(),
    )
    .unwrap();
    objects.station = unsafe {
        CreateWindowStationW(
            station_name.as_ptr(),
            STATION_CREATE_ONLY,
            STATION_ACCESS,
            &attributes,
        )
    };
    let station_status = unsafe { GetLastError() };
    assert!(
        !objects.station.is_null(),
        "CreateWindowStationW status={station_status}"
    );
    assert_ne!(unsafe { SetProcessWindowStation(objects.station) }, 0);
    objects.desktop = unsafe {
        CreateDesktopW(
            desktop_name.as_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            0x000f01ff,
            &desktop_attributes,
        )
    };
    let desktop_status = unsafe { GetLastError() };
    assert!(
        !objects.desktop.is_null(),
        "CreateDesktopW status={desktop_status}"
    );
    carrier.finish().unwrap();
    // Acquire BOTH observed records before comparing either, so a station
    // mismatch cannot suppress desktop policy evidence.
    let station = observed_descriptor(objects.station);
    let desktop = observed_descriptor(objects.desktop);
    let expected_station = expected_descriptor(&policy);
    let expected_desktop = expected_descriptor(&desktop_policy);
    // Exercise the real holder's distinct owner/group/DACL gate adapter too.
    let gate_policy = NativeSecurityDescriptorV1::from_sddl(&format!(
        "O:{}G:{}D:P(A;;0x1f0003;;;OW)(A;;0x1f0003;;;SY)(A;;0x100000;;;RC)",
        before.envelope.user_sid, before.envelope.primary_group_sid
    ))
    .unwrap();
    let gate_attributes = gate_policy.security_attributes().unwrap();
    let gate_name = format!("Local\\memcordon-policy-{}", hex::encode(nonce))
        .encode_utf16()
        .chain([0])
        .collect::<Vec<_>>();
    unsafe {
        SetLastError(0);
    }
    let raw_gate = unsafe { CreateEventW(&gate_attributes, 1, 0, gate_name.as_ptr()) };
    let gate_status = unsafe { GetLastError() };
    let gate = own(raw_gate).unwrap();
    assert_ne!(gate_status, ERROR_ALREADY_EXISTS);
    let gate_expected = selected_policy_native::expected(&gate_policy, 7).unwrap();
    let gate_actual =
        unsafe { selected_policy_native::read_gate(gate.as_raw_handle().cast()) }.unwrap();
    let gate_verified = user_policy_snapshot::verify_and_fingerprint(
        user_policy_snapshot::Domain::Gate,
        &gate_expected,
        &gate_actual,
    )
    .unwrap();
    user_policy_snapshot::validate_verified(
        user_policy_snapshot::Domain::Gate,
        &gate_expected,
        &gate_verified,
    )
    .unwrap();
    let describe = |record: &Result<user_policy_snapshot::Snapshot, String>| match record {
        Ok(record) => user_policy_snapshot::describe(record),
        Err(error) => format!("capture failed: {error}"),
    };
    let verify = |domain,
                  expected: &Result<user_policy_snapshot::Snapshot, String>,
                  actual: &Result<user_policy_snapshot::Snapshot, String>| {
        match (expected, actual) {
            (Ok(expected), Ok(actual)) => {
                let verified =
                    user_policy_snapshot::verify_and_fingerprint(domain, expected, actual)?;
                user_policy_snapshot::validate_verified(domain, expected, &verified)?;
                Ok(verified)
            }
            (expected, actual) => Err(format!(
                "policy capture failed expected={} actual={}",
                describe(expected),
                describe(actual)
            )),
        }
    };
    let station_result = verify(
        user_policy_snapshot::Domain::Station,
        &expected_station,
        &station,
    );
    let desktop_result = verify(
        user_policy_snapshot::Domain::Desktop,
        &expected_desktop,
        &desktop,
    );
    let primary = snapshot(source.as_raw_handle().cast());
    let thread = absent_thread();
    assert!(
        station_result.is_ok()
            && desktop_result.is_ok()
            && primary.as_ref().is_ok_and(|actual| actual == &before)
            && thread.is_ok(),
        "station={station_result:?}; desktop={desktop_result:?}; primary expected={before:?} actual={primary:?}; thread={thread:?}\nexpected station={}\nobserved station={}\nexpected desktop={}\nobserved desktop={}",
        describe(&expected_station),
        describe(&station),
        describe(&expected_desktop),
        describe(&desktop)
    );
}
