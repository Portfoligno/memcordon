use std::ffi::c_void;
use std::os::windows::fs::MetadataExt;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

use windows_sys::Win32::Foundation::{
    CloseHandle, DuplicateHandle, GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, SetLastError,
    WAIT_OBJECT_0,
};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_FILE_NOT_FOUND,
    ERROR_NO_TOKEN, ERROR_SERVICE_SPECIFIC_ERROR,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, DuplicateTokenEx, EqualSid, GROUP_SECURITY_INFORMATION,
    GetSecurityDescriptorControl, GetSecurityDescriptorGroup, GetSecurityDescriptorOwner,
    IsValidSecurityDescriptor, IsValidSid, OWNER_SECURITY_INFORMATION, RevertToSelf,
    SE_SELF_RELATIVE, SecurityImpersonation, TOKEN_ALL_ACCESS, TOKEN_QUERY, TOKEN_QUERY_SOURCE,
    TokenImpersonation,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_READONLY, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::JobObjects::CreateJobObjectW;
use windows_sys::Win32::System::Services::SERVICE_STOPPED;
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateEventW, CreateMutexW, CreateThread, GetCurrentProcess,
    GetCurrentProcessId, GetCurrentThread, GetProcessIdOfThread, OpenThread, OpenThreadToken,
    ResumeThread, SetEvent, SetThreadToken, SuspendThread, THREAD_QUERY_INFORMATION,
    THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, THREAD_SET_THREAD_TOKEN,
    THREAD_SUSPEND_RESUME, WaitForSingleObject,
};

use crate::windows::loader_access::{
    KNOWN_DLL_DIRECTORY_ACCESS, KNOWN_DLL_SECTION_ACCESS, KnownDllDispositionV1,
    KnownDllSectionEvidenceV1, LOADER_ANCESTOR_IDENTITY_ACCESS, LOADER_FILE_ACCESS,
    LoaderImportEdgeEvidenceV2, LoaderModuleAccessEvidenceV1, LoaderObjectAccessEvidenceV1,
    LoaderPathAccessEvidenceV1, LoaderPathRoleV1, LoaderRootEvidenceV2, LoaderRootPhaseV2,
    NativeLoaderAccessEvidenceV2, api_set_namespace_entry_for_test,
    api_set_namespace_summary_for_test, api_set_parent_selection_for_test,
    api_set_schema_resolution_for_test, api_set_schema_summary_for_test,
    api_set_selection_cache_key_for_test, capture_source_ancestor_identity_for_test,
    current_api_set_namespace_entry_for_test, current_api_set_namespace_summary_for_test,
    current_api_set_resolution_for_test, current_api_set_schema_for_test,
    forwarder_path_result_for_test, is_api_set_name_for_test, known_dll_disposition_for_test,
    loader_export_matches_for_test, loader_graph_shortest_depths_for_test,
    native_known_dll_namespace_for_test, physical_loader_admission_plan_for_test,
    validate_loader_access_for_test, validate_same_final_identity_for_test,
};
use crate::windows::package::{CONTROL_PRIVILEGES, LAUNCHER_PRIVILEGES, SESSION_BROKER_PRIVILEGES};
use crate::windows::pipe::{PipeListener, PipePreparationError};
use crate::windows::process::{
    attest_current_user_binding_duplicates_for_test, target_association_preflight_grants_for_test,
    target_association_preflight_progress_for_test, validate_guardian_desktop_binding,
    validate_target_desktop_binding, validate_target_desktop_input_state,
};
use crate::windows::security::{
    CERTIFICATION_ADMIN_DIRECTORY_ACCESS, NamedPipeSecurityError, NamedPipeSecurityMismatch,
    SecurityDescriptor, SecurityObjectKind, TARGET_PRIVATE_DESKTOP_ACCESS,
    TARGET_PRIVATE_WINDOW_STATION_ACCESS, TargetRestrictionSemantics, TargetUserObjectPolicyRoleV1,
    TokenDaclStage, admission_state_sddl, attest_token_peer_query, certification_marker_state_sddl,
    compare_file_security_sddl_for_test, compare_user_object_security_sddl_for_test,
    converge_token_peer_query, guardian_slot_name, launcher_job_sddl, launcher_process_sddl,
    launcher_state_sddl, launcher_thread_sddl, nested_canary_job_sddl, nested_canary_process_sddl,
    nested_canary_thread_sddl, normalized_access_mask, normalized_descriptor_sddl,
    package_state_sddl, pre_destructive_authority_hardening_certification_marker_state_sddl,
    pre_write_restricted_certification_marker_state_sddl, public_pipe_sddl, replay_state_sddl,
    sddl_utf16_allocation_window, service_process_sddl, service_sid, session_broker_pipe_sddl,
    session_broker_process_sddl, session_broker_service_sddl, session_broker_token_sddl,
    session_creation_carrier_token_sddl, session_holder_job_sddl, session_holder_process_sddl,
    session_holder_thread_sddl, session_holder_token_sddl, state_bootstrap_sddl, state_parent_sddl,
    state_sddl, target_desktop_sddl, target_user_object_policy, target_window_station_sddl,
    token_dacl_diagnostic_from_exit, token_dacl_nonpeer_fingerprint,
    user_object_policy_fingerprint_for_test, user_object_resultant_fingerprint_for_test,
    utf16_nul_terminated, utf16_nul_terminated_with_reported_length,
};

const SE_SACL_PRESENT_CONTROL: u16 = 0x0010;
const SE_SACL_AUTO_INHERIT_REQ_CONTROL: u16 = 0x0200;
const SE_SACL_AUTO_INHERITED_CONTROL: u16 = 0x0800;
const SE_SACL_PROTECTED_CONTROL: u16 = 0x2000;

#[derive(Clone, Copy)]
struct SyntheticApiSetValue<'a> {
    flags: u32,
    parent_alias: Option<&'a str>,
    host: &'a str,
}

#[derive(Clone)]
struct SyntheticApiSetContract<'a> {
    flags: u32,
    name: &'a str,
    hash_span: SyntheticApiSetHashSpan<'a>,
    values: Vec<SyntheticApiSetValue<'a>>,
}

#[derive(Clone, Copy)]
enum SyntheticApiSetHashSpan<'a> {
    WholeName,
    ProperPrefix,
    ExactPrefix(&'a str),
}

fn write_api_set_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn read_api_set_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn push_api_set_utf16(bytes: &mut Vec<u8>, value: &str) -> (u32, u32) {
    let offset = u32::try_from(bytes.len()).unwrap();
    for unit in value.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    (offset, u32::try_from(bytes.len()).unwrap() - offset)
}

fn synthetic_api_set_hash(value: &str, hash_factor: u32) -> u32 {
    value.encode_utf16().fold(0_u32, |hash, unit| {
        let unit = if (u16::from(b'A')..=u16::from(b'Z')).contains(&unit) {
            unit + u16::from(b'a' - b'A')
        } else {
            unit
        };
        hash.wrapping_mul(hash_factor).wrapping_add(u32::from(unit))
    })
}

fn synthetic_api_set_schema_v6(
    namespace_flags: u32,
    contracts: &[SyntheticApiSetContract<'_>],
) -> Vec<u8> {
    synthetic_api_set_schema_v6_with_factor(namespace_flags, 31, contracts)
}

fn synthetic_api_set_schema_v6_with_factor(
    namespace_flags: u32,
    hash_factor: u32,
    contracts: &[SyntheticApiSetContract<'_>],
) -> Vec<u8> {
    let entry_offset = 28usize;
    let hash_offset = entry_offset + contracts.len() * 24;
    let mut bytes = vec![0; hash_offset + contracts.len() * 8];
    write_api_set_u32(&mut bytes, 0, 6);
    write_api_set_u32(&mut bytes, 8, namespace_flags);
    write_api_set_u32(&mut bytes, 12, u32::try_from(contracts.len()).unwrap());
    write_api_set_u32(&mut bytes, 16, u32::try_from(entry_offset).unwrap());
    write_api_set_u32(&mut bytes, 20, u32::try_from(hash_offset).unwrap());
    write_api_set_u32(&mut bytes, 24, hash_factor);

    let mut hashes = Vec::with_capacity(contracts.len());

    for (contract_index, contract) in contracts.iter().enumerate() {
        let entry = entry_offset + contract_index * 24;
        let (name_offset, name_length) = push_api_set_utf16(&mut bytes, contract.name);
        let hash_key = match contract.hash_span {
            SyntheticApiSetHashSpan::WholeName => contract.name,
            SyntheticApiSetHashSpan::ProperPrefix => {
                contract
                    .name
                    .rsplit_once('-')
                    .expect("synthetic API-set name has a terminal revision")
                    .0
            }
            SyntheticApiSetHashSpan::ExactPrefix(prefix) => {
                assert!(contract.name.starts_with(prefix));
                prefix
            }
        };
        let hashed_length = u32::try_from(hash_key.encode_utf16().count() * 2).unwrap();
        let value_offset = bytes.len();
        bytes.resize(value_offset + contract.values.len() * 20, 0);
        for (value_index, value) in contract.values.iter().enumerate() {
            let record = value_offset + value_index * 20;
            write_api_set_u32(&mut bytes, record, value.flags);
            let (alias_offset, alias_length) =
                push_api_set_utf16(&mut bytes, value.parent_alias.unwrap_or(""));
            write_api_set_u32(&mut bytes, record + 4, alias_offset);
            write_api_set_u32(&mut bytes, record + 8, alias_length);
            let (host_offset, host_length) = push_api_set_utf16(&mut bytes, value.host);
            write_api_set_u32(&mut bytes, record + 12, host_offset);
            write_api_set_u32(&mut bytes, record + 16, host_length);
        }
        write_api_set_u32(&mut bytes, entry, contract.flags);
        write_api_set_u32(&mut bytes, entry + 4, name_offset);
        write_api_set_u32(&mut bytes, entry + 8, name_length);
        write_api_set_u32(&mut bytes, entry + 12, hashed_length);
        write_api_set_u32(&mut bytes, entry + 16, u32::try_from(value_offset).unwrap());
        write_api_set_u32(
            &mut bytes,
            entry + 20,
            u32::try_from(contract.values.len()).unwrap(),
        );
        let hash = synthetic_api_set_hash(hash_key, hash_factor);
        hashes.push((hash, contract_index));
    }
    hashes.sort_unstable_by_key(|(hash, _)| *hash);
    for (hash_index, (value, contract_index)) in hashes.into_iter().enumerate() {
        let hash = hash_offset + hash_index * 8;
        write_api_set_u32(&mut bytes, hash, value);
        write_api_set_u32(&mut bytes, hash + 4, contract_index as u32);
    }
    let size = u32::try_from(bytes.len()).unwrap();
    write_api_set_u32(&mut bytes, 4, size);
    bytes
}

fn synthetic_api_set_fixture() -> Vec<u8> {
    synthetic_api_set_schema_v6(
        0x0000_0003,
        &[
            SyntheticApiSetContract {
                flags: 1,
                name: "api-ms-win-core-normal-l1-1-2",
                hash_span: SyntheticApiSetHashSpan::ProperPrefix,
                values: vec![SyntheticApiSetValue {
                    flags: 7,
                    parent_alias: None,
                    host: "kernelbase.dll",
                }],
            },
            SyntheticApiSetContract {
                flags: 0,
                name: "api-ms-win-core-inactive-l1-1-2",
                hash_span: SyntheticApiSetHashSpan::ProperPrefix,
                values: Vec::new(),
            },
            SyntheticApiSetContract {
                flags: 0,
                name: "api-ms-win-core-empty-l1-1-0",
                hash_span: SyntheticApiSetHashSpan::ProperPrefix,
                values: vec![SyntheticApiSetValue {
                    flags: 0,
                    parent_alias: None,
                    host: "",
                }],
            },
            SyntheticApiSetContract {
                flags: 0,
                name: "api-ms-win-core-override-l1-1-0",
                hash_span: SyntheticApiSetHashSpan::ProperPrefix,
                values: vec![
                    SyntheticApiSetValue {
                        flags: 0,
                        parent_alias: None,
                        host: "kernelbase.dll",
                    },
                    SyntheticApiSetValue {
                        flags: 0,
                        parent_alias: Some("Blocked.Dll"),
                        host: "",
                    },
                    SyntheticApiSetValue {
                        flags: 0,
                        parent_alias: Some("Elsewhere.DLL"),
                        host: "",
                    },
                ],
            },
            SyntheticApiSetContract {
                flags: 0,
                name: "api-ms-win-core-empty-default-l1-1-0",
                hash_span: SyntheticApiSetHashSpan::ProperPrefix,
                values: vec![
                    SyntheticApiSetValue {
                        flags: 0,
                        parent_alias: None,
                        host: "",
                    },
                    SyntheticApiSetValue {
                        flags: 0,
                        parent_alias: Some("Client.Dll"),
                        host: "specialhost",
                    },
                ],
            },
            SyntheticApiSetContract {
                flags: 0,
                name: "api-ms-win-core-multiple-l1-1-0",
                hash_span: SyntheticApiSetHashSpan::ProperPrefix,
                values: vec![
                    SyntheticApiSetValue {
                        flags: 0,
                        parent_alias: None,
                        host: "kernelbase.dll",
                    },
                    SyntheticApiSetValue {
                        flags: 0,
                        parent_alias: Some("First.Dll"),
                        host: "firsthost.dll",
                    },
                    SyntheticApiSetValue {
                        flags: 0,
                        parent_alias: Some("Second.Dll"),
                        host: "secondhost.dll",
                    },
                ],
            },
        ],
    )
}

#[test]
fn native_loader_ancestor_identity_open_requests_no_access() {
    assert_eq!(LOADER_ANCESTOR_IDENTITY_ACCESS, 0);
    validate_loader_access_for_test(LOADER_ANCESTOR_IDENTITY_ACCESS, 0).unwrap();
    validate_loader_access_for_test(LOADER_ANCESTOR_IDENTITY_ACCESS, u32::MAX).unwrap();
}

#[test]
fn native_loader_leaf_and_object_masks_require_every_exact_bit() {
    for requested in [
        LOADER_FILE_ACCESS,
        KNOWN_DLL_DIRECTORY_ACCESS,
        KNOWN_DLL_SECTION_ACCESS,
    ] {
        validate_loader_access_for_test(requested, requested).unwrap();
        for bit in 0..u32::BITS {
            let mask = 1_u32 << bit;
            if requested & mask != 0 {
                let error = validate_loader_access_for_test(requested, requested & !mask)
                    .expect_err("removing any loader access bit must fail closed");
                assert!(error.contains(&format!("requested={requested:#010x}")));
                assert!(error.contains("granted="));
            }
        }
    }
}

fn loader_path_evidence(
    role: LoaderPathRoleV1,
    requested_access: u32,
    granted_access: u32,
) -> LoaderPathAccessEvidenceV1 {
    LoaderPathAccessEvidenceV1 {
        role,
        path_sha256: "11".repeat(32),
        basename: match role {
            LoaderPathRoleV1::MemcordonBootstrapImage => {
                "memcordon-target-desktop-bootstrap.exe".to_owned()
            }
            LoaderPathRoleV1::SystemModule => "KERNEL32.DLL".to_owned(),
            _ => "resource".to_owned(),
        },
        requested_access,
        granted_access,
        volume_serial: 1,
        file_id_sha256: "22".repeat(32),
        reparse_point: false,
    }
}

fn native_loader_access_evidence(native_machine: u16) -> NativeLoaderAccessEvidenceV2 {
    let bootstrap_file = loader_path_evidence(
        LoaderPathRoleV1::MemcordonBootstrapImage,
        LOADER_FILE_ACCESS,
        LOADER_FILE_ACCESS,
    );
    NativeLoaderAccessEvidenceV2 {
        schema_version: 2,
        native_machine,
        bootstrap_sha256: "33".repeat(32),
        import_contract_sha256: "44".repeat(32),
        ordered_root_sha256: String::new(),
        loader_graph_sha256: String::new(),
        impersonation_attested: true,
        thread_token_absent_after_revert: false,
        install_ancestors: vec![loader_path_evidence(
            LoaderPathRoleV1::MemcordonInstallRoot,
            LOADER_ANCESTOR_IDENTITY_ACCESS,
            0,
        )],
        bootstrap_file,
        system_ancestors: vec![loader_path_evidence(
            LoaderPathRoleV1::SystemDirectory,
            LOADER_ANCESTOR_IDENTITY_ACCESS,
            0,
        )],
        system_modules: vec![LoaderModuleAccessEvidenceV1 {
            import_contract: "KERNEL32.DLL".to_owned(),
            concrete_host: "KERNEL32.DLL".to_owned(),
            api_set_redirected: false,
            file: loader_path_evidence(
                LoaderPathRoleV1::SystemModule,
                LOADER_FILE_ACCESS,
                LOADER_FILE_ACCESS,
            ),
            pe_machine: native_machine,
            image_sha256: "66".repeat(32),
            loader_contract_sha256: "77".repeat(32),
        }],
        loader_roots: vec![
            LoaderRootEvidenceV2 {
                phase: LoaderRootPhaseV2::StaticKernel,
                descriptor_ordinal: Some(0),
                import_contract: "KERNEL32.DLL".to_owned(),
                concrete_host: "KERNEL32.DLL".to_owned(),
                export_contract_sha256: "88".repeat(32),
            },
            LoaderRootEvidenceV2 {
                phase: LoaderRootPhaseV2::ExplicitSecurity,
                descriptor_ordinal: None,
                import_contract: "ADVAPI32.DLL".to_owned(),
                concrete_host: "KERNEL32.DLL".to_owned(),
                export_contract_sha256: "88".repeat(32),
            },
            LoaderRootEvidenceV2 {
                phase: LoaderRootPhaseV2::ExplicitUser,
                descriptor_ordinal: None,
                import_contract: "USER32.DLL".to_owned(),
                concrete_host: "KERNEL32.DLL".to_owned(),
                export_contract_sha256: "88".repeat(32),
            },
        ],
        loader_edges: vec![LoaderImportEdgeEvidenceV2 {
            phase: LoaderRootPhaseV2::StaticKernel,
            depth: 0,
            parent_host: "KERNEL32.DLL".to_owned(),
            descriptor_ordinal: Some(0),
            requested_symbol: None,
            import_contract: "KERNEL32.DLL".to_owned(),
            concrete_host: "KERNEL32.DLL".to_owned(),
            resolved_target_symbol: None,
            api_set_redirected: false,
            forwarder: false,
        }],
        known_dll_directory: LoaderObjectAccessEvidenceV1 {
            object_name_sha256: "55".repeat(32),
            requested_access: KNOWN_DLL_DIRECTORY_ACCESS,
            granted_access: KNOWN_DLL_DIRECTORY_ACCESS,
        },
        known_dll_sections: vec![KnownDllSectionEvidenceV1 {
            concrete_host: "KERNEL32.DLL".to_owned(),
            disposition: KnownDllDispositionV1::Section {
                requested_access: KNOWN_DLL_SECTION_ACCESS,
                granted_access: KNOWN_DLL_SECTION_ACCESS,
            },
            read_map_attested: true,
            execute_map_attested: true,
            loader_contract_sha256: "77".repeat(32),
        }],
        exact_target_import_tier_canary_attested: true,
        evidence_sha256: String::new(),
    }
    .mark_reverted_and_seal()
    .unwrap()
}

#[test]
fn native_loader_evidence_separates_ancestor_identity_from_final_access() {
    for machine in [
        memcordon_core::WINDOWS_PE_MACHINE_AMD64,
        memcordon_core::WINDOWS_PE_MACHINE_ARM64,
    ] {
        let evidence = native_loader_access_evidence(machine);
        evidence.validate().unwrap();

        let mut nonzero_ancestor_access = evidence.clone();
        nonzero_ancestor_access.install_ancestors[0].requested_access = 1;
        assert!(nonzero_ancestor_access.validate().is_err());

        let identity_mutations: [fn(&mut LoaderPathAccessEvidenceV1); 5] = [
            |path: &mut LoaderPathAccessEvidenceV1| path.volume_serial = 0,
            |path: &mut LoaderPathAccessEvidenceV1| path.file_id_sha256.clear(),
            |path: &mut LoaderPathAccessEvidenceV1| path.path_sha256.clear(),
            |path: &mut LoaderPathAccessEvidenceV1| path.reparse_point = true,
            |path: &mut LoaderPathAccessEvidenceV1| path.basename = "x".repeat(129),
        ];
        for mutate in identity_mutations {
            let mut invalid_identity = evidence.clone();
            mutate(&mut invalid_identity.install_ancestors[0]);
            assert!(invalid_identity.validate().is_err());
        }

        for install in [true, false] {
            let mut empty = evidence.clone();
            let mut oversized = evidence.clone();
            if install {
                empty.install_ancestors.clear();
                oversized.install_ancestors = vec![evidence.install_ancestors[0].clone(); 17];
            } else {
                empty.system_ancestors.clear();
                oversized.system_ancestors = vec![evidence.system_ancestors[0].clone(); 17];
            }
            assert!(empty.validate().is_err());
            assert!(oversized.validate().is_err());
        }

        for bit in 0..u32::BITS {
            let mask = 1_u32 << bit;
            if LOADER_FILE_ACCESS & mask == 0 {
                continue;
            }
            let mut bootstrap_access = evidence.clone();
            bootstrap_access.bootstrap_file.granted_access &= !mask;
            assert!(bootstrap_access.validate().is_err());

            let mut module_access = evidence.clone();
            module_access.system_modules[0].file.granted_access &= !mask;
            assert!(module_access.validate().is_err());
        }

        let mut bad_digest = evidence;
        bad_digest.evidence_sha256 = "66".repeat(32);
        assert!(bad_digest.validate().is_err());
    }
}

#[test]
fn holder_source_identity_handles_support_root_and_nested_readback() {
    let current = std::env::current_dir().unwrap();
    let root = current.ancestors().last().unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let nested = temporary.path().join("nested");
    std::fs::create_dir(&nested).unwrap();

    for path in [root, nested.as_path()] {
        let evidence = capture_source_ancestor_identity_for_test(path).unwrap();
        assert_eq!(evidence.requested_access, LOADER_ANCESTOR_IDENTITY_ACCESS);
        assert_ne!(evidence.volume_serial, 0);
        assert_eq!(evidence.file_id_sha256.len(), 64);
        assert_eq!(evidence.path_sha256.len(), 64);
        assert!(!evidence.reparse_point);
    }
}

#[test]
fn target_final_identity_must_match_holder_pinned_leaf() {
    // This is the exact-target System32 identity relation used only after the
    // canonical KnownDll section returns STATUS_OBJECT_NAME_NOT_FOUND.
    let source = loader_path_evidence(
        LoaderPathRoleV1::SystemModule,
        LOADER_FILE_ACCESS,
        LOADER_FILE_ACCESS,
    );
    let target = source.clone();
    let source_path = std::path::Path::new(r"\\?\C:\Windows\System32\KERNEL32.DLL");
    let case_variant = std::path::Path::new(r"\\?\c:\windows\system32\kernel32.dll");
    validate_same_final_identity_for_test(source_path, &source, 7, case_variant, &target, 7)
        .unwrap();

    let different_path = std::path::Path::new(r"\\?\C:\Windows\Temp\KERNEL32.DLL");
    assert!(
        validate_same_final_identity_for_test(source_path, &source, 7, different_path, &target, 7,)
            .is_err()
    );
    let mut different_volume = target.clone();
    different_volume.volume_serial += 1;
    assert!(
        validate_same_final_identity_for_test(
            source_path,
            &source,
            7,
            case_variant,
            &different_volume,
            7,
        )
        .is_err()
    );
    assert!(
        validate_same_final_identity_for_test(source_path, &source, 7, case_variant, &target, 8,)
            .is_err()
    );
    let mut reparse = target;
    reparse.reparse_point = true;
    assert!(
        validate_same_final_identity_for_test(source_path, &source, 7, case_variant, &reparse, 7,)
            .is_err()
    );
}

#[test]
fn native_loader_inventory_rejects_missing_duplicate_and_extra_hosts() {
    let machine = memcordon_core::WINDOWS_PE_MACHINE_AMD64;
    let evidence = native_loader_access_evidence(machine);

    let mut duplicate_import = evidence.clone();
    duplicate_import
        .system_modules
        .push(duplicate_import.system_modules[0].clone());
    assert!(duplicate_import.validate().is_err());

    let mut missing_section = evidence.clone();
    missing_section.known_dll_sections.clear();
    assert!(missing_section.validate().is_err());

    let mut extra_section = evidence.clone();
    extra_section
        .known_dll_sections
        .push(KnownDllSectionEvidenceV1 {
            concrete_host: "NTDLL.DLL".to_owned(),
            disposition: KnownDllDispositionV1::FileBacked {
                not_found_status: 0xC000_0034_u32 as i32,
            },
            read_map_attested: false,
            execute_map_attested: false,
            loader_contract_sha256: "99".repeat(32),
        });
    assert!(extra_section.validate().is_err());

    let mut wrong_status = evidence.clone();
    wrong_status.known_dll_sections[0].disposition = KnownDllDispositionV1::FileBacked {
        not_found_status: 0xC000_0022_u32 as i32,
    };
    assert!(wrong_status.validate().is_err());

    let mut wrong_basename = evidence;
    wrong_basename.system_modules[0].file.basename = "NTDLL.DLL".to_owned();
    assert!(wrong_basename.validate().is_err());
}

#[test]
fn native_known_dll_policy_distinguishes_absence_from_denial() {
    assert_eq!(
        known_dll_disposition_for_test(0xC000_0034_u32 as i32).unwrap(),
        KnownDllDispositionV1::FileBacked {
            not_found_status: 0xC000_0034_u32 as i32,
        }
    );
    assert!(known_dll_disposition_for_test(0xC000_0022_u32 as i32).is_err());
    assert!(known_dll_disposition_for_test(0xC000_003A_u32 as i32).is_err());
    assert!(matches!(
        known_dll_disposition_for_test(0).unwrap(),
        KnownDllDispositionV1::Section {
            requested_access: KNOWN_DLL_SECTION_ACCESS,
            granted_access: KNOWN_DLL_SECTION_ACCESS,
        }
    ));
}

#[test]
fn native_loader_evidence_accepts_section_and_exact_file_fallback_routes() {
    let machine = memcordon_core::WINDOWS_PE_MACHINE_AMD64;
    let section = native_loader_access_evidence(machine);
    section.validate().unwrap();

    let mut fallback = section.clone();
    fallback.known_dll_sections[0].disposition = KnownDllDispositionV1::FileBacked {
        not_found_status: 0xC000_0034_u32 as i32,
    };
    fallback.known_dll_sections[0].read_map_attested = false;
    fallback.known_dll_sections[0].execute_map_attested = false;
    fallback = fallback.mark_reverted_and_seal().unwrap();
    fallback.validate().unwrap();

    let mut denied = fallback;
    denied.known_dll_sections[0].disposition = KnownDllDispositionV1::FileBacked {
        not_found_status: 0xC000_0022_u32 as i32,
    };
    assert!(denied.mark_reverted_and_seal().is_err());
}

#[test]
fn native_loader_evidence_requires_separate_map_stages_and_exact_target_tier_canary() {
    let evidence = native_loader_access_evidence(memcordon_core::WINDOWS_PE_MACHINE_AMD64);

    let mut no_read_map = evidence.clone();
    no_read_map.known_dll_sections[0].read_map_attested = false;
    assert!(no_read_map.mark_reverted_and_seal().is_err());

    let mut no_execute_map = evidence.clone();
    no_execute_map.known_dll_sections[0].execute_map_attested = false;
    assert!(no_execute_map.mark_reverted_and_seal().is_err());

    let mut no_tier_canary = evidence;
    no_tier_canary.exact_target_import_tier_canary_attested = false;
    assert!(no_tier_canary.mark_reverted_and_seal().is_err());
}

#[test]
fn native_loader_evidence_relates_api_sets_to_physical_hosts() {
    let machine = memcordon_core::WINDOWS_PE_MACHINE_ARM64;
    let mut evidence = native_loader_access_evidence(machine);
    let direct = evidence.system_modules[0].clone();
    let mut api_set = direct.clone();
    api_set.import_contract = "API-MS-WIN-CORE-SYNCH-L1-2-0.DLL".to_owned();
    api_set.api_set_redirected = true;
    evidence.system_modules = vec![api_set, direct];
    evidence = evidence.mark_reverted_and_seal().unwrap();
    evidence.validate().unwrap();
    assert_eq!(evidence.known_dll_sections.len(), 1);

    let mut unmarked_api_set = evidence.clone();
    unmarked_api_set.system_modules[0].api_set_redirected = false;
    assert!(unmarked_api_set.mark_reverted_and_seal().is_err());

    let mut redirected_direct = evidence.clone();
    redirected_direct.system_modules[1].api_set_redirected = true;
    assert!(redirected_direct.mark_reverted_and_seal().is_err());

    let mut mismatched_direct = evidence;
    mismatched_direct.system_modules[1].concrete_host = "NTDLL.DLL".to_owned();
    mismatched_direct.system_modules[1].file.basename = "NTDLL.DLL".to_owned();
    assert!(mismatched_direct.mark_reverted_and_seal().is_err());
}

#[test]
fn api_set_v6_empty_hosts_are_preserved_until_exact_reachable_selection() {
    let bytes = synthetic_api_set_fixture();
    let (sha256, contract_count, inactive_contract_count, unhosted_value_count) =
        api_set_schema_summary_for_test(&bytes).unwrap();
    assert_eq!(sha256.len(), 64);
    assert!(sha256.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(contract_count, 6);
    assert_eq!(inactive_contract_count, 1);
    assert_eq!(unhosted_value_count, 4);

    assert_eq!(
        api_set_schema_resolution_for_test(
            &bytes,
            "Api-Ms-Win-Core-Normal-L1-1-0.DlL",
            "Unrelated.DlL",
        )
        .unwrap(),
        "KERNELBASE.DLL",
    );
    assert_eq!(
        api_set_schema_resolution_for_test(
            &bytes,
            "aPi-Ms-WiN-CoRe-NoRmAl-L1-1-9",
            "Unrelated.DlL",
        )
        .unwrap(),
        "KERNELBASE.DLL",
    );
    assert_eq!(
        api_set_schema_resolution_for_test(
            &bytes,
            "api-ms-win-core-override-l1-1-0.dll",
            "unrelated.dll",
        )
        .unwrap(),
        "KERNELBASE.DLL",
    );
    assert_eq!(
        api_set_schema_resolution_for_test(
            &bytes,
            "api-ms-win-core-empty-default-l1-1-0.dll",
            "CLIENT.DLL",
        )
        .unwrap(),
        "SPECIALHOST.DLL",
    );
    assert_eq!(
        api_set_schema_resolution_for_test(
            &bytes,
            "api-ms-win-core-multiple-l1-1-0",
            "sEcOnD.dLl",
        )
        .unwrap(),
        "SECONDHOST.DLL",
    );

    let inactive =
        api_set_schema_resolution_for_test(&bytes, "api-ms-win-core-inactive-l1-1-0", "parent.dll")
            .unwrap_err();
    for fragment in [
        "API-MS-WIN-CORE-INACTIVE-L1-1-0",
        "hash_key=API-MS-WIN-CORE-INACTIVE-L1-1",
        "namespace_name=API-MS-WIN-CORE-INACTIVE-L1-1-2",
        "PARENT.DLL",
        &sha256,
        "selection=inactive",
        "value_index=none",
    ] {
        assert!(
            inactive.contains(fragment),
            "{inactive:?} lacks {fragment:?}"
        );
    }

    let empty_default =
        api_set_schema_resolution_for_test(&bytes, "api-ms-win-core-empty-l1-1-0", "parent.dll")
            .unwrap_err();
    for fragment in [
        "API-MS-WIN-CORE-EMPTY-L1-1-0",
        "PARENT",
        &sha256,
        "selection=default",
        "value_index=0",
    ] {
        assert!(
            empty_default.contains(fragment),
            "{empty_default:?} lacks {fragment:?}"
        );
    }

    let empty_exact = api_set_schema_resolution_for_test(
        &bytes,
        "api-ms-win-core-override-l1-1-0",
        "BLOCKED.DLL",
    )
    .unwrap_err();
    assert!(empty_exact.contains("selection=parent-alias"));
    assert!(empty_exact.contains("value_index=1"));
    assert!(!empty_exact.contains("KERNELBASE.DLL"));

    let empty_unselected = api_set_schema_resolution_for_test(
        &bytes,
        "api-ms-win-core-override-l1-1-0",
        "another.dll",
    )
    .unwrap();
    assert_eq!(empty_unselected, "KERNELBASE.DLL");

    let empty_default_without_matching_override = api_set_schema_resolution_for_test(
        &bytes,
        "api-ms-win-core-empty-default-l1-1-0",
        "another.dll",
    )
    .unwrap_err();
    assert!(empty_default_without_matching_override.contains("selection=default"));
    assert!(empty_default_without_matching_override.contains("value_index=0"));

    let absent =
        api_set_schema_resolution_for_test(&bytes, "api-ms-win-core-absent-l1-1-0", "parent.dll")
            .unwrap_err();
    assert!(absent.contains("selection=absent"));
    assert!(absent.contains("hash not found"));
    assert!(absent.contains("lookup_key=API-MS-WIN-CORE-ABSENT-L1-1"));
    assert!(absent.contains("value_index=none"));
}

#[test]
fn api_set_v6_lookup_keeps_prefixes_and_parent_extensions_exact() {
    let default = SyntheticApiSetValue {
        flags: 0,
        parent_alias: None,
        host: "default.dll",
    };
    let bytes = synthetic_api_set_schema_v6(
        0,
        &[
            SyntheticApiSetContract {
                flags: 0,
                name: "api-ms-win-core-prefix-l1-2-7",
                hash_span: SyntheticApiSetHashSpan::ProperPrefix,
                values: vec![
                    default,
                    SyntheticApiSetValue {
                        flags: 0,
                        parent_alias: Some("Client.DLL"),
                        host: "api-parent.dll",
                    },
                ],
            },
            SyntheticApiSetContract {
                flags: 0,
                name: "ext-ms-win-core-prefix-l1-2-4",
                hash_span: SyntheticApiSetHashSpan::ProperPrefix,
                values: vec![SyntheticApiSetValue {
                    flags: 0,
                    parent_alias: None,
                    host: "extension.dll",
                }],
            },
        ],
    );

    assert_eq!(
        api_set_schema_resolution_for_test(
            &bytes,
            "API-MS-WIN-CORE-PREFIX-L1-2-0.DLL",
            "client.dll",
        )
        .unwrap(),
        "API-PARENT.DLL",
    );
    assert_eq!(
        api_set_schema_resolution_for_test(&bytes, "API-MS-WIN-CORE-PREFIX-L1-2-0.DLL", "client",)
            .unwrap(),
        "DEFAULT.DLL",
    );
    assert_eq!(
        api_set_schema_resolution_for_test(
            &bytes,
            "EXT-MS-WIN-CORE-PREFIX-L1-2-0.DLL",
            "client.dll",
        )
        .unwrap(),
        "EXTENSION.DLL",
    );
    assert_eq!(
        api_set_selection_cache_key_for_test(
            &bytes,
            "API-MS-WIN-CORE-PREFIX-L1-2-0.DLL",
            "Client.DLL",
        )
        .unwrap(),
        api_set_selection_cache_key_for_test(
            &bytes,
            "api-ms-win-core-prefix-l1-2-99",
            "client.dll",
        )
        .unwrap(),
    );
    assert_ne!(
        api_set_selection_cache_key_for_test(
            &bytes,
            "API-MS-WIN-CORE-PREFIX-L1-2-0.DLL",
            "Client.DLL",
        )
        .unwrap(),
        api_set_selection_cache_key_for_test(
            &bytes,
            "API-MS-WIN-CORE-PREFIX-L1-2-0.DLL",
            "Client",
        )
        .unwrap(),
    );
    let wrong_level = api_set_schema_resolution_for_test(
        &bytes,
        "API-MS-WIN-CORE-PREFIX-L1-3-0.DLL",
        "client.dll",
    )
    .unwrap_err();
    assert!(wrong_level.contains("selection=absent"));
}

#[test]
fn api_set_v6_stores_schema_composition_rows_without_making_them_requests() {
    let default = |host| {
        vec![SyntheticApiSetValue {
            flags: 0,
            parent_alias: None,
            host,
        }]
    };
    let bytes = synthetic_api_set_schema_v6(
        0,
        &[
            SyntheticApiSetContract {
                flags: 0,
                name: "SchemaExt-Win3-Product-Extension-ClientCore",
                hash_span: SyntheticApiSetHashSpan::WholeName,
                values: default("composition-host.dll"),
            },
            SyntheticApiSetContract {
                flags: 0,
                name: "SchemaExt-Win3-Product-Extension-ClientCore-Opaque-Tail",
                hash_span: SyntheticApiSetHashSpan::ProperPrefix,
                values: Vec::new(),
            },
            SyntheticApiSetContract {
                flags: 0,
                name: "api-ms-win-core-demo-l1-1-0",
                hash_span: SyntheticApiSetHashSpan::ProperPrefix,
                values: default("family.dll"),
            },
        ],
    );

    assert_eq!(api_set_schema_summary_for_test(&bytes).unwrap().1, 3);
    assert_eq!(
        api_set_namespace_summary_for_test(&bytes).unwrap(),
        (1, 2, 1, 1, 1)
    );
    assert_eq!(
        api_set_schema_resolution_for_test(
            &bytes,
            "api-ms-win-core-demo-l1-1-99.dll",
            "parent.dll",
        )
        .unwrap(),
        "FAMILY.DLL"
    );
    let error = api_set_schema_resolution_for_test(
        &bytes,
        "SchemaExt-Win3-Product-Extension-ClientCore.dll",
        "parent.dll",
    )
    .unwrap_err();
    assert!(error.contains("requested API-set contract"));
    assert!(!is_api_set_name_for_test(
        "SchemaExt-Win3-Product-Extension-ClientCore.dll"
    ));
    assert!(!is_api_set_name_for_test("api-parent.dll"));
    assert!(!is_api_set_name_for_test("ext-host.dll"));
    assert!(!is_api_set_name_for_test("api-ms-win-core-demo.dll"));
    assert!(is_api_set_name_for_test("API-MS-WIN-CORE-DEMO-L1-1-99.DLL"));
    assert!(is_api_set_name_for_test("ext-ms-win-core-demo-l1-1-99.dll"));
    assert_eq!(
        api_set_selection_cache_key_for_test(
            &bytes,
            "api-ms-win-core-demo-l1-1-3.dll",
            "parent.dll",
        )
        .unwrap(),
        api_set_selection_cache_key_for_test(
            &bytes,
            "api-ms-win-core-demo-l1-1-99.dll",
            "parent.dll",
        )
        .unwrap()
    );
}

#[test]
fn api_set_v6_indexes_noncanonical_exact_prefixes_as_opaque_rows() {
    let bytes = synthetic_api_set_schema_v6(
        0,
        &[
            SyntheticApiSetContract {
                flags: 0,
                name: "api-ms-win-core-trailing-l1-1-0",
                hash_span: SyntheticApiSetHashSpan::ExactPrefix("api-ms-win-core-trailing-l1-"),
                values: Vec::new(),
            },
            SyntheticApiSetContract {
                flags: 0,
                name: "ext-ms-win-core-midcomponent-l1-1-0",
                hash_span: SyntheticApiSetHashSpan::ExactPrefix("ext-ms-win-core-midcomp"),
                values: Vec::new(),
            },
        ],
    );

    assert_eq!(
        api_set_namespace_summary_for_test(&bytes).unwrap(),
        (0, 2, 0, 0, 2)
    );
    assert_eq!(
        api_set_namespace_entry_for_test(&bytes, "api-ms-win-core-trailing-l1-1-0")
            .unwrap()
            .unwrap(),
        (
            "API-MS-WIN-CORE-TRAILING-L1-".to_owned(),
            56,
            "opaque".to_owned(),
            "proper-prefix".to_owned(),
        )
    );
    assert_eq!(
        api_set_namespace_entry_for_test(&bytes, "ext-ms-win-core-midcomponent-l1-1-0")
            .unwrap()
            .unwrap(),
        (
            "EXT-MS-WIN-CORE-MIDCOMP".to_owned(),
            46,
            "opaque".to_owned(),
            "proper-prefix".to_owned(),
        )
    );
    for request in [
        "api-ms-win-core-trailing-l1-1-0.dll",
        "ext-ms-win-core-midcomponent-l1-1-0.dll",
    ] {
        let error = api_set_schema_resolution_for_test(&bytes, request, "parent.dll").unwrap_err();
        assert!(error.contains("selection=absent"), "{request}: {error}");
    }
}

#[test]
fn api_set_v6_uses_only_the_exact_public_revision_prefix_probe() {
    let default = |host| {
        vec![SyntheticApiSetValue {
            flags: 0,
            parent_alias: None,
            host,
        }]
    };
    let collision = synthetic_api_set_schema_v6_with_factor(
        0,
        1,
        &[
            SyntheticApiSetContract {
                flags: 0,
                name: "ipa-ms-win-core-demo-l1-1",
                hash_span: SyntheticApiSetHashSpan::WholeName,
                values: default("unrelated.dll"),
            },
            SyntheticApiSetContract {
                flags: 0,
                name: "api-ms-win-core-whole-l1-1-0",
                hash_span: SyntheticApiSetHashSpan::WholeName,
                values: default("whole.dll"),
            },
        ],
    );

    let collision_error = api_set_schema_resolution_for_test(
        &collision,
        "api-ms-win-core-demo-l1-1-3.dll",
        "parent.dll",
    )
    .unwrap_err();
    assert!(collision_error.contains("hash collision"));

    let public = synthetic_api_set_schema_v6(
        0,
        &[SyntheticApiSetContract {
            flags: 0,
            name: "api-ms-win-core-demo-l1-1-0",
            hash_span: SyntheticApiSetHashSpan::ProperPrefix,
            values: default("family.dll"),
        }],
    );
    assert_eq!(
        api_set_schema_resolution_for_test(
            &public,
            "api-ms-win-core-demo-l1-1-3.dll",
            "parent.dll",
        )
        .unwrap(),
        "FAMILY.DLL"
    );
    let whole = api_set_schema_resolution_for_test(
        &collision,
        "api-ms-win-core-whole-l1-1-0.dll",
        "parent.dll",
    )
    .unwrap_err();
    assert!(whole.contains("selection=absent"));
}

#[test]
fn api_set_v6_requests_reject_malformed_contract_names() {
    let bytes = synthetic_api_set_fixture();
    for contract in [
        "apis-ms-win-core-normal-l1-1-0.dll",
        "api-l1-1-0.dll",
        "api-ms-win-core-normal.dll",
        "api-ms-win-core-normal-l1-1-x.dll",
        "api-ms-win-core-normal-l1-1-0.exe",
        "api-ms-win-core-normal-l1-1-0.dll.dll",
        r"path\api-ms-win-core-normal-l1-1-0.dll",
        "api-ms-win-core-nönascii-l1-1-0.dll",
        "SchemaExt-Win3-Product-Extension-ClientCore.dll",
    ] {
        let error = api_set_schema_resolution_for_test(&bytes, contract, "parent.dll").unwrap_err();
        assert!(
            error.contains("requested API-set contract"),
            "contract {contract:?} returned {error:?}"
        );
    }
}

#[test]
fn api_set_v6_parser_rejects_every_structural_boundary_mutant() {
    let fixture = synthetic_api_set_fixture();
    let entry_offset = read_api_set_u32(&fixture, 16) as usize;
    let hash_offset = read_api_set_u32(&fixture, 20) as usize;
    let count = read_api_set_u32(&fixture, 12);
    let first_value = read_api_set_u32(&fixture, entry_offset + 16) as usize;
    let override_entry = entry_offset + 3 * 24;
    let override_value = read_api_set_u32(&fixture, override_entry + 16) as usize + 20;

    let mut mutations: Vec<(&str, Vec<u8>, &str)> = Vec::new();
    let mut mutate = |name: &'static str, offset: usize, value: u32, expected: &'static str| {
        let mut bytes = fixture.clone();
        write_api_set_u32(&mut bytes, offset, value);
        mutations.push((name, bytes, expected));
    };
    mutate("version", 0, 5, "not canonical version 6");
    mutate(
        "size",
        4,
        fixture.len() as u32 - 1,
        "not canonical version 6",
    );
    mutate("count-zero", 12, 0, "contract count 0");
    mutate(
        "entry-table",
        16,
        fixture.len() as u32,
        "entry table exceeds",
    );
    mutate("hash-table", 20, fixture.len() as u32, "hash table exceeds");
    mutate("hash-index", hash_offset + 4, count, "outside count");
    mutate(
        "name-odd",
        entry_offset + 8,
        1,
        "name length 1 is empty or odd",
    );
    mutate(
        "hashed-odd",
        entry_offset + 12,
        1,
        "hashed length 1 is zero, odd",
    );
    mutate(
        "hashed-zero",
        entry_offset + 12,
        0,
        "hashed length 0 is zero, odd",
    );
    mutate(
        "full-mode-row-hashed-as-revision-prefix",
        entry_offset + 12,
        read_api_set_u32(&fixture, entry_offset + 8),
        "does not match namespace index",
    );
    mutate(
        "hashed-too-long",
        entry_offset + 12,
        read_api_set_u32(&fixture, entry_offset + 8) + 2,
        "exceeds name length",
    );
    mutate(
        "hashed-component-boundary",
        entry_offset + 12,
        read_api_set_u32(&fixture, entry_offset + 12) - 2,
        "does not match namespace index",
    );
    mutate(
        "hashed-earlier-boundary",
        entry_offset + 12,
        read_api_set_u32(&fixture, entry_offset + 12) - 4,
        "does not match namespace index",
    );
    mutate("hash-factor", 24, 29, "does not match namespace index");
    mutate(
        "hash-value",
        hash_offset,
        read_api_set_u32(&fixture, hash_offset).wrapping_add(1),
        "does not match namespace index",
    );
    mutate("value-count", entry_offset + 20, 65, "value count 65");
    mutate(
        "value-table",
        entry_offset + 16,
        fixture.len() as u32,
        "value table exceeds",
    );
    mutate("alias-odd", override_value + 8, 1, "odd byte length");
    mutate("host-odd", first_value + 16, 1, "odd byte length");
    mutate(
        "host-out-of-range",
        first_value + 12,
        fixture.len() as u32,
        "string exceeds",
    );
    mutate(
        "name-out-of-range",
        entry_offset + 4,
        fixture.len() as u32,
        "string exceeds",
    );

    let empty_default_entry = entry_offset + 2 * 24;
    let empty_default_value = read_api_set_u32(&fixture, empty_default_entry + 16) as usize;
    mutate(
        "zero-host-offset-out-of-range",
        empty_default_value + 12,
        fixture.len() as u32 + 1,
        "string exceeds",
    );
    drop(mutate);

    let mut duplicate_namespace_index = fixture.clone();
    write_api_set_u32(
        &mut duplicate_namespace_index,
        hash_offset + 8 + 4,
        read_api_set_u32(&fixture, hash_offset + 4),
    );
    mutations.push((
        "hash-duplicate-namespace-index",
        duplicate_namespace_index,
        "duplicates namespace index",
    ));
    let mut wrong_namespace_index = fixture.clone();
    let first_index = read_api_set_u32(&fixture, hash_offset + 4);
    let second_index = read_api_set_u32(&fixture, hash_offset + 8 + 4);
    write_api_set_u32(&mut wrong_namespace_index, hash_offset + 4, second_index);
    write_api_set_u32(&mut wrong_namespace_index, hash_offset + 8 + 4, first_index);
    mutations.push((
        "hash-wrong-namespace-index",
        wrong_namespace_index,
        "does not match namespace index",
    ));
    let mut duplicate_hash = fixture.clone();
    write_api_set_u32(
        &mut duplicate_hash,
        hash_offset + 8,
        read_api_set_u32(&fixture, hash_offset),
    );
    mutations.push(("hash-collision", duplicate_hash, "not strictly increasing"));
    let mut unsorted_hashes = fixture.clone();
    let first_hash = read_api_set_u32(&fixture, hash_offset);
    let second_hash = read_api_set_u32(&fixture, hash_offset + 8);
    write_api_set_u32(&mut unsorted_hashes, hash_offset, second_hash);
    write_api_set_u32(&mut unsorted_hashes, hash_offset + 8, first_hash);
    mutations.push(("hash-unsorted", unsorted_hashes, "not strictly increasing"));

    for (name, bytes, expected) in mutations {
        let error = api_set_schema_summary_for_test(&bytes).unwrap_err();
        assert!(
            error.contains(expected),
            "mutation {name} returned {error:?}, expected {expected:?}"
        );
    }
}

#[test]
fn api_set_v6_parser_binds_each_hash_span_to_its_exact_native_row_hash() {
    let value = SyntheticApiSetValue {
        flags: 0,
        parent_alias: None,
        host: "kernelbase.dll",
    };
    for (span, wrong_key) in [
        (
            SyntheticApiSetHashSpan::WholeName,
            "api-ms-win-core-hash-mode-l1-1",
        ),
        (
            SyntheticApiSetHashSpan::ProperPrefix,
            "api-ms-win-core-hash-mode-l1-1-0",
        ),
    ] {
        let mut bytes = synthetic_api_set_schema_v6(
            0,
            &[SyntheticApiSetContract {
                flags: 0,
                name: "api-ms-win-core-hash-mode-l1-1-0",
                hash_span: span,
                values: vec![value],
            }],
        );
        let wrong_hash = synthetic_api_set_hash(wrong_key, 31);
        let hash_offset = read_api_set_u32(&bytes, 20) as usize;
        write_api_set_u32(&mut bytes, hash_offset, wrong_hash);
        assert!(
            api_set_schema_summary_for_test(&bytes)
                .unwrap_err()
                .contains("does not match namespace index")
        );
    }
}

#[test]
fn api_set_v6_parser_rejects_ambiguous_ordinals_and_names() {
    let default = SyntheticApiSetValue {
        flags: 0,
        parent_alias: None,
        host: "kernelbase.dll",
    };
    let duplicate_contracts = synthetic_api_set_schema_v6(
        0,
        &[
            SyntheticApiSetContract {
                flags: 0,
                name: "api-ms-win-core-duplicate-l1-1-0",
                hash_span: SyntheticApiSetHashSpan::ProperPrefix,
                values: vec![default],
            },
            SyntheticApiSetContract {
                flags: 0,
                name: "API-MS-WIN-CORE-DUPLICATE-L1-1-1",
                hash_span: SyntheticApiSetHashSpan::ProperPrefix,
                values: vec![default],
            },
        ],
    );
    assert!(
        api_set_schema_summary_for_test(&duplicate_contracts)
            .unwrap_err()
            .contains("duplicate hash key")
    );

    let duplicate_full_name = synthetic_api_set_schema_v6(
        0,
        &[
            SyntheticApiSetContract {
                flags: 0,
                name: "api-ms-win-core-same-l1-1-0",
                hash_span: SyntheticApiSetHashSpan::ProperPrefix,
                values: vec![default],
            },
            SyntheticApiSetContract {
                flags: 0,
                name: "API-MS-WIN-CORE-SAME-L1-1-0",
                hash_span: SyntheticApiSetHashSpan::ProperPrefix,
                values: vec![default],
            },
        ],
    );
    assert!(
        api_set_schema_summary_for_test(&duplicate_full_name)
            .unwrap_err()
            .contains("duplicate namespace name")
    );

    let suffixed_schema_name = synthetic_api_set_schema_v6(
        0,
        &[SyntheticApiSetContract {
            flags: 0,
            name: "api-ms-win-core-suffixed-l1-1-0.dll",
            hash_span: SyntheticApiSetHashSpan::ProperPrefix,
            values: vec![default],
        }],
    );
    assert!(
        api_set_schema_summary_for_test(&suffixed_schema_name)
            .unwrap_err()
            .contains("name")
    );

    let invalid_default = synthetic_api_set_schema_v6(
        0,
        &[SyntheticApiSetContract {
            flags: 0,
            name: "api-ms-win-core-invalid-default-l1-1-0",
            hash_span: SyntheticApiSetHashSpan::ProperPrefix,
            values: vec![SyntheticApiSetValue {
                parent_alias: Some("parent.dll"),
                ..default
            }],
        }],
    );
    assert!(
        api_set_schema_summary_for_test(&invalid_default)
            .unwrap_err()
            .contains("value 0 is not the default")
    );

    let missing_override_alias = synthetic_api_set_schema_v6(
        0,
        &[SyntheticApiSetContract {
            flags: 0,
            name: "api-ms-win-core-missing-alias-l1-1-0",
            hash_span: SyntheticApiSetHashSpan::ProperPrefix,
            values: vec![default, default],
        }],
    );
    assert!(
        api_set_schema_summary_for_test(&missing_override_alias)
            .unwrap_err()
            .contains("value 1 has no parent alias")
    );

    let duplicate_alias = synthetic_api_set_schema_v6(
        0,
        &[SyntheticApiSetContract {
            flags: 0,
            name: "api-ms-win-core-duplicate-alias-l1-1-0",
            hash_span: SyntheticApiSetHashSpan::ProperPrefix,
            values: vec![
                default,
                SyntheticApiSetValue {
                    parent_alias: Some("Parent.Dll"),
                    ..default
                },
                SyntheticApiSetValue {
                    parent_alias: Some("PARENT.DLL"),
                    ..default
                },
            ],
        }],
    );
    assert!(
        api_set_schema_summary_for_test(&duplicate_alias)
            .unwrap_err()
            .contains("duplicate parent alias PARENT.DLL")
    );

    let extension_distinct_aliases = synthetic_api_set_schema_v6(
        0,
        &[SyntheticApiSetContract {
            flags: 0,
            name: "api-ms-win-core-distinct-alias-l1-1-0",
            hash_span: SyntheticApiSetHashSpan::ProperPrefix,
            values: vec![
                default,
                SyntheticApiSetValue {
                    parent_alias: Some("Parent"),
                    ..default
                },
                SyntheticApiSetValue {
                    parent_alias: Some("PARENT.DLL"),
                    ..default
                },
            ],
        }],
    );
    api_set_schema_summary_for_test(&extension_distinct_aliases).unwrap();

    let duplicate_composition_names = synthetic_api_set_schema_v6(
        0,
        &[
            SyntheticApiSetContract {
                flags: 0,
                name: "SchemaExt-Win3-Product-Extension-ClientCore",
                hash_span: SyntheticApiSetHashSpan::WholeName,
                values: Vec::new(),
            },
            SyntheticApiSetContract {
                flags: 0,
                name: "SCHEMAEXT-WIN3-PRODUCT-EXTENSION-CLIENTCORE",
                hash_span: SyntheticApiSetHashSpan::WholeName,
                values: Vec::new(),
            },
        ],
    );
    assert!(
        api_set_schema_summary_for_test(&duplicate_composition_names)
            .unwrap_err()
            .contains("duplicate namespace name")
    );

    let duplicate_opaque_prefix = synthetic_api_set_schema_v6(
        0,
        &[
            SyntheticApiSetContract {
                flags: 0,
                name: "SchemaExt-Win3-Product-Extension-Shared-One",
                hash_span: SyntheticApiSetHashSpan::ProperPrefix,
                values: Vec::new(),
            },
            SyntheticApiSetContract {
                flags: 0,
                name: "SchemaExt-Win3-Product-Extension-Shared-Two",
                hash_span: SyntheticApiSetHashSpan::ProperPrefix,
                values: Vec::new(),
            },
        ],
    );
    assert!(
        api_set_schema_summary_for_test(&duplicate_opaque_prefix)
            .unwrap_err()
            .contains("duplicate hash key")
    );
}

#[test]
fn api_set_v6_namespace_names_are_structural_before_request_classification() {
    let admitted = synthetic_api_set_schema_v6(
        0,
        &[
            SyntheticApiSetContract {
                flags: 0,
                name: "SchemaExt-Win3-Product-Extension-ClientCore",
                hash_span: SyntheticApiSetHashSpan::WholeName,
                values: Vec::new(),
            },
            SyntheticApiSetContract {
                flags: 0,
                name: "Unknown-Family-Structurally-Safe",
                hash_span: SyntheticApiSetHashSpan::WholeName,
                values: Vec::new(),
            },
        ],
    );
    assert_eq!(api_set_schema_summary_for_test(&admitted).unwrap().1, 2);

    for invalid_name in [
        "",
        "-SchemaExt",
        "SchemaExt-",
        "SchemaExt--ClientCore",
        "SchemaExt.ClientCore",
        "SchemaExt/ClientCore",
        r"SchemaExt\ClientCore",
        "SchemaExt-Client\0Core",
        "SchemaExt-Client\nCore",
        "SchemaExt-ClientCöre",
    ] {
        let bytes = synthetic_api_set_schema_v6(
            0,
            &[SyntheticApiSetContract {
                flags: 0,
                name: invalid_name,
                hash_span: SyntheticApiSetHashSpan::WholeName,
                values: Vec::new(),
            }],
        );
        assert!(
            api_set_schema_summary_for_test(&bytes).is_err(),
            "invalid structural namespace name {invalid_name:?} was admitted"
        );
    }

    let overlong = "A".repeat(65);
    let overlong_bytes = synthetic_api_set_schema_v6(
        0,
        &[SyntheticApiSetContract {
            flags: 0,
            name: &overlong,
            hash_span: SyntheticApiSetHashSpan::WholeName,
            values: Vec::new(),
        }],
    );
    assert!(api_set_schema_summary_for_test(&overlong_bytes).is_err());

    let mut invalid_utf16 = synthetic_api_set_schema_v6(
        0,
        &[SyntheticApiSetContract {
            flags: 0,
            name: "SchemaExt-Win3-Product-Extension-InvalidUtf16",
            hash_span: SyntheticApiSetHashSpan::WholeName,
            values: Vec::new(),
        }],
    );
    let entry_offset = read_api_set_u32(&invalid_utf16, 16) as usize;
    let name_offset = read_api_set_u32(&invalid_utf16, entry_offset + 4) as usize;
    invalid_utf16[name_offset..name_offset + 2].copy_from_slice(&0xd800_u16.to_le_bytes());
    assert!(
        api_set_schema_summary_for_test(&invalid_utf16)
            .unwrap_err()
            .contains("invalid UTF-16")
    );
}

#[test]
fn api_set_v6_parser_never_invents_or_admits_a_nonphysical_host() {
    for host in [
        ".",
        "..",
        r"..\escape.dll",
        r"C:\Windows\System32\kernel32.dll",
        "api-ms-win-core-nested-l1-1-0.dll",
        "ext-ms-win-nested-l1-1-0.dll",
        "nönascii.dll",
    ] {
        let bytes = synthetic_api_set_schema_v6(
            0,
            &[SyntheticApiSetContract {
                flags: 0,
                name: "api-ms-win-core-host-mutant-l1-1-0",
                hash_span: SyntheticApiSetHashSpan::ProperPrefix,
                values: vec![SyntheticApiSetValue {
                    flags: 0,
                    parent_alias: None,
                    host,
                }],
            }],
        );
        let error = api_set_schema_summary_for_test(&bytes).unwrap_err();
        assert!(error.contains("host is invalid"), "host {host:?}: {error}");
    }

    let mut invalid_utf16 = synthetic_api_set_schema_v6(
        0,
        &[SyntheticApiSetContract {
            flags: 0,
            name: "api-ms-win-core-invalid-utf16-l1-1-0",
            hash_span: SyntheticApiSetHashSpan::ProperPrefix,
            values: vec![SyntheticApiSetValue {
                flags: 0,
                parent_alias: None,
                host: "kernelbase.dll",
            }],
        }],
    );
    let entry = read_api_set_u32(&invalid_utf16, 16) as usize;
    let value = read_api_set_u32(&invalid_utf16, entry + 16) as usize;
    let host_offset = read_api_set_u32(&invalid_utf16, value + 12) as usize;
    invalid_utf16[host_offset..host_offset + 2].copy_from_slice(&0xd800_u16.to_le_bytes());
    write_api_set_u32(&mut invalid_utf16, value + 16, 2);
    assert!(
        api_set_schema_summary_for_test(&invalid_utf16)
            .unwrap_err()
            .contains("invalid UTF-16")
    );
}

#[test]
fn native_api_set_v6_schema_admits_inactive_records_on_each_windows_architecture() {
    assert!(cfg!(any(target_arch = "x86_64", target_arch = "aarch64")));
    let (sha256, contract_count, inactive_contract_count, unhosted_value_count) =
        current_api_set_schema_for_test().unwrap();
    assert_eq!(sha256.len(), 64);
    assert!(sha256.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(contract_count > 0);
    assert!(inactive_contract_count + unhosted_value_count <= contract_count * 65);
    let (
        whole_name_count,
        proper_prefix_count,
        public_contract_count,
        schema_composition_count,
        opaque_count,
    ) = current_api_set_namespace_summary_for_test().unwrap();
    assert_eq!(whole_name_count + proper_prefix_count, contract_count);
    assert_eq!(
        public_contract_count + schema_composition_count + opaque_count,
        contract_count
    );
    assert!(public_contract_count > 0);
    #[cfg(target_arch = "x86_64")]
    assert!(
        whole_name_count > 0,
        "native x64 API-set schema {sha256} has no whole-name hash rows"
    );

    if sha256 == "3192e96f7a87c4134d7b1b1c8e8ed26638f0b7d58ad99d8553f1dc005212263a" {
        let entry =
            current_api_set_namespace_entry_for_test("SchemaExt-Win3-Product-Extension-ClientCore")
                .unwrap()
                .expect("observed native schema must retain its SchemaExt composition row");
        assert_eq!(entry.0, sha256);
        assert_eq!((entry.1, entry.2), (86, 86));
        assert_eq!(entry.3, "schema-composition");
        assert_eq!(entry.4, "whole-name");
    }

    for contract in [
        "API-MS-WIN-CORE-HANDLE-L1-1-0.DLL",
        "API-MS-WIN-CORE-SYNCH-L1-2-0.DLL",
    ] {
        let host =
            current_api_set_resolution_for_test(contract, "memcordon-target-desktop-bootstrap.exe")
                .unwrap();
        assert_ne!(host, ".DLL");
        assert!(host.ends_with(".DLL"));
    }
}

#[test]
fn native_loader_graph_v2_rejects_phase_edge_identity_and_bound_mutations() {
    let evidence = native_loader_access_evidence(memcordon_core::WINDOWS_PE_MACHINE_AMD64);
    evidence.validate().unwrap();

    let mut missing_security_root = evidence.clone();
    missing_security_root
        .loader_roots
        .retain(|root| root.phase != LoaderRootPhaseV2::ExplicitSecurity);
    assert!(missing_security_root.mark_reverted_and_seal().is_err());

    let mut unordered_static = evidence.clone();
    unordered_static.loader_roots[0].descriptor_ordinal = None;
    assert!(unordered_static.mark_reverted_and_seal().is_err());

    let mut missing_parent = evidence.clone();
    missing_parent.loader_edges[0].parent_host = "NTDLL.DLL".to_owned();
    assert!(missing_parent.mark_reverted_and_seal().is_err());

    let mut depth_overflow = evidence.clone();
    depth_overflow.loader_edges[0].depth = 17;
    assert!(depth_overflow.mark_reverted_and_seal().is_err());

    let mut nonminimum_depth = evidence.clone();
    nonminimum_depth.loader_edges[0].depth = 1;
    assert!(nonminimum_depth.mark_reverted_and_seal().is_err());

    let mut virtual_without_redirect = evidence.clone();
    virtual_without_redirect.loader_edges[0].import_contract =
        "API-MS-WIN-CORE-HANDLE-L1-1-0.DLL".to_owned();
    assert!(virtual_without_redirect.mark_reverted_and_seal().is_err());

    let mut false_forwarder = evidence.clone();
    false_forwarder.loader_edges[0].forwarder = true;
    assert!(false_forwarder.mark_reverted_and_seal().is_err());

    let mut section_contract_mismatch = evidence.clone();
    section_contract_mismatch.known_dll_sections[0].loader_contract_sha256 = "aa".repeat(32);
    assert!(section_contract_mismatch.mark_reverted_and_seal().is_err());

    let mut digest_mismatch = evidence;
    digest_mismatch.loader_graph_sha256 = "bb".repeat(32);
    assert!(digest_mismatch.validate().is_err());
}

#[test]
fn native_loader_forwarder_identity_is_exact_and_independently_bounded() {
    for machine in [
        memcordon_core::WINDOWS_PE_MACHINE_AMD64,
        memcordon_core::WINDOWS_PE_MACHINE_ARM64,
    ] {
        let contract = memcordon_core::WindowsPeLoaderContract {
            machine,
            normal: Vec::new(),
            delayed: Vec::new(),
            exports: vec![
                memcordon_core::WindowsPeExport {
                    ordinal: 7,
                    name: Some("Foo".to_owned()),
                    target: memcordon_core::WindowsPeExportTarget::DirectRva(1),
                },
                memcordon_core::WindowsPeExport {
                    ordinal: 42,
                    name: None,
                    target: memcordon_core::WindowsPeExportTarget::DirectRva(2),
                },
            ],
        };
        assert!(loader_export_matches_for_test(
            &contract,
            &memcordon_core::WindowsPeImportSymbol::Name {
                hint: 0,
                name: "Foo".to_owned(),
            },
        ));
        assert!(!loader_export_matches_for_test(
            &contract,
            &memcordon_core::WindowsPeImportSymbol::Name {
                hint: 0,
                name: "foo".to_owned(),
            },
        ));
        assert!(loader_export_matches_for_test(
            &contract,
            &memcordon_core::WindowsPeImportSymbol::Ordinal(42),
        ));

        let bounded = (0..16)
            .map(|index| {
                (
                    format!("HOST{index}.DLL"),
                    memcordon_core::WindowsPeImportSymbol::Name {
                        hint: index,
                        name: format!("Symbol{index}"),
                    },
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(forwarder_path_result_for_test(&bounded), Ok(16));
        let mut overflow = bounded;
        overflow.push((
            "HOST16.DLL".to_owned(),
            memcordon_core::WindowsPeImportSymbol::Ordinal(16),
        ));
        assert_eq!(
            forwarder_path_result_for_test(&overflow),
            Err("export-forwarder-hop-bound"),
        );

        let named = |host: &str, name: &str| {
            (
                host.to_owned(),
                memcordon_core::WindowsPeImportSymbol::Name {
                    hint: 0,
                    name: name.to_owned(),
                },
            )
        };
        assert_eq!(
            forwarder_path_result_for_test(&[
                named("A.DLL", "Foo"),
                named("B.DLL", "Bar"),
                named("A.DLL", "Foo"),
            ]),
            Err("export-forwarder-cycle"),
        );
        assert_eq!(
            forwarder_path_result_for_test(&[
                named("A.DLL", "Foo"),
                named("B.DLL", "Bar"),
                named("A.DLL", "Baz"),
            ]),
            Ok(3),
        );
        let api_set_values = [
            (None, "KERNEL32.DLL"),
            (Some("KERNEL32.DLL"), "KERNELBASE.DLL"),
            (Some("SECOND.DLL"), "NTDLL.DLL"),
        ];
        assert_eq!(
            api_set_parent_selection_for_test(&api_set_values, "KERNEL32.DLL").as_deref(),
            Some("KERNELBASE.DLL"),
        );
        assert_eq!(
            api_set_parent_selection_for_test(&api_set_values, "SECOND.DLL").as_deref(),
            Some("NTDLL.DLL"),
        );
        assert_eq!(
            api_set_parent_selection_for_test(&api_set_values, "OTHER.DLL").as_deref(),
            Some("KERNEL32.DLL"),
        );
    }
}

#[test]
fn native_loader_graph_depth_is_shortest_and_traversal_order_independent() {
    let root = LoaderRootEvidenceV2 {
        phase: LoaderRootPhaseV2::StaticKernel,
        descriptor_ordinal: Some(0),
        import_contract: "A.DLL".to_owned(),
        concrete_host: "A.DLL".to_owned(),
        export_contract_sha256: "11".repeat(32),
    };
    let edge = |parent: &str, child: &str, ordinal: u32| LoaderImportEdgeEvidenceV2 {
        phase: LoaderRootPhaseV2::StaticKernel,
        depth: u32::MAX,
        parent_host: parent.to_owned(),
        descriptor_ordinal: Some(ordinal),
        requested_symbol: None,
        import_contract: child.to_owned(),
        concrete_host: child.to_owned(),
        resolved_target_symbol: None,
        api_set_redirected: false,
        forwarder: false,
    };
    let mut edges = vec![
        edge("A.DLL", "B.DLL", 0),
        edge("B.DLL", "C.DLL", 0),
        edge("C.DLL", "D.DLL", 0),
        edge("A.DLL", "D.DLL", 1),
        edge("D.DLL", "A.DLL", 0),
    ];
    let forward = loader_graph_shortest_depths_for_test(std::slice::from_ref(&root), &edges);
    edges.reverse();
    let reverse = loader_graph_shortest_depths_for_test(std::slice::from_ref(&root), &edges);
    assert_eq!(forward, reverse);
    assert_eq!(
        forward.get(&(LoaderRootPhaseV2::StaticKernel, "A.DLL".to_owned())),
        Some(&0),
    );
    assert_eq!(
        forward.get(&(LoaderRootPhaseV2::StaticKernel, "D.DLL".to_owned())),
        Some(&1),
    );

    let mut outer_edges = Vec::new();
    let mut parent = "A.DLL".to_owned();
    for depth in 1..=15 {
        let child = format!("DEPTH{depth}.DLL");
        outer_edges.push(edge(&parent, &child, depth));
        parent = child;
    }
    let outer = loader_graph_shortest_depths_for_test(&[root], &outer_edges);
    assert_eq!(
        outer.get(&(LoaderRootPhaseV2::StaticKernel, "DEPTH15.DLL".to_owned(),)),
        Some(&15),
    );
    assert_eq!(
        forwarder_path_result_for_test(&[(
            "DEPTH15.DLL".to_owned(),
            memcordon_core::WindowsPeImportSymbol::Name {
                hint: 0,
                name: "OneHop".to_owned(),
            },
        )]),
        Ok(1),
    );
}

#[test]
fn native_architectures_never_select_wow64_known_dll_namespaces() {
    for machine in [
        memcordon_core::WINDOWS_PE_MACHINE_AMD64,
        memcordon_core::WINDOWS_PE_MACHINE_ARM64,
    ] {
        assert_eq!(
            native_known_dll_namespace_for_test(machine).unwrap(),
            r"\KnownDlls"
        );
    }
    assert!(native_known_dll_namespace_for_test(0x014c).is_err());
}

#[test]
fn installed_fixed_helpers_require_the_current_native_pe_machine() {
    #[cfg(target_arch = "x86_64")]
    let (native, foreign) = (
        memcordon_core::WINDOWS_PE_MACHINE_AMD64,
        memcordon_core::WINDOWS_PE_MACHINE_ARM64,
    );
    #[cfg(target_arch = "aarch64")]
    let (native, foreign) = (
        memcordon_core::WINDOWS_PE_MACHINE_ARM64,
        memcordon_core::WINDOWS_PE_MACHINE_AMD64,
    );

    crate::windows::package::require_native_pe_machine_for_test(native).unwrap();
    let error = crate::windows::package::require_native_pe_machine_for_test(foreign).unwrap_err();
    assert!(error.contains("expected_native_machine="));
    assert!(error.contains("actual_machine="));
}

fn test_public_pipe_sddl() -> String {
    let owner = crate::windows::token::process_envelope(std::process::id())
        .unwrap()
        .owner_sid;
    public_pipe_sddl()
        .unwrap()
        .replacen("O:LS", &format!("O:{owner}"), 1)
}

#[test]
fn descriptor_text_stops_at_first_nul() {
    assert_eq!(
        utf16_nul_terminated(&['D' as u16, ':' as u16, 'P' as u16, 0, 0, 0]).unwrap(),
        "D:P"
    );
    assert!(utf16_nul_terminated(&['D' as u16, ':' as u16]).is_err());

    let d = 'D' as u16;
    let colon = ':' as u16;
    let p = 'P' as u16;
    let x = 'X' as u16;
    for (name, buffer, reported, expected) in [
        ("inclusive", &[d, colon, p, 0][..], 4, Some("D:P")),
        ("exclusive", &[d, colon, p, 0][..], 3, Some("D:P")),
        (
            "capacity-first-nul",
            &[d, colon, p, 0, 0xd800, 0xa5a5, 0][..],
            7,
            Some("D:P"),
        ),
        ("zero-immediately", &[0][..], 1, Some("")),
        ("zero-report", &[0][..], 0, None),
        ("allocation-boundary", &[d, colon, p][..], 3, None),
        ("nonzero-extra", &[d, colon, p, x][..], 3, None),
        ("reported-mismatch", &[d, colon, p, 0][..], 5, None),
        ("terminator-too-late", &[d, colon, p, x, 0][..], 3, None),
        ("multiple-zero-padding", &[d, 0, 0, 0][..], 4, Some("D")),
        ("invalid-padding-ignored", &[d, 0, 0xd800][..], 3, Some("D")),
    ] {
        let actual = utf16_nul_terminated_with_reported_length(buffer, reported);
        match expected {
            Some(expected) => assert_eq!(actual.unwrap(), expected, "{name}"),
            None => assert!(actual.is_err(), "{name}"),
        }
    }
    assert!(
        utf16_nul_terminated_with_reported_length(&[0xd800, 0], 2).is_err(),
        "invalid UTF-16 before the terminator must fail"
    );
}

#[test]
fn descriptor_text_allocation_window_is_exact_and_bounded() {
    assert_eq!(sddl_utf16_allocation_window(4, 8).unwrap(), (4, 4));
    assert_eq!(sddl_utf16_allocation_window(3, 8).unwrap(), (3, 4));
    assert_eq!(sddl_utf16_allocation_window(3, 16).unwrap(), (3, 4));

    assert!(sddl_utf16_allocation_window(0, 2).is_err());
    assert!(sddl_utf16_allocation_window(1, 0).is_err());
    assert!(sddl_utf16_allocation_window(1, 3).is_err());
    assert!(sddl_utf16_allocation_window(3, 4).is_err());
    assert!(sddl_utf16_allocation_window(1_048_577, 2_097_154).is_err());
}

#[test]
fn nested_child_completion_preserves_timeout_and_unsigned_native_status() {
    use crate::windows::qualification::{NestedChildCompletion, validate_nested_child_completion};

    assert_eq!(
        validate_nested_child_completion(NestedChildCompletion::Exited(0)),
        Ok(())
    );
    assert_eq!(
        validate_nested_child_completion(NestedChildCompletion::TimedOut).unwrap_err(),
        "nested alternate-token child timed out after 30000 ms"
    );
    assert_eq!(
        validate_nested_child_completion(NestedChildCompletion::Exited(125)).unwrap_err(),
        "nested alternate-token child exited with status 125 (0x0000007d)"
    );
    assert_eq!(
        validate_nested_child_completion(NestedChildCompletion::Exited(0xC000_013A)).unwrap_err(),
        "nested alternate-token child exited with status 3221225786 (0xc000013a)"
    );
    assert_eq!(
        validate_nested_child_completion(NestedChildCompletion::Exited(0xC000_0142)).unwrap_err(),
        "nested alternate-token child exited with status 3221225794 (0xc0000142 STATUS_DLL_INIT_FAILED; entry not instrumented)"
    );
}

#[test]
fn nested_child_stream_manifest_rejects_invalid_or_duplicate_values() {
    use crate::windows::qualification::validate_nested_child_stream_values;

    assert!(validate_nested_child_stream_values([11, 12, 13]).is_ok());
    for values in [
        [0, 12, 13],
        [u64::MAX, 12, 13],
        [11, 11, 13],
        [11, 12, 11],
        [11, 12, 12],
    ] {
        assert!(validate_nested_child_stream_values(values).is_err());
    }
}

#[test]
fn cleanup_process_creation_is_required_only_after_process_tree_completion() {
    use crate::windows::qualification::TargetResultPhaseV1;

    for phase in [
        TargetResultPhaseV1::ArgumentBinding,
        TargetResultPhaseV1::HandleInheritance,
        TargetResultPhaseV1::StandardStreams,
        TargetResultPhaseV1::ProcessTree,
    ] {
        assert!(!crate::windows::launcher_service::cleanup_process_creation_expected(phase));
    }
    for phase in [
        TargetResultPhaseV1::OuterJobMembership,
        TargetResultPhaseV1::RestrictedPrimaryConstruction,
        TargetResultPhaseV1::InnerJobCreation,
        TargetResultPhaseV1::StreamSetup,
        TargetResultPhaseV1::LoaderContext,
        TargetResultPhaseV1::SuspendedChildCreation,
        TargetResultPhaseV1::TokenMembershipReadback,
        TargetResultPhaseV1::MarkerPublication,
        TargetResultPhaseV1::Resume,
        TargetResultPhaseV1::ChildExit,
        TargetResultPhaseV1::InnerJobEmpty,
        TargetResultPhaseV1::Complete,
    ] {
        assert!(crate::windows::launcher_service::cleanup_process_creation_expected(phase));
    }
}

#[test]
fn guardian_desktop_binding_rejects_interactive_contexts() {
    assert!(validate_guardian_desktop_binding("Service-0x0-3e7$", "Default", false).is_ok());
    assert!(validate_guardian_desktop_binding("WinSta0", "Default", false).is_err());
    assert!(validate_guardian_desktop_binding("Service-0x0-3e7$", "Default", true).is_err());
}

#[test]
fn current_user_binding_attestation_duplicates_have_exact_working_rights_and_close_cleanly() {
    for _ in 0..32 {
        attest_current_user_binding_duplicates_for_test().unwrap();
    }
}

#[test]
fn private_target_desktop_binding_is_station_class_agnostic() {
    let station = format!("MemCordonTarget-{}", "ab".repeat(32));
    assert!(validate_target_desktop_binding(&station, "Restricted").is_ok());
    for (station, desktop) in [
        ("Service-0x0-3e7$", "Restricted"),
        ("WinSta0", "Restricted"),
        ("MemCordonTarget-ABCDEF", "Restricted"),
        ("MemCordonTarget-00", "Restricted"),
        ("", "Restricted"),
        ("MemCordonTarget-ab\\Bad", "Restricted"),
        (station.as_str(), "Default"),
        (station.as_str(), "Restricted\\Bad"),
    ] {
        assert!(validate_target_desktop_binding(station, desktop).is_err());
    }
}

#[test]
fn private_target_desktop_must_not_receive_input() {
    assert!(validate_target_desktop_input_state(false).is_ok());
    assert!(validate_target_desktop_input_state(true).is_err());
}

#[test]
fn nested_object_policies_are_exact_for_each_native_role() {
    let creator = crate::windows::token::process_user_sid(unsafe {
        windows_sys::Win32::System::Threading::GetCurrentProcess()
    })
    .unwrap();
    assert_eq!(
        nested_canary_job_sddl().unwrap(),
        format!("O:{creator}D:P(A;;GA;;;{creator})(A;;GA;;;WR)")
    );
    let target = format!("O:{creator}D:P(A;;GA;;;SY)(A;;GA;;;{creator})(A;;GA;;;WR)");
    assert_eq!(nested_canary_process_sddl().unwrap(), target);
    assert_eq!(nested_canary_thread_sddl().unwrap(), target);
}

#[test]
fn target_user_namespace_policy_is_private_and_write_restricted() {
    assert_eq!(TARGET_PRIVATE_WINDOW_STATION_ACCESS, 0x000f_016f);
    assert_eq!(TARGET_PRIVATE_DESKTOP_ACCESS, 0x000f_01ff);
    let token = crate::windows::token::write_restricted_current_primary().unwrap();
    let logon_sid = crate::windows::token::token_logon_sid(token.raw()).unwrap();
    let envelope = crate::windows::token::envelope(token.raw()).unwrap();
    let policy =
        target_user_object_policy(token.raw(), TargetUserObjectPolicyRoleV1::DirectTarget).unwrap();
    assert!(matches!(
        policy.restriction,
        TargetRestrictionSemantics::WriteRestricted { .. }
    ));
    let station_sddl = policy.window_station_sddl();
    let desktop_sddl = policy.desktop_sddl();
    for sddl in [&station_sddl, &desktop_sddl] {
        assert!(sddl.starts_with("O:SYG:SYD:P"));
        assert!(sddl.ends_with(&format!("S:P(ML;;NW;;;{})", envelope.integrity_level)));
        for broad in [";;;WD)", ";;;BU)", ";;;IU)", ";;;AN)", ";;;BA)", ";;;RC)"] {
            assert!(!sddl.contains(broad));
        }
        assert!(!sddl.contains(&format!(";;;{})", envelope.user_sid)));
    }
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME).unwrap();
    for trustee in [
        "S-1-5-18",
        launcher.as_str(),
        logon_sid.as_str(),
        "S-1-5-33",
    ] {
        assert!(station_sddl.contains(&format!(
            "(A;;0x{TARGET_PRIVATE_WINDOW_STATION_ACCESS:08x};;;{trustee})"
        )));
        assert!(desktop_sddl.contains(&format!(
            "(A;;0x{TARGET_PRIVATE_DESKTOP_ACCESS:08x};;;{trustee})"
        )));
    }
    assert_ne!(station_sddl, desktop_sddl);
}

#[test]
fn target_restriction_classification_rejects_every_contradictory_oracle_matrix() {
    use crate::windows::security::classify_target_restriction_for_test;

    assert!(matches!(
        classify_target_restriction_for_test(false, &[], false).unwrap(),
        TargetRestrictionSemantics::Unrestricted
    ));
    assert!(matches!(
        classify_target_restriction_for_test(true, &["S-1-5-12"], false).unwrap(),
        TargetRestrictionSemantics::Restricted { .. }
    ));
    assert!(matches!(
        classify_target_restriction_for_test(true, &["S-1-5-33"], true).unwrap(),
        TargetRestrictionSemantics::WriteRestricted { .. }
    ));
    for (is_restricted, sids, write_restricted) in [
        (true, &[][..], false),
        (false, &["S-1-5-12"][..], false),
        (false, &[][..], true),
        (true, &["S-1-5-12"][..], true),
        (true, &["S-1-5-33"][..], false),
    ] {
        assert!(
            classify_target_restriction_for_test(is_restricted, sids, write_restricted).is_err()
        );
    }
}

#[test]
fn unrestricted_target_policy_is_logon_exact_and_nested_delegation_is_explicit() {
    let token =
        crate::windows::token::current_process_token_for_attestation_and_access_check().unwrap();
    assert!(!crate::windows::token::token_is_restricted(token.raw()));
    let direct =
        target_user_object_policy(token.raw(), TargetUserObjectPolicyRoleV1::DirectTarget).unwrap();
    assert!(matches!(
        direct.restriction,
        TargetRestrictionSemantics::Unrestricted
    ));
    let direct_sddl = direct.window_station_sddl();
    let nested = target_user_object_policy(
        token.raw(),
        TargetUserObjectPolicyRoleV1::NestedWriteRestrictedDelegation,
    )
    .unwrap();
    let nested_sddl = nested.window_station_sddl();
    assert!(!direct_sddl.contains(";;;S-1-5-33)"));
    assert!(nested_sddl.contains(";;;S-1-5-33)"));
    let envelope = crate::windows::token::envelope(token.raw()).unwrap();
    assert!(!direct_sddl.contains(&format!(";;;{})", envelope.user_sid)));
    let logon_sid = crate::windows::token::token_logon_sid(token.raw()).unwrap();
    assert!(direct_sddl.contains(&format!(";;;{logon_sid})")));
}

#[test]
fn user_object_creation_descriptor_is_absolute_and_preserves_policy() {
    let token = crate::windows::token::write_restricted_current_primary().unwrap();
    let descriptor =
        SecurityDescriptor::from_sddl(&target_desktop_sddl(token.raw()).unwrap()).unwrap();
    assert!(descriptor.applies_mandatory_label());
    let absolute = descriptor.absolute_for_user_object_creation().unwrap();
    assert_ne!(unsafe { IsValidSecurityDescriptor(descriptor.raw()) }, 0);
    assert_ne!(unsafe { IsValidSecurityDescriptor(absolute.raw()) }, 0);

    let control = |raw| {
        let mut control = 0_u16;
        let mut revision = 0_u32;
        assert_ne!(
            unsafe { GetSecurityDescriptorControl(raw, &raw mut control, &raw mut revision) },
            0
        );
        (control, revision)
    };
    let (source_control, source_revision) = control(descriptor.raw());
    let (absolute_control, absolute_revision) = control(absolute.raw());
    assert_eq!(source_revision, 1);
    assert_eq!(absolute_revision, source_revision);
    assert_ne!(source_control & SE_SELF_RELATIVE, 0);
    assert_eq!(absolute_control & SE_SELF_RELATIVE, 0);
    assert_eq!(
        absolute_control & !SE_SELF_RELATIVE,
        source_control & !SE_SELF_RELATIVE
    );
    for control in [source_control, absolute_control] {
        assert_ne!(control & SE_SACL_PRESENT_CONTROL, 0);
        assert_ne!(control & SE_SACL_PROTECTED_CONTROL, 0);
        assert_eq!(control & SE_SACL_AUTO_INHERIT_REQ_CONTROL, 0);
        assert_eq!(control & SE_SACL_AUTO_INHERITED_CONTROL, 0);
    }

    let identities = |raw| {
        let mut owner: *mut c_void = ptr::null_mut();
        let mut owner_defaulted = 1_i32;
        assert_ne!(
            unsafe { GetSecurityDescriptorOwner(raw, &raw mut owner, &raw mut owner_defaulted) },
            0
        );
        assert!(!owner.is_null());
        assert_ne!(unsafe { IsValidSid(owner) }, 0);
        assert_eq!(owner_defaulted, 0);

        let mut group: *mut c_void = ptr::null_mut();
        let mut group_defaulted = 1_i32;
        assert_ne!(
            unsafe { GetSecurityDescriptorGroup(raw, &raw mut group, &raw mut group_defaulted) },
            0
        );
        assert!(!group.is_null());
        assert_ne!(unsafe { IsValidSid(group) }, 0);
        assert_eq!(group_defaulted, 0);
        (owner, group)
    };
    let (source_owner, source_group) = identities(descriptor.raw());
    let (absolute_owner, absolute_group) = identities(absolute.raw());
    assert_ne!(unsafe { EqualSid(source_owner, absolute_owner) }, 0);
    assert_ne!(unsafe { EqualSid(source_group, absolute_group) }, 0);

    let error = normalized_descriptor_sddl(
        absolute.raw(),
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        SecurityObjectKind::WindowStation,
    )
    .unwrap_err();
    assert!(error.contains("absolute security descriptor"));
}

#[test]
fn protected_mandatory_label_is_selected_and_preserved_for_user_object_creation() {
    let descriptor =
        SecurityDescriptor::from_sddl("O:SYG:SYD:P(A;;GA;;;SY)S:P(ML;;NW;;;HI)").unwrap();
    assert!(descriptor.applies_mandatory_label());
    let absolute = descriptor.absolute_for_user_object_creation().unwrap();

    let control = |raw| {
        let mut control = 0_u16;
        let mut revision = 0_u32;
        assert_ne!(
            unsafe { GetSecurityDescriptorControl(raw, &raw mut control, &raw mut revision) },
            0
        );
        assert_eq!(revision, 1);
        control
    };
    let source_control = control(descriptor.raw());
    let absolute_control = control(absolute.raw());
    for control in [source_control, absolute_control] {
        assert_ne!(control & SE_SACL_PRESENT_CONTROL, 0);
        assert_ne!(control & SE_SACL_PROTECTED_CONTROL, 0);
        assert_eq!(control & SE_SACL_AUTO_INHERIT_REQ_CONTROL, 0);
        assert_eq!(control & SE_SACL_AUTO_INHERITED_CONTROL, 0);
    }
    assert_eq!(
        absolute_control & !SE_SELF_RELATIVE,
        source_control & !SE_SELF_RELATIVE
    );
}

#[test]
fn user_object_creation_rejects_unprotected_or_auto_inherited_mandatory_label_sacls() {
    for sddl in [
        "O:SYG:SYD:P(A;;GA;;;SY)S:(ML;;NW;;;HI)",
        "O:SYG:SYD:P(A;;GA;;;SY)S:PAR(ML;;NW;;;HI)",
        "O:SYG:SYD:P(A;;GA;;;SY)S:PAI(ML;;NW;;;HI)",
    ] {
        let descriptor = SecurityDescriptor::from_sddl(sddl).unwrap();
        assert!(descriptor.applies_mandatory_label());
        let error = descriptor
            .absolute_for_user_object_creation()
            .err()
            .unwrap();
        assert!(error.contains("unprotected or auto-inherited mandatory-label SACL"));
    }
}

#[test]
fn desktop_resultant_sacl_auto_inherited_is_the_only_user_object_exception() {
    let expected = "O:SYG:SYD:P(A;;GA;;;SY)(A;;GR;;;BA)S:P(ML;;NW;;;HI)";
    let exact = expected;
    let provider_result = "O:SYG:SYD:P(A;;GA;;;SY)(A;;GR;;;BA)S:PAI(ML;;NW;;;HI)";

    compare_user_object_security_sddl_for_test(expected, exact, SecurityObjectKind::Desktop)
        .unwrap();
    compare_user_object_security_sddl_for_test(
        expected,
        provider_result,
        SecurityObjectKind::Desktop,
    )
    .unwrap();

    assert!(
        compare_user_object_security_sddl_for_test(
            expected,
            provider_result,
            SecurityObjectKind::WindowStation,
        )
        .is_err(),
        "window-station readback must not inherit the desktop provider exception"
    );
    compare_user_object_security_sddl_for_test(expected, exact, SecurityObjectKind::WindowStation)
        .unwrap();

    for drift in [
        // The resultant exception requires protected SACL state, no request,
        // and exactly one differing control bit.
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GR;;;BA)S:AI(ML;;NW;;;HI)",
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GR;;;BA)S:PARAI(ML;;NW;;;HI)",
        "O:SYG:SYD:PAI(A;;GA;;;SY)(A;;GR;;;BA)S:PAI(ML;;NW;;;HI)",
        // Mandatory-label type, provenance/scope, mask, and SID remain exact.
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GR;;;BA)S:PAI(ML;ID;NW;;;HI)",
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GR;;;BA)S:PAI(ML;OI;NW;;;HI)",
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GR;;;BA)S:PAI(ML;CI;NW;;;HI)",
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GR;;;BA)S:PAI(ML;OINP;NW;;;HI)",
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GR;;;BA)S:PAI(ML;IO;NW;;;HI)",
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GR;;;BA)",
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GR;;;BA)S:PAI(AU;SA;GA;;;SY)",
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GR;;;BA)S:PAI(ML;;NW;;;HI)(ML;;NW;;;HI)",
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GR;;;BA)S:PAI(ML;;;;;HI)",
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GR;;;BA)S:PAI(ML;;NR;;;HI)",
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GR;;;BA)S:PAI(ML;;NX;;;HI)",
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GR;;;BA)S:PAI(ML;;NWNR;;;HI)",
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GR;;;BA)S:PAI(ML;;NW;;;ME)",
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GR;;;BA)S:PAI(ML;;NW;;;LW)",
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GR;;;BA)S:PAI(ML;;NW;;;SI)",
        // Owner, group, DACL controls, ordering, flags, masks, and trustees
        // are still compared exactly after the established generic mapping.
        "O:BAG:SYD:P(A;;GA;;;SY)(A;;GR;;;BA)S:PAI(ML;;NW;;;HI)",
        "O:SYG:BAD:P(A;;GA;;;SY)(A;;GR;;;BA)S:PAI(ML;;NW;;;HI)",
        "O:SYG:SYD:(A;;GA;;;SY)(A;;GR;;;BA)S:PAI(ML;;NW;;;HI)",
        "O:SYG:SYD:PAR(A;;GA;;;SY)(A;;GR;;;BA)S:PAI(ML;;NW;;;HI)",
        "O:SYG:SYD:PAI(A;;GA;;;SY)(A;;GR;;;BA)S:PAI(ML;;NW;;;HI)",
        "O:SYG:SYD:P(A;;GA;;;SY)S:PAI(ML;;NW;;;HI)",
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GR;;;BA)(A;;GR;;;BU)S:PAI(ML;;NW;;;HI)",
        "O:SYG:SYD:P(A;;GR;;;BA)(A;;GA;;;SY)S:PAI(ML;;NW;;;HI)",
        "O:SYG:SYD:P(D;;GA;;;SY)(A;;GR;;;BA)S:PAI(ML;;NW;;;HI)",
        "O:SYG:SYD:P(A;OI;GA;;;SY)(A;;GR;;;BA)S:PAI(ML;;NW;;;HI)",
        "O:SYG:SYD:P(A;ID;GA;;;SY)(A;;GR;;;BA)S:PAI(ML;;NW;;;HI)",
        "O:SYG:SYD:P(A;;GW;;;SY)(A;;GR;;;BA)S:PAI(ML;;NW;;;HI)",
        "O:SYG:SYD:P(A;;GA;;;BA)(A;;GR;;;SY)S:PAI(ML;;NW;;;HI)",
    ] {
        assert!(
            compare_user_object_security_sddl_for_test(
                expected,
                drift,
                SecurityObjectKind::Desktop,
            )
            .is_err(),
            "unexpectedly accepted resultant desktop security drift: {drift}"
        );
    }

    assert!(
        compare_user_object_security_sddl_for_test(
            provider_result,
            provider_result,
            SecurityObjectKind::Desktop,
        )
        .is_err(),
        "creator-side SACL AI must remain invalid even when readback is identical"
    );
}

#[test]
fn target_user_object_policy_fingerprint_is_canonical_and_label_bound() {
    let symbolic = "O:SYG:SYD:P(A;;GA;;;SY)S:P(ML;;NW;;;HI)";
    let numeric = "O:S-1-5-18G:S-1-5-18D:P(A;;0x000f016f;;;S-1-5-18)S:P(ML;;NW;;;S-1-16-12288)";
    let symbolic_fingerprint =
        user_object_policy_fingerprint_for_test(symbolic, SecurityObjectKind::WindowStation)
            .unwrap();
    let numeric_fingerprint =
        user_object_policy_fingerprint_for_test(numeric, SecurityObjectKind::WindowStation)
            .unwrap();
    assert_eq!(symbolic_fingerprint, numeric_fingerprint);
    assert_ne!(
        numeric_fingerprint,
        crate::windows::record::digest(numeric.as_bytes()),
        "policy evidence must hash the parsed canonical projection, not raw input SDDL"
    );

    let medium_label = symbolic.replace(";;;HI)", ";;;ME)");
    assert_ne!(
        symbolic_fingerprint,
        user_object_policy_fingerprint_for_test(&medium_label, SecurityObjectKind::WindowStation,)
            .unwrap(),
        "mandatory-label drift must change the full policy fingerprint"
    );
    assert!(
        user_object_policy_fingerprint_for_test(
            "O:SYG:SYD:P(A;;GA;;;SY)",
            SecurityObjectKind::WindowStation,
        )
        .is_err(),
        "the policy fingerprint contract must require O/G/D/LABEL"
    );
}

#[test]
fn target_user_object_resultant_fingerprint_keeps_the_desktop_exception_narrow() {
    let expected = "O:SYG:SYD:P(A;;GA;;;SY)(A;;GR;;;BA)S:P(ML;;NW;;;HI)";
    let provider_result = "O:SYG:SYD:P(A;;GA;;;SY)(A;;GR;;;BA)S:PAI(ML;;NW;;;HI)";
    let expected_desktop =
        user_object_policy_fingerprint_for_test(expected, SecurityObjectKind::Desktop).unwrap();
    assert_eq!(
        expected_desktop,
        user_object_resultant_fingerprint_for_test(
            expected,
            provider_result,
            SecurityObjectKind::Desktop,
        )
        .unwrap()
    );

    let expected_station =
        user_object_policy_fingerprint_for_test(expected, SecurityObjectKind::WindowStation)
            .unwrap();
    assert_ne!(
        expected_station,
        user_object_resultant_fingerprint_for_test(
            expected,
            provider_result,
            SecurityObjectKind::WindowStation,
        )
        .unwrap(),
        "window stations must not inherit the desktop SACL-AI exception"
    );
}

#[test]
fn user_object_absolute_conversion_rejects_a_missing_primary_group() {
    let descriptor = SecurityDescriptor::from_sddl("O:SYD:P(A;;GA;;;SY)").unwrap();
    let error = descriptor
        .absolute_for_user_object_creation()
        .err()
        .unwrap();
    assert!(error.contains("missing required owner, group, or DACL"));
}

#[test]
fn target_private_user_object_access_checks_distinguish_station_and_desktop() {
    let tokens = [
        crate::windows::token::restricted_current_primary().unwrap(),
        crate::windows::token::write_restricted_current_primary().unwrap(),
    ];
    for token in &tokens {
        let station_sddl = target_window_station_sddl(token.raw()).unwrap();
        let station = SecurityDescriptor::from_sddl(&station_sddl).unwrap();
        assert_eq!(
            station
                .private_window_station_access_check(token.raw())
                .unwrap(),
            (true, TARGET_PRIVATE_WINDOW_STATION_ACCESS)
        );
        for required in [
            0x1,
            0x2,
            0x4,
            0x8,
            0x20,
            0x40,
            0x100,
            0x0001_0000,
            0x0002_0000,
            0x0004_0000,
            0x0008_0000,
        ] {
            let (allowed, granted) = station
                .private_window_station_access_check_for_test(token.raw(), required)
                .unwrap();
            assert!(
                allowed,
                "required private WindowStation bit {required:#010x} denied"
            );
            assert_eq!(granted & required, required);
        }
        for forbidden in [0x10, 0x200] {
            let (allowed, granted) = station
                .private_window_station_access_check_for_test(token.raw(), forbidden)
                .unwrap();
            assert!(
                !allowed,
                "unneeded private WindowStation bit {forbidden:#010x} was granted"
            );
            assert_eq!(granted & forbidden, 0);
        }

        let desktop_sddl = target_desktop_sddl(token.raw()).unwrap();
        let desktop = SecurityDescriptor::from_sddl(&desktop_sddl).unwrap();
        assert_eq!(
            desktop.private_desktop_access_check(token.raw()).unwrap(),
            (true, TARGET_PRIVATE_DESKTOP_ACCESS)
        );
        for required in [
            0x1,
            0x2,
            0x4,
            0x8,
            0x10,
            0x20,
            0x40,
            0x80,
            0x100,
            0x0001_0000,
            0x0002_0000,
            0x0004_0000,
            0x0008_0000,
        ] {
            let (allowed, granted) = desktop
                .private_desktop_access_check_for_test(token.raw(), required)
                .unwrap();
            assert!(
                allowed,
                "required private Desktop bit {required:#010x} denied"
            );
            assert_eq!(granted & required, required);
        }
        assert!(
            !station.private_desktop_access_check(token.raw()).unwrap().0,
            "window-station policy unexpectedly satisfied desktop authority"
        );
    }

    let token = &tokens[1];
    let station_sddl = target_window_station_sddl(token.raw()).unwrap();
    let logon_sid = crate::windows::token::token_logon_sid(token.raw()).unwrap();
    for missing_ace in [
        format!(
            "(A;;0x{TARGET_PRIVATE_WINDOW_STATION_ACCESS:08x};;;{})",
            logon_sid
        ),
        format!("(A;;0x{TARGET_PRIVATE_WINDOW_STATION_ACCESS:08x};;;S-1-5-33)"),
    ] {
        let descriptor =
            SecurityDescriptor::from_sddl(&station_sddl.replacen(&missing_ace, "", 1)).unwrap();
        assert!(
            !descriptor
                .private_window_station_access_check(token.raw())
                .unwrap()
                .0,
            "station authority survived required trustee removal"
        );
    }

    let desktop_sddl = target_desktop_sddl(token.raw()).unwrap();
    for missing_ace in [
        format!("(A;;0x{TARGET_PRIVATE_DESKTOP_ACCESS:08x};;;{})", logon_sid),
        format!("(A;;0x{TARGET_PRIVATE_DESKTOP_ACCESS:08x};;;S-1-5-33)"),
    ] {
        let descriptor =
            SecurityDescriptor::from_sddl(&desktop_sddl.replacen(&missing_ace, "", 1)).unwrap();
        assert!(
            !descriptor
                .private_desktop_access_check(token.raw())
                .unwrap()
                .0,
            "desktop authority survived required trustee removal"
        );
    }

    let missing_group =
        SecurityDescriptor::from_sddl(&station_sddl.replacen("G:SY", "", 1)).unwrap();
    let shape_error = missing_group
        .access_check_descriptor_shape_for_test()
        .unwrap_err();
    assert!(
        shape_error.contains("MCSEALED-WINDOWS-LIVE-ACCESS-CHECK: stage=descriptor-shape"),
        "unexpected typed shape stage: {shape_error}"
    );
    assert!(
        shape_error.contains("api=GetSecurityDescriptorGroup")
            && shape_error.contains("group_present=false"),
        "missing group was not partitioned before AccessCheck: {shape_error}"
    );
    let error = missing_group
        .private_window_station_access_check(token.raw())
        .unwrap_err();
    assert!(error.contains("1338"), "unexpected error: {error}");
}

#[test]
fn private_desktop_access_check_requires_a_duplicable_primary_token() {
    let query_only = crate::windows::token::current_process_token_for_access_check().unwrap();
    let nonduplicable = crate::windows::token::current_process_token_for_attestation().unwrap();
    let duplicable =
        crate::windows::token::current_process_token_for_attestation_and_access_check().unwrap();
    let descriptors = [
        (
            SecurityDescriptor::from_sddl(&target_window_station_sddl(duplicable.raw()).unwrap())
                .unwrap(),
            SecurityObjectKind::WindowStation,
        ),
        (
            SecurityDescriptor::from_sddl(&target_desktop_sddl(duplicable.raw()).unwrap()).unwrap(),
            SecurityObjectKind::Desktop,
        ),
    ];
    for (descriptor, kind) in &descriptors {
        let error = match kind {
            SecurityObjectKind::WindowStation => descriptor
                .private_window_station_access_check(nonduplicable.raw())
                .unwrap_err(),
            SecurityObjectKind::Desktop => descriptor
                .private_desktop_access_check(nonduplicable.raw())
                .unwrap_err(),
            _ => unreachable!(),
        };
        assert!(
            error.contains("duplicate primary token for AccessCheck"),
            "unexpected failure stage: {error}"
        );
        assert!(
            error.contains(&format!("native_code=Some({ERROR_ACCESS_DENIED})")),
            "missing native error code: {error}"
        );
    }

    let source_error = target_window_station_sddl(query_only.raw()).unwrap_err();
    assert!(
        source_error.contains("information_class=7"),
        "query-only token did not fail at TokenSource: {source_error}"
    );

    assert_eq!(
        descriptors[0]
            .0
            .private_window_station_access_check(duplicable.raw())
            .unwrap(),
        (true, TARGET_PRIVATE_WINDOW_STATION_ACCESS)
    );
    assert_eq!(
        descriptors[1]
            .0
            .private_desktop_access_check(duplicable.raw())
            .unwrap(),
        (true, TARGET_PRIVATE_DESKTOP_ACCESS)
    );
}

#[test]
fn write_restricted_behavior_attestation_requires_a_duplicable_primary_token() {
    let query_only = crate::windows::token::process_token(unsafe { GetCurrentProcess() }).unwrap();
    let error =
        crate::windows::security::write_restricted_behavior_attested(query_only.raw()).unwrap_err();
    assert!(
        error.contains("write-restricted S-1-5-33 oracle user-only/read"),
        "unexpected oracle stage: {error}"
    );
    assert!(
        error.contains("duplicate primary token for AccessCheck"),
        "unexpected failure stage: {error}"
    );
    assert!(
        error.contains(&format!("native_code=Some({ERROR_ACCESS_DENIED})")),
        "missing native error code: {error}"
    );

    let duplicable = crate::windows::token::current_process_token_for_access_check().unwrap();
    crate::windows::security::write_restricted_behavior_attested(duplicable.raw()).unwrap();
}

#[test]
fn generic_masks_match_each_object_types_current_native_mapping() {
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_EXECUTE: u32 = 0x2000_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;

    for (kind, read, write, execute, all) in [
        (
            SecurityObjectKind::File,
            0x0012_0089,
            0x0012_0116,
            0x0012_00a0,
            0x001f_01ff,
        ),
        (
            SecurityObjectKind::NamedPipe,
            0x0012_0089,
            0x0012_0116,
            0x0012_00a0,
            0x001f_01ff,
        ),
        (
            SecurityObjectKind::Mutex,
            0x0012_0000,
            0x0002_0001,
            0x0012_0000,
            0x001f_0001,
        ),
        (
            SecurityObjectKind::Job,
            0x0002_0004,
            0x0002_000b,
            0x0012_0000,
            0x001f_003f,
        ),
        (
            SecurityObjectKind::Process,
            0x0002_0410,
            0x0002_03ea,
            0x0012_0000,
            0x001f_ffff,
        ),
        (
            SecurityObjectKind::Thread,
            0x0002_0048,
            0x0002_00b0,
            0x0012_1800,
            0x001f_ffff,
        ),
        (
            SecurityObjectKind::Token,
            0x0002_0008,
            0x0002_00e0,
            0x0002_0000,
            0x000f_01ff,
        ),
        (
            SecurityObjectKind::Service,
            0x0002_008d,
            0x0002_0002,
            0x0002_0170,
            0x000f_01ff,
        ),
        (
            SecurityObjectKind::WindowStation,
            0x0002_0103,
            0x0002_000c,
            0x0002_0060,
            0x000f_016f,
        ),
        (
            SecurityObjectKind::Desktop,
            0x0002_0041,
            0x0002_00be,
            0x0002_0100,
            0x000f_01ff,
        ),
    ] {
        assert_eq!(normalized_access_mask(kind, GENERIC_READ), read);
        assert_eq!(normalized_access_mask(kind, GENERIC_WRITE), write);
        assert_eq!(normalized_access_mask(kind, GENERIC_EXECUTE), execute);
        assert_eq!(normalized_access_mask(kind, GENERIC_ALL), all);
    }

    assert_eq!(
        normalized_access_mask(SecurityObjectKind::Mutex, 0x001f_0001),
        0x001f_0001
    );
    assert_eq!(
        normalized_access_mask(SecurityObjectKind::WindowStation, GENERIC_ALL) & 0x0000_0210,
        0
    );
}

unsafe extern "system" fn holder_thread_capability_worker(parameter: *mut c_void) -> u32 {
    // SAFETY: parameter is the live manual-reset event retained by the test
    // owner until this worker exits.
    unsafe { WaitForSingleObject(parameter.cast(), 30_000) };
    0
}

struct ControlledThreadCleanup {
    event: HANDLE,
    thread: HANDLE,
    completed: bool,
}

struct CarrierWorkerContext {
    release_revert: HANDLE,
    reverted: HANDLE,
    finish: HANDLE,
    revert_succeeded: AtomicBool,
}

unsafe extern "system" fn carrier_thread_capability_worker(parameter: *mut c_void) -> u32 {
    // SAFETY: parameter points to the boxed context retained by the cleanup
    // guard until this worker exits, and all three events remain live.
    let context = unsafe { &*(parameter.cast::<CarrierWorkerContext>()) };
    unsafe { WaitForSingleObject(context.release_revert, 30_000) };
    // SAFETY: the test attaches the private carrier before releasing this
    // worker; reversion affects only the current controlled worker thread.
    let reverted = unsafe { RevertToSelf() } != 0;
    context.revert_succeeded.store(reverted, Ordering::Release);
    unsafe {
        SetEvent(context.reverted);
        WaitForSingleObject(context.finish, 30_000);
    }
    u32::from(!reverted)
}

struct CarrierWorkerCleanup {
    context: Box<CarrierWorkerContext>,
    thread: HANDLE,
    completed: bool,
}

impl Drop for CarrierWorkerCleanup {
    fn drop(&mut self) {
        // SAFETY: the guard exclusively owns the thread and event handles.
        // Releasing every gate lets any partially progressed worker converge.
        unsafe {
            if !self.completed {
                SetEvent(self.context.release_revert);
                SetEvent(self.context.finish);
                ResumeThread(self.thread);
                let _ = WaitForSingleObject(self.thread, 5_000);
            }
            CloseHandle(self.thread);
            CloseHandle(self.context.release_revert);
            CloseHandle(self.context.reverted);
            CloseHandle(self.context.finish);
        }
    }
}

impl Drop for ControlledThreadCleanup {
    fn drop(&mut self) {
        // SAFETY: this guard exclusively owns both live handles. Signalling
        // before resuming lets either a suspended or already-running worker
        // converge without leaking past the test.
        unsafe {
            if !self.completed {
                SetEvent(self.event);
                ResumeThread(self.thread);
                let _ = WaitForSingleObject(self.thread, 5_000);
            }
            CloseHandle(self.thread);
            CloseHandle(self.event);
        }
    }
}

#[test]
fn holder_primary_thread_resume_capability_is_exact_and_cannot_suspend() {
    // SAFETY: null security creates a private, noninheritable unnamed event.
    let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    assert!(
        !event.is_null(),
        "CreateEventW failed: {}",
        std::io::Error::last_os_error()
    );
    let mut thread_id = 0_u32;
    // SAFETY: the fixed worker entry and event parameter remain valid until
    // the controlled worker has exited and the cleanup guard closes them.
    let thread = unsafe {
        CreateThread(
            ptr::null(),
            0,
            Some(holder_thread_capability_worker),
            event.cast(),
            CREATE_SUSPENDED,
            &raw mut thread_id,
        )
    };
    if thread.is_null() {
        unsafe { CloseHandle(event) };
        panic!("CreateThread failed: {}", std::io::Error::last_os_error());
    }
    let mut cleanup = ControlledThreadCleanup {
        event,
        thread,
        completed: false,
    };
    assert_ne!(thread_id, 0);

    let exact_access = THREAD_QUERY_LIMITED_INFORMATION | THREAD_RESUME;
    assert_eq!(exact_access, 0x0000_1800);
    // SAFETY: thread_id names the suspended live worker and inheritance is
    // explicitly disabled. The current process satisfies its default DACL.
    let narrow = unsafe { OpenThread(exact_access, 0, thread_id) };
    assert!(
        !narrow.is_null(),
        "OpenThread failed: {}",
        std::io::Error::last_os_error()
    );
    let narrow = crate::windows::pipe::OwnedHandle::new(narrow).unwrap();
    let mut flags = 0_u32;
    assert_ne!(
        unsafe { GetHandleInformation(narrow.raw(), &raw mut flags) },
        0
    );
    assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
    assert_eq!(
        crate::windows::token::granted_handle_access(narrow.raw()).unwrap(),
        exact_access
    );
    assert_eq!(unsafe { GetProcessIdOfThread(narrow.raw()) }, unsafe {
        GetCurrentProcessId()
    });
    assert_eq!(unsafe { ResumeThread(narrow.raw()) }, 1);

    unsafe { SetLastError(0) };
    let suspend = unsafe { SuspendThread(narrow.raw()) };
    if suspend != u32::MAX {
        // SAFETY: the full creator handle repairs an unexpected suspension so
        // the worker can still terminate before the assertion unwinds.
        unsafe { ResumeThread(thread) };
    }
    assert_eq!(suspend, u32::MAX);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(ERROR_ACCESS_DENIED as i32)
    );

    assert_ne!(unsafe { SetEvent(event) }, 0);
    assert_eq!(unsafe { WaitForSingleObject(thread, 5_000) }, WAIT_OBJECT_0);
    cleanup.completed = true;
}

#[test]
fn holder_thread_broker_arm_request_has_exact_canonical_native_grant() {
    // SAFETY: null security creates private, noninheritable unnamed events.
    let release_revert = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    let reverted = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    let finish = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    if release_revert.is_null() || reverted.is_null() || finish.is_null() {
        unsafe {
            if !release_revert.is_null() {
                CloseHandle(release_revert);
            }
            if !reverted.is_null() {
                CloseHandle(reverted);
            }
            if !finish.is_null() {
                CloseHandle(finish);
            }
        }
        panic!("CreateEventW failed: {}", std::io::Error::last_os_error());
    }
    let mut context = Box::new(CarrierWorkerContext {
        release_revert,
        reverted,
        finish,
        revert_succeeded: AtomicBool::new(false),
    });
    let mut thread_id = 0_u32;
    // SAFETY: the fixed worker entry and event parameter remain valid until
    // the controlled worker has exited and the cleanup guard closes them.
    let thread = unsafe {
        CreateThread(
            ptr::null(),
            0,
            Some(carrier_thread_capability_worker),
            (&raw mut *context).cast(),
            CREATE_SUSPENDED,
            &raw mut thread_id,
        )
    };
    if thread.is_null() {
        unsafe {
            CloseHandle(context.release_revert);
            CloseHandle(context.reverted);
            CloseHandle(context.finish);
        }
        panic!("CreateThread failed: {}", std::io::Error::last_os_error());
    }
    let mut cleanup = CarrierWorkerCleanup {
        context,
        thread,
        completed: false,
    };

    let requested = crate::windows::session_broker::HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS;
    let expected_granted = crate::windows::session_broker::HOLDER_THREAD_BROKER_ARM_GRANTED_ACCESS;
    assert_eq!(
        requested,
        THREAD_QUERY_INFORMATION | THREAD_SET_THREAD_TOKEN
    );
    assert_eq!(requested, 0x0000_00c0);
    assert_eq!(
        expected_granted,
        requested | THREAD_QUERY_LIMITED_INFORMATION
    );
    assert_eq!(expected_granted, 0x0000_08c0);

    let process = unsafe { GetCurrentProcess() };
    let mut duplicate = ptr::null_mut();
    // SAFETY: the controlled thread and pseudo-process handles are live;
    // inheritance is explicitly disabled and requested is the broker mask.
    assert_ne!(
        unsafe {
            DuplicateHandle(
                process,
                thread,
                process,
                &raw mut duplicate,
                requested,
                0,
                0,
            )
        },
        0,
        "DuplicateHandle failed: {}",
        std::io::Error::last_os_error()
    );
    let duplicate = crate::windows::pipe::OwnedHandle::new(duplicate).unwrap();

    // SAFETY: thread_id names the controlled live worker and inheritance is
    // explicitly disabled. The current process satisfies its default DACL.
    let opened = unsafe { OpenThread(requested, 0, thread_id) };
    assert!(
        !opened.is_null(),
        "OpenThread failed: {}",
        std::io::Error::last_os_error()
    );
    let opened = crate::windows::pipe::OwnedHandle::new(opened).unwrap();

    for capability in [&duplicate, &opened] {
        let mut flags = 0_u32;
        assert_ne!(
            unsafe { GetHandleInformation(capability.raw(), &raw mut flags) },
            0
        );
        assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
        let actual = crate::windows::token::granted_handle_access(capability.raw()).unwrap();
        assert_eq!(actual, expected_granted);
        assert_eq!(
            actual
                & (THREAD_RESUME
                    | THREAD_SUSPEND_RESUME
                    | 0x0010_0000
                    | 0x0000_0001
                    | 0x0000_0008
                    | 0x0000_0010
                    | 0x0000_0020
                    | 0x0000_0100
                    | 0x0004_0000
                    | 0x0008_0000
                    | 0x1000_0000),
            0
        );
        assert_eq!(unsafe { GetProcessIdOfThread(capability.raw()) }, unsafe {
            GetCurrentProcessId()
        });

        let mut token = ptr::null_mut();
        unsafe { SetLastError(0) };
        assert_eq!(
            unsafe { OpenThreadToken(capability.raw(), TOKEN_QUERY, 0, &raw mut token) },
            0
        );
        assert!(token.is_null());
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(ERROR_NO_TOKEN as i32)
        );
    }

    let source = crate::windows::token::restricted_current_primary().unwrap();
    let mut carrier = ptr::null_mut();
    // SAFETY: source is a live primary token and carrier receives a private
    // impersonation token retained until worker reversion is proven.
    assert_ne!(
        unsafe {
            DuplicateTokenEx(
                source.raw(),
                TOKEN_ALL_ACCESS,
                ptr::null(),
                SecurityImpersonation,
                TokenImpersonation,
                &raw mut carrier,
            )
        },
        0
    );
    let carrier = crate::windows::pipe::OwnedHandle::new(carrier).unwrap();
    let requested_carrier =
        crate::windows::token::token_attestation_snapshot(carrier.raw()).unwrap();
    let mut arm_thread = duplicate.raw();
    // SAFETY: arm_thread carries SET_THREAD_TOKEN, carrier is a live private
    // impersonation token, and the pointer is writable for the duration.
    assert_ne!(
        unsafe { SetThreadToken(&raw mut arm_thread, carrier.raw()) },
        0,
        "SetThreadToken failed: {}",
        std::io::Error::last_os_error()
    );
    let mut observed = ptr::null_mut();
    assert_ne!(
        unsafe {
            OpenThreadToken(
                opened.raw(),
                TOKEN_QUERY | TOKEN_QUERY_SOURCE,
                1,
                &raw mut observed,
            )
        },
        0,
        "OpenThreadToken after attach failed: {}",
        std::io::Error::last_os_error()
    );
    let observed = crate::windows::pipe::OwnedHandle::new(observed).unwrap();
    let observed_carrier =
        crate::windows::token::token_attestation_snapshot(observed.raw()).unwrap();
    crate::windows::token::require_same_token_instance(
        "broker-arm-native-regression",
        &requested_carrier,
        &observed_carrier,
    )
    .unwrap();

    assert_ne!(unsafe { SetEvent(cleanup.context.release_revert) }, 0);
    assert_eq!(unsafe { ResumeThread(thread) }, 1);
    assert_eq!(
        unsafe { WaitForSingleObject(cleanup.context.reverted, 5_000) },
        WAIT_OBJECT_0
    );
    assert!(cleanup.context.revert_succeeded.load(Ordering::Acquire));
    let mut absent = ptr::null_mut();
    unsafe { SetLastError(0) };
    assert_eq!(
        unsafe {
            OpenThreadToken(
                opened.raw(),
                TOKEN_QUERY | TOKEN_QUERY_SOURCE,
                1,
                &raw mut absent,
            )
        },
        0
    );
    assert!(absent.is_null());
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(ERROR_NO_TOKEN as i32)
    );

    let limited_request = THREAD_QUERY_LIMITED_INFORMATION | THREAD_SET_THREAD_TOKEN;
    let limited = unsafe { OpenThread(limited_request, 0, thread_id) };
    assert!(
        !limited.is_null(),
        "limited OpenThread failed: {}",
        std::io::Error::last_os_error()
    );
    let limited = crate::windows::pipe::OwnedHandle::new(limited).unwrap();
    let mut limited_thread = limited.raw();
    assert_ne!(
        unsafe { SetThreadToken(&raw mut limited_thread, carrier.raw()) },
        0
    );
    let mut limited_observation = ptr::null_mut();
    unsafe { SetLastError(0) };
    if unsafe {
        OpenThreadToken(
            limited.raw(),
            TOKEN_QUERY | TOKEN_QUERY_SOURCE,
            1,
            &raw mut limited_observation,
        )
    } != 0
    {
        drop(crate::windows::pipe::OwnedHandle::new(limited_observation).unwrap());
    } else {
        assert!(limited_observation.is_null());
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(ERROR_ACCESS_DENIED as i32)
        );
    }
    let mut clear_thread = opened.raw();
    assert_ne!(
        unsafe { SetThreadToken(&raw mut clear_thread, ptr::null_mut()) },
        0
    );

    assert_ne!(unsafe { SetEvent(cleanup.context.finish) }, 0);
    assert_eq!(unsafe { WaitForSingleObject(thread, 5_000) }, WAIT_OBJECT_0);
    cleanup.completed = true;
}

#[test]
fn legacy_suspend_query_request_expands_to_resume_and_suspend() {
    // SAFETY: null security creates a private, noninheritable unnamed event.
    let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    assert!(
        !event.is_null(),
        "CreateEventW failed: {}",
        std::io::Error::last_os_error()
    );
    let mut thread_id = 0_u32;
    let thread = unsafe {
        CreateThread(
            ptr::null(),
            0,
            Some(holder_thread_capability_worker),
            event.cast(),
            CREATE_SUSPENDED,
            &raw mut thread_id,
        )
    };
    if thread.is_null() {
        unsafe { CloseHandle(event) };
        panic!("CreateThread failed: {}", std::io::Error::last_os_error());
    }
    let mut cleanup = ControlledThreadCleanup {
        event,
        thread,
        completed: false,
    };
    let legacy_access = THREAD_QUERY_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME;
    assert_eq!(legacy_access, 0x0000_0802);
    let mut legacy = ptr::null_mut();
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: all handles and output are live; desired access is deliberately
    // the legacy mask whose native expansion this regression documents.
    assert_ne!(
        unsafe {
            DuplicateHandle(
                process,
                thread,
                process,
                &raw mut legacy,
                legacy_access,
                0,
                0,
            )
        },
        0
    );
    let legacy = crate::windows::pipe::OwnedHandle::new(legacy).unwrap();
    assert_eq!(
        crate::windows::token::granted_handle_access(legacy.raw()).unwrap(),
        legacy_access | THREAD_RESUME
    );
    assert_eq!(legacy_access | THREAD_RESUME, 0x0000_1802);

    assert_ne!(unsafe { SetEvent(event) }, 0);
    assert_eq!(unsafe { ResumeThread(thread) }, 1);
    assert_eq!(unsafe { WaitForSingleObject(thread, 5_000) }, WAIT_OBJECT_0);
    cleanup.completed = true;
}

#[test]
fn job_readback_expands_generic_all_to_the_complete_native_mask() {
    let expected = SecurityDescriptor::from_sddl("D:P(A;;GA;;;SY)(A;;GA;;;BA)").unwrap();
    let attributes = expected.attributes(false);
    // SAFETY: attributes and its descriptor remain live; null creates an
    // unnamed job owned only through the returned handle.
    let job = unsafe { CreateJobObjectW(&raw const attributes, ptr::null()) };
    assert!(!job.is_null(), "CreateJobObjectW failed");

    assert!(
        expected
            .verify_kernel_object(job, SecurityObjectKind::Job)
            .is_ok()
    );
    let missing_impersonate =
        SecurityDescriptor::from_sddl("D:P(A;;0x001f001f;;;SY)(A;;GA;;;BA)").unwrap();
    assert!(
        missing_impersonate
            .verify_kernel_object(job, SecurityObjectKind::Job)
            .is_err()
    );

    // SAFETY: job is the live handle returned above and is closed once.
    unsafe { CloseHandle(job) };
}

#[test]
fn production_job_policy_round_trips_through_the_native_object() {
    let policy = launcher_job_sddl().unwrap();
    let expected = SecurityDescriptor::from_sddl(policy.strip_prefix("O:SY").unwrap()).unwrap();
    let attributes = expected.attributes(false);
    // SAFETY: attributes and its descriptor remain live; null creates an
    // unnamed job owned only through the returned handle.
    let job = unsafe { CreateJobObjectW(&raw const attributes, ptr::null()) };
    assert!(!job.is_null(), "CreateJobObjectW failed");

    assert!(
        expected
            .verify_kernel_object(job, SecurityObjectKind::Job)
            .is_ok()
    );

    // SAFETY: job is the live handle returned above and is closed once.
    unsafe { CloseHandle(job) };
}

#[test]
fn nested_job_policy_round_trips_through_the_native_object() {
    let expected = SecurityDescriptor::from_sddl(&nested_canary_job_sddl().unwrap()).unwrap();
    let attributes = expected.attributes(false);
    // SAFETY: attributes and its descriptor remain live; null creates an
    // unnamed job owned only through the returned handle.
    let job = unsafe { CreateJobObjectW(&raw const attributes, ptr::null()) };
    assert!(!job.is_null(), "CreateJobObjectW failed");

    assert!(
        expected
            .verify_kernel_object(job, SecurityObjectKind::Job)
            .is_ok()
    );

    // SAFETY: job is the live handle returned above and is closed once.
    unsafe { CloseHandle(job) };
}

#[test]
fn job_readback_rejects_the_process_specific_guardian_policy() {
    let slot = service_sid(&guardian_slot_name(0).unwrap()).unwrap();
    let invalid_job_policy = format!("{}(A;;0x00001000;;;{slot})", launcher_job_sddl().unwrap());
    let invalid_job_policy =
        SecurityDescriptor::from_sddl(invalid_job_policy.strip_prefix("O:SY").unwrap()).unwrap();
    let attributes = invalid_job_policy.attributes(false);
    // SAFETY: attributes and its descriptor remain live; null creates an
    // unnamed job owned only through the returned handle.
    let job = unsafe { CreateJobObjectW(&raw const attributes, ptr::null()) };
    assert!(!job.is_null(), "CreateJobObjectW failed");

    assert!(
        invalid_job_policy
            .verify_kernel_object(job, SecurityObjectKind::Job)
            .is_err()
    );

    // SAFETY: job is the live handle returned above and is closed once.
    unsafe { CloseHandle(job) };
}

#[test]
fn launcher_process_grants_only_the_broker_interaction_capabilities() {
    const PROCESS_QUERY_LIMITED_INFORMATION_ACE: &str = "(A;;0x00001000;;;";

    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME).unwrap();
    let broker = service_sid(memcordon_core::WINDOWS_SESSION_BROKER_SERVICE_NAME).unwrap();
    let common_prefix = format!("O:SYD:P(A;;GA;;;SY)(A;;GA;;;{launcher})");
    let process = launcher_process_sddl().unwrap();
    let thread = launcher_thread_sddl().unwrap();
    let job = launcher_job_sddl().unwrap();

    assert_eq!(
        process,
        format!("{common_prefix}(A;;0x00101040;;;{broker})")
    );
    assert_eq!(thread, common_prefix);
    assert_eq!(job, common_prefix);
    assert_eq!(process.matches("(A;;GA;;;SY)").count(), 1);
    assert_eq!(thread.matches("(A;;GA;;;SY)").count(), 1);
    assert_eq!(job.matches("(A;;GA;;;SY)").count(), 1);
    assert_eq!(process.matches(&format!("(A;;GA;;;{launcher})")).count(), 1);
    assert_eq!(thread.matches(&format!("(A;;GA;;;{launcher})")).count(), 1);
    assert_eq!(job.matches(&format!("(A;;GA;;;{launcher})")).count(), 1);
    assert_eq!(
        process
            .matches(&format!("(A;;0x00101040;;;{broker})"))
            .count(),
        1
    );
    assert!(!thread.contains(PROCESS_QUERY_LIMITED_INFORMATION_ACE));
    assert!(!job.contains(PROCESS_QUERY_LIMITED_INFORMATION_ACE));

    for index in 0..memcordon_core::WINDOWS_GUARDIAN_SLOT_COUNT {
        let slot = service_sid(&guardian_slot_name(index).unwrap()).unwrap();
        assert!(!process.contains(&slot));
        assert!(!thread.contains(&slot));
        assert!(!job.contains(&slot));
    }
}

#[test]
fn session_broker_and_holder_capability_policies_are_exact() {
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME).unwrap();
    let broker = service_sid(memcordon_core::WINDOWS_SESSION_BROKER_SERVICE_NAME).unwrap();

    assert_eq!(
        session_broker_service_sddl().unwrap(),
        format!(
            "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00000014;;;{launcher})(A;;0x00020005;;;{broker})"
        )
    );
    assert_eq!(
        session_broker_process_sddl().unwrap(),
        format!(
            "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;0x00101000;;;{launcher})(A;;0x00101000;;;BA)"
        )
    );
    let broker_process_access = crate::windows::session_broker::BROKER_PROCESS_LAUNCHER_ACCESS;
    assert_eq!(broker_process_access, 0x0010_1000);
    assert_eq!(broker_process_access & 0x0010_0000, 0x0010_0000);
    assert_eq!(broker_process_access & 0x0000_1000, 0x0000_1000);
    assert_eq!(
        broker_process_access
            & (0x0000_0001
                | 0x0000_0002
                | 0x0000_0008
                | 0x0000_0020
                | 0x0000_0040
                | 0x0000_0100
                | 0x0000_0200
                | 0x0000_0400
                | 0x0004_0000
                | 0x0008_0000),
        0
    );
    let broker_token_access = 0x0002_0008_u32;
    assert_eq!(
        session_broker_token_sddl().unwrap(),
        format!(
            "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;0x{broker_token_access:08x};;;{launcher})"
        )
    );
    assert_eq!(broker_token_access, 0x0002_0000 | 0x0000_0008);
    assert_eq!(
        broker_token_access
            & (0x0000_0001
                | 0x0000_0002
                | 0x0000_0004
                | 0x0000_0010
                | 0x0000_0020
                | 0x0000_0040
                | 0x0000_0080
                | 0x0000_0100
                | 0x0004_0000
                | 0x0008_0000),
        0
    );
    assert_eq!(
        session_broker_pipe_sddl().unwrap(),
        format!(
            "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;{broker})(A;;0x0012019b;;;{launcher})S:(ML;;NW;;;HI)"
        )
    );
    assert_eq!(
        session_holder_job_sddl().unwrap(),
        format!("O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;GA;;;{launcher})")
    );
    assert_eq!(
        session_holder_process_sddl().unwrap(),
        format!("O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;0x00101040;;;{launcher})")
    );
    let holder_thread_access = THREAD_QUERY_LIMITED_INFORMATION | THREAD_RESUME;
    let broker_arm_request_access =
        crate::windows::session_broker::HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS;
    let broker_arm_granted_access =
        crate::windows::session_broker::HOLDER_THREAD_BROKER_ARM_GRANTED_ACCESS;
    assert_eq!(holder_thread_access, 0x0000_1800);
    assert_eq!(broker_arm_request_access, 0x0000_00c0);
    assert_eq!(broker_arm_granted_access, 0x0000_08c0);
    assert_eq!(
        broker_arm_request_access & (THREAD_QUERY_INFORMATION | THREAD_SET_THREAD_TOKEN),
        broker_arm_request_access
    );
    assert_eq!(
        broker_arm_granted_access,
        broker_arm_request_access | THREAD_QUERY_LIMITED_INFORMATION
    );
    assert_eq!(
        session_holder_thread_sddl().unwrap(),
        format!(
            "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;0x{holder_thread_access:08x};;;{launcher})(A;;0x{broker_arm_request_access:08x};;;{broker})"
        )
    );
    assert_eq!(
        holder_thread_access & (THREAD_QUERY_LIMITED_INFORMATION | THREAD_RESUME),
        holder_thread_access
    );
    assert_eq!(
        holder_thread_access
            & (THREAD_SUSPEND_RESUME
                | 0x0010_0000
                | 0x0000_0001
                | 0x0000_0008
                | 0x0000_0010
                | 0x0000_0020
                | 0x0000_0100
                | 0x0004_0000
                | 0x0008_0000
                | 0x1000_0000),
        0
    );
    assert_eq!(
        broker_arm_request_access
            & (THREAD_RESUME
                | THREAD_SUSPEND_RESUME
                | 0x0010_0000
                | 0x0000_0001
                | 0x0000_0002
                | 0x0000_0008
                | 0x0000_0010
                | 0x0000_0020
                | 0x0000_0100
                | 0x0004_0000
                | 0x0008_0000
                | 0x1000_0000),
        0
    );
    let carrier_access = crate::windows::token::SESSION_CREATION_CARRIER_ACCESS;
    let carrier_readback_access = carrier_access & !0x0000_0004;
    assert_eq!(carrier_access, 0x0002_001c);
    assert_eq!(carrier_readback_access, 0x0002_0018);
    assert_eq!(
        session_creation_carrier_token_sddl().unwrap(),
        format!(
            "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;0x{carrier_readback_access:08x};;;SY)(A;;0x{carrier_readback_access:08x};;;{broker})"
        )
    );
    assert_eq!(
        carrier_access
            & (0x0000_0001
                | 0x0000_0002
                | 0x0000_0020
                | 0x0000_0040
                | 0x0000_0080
                | 0x0000_0100
                | 0x0004_0000
                | 0x0008_0000),
        0
    );
    let holder_token = session_holder_token_sddl().unwrap();
    assert!(holder_token.contains("(A;;GA;;;SY)"));
    assert!(holder_token.contains(&format!("(A;;0x00020008;;;{broker})")));
    assert!(holder_token.contains(&format!("(A;;0x00020008;;;{launcher})")));
    assert!(!holder_token.contains("0x00000010"));
}

#[test]
fn protected_dacl_only_token_mutation_preserves_owner_group_and_seals_reopen() {
    const READ_CONTROL_ACCESS: u32 = 0x0002_0000;
    const WRITE_DAC_ACCESS: u32 = 0x0004_0000;
    const PROTECTION_ACCESS: u32 = TOKEN_QUERY | READ_CONTROL_ACCESS | WRITE_DAC_ACCESS;
    const STEADY_ACCESS: u32 = TOKEN_QUERY | READ_CONTROL_ACCESS;

    struct ThreadRevert;
    impl Drop for ThreadRevert {
        fn drop(&mut self) {
            // SAFETY: this guard is created only after installing the test
            // impersonation token on the current test thread.
            let _ = unsafe { RevertToSelf() };
        }
    }

    let source = crate::windows::token::restricted_current_primary().unwrap();
    let mut test_token = ptr::null_mut();
    // SAFETY: source is a live primary token and output receives a private
    // impersonation token used only by this test thread.
    assert_ne!(
        unsafe {
            DuplicateTokenEx(
                source.raw(),
                TOKEN_ALL_ACCESS,
                ptr::null(),
                SecurityImpersonation,
                TokenImpersonation,
                &raw mut test_token,
            )
        },
        0
    );
    let test_token = crate::windows::pipe::OwnedHandle::new(test_token).unwrap();
    // SAFETY: a null thread selects the current thread; test_token remains live.
    assert_ne!(unsafe { SetThreadToken(ptr::null(), test_token.raw()) }, 0);
    let _revert = ThreadRevert;

    let owner_group_before =
        SecurityDescriptor::kernel_object_owner_group_sddl_for_test(test_token.raw()).unwrap();
    let token_user = crate::windows::token::token_user_sid(test_token.raw()).unwrap();
    let expected = SecurityDescriptor::from_sddl(&format!(
        "{owner_group_before}D:P(D;;WDWO;;;OW)(A;;0x{STEADY_ACCESS:08x};;;{token_user})"
    ))
    .unwrap();

    let process = unsafe { GetCurrentProcess() };
    let mut protection = ptr::null_mut();
    // SAFETY: source/target process pseudo-handles and the test-token handle
    // are live; output receives one exact startup convergence capability.
    assert_ne!(
        unsafe {
            DuplicateHandle(
                process,
                test_token.raw(),
                process,
                &raw mut protection,
                PROTECTION_ACCESS,
                0,
                0,
            )
        },
        0
    );
    let protection = crate::windows::pipe::OwnedHandle::new(protection).unwrap();
    assert_eq!(
        crate::windows::token::granted_handle_access(protection.raw()).unwrap(),
        PROTECTION_ACCESS
    );
    expected
        .apply_dacl_to_kernel_object_detailed(protection.raw())
        .unwrap();
    expected
        .verify_kernel_object(protection.raw(), SecurityObjectKind::Token)
        .unwrap();
    assert_eq!(
        SecurityDescriptor::kernel_object_owner_group_sddl_for_test(protection.raw()).unwrap(),
        owner_group_before
    );
    drop(protection);

    let mut steady = ptr::null_mut();
    // SAFETY: the test impersonation token is installed on this thread; OpenAsSelf
    // makes the object's DACL authorize the process identity.
    assert_ne!(
        unsafe { OpenThreadToken(GetCurrentThread(), STEADY_ACCESS, 1, &raw mut steady) },
        0
    );
    let steady = crate::windows::pipe::OwnedHandle::new(steady).unwrap();
    assert_eq!(
        crate::windows::token::granted_handle_access(steady.raw()).unwrap(),
        STEADY_ACCESS
    );
    expected
        .verify_kernel_object(steady.raw(), SecurityObjectKind::Token)
        .unwrap();

    let mut forbidden = ptr::null_mut();
    assert_eq!(
        unsafe { OpenThreadToken(GetCurrentThread(), WRITE_DAC_ACCESS, 1, &raw mut forbidden) },
        0
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(ERROR_ACCESS_DENIED as i32)
    );
    assert!(forbidden.is_null());
}

#[test]
fn token_peer_query_merge_is_exact_preserving_and_idempotent() {
    let token = crate::windows::token::restricted_current_primary().unwrap();
    let peer = service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME).unwrap();
    let before = token_dacl_nonpeer_fingerprint(token.raw(), &peer).unwrap();

    converge_token_peer_query(token.raw(), &peer).unwrap();
    attest_token_peer_query(token.raw(), &peer).unwrap();
    assert_eq!(
        token_dacl_nonpeer_fingerprint(token.raw(), &peer).unwrap(),
        before
    );

    converge_token_peer_query(token.raw(), &peer).unwrap();
    attest_token_peer_query(token.raw(), &peer).unwrap();
    assert_eq!(
        token_dacl_nonpeer_fingerprint(token.raw(), &peer).unwrap(),
        before
    );
}

#[test]
fn token_peer_query_merge_rejects_an_invalid_peer_sid() {
    let token = crate::windows::token::restricted_current_primary().unwrap();
    let error = converge_token_peer_query(token.raw(), "not-a-sid").unwrap_err();
    assert_eq!(error.stage(), TokenDaclStage::Merge);
}

#[test]
fn bootstrap_authority_is_removed_from_the_final_state_root() {
    const GENERIC_EXECUTE: u32 = 0x2000_0000;
    const DELETE: u32 = 0x0001_0000;
    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
    const FILE_ADD_FILE: u32 = 0x0000_0002;
    const FILE_ADD_SUBDIRECTORY: u32 = 0x0000_0004;
    const FILE_TRAVERSE: u32 = 0x0000_0020;

    let final_administrator =
        normalized_access_mask(SecurityObjectKind::File, GENERIC_EXECUTE | DELETE);
    assert_eq!(final_administrator, 0x0013_00a0);
    assert_ne!(final_administrator & DELETE, 0);
    assert_ne!(final_administrator & READ_CONTROL, 0);
    assert_ne!(final_administrator & FILE_TRAVERSE, 0);
    assert_eq!(final_administrator & FILE_LIST_DIRECTORY, 0);
    assert_eq!(final_administrator & FILE_ADD_FILE, 0);
    assert_eq!(final_administrator & FILE_ADD_SUBDIRECTORY, 0);
    assert_eq!(final_administrator & WRITE_DAC, 0);

    let bootstrap = state_bootstrap_sddl().unwrap();
    let parent = state_parent_sddl().unwrap();
    let final_root = state_sddl().unwrap();
    assert!(bootstrap.contains("(A;OICI;FA;;;BA)"));
    assert!(parent.contains("(A;OICI;FA;;;BA)"));
    assert!(final_root.contains("(A;;GXSD;;;BA)"));
    assert!(!final_root.contains("(A;OICI;FA;;;BA)"));
}

#[test]
fn final_state_root_policy_allows_exact_removal_without_listing() {
    use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;

    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("sealed");
    std::fs::create_dir(&root).unwrap();
    SecurityDescriptor::from_sddl(&state_sddl().unwrap())
        .unwrap()
        .apply_to_path(&root)
        .unwrap();

    assert!(std::fs::symlink_metadata(&root).is_ok());
    let list_error = std::fs::read_dir(&root).unwrap_err();
    assert_eq!(list_error.raw_os_error(), Some(ERROR_ACCESS_DENIED as i32));
    std::fs::remove_dir(&root).unwrap();
}

#[test]
fn exact_root_removal_preserves_an_unknown_child() {
    use windows_sys::Win32::Foundation::ERROR_DIR_NOT_EMPTY;

    const READ_CONTROL_ACCESS: u32 = 0x0002_0000;
    const WRITE_DAC_ACCESS: u32 = 0x0004_0000;

    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("sealed");
    let unknown = root.join("unknown-residual");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(&unknown, b"preserved evidence\n").unwrap();
    let retained = open_retained_directory(&root, READ_CONTROL_ACCESS | WRITE_DAC_ACCESS).unwrap();
    SecurityDescriptor::from_sddl(&state_sddl().unwrap())
        .unwrap()
        .apply_to_path(&root)
        .unwrap();

    let remove_error = std::fs::remove_dir(&root).unwrap_err();
    let bootstrap = state_bootstrap_sddl().unwrap();
    SecurityDescriptor::from_sddl(bootstrap.strip_prefix("O:BA").unwrap())
        .unwrap()
        .apply_to_file_object(retained.raw())
        .unwrap();
    SecurityDescriptor::from_sddl(&bootstrap)
        .unwrap()
        .verify_file_object(retained.raw())
        .unwrap();
    assert_eq!(
        remove_error.raw_os_error(),
        Some(ERROR_DIR_NOT_EMPTY as i32)
    );
    assert_eq!(std::fs::read(&unknown).unwrap(), b"preserved evidence\n");
}

#[test]
fn package_leaf_attestation_is_read_control_only() {
    for final_leaf in [
        launcher_state_sddl().unwrap(),
        replay_state_sddl().unwrap(),
        admission_state_sddl().unwrap(),
    ] {
        assert!(final_leaf.contains("(A;;RC;;;BA)"));
        assert!(!final_leaf.contains("(A;OICI;RC;;;BA)"));
        assert!(!final_leaf.contains("(A;;FA;;;BA)"));
        assert!(!final_leaf.contains("(A;OICI;FA;;;BA)"));
    }
}

#[test]
fn certification_workspace_policy_supports_all_target_classes_and_handle_scoped_publication() {
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME).unwrap();
    let control = service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME).unwrap();
    let marker = certification_marker_state_sddl().unwrap();
    assert_eq!(CERTIFICATION_ADMIN_DIRECTORY_ACCESS, 0x001f_01bf);
    assert!(marker.contains("(A;OICI;FA;;;SY)"));
    assert!(marker.contains("(A;OICI;0x001f01bf;;;BA)"));
    assert!(!marker.contains("(A;OICI;FA;;;BA)"));
    assert!(marker.contains(&format!("(D;;0x00000004;;;{control})")));
    assert!(marker.contains(&format!("(D;;0x00000004;;;{launcher})")));
    assert!(marker.contains(&format!("(A;;GX;;;{launcher})")));
    assert!(marker.contains(&format!("(A;OICIIO;GRGWGX;;;{launcher})")));
    assert!(marker.contains(&format!("(A;;GRGX;;;{control})")));
    assert!(marker.contains(&format!("(A;OICIIO;GRGX;;;{control})")));
    assert!(marker.contains("(A;;0x00000024;;;AU)"));
    assert!(marker.contains("(A;OICIIO;GRGWGX;;;AU)"));
    assert!(!marker.contains("(A;CIIO;0x00000040;;;AU)"));
    assert!(marker.contains("(A;;0x00000024;;;RC)"));
    assert!(marker.contains("(A;OICIIO;GRGWGX;;;RC)"));
    assert!(!marker.contains("(A;CIIO;0x00000040;;;RC)"));
    assert!(marker.contains("(A;;0x00000024;;;WR)"));
    assert!(marker.contains("(A;OICIIO;GRGWGX;;;WR)"));
    assert!(!marker.contains("(A;CIIO;0x00000040;;;WR)"));
    assert!(marker.contains("S:(ML;OICI;NW;;;LW)"));
    assert!(!marker.contains(&format!("(A;OICI;GRGWGXSD;;;{launcher})")));
    assert!(!marker.contains("(A;OICI;GRGWGXSD;;;AU)"));
    assert!(!marker.contains("(A;OICI;GRGWGXSD;;;RC)"));
    assert!(!marker.contains("(A;OICI;GRGWGXSD;;;WR)"));
    assert!(!marker.contains("(A;;0x00000040;;;AU)"));
    assert!(!marker.contains("(A;;0x00000040;;;RC)"));
    assert!(!marker.contains("(A;;0x00000040;;;WR)"));
    for producer in [&launcher, "AU", "RC", "WR"] {
        assert!(
            !marker.contains(&format!("SD;;;{producer})")),
            "producer {producer} retained reopenable DELETE"
        );
    }

    let package = package_state_sddl().unwrap();
    assert!(package.contains(&format!("(A;OICI;GRGX;;;{launcher})")));
    assert!(!package.contains(&format!("(A;OICI;GRGWGXSD;;;{launcher})")));
    assert!(!package.contains("(A;OICI;GRGWGXSD;;;AU)"));
    assert!(!package.contains("(A;OICI;GRGWGXSD;;;RC)"));
    assert!(!package.contains(";;;WR)"));
    assert!(!package.contains("S:(ML;OICI;NW;;;LW)"));
}

#[test]
fn installed_image_policy_grants_restricted_code_only_read_execute() {
    let temporary = tempfile::tempdir().unwrap();
    let install_root = temporary.path().join("install");
    std::fs::create_dir(&install_root).unwrap();
    SecurityDescriptor::from_sddl(crate::windows::package::INSTALL_SDDL)
        .unwrap()
        .apply_to_path(&install_root)
        .unwrap();
    let image = install_root.join("memcordon-sealed-agent.exe");
    std::fs::write(&image, b"qualification image canary\n").unwrap();

    let _token = crate::windows::token::impersonate_restricted_current_thread().unwrap();
    std::fs::File::open(&image).expect("RC must be able to read the installed image");
    let error = std::fs::OpenOptions::new()
        .write(true)
        .open(&image)
        .expect_err("RC acquired installed-image write authority");
    assert_eq!(error.raw_os_error(), Some(ERROR_ACCESS_DENIED as i32));
    assert!(crate::windows::package::INSTALL_SDDL.contains("(A;;GX;;;RC)"));
    assert!(crate::windows::package::INSTALL_SDDL.contains("(A;OIIO;GRGX;;;RC)"));
    assert!(!crate::windows::package::INSTALL_SDDL.contains("GW;;;RC)"));
    assert!(!crate::windows::package::INSTALL_SDDL.contains("GA;;;RC)"));
}

#[test]
fn qualification_frontend_handle_failures_name_every_native_role() {
    let image = std::path::Path::new(r"C:\Program Files\MemCordon\memcordon-sealed-agent.exe");
    for (api, role, path) in [
        ("CreateFileW", "installed-image", Some(image)),
        ("CreateEventW", "event", None),
        ("CreatePipe", "pipe-pair", None),
        ("CreatePipe", "pipe-read", None),
        ("CreatePipe", "pipe-write", None),
        ("DuplicateHandle", "process-duplicate", None),
        ("CreateFileMappingW", "section", None),
        ("RegOpenKeyExW", "registry", None),
        ("SetHandleInformation", "registry", None),
    ] {
        let detail = crate::windows::qualification::qualification_native_failure_for_test(
            "qualification-frontend-handle-create",
            api,
            role,
            path,
            ERROR_ACCESS_DENIED as i32,
        );
        assert!(detail.contains("stage=qualification-frontend-handle-create"));
        assert!(detail.contains(&format!("api={api}")));
        assert!(detail.contains(&format!("role={role}")));
        assert!(detail.contains("native_code=5"));
        if role == "installed-image" {
            assert!(detail.contains(&format!("path={}", image.display())));
        }
    }

    let query_failure =
        crate::windows::qualification::qualification_frontend_handle_validation_failure_for_test(
            "GetHandleInformation",
            "pipe-write-retained",
            Some(ERROR_ACCESS_DENIED as i32),
            "retained pipe writer is not live",
        );
    assert!(query_failure.contains("stage=qualification-frontend-handle-prepare"));
    assert!(query_failure.contains("api=GetHandleInformation"));
    assert!(query_failure.contains("role=pipe-write-retained"));
    assert!(query_failure.contains("native_code=5"));

    let inventory_failure =
        crate::windows::qualification::qualification_frontend_handle_validation_failure_for_test(
            "inventory",
            "installed-image",
            None,
            "advertised handle duplicates an earlier role",
        );
    assert!(inventory_failure.contains("stage=qualification-frontend-handle-prepare"));
    assert!(inventory_failure.contains("api=inventory"));
    assert!(inventory_failure.contains("native_code=none"));
}

#[test]
fn target_desktop_bootstrap_peer_exit_diagnostic_preserves_operation_and_status() {
    let (detail, native_code) =
        crate::windows::pipe::target_desktop_bootstrap_peer_exit_error_for_test(
            crate::windows::pipe::TargetDesktopBootstrapPipeOperation::StartedRead,
            "length",
            4,
            0xED14_0000,
        );
    assert_eq!(native_code, Some(0xED14_0000_u32 as i32));
    assert!(detail.contains("operation=started-read"));
    assert!(detail.contains("segment=length"));
    assert!(detail.contains("requested=4"));
    assert!(detail.contains("child_exit_code_decimal=3977510912"));
    assert!(detail.contains("child_exit_code_hex=0xED140000"));
}

#[test]
fn target_association_preflight_requires_exact_native_open_capabilities() {
    target_association_preflight_grants_for_test(
        TARGET_PRIVATE_WINDOW_STATION_ACCESS,
        TARGET_PRIVATE_DESKTOP_ACCESS,
        true,
    )
    .unwrap();

    for (station, desktop, thread_token_absent) in [
        (
            TARGET_PRIVATE_WINDOW_STATION_ACCESS & !0x0000_0001,
            TARGET_PRIVATE_DESKTOP_ACCESS,
            true,
        ),
        (
            TARGET_PRIVATE_WINDOW_STATION_ACCESS,
            TARGET_PRIVATE_DESKTOP_ACCESS & !0x0000_0001,
            true,
        ),
        (
            TARGET_PRIVATE_WINDOW_STATION_ACCESS,
            TARGET_PRIVATE_DESKTOP_ACCESS,
            false,
        ),
    ] {
        let error =
            target_association_preflight_grants_for_test(station, desktop, thread_token_absent)
                .unwrap_err();
        assert!(error.contains("station_requested="));
        assert!(error.contains("desktop_requested="));
        assert!(error.contains("thread_token_absent="));
    }
}

#[test]
fn target_association_preflight_progress_is_bounded_and_monotonic() {
    let mut sequence = 0;
    let mut last_stage = None;
    let mut last_completed = 0;
    let mut last_total = None;
    let mut accept = |stage, completed, total| {
        let next_sequence = sequence + 1;
        target_association_preflight_progress_for_test(
            sequence,
            last_stage,
            last_completed,
            last_total,
            next_sequence,
            stage,
            completed,
            total,
        )
        .unwrap();
        sequence = next_sequence;
        last_stage = Some(stage);
        last_completed = completed;
        last_total = total;
    };

    accept(0, 0, Some(1));
    accept(0, 1, Some(1));
    accept(1, 0, None);
    accept(1, 1, Some(2));
    accept(1, 2, Some(2));
    accept(2, 0, Some(1));
    accept(2, 1, Some(1));
    accept(3, 0, None);
    accept(3, 1, None);
    accept(3, 2, None);
    accept(3, 2, Some(2));
    accept(4, 0, Some(2));
    accept(4, 1, Some(2));
    accept(4, 2, Some(2));
    for stage in 5..=11 {
        accept(stage, 0, Some(1));
        accept(stage, 1, Some(1));
    }

    target_association_preflight_progress_for_test(2, Some(3), 13, None, 3, 3, 13, Some(13))
        .unwrap();
    target_association_preflight_progress_for_test(2, Some(3), 128, None, 3, 3, 128, Some(128))
        .unwrap();
    target_association_preflight_progress_for_test(
        4_095,
        Some(10),
        0,
        Some(2),
        4_096,
        10,
        1,
        Some(2),
    )
    .unwrap();

    for (
        last_sequence,
        last_stage,
        last_completed,
        last_total,
        sequence,
        stage,
        completed,
        total,
        expected,
    ) in [
        (0, None, 0, None, 0, 0, 0, Some(1), "sequence=0"),
        (1, Some(0), 0, Some(1), 1, 0, 1, Some(1), "sequence=1"),
        (1, Some(0), 0, Some(1), 3, 0, 1, Some(1), "sequence=3"),
        (2, Some(3), 1, Some(128), 3, 3, 1, Some(13), "total=13"),
        (2, Some(3), 1, None, 3, 3, 1, None, "meaningful"),
        (2, Some(3), 1, None, 3, 3, 1, Some(2), "total=2"),
        (2, Some(3), 1, Some(2), 3, 3, 2, None, "total=unknown"),
        (2, Some(3), 1, Some(2), 3, 3, 2, Some(3), "total=3"),
        (2, Some(3), 2, Some(2), 3, 3, 2, Some(2), "closed stage"),
        (2, Some(3), 1, Some(2), 3, 3, 0, Some(2), "completed=0"),
        (
            2,
            Some(3),
            1,
            Some(2),
            3,
            5,
            0,
            Some(1),
            "stage=target-token",
        ),
        (2, Some(3), 1, Some(2), 3, 4, 0, Some(1), "completion frame"),
        (2, Some(3), 2, Some(2), 3, 4, 1, Some(1), "completed=1"),
        (0, None, 0, None, 1, 1, 0, None, "stage=source-bootstrap"),
        (0, None, 0, None, 1, 0, 1, Some(1), "completed=1"),
        (
            4_095,
            Some(10),
            0,
            None,
            4_096,
            99,
            0,
            None,
            "stage ordinal is unknown",
        ),
        (
            4_096,
            Some(10),
            0,
            None,
            4_097,
            10,
            0,
            None,
            "sequence=4097",
        ),
    ] {
        let error = target_association_preflight_progress_for_test(
            last_sequence,
            last_stage,
            last_completed,
            last_total,
            sequence,
            stage,
            completed,
            total,
        )
        .unwrap_err();
        assert!(error.contains(expected), "unexpected error: {error}");
    }
}

#[test]
fn target_association_preflight_same_stage_total_lattice_is_exhaustive() {
    let totals = [None, Some(0), Some(1), Some(2), Some(3)];
    for last_completed in 0..=3 {
        for last_total in totals {
            if last_total.is_some_and(|total| last_completed > total) {
                continue;
            }
            for completed in 0..=3 {
                for total in totals {
                    let expected = total.is_none_or(|total| completed <= total)
                        && last_total != Some(last_completed)
                        && completed >= last_completed
                        && !matches!((last_total, total), (Some(_), None))
                        && !(last_total.is_some() && total.is_some() && last_total != total)
                        && (completed > last_completed
                            || (last_total.is_none() && total == Some(completed)));
                    let actual = target_association_preflight_progress_for_test(
                        2,
                        Some(3),
                        last_completed,
                        last_total,
                        3,
                        3,
                        completed,
                        total,
                    )
                    .is_ok();
                    assert_eq!(
                        actual, expected,
                        "last_completed={last_completed} last_total={last_total:?} completed={completed} total={total:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn loader_graph_admits_each_concrete_host_once_across_logical_and_forwarder_aliases() {
    let (admission_count, indices) = physical_loader_admission_plan_for_test(&[
        "KERNELBASE.DLL",
        "KERNELBASE.DLL",
        "NTDLL.DLL",
        "kernelbase.dll",
        "NTDLL.DLL",
    ]);
    assert_eq!(admission_count, 2);
    assert_eq!(indices, vec![0, 0, 1, 0, 1]);
}

#[test]
fn target_desktop_bootstrap_failed_first_transition_preserves_typed_evidence() {
    let (detail, native_code) =
        crate::windows::process::target_desktop_bootstrap_failure_transition_for_test(
            "await-started",
            true,
            Some(5),
            "TokenSource access was denied".to_owned(),
        );
    assert_eq!(native_code, Some(5));
    assert_eq!(
        detail,
        "target desktop bootstrap rejected: state=await-started phase=server-token-authentication native_code=Some(5) detail=TokenSource access was denied"
    );

    for (binding_matches, failure_detail) in [
        (false, "binding mismatch".to_owned()),
        (true, String::new()),
        (true, "x".repeat(1_025)),
    ] {
        let (detail, native_code) =
            crate::windows::process::target_desktop_bootstrap_failure_transition_for_test(
                "await-started",
                binding_matches,
                Some(5),
                failure_detail,
            );
        assert_eq!(native_code, None);
        assert_eq!(detail, "target desktop bootstrap failure frame is invalid");
    }
}

#[test]
fn target_desktop_creation_relay_accepts_only_exact_phase_ordinal_and_nonzero_tid() {
    use crate::windows::process::target_desktop_creation_transition_for_test as expected;

    assert!(expected(0, false, 1, 11));
    assert!(expected(1, true, 2, 12));
    for (completed, desktop, ordinal, thread_id) in [
        (0, false, 1, 0),
        (0, true, 1, 11),
        (0, false, 2, 11),
        (1, false, 2, 12),
        (1, true, 1, 12),
        (2, true, 3, 13),
    ] {
        assert!(!expected(completed, desktop, ordinal, thread_id));
    }
}

#[test]
fn partial_started_publication_abandons_the_failure_frame_channel() {
    use crate::windows::process::started_failure_frame_publication_is_safe_for_test as safe;

    assert!(safe(0));
    assert!(!safe(1));
    assert!(!safe(4));
    assert!(!safe(64 * 1024));
}

fn assert_cleanup_create_once_for_current_token(
    marker_root: &std::path::Path,
    marker_root_security: HANDLE,
    scenario: &str,
    fixture: Option<&crate::windows::token::RestrictedImpersonationGuard>,
) {
    const FILE_DELETE_CHILD: u32 = 0x0000_0040;
    const DELETE_ACCESS: u32 = 0x0001_0000;

    let assert_root_delete_child_denied = |effective| {
        let expected_descriptor =
            SecurityDescriptor::from_sddl(&certification_marker_state_sddl().unwrap()).unwrap();
        let (access_check_allowed, access_check_granted) = expected_descriptor
            .kernel_object_access_check_for_test(marker_root_security, effective, FILE_DELETE_CHILD)
            .unwrap_or_else(|error| {
                panic!("{scenario} live marker-root descriptor/AccessCheck failed: {error}")
            });
        match open_retained_directory(marker_root, FILE_DELETE_CHILD) {
            Err(error) => {
                assert_eq!(
                    error,
                    std::io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32).to_string(),
                    "{scenario} shared-root delete-child returned an unexpected denial"
                );
                assert!(
                    !access_check_allowed && access_check_granted & FILE_DELETE_CHILD == 0,
                    "{scenario} CreateFile denied but live marker-root AccessCheck granted delete-child: allowed={access_check_allowed} granted=0x{access_check_granted:08x}"
                );
            }
            Ok(handle) => {
                let granted = crate::windows::token::granted_handle_access(handle.raw())
                    .unwrap_or_else(|error| {
                        panic!("{scenario} cannot read unexpected directory grant: {error}")
                    });
                let cached_fixture = fixture.map(|fixture| fixture.fixture_snapshot());
                panic!(
                    "{scenario} unexpectedly acquired shared-root delete-child authority: requested=0x{FILE_DELETE_CHILD:08x} granted=0x{granted:08x} access_check_allowed={access_check_allowed} access_check_granted=0x{access_check_granted:08x} cached_fixture={cached_fixture:?}"
                );
            }
        }
        Ok(())
    };
    if let Some(fixture) = fixture {
        fixture
            .with_effective_token_for_test(|effective| assert_root_delete_child_denied(effective))
            .unwrap_or_else(|error| {
                panic!("{scenario} effective-token attestation failed: {error}")
            });
    } else {
        let token = crate::windows::token::current_process_token_for_attestation_and_access_check()
            .unwrap();
        assert_root_delete_child_denied(token.raw()).unwrap();
    }

    let workspace = marker_root.join(format!("attempt-{scenario}"));
    std::fs::create_dir(&workspace).unwrap();
    assert_eq!(
        open_retained_directory(&workspace, FILE_DELETE_CHILD).unwrap_err(),
        std::io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32).to_string(),
        "{scenario} unexpectedly acquired nonce-workspace delete-child authority"
    );
    let workspace_delete = open_retained_directory(&workspace, DELETE_ACCESS);
    if fixture.is_some() {
        assert_eq!(
            workspace_delete.unwrap_err(),
            std::io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32).to_string(),
            "{scenario} unexpectedly acquired reopenable workspace DELETE"
        );
    } else {
        drop(workspace_delete.expect("elevated cleanup lost workspace DELETE"));
    }
    let marker = workspace.join("cleanup.marker");
    let attempt_binding = workspace
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .expect("cleanup publication workspace has a UTF-8 attempt binding");
    assert_eq!(attempt_binding, format!("attempt-{scenario}"));
    let identity = crate::windows::process::process_identity(unsafe { GetCurrentProcess() })
        .expect("current process identity");
    let (receipt, staged) =
        crate::windows::qualification::publish_cleanup_process_creation_state_for_test(
            &marker,
            attempt_binding,
            &identity,
        )
        .unwrap_or_else(|failure| panic!("{scenario} create-once publication failed: {failure:?}"));
    let rename_layout =
        crate::windows::record::create_once_rename_layout_for_test(&staged, &receipt)
            .unwrap_or_else(|error| {
                panic!("{scenario} rename-layout reconstruction failed: {error}")
            });
    let original = std::fs::read(&receipt).unwrap_or_else(|error| {
        let receipt_probe = std::fs::symlink_metadata(&receipt)
            .map(|metadata| format!("present(len={})", metadata.len()))
            .unwrap_or_else(|probe| {
                format!(
                    "error(kind={:?} native_code={:?} detail={probe})",
                    probe.kind(),
                    probe.raw_os_error()
                )
            });
        let staged_probe = std::fs::symlink_metadata(&staged)
            .map(|metadata| format!("present(len={})", metadata.len()))
            .unwrap_or_else(|probe| {
                format!(
                    "error(kind={:?} native_code={:?} detail={probe})",
                    probe.kind(),
                    probe.raw_os_error()
                )
            });
        panic!(
            "{scenario} final receipt read failed: attempt_binding={attempt_binding} final={} staging={} destination_name_bytes={} information_bytes={} backing_bytes={} io_kind={:?} native_code={:?} detail={error} final_probe={receipt_probe} staging_probe={staged_probe}",
            receipt.display(),
            staged.display(),
            rename_layout.destination_name_bytes,
            rename_layout.information_bytes,
            rename_layout.backing_bytes,
            error.kind(),
            error.raw_os_error(),
        )
    });
    assert!(!staged.exists(), "{scenario} left its staging receipt");
    assert_eq!(
        std::fs::metadata(&receipt).unwrap().file_attributes() & FILE_ATTRIBUTE_READONLY,
        0,
        "{scenario} published a read-only receipt"
    );

    let mut collision_staging =
        crate::windows::record::CreateOnceStagingFile::create(&staged).unwrap();
    std::io::Write::write_all(
        collision_staging.file_mut(),
        b"collision must remain staged\n",
    )
    .unwrap();
    collision_staging.sync_all().unwrap();
    let collision =
        crate::windows::record::publish_create_once_atomically(collision_staging, &receipt)
            .expect_err("create-once publication replaced an immutable receipt");
    assert!(
        matches!(
            collision.raw_os_error(),
            Some(code) if code == ERROR_FILE_EXISTS as i32 || code == ERROR_ALREADY_EXISTS as i32
        ),
        "{scenario} collision returned unexpected error {collision:?}"
    );
    assert_eq!(std::fs::read(&receipt).unwrap(), original);
    assert_eq!(
        std::fs::read(&staged).unwrap(),
        b"collision must remain staged\n"
    );
    if fixture.is_some() {
        for path in [&receipt, &staged] {
            assert_eq!(
                open_retained_directory(path, DELETE_ACCESS).unwrap_err(),
                std::io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32).to_string(),
                "{scenario} reopened a publication leaf with DELETE"
            );
        }
    } else {
        std::fs::remove_file(staged).unwrap();
        std::fs::remove_file(receipt).unwrap();
        std::fs::remove_dir(workspace).unwrap();
    }
}

fn assert_qualification_create_once_for_write_restricted_token(
    marker_root: &std::path::Path,
    scenario: &str,
    destination_name: &str,
    producer: crate::windows::qualification::QualificationPublicationProducerForTest,
) {
    const FILE_DELETE_CHILD: u32 = 0x0000_0040;
    const DELETE_ACCESS: u32 = 0x0001_0000;
    const GENERIC_WRITE_DELETE_ACCESS: u32 = 0x4001_0000;

    let token = crate::windows::token::impersonate_write_restricted_current_thread().unwrap();
    let workspace = marker_root.join(format!("attempt-{scenario}"));
    std::fs::create_dir(&workspace).unwrap();
    assert_eq!(
        open_retained_directory(&workspace, FILE_DELETE_CHILD).unwrap_err(),
        std::io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32).to_string(),
        "{scenario} unexpectedly acquired workspace delete-child authority"
    );

    let destination = workspace.join(destination_name);
    let mut staged = destination.as_os_str().to_os_string();
    staged.push(".new");
    let staged = std::path::PathBuf::from(staged);
    crate::windows::qualification::publish_qualification_receipt_for_test(&destination, producer)
        .unwrap_or_else(|failure| {
            panic!("{scenario} retained-handle publication failed: {failure:?}")
        });
    assert!(destination.exists(), "{scenario} omitted its final receipt");
    assert!(!staged.exists(), "{scenario} retained its staging receipt");
    let receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&destination).unwrap()).unwrap();
    assert_eq!(receipt["producer"], scenario);
    assert_eq!(
        open_retained_directory(&destination, DELETE_ACCESS).unwrap_err(),
        std::io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32).to_string(),
        "{scenario} published a receipt with reopenable DELETE"
    );

    let collision = crate::windows::qualification::publish_qualification_receipt_for_test(
        &destination,
        producer,
    )
    .expect_err("create-once qualification publication replaced its destination");
    assert_eq!(collision.producer, scenario);
    assert_eq!(collision.stage, "receipt-publish-rename");
    assert_eq!(collision.api, "SetFileInformationByHandle(FileRenameInfo)");
    assert_eq!(collision.path_role, "destination");
    assert_eq!(
        collision.requested_access,
        Some(GENERIC_WRITE_DELETE_ACCESS)
    );
    assert!(
        matches!(
            collision.native_code,
            Some(code) if code == ERROR_FILE_EXISTS as i32 || code == ERROR_ALREADY_EXISTS as i32
        ),
        "{scenario} collision omitted its native no-replace status: {collision:?}"
    );
    assert_eq!(
        collision.io_error_kind,
        Some(std::io::ErrorKind::AlreadyExists)
    );
    assert!(
        !collision.detail.is_empty(),
        "{scenario} collision omitted its bounded native detail"
    );
    assert!(
        staged.exists(),
        "{scenario} collision lost staging evidence"
    );
    assert_eq!(
        open_retained_directory(&staged, DELETE_ACCESS).unwrap_err(),
        std::io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32).to_string(),
        "{scenario} collision staging leaf gained reopenable DELETE"
    );

    token.revert().unwrap();
    std::fs::remove_file(staged).unwrap();
    std::fs::remove_file(destination).unwrap();
    std::fs::remove_dir(workspace).unwrap();
}

#[test]
fn restricted_impersonation_guard_scopes_the_same_attested_token_handle() {
    let guard = crate::windows::token::impersonate_restricted_current_thread().unwrap();
    let expected_fixture = guard.fixture_snapshot();
    let mut observations = 0;
    guard
        .with_effective_token_for_test(|token| {
            assert!(!token.is_null());
            observations += 1;
            Ok(())
        })
        .unwrap();
    guard
        .with_effective_token_for_test(|token| {
            assert!(!token.is_null());
            observations += 1;
            Ok(())
        })
        .unwrap();

    assert_eq!(observations, 2);
    assert_eq!(guard.fixture_snapshot(), expected_fixture);
    guard.revert().unwrap();
}

#[test]
fn restricted_impersonation_guard_rejects_a_detached_retained_token() {
    let guard = crate::windows::token::impersonate_restricted_current_thread().unwrap();
    // SAFETY: the guard installed the current test thread's impersonation token.
    assert_ne!(unsafe { RevertToSelf() }, 0);
    let error = guard.with_effective_token_for_test(|_| Ok(())).unwrap_err();
    assert!(error.contains("stage=effective-thread-presence"), "{error}");
    assert!(error.contains("api=OpenThreadToken"), "{error}");
    assert!(error.contains("native_code=1008"), "{error}");
    drop(guard);
}

#[test]
fn entry_thread_reversion_observes_a_restricted_token_with_process_authorization() {
    let initial = crate::windows::token::nested_initial_thread_token_for_test().unwrap();
    let expected = crate::windows::token::token_attestation_snapshot(initial.raw()).unwrap();
    // SAFETY: a null thread pointer selects the current test thread and initial
    // is a live SecurityImpersonation token retained through the transition.
    assert_ne!(unsafe { SetThreadToken(ptr::null(), initial.raw()) }, 0);

    let transition = crate::windows::token::revert_entry_thread_token().unwrap();
    assert_eq!(
        transition.initial_token_id,
        Some(expected.instance.token_id)
    );
    assert_eq!(
        transition.initial_token_envelope,
        Some(expected.behavior.envelope)
    );
    assert!(transition.initial_token_behavior_attested);
    assert!(transition.initial_token_reverted);
    assert!(transition.thread_token_absent_after_revert);
}

#[test]
fn restricted_create_once_publication_uses_only_the_retained_staging_delete_capability() {
    const FILE_DELETE_CHILD: u32 = 0x0000_0040;
    const DELETE_ACCESS: u32 = 0x0001_0000;

    let temporary = tempfile::tempdir().unwrap();
    let marker_root = temporary.path().join("certification-markers");
    std::fs::create_dir(&marker_root).unwrap();
    SecurityDescriptor::from_sddl(&certification_marker_state_sddl().unwrap())
        .unwrap()
        .apply_to_path(&marker_root)
        .unwrap();

    {
        let token = crate::windows::token::impersonate_restricted_current_thread().unwrap();
        let workspace = marker_root.join("attempt-legacy-restricted");
        std::fs::create_dir(&workspace).unwrap();
        let delete_child = open_retained_directory(&workspace, FILE_DELETE_CHILD).unwrap_err();
        assert_eq!(
            delete_child,
            std::io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32).to_string()
        );
        let marker = workspace.join("cleanup.marker");
        let identity = crate::windows::process::process_identity(unsafe { GetCurrentProcess() })
            .expect("current process identity");
        let (receipt, staged) =
            crate::windows::qualification::publish_cleanup_process_creation_state_for_test(
                &marker,
                "restricted-retained-delete",
                &identity,
            )
            .expect("restricted create-once rename should retain its staging-handle DELETE");
        assert!(receipt.ends_with("cleanup.state.00-ready.json"));
        assert!(receipt.exists());
        assert!(!staged.exists());
        assert_eq!(
            open_retained_directory(&receipt, DELETE_ACCESS).unwrap_err(),
            std::io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32).to_string(),
            "published receipt retained reopenable DELETE"
        );
        token.revert().unwrap();
        std::fs::remove_file(receipt).unwrap();
        std::fs::remove_dir(workspace).unwrap();
    }
}

#[test]
fn create_once_publication_verifies_alignment_unicode_identity_and_collision_postconditions() {
    use std::collections::BTreeSet;
    use std::os::windows::ffi::OsStrExt;

    let temporary = tempfile::tempdir().unwrap();
    let mut information_residues = BTreeSet::new();
    let alignment = std::mem::size_of::<usize>();

    for padding in 0..alignment / std::mem::size_of::<u16>() {
        let destination = temporary
            .path()
            .join(format!("receipt-{}-λ-😀.json", "x".repeat(padding)));
        let mut staged = destination.as_os_str().to_os_string();
        staged.push(".new");
        let staged = std::path::PathBuf::from(staged);
        let contents = format!("alignment={padding} unicode=λ😀\n").into_bytes();
        let mut file = crate::windows::record::CreateOnceStagingFile::create(&staged).unwrap();
        std::io::Write::write_all(file.file_mut(), &contents).unwrap();
        file.sync_all().unwrap();

        let observation =
            crate::windows::record::publish_create_once_atomically_for_test(file, &destination)
                .unwrap_or_else(|error| {
                    panic!(
                        "alignment/Unicode publication failed: padding={padding} source={} destination={} error={error}",
                        staged.display(),
                        destination.display(),
                    )
                });
        assert!(observation.identity_unchanged);
        assert_eq!(observation.source_link_count, 1);
        assert_eq!(observation.final_link_count, 1);
        assert_eq!(
            observation.source_path.parent(),
            observation.final_path.parent(),
            "same-handle canonical parent changed across publication"
        );
        assert_eq!(observation.final_path.file_name(), destination.file_name());
        assert_eq!(
            usize::try_from(observation.destination_name_bytes).unwrap(),
            destination.as_os_str().encode_wide().count() * std::mem::size_of::<u16>()
        );
        assert!(observation.information_bytes > observation.destination_name_bytes);
        assert!(observation.backing_bytes >= observation.information_bytes);
        assert_eq!(
            usize::try_from(observation.backing_bytes).unwrap() % alignment,
            0
        );
        information_residues
            .insert(usize::try_from(observation.information_bytes).unwrap() % alignment);
        let source_error = std::fs::symlink_metadata(&staged).unwrap_err();
        assert_eq!(source_error.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(
            source_error.raw_os_error(),
            Some(ERROR_FILE_NOT_FOUND as i32)
        );
        assert_eq!(std::fs::read(&destination).unwrap(), contents);

        let collision_contents = b"collision evidence must remain staged\n";
        let mut collision = crate::windows::record::CreateOnceStagingFile::create(&staged).unwrap();
        std::io::Write::write_all(collision.file_mut(), collision_contents).unwrap();
        collision.sync_all().unwrap();
        let error = crate::windows::record::publish_create_once_atomically(collision, &destination)
            .expect_err("create-once collision replaced the Unicode destination");
        assert_eq!(
            error.stage(),
            crate::windows::record::CreateOncePublicationStage::Rename
        );
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(matches!(
            error.raw_os_error(),
            Some(code) if code == ERROR_FILE_EXISTS as i32 || code == ERROR_ALREADY_EXISTS as i32
        ));
        assert_eq!(std::fs::read(&destination).unwrap(), contents);
        assert_eq!(std::fs::read(&staged).unwrap(), collision_contents);

        std::fs::remove_file(staged).unwrap();
        std::fs::remove_file(destination).unwrap();
    }

    assert_eq!(
        information_residues.len(),
        alignment / std::mem::size_of::<u16>(),
        "Unicode publication cases did not cover every UTF-16/native-word tail residue"
    );
}

#[test]
fn create_once_transition_proof_anchors_canonical_parent_and_exact_leaf() {
    use crate::windows::record::{
        CreateOncePublicationStage as Stage, verify_create_once_transition_for_test as verify,
    };

    const ID: [u8; 16] = [0x5a; 16];
    let requested_source =
        std::path::Path::new(r"C:\Users\RUNNER~1\AppData\Local\Temp\mc\receipt.json.new");
    let requested_final =
        std::path::Path::new(r"C:\Users\RUNNER~1\AppData\Local\Temp\mc\receipt.json");
    let observed_source = std::path::Path::new(
        r"\Device\HarddiskVolume3\Users\runneradmin\AppData\Local\Temp\mc\receipt.json.new",
    );
    let observed_final = std::path::Path::new(
        r"\Device\HarddiskVolume3\Users\runneradmin\AppData\Local\Temp\mc\receipt.json",
    );
    assert_eq!(
        verify(
            observed_source,
            observed_final,
            requested_source,
            requested_final,
            7,
            7,
            ID,
            ID,
            1,
            1,
        ),
        Ok(()),
        "8.3 caller spelling must not be compared with canonical handle spelling"
    );

    for (final_path, requested, expected) in [
        (
            r"\Device\HarddiskVolume3\Users\other\receipt.json",
            requested_final,
            Stage::FinalParentVerification,
        ),
        (
            r"\Device\HarddiskVolume3\Users\runneradmin\AppData\Local\Temp\mc\Receipt.json",
            requested_final,
            Stage::FinalComponentVerification,
        ),
        (
            r"\Device\HarddiskVolume3\Users\runneradmin\AppData\Local\Temp\mc\café.json",
            std::path::Path::new(r"C:\Users\RUNNER~1\AppData\Local\Temp\mc\café.json"),
            Stage::FinalComponentVerification,
        ),
    ] {
        assert_eq!(
            verify(
                observed_source,
                std::path::Path::new(final_path),
                requested_source,
                requested,
                7,
                7,
                ID,
                ID,
                1,
                1,
            ),
            Err(expected),
            "unexpected transition result for {final_path}"
        );
    }

    for (volume_after, id_after, source_links, final_links, expected) in [
        (8, ID, 1, 1, Stage::VolumeIdentityVerification),
        (7, [0xa5; 16], 1, 1, Stage::FileIdentityVerification),
        (7, ID, 2, 1, Stage::SourceLinkCountBeforeRenameVerification),
        (7, ID, 1, 2, Stage::FinalLinkCountAfterRenameVerification),
    ] {
        assert_eq!(
            verify(
                observed_source,
                observed_final,
                requested_source,
                requested_final,
                7,
                volume_after,
                ID,
                id_after,
                source_links,
                final_links,
            ),
            Err(expected)
        );
    }

    for (source, final_path, requested_source, requested_final) in [
        (
            r"\Device\HarddiskVolume3\stage.new",
            r"\Device\HarddiskVolume3\final",
            r"C:\stage.new",
            r"C:\final",
        ),
        (
            r"\Device\Mup\server\share\stage.new",
            r"\Device\Mup\server\share\final",
            r"\\server\share\stage.new",
            r"\\server\share\final",
        ),
        (
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\stage.new",
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\final",
            r"C:\stage.new",
            r"C:\final",
        ),
    ] {
        assert_eq!(
            verify(
                std::path::Path::new(source),
                std::path::Path::new(final_path),
                std::path::Path::new(requested_source),
                std::path::Path::new(requested_final),
                7,
                7,
                ID,
                ID,
                1,
                1,
            ),
            Ok(()),
            "opaque canonical root form was rejected: {source}"
        );
    }
}

#[test]
fn create_once_publication_rejects_a_multiply_link_staging_object_before_rename() {
    let temporary = tempfile::tempdir().unwrap();
    let destination = temporary.path().join("receipt.json");
    let staged = temporary.path().join("receipt.json.new");
    let alias = temporary.path().join("receipt.json.alias");
    let mut file = crate::windows::record::CreateOnceStagingFile::create(&staged).unwrap();
    std::io::Write::write_all(file.file_mut(), b"link-count evidence\n").unwrap();
    file.sync_all().unwrap();
    std::fs::hard_link(&staged, &alias).unwrap();

    let error = crate::windows::record::publish_create_once_atomically(file, &destination)
        .expect_err("multiply linked staging object was published");
    assert_eq!(
        error.stage(),
        crate::windows::record::CreateOncePublicationStage::SourceLinkCountBeforeRenameVerification
    );
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.raw_os_error().is_none());
    assert!(!destination.exists());
    assert_eq!(std::fs::read(&staged).unwrap(), b"link-count evidence\n");
    assert_eq!(std::fs::read(&alias).unwrap(), b"link-count evidence\n");
}

#[test]
fn qualification_publishers_retain_only_the_create_once_staging_delete_capability() {
    let temporary = tempfile::tempdir().unwrap();
    let marker_root = temporary.path().join("certification-markers");
    std::fs::create_dir(&marker_root).unwrap();
    SecurityDescriptor::from_sddl(&certification_marker_state_sddl().unwrap())
        .unwrap()
        .apply_to_path(&marker_root)
        .unwrap();

    assert_qualification_create_once_for_write_restricted_token(
        &marker_root,
        "target-result",
        "target.result",
        crate::windows::qualification::QualificationPublicationProducerForTest::TargetResult,
    );
    assert_qualification_create_once_for_write_restricted_token(
        &marker_root,
        "nested-child",
        "nested-child.json",
        crate::windows::qualification::QualificationPublicationProducerForTest::NestedChild,
    );
}

#[test]
fn cleanup_create_once_publication_withholds_delete_child_from_restricted_producers() {
    const READ_CONTROL_ACCESS: u32 = 0x0002_0000;

    let temporary = tempfile::tempdir().unwrap();
    let marker_root = temporary.path().join("certification-markers");
    std::fs::create_dir(&marker_root).unwrap();
    let marker_sddl = certification_marker_state_sddl().unwrap();
    assert!(
        !marker_sddl.contains("G:"),
        "the live AccessCheck regression requires policy-omitted group selection"
    );
    SecurityDescriptor::from_sddl(&marker_sddl)
        .unwrap()
        .apply_to_path(&marker_root)
        .unwrap();
    let marker_root_security = open_retained_directory(&marker_root, READ_CONTROL_ACCESS).unwrap();

    assert_cleanup_create_once_for_current_token(
        &marker_root,
        marker_root_security.raw(),
        "elevated",
        None,
    );
    {
        let token = crate::windows::token::impersonate_restricted_current_thread().unwrap();
        assert_cleanup_create_once_for_current_token(
            &marker_root,
            marker_root_security.raw(),
            "restricted",
            Some(&token),
        );
        token.revert().unwrap();
    }
    {
        let token = crate::windows::token::impersonate_ordinary_current_thread().unwrap();
        assert_cleanup_create_once_for_current_token(
            &marker_root,
            marker_root_security.raw(),
            "ordinary",
            Some(&token),
        );
        token.revert().unwrap();
    }
    {
        let token = crate::windows::token::impersonate_write_restricted_current_thread().unwrap();
        assert_cleanup_create_once_for_current_token(
            &marker_root,
            marker_root_security.raw(),
            "write-restricted",
            Some(&token),
        );
        token.revert().unwrap();
    }
    {
        let token = crate::windows::token::impersonate_low_integrity_current_thread().unwrap();
        assert_cleanup_create_once_for_current_token(
            &marker_root,
            marker_root_security.raw(),
            "low-integrity",
            Some(&token),
        );
        token.revert().unwrap();
    }
    {
        let token = crate::windows::token::impersonate_deny_only_admin_current_thread().unwrap();
        assert_cleanup_create_once_for_current_token(
            &marker_root,
            marker_root_security.raw(),
            "deny-only",
            Some(&token),
        );
        token.revert().unwrap();
    }
}

#[test]
fn exact_predecessor_grants_write_restricted_delete_child_and_migrates_to_denial() {
    const FILE_DELETE_CHILD: u32 = 0x0000_0040;
    const READ_CONTROL_ACCESS: u32 = 0x0002_0000;

    let temporary = tempfile::tempdir().unwrap();
    let marker_root = temporary.path().join("certification-markers");
    std::fs::create_dir(&marker_root).unwrap();
    let predecessor = SecurityDescriptor::from_sddl(
        &pre_destructive_authority_hardening_certification_marker_state_sddl().unwrap(),
    )
    .unwrap();
    predecessor.apply_to_path(&marker_root).unwrap();
    let marker_root_security = open_retained_directory(&marker_root, READ_CONTROL_ACCESS).unwrap();

    {
        let token = crate::windows::token::impersonate_write_restricted_current_thread().unwrap();
        token
            .with_effective_token_for_test(|effective| {
                let (allowed, granted) = predecessor
                    .kernel_object_access_check_for_test(
                        marker_root_security.raw(),
                        effective,
                        FILE_DELETE_CHILD,
                    )
                    .unwrap();
                assert!(allowed);
                assert_eq!(granted & FILE_DELETE_CHILD, FILE_DELETE_CHILD);
                let opened = open_retained_directory(&marker_root, FILE_DELETE_CHILD)
                    .expect("exact predecessor no longer reproduces the native BA grant");
                assert_ne!(
                    crate::windows::token::granted_handle_access(opened.raw()).unwrap()
                        & FILE_DELETE_CHILD,
                    0
                );
                Ok(())
            })
            .unwrap();
        token.revert().unwrap();
    }

    crate::windows::package::reconcile_certification_marker_security(&marker_root).unwrap();
    let current =
        SecurityDescriptor::from_sddl(&certification_marker_state_sddl().unwrap()).unwrap();
    current.verify_path(&marker_root).unwrap();
    {
        let token = crate::windows::token::impersonate_write_restricted_current_thread().unwrap();
        token
            .with_effective_token_for_test(|effective| {
                let (allowed, granted) = current
                    .kernel_object_access_check_for_test(
                        marker_root_security.raw(),
                        effective,
                        FILE_DELETE_CHILD,
                    )
                    .unwrap();
                assert!(!allowed);
                assert_eq!(granted & FILE_DELETE_CHILD, 0);
                assert_eq!(
                    open_retained_directory(&marker_root, FILE_DELETE_CHILD).unwrap_err(),
                    std::io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32).to_string()
                );
                Ok(())
            })
            .unwrap();
        token.revert().unwrap();
    }
}

#[test]
fn retired_workspace_cleanup_uses_the_complete_cleanup_protocol_inventory() {
    let temporary = tempfile::tempdir().unwrap();
    let marker_root = temporary.path().join("certification-markers");
    std::fs::create_dir(&marker_root).unwrap();
    let digest_length = crate::windows::record::digest(&[]).len();
    let retired = marker_root.join(format!("attempt-{}", "0".repeat(digest_length)));
    std::fs::create_dir(&retired).unwrap();
    let retired_paths =
        crate::windows::package::retired_certification_workspace_paths_for_test(&retired);
    assert_eq!(retired_paths.len(), 25);
    assert_eq!(
        retired_paths
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        retired_paths.len()
    );
    for path in retired_paths {
        std::fs::write(path, b"retired protocol evidence\n").unwrap();
    }
    crate::windows::package::remove_retired_certification_workspaces_for_test(&marker_root)
        .unwrap();
    assert!(!retired.exists());

    let unexpected = marker_root.join(format!("attempt-{}", "1".repeat(digest_length)));
    std::fs::create_dir(&unexpected).unwrap();
    let evidence = unexpected.join("unexpected.evidence");
    std::fs::write(&evidence, b"must remain visible\n").unwrap();
    assert!(
        crate::windows::package::remove_retired_certification_workspaces_for_test(&marker_root)
            .is_err()
    );
    assert_eq!(std::fs::read(evidence).unwrap(), b"must remain visible\n");
}

#[test]
fn certification_marker_security_migrates_only_exact_legacy_policies() {
    let temporary = tempfile::tempdir().unwrap();
    let expected_sddl = certification_marker_state_sddl().unwrap();
    let expected = SecurityDescriptor::from_sddl(&expected_sddl).unwrap();
    let policies = [
        expected_sddl.clone(),
        pre_destructive_authority_hardening_certification_marker_state_sddl().unwrap(),
        pre_write_restricted_certification_marker_state_sddl().unwrap(),
        package_state_sddl().unwrap(),
    ];
    for (index, policy) in policies.into_iter().enumerate() {
        let path = temporary.path().join(format!("recognized-{index}"));
        std::fs::create_dir(&path).unwrap();
        SecurityDescriptor::from_sddl(&policy)
            .unwrap()
            .apply_to_path(&path)
            .unwrap();
        crate::windows::package::reconcile_certification_marker_security(&path).unwrap();
        expected.verify_path(&path).unwrap();
    }

    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME).unwrap();
    let drifted = [
        expected_sddl.replacen("(A;OICI;0x001f01bf;;;BA)", "(A;OICI;FA;;;BA)", 1),
        expected_sddl.replacen("(A;OICI;0x001f01bf;;;BA)", "(A;OI;0x001f01bf;;;BA)", 1),
        expected_sddl.replacen("(A;OICI;FA;;;SY)", "(A;OICI;0x001f01bf;;;SY)", 1),
        expected_sddl.replacen("(A;;0x00000024;;;WR)", "", 1),
        expected_sddl.replacen(
            &format!("(A;OICIIO;GRGWGX;;;{launcher})"),
            &format!("(A;OICIIO;GRGWGXSD;;;{launcher})"),
            1,
        ),
    ];
    for (index, drift_sddl) in drifted.into_iter().enumerate() {
        assert_ne!(drift_sddl, expected_sddl, "drift mutant {index} was inert");
        let drift_path = temporary.path().join(format!("arbitrary-drift-{index}"));
        std::fs::create_dir(&drift_path).unwrap();
        let drift = SecurityDescriptor::from_sddl(&drift_sddl).unwrap();
        drift.apply_to_path(&drift_path).unwrap();
        assert!(
            crate::windows::package::reconcile_certification_marker_security(&drift_path).is_err(),
            "drift mutant {index} was accepted as historical policy"
        );
        drift.verify_path(&drift_path).unwrap();
    }
}

fn open_retained_directory(
    path: &std::path::Path,
    desired_access: u32,
) -> Result<crate::windows::pipe::OwnedHandle, String> {
    use std::os::windows::ffi::OsStrExt;

    let path = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: the path is NUL-terminated and the exact directory is opened
    // without following its final reparse point.
    let raw = unsafe {
        CreateFileW(
            path.as_ptr(),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    crate::windows::pipe::OwnedHandle::new(raw)
}

#[test]
fn marker_label_transition_requires_write_owner_and_round_trips_on_the_retained_handle() {
    const DELETE_ACCESS: u32 = 0x0001_0000;
    const READ_CONTROL_ACCESS: u32 = 0x0002_0000;
    const WRITE_DAC_ACCESS: u32 = 0x0004_0000;
    const WRITE_OWNER_ACCESS: u32 = 0x0008_0000;
    const DACL_TRANSITION_ACCESS: u32 = DELETE_ACCESS | READ_CONTROL_ACCESS | WRITE_DAC_ACCESS;

    let temporary = tempfile::tempdir().unwrap();
    let marker = certification_marker_state_sddl().unwrap();
    let marker_without_owner = marker.strip_prefix("O:BA").unwrap();
    let applied = SecurityDescriptor::from_sddl(marker_without_owner).unwrap();
    let expected = SecurityDescriptor::from_sddl(&marker).unwrap();

    let denied_root = temporary.path().join("without-write-owner");
    std::fs::create_dir(&denied_root).unwrap();
    SecurityDescriptor::from_sddl(&state_bootstrap_sddl().unwrap())
        .unwrap()
        .apply_to_path(&denied_root)
        .unwrap();
    let denied = open_retained_directory(&denied_root, DACL_TRANSITION_ACCESS).unwrap();
    assert_eq!(
        applied.apply_to_file_object(denied.raw()).unwrap_err(),
        std::io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32).to_string(),
    );

    let retained_root = temporary.path().join("with-write-owner");
    std::fs::create_dir(&retained_root).unwrap();
    SecurityDescriptor::from_sddl(&state_bootstrap_sddl().unwrap())
        .unwrap()
        .apply_to_path(&retained_root)
        .unwrap();
    let retained =
        open_retained_directory(&retained_root, DACL_TRANSITION_ACCESS | WRITE_OWNER_ACCESS)
            .unwrap();
    applied.apply_to_file_object(retained.raw()).unwrap();
    expected.verify_file_object(retained.raw()).unwrap();
}

#[test]
fn file_security_comparison_accepts_only_provider_representation_equivalence() {
    let exact = "O:SYD:P(A;OICI;GR;;;SY)S:(ML;OICI;NW;;;LW)";
    let provider_result = "O:SYD:PAI(A;;GR;;;SY)(A;OICIIO;GR;;;SY)S:AI(ML;OICI;NW;;;LW)";
    compare_file_security_sddl_for_test(exact, provider_result).unwrap();

    for drift in [
        // Protection and auto-inherit request are policy, unlike resultant AI.
        "O:SYD:(A;;GR;;;SY)(A;OICIIO;GR;;;SY)S:AI(ML;OICI;NW;;;LW)",
        "O:SYD:PAR(A;;GR;;;SY)(A;OICIIO;GR;;;SY)S:AI(ML;OICI;NW;;;LW)",
        "O:SYD:PAI(A;;GR;;;SY)(A;OICIIO;GR;;;SY)S:PAR(ML;OICI;NW;;;LW)",
        "O:SYD:PAI(A;;GR;;;SY)(A;OICIIO;GR;;;SY)S:AR(ML;OICI;NW;;;LW)",
        // Both the effective and inheritance facets are mandatory and unique.
        "O:SYD:PAI(A;;GR;;;SY)S:AI(ML;OICI;NW;;;LW)",
        "O:SYD:PAI(A;OICIIO;GR;;;SY)S:AI(ML;OICI;NW;;;LW)",
        "O:SYD:PAI(A;;GR;;;SY)(A;;GR;;;SY)(A;OICIIO;GR;;;SY)S:AI(ML;OICI;NW;;;LW)",
        // Scope, provenance, mask, trustee, owner, and label remain exact.
        "O:SYD:PAI(A;;GR;;;SY)(A;OIIO;GR;;;SY)S:AI(ML;OICI;NW;;;LW)",
        "O:SYD:PAI(A;ID;GR;;;SY)(A;OICIIO;GR;;;SY)S:AI(ML;OICI;NW;;;LW)",
        "O:SYD:PAI(A;;GW;;;SY)(A;OICIIO;GR;;;SY)S:AI(ML;OICI;NW;;;LW)",
        "O:SYD:PAI(A;;GR;;;BA)(A;OICIIO;GR;;;SY)S:AI(ML;OICI;NW;;;LW)",
        "O:BAD:PAI(A;;GR;;;SY)(A;OICIIO;GR;;;SY)S:AI(ML;OICI;NW;;;LW)",
        "O:SYD:PAI(A;;GR;;;SY)(A;OICIIO;GR;;;SY)S:AI(ML;OICI;NR;;;LW)",
        "O:SYD:PAI(A;;GR;;;SY)(A;OICIIO;GR;;;SY)S:AI(ML;OICI;NW;;;ME)",
    ] {
        assert!(
            compare_file_security_sddl_for_test(exact, drift).is_err(),
            "unexpectedly accepted file security drift: {drift}"
        );
    }

    let ordered = "D:P(D;OICI;GR;;;BA)(A;OICI;GR;;;SY)";
    let reordered = "D:PAI(A;;GR;;;SY)(A;OICIIO;GR;;;SY)(D;;GR;;;BA)(D;OICIIO;GR;;;BA)";
    assert!(compare_file_security_sddl_for_test(ordered, reordered).is_err());

    let no_propagate = "D:P(A;OICINP;GR;;;SY)";
    let broadened = "D:PAI(A;;GR;;;SY)(A;OICIIO;GR;;;SY)";
    assert!(compare_file_security_sddl_for_test(no_propagate, broadened).is_err());
}

#[test]
fn labeled_retained_directory_restores_bootstrap_security_semantically() {
    const DELETE_ACCESS: u32 = 0x0001_0000;
    const READ_CONTROL_ACCESS: u32 = 0x0002_0000;
    const WRITE_DAC_ACCESS: u32 = 0x0004_0000;
    const WRITE_OWNER_ACCESS: u32 = 0x0008_0000;

    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("rollback-marker");
    std::fs::create_dir(&root).unwrap();
    let bootstrap = state_bootstrap_sddl().unwrap();
    SecurityDescriptor::from_sddl(&bootstrap)
        .unwrap()
        .apply_to_path(&root)
        .unwrap();
    let retained = open_retained_directory(
        &root,
        DELETE_ACCESS | READ_CONTROL_ACCESS | WRITE_DAC_ACCESS | WRITE_OWNER_ACCESS,
    )
    .unwrap();

    let marker = certification_marker_state_sddl().unwrap();
    SecurityDescriptor::from_sddl(marker.strip_prefix("O:BA").unwrap())
        .unwrap()
        .apply_to_file_object(retained.raw())
        .unwrap();
    SecurityDescriptor::from_sddl(&marker)
        .unwrap()
        .verify_file_object(retained.raw())
        .unwrap();

    SecurityDescriptor::from_sddl(bootstrap.strip_prefix("O:BA").unwrap())
        .unwrap()
        .apply_to_file_object(retained.raw())
        .unwrap();
    SecurityDescriptor::from_sddl(&format!("{bootstrap}S:(ML;OICI;NW;;;LW)"))
        .unwrap()
        .verify_file_object(retained.raw())
        .unwrap();
}

#[test]
fn low_integrity_marker_access_is_scoped_below_the_shared_root() {
    const DELETE_ACCESS: u32 = 0x0001_0000;

    let temporary = tempfile::tempdir().unwrap();
    let marker_root = temporary.path().join("certification-markers");
    std::fs::create_dir(&marker_root).unwrap();
    SecurityDescriptor::from_sddl(&certification_marker_state_sddl().unwrap())
        .unwrap()
        .apply_to_path(&marker_root)
        .unwrap();

    {
        let _low_integrity = crate::windows::token::impersonate_low_integrity_current_thread()
            .expect("low-integrity fixture must be available");
        let workspace = marker_root.join("attempt-low-integrity");
        std::fs::create_dir(&workspace).expect("root must allow bound workspace creation");
        std::fs::write(workspace.join("cleanup.result"), b"retired\n")
            .expect("inherited workspace rights must allow protocol leaves");
        assert_eq!(
            std::fs::write(marker_root.join("unbound-root-file"), b"denied\n")
                .unwrap_err()
                .raw_os_error(),
            Some(ERROR_ACCESS_DENIED as i32),
        );
        let delete_error = match open_retained_directory(&marker_root, DELETE_ACCESS) {
            Ok(_) => panic!("low-integrity target acquired shared-root delete authority"),
            Err(error) => error,
        };
        assert_eq!(
            delete_error,
            std::io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32).to_string(),
        );
    }
}

#[test]
fn job_process_inventory_deduplicates_the_full_process_identity() {
    let first = memcordon_core::WindowsProcessIdentityV1 {
        process_id: 41,
        creation_time_100ns: 100,
    };
    let reused = memcordon_core::WindowsProcessIdentityV1 {
        process_id: 41,
        creation_time_100ns: 200,
    };
    let mut inventory = Vec::new();

    crate::windows::launcher_service::record_job_process_identity(&mut inventory, first.clone())
        .unwrap();
    crate::windows::launcher_service::record_job_process_identity(&mut inventory, first.clone())
        .unwrap();
    crate::windows::launcher_service::record_job_process_identity(&mut inventory, reused.clone())
        .unwrap();

    assert_eq!(inventory, vec![first, reused]);
}

#[test]
fn mutex_readback_accepts_generic_mapping_and_rejects_missing_rights() {
    let expected = SecurityDescriptor::from_sddl("D:P(A;;GA;;;SY)(A;;GA;;;BA)").unwrap();
    let attributes = expected.attributes(false);
    // SAFETY: attributes and its descriptor remain live; null creates an
    // unnamed mutex owned only through the returned handle.
    let mutex = unsafe { CreateMutexW(&raw const attributes, 0, ptr::null()) };
    assert!(!mutex.is_null(), "CreateMutexW failed");

    assert!(
        expected
            .verify_kernel_object(mutex, SecurityObjectKind::Mutex)
            .is_ok()
    );
    let weakened = SecurityDescriptor::from_sddl("D:P(A;;0x001f0000;;;SY)(A;;GA;;;BA)").unwrap();
    assert!(
        weakened
            .verify_kernel_object(mutex, SecurityObjectKind::Mutex)
            .is_err()
    );

    // SAFETY: mutex is the live handle returned above and is closed once.
    unsafe { CloseHandle(mutex) };
}

#[test]
fn named_pipe_preparation_supports_security_readback() {
    let pipe_name = format!(
        r"\\.\pipe\memcordon-security-readback-{}",
        std::process::id()
    );
    let sddl = test_public_pipe_sddl();
    let descriptor = SecurityDescriptor::from_sddl(&sddl).unwrap();
    let listener = PipeListener::new(&pipe_name, descriptor);

    let pipe = listener.prepare().unwrap();
    SecurityDescriptor::from_sddl(&sddl)
        .unwrap()
        .verify_named_pipe(pipe.raw())
        .unwrap();
}

fn assert_server_response_is_drained_before_disconnect(payload: String) {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::time::Duration;

    static NEXT_PIPE: AtomicU64 = AtomicU64::new(0);

    let pipe_name = format!(
        r"\\.\pipe\memcordon-response-drain-{}-{}",
        std::process::id(),
        NEXT_PIPE.fetch_add(1, Ordering::Relaxed),
    );
    let listener = PipeListener::new(
        &pipe_name,
        SecurityDescriptor::from_sddl(&test_public_pipe_sddl()).unwrap(),
    );
    let (written_sender, written_receiver) = mpsc::channel();
    let (finished_sender, finished_receiver) = mpsc::channel();
    let expected = payload.clone();
    let server = std::thread::spawn(move || {
        let connection = listener.accept().unwrap();
        crate::windows::pipe::write_frame(connection.raw(), &payload).unwrap();
        written_sender.send(()).unwrap();
        let result = crate::windows::pipe::finish_server_response(connection.raw());
        finished_sender.send(result).unwrap();
    });

    let client = crate::windows::pipe::connect(&pipe_name).unwrap();
    written_receiver.recv().unwrap();
    assert!(matches!(
        finished_receiver.recv_timeout(Duration::from_millis(100)),
        Err(RecvTimeoutError::Timeout)
    ));
    let received: String = crate::windows::pipe::read_frame(client.raw()).unwrap();
    assert_eq!(received, expected);
    finished_receiver
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap();
    server.join().unwrap();
}

#[test]
fn server_response_completion_waits_for_small_and_large_frames_to_be_consumed() {
    assert_server_response_is_drained_before_disconnect("probe".to_owned());
    assert_server_response_is_drained_before_disconnect("x".repeat(32 * 1024));
}

fn assert_abrupt_frame_read_phase(
    write_length: bool,
    expected: crate::windows::pipe::FrameReadPhase,
) {
    use windows_sys::Win32::Storage::FileSystem::WriteFile;

    let pipe_name = format!(
        r"\\.\pipe\memcordon-frame-diagnostic-{}-{}",
        std::process::id(),
        if write_length { "payload" } else { "length" },
    );
    let listener = PipeListener::new(
        &pipe_name,
        SecurityDescriptor::from_sddl(&test_public_pipe_sddl()).unwrap(),
    );
    let server = std::thread::spawn(move || {
        let connection = listener.accept().unwrap();
        if write_length {
            let length = 16_u32.to_le_bytes();
            let mut written = 0_u32;
            // SAFETY: the four-byte length and output count remain live for the
            // synchronous write to the connected server pipe.
            assert_ne!(
                unsafe {
                    WriteFile(
                        connection.raw(),
                        length.as_ptr(),
                        u32::try_from(length.len()).unwrap(),
                        &raw mut written,
                        ptr::null_mut(),
                    )
                },
                0
            );
            assert_eq!(written, 4);
            crate::windows::pipe::finish_server_response(connection.raw()).unwrap();
        } else {
            crate::windows::pipe::disconnect(connection.raw());
        }
    });

    let client = crate::windows::pipe::connect(&pipe_name).unwrap();
    let error = crate::windows::pipe::read_frame_detailed::<String>(client.raw()).unwrap_err();
    assert_eq!(error.phase, expected);
    assert!(error.peer_closed);
    assert!(error.native_code.is_some());
    server.join().unwrap();
}

#[test]
fn frame_read_diagnostics_distinguish_length_payload_decode_and_peer_close() {
    assert_abrupt_frame_read_phase(false, crate::windows::pipe::FrameReadPhase::Length);
    assert_abrupt_frame_read_phase(true, crate::windows::pipe::FrameReadPhase::Payload);

    let pipe_name = format!(
        r"\\.\pipe\memcordon-frame-diagnostic-{}-decode",
        std::process::id(),
    );
    let listener = PipeListener::new(
        &pipe_name,
        SecurityDescriptor::from_sddl(&test_public_pipe_sddl()).unwrap(),
    );
    let server = std::thread::spawn(move || {
        let connection = listener.accept().unwrap();
        crate::windows::pipe::write_frame(connection.raw(), &"not-a-number").unwrap();
        crate::windows::pipe::finish_server_response(connection.raw()).unwrap();
    });
    let client = crate::windows::pipe::connect(&pipe_name).unwrap();
    let error = crate::windows::pipe::read_frame_detailed::<u32>(client.raw()).unwrap_err();
    assert_eq!(error.phase, crate::windows::pipe::FrameReadPhase::Decode);
    assert!(!error.peer_closed);
    assert_eq!(error.native_code, None);
    server.join().unwrap();
}

#[test]
fn named_pipe_security_readback_rejects_policy_mutations() {
    const SYSTEM_ACE: &str = "(A;;GA;;;SY)";
    const FIRST_CLIENT_ACE: &str = "(A;;0x0012019b;;;AU)";
    const LOW_LABEL: &str = "S:(ML;;NW;;;LW)";

    let pipe_name = format!(
        r"\\.\pipe\memcordon-security-mutation-{}",
        std::process::id()
    );
    let sddl = test_public_pipe_sddl();
    let listener = PipeListener::new(&pipe_name, SecurityDescriptor::from_sddl(&sddl).unwrap());
    let pipe = listener.prepare().unwrap();

    let (owner_and_dacl, after_system) = sddl.split_once(SYSTEM_ACE).unwrap();
    let (_, after_control) = after_system.split_once(FIRST_CLIENT_ACE).unwrap();
    let without_control = format!("{owner_and_dacl}{SYSTEM_ACE}{FIRST_CLIENT_ACE}{after_control}");
    let missing_client_right = sddl.replacen("0x0012019b;;;AU", "0x0012019a;;;AU", 1);
    let extra_trustee = sddl.replacen(LOW_LABEL, "(A;;GR;;;WD)S:(ML;;NW;;;LW)", 1);

    assert!(matches!(
        SecurityDescriptor::from_sddl(&without_control)
            .unwrap()
            .verify_named_pipe(pipe.raw()),
        Err(NamedPipeSecurityError::Mismatch(
            NamedPipeSecurityMismatch::AceCount { .. }
        ))
    ));
    assert!(matches!(
        SecurityDescriptor::from_sddl(&missing_client_right)
            .unwrap()
            .verify_named_pipe(pipe.raw()),
        Err(NamedPipeSecurityError::Mismatch(
            NamedPipeSecurityMismatch::AceMask { .. }
        ))
    ));
    assert!(matches!(
        SecurityDescriptor::from_sddl(&extra_trustee)
            .unwrap()
            .verify_named_pipe(pipe.raw()),
        Err(NamedPipeSecurityError::Mismatch(
            NamedPipeSecurityMismatch::AceCount { .. }
        ))
    ));

    let wrong_owner = sddl.replacen(sddl.split_once("D:").unwrap().0, "O:S-1-5-7", 1);
    assert!(matches!(
        SecurityDescriptor::from_sddl(&wrong_owner)
            .unwrap()
            .verify_named_pipe(pipe.raw()),
        Err(NamedPipeSecurityError::Mismatch(
            NamedPipeSecurityMismatch::Owner { .. }
        ))
    ));

    let wrong_label_name = format!(
        r"\\.\pipe\memcordon-security-wrong-label-{}",
        std::process::id()
    );
    let wrong_label = sddl.replacen(LOW_LABEL, "S:(ML;;NW;;;ME)", 1);
    let wrong_label_listener = PipeListener::new(
        &wrong_label_name,
        SecurityDescriptor::from_sddl(&wrong_label).unwrap(),
    );
    let wrong_label_pipe = wrong_label_listener.prepare().unwrap();
    assert!(matches!(
        SecurityDescriptor::from_sddl(&sddl)
            .unwrap()
            .verify_named_pipe(wrong_label_pipe.raw()),
        Err(NamedPipeSecurityError::Mismatch(
            NamedPipeSecurityMismatch::LabelAceTrustee { .. }
        ))
    ));
}

#[test]
fn pipe_preparation_errors_have_stable_service_subphases() {
    let (phase, detail) = crate::windows::control_service::pipe_startup_error(
        PipePreparationError::Creation("native".to_owned()),
    );
    assert_eq!(phase, 0x4d43_0103);
    assert!(detail.starts_with("MCSEALED-WINDOWS-PIPE-CREATE:"));

    let (phase, detail) = crate::windows::control_service::pipe_startup_error(
        PipePreparationError::SecurityReadback("native".to_owned()),
    );
    assert_eq!(phase, 0x4d43_0107);
    assert!(detail.starts_with("MCSEALED-WINDOWS-PIPE-SECURITY-READBACK:"));

    let (phase, detail) = crate::windows::control_service::pipe_startup_error(
        PipePreparationError::SecurityMismatch(NamedPipeSecurityMismatch::AceMask {
            index: 2,
            expected: 0x0012_019b,
            actual: 0x0012_019a,
        }),
    );
    assert_eq!(phase, 0x4d43_010e);
    assert!(detail.starts_with("MCSEALED-WINDOWS-PIPE-SECURITY-MISMATCH:"));
    assert!(detail.contains("component=dacl-ace-mask"));
    assert_eq!(
        crate::windows::security::pipe_mismatch_diagnostic_from_exit(phase),
        Some(("public", "dacl-ace-mask"))
    );
}

#[test]
fn service_process_owners_match_their_configured_accounts_and_scope_profile_privileges() {
    let control = service_process_sddl(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME).unwrap();
    let launcher = service_process_sddl(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME).unwrap();

    assert!(control.starts_with("O:LS"));
    assert!(control.contains("(D;;WDWO;;;OW)"));
    assert!(launcher.starts_with("O:SY"));
    assert_eq!(CONTROL_PRIVILEGES, &["SeImpersonatePrivilege"]);
    assert!(!CONTROL_PRIVILEGES.contains(&"SeRestorePrivilege"));
    assert_eq!(
        LAUNCHER_PRIVILEGES,
        &[
            "SeAssignPrimaryTokenPrivilege",
            "SeBackupPrivilege",
            "SeIncreaseQuotaPrivilege",
            "SeRestorePrivilege",
            "SeTcbPrivilege",
        ]
    );
    assert_eq!(
        SESSION_BROKER_PRIVILEGES,
        &[
            "SeAssignPrimaryTokenPrivilege",
            "SeIncreaseQuotaPrivilege",
            "SeImpersonatePrivilege",
            "SeSecurityPrivilege",
            "SeTcbPrivilege",
        ]
    );
    assert!(!LAUNCHER_PRIVILEGES.contains(&"SeSecurityPrivilege"));
    assert!(!CONTROL_PRIVILEGES.contains(&"SeSecurityPrivilege"));
}

#[test]
fn package_authority_can_only_query_and_synchronize_service_processes() {
    let control = service_process_sddl(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME).unwrap();
    let launcher = service_process_sddl(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME).unwrap();

    for descriptor in [&control, &launcher] {
        assert_eq!(descriptor.matches("(A;;0x00101000;;;BA)").count(), 1);
        assert!(!descriptor.contains("(A;;GA;;;BA)"));
        assert!(!descriptor.contains("(A;;0x00101001;;;BA)"));
        assert!(!descriptor.contains("(A;;0x00101020;;;BA)"));
        assert!(!descriptor.contains("(A;;0x00101040;;;BA)"));
    }
}

#[test]
fn guardian_slots_can_only_query_the_actual_launcher_service_process() {
    let launcher = service_process_sddl(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME).unwrap();

    for index in 0..memcordon_core::WINDOWS_GUARDIAN_SLOT_COUNT {
        let slot = service_sid(&guardian_slot_name(index).unwrap()).unwrap();
        assert_eq!(
            launcher
                .matches(&format!("(A;;0x00001000;;;{slot})"))
                .count(),
            1
        );
        assert_eq!(launcher.matches(&format!(";;;{slot})")).count(), 1);
        assert!(!launcher.contains(&format!("(A;;0x00000800;;;{slot})")));
        assert!(!launcher.contains(&format!("(A;;GA;;;{slot})")));
    }
}

#[test]
fn startup_failure_status_preserves_a_service_specific_phase() {
    let phase = 0x4d43_0104;
    let status = crate::windows::service::service_status(
        SERVICE_STOPPED,
        0,
        ERROR_SERVICE_SPECIFIC_ERROR,
        phase,
        0,
        0,
    );
    assert_eq!(status.dwWin32ExitCode, ERROR_SERVICE_SPECIFIC_ERROR);
    assert_eq!(status.dwServiceSpecificExitCode, phase);
}

#[test]
fn launcher_authentication_failures_have_stable_service_subphases() {
    let cases = [
        (0x4d43_0301, "pipe-connect"),
        (0x4d43_0302, "pipe-policy"),
        (0x4d43_0303, "pipe-security-readback"),
        (0x4d43_0304, "pipe-security-mismatch"),
        (0x4d43_0305, "peer-pid"),
        (0x4d43_0306, "process-open"),
        (0x4d43_0307, "image"),
        (0x4d43_0308, "token-open"),
        (0x4d43_0309, "ordinary-service-sid"),
        (0x4d43_030a, "restricting-service-sid"),
        (0x4d43_030b, "process-identity"),
        (0x4d43_030c, "probe-write"),
        (0x4d43_030d, "probe-read"),
        (0x4d43_030e, "probe-schema"),
        (0x4d43_030f, "probe-identity"),
        (0x4d43_0310, "launcher-peer-rejected"),
        (0x4d43_0311, "probe-response-kind"),
        (0x4d43_0312, "token-user-query"),
        (0x4d43_0313, "account-mismatch"),
    ];
    for (phase, diagnostic) in cases {
        assert_eq!(
            crate::windows::control_service::launcher_authentication_diagnostic_from_exit(phase),
            Some(diagnostic)
        );
    }
}

#[test]
fn reciprocal_token_policy_and_control_authentication_diagnostics_are_stable() {
    let token_policy = [
        (0x4d43_0110, ("control", "token-dacl-open")),
        (0x4d43_0114, ("control", "token-dacl-mismatch")),
        (0x4d43_0210, ("launcher", "token-dacl-open")),
        (0x4d43_0214, ("launcher", "token-dacl-mismatch")),
    ];
    for (code, diagnostic) in token_policy {
        assert_eq!(token_dacl_diagnostic_from_exit(code), Some(diagnostic));
    }

    let control_authentication = [
        (0x4d43_0320, "peer-pid"),
        (0x4d43_0321, "process-open"),
        (0x4d43_0322, "image"),
        (0x4d43_0323, "token-open"),
        (0x4d43_0324, "token-user-query"),
        (0x4d43_0325, "account-mismatch"),
        (0x4d43_0326, "ordinary-service-sid"),
        (0x4d43_0327, "restricting-service-sid"),
    ];
    for (code, diagnostic) in control_authentication {
        assert_eq!(
            crate::windows::control_service::control_authentication_diagnostic_from_exit(code),
            Some(diagnostic)
        );
    }
}

#[test]
fn control_authentication_rejection_codes_are_typed() {
    let cases = [
        ("MCSEALED-WINDOWS-CONTROL-AUTH-PEER-PID", "peer-pid"),
        ("MCSEALED-WINDOWS-CONTROL-AUTH-PROCESS-OPEN", "process-open"),
        ("MCSEALED-WINDOWS-CONTROL-AUTH-IMAGE", "image"),
        ("MCSEALED-WINDOWS-CONTROL-AUTH-TOKEN-OPEN", "token-open"),
        (
            "MCSEALED-WINDOWS-CONTROL-AUTH-TOKEN-USER-QUERY",
            "token-user-query",
        ),
        (
            "MCSEALED-WINDOWS-CONTROL-AUTH-ACCOUNT-MISMATCH",
            "account-mismatch",
        ),
        (
            "MCSEALED-WINDOWS-CONTROL-AUTH-ORDINARY-SID",
            "ordinary-service-sid",
        ),
        (
            "MCSEALED-WINDOWS-CONTROL-AUTH-RESTRICTING-SID",
            "restricting-service-sid",
        ),
    ];
    for (code, subphase) in cases {
        assert_eq!(
            crate::windows::launcher_service::control_authentication_subphase(code),
            Some(subphase)
        );
    }
}
