use std::ffi::c_void;
use std::io;
use std::ptr;

use memcordon_core::{
    WindowsCallerTokenEnvelopeV1, WindowsSealedFault, WindowsServiceSelfAttestationV1,
    windows_service_attestation_challenge_is_valid,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows_sys::Wdk::Foundation::{NtQueryObject, ObjectBasicInformation};
use windows_sys::Wdk::Storage::FileSystem::NtSetInformationToken;
use windows_sys::Win32::Foundation::{
    DuplicateHandle, ERROR_NO_TOKEN, ERROR_NOT_ALL_ASSIGNED, ERROR_SUCCESS, GetHandleInformation,
    GetLastError, HANDLE, HANDLE_FLAG_INHERIT, LUID, LocalFree, RtlNtStatusToDosError,
    STATUS_ACCESS_DENIED, SetLastError,
};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};
use windows_sys::Win32::Security::LookupPrivilegeValueW;
use windows_sys::Win32::Security::{
    ACL, AdjustTokenPrivileges, CreateWellKnownSid, DuplicateTokenEx, EqualSid, GetLengthSid,
    GetTokenInformation, IsTokenRestricted, IsValidSid, LUID_AND_ATTRIBUTES, PRIVILEGE_SET,
    PrivilegeCheck, RevertToSelf, SE_PRIVILEGE_ENABLED, SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES,
    SecurityAnonymous, SecurityDelegation, SecurityImpersonation, SetTokenInformation,
    TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_PRIVILEGES, TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DEFAULT_DACL, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_GROUPS, TOKEN_IMPERSONATE,
    TOKEN_MANDATORY_LABEL, TOKEN_MANDATORY_POLICY, TOKEN_ORIGIN, TOKEN_OWNER, TOKEN_PRIMARY_GROUP,
    TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_QUERY_SOURCE, TOKEN_SOURCE, TOKEN_STATISTICS,
    TokenDefaultDacl, TokenElevation, TokenElevationType, TokenGroups, TokenImpersonation,
    TokenImpersonationLevel, TokenIntegrityLevel, TokenIsAppContainer, TokenLogonSid,
    TokenMandatoryPolicy, TokenOrigin, TokenOwner, TokenPrimary, TokenPrimaryGroup,
    TokenPrivileges, TokenRestrictedSids, TokenSessionId, TokenSource, TokenStatistics,
    TokenUIAccess, TokenUser, TokenVirtualizationAllowed, TokenVirtualizationEnabled,
    WinAuthenticatedUserSid,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, ImpersonateNamedPipeClient};
use windows_sys::Win32::System::SystemServices::{
    SE_GROUP_ENABLED, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_INTEGRITY, SE_GROUP_LOGON_ID,
    SE_GROUP_MANDATORY,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
    PROCESS_DUP_HANDLE, PROCESS_QUERY_LIMITED_INFORMATION, SetThreadToken,
};
use windows_sys::Win32::System::WindowsProgramming::PUBLIC_OBJECT_BASIC_INFORMATION;

use super::pipe::OwnedHandle;

const CALLER_PRIMARY_LAUNCH_ACCESS: u32 = TOKEN_QUERY
    | TOKEN_QUERY_SOURCE
    | TOKEN_DUPLICATE
    | TOKEN_ASSIGN_PRIMARY
    | TOKEN_ADJUST_DEFAULT
    | TOKEN_ADJUST_SESSIONID;
const HOLDER_MUTABLE_TOKEN_ACCESS: u32 = TOKEN_QUERY
    | TOKEN_QUERY_SOURCE
    | TOKEN_DUPLICATE
    | TOKEN_ASSIGN_PRIMARY
    | TOKEN_ADJUST_DEFAULT
    | TOKEN_ADJUST_SESSIONID;
const HOLDER_LAUNCH_TOKEN_ACCESS: u32 =
    TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY;
pub(crate) const SESSION_CREATION_CARRIER_ACCESS: u32 =
    TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_IMPERSONATE | READ_CONTROL_ACCESS;
const PROCESS_TOKEN_QUERY_ACCESS: u32 = TOKEN_QUERY;
const TOKEN_ATTESTATION_ACCESS: u32 = TOKEN_QUERY | TOKEN_QUERY_SOURCE;
const READ_CONTROL_ACCESS: u32 = 0x0002_0000;
const WRITE_DAC_ACCESS: u32 = 0x0004_0000;
const SE_PRIVILEGE_REMOVED: u32 = 0x0000_0004;
const RESTRICTED_CODE_SID: &str = "S-1-5-12";
const AUTHENTICATED_USERS_SID: &str = "S-1-5-11";
const CREATE_RESTRICTED_TOKEN_INPUT_ATTRIBUTES: u32 = 0;
const NORMALIZED_RESTRICTING_SID_ATTRIBUTES: u32 =
    SE_GROUP_MANDATORY as u32 | SE_GROUP_ENABLED_BY_DEFAULT as u32 | SE_GROUP_ENABLED as u32;
const SE_GROUP_USE_FOR_DENY_ONLY_ATTRIBUTES: u32 = 0x0000_0010;
// MS-LSAD 3.1.1.2.1 defines SeChangeNotifyPrivilege as the stable LUID
// { HighPart: 0, LowPart: 23 }. Snapshot normalization must remain a pure
// function of the supplied token handle, including while the caller is
// impersonating a restricted token, so this value is not resolved through LSA.
const SE_CHANGE_NOTIFY_PRIVILEGE_LUID: LUID = LUID {
    LowPart: 23,
    HighPart: 0,
};
const SESSION_BROKER_RAW_SOURCE_PRIVILEGES: &[(&str, bool)] = &[
    ("SeAssignPrimaryTokenPrivilege", false),
    ("SeIncreaseQuotaPrivilege", false),
    ("SeImpersonatePrivilege", true),
    ("SeSecurityPrivilege", false),
    ("SeTcbPrivilege", true),
    ("SeChangeNotifyPrivilege", true),
];
const SESSION_BROKER_NORMALIZED_SOURCE_PRIVILEGES: &[(&str, bool)] = &[
    ("SeAssignPrimaryTokenPrivilege", false),
    ("SeIncreaseQuotaPrivilege", false),
    ("SeImpersonatePrivilege", false),
    ("SeSecurityPrivilege", false),
    ("SeTcbPrivilege", false),
    ("SeChangeNotifyPrivilege", true),
];

use super::{pipe, process, record, security};

mod attestation;
mod derivation;
mod fixture_derivation;
mod query;
mod service_attestation;

pub(crate) use attestation::{
    AssignedProcessTokenEvidenceV1, EntryThreadTokenTransition, InstalledThreadTokenAttestation,
    SessionBrokerSourceError, TokenAttestationDifferenceV1, TokenAttestationRelationError,
    TokenAttestationSnapshot, TokenBehaviorEvidence, TokenInstanceEvidence, TokenLineageEvidence,
    TokenQueryAttestationSnapshot, TokenQueryLineageEvidence, install_thread_token,
    nested_loader_behavior_failures, require_assigned_process_authority,
    require_assigned_token_authority, require_primary_to_impersonation_authority,
    require_same_process_token_query, require_same_token_instance, revert_entry_thread_token,
    token_attestation_snapshot, token_query_attestation_snapshot,
};
pub(crate) use derivation::{
    LauncherHolderTokenDerivation, LauncherHolderTokenDerivationError,
    LauncherHolderTokenDerivationStage, SessionBrokerHolderToken,
    canonical_same_access_restricting_sids, current_process_token_for_access_check,
    current_process_token_for_attestation, current_process_token_for_attestation_and_access_check,
    derive_launcher_holder_primary, derive_session_broker_holder_primary, granted_handle_access,
    normalize_current_session_broker_source_privileges, validate_holder_session_derivation,
    validate_normalized_session_broker_source_snapshot, with_scoped_loader_profile_privileges,
    with_scoped_service_owner_restore_privilege, with_session_broker_launch_privileges,
};
pub(crate) use fixture_derivation::{
    NestedTargetTokens, RestrictedImpersonationGuard, TokenFixtureSnapshot,
    impersonate_deny_only_admin_current_thread, impersonate_low_integrity_current_thread,
    impersonate_ordinary_current_thread, impersonate_restricted_current_thread,
    impersonate_write_restricted_current_thread, nested_target_tokens, restricted_current_primary,
    write_restricted_current_primary,
};
pub(crate) use query::{
    AttachedCreationCarrierGuard, TokenOpenError, TokenRestrictingSidInventory,
    attach_creation_carrier_to_thread, authenticate_pipe_client,
    current_creation_carrier_attestation, current_thread_envelope, current_thread_fixture_snapshot,
    enabled_group_entry_matches, envelope, envelope_mismatch_fields, groups_digest,
    privileges_digest, process_token, process_token_detailed, process_token_query_attestation,
    process_user_sid, require_thread_token_absent, restricted_sid_count,
    restricting_sid_entry_matches, revert_creation_carrier_and_attest_absent, sid_string,
    thread_token_attestation, token_group_entries, token_has_enabled_group,
    token_has_restricting_sid, token_is_restricted, token_logon_sid, token_privilege_entries,
    token_restricting_sid_attributes, token_restricting_sid_inventory, token_restricting_sids,
    token_user_sid,
};
pub(crate) use service_attestation::{
    ServiceSelfAttestationError, current_service_self_attestation, pipe_client_is_elevated,
    service_attestation_challenge,
};

#[cfg(test)]
pub(crate) use derivation::{
    canonical_same_access_restricting_sids_for_test,
    exact_disabled_privilege_set_transition_for_test, holder_access_mask_readback_for_test,
    nested_initial_thread_token_for_test, normalized_session_broker_privilege_entries_for_test,
    validate_authenticated_users_matches_for_test, validate_logon_sid_group_inventory_for_test,
    validate_target_user_matches_for_test, validate_token_logon_sid_attributes_for_test,
};
#[cfg(test)]
pub(crate) use fixture_derivation::{
    effective_thread_token_identity_validation_for_test, restricted_fixture_open_error_for_test,
};
#[cfg(test)]
pub(crate) use query::{privilege_is_enabled_sensitive_for_test, token_query_error_for_test};
#[cfg(test)]
pub(crate) use service_attestation::process_envelope;
