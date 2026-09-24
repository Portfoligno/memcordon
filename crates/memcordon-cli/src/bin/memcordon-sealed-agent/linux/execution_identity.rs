//! Native target-identity transition for a future qualified private profile.
//! Resolving administrator authority here is not an executable-file proof or
//! permission to release the target; both remain separate prelaunch gates.

use memcordon_core::workload_contract::ExecutionIdentityRequestV2;
use memcordon_core::workload_registry_v2::LinuxExecutionIdentityV2;

use crate::request::CallerExecutionEnvelopeV2;

// Linux UAPI securebits.h: NOROOT and NO_SETUID_FIXUP are set and locked;
// KEEP_CAPS is off and locked; ambient raising is denied and locked.
const SECURE_BITS_REQUIRED: libc::c_ulong =
    (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 5) | (1 << 6) | (1 << 7);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedTargetIdentity {
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
    delegated: bool,
}

impl ResolvedTargetIdentity {
    pub const fn uid(&self) -> libc::uid_t {
        self.uid
    }

    pub const fn gid(&self) -> libc::gid_t {
        self.gid
    }

    pub fn groups(&self) -> &[libc::gid_t] {
        &self.groups
    }

    pub const fn delegated(&self) -> bool {
        self.delegated
    }
}

/// `record` must be the one selected by an authenticated, exact V2 grant.
/// The provider and guardian identities are explicit inputs so a dedicated
/// candidate cannot silently reuse a trusted service principal. `caller`
/// must come from the authenticated native capture path, which rejects active
/// capability sets; the envelope itself does not carry those set values.
pub fn resolve_target_identity(
    request: &ExecutionIdentityRequestV2,
    record: Option<&LinuxExecutionIdentityV2>,
    caller: &CallerExecutionEnvelopeV2,
    provider_uid: u32,
    guardian_uid: u32,
) -> Result<ResolvedTargetIdentity, String> {
    match request {
        ExecutionIdentityRequestV2::PreserveCaller => {
            if record.is_some()
                || caller.uid == 0
                || caller.gid == 0
                || !caller.no_new_privs
                || caller.capability_bounding_set != 0
                || caller.supplementary_groups.len() > 32
                || caller.supplementary_groups.contains(&0)
            {
                return Err("MCSEALED-PRIVATE-IDENTITY: preserved caller is not eligible".into());
            }
            let mut groups = caller.supplementary_groups.clone();
            groups.sort_unstable();
            if groups.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err("MCSEALED-PRIVATE-IDENTITY: duplicate caller group".into());
            }
            Ok(ResolvedTargetIdentity {
                uid: caller.uid,
                gid: caller.gid,
                groups,
                delegated: false,
            })
        }
        ExecutionIdentityRequestV2::AdministratorProfile { reference } => {
            let record = record.ok_or("MCSEALED-PRIVATE-IDENTITY: identity record absent")?;
            if !record.enabled
                || &record.reference != reference
                || record.semantic_digest()? != reference.semantic_digest
            {
                return Err("MCSEALED-PRIVATE-IDENTITY: identity authority mismatch".into());
            }
            let uid = record.uid.get();
            if uid == caller.uid || uid == provider_uid || uid == guardian_uid {
                return Err("MCSEALED-PRIVATE-IDENTITY: target uses a trusted principal".into());
            }
            let mut groups: Vec<_> = record
                .supplementary_groups
                .as_slice()
                .iter()
                .map(|group| group.get())
                .collect();
            groups.sort_unstable();
            Ok(ResolvedTargetIdentity {
                uid,
                gid: record.gid.get(),
                groups,
                delegated: true,
            })
        }
    }
}

/// Apply the exact target credentials in the single-threaded, trusted setup
/// stub after privileged namespace/mount/fd work, before installing seccomp.
/// Any error is fatal to that stub; it must not execute candidate code.
pub fn apply_target_identity(target: &ResolvedTargetIdentity) -> Result<(), String> {
    if target.uid == 0 || target.gid == 0 {
        return Err("MCSEALED-PRIVATE-IDENTITY: zero target ID".into());
    }
    let last_capability = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .map_err(|error| format!("MCSEALED-PRIVATE-IDENTITY: capability limit: {error}"))?
        .trim()
        .parse::<u32>()
        .map_err(|_| "MCSEALED-PRIVATE-IDENTITY: invalid capability limit")?;
    if last_capability >= u64::BITS {
        return Err("MCSEALED-PRIVATE-IDENTITY: capability mask unsupported".into());
    }
    for capability in 0..=last_capability {
        // SAFETY: the capability index is bounded by cap_last_cap and the
        // single-threaded setup still has effective CAP_SETPCAP.
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) } == -1 {
            return Err(native_error("drop capability bounding set"));
        }
    }
    // SAFETY: these prctl operations take scalar arguments only.
    if unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) } == -1
        || unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        } == -1
        || unsafe { libc::prctl(libc::PR_SET_SECUREBITS, SECURE_BITS_REQUIRED, 0, 0, 0) } == -1
    {
        return Err(native_error("lock target securebits"));
    }
    // SAFETY: the group slice remains live throughout setgroups; credential
    // calls use exact resolved nonroot IDs and are checked individually.
    if unsafe { libc::setgroups(target.groups.len(), target.groups.as_ptr()) } == -1 {
        return Err(native_error("set target groups"));
    }
    if unsafe { libc::setresgid(target.gid, target.gid, target.gid) } == -1 {
        return Err(native_error("set target GIDs"));
    }
    if unsafe { libc::setresuid(target.uid, target.uid, target.uid) } == -1 {
        return Err(native_error("set target UIDs"));
    }
    clear_capabilities()?;
    // SAFETY: NNP is an irreversible scalar operation on the current thread.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == -1 {
        return Err(native_error("set target no_new_privs"));
    }
    verify_target_identity(target, last_capability)
}

fn verify_target_identity(
    target: &ResolvedTargetIdentity,
    last_capability: u32,
) -> Result<(), String> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|error| format!("MCSEALED-PRIVATE-IDENTITY: status readback: {error}"))?;
    let status = super::envelope::parse_proc_status(&status)
        .map_err(|error| format!("MCSEALED-PRIVATE-IDENTITY: status readback: {error}"))?;
    let mut groups = status.supplementary_groups;
    groups.sort_unstable();
    if status.uids != [target.uid; 4]
        || status.gids != [target.gid; 4]
        || groups != target.groups
        || !status.no_new_privs
        || status.capability_inheritable_set != 0
        || status.capability_permitted_set != 0
        || status.capability_effective_set != 0
        || status.capability_bounding_set != 0
        || status.capability_ambient_set != 0
    {
        return Err("MCSEALED-PRIVATE-IDENTITY: target credential readback mismatch".into());
    }
    // SAFETY: PR_GET_SECUREBITS and PR_CAPBSET_READ take scalar arguments.
    if unsafe { libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0) } != SECURE_BITS_REQUIRED as i32 {
        return Err("MCSEALED-PRIVATE-IDENTITY: securebits readback mismatch".into());
    }
    for capability in 0..=last_capability {
        if unsafe { libc::prctl(libc::PR_CAPBSET_READ, capability, 0, 0, 0) } != 0 {
            return Err("MCSEALED-PRIVATE-IDENTITY: bounding capability remains".into());
        }
    }
    Ok(())
}

fn clear_capabilities() -> Result<(), String> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let zero = [Data {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: capset receives a valid v3 header and two live zeroed entries.
    if unsafe { libc::syscall(libc::SYS_capset, &raw const header, zero.as_ptr()) } == -1 {
        return Err(native_error("clear target capabilities"));
    }
    Ok(())
}

fn native_error(phase: &str) -> String {
    format!(
        "MCSEALED-PRIVATE-IDENTITY: {phase}: {}",
        std::io::Error::last_os_error()
    )
}
