//! Authenticated provider admission, rechecked while registry activation is excluded.
#![cfg(any(target_os = "linux", target_os = "windows"))]
use memcordon_core::DiagnosticSha256;
#[cfg(target_os = "linux")]
pub use memcordon_core::workload_admission_v2::ProviderAdmissionSnapshotV2 as FrozenAdmissionV2;
use memcordon_core::workload_contract::WorkloadContractV1;
pub use memcordon_core::workload_registry::ProviderAdmissionSnapshotV1 as FrozenAdmission;
use memcordon_core::workload_registry::{AdmissionRejectionV1, BaselineProfile, CallerSelector};
#[cfg(target_os = "linux")]
use memcordon_core::workload_registry_v2::{
    AdmissionCodeV2, AdmissionRejectionV2, ProfileKindV2, resolve_v2,
};
#[cfg(target_os = "windows")]
pub fn discover_windows(
    sid: &str,
) -> Result<memcordon_core::workload_discovery::WorkloadDiscoveryV1, String> {
    let lease = crate::windows::policy_registry::Lease::acquire()?;
    let activation = lease.read()?;
    memcordon_core::workload_discovery::WorkloadDiscoveryV1::authenticated(
        activation
            .as_ref()
            .map(|activation| (&activation.registry, &activation.epoch)),
        &CallerSelector::Windows {
            sid: memcordon_core::BoundedText::new(sid).map_err(str::to_owned)?,
        },
        BaselineProfile::WindowsHostNetworkExternal,
        windows_qualification_digest()?,
        crate::windows::package::installed_public_provider_binding()?,
        memcordon_core::BoundedText::new(&crate::windows::record::boot_identity()?)
            .map_err(str::to_owned)?,
    )
}
#[cfg(target_os = "windows")]
pub fn inspect_windows(
    contract: &WorkloadContractV1,
    sid: &str,
) -> Result<memcordon_core::workload_evidence::WorkloadResolutionReportV1, String> {
    use memcordon_core::workload_evidence::*;
    let request_binding = RequestBindingV1::from_contract(contract)?;
    let result = (|| -> Result<WorkloadResolutionReportV1, String> {
        let lease = crate::windows::policy_registry::Lease::acquire()?;
        let activation = lease.read()?.ok_or("policy activation absent")?;
        let caller = CallerSelector::Windows {
            sid: memcordon_core::BoundedText::new(sid).map_err(str::to_owned)?,
        };
        let qualification = windows_qualification_digest()?;
        if let Err(rejection) = memcordon_core::workload_registry::resolve(
            &activation.registry,
            &activation.epoch,
            contract,
            &caller,
            BaselineProfile::WindowsHostNetworkExternal,
            &qualification,
        ) {
            return Ok(WorkloadResolutionReportV1::Rejected {
                binding: request_binding.clone(),
                rejection,
                target_authorized: False::default(),
            });
        }
        let binding = PlanBindingV1::from_authorized(
            contract,
            activation.registry_digest,
            qualification,
            crate::windows::package::installed_public_provider_binding()?,
            memcordon_core::BoundedText::new(&crate::windows::record::boot_identity()?)
                .map_err(str::to_owned)?,
        )?;
        let mut pending = memcordon_core::BoundedVec::default();
        for check in [
            PrelaunchCheck::CallerIdentity,
            PrelaunchCheck::InvocationIdentity,
            PrelaunchCheck::DescriptorCustody,
            PrelaunchCheck::NativeControls,
            PrelaunchCheck::Guardian,
            PrelaunchCheck::CurrentEpoch,
            PrelaunchCheck::DurableCheckpoint,
        ] {
            pending.try_push(check).expect("fixed prelaunch checks fit");
        }
        Ok(WorkloadResolutionReportV1::Planned {
            binding,
            effective: EffectiveWorkloadPolicyV1 {
                profile: BaselineProfile::WindowsHostNetworkExternal,
                ceiling: BaselineProfile::WindowsHostNetworkExternal.ceiling(),
                restriction: BaselineRestrictionObservationV1::WindowsNetworkExternallyGoverned,
            },
            pending,
        })
    })();
    Ok(
        result.unwrap_or_else(|_| WorkloadResolutionReportV1::Unavailable {
            request: Some(request_binding),
            reason: AdmissionAvailabilityFailure::BindingUnavailable,
            authorization: AuthorizationKnowledge::NotAuthorized,
        }),
    )
}

#[cfg(target_os = "windows")]
pub fn plan_windows(
    request: &WorkloadContractV1,
    sid: &str,
    private_invocation_digest: DiagnosticSha256,
) -> Result<(FrozenAdmission, crate::windows::policy_registry::Lease), AdmissionRejectionV1> {
    use memcordon_core::workload_registry::{AdmissionCode, resolve};
    let unavailable = || AdmissionRejectionV1::single(AdmissionCode::HostPrerequisiteUnavailable);
    request
        .validate()
        .map_err(|_| AdmissionRejectionV1::single(AdmissionCode::PolicyIncompatible))?;
    let lease = crate::windows::policy_registry::Lease::acquire().map_err(|_| unavailable())?;
    let activation = lease
        .read()
        .map_err(|_| unavailable())?
        .ok_or_else(|| AdmissionRejectionV1::single(AdmissionCode::ProfileNotAuthorized))?;
    let caller = CallerSelector::Windows {
        sid: memcordon_core::BoundedText::new(sid).map_err(|_| unavailable())?,
    };
    let qualification = windows_qualification_digest().map_err(|_| unavailable())?;
    resolve(
        &activation.registry,
        &activation.epoch,
        request,
        &caller,
        BaselineProfile::WindowsHostNetworkExternal,
        &qualification,
    )?;
    lease
        .retain_snapshot(&activation.registry)
        .map_err(|_| unavailable())?;
    let snapshot = FrozenAdmission {
        request: request.clone(),
        request_digest: memcordon_core::workload_codec::contract_digest(request)
            .map_err(|_| unavailable())?,
        private_invocation_digest,
        caller_invocation_reference: crate::windows::policy_registry::random_nonce()
            .map_err(|_| unavailable())?,
        registry_digest: activation.registry_digest,
        qualification_digest: qualification,
        admission_nonce: crate::windows::policy_registry::random_nonce()
            .map_err(|_| unavailable())?,
        caller,
        native_profile: BaselineProfile::WindowsHostNetworkExternal,
    };
    Ok((snapshot, lease))
}

#[cfg(target_os = "windows")]
fn windows_qualification_digest() -> Result<DiagnosticSha256, String> {
    let receipt = crate::windows::qualification::local_receipt()?;
    Ok(memcordon_core::workload_codec::hash_bytes(
        &serde_json::to_vec(&receipt).map_err(|error| error.to_string())?,
    ))
}

#[cfg(target_os = "windows")]
pub fn revalidate_windows(
    snapshot: &FrozenAdmission,
) -> Result<crate::windows::policy_registry::Lease, String> {
    let lease = crate::windows::policy_registry::Lease::acquire()?;
    let activation = lease
        .read()?
        .ok_or("MCSEALED-POLICY-NOT-AUTHORIZED: activated registry absent")?;
    if activation.registry_digest != snapshot.registry_digest {
        return Err("MCSEALED-POLICY-EPOCH-STALE: activated registry changed".into());
    }
    let qualification = windows_qualification_digest()?;
    if qualification != snapshot.qualification_digest {
        return Err("MCSEALED-POLICY-DRIFT: qualification changed before authorization".into());
    }
    crate::windows::package::installed_public_provider_binding()?;
    memcordon_core::workload_registry::resolve(
        &activation.registry,
        &activation.epoch,
        &snapshot.request,
        &snapshot.caller,
        snapshot.native_profile,
        &qualification,
    )
    .map_err(|rejection| format!("MCSEALED-POLICY-ADMISSION: {:?}", rejection))?;
    Ok(lease)
}

#[cfg(target_os = "windows")]
pub fn revoked_windows(snapshot: &FrozenAdmission) -> Result<bool, String> {
    let lease = crate::windows::policy_registry::Lease::acquire()?;
    let activation = lease
        .read()?
        .ok_or("MCSEALED-POLICY-DRIFT: activated registry absent")?;
    Ok(activation
        .revoked_admissions
        .as_slice()
        .contains(&snapshot.admission_nonce))
}

#[cfg(target_os = "linux")]
pub fn plan_linux(
    request: &WorkloadContractV1,
    uid: u32,
    qualification: &str,
    private_invocation_digest: DiagnosticSha256,
) -> Result<(FrozenAdmission, crate::policy_registry::native::Lease), AdmissionRejectionV1> {
    use memcordon_core::workload_registry::{AdmissionCode, resolve};
    let unavailable = || AdmissionRejectionV1::single(AdmissionCode::HostPrerequisiteUnavailable);
    request
        .validate()
        .map_err(|_| AdmissionRejectionV1::single(AdmissionCode::PolicyIncompatible))?;
    let lease = crate::policy_registry::native::Lease::acquire().map_err(|_| unavailable())?;
    let activation = lease
        .read()
        .map_err(|_| unavailable())?
        .ok_or_else(|| AdmissionRejectionV1::single(AdmissionCode::ProfileNotAuthorized))?;
    let digest = DiagnosticSha256::try_from(
        memcordon_core::BoundedText::new(qualification).map_err(|_| unavailable())?,
    )
    .map_err(|_| unavailable())?;
    let caller = CallerSelector::Linux { uid };
    resolve(
        &activation.registry,
        &activation.epoch,
        request,
        &caller,
        BaselineProfile::LinuxUnixCreate,
        &digest,
    )?;
    if lease
        .versioned_live_bindings()
        .map_err(|_| unavailable())?
        .len()
        >= memcordon_core::workload_limits::LIVE_BINDINGS
    {
        return Err(unavailable());
    }
    lease
        .retain_snapshot(&activation.registry)
        .map_err(|_| unavailable())?;
    Ok((
        FrozenAdmission {
            private_invocation_digest,
            caller_invocation_reference: crate::policy_registry::native::random_nonce()
                .map_err(|_| unavailable())?,
            request: request.clone(),
            request_digest: memcordon_core::workload_codec::contract_digest(request)
                .map_err(|_| unavailable())?,
            registry_digest: activation.registry_digest,
            qualification_digest: digest,
            admission_nonce: crate::policy_registry::native::random_nonce()
                .map_err(|_| unavailable())?,
            caller,
            native_profile: BaselineProfile::LinuxUnixCreate,
        },
        lease,
    ))
}

#[cfg(target_os = "linux")]
pub fn check_linux(
    request: &WorkloadContractV1,
    uid: u32,
    qualification: &str,
) -> Result<(), AdmissionRejectionV1> {
    use memcordon_core::workload_registry::{AdmissionCode, resolve};
    let unavailable = || AdmissionRejectionV1::single(AdmissionCode::HostPrerequisiteUnavailable);
    let lease = crate::policy_registry::native::Lease::acquire().map_err(|_| unavailable())?;
    let activation = lease
        .read()
        .map_err(|_| unavailable())?
        .ok_or_else(|| AdmissionRejectionV1::single(AdmissionCode::ProfileNotAuthorized))?;
    let digest = DiagnosticSha256::try_from(
        memcordon_core::BoundedText::new(qualification).map_err(|_| unavailable())?,
    )
    .map_err(|_| unavailable())?;
    resolve(
        &activation.registry,
        &activation.epoch,
        request,
        &CallerSelector::Linux { uid },
        BaselineProfile::LinuxUnixCreate,
        &digest,
    )
    .map(|_| ())
}

/// V2 plan routing authenticates policy/caller/identity selectors but cannot
/// issue a planned or authorized result until a native V4 launch/qualification
/// source exists. In particular a registry-supplied digest is never treated as
/// proof that private networking is installed on this host.
#[cfg(target_os = "linux")]
pub fn plan_linux_v2_rejection(
    request: &memcordon_core::workload_contract::WorkloadContractV2,
    uid: u32,
) -> AdmissionRejectionV2 {
    let reject = AdmissionRejectionV2::single;
    if request.validate().is_err() {
        return reject(AdmissionCodeV2::PolicyIncompatible);
    }
    let lease = match crate::policy_registry::native::Lease::acquire() {
        Ok(lease) => lease,
        Err(_) => return reject(AdmissionCodeV2::HostPrerequisiteUnavailable),
    };
    let activation = match lease.read_v2() {
        Ok(Some(activation)) => activation,
        Ok(None) => return reject(AdmissionCodeV2::ProfileNotAuthorized),
        Err(_) => return reject(AdmissionCodeV2::HostPrerequisiteUnavailable),
    };
    let native_profile = match [
        ProfileKindV2::LinuxUnixCreateV1,
        ProfileKindV2::LinuxTcp4PrivateV1,
    ]
    .into_iter()
    .find(|profile| profile.reference() == request.authorized_profile)
    {
        Some(profile) => profile,
        None => return reject(AdmissionCodeV2::ProfileDigestMismatch),
    };
    let qualification = match activation
        .registry
        .profiles
        .as_slice()
        .iter()
        .find(|profile| profile.reference == request.authorized_profile)
    {
        Some(profile) => &profile.qualification_digest,
        None => return reject(AdmissionCodeV2::ProfileNotAuthorized),
    };
    if let Err(rejection) = resolve_v2(
        &activation.registry,
        &activation.epoch,
        request,
        &CallerSelector::Linux { uid },
        native_profile,
        qualification,
    ) {
        return rejection;
    }
    reject(AdmissionCodeV2::HostPrerequisiteUnavailable)
}

/// Freeze the exact authenticated V2 decision while the caller holds the
/// installed package-generation lease. The returned policy lease must remain
/// held until the V4 durable record has acquired its snapshot reference;
/// neither this plan nor the registry alone authorizes target release.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub fn plan_linux_v2(
    request: &memcordon_core::workload_contract::WorkloadContractV2,
    uid: u32,
    caller_envelope_reference: memcordon_core::workload_contract::Nonce128,
    caller_envelope_digest: DiagnosticSha256,
    native_invocation_digest: DiagnosticSha256,
    installed: &crate::package::VerifiedInstalledPrivateAuthorityLease,
) -> Result<(FrozenAdmissionV2, crate::policy_registry::native::Lease), AdmissionRejectionV2> {
    let unavailable = || AdmissionRejectionV2::single(AdmissionCodeV2::HostPrerequisiteUnavailable);
    request
        .validate()
        .map_err(|_| AdmissionRejectionV2::single(AdmissionCodeV2::PolicyIncompatible))?;
    let lease = crate::policy_registry::native::Lease::acquire().map_err(|_| unavailable())?;
    let activation = lease
        .read_v2()
        .map_err(|_| unavailable())?
        .ok_or_else(|| AdmissionRejectionV2::single(AdmissionCodeV2::ProfileNotAuthorized))?;
    let caller = CallerSelector::Linux { uid };
    resolve_v2(
        &activation.registry,
        &activation.epoch,
        request,
        &caller,
        ProfileKindV2::LinuxTcp4PrivateV1,
        installed.qualification_digest(),
    )?;
    if lease
        .versioned_live_bindings()
        .map_err(|_| unavailable())?
        .len()
        >= memcordon_core::workload_limits::LIVE_BINDINGS
    {
        return Err(unavailable());
    }
    lease
        .retain_snapshot_v2(&activation.registry)
        .map_err(|_| unavailable())?;
    let native_abi = match installed.filter_abi() {
        crate::linux::network_filter::NativeAbi::X86_64 => {
            memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2::X86_64LinuxGnu
        }
        crate::linux::network_filter::NativeAbi::Aarch64 => {
            memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2::Aarch64LinuxGnu
        }
    };
    let frozen = FrozenAdmissionV2::freeze(
        &activation.registry,
        &activation.epoch,
        request,
        &caller,
        installed.qualification_digest().clone(),
        installed.generation_digest().clone(),
        native_abi,
        crate::policy_registry::native::random_nonce().map_err(|_| unavailable())?,
        caller_envelope_reference,
        caller_envelope_digest,
        native_invocation_digest,
    )
    .map_err(|_| unavailable())?;
    Ok((frozen, lease))
}

#[cfg(target_os = "linux")]
/// Called under the activation lease immediately before checkpoint commit.
/// The lease remains held through release-intent persistence and the one-byte
/// release, then is dropped promptly.
#[cfg(target_os = "linux")]
pub fn revalidate_linux_v2(
    snapshot: &FrozenAdmissionV2,
    lease: &crate::policy_registry::native::Lease,
) -> Result<(), String> {
    let active = lease.read_v2()?.ok_or("V2 activation absent")?;
    if active.epoch != snapshot.epoch || active.registry_digest != snapshot.registry_digest {
        return Err("V2 activation changed before private release".into());
    }
    if active
        .revoked_admissions
        .as_slice()
        .contains(&snapshot.admission_nonce)
    {
        return Err("V2 private admission was revoked".into());
    }
    snapshot.validate_against(&active.registry)
}

#[cfg(target_os = "linux")]
pub fn revoked_linux_v2(snapshot: &FrozenAdmissionV2) -> Result<bool, String> {
    let lease = crate::policy_registry::native::Lease::acquire()?;
    let Some(active) = lease.read_v2()? else {
        return Ok(true);
    };
    Ok(active
        .revoked_admissions
        .as_slice()
        .contains(&snapshot.admission_nonce))
}

#[cfg(target_os = "linux")]
pub trait LinuxAdmission {
    fn revoked_linux(&self) -> Result<bool, String>;
    fn revalidate_linux(&self) -> Result<crate::policy_registry::native::Lease, String>;
}
#[cfg(target_os = "linux")]
impl LinuxAdmission for FrozenAdmission {
    fn revoked_linux(&self) -> Result<bool, String> {
        let lease = crate::policy_registry::native::Lease::acquire()?;
        let activation = lease
            .read()?
            .ok_or("MCSEALED-POLICY-DRIFT: activated registry absent")?;
        Ok(activation
            .revoked_admissions
            .as_slice()
            .contains(&self.admission_nonce))
    }
    fn revalidate_linux(&self) -> Result<crate::policy_registry::native::Lease, String> {
        crate::package::verify()?;
        let lease = crate::policy_registry::native::Lease::acquire()?;
        let activation = lease
            .read()?
            .ok_or("MCSEALED-POLICY-NOT-AUTHORIZED: policy registry absent")?;
        if activation.registry_digest != self.registry_digest {
            return Err("MCSEALED-POLICY-EPOCH-STALE: activated registry changed".into());
        }
        memcordon_core::workload_registry::resolve(
            &activation.registry,
            &activation.epoch,
            &self.request,
            &self.caller,
            self.native_profile,
            &self.qualification_digest,
        )
        .map_err(|rejection| format!("MCSEALED-POLICY-ADMISSION: {:?}", rejection.code))?;
        Ok(lease)
    }
}
