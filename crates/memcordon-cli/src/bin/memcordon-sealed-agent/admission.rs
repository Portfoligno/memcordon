//! Authenticated provider admission, rechecked while registry activation is excluded.
#![cfg(any(target_os = "linux", target_os = "windows"))]
use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_contract::WorkloadContractV1;
pub use memcordon_core::workload_registry::RuntimeAdmissionSnapshot as FrozenAdmission;
use memcordon_core::workload_registry::{AdmissionRejectionV1, BaselineProfile, CallerSelector};
#[cfg(target_os = "windows")]
pub fn discover_windows(
    sid: &str,
) -> Result<memcordon_core::workload_discovery::WorkloadDiscovery, String> {
    let lease = crate::windows::policy_registry::Lease::acquire()?;
    let activation = lease.read()?;
    memcordon_core::workload_discovery::WorkloadDiscovery::authenticated(
        activation
            .as_ref()
            .map(|activation| (&activation.registry, &activation.epoch)),
        &CallerSelector::Windows {
            sid: memcordon_core::BoundedText::new(sid).map_err(str::to_owned)?,
        },
        BaselineProfile::WindowsHostNetworkExternal,
        crate::windows::package::installed_public_provider_binding()?,
        memcordon_core::BoundedText::new(&crate::windows::record::boot_identity()?)
            .map_err(str::to_owned)?,
    )
}
#[cfg(target_os = "windows")]
pub fn inspect_windows(
    contract: &WorkloadContractV1,
    sid: &str,
) -> Result<memcordon_core::workload_evidence::RuntimeWorkloadResolution, String> {
    use memcordon_core::workload_evidence::*;
    let request_binding = RequestBindingV1::from_contract(contract)?;
    let result = (|| -> Result<RuntimeWorkloadResolution, String> {
        let lease = crate::windows::policy_registry::Lease::acquire()?;
        let activation = lease.read()?.ok_or("policy activation absent")?;
        let caller = CallerSelector::Windows {
            sid: memcordon_core::BoundedText::new(sid).map_err(str::to_owned)?,
        };
        if let Err(rejection) = memcordon_core::workload_registry::resolve(
            &activation.registry,
            &activation.epoch,
            contract,
            &caller,
            BaselineProfile::WindowsHostNetworkExternal,
        ) {
            return Ok(RuntimeWorkloadResolution::Rejected {
                binding: request_binding.clone(),
                rejection,
                target_authorized: False::default(),
            });
        }
        let binding = RuntimePlanBinding::from_local_grant(
            contract,
            activation.registry_digest,
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
        Ok(RuntimeWorkloadResolution::Planned {
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
        result.unwrap_or_else(|_| RuntimeWorkloadResolution::Unavailable {
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
    resolve(
        &activation.registry,
        &activation.epoch,
        request,
        &caller,
        BaselineProfile::WindowsHostNetworkExternal,
    )?;
    lease
        .retain_snapshot(&activation.registry)
        .map_err(|_| unavailable())?;
    let snapshot = FrozenAdmission {
        format: "memcordon.local-admission".into(),
        revision: 1,
        request: request.clone(),
        request_digest: memcordon_core::workload_codec::contract_digest(request)
            .map_err(|_| unavailable())?,
        private_invocation_digest,
        caller_invocation_reference: crate::windows::policy_registry::random_nonce()
            .map_err(|_| unavailable())?,
        registry_digest: activation.registry_digest,
        admission_nonce: crate::windows::policy_registry::random_nonce()
            .map_err(|_| unavailable())?,
        caller,
        native_profile: BaselineProfile::WindowsHostNetworkExternal,
    };
    Ok((snapshot, lease))
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
    crate::windows::package::installed_public_provider_binding()?;
    memcordon_core::workload_registry::resolve(
        &activation.registry,
        &activation.epoch,
        &snapshot.request,
        &snapshot.caller,
        snapshot.native_profile,
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
    let caller = CallerSelector::Linux { uid };
    resolve(
        &activation.registry,
        &activation.epoch,
        request,
        &caller,
        BaselineProfile::LinuxUnixCreate,
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
            format: "memcordon.local-admission".into(),
            revision: 1,
            private_invocation_digest,
            caller_invocation_reference: crate::policy_registry::native::random_nonce()
                .map_err(|_| unavailable())?,
            request: request.clone(),
            request_digest: memcordon_core::workload_codec::contract_digest(request)
                .map_err(|_| unavailable())?,
            registry_digest: activation.registry_digest,
            admission_nonce: crate::policy_registry::native::random_nonce()
                .map_err(|_| unavailable())?,
            caller,
            native_profile: BaselineProfile::LinuxUnixCreate,
        },
        lease,
    ))
}

#[cfg(target_os = "linux")]
pub fn check_linux(request: &WorkloadContractV1, uid: u32) -> Result<(), AdmissionRejectionV1> {
    use memcordon_core::workload_registry::{AdmissionCode, resolve};
    let unavailable = || AdmissionRejectionV1::single(AdmissionCode::HostPrerequisiteUnavailable);
    let lease = crate::policy_registry::native::Lease::acquire().map_err(|_| unavailable())?;
    let activation = lease
        .read()
        .map_err(|_| unavailable())?
        .ok_or_else(|| AdmissionRejectionV1::single(AdmissionCode::ProfileNotAuthorized))?;
    resolve(
        &activation.registry,
        &activation.epoch,
        request,
        &CallerSelector::Linux { uid },
        BaselineProfile::LinuxUnixCreate,
    )
    .map(|_| ())
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
        )
        .map_err(|rejection| format!("MCSEALED-POLICY-ADMISSION: {:?}", rejection.code))?;
        Ok(lease)
    }
}
