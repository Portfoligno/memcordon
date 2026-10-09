//! Advisory V3 resolution reads current native authority without reserving it.
use crate::protocol::{Frame, MessageKind};
use memcordon_core::mixed_advisory::{MixedCapabilitiesV2, MixedPlanV2};

pub(super) fn plan(request: &Frame, count: usize, uid: u32) -> Result<Frame, String> {
    if count != 0 || request.attempt_id != [0; 16] {
        return Err("mixed advisory request carries native attempt resources".into());
    }
    let contract =
        match memcordon_core::workload_contract::WorkloadContract::parse(&request.payload)? {
            memcordon_core::workload_contract::WorkloadContract::V3(value) => value,
            _ => return Err("mixed plan requires exact V3 contract".into()),
        };
    let _package = super::service::acquire_shared_package_lease()?;
    let provider = super::runtime_manifest::installed_binding()?;
    let lease = crate::policy_registry::native::Lease::acquire()?;
    let mut value = MixedPlanV2 {
        format: "memcordon.plan".into(),
        revision: 2,
        provider_contract: 4,
        launch_wire: 4,
        provider,
        request_sha256: contract.digest()?,
        request: contract,
        available_for_preparation: false,
        conflict: None,
        prerequisite_error: None,
        pending: memcordon_core::mixed_advisory::pending_obligations(),
        authorizes_launch: false,
    };
    match lease.read_v3()? {
        None => {
            value.conflict =
                Some(memcordon_core::workload_registry_v3::AdmissionCodeV3::UnauthorizedProfile)
        }
        Some(activation) => {
            match activation
                .registry
                .resolve(&value.request, uid, &activation.epoch)
            {
                Err(reason) => value.conflict = Some(reason),
                Ok(resolved) => {
                    let prerequisites = (|| {
                        if !cfg!(all(feature = "private-tcp", target_env = "gnu")) {
                            return Err("mixed provider feature/ABI unavailable".into());
                        }
                        crate::package::verify()?;
                        super::launcher::check_network_endpoint()?;
                        super::execution_identity::ResolvedTargetIdentity::exclusive(
                            resolved.identity,
                            uid,
                        )?;
                        let runtime = super::runtime_image::open_installed(resolved.image)?;
                        let input = super::runtime_image::open_installed(resolved.input)?;
                        super::image_elf_closure::validate(&runtime, &input)?;
                        Ok::<(), String>(())
                    })();
                    if let Err(reason) = prerequisites {
                        value.prerequisite_error =
                            Some(memcordon_core::BoundedText::new(&reason).map_err(str::to_owned)?);
                    }
                }
            }
        }
    }
    value.available_for_preparation =
        value.conflict.is_none() && value.prerequisite_error.is_none();
    value.validate()?;
    Ok(Frame {
        kind: MessageKind::MixedPlanReceipt,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: serde_json::to_vec(&value).map_err(|error| error.to_string())?,
    })
}

pub(super) fn discovery(request: &Frame, count: usize, uid: u32) -> Result<Frame, String> {
    if count != 0 || request.attempt_id != [0; 16] || !request.payload.is_empty() {
        return Err("mixed discovery carries native attempt resources".into());
    }
    let _package = super::service::acquire_shared_package_lease()?;
    let provider = super::runtime_manifest::installed_binding()?;
    let supported = cfg!(all(feature = "private-tcp", target_env = "gnu"));
    let installed_enabled = supported
        && crate::package::verify().is_ok()
        && super::launcher::check_network_endpoint().is_ok();
    let lease = crate::policy_registry::native::Lease::acquire()?;
    let activation = lease.read_v3()?;
    let eligible = activation.as_ref().is_some_and(|a| {
        a.registry.grants.as_slice().iter().any(|grant| {
            grant.enabled
                && grant
                    .callers
                    .as_slice()
                    .contains(&memcordon_core::workload_registry::CallerSelector::Linux { uid })
                && a.registry
                    .execution_identities
                    .as_slice()
                    .iter()
                    .any(|identity| {
                        identity.enabled
                            && identity
                                .reference()
                                .is_ok_and(|reference| reference == grant.execution_identity)
                            && super::execution_identity::ResolvedTargetIdentity::exclusive(
                                identity, uid,
                            )
                            .is_ok()
                    })
        })
    });
    let image_support = activation.as_ref().is_some_and(|a| {
        !a.registry.images.as_slice().is_empty()
            && a.registry
                .images
                .as_slice()
                .iter()
                .all(|image| super::runtime_image::open_installed(image).is_ok())
    });
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| error.to_string())?;
    let value = MixedCapabilitiesV2 {
        format: "memcordon.capabilities".into(),
        revision: 2,
        provider_contract: 4,
        launch_wire: 4,
        provider,
        boot_identity: memcordon_core::BoundedText::new(boot.trim()).map_err(str::to_owned)?,
        profile: memcordon_core::workload_registry_v3::profile_reference(),
        request_versions: vec![3],
        carrier_versions: vec![2],
        supported,
        installed_enabled,
        exclusive_identity_eligible: installed_enabled && eligible,
        image_support: installed_enabled && image_support,
        plan: None,
        authorizes_launch: false,
    };
    value.validate()?;
    Ok(Frame {
        kind: MessageKind::MixedDiscoveryReceipt,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: serde_json::to_vec(&value).map_err(|error| error.to_string())?,
    })
}
