use crate::windows_installed_cases::InstalledWindowsPayload;
use crate::{CiError, Result};
use std::path::Path;

/// Observe the retained public client and installed provider roles separately.
pub fn observe(
    current: &InstalledWindowsPayload,
    binary_root: &Path,
    retained: &Path,
    binaries: &[String],
    target: &str,
) -> Result<Vec<serde_json::Value>> {
    use memcordon_core::runtime_manifest::{RuntimeComponentRole as Role, RuntimeManifest};
    let measure = |path: &Path, operation: &str| {
        super::artifacts::read_file(path).map_err(|error| {
            CiError::Message(format!(
                "Windows component readback {operation}; path={path:?}: {error}"
            ))
        })
    };
    let retained_manifest = retained.join("runtime-manifest.json");
    let manifest_bytes = measure(&retained_manifest, "retained manifest")?;
    let manifest = RuntimeManifest::parse(&manifest_bytes).map_err(CiError::Message)?;
    if manifest
        .public_binding(&manifest_bytes)
        .map_err(CiError::Message)?
        != current.provider
        || manifest.source_commit != current.source_commit
        || manifest.version != current.version
        || manifest.target != current.target
        || current.target != target
        || super::artifacts::checksum(&manifest_bytes) != current.installed_manifest.sha256
        || current.installed_manifest.path != binary_root.join("runtime-manifest.json")
        || measure(&current.installed_manifest.path, "installed manifest")? != manifest_bytes
        || binaries.len() != 4
        || manifest.components.len() != 4
        || current.components.len() != 4
        || current.installed_components.len() != 3
    {
        return Err(CiError::Message(
            "Windows component readback manifest/source/inventory differs".into(),
        ));
    }
    let mut roles = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    let mut records = Vec::new();
    for binary in binaries {
        let name = super::target::binary_name(binary, target);
        let matches = manifest
            .components
            .iter()
            .filter(|component| component.path == name)
            .collect::<Vec<_>>();
        if matches.len() != 1 || !names.insert(name.clone()) {
            return Err(CiError::Message(format!(
                "Windows component readback ambiguous binary={binary}"
            )));
        }
        let component = matches[0];
        let role = component.role;
        if roles.contains(&role)
            || !matches!(
                role,
                Role::PublicCli | Role::SealedAgent | Role::DesktopBootstrap | Role::SessionBroker
            )
        {
            return Err(CiError::Message(format!(
                "Windows component readback duplicate/unexpected role={role:?} binary={binary}"
            )));
        }
        roles.push(role);
        let selected_path = retained.join(&name);
        let selected = current
            .components
            .iter()
            .filter(|artifact| artifact.path == selected_path)
            .collect::<Vec<_>>();
        if selected.len() != 1 || selected[0].sha256 != component.sha256 {
            return Err(CiError::Message(format!(
                "Windows component readback selected binding differs role={role:?} binary={binary} path={selected_path:?}"
            )));
        }
        let selected = selected[0];
        let actual = if role == Role::PublicCli {
            if current.cli.path != selected.path || current.cli.sha256 != selected.sha256 {
                return Err(CiError::Message(
                    "Windows component readback public client binding differs".into(),
                ));
            }
            &current.cli
        } else {
            let actual_path = binary_root.join(&name);
            let installed = current
                .installed_components
                .iter()
                .filter(|artifact| artifact.path == actual_path)
                .collect::<Vec<_>>();
            if installed.len() != 1 || installed[0].sha256 != selected.sha256 {
                return Err(CiError::Message(format!(
                    "Windows component readback installed binding differs role={role:?} binary={binary} path={actual_path:?}"
                )));
            }
            if role == Role::SealedAgent
                && (current.agent.path != selected.path
                    || current.agent.sha256 != selected.sha256
                    || current.installed_agent.path != installed[0].path
                    || current.installed_agent.sha256 != installed[0].sha256)
            {
                return Err(CiError::Message(
                    "Windows component readback agent binding differs".into(),
                ));
            }
            installed[0]
        };
        let context = format!("role={role:?} binary={binary}");
        let selected_bytes = measure(&selected.path, &format!("selected {context}"))?;
        let actual_bytes = measure(&actual.path, &format!("actual {context}"))?;
        let hash = super::artifacts::checksum(&actual_bytes);
        if hash != selected.sha256
            || hash != actual.sha256
            || hash != component.sha256
            || super::artifacts::checksum(&selected_bytes) != selected.sha256
            || actual_bytes != selected_bytes
            || actual_bytes.len() as u64 != component.size
        {
            return Err(CiError::Message(format!(
                "Windows component readback measured bytes differ {context} path={:?}",
                actual.path
            )));
        }
        records.push(serde_json::json!({"binary":binary,"path":actual.path,"sha256":hash}));
    }
    Ok(records)
}
