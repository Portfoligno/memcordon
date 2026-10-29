//! Independent current package invocation and finalization joins.
use super::{CaseEvidenceV2, ProductObservationV2};
use crate::VerificationResult;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn fields(value: &Value, expected: &[&str]) -> VerificationResult<()> {
    let object = value
        .as_object()
        .ok_or("package carrier is not an object")?;
    if object.len() != expected.len() || expected.iter().any(|name| !object.contains_key(*name)) {
        return Err("package carrier field set differs".into());
    }
    Ok(())
}

pub fn verify_observed(
    evidence: &CaseEvidenceV2,
    input: &Value,
    resolver: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    let operation = match (evidence.key.family.as_str(), evidence.key.scenario.as_str()) {
        ("C-PACKAGE", "fresh-install") => "install",
        ("C-PACKAGE", "verify") => "verify",
        ("C-PACKAGE", "upgrade") => "upgrade",
        ("C-PACKAGE", "final-uninstall") => "uninstall",
        ("C-INSTALL-CURRENT", "opaque-state-refused") => "install",
        ("C-INSTALL-CURRENT", "fresh-without-registry") => "install",
        ("C-INSTALL-CURRENT", "current-reinstall") => "upgrade",
        ("C-INSTALL-CURRENT", "owned-current-uninstall") => "uninstall",
        ("C-INSTALL-CURRENT", "interrupted-current-install" | "current-recovery") => "upgrade",
        _ => return Err("unknown current Linux package operation".into()),
    };
    fields(
        input,
        &[
            "format",
            "revision",
            "run_id",
            "key",
            "lease_id",
            "operation",
            "operation_receipt",
        ],
    )?;
    if input["format"] != "memcordon.linux-current-package-input"
        || input["revision"] != 1
        || input["run_id"] != evidence.run_id
        || input["key"] != serde_json::to_value(&evidence.key).map_err(|e| e.to_string())?
        || input["lease_id"].as_str() != evidence.lease_id.as_deref()
        || input["operation"] != operation
        || input["operation_receipt"] != evidence.invocation
        || evidence.raw_result.is_some()
        || evidence.request.is_some()
    {
        return Err("current package input/operation association differs".into());
    }
    let receipt = crate::validate_json_document(&resolver(&evidence.invocation)?)?;
    let opaque = evidence.key.family == "C-INSTALL-CURRENT"
        && evidence.key.scenario == "opaque-state-refused";
    let status = if opaque { 125 } else { 0 };
    let interrupted = evidence.key.family == "C-INSTALL-CURRENT"
        && evidence.key.scenario == "interrupted-current-install";
    fields(
        &receipt,
        &[
            "format",
            "revision",
            "lease_id",
            "program",
            "executable_sha256",
            "arguments",
            "process",
            "completed",
        ],
    )?;
    fields(&receipt["process"], &["pid", "birth"])?;
    fields(
        &receipt["completed"],
        &["status", "raw_wait_status", "stdout", "stderr"],
    )?;
    let program = receipt["program"]
        .as_str()
        .ok_or("package original program path absent")?;
    let arguments = if operation == "verify" {
        serde_json::json!(["package", operation, "--json"])
    } else {
        serde_json::json!(["package", operation])
    };
    if receipt["format"] != "memcordon.current-root-operation"
        || receipt["revision"] != 1
        || receipt["lease_id"].as_str() != evidence.lease_id.as_deref()
        || receipt["executable_sha256"] != evidence.fixture_sha256
        || receipt["arguments"] != arguments
        || !super::linux::unix_absolute(program)
        || std::path::Path::new(program)
            .file_name()
            .and_then(|name| name.to_str())
            != Some("memcordon-sealed-agent")
        || receipt["process"]["pid"]
            .as_u64()
            .is_none_or(|pid| pid == 0 || pid > u64::from(u32::MAX))
        || receipt["process"]["birth"].as_u64().is_none()
        || receipt["completed"]["status"]
            != if interrupted {
                Value::Null
            } else {
                status.into()
            }
        || receipt["completed"]["raw_wait_status"] != if interrupted { 9 } else { status * 256 }
        || hex::encode(Sha256::digest(resolver(&evidence.fixture)?)) != evidence.fixture_sha256
    {
        return Err("actual native package child/executable/wait does not match operation".into());
    }
    let stdout: Vec<u8> = serde_json::from_value(receipt["completed"]["stdout"].clone())
        .map_err(|e| e.to_string())?;
    let stderr: Vec<u8> = serde_json::from_value(receipt["completed"]["stderr"].clone())
        .map_err(|e| e.to_string())?;
    if resolver(&evidence.stdout)? != stdout || resolver(&evidence.stderr)? != stderr {
        return Err("package raw streams differ from original reaped child capture".into());
    }
    if opaque {
        let proof = crate::validate_json_document(&resolver(&evidence.native_observation)?)?;
        let before: Vec<u8> = serde_json::from_value(proof["native"]["before"].clone())
            .map_err(|error| error.to_string())?;
        let after: Vec<u8> = serde_json::from_value(proof["native"]["after"].clone())
            .map_err(|error| error.to_string())?;
        let expected: Vec<u8> =
            serde_json::from_value(proof["bytes"].clone()).map_err(|error| error.to_string())?;
        if proof["format"] != "memcordon.linux-current-opaque-install"
            || proof["revision"] != 1
            || proof["run_id"] != evidence.run_id
            || proof["lease_id"].as_str() != evidence.lease_id.as_deref()
            || proof["operation"] != evidence.invocation
            || proof["native"]["path"] != "/usr/libexec/memcordon-sealed-agent"
            || proof["native"]["uid"] != 0
            || proof["native"]["links"] != 2
            || proof["native"]["mode"] != 0o100600
            || proof["native"]["owned_link_retired"] != true
            || proof["native"]["inode"]
                .as_u64()
                .is_none_or(|inode| inode == 0)
            || proof["native"]["device"]
                .as_u64()
                .is_none_or(|device| device == 0)
            || before != after
            || before != expected
            || !before.starts_with(b"opaque-current-install-fixture\0")
            || before.len() != b"opaque-current-install-fixture\0".len() + 32
            || crate::validate_json_document(&before).is_ok()
            || !stdout.is_empty()
            || !String::from_utf8_lossy(&stderr).contains("provider is already installed")
        {
            return Err(
                "current installer did not preserve exact original opaque occupied inode and bytes"
                    .into(),
            );
        }
    }
    if operation == "verify" {
        let inspected = crate::validate_json_document(&stdout)?;
        if inspected["format"] != "memcordon.installed-provider-inspection"
            || inspected["revision"] != 2
            || inspected["installed_artifacts_valid"] != true
            || inspected["provider_reachable"] != true
            || inspected["agent"]["executable_sha256"] != evidence.fixture_sha256
            || inspected["agent"]["format"] != "memcordon.agent-package-inspection"
            || inspected["agent"]["revision"] != 2
            || inspected["agent"]["source_commit"] != evidence.source_commit
            || inspected["agent"]["runtime_manifest_revision"] != 2
        {
            return Err(
                "current package verify did not observe selected installed provider".into(),
            );
        }
    }
    if evidence.key.family == "C-INSTALL-CURRENT"
        && evidence.key.scenario == "fresh-without-registry"
    {
        let before = crate::validate_json_document(&resolver(&evidence.native_observation)?)?;
        let expected_paths = [
            "/sys/fs/cgroup/memcordon-sealed",
            "/run/memcordon",
            "/var/lib/memcordon/workload-attempts",
            "/var/lib/memcordon/workload-inputs",
            "/var/lib/memcordon/workload-resources",
        ];
        if before["format"] != "memcordon.linux-current-fresh-install-before"
            || before["revision"] != 1
            || before["lease_id"].as_str() != evidence.lease_id.as_deref()
            || !before["paths"].as_array().is_some_and(|paths| {
                paths.len() == 5
                    && paths
                        .iter()
                        .zip(expected_paths)
                        .all(|(path, expected)| path["absent"] == true && path["path"] == expected)
            })
            || !before["package_images"].as_array().is_some_and(|images| {
                !images.is_empty()
                    && images.iter().all(|image| image["absent"] == true)
                    && images
                        .iter()
                        .any(|image| image["path"] == "/usr/libexec/memcordon-sealed-agent")
            })
        {
            return Err(
                "fresh current installation did not begin with actual native absence".into(),
            );
        }
    }
    if evidence.key.family == "C-INSTALL-CURRENT" && evidence.key.scenario == "current-reinstall" {
        let installed = crate::validate_json_document(&resolver(&evidence.native_observation)?)?;
        let images = installed["binaries"]
            .as_array()
            .ok_or("current reinstall installed image census absent")?;
        let agents: Vec<_> = images
            .iter()
            .filter(|image| image["binary"] == "memcordon-sealed-agent")
            .collect();
        if agents.len() != 1
            || agents[0]["sha256"] != evidence.fixture_sha256
            || installed["manifest"]["revision"] != 2
            || installed["manifest"]["source_commit"] != evidence.source_commit
            || installed["manifest"]["target"] != evidence.key.target
        {
            return Err(
                "current reinstall did not read back the exact current installed bytes".into(),
            );
        }
    }
    if operation == "uninstall" {
        let absence = crate::validate_json_document(&resolver(&evidence.retirement)?)?;
        if absence["format"] != "memcordon.linux-installed-absence"
            || absence["revision"] != 1
            || absence["lease_id"].as_str() != evidence.lease_id.as_deref()
        {
            return Err("current uninstall absence association differs".into());
        }
        let paths = absence["paths"]
            .as_array()
            .ok_or("current uninstall native paths absent")?;
        if paths.len() != 5
            || paths
                .iter()
                .any(|path| path["absent"] != true && path["children"] != serde_json::json!([]))
        {
            return Err("current uninstall retains native allocations".into());
        }
    }
    if evidence.key.family == "C-INSTALL-CURRENT"
        && matches!(
            evidence.key.scenario.as_str(),
            "interrupted-current-install" | "current-recovery"
        )
    {
        let native = crate::validate_json_document(&resolver(&evidence.native_observation)?)?;
        if interrupted {
            verify_interruption(&native, &receipt, evidence)?;
        } else {
            if native["format"] != "memcordon.linux-current-package-recovery"
                || native["revision"] != 1
                || native["lease_id"].as_str() != evidence.lease_id.as_deref()
                || native["journal_absent"] != true
            {
                return Err(
                    "current recovery retained a transaction journal or changed lifetime".into(),
                );
            }
            let fault = crate::validate_json_document(&resolver(
                native["interruption"]
                    .as_str()
                    .ok_or("current recovery original interruption absent")?,
            )?)?;
            let original = crate::validate_json_document(&resolver(
                fault["operation"]
                    .as_str()
                    .ok_or("current interruption original invocation absent")?,
            )?)?;
            verify_interruption(&fault, &original, evidence)?;
            let images = native["readback"]["binaries"]
                .as_array()
                .ok_or("current recovery installed image census absent")?;
            let agents: Vec<_> = images
                .iter()
                .filter(|image| image["binary"] == "memcordon-sealed-agent")
                .collect();
            if agents.len() != 1
                || agents[0]["sha256"] != evidence.fixture_sha256
                || native["readback"]["manifest"]["revision"] != 2
                || native["readback"]["manifest"]["source_commit"] != evidence.source_commit
                || native["readback"]["manifest"] != fault["manifest_before"]
            {
                return Err(
                    "current recovery did not restore/reinstall exactly the same current package"
                        .into(),
                );
            }
        }
    }
    Ok(())
}

pub fn verify_interruption(
    native: &Value,
    operation: &Value,
    evidence: &CaseEvidenceV2,
) -> VerificationResult<()> {
    let publication = &native["publication"];
    let permission = &native["permission"];
    let detached = &native["detached"];
    let identity = &operation["process"];
    let current_bytes: Vec<u8> = serde_json::from_value(native["manifest_bytes_before"].clone())
        .map_err(|error| error.to_string())?;
    let manifest = crate::validate_json_document(&current_bytes)?;
    if native["format"] != "memcordon.linux-current-install-interruption"
        || native["revision"] != 1
        || native["lease_id"].as_str() != evidence.lease_id.as_deref()
        || native["manifest_before"] != manifest
        || manifest["format"] != "memcordon.runtime-manifest"
        || manifest["revision"] != 2
        || manifest["source_commit"] != evidence.source_commit
        || manifest["target"] != evidence.key.target
        || operation["executable_sha256"] != evidence.fixture_sha256
        || operation["arguments"] != serde_json::json!(["package", "upgrade"])
        || operation["format"] != "memcordon.current-root-operation"
        || operation["revision"] != 1
        || identity["pid"]
            .as_u64()
            .is_none_or(|pid| pid == 0 || pid > u64::from(u32::MAX))
        || identity["birth"].as_u64().is_none()
        || operation["lease_id"].as_str() != evidence.lease_id.as_deref()
        || operation["completed"]["status"] != Value::Null
        || operation["completed"]["raw_wait_status"] != 9
        || permission["mechanism"] != "fanotify-open-permission"
        || permission["scope_kind"] != "file"
        || permission["file_uid"] != 0
        || permission["pid"] != identity["pid"]
        || permission["allow_written"] != true
        || permission["device"] != native["executable_identity"]["device"]
        || permission["inode"] != native["executable_identity"]["inode"]
        || permission["file_length"] != native["executable_identity"]["length"]
        || native["executable_identity"]["sha256"] != evidence.fixture_sha256
        || native["executable_identity"]["mode"] != 0o100555
        || native["executable_identity"]["uid"] != 0
        || publication["mechanism"] != "ptrace-native-rename-exit"
        || publication["pid"] != identity["pid"]
        || publication["birth"] != identity["birth"]
        || publication["return_value"] != 0
        || publication["worker_stopped_before_userspace"] != true
        || publication["destination"] != ".memcordon-current-package-transaction.json"
        || publication["source"]
            .as_str()
            .is_none_or(|source| !journal_leaf(source))
        || detached["pid"] != identity["pid"]
        || detached["birth"] != identity["birth"]
        || detached["ptrace_detached"] != true
        || detached["native_group_stop_observed"] != true
        || detached["exit_wait_consumed"] != false
        || detached["signal"] != 19
        || native["signal"] != 9
        || native["signal_result"] != 0
        || native["original_process_retired"]["pid"] != identity["pid"]
        || native["original_process_retired"]["birth"] != identity["birth"]
        || native["original_process_retired"]["pidfd_readable"] != true
        || native["original_process_retired"]["raw_wait_status"] != 9
    {
        return Err("current installer interruption lacks exact original native publication/kill/reap binding".into());
    }
    let (architecture, syscalls) = if evidence.key.target.starts_with("aarch64-") {
        (0xc00000b7_u64, vec![38_u64, 276])
    } else if evidence.key.target.starts_with("x86_64-") {
        (0xc000003e_u64, vec![82_u64, 264, 316])
    } else {
        return Err("unsupported current installer ABI".into());
    };
    if publication["architecture"] != architecture
        || !syscalls
            .iter()
            .any(|number| publication["syscall"] == *number)
        || publication["inode"].as_u64().is_none_or(|inode| inode == 0)
        || publication["directory_inode"]
            .as_u64()
            .is_none_or(|inode| inode == 0)
    {
        return Err("current installer kernel publication ABI/native inode absent".into());
    }
    let bytes: Vec<u8> = serde_json::from_value(publication["record_bytes"].clone())
        .map_err(|error| error.to_string())?;
    let journal = crate::validate_json_document(&bytes)?;
    let entries = journal["entries"]
        .as_array()
        .ok_or("current installer journal entries absent")?;
    fields(&journal, &["format", "revision", "phase", "entries"])?;
    if journal["format"] != "memcordon.current-package-transaction"
        || journal["revision"] != 1
        || journal["phase"] != "preparing"
        || entries.is_empty()
        || entries.len() > 32
    {
        return Err("interruption did not observe the current native package transaction".into());
    }
    let mut paths = std::collections::BTreeSet::new();
    let native_files = native["file_inventory"]
        .as_array()
        .ok_or("current package independent native file inventory absent")?;
    if native_files.len() != entries.len() {
        return Err("current package independent native inventory omits roles".into());
    }
    for entry in entries {
        fields(
            entry,
            &[
                "path",
                "backup",
                "old_sha256",
                "old_device",
                "old_inode",
                "stage",
                "placeholder",
            ],
        )?;
        let target = entry["path"]
            .as_str()
            .ok_or("current journal target absent")?;
        let actual: Vec<_> = native_files
            .iter()
            .filter(|file| file["path"] == target)
            .collect();
        if actual.len() != 1 {
            return Err("current package native target role duplicated/absent".into());
        }
        let actual = actual[0];
        if entry["old_sha256"].is_null() {
            if actual["target"]["absent"] != true || actual["target"]["path"] != target {
                return Err("fresh current journal target was already occupied".into());
            }
        } else if actual["target"]["path"] != target
            || actual["target"]["device"] != entry["old_device"]
            || actual["target"]["inode"] != entry["old_inode"]
            || actual["target"]["sha256"] != entry["old_sha256"]
            || actual["target"]["uid"] != 0
            || actual["target"]["links"] != 1
            || actual["target"]["mode"]
                .as_u64()
                .is_none_or(|mode| mode & 0o022 != 0)
        {
            return Err(
                "current journal old target differs from independent native inode/digest".into(),
            );
        }
        if !paths.insert(target)
            || ![
                "/usr/libexec/memcordon-sealed-agent",
                "/usr/libexec/memcordon",
                "/usr/libexec/memcordon-arm32-abi-helper",
                "/usr/libexec/memcordon-runtime-manifest.json",
                "/usr/lib/systemd/system/memcordon-sealed-agent.service",
                "/usr/lib/systemd/system/memcordon-sealed-agent.socket",
                "/usr/lib/systemd/system/memcordon-sealed-launcher.service",
                "/usr/lib/systemd/system/memcordon-sealed-launcher.socket",
                "/usr/lib/systemd/system/memcordon-sealed-network-launcher.service",
                "/usr/lib/systemd/system/memcordon-sealed-network-launcher.socket",
                "/usr/lib/tmpfiles.d/memcordon.conf",
            ]
            .contains(&target)
        {
            return Err(
                "current package journal contains an unknown/duplicate artifact role".into(),
            );
        }
        for (role, prefix) in [
            ("stage", ".memcordon-stage-"),
            ("placeholder", ".memcordon-backup-"),
        ] {
            let file = &entry[role];
            if file.is_null() {
                if !actual[role].is_null() {
                    return Err("native current temporary role has no journal owner".into());
                }
                continue;
            }
            for field in ["path", "device", "inode", "mode", "sha256"] {
                if actual[role][field] != file[field] {
                    return Err("current temporary inode/digest differs from independent native observation".into());
                }
            }
            if actual[role]["uid"] != 0 || actual[role]["links"] != 1 {
                return Err("current temporary native inode is not exclusively root-owned".into());
            }
            fields(file, &["path", "device", "inode", "mode", "sha256"])?;
            let path = std::path::Path::new(
                file["path"]
                    .as_str()
                    .ok_or("current temporary native path absent")?,
            );
            if path.parent() != std::path::Path::new(target).parent()
                || path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_none_or(|name| !name.starts_with(prefix))
                || file["inode"].as_u64().is_none_or(|inode| inode == 0)
                || file["mode"]
                    .as_u64()
                    .is_none_or(|mode| mode & 0o022 != 0 || mode & !0o7777 != 0)
                || file["sha256"].as_str().is_none_or(|hash| {
                    hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
            {
                return Err("current package temporary inode/digest custody differs".into());
            }
        }
        if entry["backup"].is_null() != entry["placeholder"].is_null()
            || (!entry["placeholder"].is_null()
                && (entry["placeholder"]["path"] != entry["backup"]
                    || entry["placeholder"]["mode"] != 0o600
                    || entry["placeholder"]["sha256"] != crate::sha256(&[])))
        {
            return Err("current package backup placeholder authority differs".into());
        }
    }
    let agents: Vec<_> = entries
        .iter()
        .filter(|entry| entry["path"] == "/usr/libexec/memcordon-sealed-agent")
        .collect();
    if agents.len() != 1
        || agents[0]["old_sha256"] != evidence.fixture_sha256
        || agents[0]["old_inode"]
            .as_u64()
            .is_none_or(|inode| inode == 0)
        || agents[0]["backup"].as_str().is_none()
    {
        return Err("interrupted package was not the installed same-current provider".into());
    }
    Ok(())
}
fn journal_leaf(value: &str) -> bool {
    std::path::Path::new(value)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(".memcordon-journal-"))
}
pub fn verify_case(
    evidence: &CaseEvidenceV2,
    input: &Value,
    product: &ProductObservationV2,
    resolver: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    let agents = product
        .components
        .iter()
        .filter(|component| component.role == "sealed-agent")
        .collect::<Vec<_>>();
    if agents.len() != 1 || agents[0].installed_sha256 != evidence.fixture_sha256 {
        return Err("package operation did not execute selected product agent".into());
    }
    if evidence.key.family == "C-INSTALL-CURRENT"
        && matches!(
            evidence.key.scenario.as_str(),
            "interrupted-current-install" | "current-recovery"
        )
    {
        let native = crate::validate_json_document(&resolver(&evidence.native_observation)?)?;
        let fault = if evidence.key.scenario == "current-recovery" {
            crate::validate_json_document(&resolver(
                native["interruption"]
                    .as_str()
                    .ok_or("current recovery original source capture absent")?,
            )?)?
        } else {
            native
        };
        let bytes: Vec<u8> = serde_json::from_value(fault["manifest_bytes_before"].clone())
            .map_err(|error| error.to_string())?;
        if bytes != resolver(&product.runtime_manifest)? {
            return Err(
                "current interruption descriptor is not exact selected installed product inventory"
                    .into(),
            );
        }
    }
    verify_observed(evidence, input, resolver)
}
