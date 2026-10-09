//! Independent, nonpublished acceptance policy for consumer-readiness.v1.
//! No producer library, expected-set generator, or result validation is linked.
mod anchors;
mod custody;
mod wire;
pub use wire::{
    validate_mixed_public_arguments as validate_linux_mixed_public_arguments,
    validate_mixed_public_invocation as validate_linux_mixed_public_invocation,
};
mod behavior;
mod filter_anchor;
mod linux_account_refusal;
mod linux_build;
mod linux_component;
mod linux_cross_account;
mod linux_cross_attempt;
mod linux_isolation;
pub use linux_account_refusal::LinuxAccountRefusalEvidence;
mod linux_import_refusal;
pub use linux_import_refusal::LinuxIsolationImportEvidence;
pub use linux_isolation::validate_linux_outside_file;
mod linux_policy;
pub mod windows_acceptance;
mod windows_actors;
mod windows_toolchain;
pub use linux_policy::LinuxPolicyGateEvidence;
pub use linux_policy::validate_linux_policy_discovery;
pub use linux_policy::validate_linux_policy_gate;
pub use linux_policy::{
    LinuxPolicyDiscoveryEvidence, LinuxPolicyRefusalEvidence,
    validate_linux_policy_activation_sequence, validate_linux_policy_command_capture,
    validate_linux_policy_frontend, validate_linux_policy_mutation,
    validate_linux_policy_refusal_result,
};
mod linux_exports;
mod linux_images;
mod linux_limits;
mod linux_recovery;
mod linux_recovery_route;
mod linux_registry;
mod linux_release;
pub use linux_exports::{
    LinuxImageExportEvidence, validate_linux_export_outcome,
    validate_linux_export_permission_settlement, validate_linux_export_source,
};
mod linux_ingress;
mod linux_legacy;
mod linux_lifecycle;
mod linux_policy_running;
pub use linux_ingress::LinuxMalformedIngressEvidence;
pub use linux_legacy::{
    LinuxFrozenLegacyCommand, LinuxFrozenLegacyEvidence, linux_frozen_native_launch,
    linux_frozen_request_digest,
};
pub use linux_lifecycle::{
    LinuxDeliveryEvidence, LinuxLifecycleLossEvidence, validate_linux_lifecycle_intervention,
};
mod linux_refusal_census;
pub use filter_anchor::frozen_linux_filter_program;
pub use linux_build::{linux_image_reference, validate_linux_generated_lifecycle};
pub use linux_component::{
    FilterObservation, FilterVector, Instruction, JournalProcess, LinuxFilterReceipt,
    LinuxJournalReceipt, LinuxVersionReceipt, validate_linux_filter_receipt,
    validate_linux_journal_receipt, validate_linux_mixed_version_vector,
    validate_linux_version_vector,
};
pub use linux_images::{
    LinuxImageImportEvidence, LinuxImageMemberCapture, LinuxImagePreparationEvidence,
    validate_linux_image_command, validate_linux_image_mutation,
};
pub use linux_limits::{validate_bounded_large_streams, validate_memory_event_transition};
pub use linux_recovery::{
    LinuxCrashExit, LinuxCrashIntent, LinuxLostTerminalReceipt, LinuxNativeRecoveryCaseEvidence,
    LinuxPreAccountNative, LinuxRecoveredOwnership, LinuxRecoveryCapture, LinuxRecoveryCgroup,
    LinuxRecoveryCommandProcess, LinuxRecoveryComponentEvidence, LinuxRecoveryInvocation,
    LinuxRecoveryOwnership, LinuxRecoveryProcess, LinuxRecoveryReservationRecord,
    LinuxRecoveryWorker, validate_linux_crash_controller, validate_linux_lost_terminal_delivery,
    validate_linux_pre_account_native, validate_linux_recovered_ownership,
    validate_linux_recovery_capture, validate_linux_recovery_command_process,
    validate_linux_recovery_ownership, validate_linux_recovery_reservation,
};
pub(crate) use linux_refusal_census::validate_linux_refusal_census;
pub use linux_registry::linux_registry_digest;
pub use linux_release::{
    LinuxReleaseGate, LinuxReleaseObservation, LinuxReleaseReceipt, LinuxReleaseReference,
    LinuxReleaseWait, linux_release_effective_invocation,
    validate_linux_component_fixture_acquisition, validate_linux_release_gate,
    validate_linux_release_ownership, validate_linux_release_policy,
    validate_linux_release_receipt, validate_linux_release_reference,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const PROFILE: &str = "memcordon.consumer-readiness.v1";
pub const MAX_INDEX_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
pub type VerificationResult<T> = Result<T, String>;

pub fn validate_windows_receiptless_cause(
    original: &serde_json::Value,
    secondary: &serde_json::Value,
) -> VerificationResult<()> {
    let expected = serde_json::json!({"observed":{"event":{"sequence":1,"origin":"launcher","category":"monitor",
        "operation":"observe-process-identity","code":"process-inventory-observation","native_code":{"win32":1234},
        "observed_phase":"monitoring","safe_detail":"no-additional-detail","detail_redacted":true,
        "detail_truncated":false,"terminalization_reference":null}}});
    let expected_secondary = serde_json::json!({"sequence":2,"origin":"launcher","category":"terminalization",
        "operation":"validate-terminal-response","code":"terminal-binding","native_code":null,
        "observed_phase":"terminalizing","safe_detail":"no-additional-detail","detail_redacted":true,
        "detail_truncated":false,"terminalization_reference":"first-error"});
    if original != &expected || secondary != &expected_secondary {
        return Err("receiptless cause differs from exact declared component vector".into());
    }
    Ok(())
}

fn validate_producer_bundle(
    index: &EvidenceIndex,
    origin: &ProducerOrigin,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    use std::io::Read;
    if origin.repository != index.repository {
        return Err("producer API repository differs from native assessment repository".into());
    }
    if custody.hash(&origin.bundle_artifact)? != origin.artifact_sha256 {
        return Err("actual downloaded producer archive digest differs".into());
    }
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(
        custody.bytes(&origin.bundle_artifact)?,
    ))
    .map_err(|error| error.to_string())?;
    if archive.len() > 131_072 {
        return Err("producer ZIP member count exceeds finite bound".into());
    }
    let mut members = BTreeSet::new();
    let mut total = 0u64;
    for ordinal in 0..archive.len() {
        let member = archive
            .by_index(ordinal)
            .map_err(|error| error.to_string())?;
        let name = member.name();
        let path = name.strip_suffix('/').unwrap_or(name);
        custody::validate_path(path)?;
        if !members.insert(name.to_owned()) || member.size() > MAX_ARTIFACT_BYTES {
            return Err("producer ZIP member duplicate/oversized".into());
        }
        if let Some(mode) = member.unix_mode() {
            let kind = mode & 0o170000;
            if ![0, 0o100000, 0o040000].contains(&kind)
                || (kind == 0o040000 && !member.is_dir())
                || (kind == 0o100000 && member.is_dir())
            {
                return Err("producer ZIP contains a special/aliased member".into());
            }
        }
        total = total
            .checked_add(member.size())
            .ok_or("producer ZIP total overflow")?;
        if total > 4 * 1024 * 1024 * 1024 {
            return Err("producer ZIP decoded bytes exceed finite bound".into());
        }
    }
    let manifest_bytes = {
        let member = archive
            .by_name("producer-manifest.json")
            .map_err(|_| "producer archive lacks immutable original manifest")?;
        if member.is_dir() || member.size() > MAX_INDEX_BYTES as u64 {
            return Err("producer archive manifest exceeds bound".into());
        }
        let declared = member.size();
        let mut bytes = Vec::new();
        member
            .take(MAX_INDEX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() > MAX_INDEX_BYTES || bytes.len() as u64 != declared {
            return Err("producer manifest decoded length differs/exceeds bound".into());
        }
        bytes
    };
    let manifest: ProducerManifest = wire::decode(&manifest_bytes)?;
    header(
        &manifest.format,
        manifest.revision,
        "memcordon.consumer-readiness.producer",
    )?;
    if manifest.job != origin.job
        || manifest.run_id != origin.run_id
        || manifest.run_attempt != origin.run_attempt
        || manifest.source_commit != origin.source_commit
        || manifest.source_tree_sha256 != origin.source_tree_sha256
        || manifest.version != origin.version
        || manifest.manifest_sha256 != origin.manifest_sha256
    {
        return Err(
            "original producer ZIP run/attempt/source/profile differs from transported origin"
                .into(),
        );
    }
    if manifest.artifacts.len() > 131_072
        || manifest.products.len() > 1
        || manifest.component_builds.len() > 1
        || manifest.records.len() > 16_384
    {
        return Err("producer payload collections exceed finite cell bounds".into());
    }
    let mut artifact_names = BTreeSet::new();
    for artifact in &manifest.artifacts {
        if !artifact_names.insert(artifact.path.as_str())
            || artifact.path == "producer-manifest.json"
            || artifact.path == origin.bundle_artifact
        {
            return Err("producer artifact table duplicate/self-referential".into());
        }
        let expected = custody.bytes(&artifact.path)?;
        if expected.len() as u64 != artifact.length || sha256(expected) != artifact.sha256 {
            return Err("producer raw artifact table differs from assessed bytes".into());
        }
        let member = archive
            .by_name(&artifact.path)
            .map_err(|_| "assessed raw artifact absent from actual producer ZIP")?;
        if member.is_dir() || member.size() != artifact.length {
            return Err("producer member type/length differs".into());
        }
        let mut bytes = Vec::new();
        member
            .take(artifact.length + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() as u64 != artifact.length {
            return Err("producer member decoded length differs/exceeds bound".into());
        }
        if bytes != expected {
            return Err("current raw evidence bytes differ from original producer ZIP".into());
        }
    }
    fn equal<T: Serialize>(left: &T, right: &T) -> VerificationResult<bool> {
        Ok(
            serde_json::to_value(left).map_err(|error| error.to_string())?
                == serde_json::to_value(right).map_err(|error| error.to_string())?,
        )
    }
    let mut product_keys = BTreeSet::new();
    for product in &manifest.products {
        if producer_job(&product.key.target, Some(&product.key.channel))? != origin.job
            || !product_keys.insert(product.key.clone())
        {
            return Err("producer archive product assigned to another job/duplicated".into());
        }
        let current = index
            .products
            .iter()
            .find(|current| current.key == product.key)
            .ok_or("original producer product missing from assessment")?;
        if !equal(current, product)? {
            return Err("assessed product differs from immutable original producer payload".into());
        }
        let mut paths = vec![
            product.materialization.as_str(),
            product.runtime_manifest.as_str(),
            product.lifecycle.journal.as_str(),
            product.lifecycle.receipt.as_str(),
        ];
        paths.extend(
            product
                .components
                .iter()
                .map(|component| component.artifact.as_str()),
        );
        if let Some(path) = &product.registry_graph {
            paths.push(path);
            let graph: RegistryGraph = wire::decode(custody.bytes(path)?)?;
            if !artifact_names.contains(graph.raw_metadata.as_str())
                || !artifact_names.contains(graph.raw_lock.as_str())
                || graph
                    .packages
                    .iter()
                    .any(|package| !artifact_names.contains(package.crate_artifact.as_str()))
            {
                return Err(
                    "Cargo raw graph metadata/lock/crates cross producer archive custody".into(),
                );
            }
        }
        if paths.iter().any(|path| !artifact_names.contains(path)) {
            return Err("product artifact crosses original producer archive custody".into());
        }
        let journal: InstalledLifecycleJournal =
            wire::decode(custody.bytes(&product.lifecycle.journal)?)?;
        if journal
            .events
            .iter()
            .any(|event| !artifact_names.contains(event.native_receipt.as_str()))
        {
            return Err(
                "lifecycle native operation receipt crosses producer archive custody".into(),
            );
        }
    }
    for product in &index.products {
        if producer_job(&product.key.target, Some(&product.key.channel))? == origin.job
            && !product_keys.contains(&product.key)
        {
            return Err("assessed product is absent from original producer archive".into());
        }
    }
    let mut build_targets = BTreeSet::new();
    for build in &manifest.component_builds {
        if producer_job(&build.target, None)? != origin.job
            || !build_targets.insert(build.target.as_str())
        {
            return Err("producer component assigned to another job/duplicated".into());
        }
        let current = index
            .component_builds
            .iter()
            .find(|current| current.target == build.target)
            .ok_or("original component build missing from assessment")?;
        if !equal(current, build)? {
            return Err("assessed native build differs from original producer archive".into());
        }
        if !artifact_names.contains(build.executable.as_str()) {
            return Err(
                "native component executable crosses original producer archive custody".into(),
            );
        }
        if build
            .actor_executable
            .as_ref()
            .is_some_and(|path| !artifact_names.contains(path.as_str()))
        {
            return Err("native component actor crosses original producer archive custody".into());
        }
        if build
            .parser_executable
            .as_ref()
            .is_some_and(|path| !artifact_names.contains(path.as_str()))
        {
            return Err("native parser harness crosses original producer archive custody".into());
        }
    }
    for build in &index.component_builds {
        if producer_job(&build.target, None)? == origin.job
            && !build_targets.contains(build.target.as_str())
        {
            return Err("assessed native build absent from original producer archive".into());
        }
    }
    let mut record_keys = BTreeSet::new();
    for record in &manifest.records {
        if producer_job(&record.key.target, record.key.channel.as_deref())? != origin.job
            || record.run_id != origin.run_id
            || !record_keys.insert(record.key.clone())
        {
            return Err("producer raw row assigned to another job/run/duplicated".into());
        }
        let current = index
            .records
            .iter()
            .find(|current| current.key == record.key)
            .ok_or("original producer row absent from assessment")?;
        if !equal(current, record)? {
            return Err("assessed raw row differs from immutable original producer archive".into());
        }
        if let Some(path) = &record.evidence {
            if !artifact_names.contains(path.as_str()) {
                return Err("producer row points outside original archive custody table".into());
            }
            let raw: serde_json::Value = wire::decode(custody.bytes(path)?)?;
            if raw["format"] == "memcordon.consumer-readiness.linux-isolation-import-refusal" {
                let evidence: LinuxIsolationImportEvidence =
                    serde_json::from_value(raw).map_err(|error| error.to_string())?;
                if evidence.key != record.key
                    || evidence.run_id != origin.run_id
                    || evidence.source_commit != index.source_commit
                    || evidence.source_tree_sha256 != index.source_tree_sha256
                {
                    return Err("isolation import crosses original producer row/source".into());
                }
                for path in evidence.artifact_paths() {
                    custody::validate_path(path)?;
                    if !artifact_names.contains(path) {
                        return Err(
                            "isolation import references another original producer archive".into(),
                        );
                    }
                }
                continue;
            }
            if raw["format"] == "memcordon.consumer-readiness.linux-account-refusal" {
                let evidence: LinuxAccountRefusalEvidence =
                    serde_json::from_value(raw).map_err(|error| error.to_string())?;
                if evidence.key != record.key
                    || evidence.run_id != origin.run_id
                    || evidence.source_commit != index.source_commit
                    || evidence.source_tree_sha256 != index.source_tree_sha256
                {
                    return Err("account refusal crosses original producer row/source".into());
                }
                for path in evidence.artifact_paths() {
                    custody::validate_path(path)?;
                    if !artifact_names.contains(path) {
                        return Err(
                            "account refusal references another original producer archive".into(),
                        );
                    }
                }
                continue;
            }
            if raw["format"] == "memcordon.consumer-readiness.linux-policy-refusal" {
                let evidence: LinuxPolicyRefusalEvidence =
                    serde_json::from_value(raw).map_err(|error| error.to_string())?;
                if evidence.key != record.key
                    || evidence.run_id != origin.run_id
                    || evidence.source_commit != index.source_commit
                    || evidence.source_tree_sha256 != index.source_tree_sha256
                {
                    return Err(
                        "policy refusal crosses original producer row/source custody".into(),
                    );
                }
                for path in evidence.artifact_paths() {
                    custody::validate_path(path)?;
                    if !artifact_names.contains(path) {
                        return Err("policy refusal references another producer archive".into());
                    }
                }
                let census: serde_json::Value =
                    wire::decode(custody.bytes(&evidence.native_census)?)?;
                let owner: serde_json::Value = wire::decode(custody.bytes(&evidence.owner)?)?;
                let mut checkpoints = 0usize;
                for path in artifact_names
                    .iter()
                    .filter(|path| path.ends_with("/owned-resources-acquired.json"))
                {
                    let checkpoint: serde_json::Value = wire::decode(custody.bytes(path)?)?;
                    if checkpoint["identity"] == census["identity"]
                        && checkpoint["cell"] == census["cell"]
                        && checkpoint["admin_root"] == owner["admin_root"]
                        && checkpoint["account"] == census["account"]
                    {
                        checkpoints += 1;
                    }
                }
                if checkpoints != 1 {
                    return Err(
                        "policy account acquisition lacks unique original archive custody".into(),
                    );
                }
                continue;
            }
            if raw["format"] == "memcordon.consumer-readiness.linux-malformed-ingress" {
                let evidence: LinuxMalformedIngressEvidence =
                    serde_json::from_value(raw).map_err(|error| error.to_string())?;
                if evidence.key != record.key
                    || evidence.run_id != origin.run_id
                    || evidence.source_commit != index.source_commit
                    || evidence.source_tree_sha256 != index.source_tree_sha256
                {
                    return Err("malformed ingress crosses original producer archive source".into());
                }
                for path in evidence.artifact_paths() {
                    custody::validate_path(path)?;
                    if !artifact_names.contains(path) {
                        return Err("malformed ingress references another producer archive".into());
                    }
                }
                if !evidence.original_lease.ends_with("/lease-owner.json")
                    || !evidence
                        .acquisition
                        .ends_with("/owned-resources-acquired.json")
                {
                    return Err(
                        "malformed ingress omits original pre-mutation acquisition members".into(),
                    );
                }
                continue;
            }
            if raw["format"] == "memcordon.consumer-readiness.linux-frozen-legacy" {
                let evidence: LinuxFrozenLegacyEvidence =
                    serde_json::from_value(raw).map_err(|error| error.to_string())?;
                if evidence.key != record.key
                    || evidence.run_id != origin.run_id
                    || evidence.source_commit != index.source_commit
                    || evidence.source_tree_sha256 != index.source_tree_sha256
                {
                    return Err("frozen legacy crosses original producer source".into());
                }
                for path in evidence.artifact_paths() {
                    custody::validate_path(path)?;
                    if !artifact_names.contains(path) {
                        return Err(
                            "frozen legacy references another original producer archive".into()
                        );
                    }
                }
                continue;
            }
            if raw["format"] == "memcordon.consumer-readiness.acquisition-case" {
                let evidence: AcquisitionCaseEvidence =
                    serde_json::from_value(raw).map_err(|error| error.to_string())?;
                for path in [
                    &evidence.original_acquisition,
                    &evidence.substituted_acquisition,
                    &evidence.refusal,
                    &evidence.quiescence,
                    &evidence.fixture,
                ] {
                    if !artifact_names.contains(path.as_str()) {
                        return Err(
                            "acquisition refusal references another producer archive".into()
                        );
                    }
                }
                continue;
            }
            if raw["format"] == "memcordon.consumer-readiness.linux-native-recovery" {
                let evidence: LinuxNativeRecoveryCaseEvidence =
                    serde_json::from_value(raw).map_err(|error| error.to_string())?;
                if evidence.revision != 1
                    || evidence.key != record.key
                    || evidence.run_id != origin.run_id
                    || evidence.source_commit != index.source_commit
                    || evidence.source_tree_sha256 != index.source_tree_sha256
                    || record.key.channel.is_some()
                    || record.key.evidence_class != EvidenceClass::NativeComponentRegression
                    || record.key.family != "L-LIFE-04"
                    || match &evidence.recovery {
                        LinuxRecoveryComponentEvidence::AccountRetirementCrash { .. } => {
                            record.key.scenario != "crash-before-account-retirement"
                        }
                        LinuxRecoveryComponentEvidence::LostTerminalResponse { .. } => {
                            record.key.scenario != "lost-terminal-response"
                        }
                    }
                {
                    return Err("native recovery crosses original producer row/source scope".into());
                }
                for path in evidence.artifact_paths() {
                    custody::validate_path(path)?;
                    if !artifact_names.contains(path) {
                        return Err("native recovery references another producer archive".into());
                    }
                }
                let recipe = if record.key.scenario == "crash-before-account-retirement" {
                    "account-retirement"
                } else {
                    "lost-terminal"
                };
                let base = format!("{}/candidate-native/components", record.key.target);
                for path in [
                    "native-prepared.json",
                    "native-exit.json",
                    "recovery-fixture.json",
                    "current-contract.json",
                    "current-activation.json",
                    "boundary-journal.bin",
                    "boundary-reference.json",
                    "export-receipt.json",
                ]
                .map(|leaf| format!("{base}/{recipe}/{leaf}"))
                .into_iter()
                .chain([
                    format!("{base}/roles/compiler/native-operation-deadline.json"),
                    format!("{base}/roles/compiler/acquisition-origin.json"),
                    format!("{base}/roles/compiler/measured-harnesses.json"),
                    format!("{base}/roles/compiler/native-host.json"),
                    format!("{base}/roles/compiler/native-compiler.bin"),
                ]) {
                    if !artifact_names.contains(path.as_str()) {
                        return Err(
                            "native recovery implicit raw peer crosses producer archive".into()
                        );
                    }
                }
                continue;
            }
            if raw["format"] == "memcordon.consumer-readiness.linux-image-import" {
                let evidence: LinuxImageImportEvidence =
                    serde_json::from_value(raw).map_err(|error| error.to_string())?;
                if evidence.key != record.key
                    || evidence.run_id != origin.run_id
                    || evidence.source_commit != index.source_commit
                    || evidence.source_tree_sha256 != index.source_tree_sha256
                {
                    return Err("image import crosses original producer source/row".into());
                }
                for path in evidence.artifact_paths() {
                    custody::validate_path(path)?;
                    if !artifact_names.contains(path) {
                        return Err(
                            "image import references another original producer archive".into()
                        );
                    }
                }
                continue;
            }
            if raw["format"] == "memcordon.consumer-readiness.linux-image-export" {
                let evidence: LinuxImageExportEvidence =
                    serde_json::from_value(raw).map_err(|error| error.to_string())?;
                if evidence.key != record.key
                    || evidence.run_id != origin.run_id
                    || evidence.source_commit != index.source_commit
                    || evidence.source_tree_sha256 != index.source_tree_sha256
                {
                    return Err("image export crosses original producer source/row".into());
                }
                for path in evidence.artifact_paths() {
                    custody::validate_path(path)?;
                    if !artifact_names.contains(path) {
                        return Err(
                            "image export references another original producer archive".into()
                        );
                    }
                }
                continue;
            }
            if [
                "memcordon.consumer-readiness.linux-lifecycle-loss",
                "memcordon.consumer-readiness.linux-delivery",
            ]
            .contains(&raw["format"].as_str().unwrap_or(""))
            {
                let evidence: LinuxLifecycleLossEvidence =
                    serde_json::from_value(raw).map_err(|error| error.to_string())?;
                if evidence.key != record.key
                    || evidence.run_id != origin.run_id
                    || evidence.source_commit != index.source_commit
                    || evidence.source_tree_sha256 != index.source_tree_sha256
                {
                    return Err(
                        "lifecycle raw evidence crosses original producer source/row".into(),
                    );
                }
                for path in evidence.artifact_paths() {
                    custody::validate_path(path)?;
                    if !artifact_names.contains(path) {
                        return Err(
                            "lifecycle raw evidence references another original producer archive"
                                .into(),
                        );
                    }
                }
                let originals = index.artifacts.iter().filter(|artifact| {
                    artifact.path.rsplit('/').next() == Some("lease-owner.json")
                });
                let mut found = false;
                for artifact in originals {
                    let lease: serde_json::Value = wire::decode(custody.bytes(&artifact.path)?)?;
                    if lease["lease_id"] == evidence.lease_id
                        && lease["identity"]["run_id"] == evidence.run_id
                    {
                        if found || !artifact_names.contains(artifact.path.as_str()) {
                            return Err(
                                "lifecycle original lease crosses producer archive or is ambiguous"
                                    .into(),
                            );
                        }
                        found = true;
                    }
                }
                if !found {
                    return Err(
                        "lifecycle original lease acquisition absent from producer archive".into(),
                    );
                }
                continue;
            }
            let evidence: CaseEvidence =
                serde_json::from_value(raw).map_err(|error| error.to_string())?;
            let mut paths = vec![
                &evidence.fixture,
                &evidence.fixture_source,
                &evidence.input,
                &evidence.invocation,
                &evidence.native_observation,
                &evidence.retirement,
                &evidence.semantic_observation,
            ];
            for path in [
                &evidence.request,
                &evidence.raw_result,
                &evidence.provider_request,
                &evidence.authenticated_terminal,
                &evidence.execution_invocation,
                &evidence.execution_environment,
                &evidence.transcript,
                &evidence.inventory,
                &evidence.qualification,
                &evidence.export_receipt,
                &evidence.prepared_observation,
                &evidence.prepared_native_receipt,
            ]
            .into_iter()
            .flatten()
            {
                paths.push(path);
            }
            if paths
                .iter()
                .any(|path| !artifact_names.contains(path.as_str()))
            {
                return Err("case evidence references another producer archive".into());
            }
            let invocation: NativeInvocation = wire::decode(custody.bytes(&evidence.invocation)?)?;
            let semantic: SemanticObservation =
                wire::decode(custody.bytes(&evidence.semantic_observation)?)?;
            if record.key.evidence_class == EvidenceClass::NativeComponentRegression
                && semantic.component_actors.is_some() == semantic.component_test.is_some()
            {
                return Err(
                    "native component requires exactly one actual harness or actor execution role"
                        .into(),
                );
            }
            let mut nested = vec![invocation.environment.as_str()];
            if let Some(behavior) = &semantic.fixture_behavior {
                nested.extend([behavior.descriptor.as_str(), behavior.transcript.as_str()]);
                if let Some(token) = &behavior.expected_token {
                    nested.push(token);
                }
                if let Some(binding) = &behavior.native_binding {
                    nested.push(binding);
                }
                nested.extend(
                    behavior
                        .peer_artifacts
                        .iter()
                        .map(|artifact| artifact.path.as_str()),
                );
                for peer in behavior
                    .peer_artifacts
                    .iter()
                    .filter(|peer| peer.role == "selected-native-library-inputs")
                {
                    let inputs: serde_json::Value = wire::json(custody.bytes(&peer.path)?)?;
                    for input in inputs
                        .as_array()
                        .ok_or("native library input inventory is not an array")?
                    {
                        let path = input["artifact"]
                            .as_str()
                            .ok_or("native library input artifact absent")?;
                        if !artifact_names.contains(path) {
                            return Err(
                                "native library input crosses original producer archive".into()
                            );
                        }
                    }
                }
            }
            if let Some(actors) = &semantic.component_actors {
                for actor in actors {
                    nested.extend([
                        actor.invocation.as_str(),
                        actor.exit.as_str(),
                        actor.observation.as_str(),
                        actor.stdout.as_str(),
                        actor.stderr.as_str(),
                        actor.actor_held.as_str(),
                        actor.native_retirement.as_str(),
                        actor.settlement_inventory.as_str(),
                        actor.provider_request.as_str(),
                        actor.settlement_invocation.as_str(),
                        actor.settlement_exit.as_str(),
                        actor.settlement_stderr.as_str(),
                        actor.settlement_deadline.as_str(),
                    ]);
                    for path in [
                        &actor.held_before,
                        &actor.held_after,
                        &actor.worker_exit,
                        &actor.frontend_exit,
                        &actor.recovery,
                        &actor.recovery_invocation,
                        &actor.recovery_exit,
                        &actor.recovery_stderr,
                        &actor.control_worker_site,
                        &actor.control_worker_held,
                    ]
                    .into_iter()
                    .flatten()
                    {
                        nested.push(path);
                    }
                }
            }
            if let Some(capacity) = &semantic.windows_capacity {
                nested.extend(capacity.attempts.iter().map(String::as_str));
                nested.extend(capacity.inventories.iter().map(String::as_str));
                for path in [
                    &capacity.overlap_live_association,
                    &capacity.overlap_held_guardian,
                ]
                .into_iter()
                .flatten()
                {
                    nested.push(path);
                }
            }
            if let Some(refusal) = &semantic.windows_refusal {
                if !matches!(
                    refusal,
                    WindowsRefusalEvidence::AcquisitionSubstitution { .. }
                ) {
                    let result = evidence
                        .raw_result
                        .as_deref()
                        .ok_or("executed Windows refusal omits actual capture parent")?;
                    let parent = result
                        .rsplit_once('/')
                        .ok_or("Windows refusal raw result namespace absent")?
                        .0;
                    if ["stdout.bin", "stderr.bin"]
                        .iter()
                        .any(|leaf| !artifact_names.contains(format!("{parent}/{leaf}").as_str()))
                    {
                        return Err(
                            "Windows refusal captures cross original producer ZIP custody".into(),
                        );
                    }
                }
                if matches!(
                    refusal,
                    WindowsRefusalEvidence::AuthenticatedAdmission { .. }
                ) {
                    let product = manifest
                        .products
                        .iter()
                        .find(|product| {
                            product.key.target == record.key.target
                                && Some(product.key.channel.as_str())
                                    == record.key.channel.as_deref()
                        })
                        .ok_or("authenticated refusal original selected product absent")?;
                    let parent = product
                        .lifecycle
                        .journal
                        .rsplit_once('/')
                        .ok_or("authenticated refusal original lifetime namespace absent")?
                        .0;
                    if !artifact_names.contains(format!("{parent}/selected-current.json").as_str())
                    {
                        return Err("Windows authenticated refusal acquisition crosses original producer ZIP custody".into());
                    }
                }
                match refusal {
                    WindowsRefusalEvidence::AuthenticatedAdmission {
                        provider_request,
                        requested_contract,
                        quiescence,
                        policy_apply,
                        policy_restore,
                        baseline_policy,
                        baseline_contract,
                        baseline_activation,
                        prior_contract,
                        prior_activation,
                        prior_invocation,
                        prior_exit,
                        prior_stderr,
                        guardian_quiescence,
                        frontend,
                    } => {
                        nested.extend([
                            provider_request.as_str(),
                            requested_contract.as_str(),
                            quiescence.as_str(),
                            baseline_policy.as_str(),
                            baseline_contract.as_str(),
                            baseline_activation.as_str(),
                            prior_contract.as_str(),
                            prior_activation.as_str(),
                            prior_invocation.as_str(),
                            prior_exit.as_str(),
                            prior_stderr.as_str(),
                            guardian_quiescence.as_str(),
                            frontend.as_str(),
                        ]);
                        for path in [policy_apply, policy_restore].into_iter().flatten() {
                            nested.push(path);
                        }
                    }
                    WindowsRefusalEvidence::UnsupportedPublicRequest {
                        quiescence,
                        guardian_quiescence,
                        frontend,
                    } => nested.extend([
                        quiescence.as_str(),
                        guardian_quiescence.as_str(),
                        frontend.as_str(),
                    ]),
                    WindowsRefusalEvidence::NativeArgument {
                        receipt,
                        quiescence,
                        guardian_quiescence,
                        frontend,
                    } => nested.extend([
                        receipt.as_str(),
                        quiescence.as_str(),
                        guardian_quiescence.as_str(),
                        frontend.as_str(),
                    ]),
                    WindowsRefusalEvidence::AcquisitionSubstitution {
                        original_acquisition,
                        substituted_acquisition,
                        receipt,
                        quiescence,
                    } => nested.extend([
                        original_acquisition.as_str(),
                        substituted_acquisition.as_str(),
                        receipt.as_str(),
                        quiescence.as_str(),
                    ]),
                }
            }
            if let Some(test) = &semantic.component_test {
                nested.extend([test.native_receipt.as_str(), test.raw_test_output.as_str()]);
                if let Some(path) = &test.native_retirement {
                    nested.push(path);
                }
                if let Some(fixture) = &test.fixture_acquisition {
                    nested.extend([
                        fixture.checkpoint.as_str(),
                        fixture.account_intent.as_str(),
                        fixture.account_readback.as_str(),
                        fixture.group_readback.as_str(),
                    ]);
                }
            }
            if record.key.evidence_class == EvidenceClass::NativeComponentRegression
                && record.key.family == "L-VER-01"
                && record.key.scenario == "journal-barrier"
            {
                let test = semantic
                    .component_test
                    .as_ref()
                    .ok_or("native journal lacks actual harness")?;
                let receipt: LinuxJournalReceipt =
                    wire::decode(custody.bytes(&test.native_receipt)?)?;
                let prefix = test
                    .native_receipt
                    .rsplit_once('/')
                    .ok_or("journal receipt has no producer namespace")?
                    .0;
                let input = format!("{prefix}/native-input.json");
                if [
                    &receipt.record_before,
                    &receipt.record_after_refusal,
                    &input,
                ]
                .iter()
                .any(|path| !artifact_names.contains(path.as_str()))
                {
                    return Err("journal raw bytes cross original producer ZIP custody".into());
                }
            }
            if record.key.evidence_class == EvidenceClass::NativeComponentRegression
                && record.key.family == "L-VER-01"
                && record.key.scenario == "release-barrier"
            {
                let test = semantic
                    .component_test
                    .as_ref()
                    .ok_or("native release lacks actual harness")?;
                let receipt: LinuxReleaseReceipt =
                    wire::decode(custody.bytes(&test.native_receipt)?)?;
                let prefix = test
                    .native_receipt
                    .rsplit_once('/')
                    .ok_or("release receipt has no producer namespace")?
                    .0;
                if receipt.artifact_paths().iter().any(|path|!artifact_names.contains(*path))
                    || !artifact_names.contains(format!("{prefix}/native-input.json").as_str())
                    || !artifact_names.contains(format!("{}/candidate-native/components/roles/compiler/native-operation-deadline.json",record.key.target).as_str())
                    || !artifact_names.contains(format!("{}/candidate-native/components/roles/compiler/acquisition-origin.json",record.key.target).as_str()) {
                    return Err("leased release raw references cross original producer ZIP custody".into());
                }
                let acquired_origin: serde_json::Value = wire::decode(custody.bytes(&format!(
                    "{}/candidate-native/components/roles/compiler/acquisition-origin.json",
                    record.key.target
                ))?)?;
                if acquired_origin["job"] != manifest.job
                    || acquired_origin["run_id"] != manifest.run_id
                    || acquired_origin["run_attempt"] != manifest.run_attempt
                {
                    return Err(
                        "leased release acquisition origin crosses original producer attempt"
                            .into(),
                    );
                }
            }
            if record.key.evidence_class == EvidenceClass::NativeComponentRegression
                && record.key.family == "L-VER-01"
                && [
                    "v1-vectors",
                    "v2-vectors",
                    "v3-vectors",
                    "projection-mutation",
                ]
                .contains(&record.key.scenario.as_str())
            {
                let test = semantic
                    .component_test
                    .as_ref()
                    .ok_or("native version vectors lack actual harness")?;
                let receipt: LinuxVersionReceipt =
                    wire::decode(custody.bytes(&test.native_receipt)?)?;
                if [
                    &receipt.v1_canonical,
                    &receipt.v2_request,
                    &receipt.v2_canonical,
                    &receipt.v3_request,
                    &receipt.v3_canonical,
                    &receipt.projection,
                ]
                .iter()
                .any(|path| !artifact_names.contains(path.as_str()))
                {
                    return Err("version vectors cross original producer ZIP custody".into());
                }
            }
            if record.key.evidence_class == EvidenceClass::NativeComponentRegression
                && record.key.family == "C-PARSER"
                && ["omitted-case", "duplicate-case", "wrong-product"]
                    .contains(&record.key.scenario.as_str())
            {
                let test = semantic
                    .component_test
                    .as_ref()
                    .ok_or("native parser lacks actual harness")?;
                let receipt: NativeParserMutationReceipt =
                    wire::decode(custody.bytes(&test.native_receipt)?)?;
                // Own the decoded references until all nested custody checks.
                for path in
                    std::iter::once(&receipt.manifest).chain(receipt.observations.iter().flat_map(
                        |observation| [&observation.base_input, &observation.mutated_input],
                    ))
                {
                    if !artifact_names.contains(path.as_str()) {
                        return Err(
                            "native parser raw mutation crosses original producer ZIP custody"
                                .into(),
                        );
                    }
                }
            }
            if record.key.evidence_class == EvidenceClass::NativeComponentRegression
                && record.key.family == "C-PARSER"
                && !["omitted-case", "duplicate-case", "wrong-product"]
                    .contains(&record.key.scenario.as_str())
            {
                let test = semantic
                    .component_test
                    .as_ref()
                    .ok_or("operational parser lacks actual harness")?;
                let receipt: OperationalParserReceipt =
                    wire::decode(custody.bytes(&test.native_receipt)?)?;
                for path in receipt
                    .observations
                    .iter()
                    .flat_map(|observation| [&observation.base_input, &observation.mutated_input])
                {
                    if !artifact_names.contains(path.as_str()) {
                        return Err(
                            "operational parser mutation crosses original producer ZIP custody"
                                .into(),
                        );
                    }
                }
            }
            for operation in &semantic.operations {
                nested.push(&operation.native_receipt);
            }
            for comparison in &semantic.comparisons {
                nested.push(&comparison.actual);
                nested.push(&comparison.expected);
            }
            if let Some(probe) = &semantic.negative_probe {
                nested.push(&probe.receipt);
            }
            if let Some(test) = &semantic.component_test {
                nested.push(&test.raw_test_output);
                nested.push(&test.native_receipt);
            }
            if let Some(loss) = &evidence.windows_loss {
                nested.extend([
                    loss.action.as_str(),
                    loss.live_observation.as_str(),
                    loss.native_family_retirement.as_str(),
                    loss.recovery.as_str(),
                    loss.stdout.as_str(),
                    loss.stderr.as_str(),
                    loss.recovery_invocation.as_str(),
                    loss.recovery_process.as_str(),
                    loss.recovery_creation.as_str(),
                    loss.recovery_stderr.as_str(),
                    loss.original_lease_owner.as_str(),
                    loss.original_deadlines.as_str(),
                ]);
                for path in [&loss.original_result, &loss.capture_failure]
                    .into_iter()
                    .flatten()
                {
                    nested.push(path);
                }
            }
            if nested.iter().any(|path| !artifact_names.contains(path)) {
                return Err("nested raw evidence references another producer archive".into());
            }
        }
    }
    for record in &index.records {
        if record.state == CaseState::Passed
            && producer_job(&record.key.target, record.key.channel.as_deref())? == origin.job
            && !record_keys.contains(&record.key)
        {
            return Err("passed row is absent from original producer archive".into());
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(deny_unknown_fields)]
pub struct CaseKey {
    pub target: String,
    pub channel: Option<String>,
    pub evidence_class: EvidenceClass,
    pub family: String,
    pub scenario: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    InstalledProduct,
    NativeComponentRegression,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(deny_unknown_fields)]
pub struct ProductKey {
    pub target: String,
    pub channel: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: String,
    pub revision: u32,
    pub profile: String,
    pub targets: Vec<String>,
    pub channels: Vec<String>,
    pub requirements: Vec<String>,
    pub linux_profile: String,
    pub linux_request_revision: u32,
    pub linux_result_revision: u32,
    pub windows_profile: String,
    pub windows_request_revision: u32,
    pub windows_result_revision: u32,
    pub windows_churn_creations: u32,
    pub windows_churn_generations: u32,
    pub windows_churn_live_cohort: u32,
    pub windows_population_processes: u32,
    pub cases: Vec<ManifestCase>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestCase {
    pub family: String,
    pub platform: String,
    pub evidence_class: EvidenceClass,
    pub scenarios: Vec<String>,
    pub requirements: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceIndex {
    pub format: String,
    pub revision: u32,
    pub profile: String,
    pub run_id: String,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub version: String,
    pub manifest_sha256: String,
    #[serde(default)]
    pub repository: Option<String>,
    pub products: Vec<ProductObservation>,
    pub component_builds: Vec<ComponentBuild>,
    pub workflow_cells: Vec<ProductKey>,
    pub fixture_cases: Vec<CaseKey>,
    pub artifacts: Vec<Artifact>,
    pub records: Vec<CaseRecord>,
    pub producer_origins: Vec<ProducerOrigin>,
    pub job_outcomes: Vec<JobOutcome>,
    pub assessment_failures: Vec<String>,
}

/// CI transport provenance. This data is never supplied to product admission.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerOrigin {
    pub job: String,
    pub run_id: String,
    pub run_attempt: u64,
    pub artifact_id: String,
    pub artifact_sha256: String,
    pub bundle_artifact: String,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub version: String,
    pub manifest_sha256: String,
    #[serde(default)]
    pub repository: Option<String>,
}

/// Frozen descriptive producer payload inside the uploaded archive. It binds
/// an actual attempt before upload without a self-referential archive digest.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerManifest {
    pub format: String,
    pub revision: u32,
    pub job: String,
    pub run_id: String,
    pub run_attempt: u64,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub version: String,
    pub manifest_sha256: String,
    pub artifacts: Vec<Artifact>,
    pub products: Vec<ProductObservation>,
    pub component_builds: Vec<ComponentBuild>,
    pub records: Vec<CaseRecord>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum JobResult {
    Success,
    Failure,
    Cancelled,
    Skipped,
    Missing,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobOutcome {
    pub job: String,
    pub result: JobResult,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub path: String,
    pub length: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostObservation {
    pub kernel: String,
    pub native_target: String,
    pub executable_target: String,
    pub emulated: bool,
    pub toolchain_identity: String,
    pub toolchain_sha256: String,
    pub lockfile_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Component {
    pub role: String,
    pub artifact: String,
    pub installed_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductObservation {
    pub key: ProductKey,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub version: String,
    pub host: HostObservation,
    pub features: Vec<String>,
    pub components: Vec<Component>,
    pub materialization: String,
    pub runtime_manifest: String,
    pub package_sha256: String,
    pub registry_graph_sha256: Option<String>,
    pub registry_graph: Option<String>,
    pub request_revision: u32,
    pub result_revision: u32,
    pub runtime_profile: String,
    pub lifecycle: LifecycleObservation,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionCaseEvidence {
    pub format: String,
    pub revision: u32,
    pub key: CaseKey,
    pub run_id: String,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub lease_id: String,
    pub original_acquisition: String,
    pub substituted_acquisition: String,
    pub refusal: String,
    pub quiescence: String,
    pub fixture: String,
    pub fixture_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleObservation {
    pub lease_id: String,
    pub journal: String,
    pub receipt: String,
    pub journal_before_mutation: bool,
    pub installed_verified: bool,
    pub all_cases_inside_lease: bool,
    pub explicit_finalization: bool,
    pub finalization_records: u32,
    pub package_absent: bool,
    pub policy_retired: bool,
    pub native_resources_retired: bool,
    pub cleanup_failures: Vec<String>,
    pub outstanding: Vec<String>,
    pub predecessor_version: String,
    pub predecessor_package_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledLifecycleJournal {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub lease_id: String,
    pub key: ProductKey,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub events: Vec<InstalledLifecycleEvent>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledLifecycleEvent {
    pub sequence: u64,
    pub phase: String,
    pub operation: String,
    pub succeeded: bool,
    pub native_receipt: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledLifecycleReceipt {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub lease_id: String,
    pub key: ProductKey,
    pub journal_sha256: String,
    pub final_sequence: u64,
    pub explicit_finalization_count: u32,
    pub package_absent: bool,
    pub policy_retired: bool,
    pub native_resources_retired: bool,
    pub cache_quiescent: bool,
    pub cleanup_failures: Vec<String>,
    pub outstanding: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentBuild {
    pub target: String,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub host: HostObservation,
    pub recipe_id: String,
    pub recipe_sha256: String,
    pub executable: String,
    pub instrumented: bool,
    pub actor_executable: Option<String>,
    pub parser_executable: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CaseState {
    NotRun,
    Blocked,
    Failed,
    Passed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseRecord {
    pub key: CaseKey,
    pub run_id: String,
    pub state: CaseState,
    pub reason: Option<String>,
    pub evidence: Option<String>,
}

/// Persisted controller facts. A runner state is never an acceptance predicate.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseEvidence {
    pub format: String,
    pub revision: u32,
    pub key: CaseKey,
    pub run_id: String,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub lease_id: Option<String>,
    pub fixture: String,
    pub fixture_source: String,
    pub fixture_sha256: String,
    pub fixture_source_sha256: String,
    pub input: String,
    pub input_sha256: String,
    pub invocation: String,
    pub request: Option<String>,
    pub raw_result: Option<String>,
    pub provider_request: Option<String>,
    pub authenticated_terminal: Option<String>,
    pub windows_loss: Option<WindowsLossEvidence>,
    pub execution_invocation: Option<String>,
    pub execution_environment: Option<String>,
    pub transcript: Option<String>,
    pub inventory: Option<String>,
    pub qualification: Option<String>,
    pub export_receipt: Option<String>,
    pub prepared_observation: Option<String>,
    pub prepared_native_receipt: Option<String>,
    pub native_observation: String,
    pub retirement: String,
    pub semantic_observation: String,
    pub component_recipe_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsLossEvidence {
    pub action: String,
    pub live_observation: String,
    pub original_result: Option<String>,
    pub native_family_retirement: String,
    pub recovery: String,
    pub stdout: String,
    pub stderr: String,
    pub capture_failure: Option<String>,
    pub recovery_invocation: String,
    pub recovery_process: String,
    pub recovery_stderr: String,
    pub original_lease_owner: String,
    pub original_deadlines: String,
    pub recovery_creation: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeInvocation {
    pub format: String,
    pub revision: u32,
    pub arguments: NativeArguments,
    pub executable_sha256: String,
    pub environment: String,
    pub environment_sha256: String,
    pub association_sha256: String,
    pub budget_tokens: Vec<BudgetToken>,
    pub memory_token: Option<String>,
    pub deadline_token: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetToken {
    pub kind: String,
    pub token: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureInput {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub key: CaseKey,
    pub challenge_sha256: String,
    pub binary: Vec<u8>,
    pub target_argv: NativeArguments,
    pub deadline_millis: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub toolchain_identity: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    tag = "encoding",
    content = "values",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum NativeArguments {
    UnixBytes(Vec<Vec<u8>>),
    WindowsUtf16(Vec<Vec<u16>>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    tag = "encoding",
    content = "values",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum NativeEnvironment {
    UnixBytes(Vec<UnixEnvironmentVariable>),
    WindowsUtf16(Vec<WindowsEnvironmentVariable>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnixEnvironmentVariable {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsEnvironmentVariable {
    pub name: Vec<u16>,
    pub value: Vec<u16>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeObservation {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub lease_id: Option<String>,
    pub target: String,
    pub executable_sha256: String,
    pub invocation_sha256: String,
    pub execution_invocation_sha256: Option<String>,
    pub request_sha256: Option<String>,
    pub provider_sha256: Option<String>,
    pub provider_generation: Option<String>,
    pub runtime_manifest_sha256: Option<String>,
    pub attempt_id: Option<String>,
    pub root_pid: Option<u32>,
    pub root_birth: Option<u64>,
    pub attempt_nonce: Option<String>,
    pub held_processes: Vec<HeldProcessIdentity>,
    pub frontend_status: i32,
    pub origin: OutcomeOrigin,
    pub target_status: Option<i32>,
    pub authenticated_provider_exchange: bool,
    pub relay_complete: bool,
    pub result_named_identity_verified: bool,
    pub result_readback_verified: bool,
    pub application_stage: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeldProcessIdentity {
    pub pid: u32,
    pub birth: u64,
    pub parent_pid: Option<u32>,
    pub parent_birth: Option<u64>,
    pub retirement_observed: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeOrigin {
    Target,
    Deadline,
    Memory,
    Interrupted,
    AdmissionRefusal,
    ProviderFailure,
    ApplicationRefusal,
    ComponentRegression,
    PackageOperation,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementObservation {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub attempt_id: Option<String>,
    pub root_pid: Option<u32>,
    pub root_birth: Option<u64>,
    pub target_reaped_or_absent: bool,
    pub aggregate_empty: bool,
    pub relays_retired: bool,
    pub guardian_retired: bool,
    pub native_handles_closed: bool,
    pub independently_observed: bool,
    pub namespace_init_reaped: Option<bool>,
    pub private_root_closed: Option<bool>,
    pub exports_finalized: Option<bool>,
    pub account_reservation_retired: Option<bool>,
    pub final_job_handles_closed: Option<bool>,
    pub active_processes_zero: Option<bool>,
    pub outstanding: Vec<String>,
    pub failed_operations: Vec<String>,
}

/// Operations are native/controller observations, not fixture success strings.
/// Byte comparisons reference independently collected peer/controller products.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticObservation {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub key: CaseKey,
    pub challenge: String,
    pub operations: Vec<OperationObservation>,
    pub comparisons: Vec<ByteComparison>,
    pub counters: BTreeMap<String, u64>,
    pub negative_probe: Option<NegativeProbe>,
    pub component_test: Option<ComponentTest>,
    pub component_actors: Option<Vec<ComponentActor>>,
    pub windows_capacity: Option<WindowsCapacityEvidence>,
    pub windows_refusal: Option<WindowsRefusalEvidence>,
    pub fixture_behavior: Option<FixtureBehavior>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsCapacityEvidence {
    pub attempts: Vec<String>,
    pub inventories: Vec<String>,
    pub overlap_live_association: Option<String>,
    pub overlap_held_guardian: Option<String>,
}

/// The finite vector describes every invocation, including the overlapping
/// invocation whose global image census cannot yet be empty.
pub fn validate_windows_capacity_shape(
    vector: &WindowsCapacityEvidence,
    key: &CaseKey,
) -> VerificationResult<()> {
    if key.family != "W-CAPACITY"
        || !key.target.ends_with("windows-msvc")
        || key.evidence_class != EvidenceClass::InstalledProduct
    {
        return Err("Windows capacity vector is outside its installed case".into());
    }
    let (attempts, inventories, overlap) = match key.scenario.as_str() {
        "serial-retirement" => (3, 4, false),
        "bounded-concurrency" => (2, 2, true),
        "fresh-positive-after-recovery" => (1, 2, false),
        _ => return Err("unknown Windows capacity scenario".into()),
    };
    if vector.attempts.len() != attempts
        || vector.inventories.len() != inventories
        || vector.overlap_live_association.is_some() != overlap
        || vector.overlap_held_guardian.is_some() != overlap
    {
        return Err("Windows capacity vector omits or adds a constituent".into());
    }
    let mut paths = BTreeSet::new();
    for path in vector
        .attempts
        .iter()
        .chain(vector.inventories.iter())
        .chain(vector.overlap_live_association.iter())
        .chain(vector.overlap_held_guardian.iter())
    {
        if path.is_empty() || path.len() > 4096 || !paths.insert(path) {
            return Err("Windows capacity raw constituent path is absent or reused".into());
        }
    }
    Ok(())
}

/// Decode the actual unwrapped recovery response. Completed tombstones retain
/// no workload authority; all six authority-bearing counters must be zero.
pub fn validate_windows_capacity_inventory(
    raw: &serde_json::Value,
    generation: &str,
) -> VerificationResult<()> {
    let fields = [
        "schema_version",
        "challenge",
        "provider_generation",
        "current_boot_identity",
        "executing",
        "incomplete_proof",
        "unacknowledged_outboxes",
        "ack_retirement_in_progress",
        "completed_tombstones",
        "active_admissions",
        "quarantined",
    ];
    if raw.as_object().is_none_or(|object| {
        object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str()))
    }) || raw["schema_version"] != 1
        || raw["provider_generation"].as_str() != Some(generation)
        || generation.is_empty()
    {
        return Err("capacity inventory schema or selected provider generation differs".into());
    }
    for field in ["challenge", "current_boot_identity"] {
        if raw[field]
            .as_str()
            .is_none_or(|value| value.is_empty() || value.len() > 4096)
        {
            return Err("capacity inventory native challenge/boot identity absent".into());
        }
    }
    let mut total = 0u64;
    for field in [
        "executing",
        "incomplete_proof",
        "unacknowledged_outboxes",
        "ack_retirement_in_progress",
        "completed_tombstones",
        "active_admissions",
        "quarantined",
    ] {
        let count = raw[field]
            .as_u64()
            .filter(|count| *count <= u64::from(u32::MAX))
            .ok_or("capacity inventory counter is not bounded native u32")?;
        total = total
            .checked_add(count)
            .ok_or("capacity inventory total overflow")?;
        if field != "completed_tombstones" && count != 0 {
            return Err("capacity inventory retains workload or outbox authority".into());
        }
    }
    if total > u64::from(u32::MAX) {
        return Err("capacity inventory counters exceed native total bound".into());
    }
    Ok(())
}

/// Validates only the exact raw exclusion binding; the caller must first join
/// the expected live observation and two native owners to the first constituent.
pub fn validate_windows_capacity_exclusions(
    raw: &serde_json::Value,
    live: &serde_json::Value,
    expected_live: &serde_json::Value,
    expected: &[(u32, u64); 2],
    own: &[HeldProcessIdentity],
) -> VerificationResult<()> {
    if live != expected_live
        || expected[0] == expected[1]
        || expected.iter().any(|(pid, birth)| *pid == 0 || *birth == 0)
    {
        return Err(
            "capacity exclusion live association or expected first native owners differ".into(),
        );
    }
    let excluded = raw.as_array().ok_or("capacity held exclusions absent")?;
    if excluded.len() != 2 {
        return Err("capacity excludes exactly first root and held TCP peer".into());
    }
    let mut identities = BTreeSet::new();
    for process in excluded {
        if process.as_object().is_none_or(|object| {
            object.len() != 4
                || object.keys().any(|key| {
                    ![
                        "pid",
                        "birth",
                        "held_live_before_overlap",
                        "still_live_at_own_retirement",
                    ]
                    .contains(&key.as_str())
                })
        }) || process["held_live_before_overlap"] != true
            || process["still_live_at_own_retirement"] != true
        {
            return Err(
                "capacity raw exclusions lack actual before-and-after live ownership".into(),
            );
        }
        let pid = u32::try_from(
            process["pid"]
                .as_u64()
                .ok_or("capacity excluded PID absent")?,
        )
        .map_err(|_| "capacity excluded PID out of range")?;
        let birth = process["birth"]
            .as_u64()
            .ok_or("capacity excluded birth absent")?;
        if !identities.insert((pid, birth))
            || own
                .iter()
                .any(|held| held.pid == pid && held.birth == birth)
        {
            return Err("capacity exclusion duplicates or hides its own retired family".into());
        }
    }
    if identities != expected.iter().copied().collect() {
        return Err(
            "capacity excluded identities differ from actual first held root and TCP peer".into(),
        );
    }
    Ok(())
}

/// Joins the application refusal to independently retained native listeners.
pub fn validate_linux_endpoint_mismatch(
    observation: &serde_json::Value,
    receipt: &serde_json::Value,
    pid: u32,
    birth: u64,
    network: &serde_json::Value,
    attempt: &str,
    challenge: &[u8],
) -> VerificationResult<()> {
    let fields = [
        "intended",
        "observed",
        "both_listeners_retained",
        "readiness_reached",
        "application_status",
    ];
    let receipt_fields = [
        "format",
        "revision",
        "process_id",
        "birth",
        "network",
        "listeners",
        "root_held_live_before_and_after",
        "kernel_listen_and_root_descriptor_observed_twice",
        "challenge",
        "attempt_id",
    ];
    if observation.as_object().is_none_or(|object| {
        object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str()))
    }) || observation["both_listeners_retained"] != true
        || observation["readiness_reached"] != false
        || observation["application_status"] != 42
        || receipt.as_object().is_none_or(|object| {
            object.len() != receipt_fields.len()
                || object
                    .keys()
                    .any(|key| !receipt_fields.contains(&key.as_str()))
        })
        || receipt["format"] != "memcordon.linux-native-endpoint-mismatch"
        || receipt["revision"] != 1
        || receipt["process_id"] != pid
        || receipt["birth"] != birth
        || pid == 0
        || birth == 0
        || receipt["network"] != *network
        || receipt["attempt_id"] != attempt
        || attempt.is_empty()
        || challenge.len() != 32
        || receipt["challenge"] != hex::encode(challenge)
        || receipt["root_held_live_before_and_after"] != true
        || receipt["kernel_listen_and_root_descriptor_observed_twice"] != true
    {
        return Err("endpoint refusal differs from held native root, namespace, challenge or application stage".into());
    }
    if network.as_object().is_none_or(|object| {
        object.len() != 2
            || object
                .keys()
                .any(|key| !["device", "inode"].contains(&key.as_str()))
    }) || network["device"].as_u64().is_none()
        || network["inode"].as_u64().is_none_or(|inode| inode == 0)
    {
        return Err("endpoint native network identity absent".into());
    }
    let listeners = receipt["listeners"]
        .as_array()
        .filter(|listeners| listeners.len() == 2)
        .ok_or("endpoint native listener pair absent")?;
    let mut addresses = BTreeSet::new();
    let mut inodes = BTreeSet::new();
    for (ordinal, field) in ["intended", "observed"].iter().enumerate() {
        let listener = &listeners[ordinal];
        if listener.as_object().is_none_or(|object| {
            object.len() != 2
                || object
                    .keys()
                    .any(|key| !["endpoint", "socket_inode"].contains(&key.as_str()))
        }) || listener["endpoint"] != observation[*field]
        {
            return Err("native listener endpoint differs from actual application refusal".into());
        }
        let address: std::net::SocketAddrV4 = listener["endpoint"]
            .as_str()
            .ok_or("native endpoint absent")?
            .parse()
            .map_err(|_| "native endpoint malformed")?;
        let inode = listener["socket_inode"]
            .as_u64()
            .filter(|inode| *inode > 0)
            .ok_or("native listener socket inode absent")?;
        if *address.ip() != std::net::Ipv4Addr::LOCALHOST
            || address.port() == 0
            || !addresses.insert(address)
            || !inodes.insert(inode)
        {
            return Err("native mismatch listeners are unreserved, nonloopback or aliased".into());
        }
    }
    Ok(())
}

/// Preauthorization and acquisition refusals preserve their distinct raw
/// sources; they do not imply a target, Job, guardian or terminal existed.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
#[expect(
    clippy::large_enum_variant,
    reason = "Preserve direct typed refusal wire payloads and their public constructors"
)]
pub enum WindowsRefusalEvidence {
    AuthenticatedAdmission {
        provider_request: String,
        requested_contract: String,
        quiescence: String,
        policy_apply: Option<String>,
        policy_restore: Option<String>,
        baseline_policy: String,
        baseline_contract: String,
        baseline_activation: String,
        prior_contract: String,
        prior_activation: String,
        prior_invocation: String,
        prior_exit: String,
        prior_stderr: String,
        guardian_quiescence: String,
        frontend: String,
    },
    UnsupportedPublicRequest {
        quiescence: String,
        guardian_quiescence: String,
        frontend: String,
    },
    NativeArgument {
        receipt: String,
        quiescence: String,
        guardian_quiescence: String,
        frontend: String,
    },
    AcquisitionSubstitution {
        original_acquisition: String,
        substituted_acquisition: String,
        receipt: String,
        quiescence: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureBehavior {
    pub descriptor: String,
    pub transcript: String,
    pub expected_token: Option<String>,
    pub peer_artifacts: Vec<BehaviorArtifact>,
    pub native_binding: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorArtifact {
    pub role: String,
    pub path: String,
}

/// Actual support actors are separate from Rust test-harness executions.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentActor {
    pub provider_request: String,
    pub recipe_id: String,
    pub selection_kind: String,
    pub selection: String,
    pub invocation: String,
    pub exit: String,
    pub observation: String,
    pub stdout: String,
    pub stderr: String,
    pub actor_held: String,
    pub native_retirement: String,
    pub settlement_inventory: String,
    pub settlement_invocation: String,
    pub settlement_exit: String,
    pub settlement_stderr: String,
    pub settlement_deadline: String,
    pub held_before: Option<String>,
    pub held_after: Option<String>,
    pub worker_exit: Option<String>,
    pub frontend_exit: Option<String>,
    pub recovery: Option<String>,
    pub recovery_invocation: Option<String>,
    pub recovery_exit: Option<String>,
    pub recovery_stderr: Option<String>,
    pub control_worker_site: Option<String>,
    pub control_worker_held: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationObservation {
    pub operation: String,
    pub attempt_id: Option<String>,
    pub root_pid: Option<u32>,
    pub observer: String,
    pub native_receipt: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOperationReceipt {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub operation: String,
    pub attempt_id: Option<String>,
    pub root_pid: Option<u32>,
    pub root_birth: Option<u64>,
    pub observer_pid: u32,
    pub observer_birth: u64,
    pub challenge_sha256: String,
    pub native_domain: String,
    pub native_code: i64,
    pub observed_value: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ByteComparison {
    pub role: String,
    pub actual: String,
    pub expected: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NegativeProbe {
    pub stage: String,
    pub domain: String,
    pub native_code: i64,
    pub receipt: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentTest {
    pub recipe_id: String,
    pub test_name: String,
    pub native_exit: i32,
    pub tests_executed: u64,
    pub tests_failed: u64,
    pub tests_ignored: u64,
    pub raw_test_output: String,
    pub native_receipt: String,
    pub native_retirement: Option<String>,
    #[serde(default)]
    pub fixture_acquisition: Option<ComponentFixtureAcquisition>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentFixtureAcquisition {
    pub checkpoint: String,
    pub account_intent: String,
    pub account_readback: String,
    pub group_readback: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeParserMutationReceipt {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub recipe_id: String,
    pub test_name: String,
    pub native_target: String,
    pub executable_sha256: String,
    pub challenge_sha256: String,
    pub manifest: String,
    pub observations: Vec<ParserMutationObservation>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ParserMutationObservation {
    pub scenario: String,
    pub base_input: String,
    pub mutated_input: String,
    pub operation: String,
    pub actual_refusal: String,
    pub baseline_profile_ready: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalParserReceipt {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub recipe_id: String,
    pub test_name: String,
    pub native_target: String,
    pub executable_sha256: String,
    pub challenge_sha256: String,
    pub observations: Vec<OperationalParserMutation>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalParserMutation {
    pub scenario: String,
    pub operation: String,
    pub base_input: String,
    pub mutated_input: String,
    pub actual_refusal: String,
    pub baseline_accepted: bool,
    pub fixture_resource_claims: bool,
}

pub fn validate_operational_parser_receipt(
    receipt: &OperationalParserReceipt,
    key: &CaseKey,
    artifacts: &[Artifact],
    root: &Path,
) -> VerificationResult<()> {
    validate_operational_parser(receipt, key, &custody::Custody::new(root, artifacts)?)
}

fn validate_operational_parser(
    receipt: &OperationalParserReceipt,
    key: &CaseKey,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    header(
        &receipt.format,
        receipt.revision,
        "memcordon.native-operational-parser-receipt",
    )?;
    let required = [
        "duplicate-key",
        "wrong-format",
        "wrong-revision",
        "unknown-authority-variant",
        "oversized-record",
        "stale-attempt",
        "forged-cleanup",
    ];
    if key.evidence_class != EvidenceClass::NativeComponentRegression
        || key.channel.is_some()
        || key.family != "C-PARSER"
        || !required.contains(&key.scenario.as_str())
        || receipt.native_target != key.target
        || receipt.test_name
            != "operational_parser_receipts::native_operational_parser_mutations_emit_actual_receipts"
        || receipt.observations.len() != required.len()
    {
        return Err("operational parser actual source/selection differs".into());
    }
    identifier(&receipt.run_id)?;
    identifier(&receipt.recipe_id)?;
    digest(&receipt.executable_sha256)?;
    digest(&receipt.challenge_sha256)?;
    let mut scenarios = BTreeSet::new();
    for observation in &receipt.observations {
        let terminal = ["stale-attempt", "forged-cleanup"].contains(&observation.scenario.as_str());
        if !scenarios.insert(observation.scenario.as_str())
            || !required.contains(&observation.scenario.as_str())
            || !observation.baseline_accepted
            || !observation.fixture_resource_claims
            || observation.actual_refusal.is_empty()
            || observation.actual_refusal.len() > 4096
            || observation.operation
                != if terminal {
                    "core-windows-terminal-v2-association"
                } else {
                    "core-result-v2-parse"
                }
        {
            return Err("operational parser mutation applicability/refusal differs".into());
        }
        let base_bytes = custody.bytes(&observation.base_input)?;
        let changed_bytes = custody.bytes(&observation.mutated_input)?;
        let mut expected: serde_json::Value = wire::json(base_bytes)?;
        if terminal {
            if expected["schema_version"] != 2
                || expected["attempt_id"] != expected["retirement_proof"]["attempt_id"]
                || expected["retirement_proof"]["native_job_empty_observed"] != true
            {
                return Err("terminal parser baseline lacks bound protocol-vector proof".into());
            }
        } else if expected["format"] != "memcordon.result"
            || expected["revision"] != 2
            || expected["runtime"]["outcome"]["kind"] != "rejected-ingress"
            || expected["runtime"]["outcome"]["allocation"]["authorization"] != "never-authorized"
            || expected["runtime"]["outcome"]["allocation"]["obligations"] != serde_json::json!([])
        {
            return Err("operational parser baseline invented execution/authorization".into());
        }
        if observation.scenario == "duplicate-key" {
            let original =
                std::str::from_utf8(base_bytes).map_err(|_| "parser baseline encoding differs")?;
            let exact = format!(
                "{{\"format\":\"memcordon.result\",{}",
                original
                    .strip_prefix('{')
                    .ok_or("parser baseline object absent")?
            );
            if changed_bytes != exact.as_bytes() || wire::json(changed_bytes).is_ok() {
                return Err("duplicate-key raw mutation differs or was accepted".into());
            }
            continue;
        }
        match observation.scenario.as_str() {
            "wrong-format" => expected["format"] = serde_json::json!("memcordon.forged"),
            "wrong-revision" => expected["revision"] = serde_json::json!(99),
            "unknown-authority-variant" => {
                expected["runtime"]["outcome"]["allocation"]["authorization"] =
                    serde_json::json!("qualified-by-readiness")
            }
            "oversized-record" => {
                expected["runtime"]["outcome"]["detail"] =
                    serde_json::json!("x".repeat(128 * 1024 + 1))
            }
            "stale-attempt" => {
                expected["retirement_proof"]["attempt_id"] = serde_json::json!("stale-attempt")
            }
            "forged-cleanup" => {
                expected["retirement_proof"]["native_job_empty_observed"] = serde_json::json!(false)
            }
            _ => return Err("unexpected operational parser mutation".into()),
        }
        if wire::json(changed_bytes)? != expected {
            return Err(
                "retained operational mutation differs from exact actual parser vector".into(),
            );
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsNativeComponentReceipt {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub recipe_id: String,
    pub test_name: String,
    pub native_target: String,
    pub executable_sha256: String,
    pub payload: WindowsNativeComponentPayload,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
#[expect(
    clippy::large_enum_variant,
    reason = "Preserve direct typed component wire payloads and their public constructors"
)]
pub enum WindowsNativeComponentPayload {
    CausalCapture {
        before_journal: String,
        after_journal: String,
        first_api: String,
        first_return: i32,
        first_win32_code: u32,
        second_api: String,
        second_return: i32,
        second_win32_code: u32,
        invalid_handle_was_null: bool,
    },
    ReplayOwnedOutbox {
        record: String,
        after_record: String,
        first_response: String,
        repeated_response: String,
        duplicate_refusal: String,
        nonce_refusal: String,
        request_refusal: String,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        fixture_resource_claims: bool,
        installed_state_accessed: bool,
        ack_record: String,
        staged_ack: String,
        completed_ack: String,
        retired_response: String,
        repeated_retired_response: String,
        active_record_refusal: String,
        ack_nonce_refusal: String,
        ack_caller_refusal: String,
        outbox_absent_after_ack: bool,
        available_journal: String,
        expired_journal: String,
        expiry_record: String,
        retention: serde_json::Value,
        pre_expiry_clock: u64,
        expired_clock: u64,
        same_boot: bool,
    },
    BindingSeed {
        before_record: String,
        after_record: String,
        replacement_observation: String,
        refusal: String,
        stores_before_refusal: u64,
        stores_after_refusal: u64,
    },
    BindingProof {
        before_record: String,
        after_refusal_record: String,
        after_matching_record: String,
        mismatched_receipt: String,
        matching_receipt: String,
        refusal: String,
    },
    BindingReceiptless {
        before_record: String,
        after_record: String,
        response: String,
        original: String,
        refusal: String,
    },
    BindingGeneration {
        record: String,
        attempt_id: String,
        provider_generation: String,
        substituted_generation: String,
        refusal: String,
    },
    Writer {
        observations: Vec<WindowsWriterObservation>,
    },
    WriterFrozen {
        observations: Vec<WindowsFrozenWriterObservation>,
    },
    WriterReservation {
        attempt_id: String,
        request_sha256: String,
        owner_identity: WindowsComponentIdentity,
        owner_held_live_during_refusal: bool,
        before_reservation: String,
        after_refusal_reservation: String,
        retirement_without_local_proof: String,
        writer_frozen_during_refusal: bool,
        writer_joined_before_retirement: bool,
        published_record: String,
        local_writer_retirement_proved: bool,
        reservation_absent_after_retirement: bool,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WindowsComponentIdentity {
    pub process_id: u32,
    pub creation_time_100ns: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsFrozenWriterMember {
    pub identity: WindowsComponentIdentity,
    pub held_before_cleanup: bool,
    pub retirement_observed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsFrozenWriterObservation {
    pub cleanup_owner: String,
    pub job_active_before: u64,
    pub job_active_after: u64,
    pub job_members: Vec<WindowsFrozenWriterMember>,
    pub worker_identity: WindowsComponentIdentity,
    pub worker_retired_during_cleanup: bool,
    pub guardian_identity: WindowsComponentIdentity,
    pub guardian_retired_during_cleanup: bool,
    pub writer_frozen_during_cleanup: bool,
    pub cleanup_publication_confirmed: bool,
    pub after_record: String,
    pub original: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsWriterObservation {
    pub phase: String,
    pub before_record: String,
    pub after_record: String,
    pub original: String,
    pub caller_ack_revision: u64,
    pub persisted_revision: u64,
    pub publication_rejected: bool,
    pub native_code: Option<WindowsNativeComponentCode>,
    pub publisher_process: Option<WindowsPublisherProcess>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsPublisherProcess {
    pub process_id: u32,
    pub creation_time_100ns: u64,
    pub held_before_input_delivery: bool,
    pub exit_status: i32,
    pub retirement_observed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsNativeComponentCode {
    Win32(u32),
    NtStatus(u32),
    HResult(u32),
    Winsock(i32),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Verdict {
    pub format: String,
    pub revision: u32,
    pub profile: String,
    pub run_id: String,
    pub manifest_sha256: String,
    pub evidence_index_sha256: String,
    pub scope: VerificationScope,
    pub profile_ready: bool,
    pub accepted: bool,
    pub checked_records: usize,
    pub failures: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum VerificationScope {
    CompleteProfile,
    CandidateBeforePublication,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(deny_unknown_fields)]
pub struct RegistryPackage {
    pub name: String,
    pub version: String,
    pub crate_sha256: String,
    pub crate_artifact: String,
    pub features: Vec<String>,
    pub dependencies: Vec<RegistryDependency>,
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(deny_unknown_fields)]
pub struct RegistryDependency {
    pub name: String,
    pub version: String,
    pub kind: Option<String>,
    pub target: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryGraph {
    pub format: String,
    pub revision: u32,
    pub packages: Vec<RegistryPackage>,
    pub raw_metadata: String,
    pub raw_lock: String,
}

pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn validate_json_document(bytes: &[u8]) -> VerificationResult<serde_json::Value> {
    wire::json(bytes)
}

pub fn reconstruct_invocation_sha256(invocation: &NativeInvocation) -> VerificationResult<String> {
    wire::invocation_digest(invocation)
}

pub fn validate_artifact_custody(root: &Path, artifacts: &[Artifact]) -> VerificationResult<()> {
    custody::Custody::new(root, artifacts).map(|_| ())
}

/// Independent wire assessment for retained Windows terminal controller vectors.
/// This function alone cannot establish any installed readiness row.
pub fn validate_windows_terminal_observation(
    bytes: &[u8],
    native: &NativeObservation,
    key: &CaseKey,
) -> VerificationResult<()> {
    wire::validate_windows_delivery_and_sample(&wire::json(bytes)?, native, key)
}

/// Assesses a retained component decoder vector with native named-file custody.
/// It cannot establish installed execution or whole-profile readiness.
pub fn validate_windows_native_component(
    receipt: &WindowsNativeComponentReceipt,
    key: &CaseKey,
    artifacts: &[Artifact],
    root: &Path,
) -> VerificationResult<()> {
    header(
        &receipt.format,
        receipt.revision,
        "memcordon.windows-native-component",
    )?;
    digest(&receipt.executable_sha256)?;
    identifier(&receipt.run_id)?;
    identifier(&receipt.recipe_id)?;
    if key.evidence_class != EvidenceClass::NativeComponentRegression
        || key.channel.is_some()
        || !key.target.ends_with("windows-msvc")
        || receipt.native_target != key.target
    {
        return Err(
            "component decoder vector substitutes installed authority or another native target"
                .into(),
        );
    }
    wire::validate_windows_component(receipt, key, &custody::Custody::new(root, artifacts)?)
}

/// Independent raw behavioral decoder entrypoint. Success proves only these
/// supplied artifact associations, never installation or native retirement.
pub fn validate_fixture_behavior(
    semantic: &SemanticObservation,
    native: &NativeObservation,
    input: &FixtureInput,
    artifacts: &[Artifact],
    root: &Path,
) -> VerificationResult<()> {
    let behavior = semantic
        .fixture_behavior
        .as_ref()
        .ok_or("raw fixture behavior absent")?;
    let facts = behavior::validate(
        behavior,
        semantic,
        native,
        input,
        &custody::Custody::new(root, artifacts)?,
    )?;
    for operation in &semantic.operations {
        if !facts.operations.contains(&operation.operation) {
            return Err("requested behavioral fact absent from raw decoder".into());
        }
    }
    Ok(())
}

/// CI parser vectors only. Replays the exact frozen inventory mutation shape;
/// success never establishes product execution or resource retirement.
pub fn validate_native_parser_mutations(
    receipt: &NativeParserMutationReceipt,
    key: &CaseKey,
    artifacts: &[Artifact],
    root: &Path,
) -> VerificationResult<()> {
    validate_parser_mutations(receipt, key, &custody::Custody::new(root, artifacts)?)
}
fn validate_parser_mutations(
    receipt: &NativeParserMutationReceipt,
    key: &CaseKey,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    header(
        &receipt.format,
        receipt.revision,
        "memcordon.native-parser-mutation-receipt",
    )?;
    if key.evidence_class != EvidenceClass::NativeComponentRegression
        || key.channel.is_some()
        || key.family != "C-PARSER"
        || !["omitted-case", "duplicate-case", "wrong-product"].contains(&key.scenario.as_str())
        || receipt.native_target != key.target
        || receipt.test_name != "native_index_mutations_emit_actual_parser_receipts"
        || receipt.observations.len() != 3
    {
        return Err("native parser receipt source/selection differs".into());
    }
    identifier(&receipt.run_id)?;
    identifier(&receipt.recipe_id)?;
    digest(&receipt.executable_sha256)?;
    digest(&receipt.challenge_sha256)?;
    let expected = validate_manifest(custody.bytes(&receipt.manifest)?)?;
    let mut scenarios = BTreeSet::new();
    for observation in &receipt.observations {
        if !scenarios.insert(observation.scenario.as_str())
            || observation.operation != "independent-evidence-index-frozen-inventory"
            || observation.baseline_profile_ready
            || observation.actual_refusal
                != "missing/duplicate/unexpected/reclassified evidence rows"
        {
            return Err("actual CI parser mutation operation/refusal differs".into());
        }
        let base: EvidenceIndex = wire::decode(custody.bytes(&observation.base_input)?)?;
        let keys = base
            .records
            .iter()
            .map(|record| record.key.clone())
            .collect::<BTreeSet<_>>();
        if base.format != "memcordon.consumer-readiness.evidence"
            || base.revision != 1
            || base.profile != PROFILE
            || keys != expected
            || base.records.len() != expected.len()
            || base.fixture_cases.iter().cloned().collect::<BTreeSet<_>>() != expected
            || base
                .records
                .iter()
                .any(|record| record.state != CaseState::NotRun || record.evidence.is_some())
            || !base.products.is_empty()
            || !base.component_builds.is_empty()
        {
            return Err(
                "baseline CI parser vector invents readiness or narrows frozen inventory".into(),
            );
        }
        let actual: EvidenceIndex = wire::decode(custody.bytes(&observation.mutated_input)?)?;
        let mut mutated = base;
        match observation.scenario.as_str() {
            "omitted-case" => {
                mutated.records.pop();
            }
            "duplicate-case" => mutated.records.push(mutated.records[0].clone()),
            "wrong-product" => {
                mutated
                    .records
                    .iter_mut()
                    .find(|record| record.key.evidence_class == EvidenceClass::InstalledProduct)
                    .ok_or("parser baseline has no installed row")?
                    .key
                    .channel = Some("unselected-product".into())
            }
            _ => return Err("unexpected CI parser mutation scenario".into()),
        }
        if serde_json::to_value(actual).map_err(|error| error.to_string())?
            != serde_json::to_value(mutated).map_err(|error| error.to_string())?
        {
            return Err(
                "retained raw index mutation differs from exact source-backed operation".into(),
            );
        }
    }
    if scenarios
        != ["omitted-case", "duplicate-case", "wrong-product"]
            .into_iter()
            .collect()
    {
        return Err("native CI parser receipt omitted a required actual mutation".into());
    }
    Ok(())
}

pub fn validate_windows_native_argument_refusal(
    bytes: &[u8],
    native: &NativeObservation,
) -> VerificationResult<()> {
    wire::validate_windows_argument_refusal(&wire::json(bytes)?, native)
}

fn digest(value: &str) -> VerificationResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("expected lowercase SHA-256".into());
    }
    Ok(())
}

fn identifier(value: &str) -> VerificationResult<()> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err("invalid bounded identifier".into());
    }
    Ok(())
}

fn exact_strings(
    values: &[String],
    expected: impl IntoIterator<Item = impl AsRef<str>>,
) -> VerificationResult<()> {
    let actual: BTreeSet<_> = values.iter().map(String::as_str).collect();
    let required: BTreeSet<String> = expected
        .into_iter()
        .map(|v| v.as_ref().to_owned())
        .collect();
    if actual.len() != values.len()
        || actual
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
            != required
    {
        return Err("required finite set differs or contains duplicates".into());
    }
    Ok(())
}

pub fn validate_manifest(bytes: &[u8]) -> VerificationResult<BTreeSet<CaseKey>> {
    if bytes.len() > 1024 * 1024 {
        return Err("manifest exceeds bound".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
    let manifest: Manifest = toml::from_str(text).map_err(|e| e.to_string())?;
    if manifest.format != "memcordon.consumer-readiness"
        || manifest.revision != 1
        || manifest.profile != PROFILE
        || manifest.linux_profile != "linux-tcp4-unix-private-v1"
        || manifest.linux_request_revision != 3
        || manifest.linux_result_revision != 2
        || manifest.windows_profile != "windows-host-network-external-v1"
        || manifest.windows_request_revision != 1
        || manifest.windows_result_revision != 1
        || manifest.windows_churn_creations != 4096
        || manifest.windows_churn_generations != 3
        || manifest.windows_churn_live_cohort != 64
        || manifest.windows_population_processes != 257
    {
        return Err("frozen readiness profile parameters differ".into());
    }
    exact_strings(&manifest.targets, anchors::TARGETS)?;
    exact_strings(&manifest.channels, anchors::CHANNELS)?;
    exact_strings(&manifest.requirements, anchors::REQUIREMENTS)?;
    let mut groups = BTreeSet::new();
    for case in &manifest.cases {
        let class = match case.evidence_class {
            EvidenceClass::InstalledProduct => "installed_product",
            EvidenceClass::NativeComponentRegression => "native_component_regression",
        };
        if !groups.insert((case.family.as_str(), case.platform.as_str(), class)) {
            return Err("duplicate manifest case group".into());
        }
        let anchor = anchors::CASES
            .iter()
            .find(|a| a.0 == case.family && a.1 == case.platform && a.2 == class)
            .ok_or("unknown or reclassified manifest case group")?;
        exact_strings(&case.scenarios, anchor.3.split_whitespace())?;
        exact_strings(&case.requirements, anchor.4.split_whitespace())?;
    }
    if groups.len() != anchors::CASES.len() {
        return Err("manifest omits independently pinned semantic group".into());
    }
    let mut expected = BTreeSet::new();
    for (family, platform, class, scenarios, _) in anchors::CASES {
        for target in anchors::TARGETS {
            if (*platform == "linux" && !target.ends_with("linux-gnu"))
                || (*platform == "windows" && !target.ends_with("windows-msvc"))
            {
                continue;
            }
            for scenario in scenarios.split_whitespace() {
                let evidence_class = if *class == "installed_product" {
                    EvidenceClass::InstalledProduct
                } else {
                    EvidenceClass::NativeComponentRegression
                };
                let channels: Vec<Option<String>> =
                    if evidence_class == EvidenceClass::InstalledProduct {
                        anchors::CHANNELS
                            .iter()
                            .map(|c| Some((*c).to_owned()))
                            .collect()
                    } else {
                        vec![None]
                    };
                for channel in channels {
                    expected.insert(CaseKey {
                        target: target.into(),
                        channel,
                        evidence_class,
                        family: (*family).into(),
                        scenario: scenario.into(),
                    });
                }
            }
        }
    }
    Ok(expected)
}

fn header(format: &str, revision: u32, expected: &str) -> VerificationResult<()> {
    if format != expected || revision != 1 {
        return Err(format!("unsupported {expected} format/revision"));
    }
    Ok(())
}

fn host(host: &HostObservation, target: &str) -> VerificationResult<()> {
    if host.native_target != target
        || host.executable_target != target
        || host.emulated
        || host.kernel.is_empty()
        || host.kernel.len() > 512
        || host.toolchain_identity.is_empty()
        || host.toolchain_identity.len() > 512
    {
        return Err("native host/executable/toolchain observation differs".into());
    }
    digest(&host.toolchain_sha256)?;
    digest(&host.lockfile_sha256)
}

pub fn verify(
    manifest_path: &Path,
    report_path: &Path,
    artifact_root: &Path,
) -> VerificationResult<Verdict> {
    verify_scoped(
        manifest_path,
        report_path,
        artifact_root,
        VerificationScope::CompleteProfile,
    )
}

pub fn verify_scoped(
    manifest_path: &Path,
    report_path: &Path,
    artifact_root: &Path,
    scope: VerificationScope,
) -> VerificationResult<Verdict> {
    let manifest_bytes = custody::read_external(manifest_path, 1024 * 1024)?;
    let expected = validate_manifest(&manifest_bytes)?;
    let index_bytes = custody::read_external(report_path, MAX_INDEX_BYTES as u64)?;
    let index: EvidenceIndex = wire::decode(&index_bytes)?;
    verify_index(
        &manifest_bytes,
        &expected,
        &index_bytes,
        &index,
        artifact_root,
        scope,
    )
}

fn producer_job(target: &str, channel: Option<&str>) -> VerificationResult<String> {
    let label = anchors::PRODUCER_JOBS
        .iter()
        .find_map(|(native, label)| (*native == target).then_some(*label))
        .ok_or("unknown native producer target")?;
    match channel {
        None => Ok(format!("native-{label}")),
        Some(channel) => {
            let (stage, kind) = channel.split_once('-').ok_or("unknown producer channel")?;
            if !["candidate", "public"].contains(&stage) || !["native", "cargo"].contains(&kind) {
                return Err("unknown producer channel".into());
            }
            Ok(format!("{stage}-{label}-{kind}"))
        }
    }
}

fn expected_producer_jobs(scope: VerificationScope) -> BTreeSet<String> {
    anchors::PRODUCER_JOBS
        .into_iter()
        .flat_map(|(_, label)| {
            let mut jobs = vec![
                format!("native-{label}"),
                format!("candidate-{label}-native"),
                format!("candidate-{label}-cargo"),
            ];
            if scope == VerificationScope::CompleteProfile {
                jobs.extend([
                    format!("public-{label}-native"),
                    format!("public-{label}-cargo"),
                ]);
            }
            jobs
        })
        .collect()
}

fn producer_origin<'a>(
    index: &'a EvidenceIndex,
    target: &str,
    channel: Option<&str>,
) -> VerificationResult<&'a ProducerOrigin> {
    let job = producer_job(target, channel)?;
    index
        .producer_origins
        .iter()
        .find(|origin| origin.job == job)
        .ok_or_else(|| format!("required immutable producer origin missing: {job}"))
}

fn verify_index(
    manifest_bytes: &[u8],
    expected: &BTreeSet<CaseKey>,
    index_bytes: &[u8],
    index: &EvidenceIndex,
    artifact_root: &Path,
    scope: VerificationScope,
) -> VerificationResult<Verdict> {
    header(
        &index.format,
        index.revision,
        "memcordon.consumer-readiness.evidence",
    )?;
    if index.profile != PROFILE || index.manifest_sha256 != sha256(manifest_bytes) {
        return Err("profile/manifest binding differs".into());
    }
    identifier(&index.run_id)?;
    digest(&index.source_tree_sha256)?;
    if index.source_commit.len() != 40
        || !index
            .source_commit
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("source commit is not immutable lowercase Git identity".into());
    }
    if index.version.is_empty() || index.version.len() > 128 {
        return Err("invalid version".into());
    }
    let workflow: BTreeSet<_> = index.workflow_cells.iter().cloned().collect();
    let product_keys: BTreeSet<_> = anchors::TARGETS
        .into_iter()
        .flat_map(|target| {
            anchors::CHANNELS
                .into_iter()
                .map(move |channel| ProductKey {
                    target: target.into(),
                    channel: channel.into(),
                })
        })
        .collect();
    if workflow.len() != index.workflow_cells.len() || workflow != product_keys {
        return Err("actual workflow matrix differs".into());
    }
    let fixture_keys: BTreeSet<_> = index.fixture_cases.iter().cloned().collect();
    if fixture_keys.len() != index.fixture_cases.len() || &fixture_keys != expected {
        return Err("actual fixture inventory differs".into());
    }
    if index.records.len() > 16_384 || index.artifacts.len() > 131_072 {
        return Err("evidence collections exceed bounds".into());
    }
    let record_keys: BTreeSet<_> = index.records.iter().map(|r| r.key.clone()).collect();
    if record_keys.len() != index.records.len() || &record_keys != expected {
        return Err("missing/duplicate/unexpected/reclassified evidence rows".into());
    }
    let expected_jobs = expected_producer_jobs(scope);
    let actual_jobs = index
        .job_outcomes
        .iter()
        .map(|outcome| outcome.job.clone())
        .collect::<BTreeSet<_>>();
    if actual_jobs.len() != index.job_outcomes.len() || actual_jobs != expected_jobs {
        return Err("missing/duplicate/unexpected required producer job outcomes".into());
    }
    let mut origin_jobs = BTreeSet::new();
    for origin in &index.producer_origins {
        if !expected_jobs.contains(&origin.job)
            || !origin_jobs.insert(origin.job.clone())
            || origin.run_attempt == 0
            || origin.artifact_id.is_empty()
            || !origin.artifact_id.bytes().all(|byte| byte.is_ascii_digit())
            || origin
                .artifact_id
                .parse::<u64>()
                .ok()
                .is_none_or(|value| value == 0)
            || origin.source_commit != index.source_commit
            || origin.source_tree_sha256 != index.source_tree_sha256
            || origin.version != index.version
            || origin.manifest_sha256 != index.manifest_sha256
        {
            return Err("producer immutable origin/source/profile differs".into());
        }
        identifier(&origin.run_id)?;
        digest(&origin.artifact_sha256)?;
    }
    let custody = custody::Custody::new(artifact_root, &index.artifacts)?;
    for origin in &index.producer_origins {
        validate_producer_bundle(index, origin, &custody)?;
    }
    let mut products = BTreeMap::new();
    if index.assessment_failures.len() > 64
        || index
            .assessment_failures
            .iter()
            .any(|failure| failure.is_empty() || failure.len() > 4096)
    {
        return Err("assessment failure observation exceeds finite bound".into());
    }
    let mut failures = index.assessment_failures.clone();
    for outcome in &index.job_outcomes {
        if outcome.result != JobResult::Success || !origin_jobs.contains(&outcome.job) {
            failures.push(format!(
                "{}: actual producer outcome {:?} or required immutable artifact origin missing",
                outcome.job, outcome.result
            ));
        }
    }
    for product in &index.products {
        if products.insert(product.key.clone(), product).is_some() {
            return Err("duplicate product cell".into());
        }
        if let Err(error) = verify_product(index, product, &custody) {
            failures.push(format!("{:?}: {error}", product.key));
        }
    }
    let assessed_products: BTreeSet<_> = product_keys
        .into_iter()
        .filter(|key| {
            scope == VerificationScope::CompleteProfile || key.channel.starts_with("candidate-")
        })
        .collect();
    if products.keys().cloned().collect::<BTreeSet<_>>() != assessed_products {
        return Err("selected product matrix differs from explicit verification scope".into());
    }
    if scope == VerificationScope::CompleteProfile {
        for target in anchors::TARGETS {
            let get = |channel: &str| {
                products
                    .get(&ProductKey {
                        target: target.into(),
                        channel: channel.into(),
                    })
                    .copied()
                    .ok_or("delivered lineage product missing")
            };
            if get("candidate-native")?.package_sha256 != get("public-native")?.package_sha256 {
                failures.push(format!(
                    "{target}: published native archive differs from candidate bytes"
                ));
            }
            let candidate = registry_graph(get("candidate-cargo")?, &custody)?;
            let public = registry_graph(get("public-cargo")?, &custody)?;
            if candidate != public {
                failures.push(format!(
                    "{target}: published Cargo package graph differs from candidate package bytes"
                ));
            }
        }
    }
    let mut builds = BTreeMap::new();
    for build in &index.component_builds {
        producer_origin(index, &build.target, None)?;
        if builds.insert(build.target.clone(), build).is_some() {
            return Err("duplicate native component build target".into());
        }
        host(&build.host, &build.target)?;
        if build.source_commit != index.source_commit
            || build.source_tree_sha256 != index.source_tree_sha256
        {
            return Err("component source binding differs".into());
        }
        identifier(&build.recipe_id)?;
        digest(&build.recipe_sha256)?;
        custody.bytes(&build.executable)?;
        if let Some(actor) = &build.actor_executable {
            if actor == &build.executable || !build.target.ends_with("windows-msvc") {
                return Err(
                    "component actor role must be distinct Windows native executable".into(),
                );
            }
            custody.bytes(actor)?;
        }
        if let Some(parser) = &build.parser_executable {
            if parser == &build.executable || build.actor_executable.as_ref() == Some(parser) {
                return Err(
                    "native parser harness role must be distinct measured executable".into(),
                );
            }
            custody.bytes(parser)?;
        }
    }
    if builds.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != anchors::TARGETS.into_iter().collect()
    {
        return Err("native component build matrix differs".into());
    }
    for record in &index.records {
        if scope == VerificationScope::CandidateBeforePublication
            && record
                .key
                .channel
                .as_ref()
                .is_some_and(|c| c.starts_with("public-"))
        {
            if !matches!(record.state, CaseState::NotRun | CaseState::Blocked)
                || record.reason.as_deref() != Some("publication-pending")
                || record.evidence.is_some()
            {
                failures.push(format!(
                    "{:?}: public cell must remain explicitly publication-pending",
                    record.key
                ));
            }
            continue;
        }
        let result = verify_record(index, record, &products, &builds, &custody);
        if let Err(error) = result {
            failures.push(format!("{:?}: {error}", record.key));
        }
    }
    if failures.len() > 16_384 {
        return Err("verification failure count exceeds bound".into());
    }
    Ok(Verdict {
        format: "memcordon.consumer-readiness.verdict".into(),
        revision: 1,
        profile: PROFILE.into(),
        run_id: index.run_id.clone(),
        manifest_sha256: sha256(manifest_bytes),
        evidence_index_sha256: sha256(index_bytes),
        scope,
        profile_ready: scope == VerificationScope::CompleteProfile && failures.is_empty(),
        accepted: failures.is_empty(),
        checked_records: index.records.len(),
        failures,
    })
}

fn registry_graph(
    product: &ProductObservation,
    custody: &custody::Custody,
) -> VerificationResult<Vec<RegistryPackage>> {
    let path = product
        .registry_graph
        .as_deref()
        .ok_or("Cargo product lacks persisted exact package graph")?;
    registry_graph_document(
        path,
        product
            .registry_graph_sha256
            .as_deref()
            .ok_or("Cargo graph digest absent")?,
        custody,
    )
}

/// Structural Cargo graph custody/metadata checking for independent mutation
/// tests and tooling. This never returns a profile or native execution verdict.
pub fn validate_cargo_graph_artifacts(
    root: &Path,
    artifacts: &[Artifact],
    path: &str,
    digest: &str,
) -> VerificationResult<Vec<RegistryPackage>> {
    registry_graph_document(path, digest, &custody::Custody::new(root, artifacts)?)
}

fn registry_graph_document(
    path: &str,
    expected_digest: &str,
    custody: &custody::Custody,
) -> VerificationResult<Vec<RegistryPackage>> {
    if expected_digest != custody.hash(path)? {
        return Err("Cargo graph persisted digest differs".into());
    }
    let graph: RegistryGraph = wire::decode(custody.bytes(path)?)?;
    header(
        &graph.format,
        graph.revision,
        "memcordon.consumer-readiness.registry-graph",
    )?;
    let metadata: serde_json::Value = wire::decode(custody.bytes(&graph.raw_metadata)?)?;
    let lock: toml::Value = toml::from_str(
        std::str::from_utf8(custody.bytes(&graph.raw_lock)?).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let raw_packages = metadata["packages"]
        .as_array()
        .ok_or("actual Cargo metadata packages absent")?;
    let nodes = metadata["resolve"]["nodes"]
        .as_array()
        .ok_or("actual Cargo metadata resolved nodes absent")?;
    if raw_packages.len() > 4096 || nodes.len() > 4096 {
        return Err("actual Cargo metadata graph exceeds bound".into());
    }
    let mut by_id = BTreeMap::new();
    for package in raw_packages {
        let id = package["id"]
            .as_str()
            .ok_or("actual Cargo package id absent")?;
        if by_id.insert(id, package).is_some() {
            return Err("actual Cargo metadata duplicate package id".into());
        }
    }
    let root = metadata["resolve"]["root"]
        .as_str()
        .ok_or("actual selected Cargo root absent")?;
    let mut reachable = BTreeSet::new();
    let mut pending = vec![root];
    while let Some(id) = pending.pop() {
        if reachable.insert(id) {
            let node = nodes
                .iter()
                .find(|node| node["id"].as_str() == Some(id))
                .ok_or("actual reachable Cargo node absent")?;
            for edge in node["deps"]
                .as_array()
                .ok_or("actual reachable Cargo edges absent")?
            {
                pending.push(
                    edge["pkg"]
                        .as_str()
                        .ok_or("actual reachable Cargo edge id absent")?,
                );
            }
        }
    }
    let mut raw_nodes = BTreeMap::new();
    for node in nodes {
        if !reachable.contains(node["id"].as_str().ok_or("actual Cargo node id absent")?) {
            continue;
        }
        let package = by_id
            .get(node["id"].as_str().ok_or("actual Cargo node id absent")?)
            .ok_or("actual Cargo node package absent")?;
        let name = package["name"]
            .as_str()
            .ok_or("actual Cargo package name absent")?;
        let version = package["version"]
            .as_str()
            .ok_or("actual Cargo package version absent")?;
        if raw_nodes.insert((name, version), node).is_some() {
            return Err("actual Cargo node identity ambiguous".into());
        }
    }
    if graph.packages.is_empty() || graph.packages.len() > 4096 {
        return Err("Cargo graph cardinality differs".into());
    }
    let mut identities = BTreeSet::new();
    let mut packages = graph.packages;
    for package in &mut packages {
        identifier(&package.name)?;
        semver::Version::parse(&package.version).map_err(|e| e.to_string())?;
        digest(&package.crate_sha256)?;
        let raw = raw_nodes
            .remove(&(package.name.as_str(), package.version.as_str()))
            .ok_or("summarized graph node absent from actual Cargo metadata")?;
        let raw_features: Vec<String> =
            serde_json::from_value(raw["features"].clone()).map_err(|e| e.to_string())?;
        if raw_features.iter().collect::<BTreeSet<_>>()
            != package.features.iter().collect::<BTreeSet<_>>()
        {
            return Err("Cargo feature summary differs from actual metadata".into());
        }
        let mut raw_edges = BTreeSet::new();
        for dependency in raw["deps"]
            .as_array()
            .ok_or("actual Cargo dependency edges absent")?
        {
            let target = by_id
                .get(
                    dependency["pkg"]
                        .as_str()
                        .ok_or("actual Cargo edge id absent")?,
                )
                .ok_or("actual Cargo edge package absent")?;
            for kind in dependency["dep_kinds"]
                .as_array()
                .ok_or("actual Cargo dependency kind/target absent")?
            {
                raw_edges.insert(RegistryDependency {
                    name: target["name"]
                        .as_str()
                        .ok_or("actual Cargo edge name absent")?
                        .into(),
                    version: target["version"]
                        .as_str()
                        .ok_or("actual Cargo edge version absent")?
                        .into(),
                    kind: serde_json::from_value(kind["kind"].clone())
                        .map_err(|e| e.to_string())?,
                    target: serde_json::from_value(kind["target"].clone())
                        .map_err(|e| e.to_string())?,
                });
            }
        }
        if raw_edges != package.dependencies.iter().cloned().collect() {
            return Err("Cargo edge summary differs from actual kind/target metadata".into());
        }
        let locked = lock["package"]
            .as_array()
            .ok_or("actual packaged Cargo lock entries absent")?
            .iter()
            .filter(|entry| {
                entry.get("name").and_then(toml::Value::as_str) == Some(package.name.as_str())
                    && entry.get("version").and_then(toml::Value::as_str)
                        == Some(package.version.as_str())
            })
            .collect::<Vec<_>>();
        if locked.len() != 1
            || locked[0]
                .get("checksum")
                .and_then(toml::Value::as_str)
                .is_some_and(|checksum| checksum != package.crate_sha256)
        {
            return Err(
                "consumed Cargo crate differs from actual packaged/test lock checksum".into(),
            );
        }
        if custody.hash(&package.crate_artifact)? != package.crate_sha256 {
            return Err("Cargo graph crate bytes differ from persisted package".into());
        }
        // Collection paths vary by channel; compare the delivered package
        // identity, bytes and graph edges after independently hashing each.
        package.crate_artifact.clear();
        if !identities.insert((package.name.clone(), package.version.clone())) {
            return Err("Cargo graph duplicate package identity".into());
        }
        if package.features.len() > 4096
            || package
                .features
                .iter()
                .any(|feature| feature.is_empty() || feature.len() > 128)
        {
            return Err("Cargo graph feature set exceeds finite bound".into());
        }
        let features = package.features.iter().cloned().collect::<BTreeSet<_>>();
        if features.len() != package.features.len() {
            return Err("Cargo graph duplicate selected feature".into());
        }
        package.features = features.into_iter().collect();
        if package.dependencies.len() > 16_384
            || package.dependencies.iter().any(|edge| {
                edge.kind
                    .as_deref()
                    .is_some_and(|kind| !matches!(kind, "dev" | "build"))
                    || edge
                        .target
                        .as_ref()
                        .is_some_and(|target| target.is_empty() || target.len() > 4096)
            })
        {
            return Err("Cargo graph dependency kind/target differs or exceeds bound".into());
        }
        let dependencies: BTreeSet<_> = package.dependencies.iter().cloned().collect();
        if dependencies.len() != package.dependencies.len() {
            return Err("Cargo graph duplicate edge".into());
        }
        package.dependencies = dependencies.into_iter().collect();
    }
    if !raw_nodes.is_empty() {
        return Err("summarized Cargo graph omits actual reachable selected node".into());
    }
    for package in &packages {
        for dependency in &package.dependencies {
            if !identities.contains(&(dependency.name.clone(), dependency.version.clone())) {
                return Err("Cargo graph edge refers to absent package".into());
            }
        }
    }
    packages.sort();
    Ok(packages)
}

fn verify_product(
    index: &EvidenceIndex,
    product: &ProductObservation,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    let origin = producer_origin(index, &product.key.target, Some(&product.key.channel))?;
    host(&product.host, &product.key.target)?;
    if product.source_commit != index.source_commit
        || product.source_tree_sha256 != index.source_tree_sha256
        || product.version != index.version
    {
        return Err("materialized source/version differs".into());
    }
    let linux = product.key.target.ends_with("linux-gnu");
    let (request, result, profile, features, components): (_, _, _, &[&str], &[&str]) = if linux {
        (
            3,
            2,
            "linux-tcp4-unix-private-v1",
            &["private-tcp", "sealed-runtime"],
            &["public-cli", "sealed-agent"],
        )
    } else {
        (
            1,
            1,
            "windows-host-network-external-v1",
            &["sealed-runtime", "windows-sealed-runtime"],
            &[
                "public-cli",
                "sealed-agent",
                "desktop-bootstrap",
                "session-broker",
            ],
        )
    };
    if product.request_revision != request
        || product.result_revision != result
        || product.runtime_profile != profile
    {
        return Err("selected contract/output/profile differs".into());
    }
    exact_strings(&product.features, features.iter().copied())?;
    exact_strings(
        &product
            .components
            .iter()
            .map(|c| c.role.clone())
            .collect::<Vec<_>>(),
        components.iter().copied(),
    )?;
    for component in &product.components {
        if custody.hash(&component.artifact)? != component.installed_sha256 {
            return Err("installed executable differs from selected materialization".into());
        }
        custody::executable_target(custody.bytes(&component.artifact)?, &product.key.target)?;
    }
    if custody.hash(&product.materialization)? != product.package_sha256 {
        return Err("materialized package digest differs".into());
    }
    custody.bytes(&product.runtime_manifest)?;
    if product.key.channel.ends_with("cargo") {
        registry_graph(product, custody)?;
    } else if product.registry_graph_sha256.is_some() || product.registry_graph.is_some() {
        return Err("native channel unexpectedly substitutes Cargo graph".into());
    }
    let lease = &product.lifecycle;
    identifier(&lease.lease_id)?;
    let journal: InstalledLifecycleJournal = wire::decode(custody.bytes(&lease.journal)?)?;
    let receipt: InstalledLifecycleReceipt = wire::decode(custody.bytes(&lease.receipt)?)?;
    header(
        &journal.format,
        journal.revision,
        "memcordon.consumer-readiness.installed-journal",
    )?;
    header(
        &receipt.format,
        receipt.revision,
        "memcordon.consumer-readiness.installed-retirement",
    )?;
    if journal.run_id != origin.run_id
        || receipt.run_id != origin.run_id
        || journal.lease_id != lease.lease_id
        || receipt.lease_id != lease.lease_id
        || journal.key != product.key
        || receipt.key != product.key
        || journal.source_commit != index.source_commit
        || journal.source_tree_sha256 != index.source_tree_sha256
        || receipt.journal_sha256 != custody.hash(&lease.journal)?
        || journal.events.is_empty()
        || journal.events.len() > 4096
    {
        return Err("installed journal/retirement custody association differs".into());
    }
    let mut sequence = 0;
    let mut phases = Vec::new();
    for event in &journal.events {
        if event.sequence <= sequence || event.operation.is_empty() || !event.succeeded {
            return Err("installed lifecycle sequence/native operation failed".into());
        }
        sequence = event.sequence;
        custody.bytes(&event.native_receipt)?;
        if phases.last() != Some(&event.phase) {
            phases.push(event.phase.clone());
        }
    }
    let expected_phases = [
        "owned-before-mutation",
        "install",
        "verify",
        "upgrade",
        "cases",
        "finalization",
        "retired",
    ];
    if phases.iter().map(String::as_str).collect::<Vec<_>>() != expected_phases
        || receipt.final_sequence != sequence
        || receipt.explicit_finalization_count != 1
        || !receipt.package_absent
        || !receipt.policy_retired
        || !receipt.native_resources_retired
        || !receipt.cache_quiescent
        || !receipt.cleanup_failures.is_empty()
        || !receipt.outstanding.is_empty()
    {
        return Err("persisted installed lifecycle/final native retirement incomplete".into());
    }
    if !lease.journal_before_mutation
        || !lease.installed_verified
        || !lease.all_cases_inside_lease
        || !lease.explicit_finalization
        || lease.finalization_records != 1
        || !lease.package_absent
        || !lease.policy_retired
        || !lease.native_resources_retired
        || !lease.cleanup_failures.is_empty()
        || !lease.outstanding.is_empty()
    {
        return Err("installed lifetime/finalization/retirement incomplete".into());
    }
    let predecessor =
        semver::Version::parse(&lease.predecessor_version).map_err(|e| e.to_string())?;
    let successor = semver::Version::parse(&index.version).map_err(|e| e.to_string())?;
    if predecessor >= successor {
        return Err("upgrade is not a selected older predecessor".into());
    }
    digest(&lease.predecessor_package_sha256)?;
    Ok(())
}

/// Structural shape only; selected product, source and native quiescence joins
/// remain mandatory in the acquisition case verifier.
pub fn validate_acquisition_payload_shape(original: &serde_json::Value) -> VerificationResult<()> {
    let fields = [
        "channel",
        "source_commit",
        "version",
        "target",
        "artifacts",
        "cli",
        "agent",
        "components",
        "installed_components",
        "fixture",
        "installed_agent",
        "installed_manifest",
        "provider",
        "output_directory",
    ];
    if original.as_object().is_none_or(|object| {
        object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str()))
    }) {
        return Err("original acquisition payload schema differs".into());
    }
    for field in [
        "channel",
        "source_commit",
        "version",
        "target",
        "output_directory",
    ] {
        if original[field].as_str().is_none_or(str::is_empty) {
            return Err("acquisition scalar field differs".into());
        }
    }
    let artifact = |row: &serde_json::Value| -> bool {
        row.as_object().is_some_and(|object| {
            object.len() == 2 && object.contains_key("path") && object.contains_key("sha256")
        }) && row["path"].as_str().is_some_and(|path| !path.is_empty())
            && row["sha256"]
                .as_str()
                .is_some_and(|value| digest(value).is_ok())
    };
    for field in [
        "cli",
        "agent",
        "fixture",
        "installed_agent",
        "installed_manifest",
    ] {
        if !artifact(&original[field]) {
            return Err("acquisition selected artifact shape differs".into());
        }
    }
    for field in ["artifacts", "components", "installed_components"] {
        let rows = original[field]
            .as_array()
            .ok_or("acquisition artifact array absent")?;
        if rows.is_empty()
            || rows.len() > 64
            || rows.iter().any(|row| !artifact(row))
            || field != "artifacts" && rows.len() != 4
        {
            return Err("acquisition artifact array shape differs".into());
        }
    }
    let fields = ["generation", "source_commit", "runtime_manifest_sha256"];
    if original["provider"].as_object().is_none_or(|object| {
        object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str()))
    }) || fields.iter().any(|field| {
        original["provider"][*field]
            .as_str()
            .is_none_or(str::is_empty)
    }) {
        return Err("acquisition provider shape differs".into());
    }
    digest(
        original["provider"]["runtime_manifest_sha256"]
            .as_str()
            .ok_or("acquisition provider digest absent")?,
    )?;
    Ok(())
}

fn verify_acquisition_case(
    index: &EvidenceIndex,
    record: &CaseRecord,
    evidence: &AcquisitionCaseEvidence,
    products: &BTreeMap<ProductKey, &ProductObservation>,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    header(
        &evidence.format,
        evidence.revision,
        "memcordon.consumer-readiness.acquisition-case",
    )?;
    if record.key.evidence_class != EvidenceClass::InstalledProduct
        || !record.key.target.ends_with("windows-msvc")
        || record.key.family != "W-BINDING"
        || record.key.scenario != "component-substitution"
        || evidence.key != record.key
        || evidence.run_id != record.run_id
        || evidence.source_commit != index.source_commit
        || evidence.source_tree_sha256 != index.source_tree_sha256
    {
        return Err("nonexecution acquisition refusal substituted another product case".into());
    }
    let product = products
        .get(&ProductKey {
            target: record.key.target.clone(),
            channel: record
                .key
                .channel
                .clone()
                .ok_or("acquisition product channel absent")?,
        })
        .ok_or("acquisition selected product absent")?;
    if evidence.lease_id != product.lifecycle.lease_id {
        return Err("acquisition refusal outside selected installed lifetime".into());
    }
    let original: serde_json::Value = wire::decode(custody.bytes(&evidence.original_acquisition)?)?;
    let substituted: serde_json::Value =
        wire::decode(custody.bytes(&evidence.substituted_acquisition)?)?;
    let agent = product
        .components
        .iter()
        .find(|component| component.role == "sealed-agent")
        .ok_or("selected acquisition agent absent")?;
    let cli = product
        .components
        .iter()
        .find(|component| component.role == "public-cli")
        .ok_or("selected acquisition CLI absent")?;
    let fields = [
        "channel",
        "source_commit",
        "version",
        "target",
        "artifacts",
        "cli",
        "agent",
        "components",
        "installed_components",
        "fixture",
        "installed_agent",
        "installed_manifest",
        "provider",
        "output_directory",
    ];
    validate_acquisition_payload_shape(&original)?;
    if original.as_object().is_none_or(|object| {
        object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str()))
    }) {
        return Err("original acquisition differs from frozen installed payload schema".into());
    }
    for field in [
        "cli",
        "agent",
        "fixture",
        "installed_agent",
        "installed_manifest",
    ] {
        if original[field].as_object().is_none_or(|object| {
            object.len() != 2 || !object.contains_key("path") || !object.contains_key("sha256")
        }) || original[field]["path"].as_str().is_none_or(str::is_empty)
        {
            return Err("acquisition selected artifact schema differs".into());
        }
    }
    let provider_fields = ["generation", "source_commit", "runtime_manifest_sha256"];
    if original["provider"].as_object().is_none_or(|object| {
        object.len() != provider_fields.len()
            || object
                .keys()
                .any(|key| !provider_fields.contains(&key.as_str()))
    }) || provider_fields.iter().any(|field| {
        original["provider"][*field]
            .as_str()
            .is_none_or(str::is_empty)
    }) {
        return Err("acquisition provider binding schema differs".into());
    }
    let acquisition_artifacts = original["artifacts"]
        .as_array()
        .ok_or("acquisition artifact table absent")?;
    if acquisition_artifacts.is_empty()
        || acquisition_artifacts.len() > 64
        || acquisition_artifacts.iter().any(|row| {
            row.as_object().is_none_or(|object| {
                object.len() != 2 || !object.contains_key("path") || !object.contains_key("sha256")
            }) || row["path"].as_str().is_none_or(str::is_empty)
                || row["sha256"]
                    .as_str()
                    .is_none_or(|value| digest(value).is_err())
        })
    {
        return Err("acquisition artifact table schema differs".into());
    }
    let expected_channel = if product.key.channel.ends_with("cargo") {
        "cargo-package"
    } else {
        "native-bundle"
    };
    let expected_hashes = product
        .components
        .iter()
        .map(|component| component.installed_sha256.as_str())
        .collect::<BTreeSet<_>>();
    for field in ["components", "installed_components"] {
        let rows = original[field]
            .as_array()
            .ok_or("acquisition full component table absent")?;
        let hashes = rows
            .iter()
            .map(|row| row["sha256"].as_str().ok_or("component hash absent"))
            .collect::<Result<BTreeSet<_>, _>>()?;
        if rows.len() != 4
            || hashes != expected_hashes
            || rows.iter().any(|row| {
                row.as_object().is_none_or(|object| {
                    object.len() != 2
                        || !object.contains_key("path")
                        || !object.contains_key("sha256")
                }) || row["path"].as_str().is_none_or(str::is_empty)
            })
        {
            return Err("acquisition omitted/substituted selected four-component bytes".into());
        }
    }
    digest(&evidence.fixture_sha256)?;
    if custody.hash(&evidence.fixture)? != evidence.fixture_sha256
        || original["fixture"]["sha256"] != evidence.fixture_sha256
        || original["channel"] != expected_channel
        || original["cli"]["sha256"] != cli.installed_sha256
        || original["agent"]["sha256"] != agent.installed_sha256
        || original["provider"]["generation"]
            != format!("{}:{}", index.version, index.source_commit)
        || original["provider"]["source_commit"] != index.source_commit
    {
        return Err("acquisition fixture/CLI/channel/provider measurement differs".into());
    }
    if original["source_commit"] != index.source_commit
        || original["version"] != index.version
        || original["target"] != record.key.target
        || original["installed_agent"]["sha256"] != agent.installed_sha256
        || original["installed_manifest"]["sha256"] != custody.hash(&product.runtime_manifest)?
        || original["provider"]["runtime_manifest_sha256"]
            != custody.hash(&product.runtime_manifest)?
        || original["fixture"]["sha256"] == original["installed_agent"]["sha256"]
    {
        return Err("actual original acquisition differs from selected measured product".into());
    }
    let mut expected = original.clone();
    expected["installed_agent"] = original["fixture"].clone();
    if substituted != expected {
        return Err(
            "acquisition substitution changed more than actual selected agent input".into(),
        );
    }
    let refusal: serde_json::Value = wire::decode(custody.bytes(&evidence.refusal)?)?;
    let fields = [
        "format",
        "revision",
        "operation",
        "original_accepted",
        "changed_component",
        "refusal",
        "installation_mutated",
        "target_released",
    ];
    if refusal.as_object().is_none_or(|object| {
        object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str()))
    }) || refusal["format"] != "memcordon.windows-acquisition-refusal"
        || refusal["revision"] != 1
        || refusal["operation"] != "validate-installed-selection"
        || refusal["original_accepted"] != true
        || refusal["changed_component"] != "installed-agent"
        || refusal["refusal"] != "selected installed channel identity differs"
        || refusal["installation_mutated"] != false
        || refusal["target_released"] != false
    {
        return Err("actual acquisition refusal differs from exact validator operation".into());
    }
    let quiescence: serde_json::Value = wire::decode(custody.bytes(&evidence.quiescence)?)?;
    let fields = [
        "format",
        "revision",
        "provider",
        "installed_agent_sha256",
        "runtime_manifest_sha256",
        "guardian_native_quiescence",
        "fixture_processes_absent",
        "owned_policy_restoration_required",
        "owned_policy_restoration_completed",
    ];
    if quiescence.as_object().is_none_or(|object| {
        object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str()))
    }) || quiescence["format"] != "memcordon.windows-native-refusal-quiescence"
        || quiescence["revision"] != 1
        || quiescence["provider"] != original["provider"]
        || quiescence["installed_agent_sha256"] != agent.installed_sha256
        || quiescence["runtime_manifest_sha256"] != custody.hash(&product.runtime_manifest)?
        || quiescence["guardian_native_quiescence"] != true
        || quiescence["fixture_processes_absent"] != true
        || quiescence["owned_policy_restoration_required"] != false
        || quiescence["owned_policy_restoration_completed"] != false
    {
        return Err("nonexecution acquisition native quiescence association differs".into());
    }
    Ok(())
}

/// Exercise the actual no-target policy record router with persisted custody.
/// Whole producer ZIP and product-lifecycle verification remain separate.
pub fn validate_linux_policy_case(
    index: &EvidenceIndex,
    record: &CaseRecord,
    root: &Path,
) -> VerificationResult<()> {
    if !(record.key.family == "L-ID-02"
        || (record.key.family == "L-ID-03"
            && ["revoke-discovery", "revoke-preparation", "revoke-release"]
                .contains(&record.key.scenario.as_str())))
        || record.key.evidence_class != EvidenceClass::InstalledProduct
        || !record.key.target.ends_with("linux-gnu")
    {
        return Err("record is outside installed Linux no-target policy applicability".into());
    }
    let custody = custody::Custody::new(root, &index.artifacts)?;
    let products = index
        .products
        .iter()
        .map(|product| (product.key.clone(), product))
        .collect();
    let builds: BTreeMap<_, _> = index
        .component_builds
        .iter()
        .map(|build| (build.target.clone(), build))
        .collect();
    if builds.len() != index.component_builds.len() {
        return Err("duplicate native component build target".into());
    }
    verify_record(index, record, &products, &builds, &custody)
}

/// Validate one persisted row against its original artifact inventory and
/// source/product associations. Full readiness still requires `verify_scoped`.
pub fn validate_case_record(
    index: &EvidenceIndex,
    record: &CaseRecord,
    root: &Path,
) -> VerificationResult<()> {
    let custody = custody::Custody::new(root, &index.artifacts)?;
    let products = index
        .products
        .iter()
        .map(|product| (product.key.clone(), product))
        .collect();
    let builds: BTreeMap<_, _> = index
        .component_builds
        .iter()
        .map(|build| (build.target.clone(), build))
        .collect();
    if builds.len() != index.component_builds.len() {
        return Err("duplicate native component build target".into());
    }
    verify_record(index, record, &products, &builds, &custody)
}

fn verify_linux_policy_refusal(
    index: &EvidenceIndex,
    record: &CaseRecord,
    evidence: &LinuxPolicyRefusalEvidence,
    products: &BTreeMap<ProductKey, &ProductObservation>,
    builds: &BTreeMap<String, &ComponentBuild>,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    header(
        &evidence.format,
        evidence.revision,
        "memcordon.consumer-readiness.linux-policy-refusal",
    )?;
    let origin = producer_origin(index, &record.key.target, record.key.channel.as_deref())?;
    if evidence.key != record.key
        || evidence.run_id != origin.run_id
        || evidence.source_commit != index.source_commit
        || evidence.source_tree_sha256 != index.source_tree_sha256
        || !(record.key.family == "L-ID-02"
            || (record.key.family == "L-ID-03"
                && ["revoke-discovery", "revoke-preparation", "revoke-release"]
                    .contains(&record.key.scenario.as_str())))
        || record.key.evidence_class != EvidenceClass::InstalledProduct
        || !record.key.target.ends_with("linux-gnu")
    {
        return Err(
            "Linux no-target policy evidence crosses source/origin/finite applicability".into(),
        );
    }
    for path in evidence.artifact_paths() {
        custody.bytes(path)?;
    }
    let product = products
        .get(&ProductKey {
            target: record.key.target.clone(),
            channel: record
                .key
                .channel
                .clone()
                .ok_or("policy installed channel absent")?,
        })
        .copied()
        .ok_or("policy selected product absent")?;
    if evidence.lease_id != product.lifecycle.lease_id {
        return Err("policy refusal crosses original installation lifetime".into());
    }
    let cli = product
        .components
        .iter()
        .find(|component| component.role == "public-cli")
        .ok_or("policy selected CLI absent")?;
    let agent = product
        .components
        .iter()
        .find(|component| component.role == "sealed-agent")
        .ok_or("policy selected agent absent")?;
    let decode = |path: &str| -> VerificationResult<serde_json::Value> {
        wire::decode(custody.bytes(path)?)
    };
    let baseline = decode(&evidence.baseline_registry)?;
    let baseline_contract = decode(&evidence.baseline_contract)?;
    let baseline_activation = decode(&evidence.baseline_activation)?;
    linux_policy::activation_registry(&baseline_activation)?;
    if baseline_activation["format"] != "memcordon.local-private-activation"
        || baseline_activation["revision"] != 2
        || baseline_activation["registry"] != baseline
        || baseline_activation["registry_digest"]
            != linux_registry_digest(&baseline, &record.key.target)?
        || baseline_contract["expected_epoch"] != baseline_activation["epoch"]
    {
        return Err("policy baseline activation is not actual selected registry/epoch".into());
    }
    let owner = decode(&evidence.owner)?;
    let owner_fields = [
        "format",
        "revision",
        "run_id",
        "source_commit",
        "source_tree_sha256",
        "cell",
        "lease_id",
        "provider",
        "baseline_registry",
        "baseline_epoch",
        "admin_root",
        "admin_root_device",
        "admin_root_inode",
        "privileged_policy_root",
    ];
    let owner_object = owner
        .as_object()
        .ok_or("policy native owner is not an object")?;
    let admin = owner["admin_root"]
        .as_str()
        .ok_or("policy original administrator root absent")?;
    let privileged = format!("{admin}/policy-cases-{}", evidence.lease_id);
    if owner_object.len() != owner_fields.len()
        || owner_fields
            .iter()
            .any(|field| !owner_object.contains_key(*field))
        || owner["format"] != "memcordon.linux-policy-case-owner"
        || owner["revision"] != 1
        || owner["run_id"] != evidence.run_id
        || owner["source_commit"] != evidence.source_commit
        || owner["source_tree_sha256"] != evidence.source_tree_sha256
        || owner["lease_id"] != evidence.lease_id
        || owner["baseline_registry"] != baseline
        || owner["baseline_epoch"] != baseline_activation["epoch"]
        || !admin.starts_with("/var/lib/memcordon-consumer-readiness/")
        || admin.ends_with('/')
        || admin.contains('\0')
        || admin
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == "..")
        || owner["privileged_policy_root"] != privileged
        || ["admin_root_device", "admin_root_inode"]
            .iter()
            .any(|field| owner[*field].as_u64().filter(|value| *value > 0).is_none())
    {
        return Err("policy original owner/source/protected staging differs".into());
    }
    let lifecycle: InstalledLifecycleJournal =
        serde_json::from_value(decode(&product.lifecycle.journal)?)
            .map_err(|error| error.to_string())?;
    let acquisitions: Vec<_> = lifecycle
        .events
        .iter()
        .filter(|event| {
            event.phase == "owned-before-mutation"
                && event.operation == "administrative-staging-created"
                && event.succeeded
        })
        .collect();
    if acquisitions.len() != 1
        || lifecycle.lease_id != evidence.lease_id
        || lifecycle.run_id != evidence.run_id
        || lifecycle.source_commit != evidence.source_commit
        || lifecycle.source_tree_sha256 != evidence.source_tree_sha256
    {
        return Err(
            "policy administrator identity lacks original installed lifetime acquisition".into(),
        );
    }
    let acquisition = decode(&acquisitions[0].native_receipt)?;
    let object = acquisition
        .as_object()
        .ok_or("native administrator acquisition not an object")?;
    if object.len() != 3
        || ["path", "device", "inode"]
            .iter()
            .any(|field| !object.contains_key(*field))
        || acquisition["path"] != owner["admin_root"]
        || acquisition["device"] != owner["admin_root_device"]
        || acquisition["inode"] != owner["admin_root_inode"]
    {
        return Err(
            "policy administrator path/inode crosses original native lifetime receipt".into(),
        );
    }
    let census = decode(&evidence.native_census)?;
    let census_fields = [
        "format",
        "revision",
        "identity",
        "cell",
        "lease_id",
        "scenario",
        "attempt_id",
        "provider",
        "account",
        "result_sha256",
        "request_sha256",
        "tasks",
        "cgroup_root",
        "journal_root",
    ];
    let census_object = census
        .as_object()
        .ok_or("policy native census is not an object")?;
    for (field, fields) in [
        (
            "identity",
            vec!["run_id", "source_commit", "source_tree_sha256", "version"],
        ),
        (
            "provider",
            vec!["generation", "source_commit", "runtime_manifest_sha256"],
        ),
        (
            "account",
            vec![
                "name",
                "uid",
                "gid",
                "intent",
                "native_readback",
                "group_readback",
            ],
        ),
    ] {
        let object = census[field]
            .as_object()
            .ok_or("native policy census association is not an object")?;
        if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
            return Err("native policy census association schema differs".into());
        }
    }
    let attempt = evidence
        .provider_request
        .rsplit('/')
        .next()
        .and_then(|name| name.strip_suffix(".provider-request.bin"))
        .filter(|name| {
            name.len() == 32
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or("policy original native request attempt basename differs")?;
    if census_object.len() != census_fields.len()
        || census_fields
            .iter()
            .any(|field| !census_object.contains_key(*field))
        || census["format"] != "memcordon.linux-policy-native-census"
        || census["revision"] != 1
        || census["identity"]["run_id"] != evidence.run_id
        || census["identity"]["source_commit"] != evidence.source_commit
        || census["identity"]["source_tree_sha256"] != evidence.source_tree_sha256
        || census["identity"]["version"] != product.version
        || census["cell"]
            != serde_json::to_value(ProductKey {
                target: record.key.target.clone(),
                channel: record.key.channel.clone().ok_or("policy channel absent")?,
            })
            .map_err(|error| error.to_string())?
        || owner["cell"] != census["cell"]
        || owner["provider"] != census["provider"]
        || census["provider"]["source_commit"] != evidence.source_commit
        || census["provider"]["runtime_manifest_sha256"]
            != custody.hash(&product.runtime_manifest)?
        || census["provider"]["generation"]
            != format!("{}:{}", product.version, evidence.source_commit)
        || census["lease_id"] != evidence.lease_id
        || census["scenario"] != record.key.scenario
        || census["attempt_id"] != attempt
        || census["result_sha256"] != custody.hash(&evidence.raw_result)?
        || census["request_sha256"] != custody.hash(&evidence.provider_request)?
    {
        return Err("policy native census crosses actual request/result/source/lifetime".into());
    }
    let identities = baseline["execution_identities"]
        .as_array()
        .ok_or("policy baseline identities absent")?;
    let mut account_checkpoint = None;
    for artifact in index
        .artifacts
        .iter()
        .filter(|artifact| artifact.path.ends_with("/owned-resources-acquired.json"))
    {
        let checkpoint = decode(&artifact.path)?;
        if checkpoint["identity"] != census["identity"]
            || checkpoint["cell"] != census["cell"]
            || checkpoint["admin_root"] != owner["admin_root"]
        {
            continue;
        }
        let fields = [
            "format",
            "revision",
            "identity",
            "cell",
            "admin_root",
            "device",
            "inode",
            "legacy",
            "images",
            "account",
        ];
        let object = checkpoint
            .as_object()
            .ok_or("native resource checkpoint not an object")?;
        if object.len() != fields.len()
            || fields.iter().any(|field| !object.contains_key(*field))
            || checkpoint["format"] != "memcordon.owned-readiness-resources"
            || checkpoint["revision"] != 1
            || checkpoint["device"] != owner["admin_root_device"]
            || checkpoint["inode"] != owner["admin_root_inode"]
            || checkpoint["account"] != census["account"]
            || checkpoint["legacy"] != baseline["legacy"]
        {
            return Err(
                "policy census exclusive account crosses original acquired native resources".into(),
            );
        }
        if account_checkpoint.replace(artifact.path.as_str()).is_some() {
            return Err("policy exclusive account acquisition is ambiguous".into());
        }
    }
    if account_checkpoint.is_none() {
        return Err("policy census omits original exact account acquisition checkpoint".into());
    }
    if identities.len() != 1
        || identities[0]["enabled"] != true
        || census["account"]["uid"] != identities[0]["uid"]
        || census["account"]["gid"] != identities[0]["gid"]
    {
        return Err("policy native census crosses selected exclusive account".into());
    }
    validate_linux_refusal_census(
        &census,
        &census["identity"],
        &census["cell"],
        &evidence.lease_id,
        &record.key.scenario,
        &census["account"],
        &owner["provider"],
        custody.hash(&evidence.provider_request)?,
        custody.hash(&evidence.raw_result)?,
        attempt,
    )?;
    let applied = decode(&evidence.activation_policy)?;
    let requested = decode(&evidence.requested_contract)?;
    let activation = decode(&evidence.activation)?;
    let restoration = decode(&evidence.restoration)?;
    let restored = decode(&evidence.restoration_policy)?;
    if (record.key.scenario == "revoke-discovery") != evidence.discovery.is_some() {
        return Err("policy discovery applicability differs".into());
    }
    if ["revoke-preparation", "revoke-release"].contains(&record.key.scenario.as_str())
        != evidence.gate.is_some()
    {
        return Err("policy gate applicability differs".into());
    }
    if let Some(gate) = &evidence.gate {
        let prepared = decode(&gate.prepared)?;
        let receipt = decode(&gate.prepared_native)?;
        let revoked = decode(&gate.revocation_policy)?;
        let revocation = decode(&gate.revocation)?;
        let release = gate.release.as_deref().map(decode).transpose()?;
        let release_ack = gate.release_ack.as_deref().map(decode).transpose()?;
        validate_linux_policy_gate(
            &record.key.scenario,
            &prepared,
            &receipt,
            &decode(&gate.retirement)?,
            &decode(&gate.acknowledgment)?,
            &requested,
            &census["provider"],
            &baseline,
            &revoked,
            &activation,
            &revocation,
            &restoration,
            custody.hash(&gate.prepared)?,
            &evidence.run_id,
            attempt,
            release.as_ref(),
            release_ack.as_ref(),
        )?;
        if revocation["registry_digest"] != linux_registry_digest(&revoked, &record.key.target)? {
            return Err("policy gate native revocation digest differs".into());
        }
        let command = decode(&gate.revocation_invocation)?;
        let argv: Vec<Vec<u8>> = serde_json::from_value(command["arguments"].clone())
            .map_err(|error| error.to_string())?;
        if argv.len() != 5
            || argv[4]
                != format!(
                    "{privileged}/{}/revocation.policy.json",
                    record.key.scenario
                )
                .as_bytes()
        {
            return Err("policy gate native revocation escapes original staging".into());
        }
        validate_linux_policy_command_capture(
            &command,
            &decode(&gate.revocation_exit)?,
            custody.bytes(&gate.revocation_invocation)?,
            custody.bytes(&gate.revocation)?,
            custody.bytes(&gate.revocation_stderr)?,
            custody.bytes(&gate.revocation_policy)?,
            &agent.installed_sha256,
        )?;
    }
    if let Some(discovery) = &evidence.discovery {
        let discovery_command = decode(&discovery.invocation)?;
        let arguments: Vec<Vec<u8>> =
            serde_json::from_value(discovery_command["arguments"].clone())
                .map_err(|error| error.to_string())?;
        let command = decode(&evidence.frontend_invocation)?;
        let frontend_arguments: Vec<Vec<u8>> = serde_json::from_value(command["arguments"].clone())
            .map_err(|error| error.to_string())?;
        let contract_path = frontend_arguments
            .get(11)
            .ok_or("discovery public contract path absent")?;
        let contract_path = std::str::from_utf8(contract_path)
            .map_err(|_| "discovery contract path is not UTF8")?;
        // This is retained Linux command wire, independent of the verifier host.
        let parent = contract_path
            .rsplit_once('/')
            .ok_or("discovery contract parent absent")?
            .0;
        let expected_path = format!("{parent}/discovery-contract.json");
        if arguments.last().map(Vec::as_slice) != Some(expected_path.as_bytes())
            || decode(&discovery.contract)? != requested
        {
            return Err("discovery command does not address original exact contract".into());
        }
        let revoked = decode(&discovery.revocation_policy)?;
        let revocation = decode(&discovery.revocation)?;
        linux_policy::validate_linux_policy_discovery(
            &discovery_command,
            &decode(&discovery.exit)?,
            custody.bytes(&discovery.stdout)?,
            custody.bytes(&discovery.stderr)?,
            &requested,
            &baseline,
            &activation,
            &revoked,
            &revocation,
            &restoration,
            &cli.installed_sha256,
            &census["provider"],
        )?;
        if revocation["registry_digest"] != linux_registry_digest(&revoked, &record.key.target)? {
            return Err("discovery native revocation digest differs".into());
        }
        let revocation_command = decode(&discovery.revocation_invocation)?;
        let argv: Vec<Vec<u8>> = serde_json::from_value(revocation_command["arguments"].clone())
            .map_err(|error| error.to_string())?;
        if argv.len() != 5
            || argv[4]
                != format!("{privileged}/revoke-discovery/discovery-revocation.policy.json")
                    .as_bytes()
        {
            return Err("discovery revocation escapes original staging".into());
        }
        validate_linux_policy_command_capture(
            &revocation_command,
            &decode(&discovery.revocation_exit)?,
            custody.bytes(&discovery.revocation_invocation)?,
            custody.bytes(&discovery.revocation)?,
            custody.bytes(&discovery.revocation_stderr)?,
            custody.bytes(&discovery.revocation_policy)?,
            &agent.installed_sha256,
        )?;
    }
    if restored != baseline
        || activation["registry_digest"] != linux_registry_digest(&applied, &record.key.target)?
        || restoration["registry_digest"] != linux_registry_digest(&baseline, &record.key.target)?
    {
        return Err("policy activation/restoration canonical registry bytes differ".into());
    }
    let positive = index
        .records
        .iter()
        .find(|candidate| {
            candidate.key.target == record.key.target
                && candidate.key.channel == record.key.channel
                && candidate.key.evidence_class == EvidenceClass::InstalledProduct
                && candidate.key.family == "C-ADMISSION"
                && candidate.key.scenario == "positive"
        })
        .ok_or("policy mutation lacks separately observed baseline admission")?;
    verify_record(index, positive, products, builds, custody)?;
    let positive_evidence: CaseEvidence = wire::decode(
        custody.bytes(
            positive
                .evidence
                .as_deref()
                .ok_or("baseline admission evidence absent")?,
        )?,
    )?;
    let mut admitted = decode(
        positive_evidence
            .request
            .as_deref()
            .ok_or("baseline admitted contract absent")?,
    )?;
    let mut expected = baseline_contract.clone();
    admitted
        .as_object_mut()
        .ok_or("baseline admitted contract is not an object")?
        .remove("expected_epoch");
    expected
        .as_object_mut()
        .ok_or("baseline policy contract is not an object")?
        .remove("expected_epoch");
    if admitted != expected {
        return Err(
            "policy original authority differs from independently verified positive request".into(),
        );
    }
    let challenge = custody.bytes(&evidence.challenge)?;
    let command = decode(&evidence.frontend_invocation)?;
    let invocation = decode(&evidence.invocation)?;
    let caller = if record.key.scenario == "wrong-caller" {
        65533
    } else {
        65534
    };
    validate_linux_policy_frontend(
        &command,
        &invocation,
        challenge,
        caller,
        &cli.installed_sha256,
    )?;
    let exit = decode(&evidence.frontend_exit)?;
    let exit_fields = [
        "format",
        "revision",
        "process_id",
        "process_birth",
        "raw_wait_status",
        "native_exit",
        "signal",
        "invocation_sha256",
        "stdout_sha256",
        "stderr_sha256",
    ];
    let object = exit
        .as_object()
        .ok_or("policy frontend exit is not an object")?;
    if object.len() != exit_fields.len()
        || exit_fields.iter().any(|field| !object.contains_key(*field))
        || exit["format"] != "memcordon.linux-policy-frontend-exit"
        || exit["revision"] != 1
        || !exit["signal"].is_null()
        || exit["process_birth"]
            .as_u64()
            .filter(|birth| *birth > 0)
            .is_none()
        || exit["invocation_sha256"] != custody.hash(&evidence.frontend_invocation)?
        || exit["stdout_sha256"] != custody.hash(&evidence.stdout)?
        || exit["stderr_sha256"] != custody.hash(&evidence.stderr)?
    {
        return Err("policy frontend native exit/captures cross retained command bytes".into());
    }
    let pid = u32::try_from(
        exit["process_id"]
            .as_u64()
            .ok_or("policy actual frontend PID absent")?,
    )
    .map_err(|error| error.to_string())?;
    let status = i32::try_from(
        exit["native_exit"]
            .as_i64()
            .ok_or("policy actual native exit absent")?,
    )
    .map_err(|error| error.to_string())?;
    if !(0..=255).contains(&status)
        || exit["raw_wait_status"].as_i64() != Some(i64::from(status) << 8)
    {
        return Err("policy frontend raw native wait differs".into());
    }
    let result = decode(&evidence.raw_result)?;
    let reason = result["runtime"]["outcome"]["reason"]
        .as_str()
        .ok_or("policy actual refusal reason absent")?;
    validate_linux_policy_refusal_result(
        &result,
        custody.bytes(&evidence.provider_request)?,
        &requested,
        &invocation,
        &product.version,
        &record.key.target,
        status,
        pid,
        reason,
    )?;
    validate_linux_policy_mutation(
        &record.key.scenario,
        &baseline,
        &applied,
        &baseline_contract,
        &requested,
        &activation["epoch"],
        caller,
        reason,
    )?;
    let earlier = evidence
        .earlier_activations
        .iter()
        .map(|path| decode(path))
        .collect::<VerificationResult<Vec<_>>>()?;
    validate_linux_policy_activation_sequence(
        &record.key.scenario,
        &baseline,
        &applied,
        &requested,
        &activation,
        &restoration,
        &earlier,
    )?;
    for (ordinal, path) in evidence.earlier_activations.iter().enumerate() {
        if earlier[ordinal]["registry_digest"]
            != linux_registry_digest(&baseline, &record.key.target)?
        {
            return Err("policy earlier activation canonical digest differs".into());
        }
        let mut associated = false;
        for candidate in &index.records {
            if candidate.key.target != record.key.target
                || candidate.key.channel != record.key.channel
                || candidate.key.family != "L-ID-02"
                || candidate.key.scenario == "wrong-epoch"
            {
                continue;
            }
            let Some(candidate_path) = candidate.evidence.as_deref() else {
                continue;
            };
            let raw = decode(candidate_path)?;
            if raw["format"] != "memcordon.consumer-readiness.linux-policy-refusal" {
                continue;
            }
            let other: LinuxPolicyRefusalEvidence =
                serde_json::from_value(raw).map_err(|error| error.to_string())?;
            if custody.hash(path)? == custody.hash(&other.restoration)? {
                verify_record(index, candidate, products, builds, custody)?;
                associated = true;
                break;
            }
        }
        if !associated {
            return Err(
                "policy stale epoch lacks independently checked earlier native restoration capture"
                    .into(),
            );
        }
    }
    for (ordinal, (invocation_path, exit_path, stdout_path, stderr_path, policy_path)) in [
        (
            &evidence.activation_invocation,
            &evidence.activation_exit,
            &evidence.activation,
            &evidence.activation_stderr,
            &evidence.activation_policy,
        ),
        (
            &evidence.restoration_invocation,
            &evidence.restoration_exit,
            &evidence.restoration,
            &evidence.restoration_stderr,
            &evidence.restoration_policy,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let actual_command = decode(invocation_path)?;
        let arguments: Vec<Vec<u8>> = serde_json::from_value(actual_command["arguments"].clone())
            .map_err(|error| error.to_string())?;
        let stem = if ordinal == 0 {
            "activation"
        } else {
            "restoration"
        };
        if arguments.len() != 5
            || arguments[4]
                != format!("{privileged}/{}/{stem}.policy.json", record.key.scenario).as_bytes()
        {
            return Err("policy native command crosses original owned case staging".into());
        }
        validate_linux_policy_command_capture(
            &actual_command,
            &decode(exit_path)?,
            custody.bytes(invocation_path)?,
            custody.bytes(stdout_path)?,
            custody.bytes(stderr_path)?,
            custody.bytes(policy_path)?,
            &agent.installed_sha256,
        )?;
    }
    let public = decode(&evidence.provider_request)?;
    let mut native = public["native_launch"]
        .as_array()
        .ok_or("policy native launch missing")?
        .iter()
        .map(|byte| {
            byte.as_u64()
                .and_then(|byte| u8::try_from(byte).ok())
                .ok_or("policy native launch byte malformed")
        })
        .collect::<Result<Vec<_>, _>>()?;
    if native.get(2..10) != Some(&[0u8; 8][..]) {
        return Err("policy public request invents a restart attempt".into());
    }
    native.extend(
        hex::decode(wire::v3_request_digest(&requested)?).map_err(|error| error.to_string())?,
    );
    let input = FixtureInput {
        format: "memcordon.consumer-readiness.input".into(),
        revision: 1,
        run_id: evidence.run_id.clone(),
        key: record.key.clone(),
        challenge_sha256: sha256(challenge),
        binary: Vec::new(),
        target_argv: NativeArguments::UnixBytes(vec![
            b"tcp-http".to_vec(),
            hex::encode(challenge).into_bytes(),
        ]),
        deadline_millis: None,
        memory_bytes: None,
        toolchain_identity: None,
    };
    wire::validate_mixed_public_invocation(
        &native,
        custody.bytes(&evidence.requested_contract)?,
        &serde_json::to_vec(&input).map_err(|error| error.to_string())?,
        &serde_json::to_vec(&NativeEnvironment::UnixBytes(Vec::new()))
            .map_err(|error| error.to_string())?,
    )?;
    Ok(())
}

fn verify_record(
    index: &EvidenceIndex,
    record: &CaseRecord,
    products: &BTreeMap<ProductKey, &ProductObservation>,
    builds: &BTreeMap<String, &ComponentBuild>,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    if record.state != CaseState::Passed {
        if record.state == CaseState::Blocked && record.reason.as_deref().is_none_or(str::is_empty)
        {
            return Err("blocked row omits precise precondition".into());
        }
        return Err(format!(
            "required case is {:?}: {}",
            record.state,
            record.reason.as_deref().unwrap_or("no evidence")
        ));
    }
    let origin = producer_origin(index, &record.key.target, record.key.channel.as_deref())?;
    if record.run_id != origin.run_id {
        return Err("row differs from immutable producer origin run".into());
    }
    if record.reason.is_some() {
        return Err("passed row carries a blocker/failure reason".into());
    }
    let raw: serde_json::Value = wire::decode(
        custody.bytes(
            record
                .evidence
                .as_deref()
                .ok_or("passed row omits persisted evidence")?,
        )?,
    )?;
    if raw["format"] == "memcordon.consumer-readiness.linux-isolation-import-refusal" {
        let evidence: LinuxIsolationImportEvidence =
            serde_json::from_value(raw).map_err(|error| error.to_string())?;
        return linux_import_refusal::verify(index, record, &evidence, products, custody);
    }
    if raw["format"] == "memcordon.consumer-readiness.linux-account-refusal" {
        let evidence: LinuxAccountRefusalEvidence =
            serde_json::from_value(raw).map_err(|error| error.to_string())?;
        return linux_account_refusal::verify(index, record, &evidence, products, custody);
    }
    if raw["format"] == "memcordon.consumer-readiness.linux-policy-refusal" {
        let evidence: LinuxPolicyRefusalEvidence =
            serde_json::from_value(raw).map_err(|error| error.to_string())?;
        return verify_linux_policy_refusal(index, record, &evidence, products, builds, custody);
    }
    if raw["format"] == "memcordon.consumer-readiness.linux-frozen-legacy" {
        let evidence: LinuxFrozenLegacyEvidence =
            serde_json::from_value(raw).map_err(|error| error.to_string())?;
        return linux_legacy::verify(index, record, &evidence, products, custody);
    }
    if raw["format"] == "memcordon.consumer-readiness.linux-malformed-ingress" {
        let evidence: LinuxMalformedIngressEvidence =
            serde_json::from_value(raw).map_err(|error| error.to_string())?;
        return linux_ingress::verify(index, record, &evidence, products, custody);
    }
    if raw["format"] == "memcordon.consumer-readiness.linux-native-recovery" {
        let evidence: LinuxNativeRecoveryCaseEvidence =
            serde_json::from_value(raw).map_err(|error| error.to_string())?;
        return linux_recovery_route::validate(index, record, &evidence, builds, custody);
    }
    if raw["format"] == "memcordon.consumer-readiness.linux-image-import" {
        let evidence: LinuxImageImportEvidence =
            serde_json::from_value(raw).map_err(|error| error.to_string())?;
        return linux_images::verify_import(index, record, &evidence, products, custody);
    }
    if raw["format"] == "memcordon.consumer-readiness.linux-image-export" {
        let evidence: LinuxImageExportEvidence =
            serde_json::from_value(raw).map_err(|error| error.to_string())?;
        return linux_exports::verify_export(index, record, &evidence, products, custody);
    }
    if raw["format"] == "memcordon.consumer-readiness.linux-lifecycle-loss" {
        let evidence: LinuxLifecycleLossEvidence =
            serde_json::from_value(raw).map_err(|error| error.to_string())?;
        return linux_lifecycle::verify_loss(index, record, &evidence, products, custody);
    }
    if raw["format"] == "memcordon.consumer-readiness.linux-delivery" {
        let evidence: LinuxDeliveryEvidence =
            serde_json::from_value(raw).map_err(|error| error.to_string())?;
        return linux_lifecycle::verify_delivery(index, record, &evidence, products, custody);
    }
    if raw["format"] == "memcordon.consumer-readiness.acquisition-case" {
        let evidence: AcquisitionCaseEvidence =
            serde_json::from_value(raw).map_err(|error| error.to_string())?;
        return verify_acquisition_case(index, record, &evidence, products, custody);
    }
    let evidence: CaseEvidence = serde_json::from_value(raw).map_err(|error| error.to_string())?;
    header(
        &evidence.format,
        evidence.revision,
        "memcordon.consumer-readiness.case",
    )?;
    if evidence.key != record.key
        || evidence.run_id != origin.run_id
        || evidence.source_commit != index.source_commit
        || evidence.source_tree_sha256 != index.source_tree_sha256
    {
        return Err("case/run/source binding differs".into());
    }
    digest(&evidence.fixture_sha256)?;
    digest(&evidence.fixture_source_sha256)?;
    if custody.hash(&evidence.fixture)? != evidence.fixture_sha256
        || custody.hash(&evidence.fixture_source)? != evidence.fixture_source_sha256
    {
        return Err("trusted fixture source/executable digest differs".into());
    }
    if custody.hash(&evidence.input)? != evidence.input_sha256 {
        return Err("fresh fixture input digest differs".into());
    }
    let invocation: NativeInvocation = wire::decode(custody.bytes(&evidence.invocation)?)?;
    header(
        &invocation.format,
        invocation.revision,
        "memcordon.consumer-readiness.invocation",
    )?;
    digest(&invocation.environment_sha256)?;
    digest(&invocation.association_sha256)?;
    if custody.hash(&invocation.environment)? != invocation.environment_sha256 {
        return Err("environment receipt digest differs".into());
    }
    wire::validate_arguments(&invocation.arguments, &record.key.target)?;
    if wire::invocation_digest(&invocation)? != invocation.association_sha256 {
        return Err("native argv/budgets do not reconstruct public invocation association".into());
    }
    let native: NativeObservation = wire::decode(custody.bytes(&evidence.native_observation)?)?;
    header(
        &native.format,
        native.revision,
        "memcordon.consumer-readiness.native",
    )?;
    if native.run_id != origin.run_id
        || native.target != record.key.target
        || native.lease_id != evidence.lease_id
        || native.executable_sha256 != invocation.executable_sha256
        || native.invocation_sha256 != invocation.association_sha256
    {
        return Err("native observation/invocation binding differs".into());
    }
    if !native.relay_complete
        || !native.result_named_identity_verified
        || !native.result_readback_verified
    {
        return Err("relay/report custody is incomplete".into());
    }
    let retirement: RetirementObservation = wire::decode(custody.bytes(&evidence.retirement)?)?;
    let semantic: SemanticObservation =
        wire::decode(custody.bytes(&evidence.semantic_observation)?)?;
    let windows_context = windows_acceptance::WindowsAcceptanceContext {
        index,
        record,
        evidence: &evidence,
        invocation: &invocation,
        native: &native,
        retirement: &retirement,
        semantic: &semantic,
        products,
        builds,
        custody,
    };
    if windows_acceptance::validate_preprovider_refusal_case(&windows_context)?
        || windows_acceptance::validate_authenticated_refusal_case(&windows_context)?
        || windows_actors::validate(&windows_context)?
    {
        return Ok(());
    }
    verify_retirement(&retirement, &native, &record.key, &semantic, custody)?;
    match record.key.evidence_class {
        EvidenceClass::InstalledProduct => {
            let key = ProductKey {
                target: record.key.target.clone(),
                channel: record
                    .key
                    .channel
                    .clone()
                    .ok_or("product row omits channel")?,
            };
            let product = products.get(&key).ok_or("row has no selected product")?;
            if evidence.lease_id.as_deref() != Some(product.lifecycle.lease_id.as_str())
                || evidence.component_recipe_id.is_some()
            {
                return Err(
                    "row is outside installed lease or substitutes a component recipe".into(),
                );
            }
            let cli = product
                .components
                .iter()
                .find(|c| c.role == "public-cli")
                .ok_or("selected CLI missing")?;
            let nul_facade = record.key.target.ends_with("windows-msvc")
                && record.key.family == "W-IO"
                && record.key.scenario == "argv-nul-rejection";
            if native.executable_sha256
                != if nul_facade {
                    evidence.fixture_sha256.as_str()
                } else {
                    cli.installed_sha256.as_str()
                }
            {
                return Err("case did not execute selected installed CLI or exact native NUL facade fixture".into());
            }
            if native.origin != OutcomeOrigin::PackageOperation {
                let request = evidence
                    .request
                    .as_deref()
                    .ok_or("product case omits request")?;
                let frontend_refusal = record.key.target.ends_with("windows-msvc")
                    && native.origin == OutcomeOrigin::AdmissionRefusal
                    && ((record.key.family == "W-IO"
                        && record.key.scenario == "argv-nul-rejection")
                        || (record.key.family == "W-STATUS"
                            && record.key.scenario == "admission-refusal"));
                if frontend_refusal
                    && (native.root_pid.is_some()
                        || native.root_birth.is_some()
                        || native.target_status.is_some()
                        || native.authenticated_provider_exchange
                        || native.attempt_id.is_some()
                        || native.attempt_nonce.is_some()
                        || evidence.authenticated_terminal.is_some()
                        || evidence.provider_request.is_some())
                {
                    return Err(
                        "preauthorization facade refusal invents released target/provider terminal"
                            .into(),
                    );
                }
                let actual_request = if !frontend_refusal
                    && (record.key.target.ends_with("windows-msvc")
                        || !wire::legacy_linux(&record.key))
                {
                    evidence
                        .provider_request
                        .as_deref()
                        .ok_or("case omits actual provider request bytes")?
                } else {
                    request
                };
                if !frontend_refusal
                    && native.request_sha256.as_deref() != Some(custody.hash(actual_request)?)
                {
                    return Err("actual provider request binding differs".into());
                }
                let provider = product
                    .components
                    .iter()
                    .find(|c| c.role == "sealed-agent")
                    .ok_or("selected provider missing")?;
                if !frontend_refusal
                    && native.provider_sha256.as_deref() != Some(provider.installed_sha256.as_str())
                {
                    return Err(
                        "authenticated provider differs from selected installed product".into(),
                    );
                }
                if !frontend_refusal
                    && native.runtime_manifest_sha256.as_deref()
                        != Some(custody.hash(&product.runtime_manifest)?)
                {
                    return Err("authenticated installed runtime manifest differs".into());
                }
                if native.origin != OutcomeOrigin::AdmissionRefusal
                    && !native.authenticated_provider_exchange
                {
                    return Err("product case has no authenticated provider exchange".into());
                }
                wire::validate_request(custody.bytes(request)?, &record.key, native.origin)?;
                if evidence.windows_loss.is_some() {
                    wire::validate_windows_loss(&evidence, &native, &record.key, product, custody)?;
                } else {
                    wire::validate_result(
                        custody.bytes(
                            evidence
                                .raw_result
                                .as_deref()
                                .ok_or("product case omits raw selected-format result")?,
                        )?,
                        evidence
                            .authenticated_terminal
                            .as_deref()
                            .map(|path| custody.bytes(path))
                            .transpose()?,
                        custody.bytes(request)?,
                        &native,
                        &record.key,
                        &index.version,
                        &index.source_commit,
                        &evidence,
                        custody,
                    )?;
                }
                if record.key.target.ends_with("linux-gnu")
                    && !wire::legacy_linux(&record.key)
                    && native.origin != OutcomeOrigin::AdmissionRefusal
                {
                    let native_invocation_bytes = custody.bytes(
                        evidence
                            .execution_invocation
                            .as_deref()
                            .ok_or("mixed case omits actual native invocation bytes")?,
                    )?;
                    if native.execution_invocation_sha256.as_deref()
                        != Some(sha256(native_invocation_bytes).as_str())
                    {
                        return Err("mixed native invocation digest differs".into());
                    }
                    wire::validate_mixed_invocation(
                        native_invocation_bytes,
                        custody.bytes(request)?,
                        custody.bytes(&evidence.input)?,
                        custody.bytes(
                            evidence
                                .execution_environment
                                .as_deref()
                                .ok_or("mixed case omits approved effective environment bytes")?,
                        )?,
                    )?;
                }
            }
        }
        EvidenceClass::NativeComponentRegression => {
            let build = builds
                .get(&record.key.target)
                .ok_or("component build missing")?;
            let semantic: SemanticObservation =
                wire::decode(custody.bytes(&evidence.semantic_observation)?)?;
            if semantic.component_actors.is_some() == semantic.component_test.is_some() {
                return Err(
                    "native component requires exactly one actual harness or actor execution role"
                        .into(),
                );
            }
            let executable = if record.key.family == "C-PARSER" {
                build
                    .parser_executable
                    .as_deref()
                    .ok_or("actual native parser harness role absent")?
            } else if semantic.component_actors.is_some() && semantic.component_test.is_none() {
                build
                    .actor_executable
                    .as_deref()
                    .ok_or("actual native component actor executable role absent")?
            } else {
                build.executable.as_str()
            };
            if record.key.channel.is_some()
                || evidence.lease_id.is_some()
                || evidence.component_recipe_id.as_deref() != Some(build.recipe_id.as_str())
                || native.origin != OutcomeOrigin::ComponentRegression
                || native.executable_sha256 != custody.hash(executable)?
            {
                return Err(
                    "component evidence substituted into product or recipe binding differs".into(),
                );
            }
        }
    }
    verify_semantic(&semantic, &native, &evidence, custody, index)
}

fn verify_retirement(
    retired: &RetirementObservation,
    native: &NativeObservation,
    key: &CaseKey,
    semantic: &SemanticObservation,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    verify_retirement_in_scope(retired, native, key, semantic, custody, false)
}
fn verify_retirement_in_scope(
    retired: &RetirementObservation,
    native: &NativeObservation,
    key: &CaseKey,
    semantic: &SemanticObservation,
    custody: &custody::Custody,
    owned_overlap: bool,
) -> VerificationResult<()> {
    header(
        &retired.format,
        retired.revision,
        "memcordon.consumer-readiness.retirement",
    )?;
    let parser_root = key.family == "C-PARSER"
        || (key.family == "L-VER-01"
            && [
                "filter-x64",
                "filter-arm64",
                "journal-barrier",
                "release-barrier",
                "v1-vectors",
                "v2-vectors",
                "v3-vectors",
                "projection-mutation",
            ]
            .contains(&key.scenario.as_str()));
    let root_only = key.evidence_class == EvidenceClass::NativeComponentRegression
        && (key.target.ends_with("windows-msvc") || parser_root)
        && semantic.component_test.is_some()
        && semantic.component_actors.is_none();
    if root_only {
        let test = semantic.component_test.as_ref().expect("checked harness");
        let receipt: serde_json::Value = wire::decode(
            custody.bytes(
                test.native_retirement
                    .as_deref()
                    .ok_or("native harness retirement receipt absent")?,
            )?,
        )?;
        let birth = if key.target.ends_with("windows-msvc") {
            "creation_time_100ns"
        } else {
            "birth"
        };
        let format = if key.target.ends_with("windows-msvc") {
            "memcordon.windows-native-test-retirement"
        } else {
            "memcordon.linux-native-test-retirement"
        };
        let fields = [
            "format",
            "revision",
            "process_id",
            birth,
            "image_sha256",
            "held_before_input_delivery",
            "retirement_observed",
            "same_image_helpers_absent",
        ];
        if receipt.as_object().is_none_or(|object| {
            object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str()))
        }) || receipt["format"] != format
            || receipt["revision"] != 1
            || receipt["process_id"].as_u64() != native.root_pid.map(u64::from)
            || receipt[birth].as_u64() != native.root_birth
            || receipt["image_sha256"] != native.executable_sha256
            || receipt["held_before_input_delivery"] != true
            || receipt["retirement_observed"] != true
            || receipt["same_image_helpers_absent"] != true
            || retired.guardian_retired
            || retired.native_handles_closed
        {
            return Err("root-only harness retirement invented guardian/closure or differs from held native root".into());
        }
    }
    if retired.run_id != native.run_id
        || retired.attempt_id != native.attempt_id
        || retired.root_pid != native.root_pid
        || retired.root_birth != native.root_birth
        || !retired.target_reaped_or_absent
        || !retired.aggregate_empty
        || !retired.relays_retired
        || (!root_only && (!retired.guardian_retired || !retired.native_handles_closed))
        || retired.independently_observed == owned_overlap
        || !retired.outstanding.is_empty()
        || !retired.failed_operations.is_empty()
    {
        return Err("native aggregate retirement is incomplete or binding differs".into());
    }
    if key.evidence_class == EvidenceClass::InstalledProduct
        && native.origin != OutcomeOrigin::PackageOperation
        && native.origin != OutcomeOrigin::AdmissionRefusal
    {
        if native.root_pid.is_none_or(|pid| pid == 0)
            || native.root_birth.is_none_or(|birth| birth == 0)
            || native.attempt_id.as_deref().is_none_or(str::is_empty)
        {
            return Err("released target lacks held native identity/attempt".into());
        }
        if key.target.ends_with("linux-gnu") {
            if [
                retired.namespace_init_reaped,
                retired.private_root_closed,
                retired.exports_finalized,
                retired.account_reservation_retired,
            ]
            .iter()
            .any(|v| *v != Some(true))
            {
                return Err("Linux root/export/account retirement incomplete".into());
            }
        } else if retired.final_job_handles_closed != Some(true)
            || retired.active_processes_zero != Some(true)
        {
            return Err("Windows authoritative Job retirement incomplete".into());
        }
    }
    Ok(())
}

fn verify_semantic(
    semantic: &SemanticObservation,
    native: &NativeObservation,
    evidence: &CaseEvidence,
    custody: &custody::Custody,
    index: &EvidenceIndex,
) -> VerificationResult<()> {
    header(
        &semantic.format,
        semantic.revision,
        "memcordon.consumer-readiness.semantic",
    )?;
    if semantic.run_id != evidence.run_id
        || semantic.key != evidence.key
        || semantic.operations.len() > 256
        || semantic.comparisons.len() > 256
        || semantic.counters.len() > 64
    {
        return Err("semantic association/bounds differ".into());
    }
    if let Some(vector) = &semantic.windows_capacity {
        validate_windows_capacity_shape(vector, &evidence.key)?;
        let generation = native
            .provider_generation
            .as_deref()
            .ok_or("capacity selected provider generation absent")?;
        let mut boot = None;
        for path in &vector.inventories {
            let raw: serde_json::Value = wire::decode(custody.bytes(path)?)?;
            validate_windows_capacity_inventory(&raw, generation)?;
            let current = raw["current_boot_identity"]
                .as_str()
                .expect("validated boot")
                .to_owned();
            if boot.as_ref().is_some_and(|previous| previous != &current) {
                return Err("capacity inventory changed native boot across constituents".into());
            }
            boot = Some(current);
        }
        let mut challenges = BTreeSet::new();
        let mut attempts = BTreeSet::new();
        let mut roots = BTreeSet::new();
        let mut first_capacity: Option<(NativeObservation, SemanticObservation)> = None;
        for (ordinal, path) in vector.attempts.iter().enumerate() {
            let constituent: CaseEvidence = wire::decode(custody.bytes(path)?)?;
            header(
                &constituent.format,
                constituent.revision,
                "memcordon.consumer-readiness.case",
            )?;
            if constituent.key != evidence.key
                || constituent.run_id != evidence.run_id
                || constituent.source_commit != evidence.source_commit
                || constituent.source_tree_sha256 != evidence.source_tree_sha256
                || constituent.lease_id != evidence.lease_id
                || constituent.fixture_sha256 != evidence.fixture_sha256
                || constituent.fixture_source_sha256 != evidence.fixture_source_sha256
                || constituent.component_recipe_id.is_some()
                || custody.hash(&constituent.fixture)? != constituent.fixture_sha256
                || custody.hash(&constituent.fixture_source)? != constituent.fixture_source_sha256
                || custody.hash(&constituent.input)? != constituent.input_sha256
            {
                return Err("capacity constituent differs from actual source, fixture, lease or input custody".into());
            }
            let child_semantic: SemanticObservation =
                wire::decode(custody.bytes(&constituent.semantic_observation)?)?;
            header(
                &child_semantic.format,
                child_semantic.revision,
                "memcordon.consumer-readiness.semantic",
            )?;
            if child_semantic.windows_capacity.is_some()
                || child_semantic.key != evidence.key
                || child_semantic.run_id != evidence.run_id
            {
                return Err(
                    "capacity constituent recurses or relabels its original semantic observation"
                        .into(),
                );
            }
            if ordinal == 0
                && (constituent.input != evidence.input
                    || constituent.input_sha256 != evidence.input_sha256
                    || constituent.invocation != evidence.invocation
                    || constituent.request != evidence.request
                    || constituent.provider_request != evidence.provider_request
                    || constituent.raw_result != evidence.raw_result
                    || constituent.authenticated_terminal != evidence.authenticated_terminal
                    || constituent.native_observation != evidence.native_observation
                    || constituent.retirement != evidence.retirement
                    || child_semantic.challenge != semantic.challenge
                    || serde_json::to_value(&child_semantic.fixture_behavior)
                        .map_err(|error| error.to_string())?
                        != serde_json::to_value(&semantic.fixture_behavior)
                            .map_err(|error| error.to_string())?)
            {
                return Err(
                    "capacity representative substitutes another actual constituent or raw product"
                        .into(),
                );
            }
            let challenge = custody.bytes(&child_semantic.challenge)?;
            let child_input: FixtureInput = wire::decode(custody.bytes(&constituent.input)?)?;
            header(
                &child_input.format,
                child_input.revision,
                "memcordon.consumer-readiness.input",
            )?;
            if challenge.len() != 32
                || challenge.iter().all(|byte| *byte == 0)
                || !challenges.insert(sha256(challenge))
                || child_input.key != evidence.key
                || child_input.run_id != evidence.run_id
                || child_input.challenge_sha256 != sha256(challenge)
            {
                return Err(
                    "capacity constituent lacks its own distinct native challenge and input".into(),
                );
            }
            let child_native: NativeObservation =
                wire::decode(custody.bytes(&constituent.native_observation)?)?;
            header(
                &child_native.format,
                child_native.revision,
                "memcordon.consumer-readiness.native",
            )?;
            let attempt = child_native
                .attempt_id
                .as_deref()
                .ok_or("capacity constituent attempt absent")?;
            let root = child_native
                .root_pid
                .ok_or("capacity constituent held root absent")?;
            let birth = child_native
                .root_birth
                .ok_or("capacity constituent root birth absent")?;
            if child_native.run_id != evidence.run_id
                || child_native.target != evidence.key.target
                || child_native.lease_id != evidence.lease_id
                || child_native.provider_generation != native.provider_generation
                || child_native.provider_sha256 != native.provider_sha256
                || child_native.runtime_manifest_sha256 != native.runtime_manifest_sha256
                || !child_native.authenticated_provider_exchange
                || child_native.origin != OutcomeOrigin::Target
                || !attempts.insert(attempt.to_owned())
                || !roots.insert((root, birth))
                || child_native.request_sha256.as_deref()
                    != Some(
                        custody.hash(
                            constituent
                                .provider_request
                                .as_deref()
                                .ok_or("capacity constituent actual provider request absent")?,
                        )?,
                    )
            {
                return Err("capacity constituent reuses or changes authenticated native attempt/root/provider custody".into());
            }
            let child_invocation: NativeInvocation =
                wire::decode(custody.bytes(&constituent.invocation)?)?;
            header(
                &child_invocation.format,
                child_invocation.revision,
                "memcordon.consumer-readiness.invocation",
            )?;
            wire::validate_arguments(&child_invocation.arguments, &evidence.key.target)?;
            if child_invocation.executable_sha256 != native.executable_sha256
                || child_native.executable_sha256 != child_invocation.executable_sha256
                || child_native.invocation_sha256 != child_invocation.association_sha256
                || wire::invocation_digest(&child_invocation)?
                    != child_invocation.association_sha256
                || custody.hash(&child_invocation.environment)?
                    != child_invocation.environment_sha256
            {
                return Err(
                    "capacity constituent actual public invocation/environment association differs"
                        .into(),
                );
            }
            let request = constituent
                .request
                .as_deref()
                .ok_or("capacity constituent public request absent")?;
            wire::validate_request(
                custody.bytes(request)?,
                &constituent.key,
                child_native.origin,
            )?;
            wire::validate_result(
                custody.bytes(
                    constituent
                        .raw_result
                        .as_deref()
                        .ok_or("capacity constituent actual result absent")?,
                )?,
                Some(
                    custody.bytes(
                        constituent
                            .authenticated_terminal
                            .as_deref()
                            .ok_or("capacity constituent authenticated terminal absent")?,
                    )?,
                ),
                custody.bytes(request)?,
                &child_native,
                &constituent.key,
                &index.version,
                &index.source_commit,
                &constituent,
                custody,
            )?;
            let behavior = child_semantic
                .fixture_behavior
                .as_ref()
                .ok_or("capacity constituent actual Joint behavior absent")?;
            let owned_overlap = evidence.key.scenario == "bounded-concurrency" && ordinal == 1;
            if owned_overlap {
                let (first_native, first_semantic) = first_capacity
                    .as_ref()
                    .ok_or("overlap first authenticated constituent absent")?;
                let first_behavior = first_semantic
                    .fixture_behavior
                    .as_ref()
                    .ok_or("overlap first actual Joint behavior absent")?;
                let first_peer = |role: &str| {
                    first_behavior
                        .peer_artifacts
                        .iter()
                        .find(|peer| peer.role == role)
                        .map(|peer| peer.path.as_str())
                        .ok_or("overlap first independently held peer artifact absent")
                };
                let first_live: serde_json::Value =
                    wire::decode(custody.bytes(first_peer("native-live-association")?)?)?;
                let overlap_live: serde_json::Value = wire::decode(
                    custody.bytes(
                        vector
                            .overlap_live_association
                            .as_deref()
                            .ok_or("overlap live native association absent")?,
                    )?,
                )?;
                let guardian: serde_json::Value = wire::decode(
                    custody.bytes(
                        vector
                            .overlap_held_guardian
                            .as_deref()
                            .ok_or("overlap held native guardian absent")?,
                    )?,
                )?;
                let peer: serde_json::Value =
                    wire::decode(custody.bytes(first_peer("native-tcp-peer")?)?)?;
                let mandatory = [
                    "format",
                    "revision",
                    "challenge",
                    "guardian_identity",
                    "association",
                ];
                let optional = [
                    "live_nonce",
                    "live_target_identity",
                    "worker_process_identity",
                    "worker_thread_identity",
                ];
                if overlap_live.as_object().is_none_or(|object| {
                    mandatory.iter().any(|field| !object.contains_key(*field))
                        || object.keys().any(|field| {
                            !mandatory.contains(&field.as_str())
                                && !optional.contains(&field.as_str())
                        })
                }) || overlap_live["format"] != "memcordon.windows-live-guardian-observation"
                    || overlap_live["revision"] != 1
                    || overlap_live["association"] != first_live["association"]
                    || overlap_live["live_nonce"] != first_live["live_nonce"]
                    || overlap_live["live_target_identity"] != first_live["live_target_identity"]
                    || overlap_live["guardian_identity"] != first_live["guardian_identity"]
                    || guardian != overlap_live["guardian_identity"]
                    || guardian.as_object().is_none_or(|object| {
                        object.len() != 2
                            || object.keys().any(|key| {
                                !["process_id", "creation_time_100ns"].contains(&key.as_str())
                            })
                    })
                {
                    return Err("overlap independently held first guardian/live association differs from actual first native attempt".into());
                }
                let root = (
                    first_native
                        .root_pid
                        .ok_or("overlap first held root absent")?,
                    first_native
                        .root_birth
                        .ok_or("overlap first held root birth absent")?,
                );
                let peer_identity = (
                    u32::try_from(
                        peer["pid"]
                            .as_u64()
                            .ok_or("overlap first held TCP peer PID absent")?,
                    )
                    .map_err(|_| "overlap first peer PID out of range")?,
                    peer["birth"]
                        .as_u64()
                        .ok_or("overlap first held TCP peer birth absent")?,
                );
                if peer_identity == root
                    || peer["parent_pid"].as_u64() != Some(u64::from(root.0))
                    || peer["parent_birth"].as_u64() != Some(root.1)
                    || peer["native_parent_edge_observed"] != true
                    || peer["parent_and_child_held_live"] != true
                {
                    return Err("overlap exclusions omit actual independently held first-family parent edge".into());
                }
                behavior::validate_capacity_overlap(
                    behavior,
                    &child_semantic,
                    &child_native,
                    &child_input,
                    custody,
                    &behavior::CapacityOverlap {
                        live: overlap_live,
                        excluded: [root, peer_identity],
                    },
                )?;
            } else {
                behavior::validate(
                    behavior,
                    &child_semantic,
                    &child_native,
                    &child_input,
                    custody,
                )?;
            }
            let retired: RetirementObservation =
                wire::decode(custody.bytes(&constituent.retirement)?)?;
            verify_retirement_in_scope(
                &retired,
                &child_native,
                &constituent.key,
                &child_semantic,
                custody,
                owned_overlap,
            )?;
            if ordinal == 0 {
                first_capacity = Some((child_native, child_semantic));
            }
        }
    }
    let challenge = custody.bytes(&semantic.challenge)?;
    if challenge.len() != 32 || challenge.iter().all(|byte| *byte == 0) {
        return Err("case lacks fresh controller challenge".into());
    }
    let input: FixtureInput = wire::decode(custody.bytes(&evidence.input)?)?;
    header(
        &input.format,
        input.revision,
        "memcordon.consumer-readiness.input",
    )?;
    if input.key != evidence.key
        || input.run_id != evidence.run_id
        || input.challenge_sha256 != sha256(challenge)
    {
        return Err("fixture input/challenge association differs".into());
    }
    wire::validate_arguments(&input.target_argv, &evidence.key.target)?;
    let mut operations = BTreeSet::new();
    if let Some(behavior) = &semantic.fixture_behavior
        && evidence.key.target.ends_with("linux-gnu")
        && behavior.native_binding != evidence.prepared_native_receipt
    {
        return Err("Linux behavior root binding differs from independent preauthorization native observation".into());
    }
    let behavior_facts = semantic
        .fixture_behavior
        .as_ref()
        .map(|behavior| {
            if semantic.key.family == "L-ISO-03"
                && semantic.key.scenario == "other-attempt-abstract"
            {
                linux_cross_attempt::validate(behavior, semantic, native, evidence, index, custody)
            } else if semantic.key.family == "L-ID-03"
                && ["drain-running", "revoke-running", "restart-fresh-admission"]
                    .contains(&semantic.key.scenario.as_str())
            {
                behavior::validate(behavior, semantic, native, &input, custody)?;
                linux_policy_running::validate(behavior, semantic, native, evidence, index, custody)
            } else {
                behavior::validate(behavior, semantic, native, &input, custody)
            }
        })
        .transpose()?;
    for operation in &semantic.operations {
        if operation.observer == "owned-native-loss" {
            let key = &evidence.key;
            let allowed = key.target.ends_with("windows-msvc")
                && key.evidence_class == EvidenceClass::InstalledProduct
                && ((key.family == "W-RETIREMENT"
                    && [
                        "frontend-loss",
                        "control-service-loss",
                        "attempt-worker-loss",
                    ]
                    .contains(&key.scenario.as_str()))
                    || (key.family == "C-LIFETIME"
                        && ["frontend-loss", "service-loss", "worker-loss"]
                            .contains(&key.scenario.as_str())));
            let loss = evidence
                .windows_loss
                .as_ref()
                .ok_or("native loss observer lacks original bound loss graph")?;
            if !allowed
                || native.origin != OutcomeOrigin::ProviderFailure
                || operation.native_receipt != loss.action
                || operation.attempt_id != native.attempt_id
                || operation.root_pid != native.root_pid
                || !operations.insert(operation.operation.as_str())
                || ![
                    format!("fault-{}", key.scenario),
                    "original-cause-retained".into(),
                    "independent-retirement".into(),
                ]
                .contains(&operation.operation)
                || semantic.operations.len() != 3
            {
                return Err("native loss observer changes original finite action/cause/retirement association".into());
            }
            // validate_windows_loss has already decoded the original action,
            // actual held family, captured cause and independent recovery graph.
            custody.bytes(&loss.action)?;
            continue;
        }
        if operation.observer == "owned-image-entrypoint" {
            if evidence.key.family != "L-IMG-03"
                || evidence.key.scenario != "image-only-entrypoint"
                || evidence.key.evidence_class != EvidenceClass::InstalledProduct
                || !evidence.key.target.ends_with("linux-gnu")
                || !["host-entrypoint-absent", "image-entrypoint-executed"]
                    .contains(&operation.operation.as_str())
                || operation.attempt_id != native.attempt_id
                || operation.root_pid != native.root_pid
                || !operations.insert(operation.operation.as_str())
            {
                return Err(
                    "image entrypoint observer substitutes finite native operation/binding".into(),
                );
            }
            let raw: serde_json::Value = wire::decode(custody.bytes(&operation.native_receipt)?)?;
            let prepared: serde_json::Value = wire::decode(
                custody.bytes(
                    evidence
                        .prepared_native_receipt
                        .as_deref()
                        .ok_or("image entrypoint native preparation absent")?,
                )?,
            )?;
            linux_images::validate_entrypoint(
                &raw,
                &prepared,
                native,
                &evidence.fixture_sha256,
                challenge,
            )?;
            if raw["executable"]["length"].as_u64()
                != Some(custody.bytes(&evidence.fixture)?.len() as u64)
            {
                return Err("image entrypoint native executable length differs from measured original fixture".into());
            }
            let result: serde_json::Value = wire::decode(
                custody.bytes(
                    evidence
                        .raw_result
                        .as_deref()
                        .ok_or("image entrypoint genuine raw result absent")?,
                )?,
            )?;
            if linux_build::linux_image_reference(
                &raw["source"]["runtime_definition"],
                &native.target,
            )? != result["runtime"]["outcome"]["admission"]["request"]["runtime_image"]
            {
                return Err("image entrypoint source definition differs from original admitted runtime image".into());
            }
            continue;
        }
        if operation.observer == "owned-native-capacity" {
            let vector = semantic
                .windows_capacity
                .as_ref()
                .ok_or("capacity operation lacks full actual constituent vector")?;
            let expected = format!("capacity-{}", evidence.key.scenario);
            if evidence.key.family != "W-CAPACITY"
                || !evidence.key.target.ends_with("windows-msvc")
                || evidence.key.evidence_class != EvidenceClass::InstalledProduct
                || ![expected.as_str(), "fresh-admission", "capacity-attempts"]
                    .contains(&operation.operation.as_str())
                || operation.attempt_id != native.attempt_id
                || operation.root_pid != native.root_pid
                || vector.inventories.last().map(String::as_str)
                    != Some(operation.native_receipt.as_str())
                || semantic.counters.get("capacity-attempts")
                    != Some(&(vector.attempts.len() as u64))
                || !operations.insert(operation.operation.as_str())
            {
                return Err("capacity operation substitutes incomplete constituent or native final inventory custody".into());
            }
            let raw: serde_json::Value = wire::decode(custody.bytes(&operation.native_receipt)?)?;
            validate_windows_capacity_inventory(
                &raw,
                native
                    .provider_generation
                    .as_deref()
                    .ok_or("capacity selected generation absent")?,
            )?;
            continue;
        }
        if operation.observer == "owned-admission" {
            if !evidence.key.target.ends_with("linux-gnu")
                || evidence.key.evidence_class != EvidenceClass::InstalledProduct
                || evidence.key.family != "C-ADMISSION"
                || evidence.key.scenario != "positive"
                || operation.operation != "admission-granted"
                || operation.attempt_id != native.attempt_id
                || operation.root_pid != native.root_pid
                || Some(operation.native_receipt.as_str()) != evidence.raw_result.as_deref()
                || !native.authenticated_provider_exchange
                || native.origin != OutcomeOrigin::Target
                || native.target_status != Some(0)
                || !operations.insert(operation.operation.as_str())
            {
                return Err(
                    "positive admission observation substitutes another native product result"
                        .into(),
                );
            }
            let raw: serde_json::Value = wire::decode(custody.bytes(&operation.native_receipt)?)?;
            if raw["runtime"]["outcome"]["kind"] != "executed" {
                return Err("positive admission lacks actual native execution".into());
            }
            continue;
        }
        if operation.observer == "owned-current-result" {
            if evidence.key.evidence_class != EvidenceClass::InstalledProduct
                || evidence.key.family != "C-PARSER"
                || evidence.key.scenario != "valid-current-result"
                || operation.operation != "strict-current-result-decoded"
                || operation.attempt_id != native.attempt_id
                || operation.root_pid != native.root_pid
                || Some(operation.native_receipt.as_str()) != evidence.raw_result.as_deref()
                || !native.authenticated_provider_exchange
                || !operations.insert(operation.operation.as_str())
            {
                return Err(
                    "current result parser observation substitutes a different raw product result"
                        .into(),
                );
            }
            // verify_case independently decoded this exact selected-format raw
            // result and joined its native request/provider/attempt above.
            custody.bytes(&operation.native_receipt)?;
            continue;
        }
        if operation.observer == "authenticated-provider" {
            if !operations.insert(operation.operation.as_str())
                || operation.attempt_id != native.attempt_id
                || operation.root_pid != native.root_pid
                || Some(operation.native_receipt.as_str())
                    != evidence.authenticated_terminal.as_deref()
                || !evidence.key.target.ends_with("windows-msvc")
            {
                return Err(
                    "native provider fact operation is unbound or substitutes another raw receipt"
                        .into(),
                );
            }
            let sidecar: serde_json::Value =
                wire::decode(custody.bytes(&operation.native_receipt)?)?;
            let terminal = sidecar
                .get("terminal")
                .ok_or("authenticated native terminal absent")?;
            match operation.operation.as_str() {
                "creation-job-attested"
                | "suspended-target-attested"
                | "native-handle-list-attested" => {
                    // The full raw selected result/terminal has already passed
                    // independent creation/envelope validation above.
                    if !native.authenticated_provider_exchange {
                        return Err("native creation fact lacks authenticated exchange".into());
                    }
                }
                "sample-eviction-attested" | "evicted-completions" => {
                    let count = terminal
                        .pointer("/process_observation/coverage/counters/sample_evictions")
                        .and_then(serde_json::Value::as_u64)
                        .ok_or("actual sample eviction counter absent")?;
                    if count == 0
                        || semantic
                            .counters
                            .get(&operation.operation)
                            .is_some_and(|value| *value != count)
                    {
                        return Err("actual sample eviction counter differs".into());
                    }
                }
                _ => return Err("unknown independently decoded provider fact operation".into()),
            }
            continue;
        }
        if operation.observer == "owned-fixture-behavior" {
            let (behavior, facts) = semantic
                .fixture_behavior
                .as_ref()
                .zip(behavior_facts.as_ref())
                .ok_or("fixture operation lacks raw source-bound behavior")?;
            if !operations.insert(operation.operation.as_str())
                || operation.native_receipt != behavior.transcript
                || operation.attempt_id != native.attempt_id
                || operation.root_pid != native.root_pid
                || !facts.operations.contains(&operation.operation)
            {
                return Err("fixture operation is unbound, duplicated or absent from independently decoded behavior".into());
            }
            if semantic
                .counters
                .get(&operation.operation)
                .is_some_and(|value| facts.counters.get(&operation.operation) != Some(value))
            {
                return Err(
                    "fixture counter differs from independently decoded raw events/products".into(),
                );
            }
            continue;
        }
        if !operations.insert(operation.operation.as_str())
            || operation.observer != "native-controller"
            || operation.attempt_id != native.attempt_id
            || operation.root_pid != native.root_pid
        {
            return Err("operation is duplicate, unbound or solely fixture-reported".into());
        }
        // Native receipt decoding independently joins the exact collected fact.
        let receipt: NativeOperationReceipt =
            wire::decode(custody.bytes(&operation.native_receipt)?)?;
        header(
            &receipt.format,
            receipt.revision,
            "memcordon.consumer-readiness.operation",
        )?;
        if receipt.operation != operation.operation
            || receipt.attempt_id != operation.attempt_id
            || receipt.root_pid != operation.root_pid
            || receipt.root_birth != native.root_birth
            || receipt.run_id != native.run_id
            || receipt.observer_pid == 0
            || receipt.observer_birth == 0
            || receipt.observer_pid == native.root_pid.unwrap_or(0)
            || receipt.challenge_sha256 != sha256(challenge)
            || !["linux-native", "windows-native", "controller"]
                .contains(&receipt.native_domain.as_str())
            || receipt.native_code != 0
        {
            return Err("persisted independent native operation receipt differs".into());
        }
        if semantic
            .counters
            .get(&operation.operation)
            .is_some_and(|count| *count != receipt.observed_value)
        {
            return Err("counter differs from independently collected native receipt".into());
        }
    }
    let mut roles = BTreeSet::new();
    if let Some(probe) = &semantic.negative_probe {
        let fixture_host_denial = semantic
            .fixture_behavior
            .as_ref()
            .is_some_and(|behavior| probe.receipt == behavior.transcript)
            && ((evidence.key.family == "L-ISO-01"
                && [
                    "host-tcp",
                    "nonloopback",
                    "ipv6",
                    "udp",
                    "raw",
                    "packet",
                    "netlink",
                ]
                .contains(&evidence.key.scenario.as_str()))
                || (evidence.key.family == "L-ISO-02"
                    && ["host-run-socket", "host-temp-socket"]
                        .contains(&evidence.key.scenario.as_str()))
                || (evidence.key.family == "L-ISO-04"
                    && [
                        "symlink",
                        "dotdot",
                        "proc-root",
                        "proc-cwd",
                        "proc-fd",
                        "opath",
                        "hardlink",
                        "mount-alias",
                    ]
                    .contains(&evidence.key.scenario.as_str()))
                || (evidence.key.family == "L-ISO-03"
                    && ["host-abstract", "other-attempt-abstract"]
                        .contains(&evidence.key.scenario.as_str()))
                || (evidence.key.family == "L-ISO-05"
                    && [
                        "stdio-host-socket",
                        "extra-host-fd",
                        "pidfd-getfd",
                        "ptrace",
                        "namespace-entry",
                    ]
                    .contains(&evidence.key.scenario.as_str())));
        if fixture_host_denial {
            if !behavior_facts
                .as_ref()
                .is_some_and(|facts| facts.operations.contains("native-authority-probe"))
            {
                return Err(
                    "host native denial lacks decoded live canary/namespace association".into(),
                );
            }
        } else {
            let receipt: NativeOperationReceipt = wire::decode(custody.bytes(&probe.receipt)?)?;
            header(
                &receipt.format,
                receipt.revision,
                "memcordon.consumer-readiness.operation",
            )?;
            if receipt.operation != probe.stage
                || receipt.native_domain != probe.domain
                || receipt.native_code != probe.native_code
                || receipt.run_id != native.run_id
                || receipt.attempt_id != native.attempt_id
                || receipt.root_pid != native.root_pid
                || receipt.root_birth != native.root_birth
                || receipt.observer_pid == 0
                || receipt.observer_birth == 0
                || receipt.observer_pid == native.root_pid.unwrap_or(0)
                || receipt.challenge_sha256 != sha256(challenge)
            {
                return Err("native negative probe persisted receipt differs".into());
            }
        }
    }
    for comparison in &semantic.comparisons {
        if !roles.insert(comparison.role.as_str()) || comparison.actual == comparison.expected {
            return Err("duplicate comparison or self-comparison".into());
        }
        if custody.bytes(&comparison.actual)? != custody.bytes(&comparison.expected)? {
            return Err(format!("exact byte comparison failed: {}", comparison.role));
        }
    }
    if evidence.key.evidence_class == EvidenceClass::NativeComponentRegression {
        let test = semantic
            .component_test
            .as_ref()
            .ok_or("component regression lacks native test observation")?;
        let ci_parser = evidence.key.family == "C-PARSER"
            && ["omitted-case", "duplicate-case", "wrong-product"]
                .contains(&evidence.key.scenario.as_str());
        let operational_parser = evidence.key.family == "C-PARSER" && !ci_parser;
        let filter_vector = evidence.key.family == "L-VER-01"
            && ["filter-x64", "filter-arm64"].contains(&evidence.key.scenario.as_str());
        let journal_barrier =
            evidence.key.family == "L-VER-01" && evidence.key.scenario == "journal-barrier";
        let release_barrier = evidence.key.target.ends_with("linux-gnu")
            && evidence.key.family == "L-VER-01"
            && evidence.key.scenario == "release-barrier";
        let version_vector = evidence.key.family == "L-VER-01"
            && [
                "v1-vectors",
                "v2-vectors",
                "v3-vectors",
                "projection-mutation",
            ]
            .contains(&evidence.key.scenario.as_str());
        if Some(test.recipe_id.as_str()) != evidence.component_recipe_id.as_deref()
            || (evidence.key.target.ends_with("windows-msvc")
                && (test.test_name.is_empty() || test.test_name.len() > 512))
            || (!evidence.key.target.ends_with("windows-msvc")
                && !ci_parser
                && !operational_parser
                && !filter_vector
                && !journal_barrier
                && !release_barrier
                && !version_vector
                && test.test_name != format!("{}/{}", evidence.key.family, evidence.key.scenario))
            || test.native_exit != 0
            || test.tests_executed != 1
            || test.tests_failed != 0
            || test.tests_ignored != 0
        {
            return Err("native component regression did not execute exact required test".into());
        }
        custody.bytes(&test.raw_test_output)?;
        if ci_parser {
            let receipt: NativeParserMutationReceipt =
                wire::decode(custody.bytes(&test.native_receipt)?)?;
            if receipt.run_id != native.run_id
                || receipt.recipe_id != test.recipe_id
                || receipt.test_name != test.test_name
                || receipt.executable_sha256 != native.executable_sha256
                || receipt.challenge_sha256 != sha256(challenge)
            {
                return Err("native parser actual harness/challenge association differs".into());
            }
            validate_parser_mutations(&receipt, &evidence.key, custody)?;
            let output = std::str::from_utf8(custody.bytes(&test.raw_test_output)?)
                .map_err(|_| "native parser harness stdout not UTF-8")?;
            let line = format!("test {} ... ok", test.test_name);
            if output
                .lines()
                .filter(|value| *value == "running 1 test")
                .count()
                != 1
                || output.lines().filter(|value| *value == line).count() != 1
                || output
                    .lines()
                    .filter(|value| {
                        value.starts_with(
                            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ",
                        )
                    })
                    .count()
                    != 1
            {
                return Err("native parser actual selected test execution differs".into());
            }
        } else if operational_parser {
            let receipt: OperationalParserReceipt =
                wire::decode(custody.bytes(&test.native_receipt)?)?;
            if receipt.run_id != native.run_id
                || receipt.recipe_id != test.recipe_id
                || receipt.test_name != test.test_name
                || receipt.executable_sha256 != native.executable_sha256
                || receipt.challenge_sha256 != sha256(challenge)
            {
                return Err(
                    "operational parser actual harness/challenge association differs".into(),
                );
            }
            validate_operational_parser(&receipt, &evidence.key, custody)?;
            let output = std::str::from_utf8(custody.bytes(&test.raw_test_output)?)
                .map_err(|_| "operational parser stdout not UTF-8")?;
            let line = format!("test {} ... ok", test.test_name);
            if output
                .lines()
                .filter(|value| *value == "running 1 test")
                .count()
                != 1
                || output.lines().filter(|value| *value == line).count() != 1
                || output
                    .lines()
                    .filter(|value| {
                        value.starts_with(
                            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ",
                        )
                    })
                    .count()
                    != 1
            {
                return Err("actual operational parser selected test execution differs".into());
            }
        } else if filter_vector {
            let receipt: LinuxFilterReceipt = wire::decode(custody.bytes(&test.native_receipt)?)?;
            if receipt.run_id != native.run_id
                || receipt.recipe_id != test.recipe_id
                || receipt.test_name != test.test_name
                || receipt.executable_sha256 != native.executable_sha256
                || receipt.challenge_sha256 != sha256(challenge)
            {
                return Err("BPF actual native harness/challenge association differs".into());
            }
            validate_linux_filter_receipt(&receipt, &evidence.key)?;
            let output = std::str::from_utf8(custody.bytes(&test.raw_test_output)?)
                .map_err(|_| "BPF native harness output not UTF-8")?;
            let line = format!("test {} ... ok", test.test_name);
            if output
                .lines()
                .filter(|value| *value == "running 1 test")
                .count()
                != 1
                || output.lines().filter(|value| *value == line).count() != 1
                || output
                    .lines()
                    .filter(|value| {
                        value.starts_with(
                            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ",
                        )
                    })
                    .count()
                    != 1
            {
                return Err("actual BPF selected test execution differs".into());
            }
        } else if version_vector {
            let receipt: LinuxVersionReceipt = wire::decode(custody.bytes(&test.native_receipt)?)?;
            if receipt.run_id != native.run_id
                || receipt.recipe_id != test.recipe_id
                || receipt.test_name != test.test_name
                || receipt.executable_sha256 != native.executable_sha256
                || receipt.challenge_sha256 != sha256(challenge)
            {
                return Err("version vector actual harness/challenge association differs".into());
            }
            if ["v3-vectors", "projection-mutation"].contains(&evidence.key.scenario.as_str()) {
                validate_linux_mixed_version_vector(
                    &receipt,
                    &evidence.key,
                    custody.bytes(&receipt.v1_canonical)?,
                    custody.bytes(&receipt.v2_request)?,
                    custody.bytes(&receipt.v2_canonical)?,
                    custody.bytes(&receipt.v3_request)?,
                    custody.bytes(&receipt.v3_canonical)?,
                    custody.bytes(&receipt.projection)?,
                )?;
            } else {
                validate_linux_version_vector(
                    &receipt,
                    &evidence.key,
                    custody.bytes(&receipt.v1_canonical)?,
                    custody.bytes(&receipt.v2_request)?,
                    custody.bytes(&receipt.v2_canonical)?,
                )?;
            }
            let output = std::str::from_utf8(custody.bytes(&test.raw_test_output)?)
                .map_err(|_| "version native harness output not UTF-8")?;
            let line = format!("test {} ... ok", test.test_name);
            if output
                .lines()
                .filter(|value| *value == "running 1 test")
                .count()
                != 1
                || output.lines().filter(|value| *value == line).count() != 1
                || output
                    .lines()
                    .filter(|value| {
                        value.starts_with(
                            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ",
                        )
                    })
                    .count()
                    != 1
            {
                return Err("actual version selected test execution differs".into());
            }
        } else if release_barrier {
            let receipt: LinuxReleaseReceipt = wire::decode(custody.bytes(&test.native_receipt)?)?;
            let prefix = test
                .native_receipt
                .rsplit_once('/')
                .ok_or("release native receipt namespace absent")?
                .0;
            let input: serde_json::Value =
                wire::decode(custody.bytes(&format!("{prefix}/native-input.json"))?)?;
            let input_fields = [
                "run_id",
                "recipe_id",
                "native_target",
                "artifact_root",
                "artifact_prefix",
                "challenge",
                "work_deadline_unix_millis",
                "cleanup_deadline_unix_millis",
                "fixture_path",
                "fixture_sha256",
            ];
            if input.as_object().is_none_or(|object| {
                object.len() != input_fields.len()
                    || object
                        .keys()
                        .any(|field| !input_fields.contains(&field.as_str()))
            }) || input["run_id"] != native.run_id
                || input["recipe_id"] != test.recipe_id
                || input["native_target"] != evidence.key.target
                || input["artifact_prefix"] != prefix
                || input["challenge"] != serde_json::json!(challenge)
                || input["fixture_sha256"] != receipt.fixture_sha256
                || input["work_deadline_unix_millis"]
                    .as_u64()
                    .is_none_or(|work| {
                        work == 0
                            || input["cleanup_deadline_unix_millis"]
                                .as_u64()
                                .is_none_or(|cleanup| cleanup <= work)
                    })
            {
                return Err(
                    "leased release native input/fixture/original cutoff association differs"
                        .into(),
                );
            }
            let acquired = test
                .fixture_acquisition
                .as_ref()
                .ok_or("leased release lacks actual retained fixture acquisition")?;
            let (fixture_prefix, leaf) = acquired
                .checkpoint
                .rsplit_once('/')
                .ok_or("native fixture checkpoint namespace absent")?;
            if leaf != "owned-resources-acquired.json"
                || acquired.account_intent
                    != format!("{fixture_prefix}/exclusive-account-intent.json")
                || acquired.account_readback
                    != format!("{fixture_prefix}/exclusive-account-getent.bin")
                || acquired.group_readback != format!("{fixture_prefix}/exclusive-group-getent.bin")
            {
                return Err("native fixture acquisition raw paths are redirected".into());
            }
            let checkpoint: serde_json::Value = wire::decode(custody.bytes(&acquired.checkpoint)?)?;
            let intent: serde_json::Value = wire::decode(custody.bytes(&acquired.account_intent)?)?;
            let account = validate_linux_component_fixture_acquisition(
                &checkpoint,
                &intent,
                custody.bytes(&acquired.account_readback)?,
                custody.bytes(&acquired.group_readback)?,
                &native.run_id,
                &index.source_commit,
                &index.source_tree_sha256,
                &index.version,
                &evidence.key.target,
            )?;
            let admin = checkpoint["admin_root"]
                .as_str()
                .ok_or("native fixture acquired administrative root absent")?;
            let scope = admin
                .strip_suffix("/component-package-admin")
                .ok_or("native fixture administrative scope differs")?;
            let original_prefix = format!("{}/candidate-native/components", evidence.key.target);
            if prefix != format!("{original_prefix}/release")
                || fixture_prefix != format!("{original_prefix}/native-fixture")
                || input["fixture_path"] != format!("{scope}/release-fixture.json")
                || input["artifact_root"] != format!("{scope}/recipes/release")
            {
                return Err(
                    "release input substitutes acquired fixture descriptor/recipe scope".into(),
                );
            }
            let deadline_path =
                format!("{original_prefix}/roles/compiler/native-operation-deadline.json");
            let deadline_bytes = custody.bytes(&deadline_path)?;
            let deadline: serde_json::Value = wire::decode(deadline_bytes)?;
            let origin: serde_json::Value = wire::decode(custody.bytes(&format!(
                "{original_prefix}/roles/compiler/acquisition-origin.json"
            ))?)?;
            let selected_source = &deadline["source"];
            let repository = index
                .repository
                .as_deref()
                .filter(|repository| !repository.is_empty())
                .ok_or("release native assessment repository authority absent")?;
            let transported_origin = producer_origin(index, &evidence.key.target, None)?;
            if transported_origin.repository.as_deref() != Some(repository) {
                return Err(
                    "release original API repository differs from native assessment authority"
                        .into(),
                );
            }
            let source_matches = match selected_source["kind"].as_str() {
                Some("working") => {
                    selected_source.as_object().is_some_and(|fields| {
                        fields.len() == 3
                            && fields.keys().all(|field| {
                                ["kind", "version", "commit"].contains(&field.as_str())
                            })
                    }) && selected_source["commit"] == index.source_commit
                        && selected_source["version"] == index.version
                }
                Some("tagged") => {
                    selected_source.as_object().is_some_and(|fields| {
                        fields.len() == 2
                            && fields.contains_key("kind")
                            && fields.contains_key("source")
                    }) && selected_source["source"].as_object().is_some_and(|fields| {
                        fields.len() == 6
                            && fields.keys().all(|field| {
                                [
                                    "format",
                                    "revision",
                                    "repository",
                                    "tag_ref",
                                    "commit",
                                    "version",
                                ]
                                .contains(&field.as_str())
                            })
                    }) && selected_source["source"]["format"] == "memcordon.selected-source"
                        && selected_source["source"]["revision"] == 1
                        && selected_source["source"]["tag_ref"]
                            == format!("refs/tags/{}", index.version)
                        && selected_source["source"]["repository"]
                            .as_str()
                            .is_some_and(|repository| {
                                let parts = repository.split('/').collect::<Vec<_>>();
                                parts.len() == 2
                                    && parts.iter().all(|part| {
                                        !part.is_empty()
                                            && *part != "."
                                            && *part != ".."
                                            && part.bytes().all(|byte| {
                                                byte.is_ascii_alphanumeric()
                                                    || matches!(byte, b'-' | b'_' | b'.')
                                            })
                                    })
                            })
                        && selected_source["source"]["repository"] == repository
                        && selected_source["source"]["commit"] == index.source_commit
                        && selected_source["source"]["version"] == index.version
                }
                _ => false,
            };
            let deadline_fields = [
                "format",
                "revision",
                "source",
                "native_target",
                "started_unix_millis",
                "work_deadline_unix_millis",
                "cleanup_deadline_unix_millis",
            ];
            if deadline.as_object().is_none_or(|fields| {
                fields.len() != deadline_fields.len()
                    || fields
                        .keys()
                        .any(|field| !deadline_fields.contains(&field.as_str()))
            }) || deadline["format"] != "memcordon.consumer-readiness.original-native-deadline"
                || deadline["revision"] != 1
                || deadline["native_target"] != evidence.key.target
                || !source_matches
                || deadline["source"] != origin["source"]
                || origin["format"] != "memcordon.consumer-readiness.native-acquisition-origin"
                || origin["revision"] != 1
                || origin["target"] != evidence.key.target
                || origin["run_id"] != native.run_id
                || origin["deadline_sha256"] != sha256(deadline_bytes)
                || input["work_deadline_unix_millis"] != deadline["work_deadline_unix_millis"]
                || input["cleanup_deadline_unix_millis"] != deadline["cleanup_deadline_unix_millis"]
                || deadline["work_deadline_unix_millis"]
                    .as_u64()
                    .zip(deadline["started_unix_millis"].as_u64())
                    .is_none_or(|(work, start)| work.checked_sub(start) != Some(140 * 60 * 1000))
                || deadline["cleanup_deadline_unix_millis"]
                    .as_u64()
                    .zip(deadline["work_deadline_unix_millis"].as_u64())
                    .is_none_or(|(cleanup, work)| cleanup.checked_sub(work) != Some(15 * 60 * 1000))
            {
                return Err(
                    "release input renews/substitutes original acquisition deadline".into(),
                );
            }
            let fixture: serde_json::Value = wire::decode(custody.bytes(&receipt.fixture)?)?;
            if checkpoint["legacy"] != fixture["registry"]["legacy"]
                || !fixture["registry"]["images"]
                    .as_array()
                    .is_some_and(|images| {
                        images.len() == 2
                            && images.contains(&checkpoint["images"]["runtime"])
                            && images.contains(&checkpoint["images"]["input"])
                    })
            {
                return Err(
                    "leased fixture registry/image declarations differ from native acquisition"
                        .into(),
                );
            }
            validate_linux_release_receipt(
                &receipt,
                &native.run_id,
                &test.recipe_id,
                &evidence.key.target,
                &native.executable_sha256,
                challenge,
                (
                    native.root_pid.ok_or("release held harness PID absent")?,
                    native
                        .root_birth
                        .ok_or("release held harness birth absent")?,
                ),
                account,
                |path| Ok(custody.bytes(path)?.to_vec()),
            )?;
            let output = std::str::from_utf8(custody.bytes(&test.raw_test_output)?)
                .map_err(|_| "release native harness output not UTF-8")?;
            let line = format!("test {} ... ok", test.test_name);
            if output
                .lines()
                .filter(|value| *value == "running 1 test")
                .count()
                != 1
                || output.lines().filter(|value| *value == line).count() != 1
                || output
                    .lines()
                    .filter(|value| {
                        value.starts_with(
                            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ",
                        )
                    })
                    .count()
                    != 1
            {
                return Err("actual leased release selected test execution differs".into());
            }
        } else if journal_barrier {
            let receipt: LinuxJournalReceipt = wire::decode(custody.bytes(&test.native_receipt)?)?;
            if receipt.run_id != native.run_id
                || receipt.recipe_id != test.recipe_id
                || receipt.test_name != test.test_name
                || receipt.executable_sha256 != native.executable_sha256
                || receipt.challenge_sha256 != sha256(challenge)
                || receipt.frontend.pid != native.root_pid.unwrap_or(0)
                || receipt.frontend.start_time != native.root_birth.unwrap_or(0)
                || receipt.attempt_id
                    != hex::encode(challenge.get(..16).ok_or("journal challenge truncated")?)
            {
                return Err("journal actual held harness/challenge association differs".into());
            }
            validate_linux_journal_receipt(
                &receipt,
                &evidence.key,
                custody.bytes(&receipt.record_before)?,
                custody.bytes(&receipt.record_after_refusal)?,
            )?;
            let prefix = test
                .native_receipt
                .rsplit_once('/')
                .ok_or("journal receipt has no producer namespace")?
                .0;
            let input = custody.bytes(&format!("{prefix}/native-input.json"))?;
            let journal = std::str::from_utf8(custody.bytes(&receipt.record_before)?)
                .map_err(|_| "journal record is not UTF-8")?;
            let payload = journal
                .lines()
                .find_map(|line| line.strip_prefix("payload="))
                .ok_or("journal payload absent")?;
            let record: serde_json::Value = wire::decode(payload.as_bytes())?;
            if record["caller_envelope_digest"] != sha256(input) {
                return Err("journal original native input digest differs".into());
            }
            let output = std::str::from_utf8(custody.bytes(&test.raw_test_output)?)
                .map_err(|_| "journal native harness output not UTF-8")?;
            let line = format!("test {} ... ok", test.test_name);
            if output
                .lines()
                .filter(|value| *value == "running 1 test")
                .count()
                != 1
                || output.lines().filter(|value| *value == line).count() != 1
                || output
                    .lines()
                    .filter(|value| {
                        value.starts_with(
                            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ",
                        )
                    })
                    .count()
                    != 1
            {
                return Err("actual journal selected test execution differs".into());
            }
        } else if evidence.key.target.ends_with("windows-msvc") {
            let receipt: WindowsNativeComponentReceipt =
                wire::decode(custody.bytes(&test.native_receipt)?)?;
            header(
                &receipt.format,
                receipt.revision,
                "memcordon.windows-native-component",
            )?;
            if receipt.run_id != native.run_id
                || receipt.recipe_id != test.recipe_id
                || receipt.test_name != test.test_name
                || receipt.native_target != native.target
                || receipt.executable_sha256 != native.executable_sha256
            {
                return Err(
                    "native component receipt source/recipe/test association differs".into(),
                );
            }
            wire::validate_windows_component(&receipt, &evidence.key, custody)?;
            let captured = std::str::from_utf8(custody.bytes(&test.raw_test_output)?)
                .map_err(|_| "native Rust test capture is not bounded UTF-8")?;
            let test_line = format!("test {} ... ok", receipt.test_name);
            if captured
                .lines()
                .filter(|line| *line == "running 1 test")
                .count()
                != 1
                || captured.lines().filter(|line| *line == test_line).count() != 1
                || captured
                    .lines()
                    .filter(|line| {
                        line.starts_with(
                            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ",
                        )
                    })
                    .count()
                    != 1
            {
                return Err(
                    "native Rust test capture does not show exactly the selected real test".into(),
                );
            }
        } else {
            return Err(
                "Linux component row lacks a frozen independently decoded native receipt".into(),
            );
        }
        return Ok(());
    }
    if semantic.component_test.is_some() {
        return Err("installed case substitutes component test".into());
    }
    if semantic
        .counters
        .keys()
        .any(|counter| !operations.contains(counter.as_str()))
    {
        return Err("counter has no independent native operation receipt".into());
    }
    wire::semantic_expectations(
        &evidence.key,
        native,
        semantic,
        &input,
        &operations,
        &roles,
        custody,
    )
}
