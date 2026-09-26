//! Static-to-prepared installed public production. Runtime identities are
//! sampled after H1 activation; no future receipt or terminal enters intent.
use crate::private_observer_session::{
    AuthenticatedCustodianTransportV1, ObservedGenerationV1, ObserverSessionDescriptorV1,
};
use crate::private_public_plan::StaticPublicSuiteIntentV1;
use crate::{CiError, Result};
use memcordon_core::private_public_preparation_v2::{
    ApprovedPublicPreparationPolicyV2, PublicPreparedRoleV2,
};
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicStaticCaseInputV2 {
    pub(crate) selector: String,
    pub(crate) contract_template_path: PathBuf,
    pub(crate) fixture_path: PathBuf,
    pub(crate) report_directory: PathBuf,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProtectedPublicProducerIntentV2 {
    schema_version: u8,
    pub(crate) suite: StaticPublicSuiteIntentV1,
    preparation_policy_sha256: DiagnosticSha256,
    custody_policy: PathBuf,
    enrolled_host: String,
    probe: crate::private_probe_bundle::ExpectedProbeBundleV1,
    upgrade_intent_path: PathBuf,
    upgrade_intent_sha256: DiagnosticSha256,
    upgrade_archive_path: PathBuf,
    historical_spoof_report_directory: PathBuf,
    pub(crate) cases: Vec<PublicStaticCaseInputV2>,
    pub(crate) policy: PublicStaticPolicyInputV2,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicStaticPolicyInputV2 {
    pub(crate) fixture_template_path: PathBuf,
    pub(crate) branches: Vec<PublicStaticPolicyBranchInputV2>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicStaticPolicyBranchInputV2 {
    pub(crate) branch: memcordon_core::private_release_branch_v1::PolicyOperationBranchV1,
    pub(crate) contract_template_path: PathBuf,
    pub(crate) report_directory: PathBuf,
}
impl ProtectedPublicProducerIntentV2 {
    fn read(path: &Path, target: &str) -> Result<Self> {
        let bytes = crate::private_protected_readback::read_protected_raw_case_file(path)?;
        let intent: Self = crate::private_observer_session::strict_json(&bytes, 256 * 1024)?;
        intent.suite.validate()?;
        if intent.schema_version != 2
            || intent.suite.observer_subject.target != target
            || intent.enrolled_host.is_empty()
            || !intent.custody_policy.is_absolute()
            || intent.preparation_policy_sha256.bytes() == &[0; 32]
            || !intent.upgrade_intent_path.is_absolute()
            || !intent.upgrade_archive_path.is_absolute()
            || !intent.historical_spoof_report_directory.is_absolute()
            || intent.upgrade_intent_sha256.bytes() == &[0; 32]
            || intent.cases.len() != intent.suite.scenarios.len()
            || !intent.policy.fixture_template_path.is_absolute()
            || intent.policy.branches.len() != 5
            || intent
                .policy
                .branches
                .iter()
                .zip(memcordon_core::private_release_branch_v1::PolicyOperationBranchV1::ALL)
                .any(|(input, branch)| {
                    input.branch != branch
                        || !input.contract_template_path.is_absolute()
                        || !input.report_directory.is_absolute()
                })
            || intent
                .cases
                .iter()
                .zip(&intent.suite.scenarios)
                .any(|(input, case)| {
                    input.selector != case.selector
                        || !input.contract_template_path.is_absolute()
                        || !input.fixture_path.is_absolute()
                        || !input.report_directory.is_absolute()
                })
        {
            return fail("static public producer inputs differ from exact approved catalogue");
        }
        let mut reports = std::collections::BTreeSet::new();
        if intent.cases.iter().any(|case| {
            case.report_directory == intent.historical_spoof_report_directory
                || !reports.insert(&case.report_directory)
        }) {
            return fail("public report directories alias across physical scenarios");
        }
        if intent.policy.branches.iter().any(|branch| {
            branch.report_directory == intent.historical_spoof_report_directory
                || !reports.insert(&branch.report_directory)
        }) {
            return fail("public policy report directories alias other physical scenarios");
        }
        Ok(intent)
    }
}
fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}

#[cfg(target_os = "linux")]
struct LivePublicHistoricalPositiveV1 {
    selector: String,
    challenge: String,
    host: crate::private_final_install::FinalHostReadbackV1,
    provider: crate::private_public_dispatch::StructuralProviderFrameReadbackV2,
    join: crate::private_public_kernel_join::VerifiedPublicCaseKernelJoinV1,
    interval: crate::private_kernel_observer::VerifiedKernelIntervalV1,
}

#[cfg(target_os = "linux")]
pub(crate) fn read_pinned_image(path: &Path, expected: &DiagnosticSha256) -> Result<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    if !path.is_absolute() {
        return fail("public pinned image is not absolute");
    }
    let mut ancestor = PathBuf::from("/");
    let mut held_directories = Vec::new();
    for component in path
        .parent()
        .ok_or_else(|| CiError::Message("public image parent absent".into()))?
        .components()
    {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(name) => ancestor.push(name),
            _ => return fail("public image path is not canonical"),
        }
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&ancestor)?;
        let metadata = directory.metadata()?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return fail("public image ancestor is mutable");
        }
        held_directories.push((directory, metadata.dev(), metadata.ino()));
    }
    let mut image = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = image.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
        || before.len() == 0
        || before.len() > 64 * 1024 * 1024
    {
        return fail("public image object protection or 64MiB bound differs");
    }
    let mut bytes = Vec::new();
    image
        .by_ref()
        .take(before.len() + 1)
        .read_to_end(&mut bytes)?;
    let after = image.metadata()?;
    if bytes.len() as u64 != before.len()
        || hash_bytes(&bytes) != *expected
        || (
            before.dev(),
            before.ino(),
            before.len(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.ctime(),
            after.ctime_nsec(),
        )
    {
        return fail("public pinned image changed during held-object read");
    }
    for (directory, dev, inode) in held_directories {
        let metadata = directory.metadata()?;
        if metadata.dev() != dev
            || metadata.ino() != inode
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return fail("held public image ancestor changed");
        }
    }
    Ok(bytes)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActualPublicPreparationContextV2 {
    pub(crate) schema_version: u8,
    pub(crate) installation_epoch: DiagnosticSha256,
    pub(crate) active_h1_receipt_sha256: DiagnosticSha256,
    pub(crate) manifest_sha256: DiagnosticSha256,
    pub(crate) qualification_sha256: DiagnosticSha256,
    pub(crate) policy_epoch: memcordon_core::workload_contract::PolicyEpoch,
    pub(crate) registry_sha256: DiagnosticSha256,
}

#[cfg(target_os = "linux")]
fn observe_generation(
    root: &Path,
    intent: &ProtectedPublicProducerIntentV2,
    generation: u32,
) -> Result<(
    crate::private_final_install::FinalHostReadbackV1,
    ActualPublicPreparationContextV2,
    ObservedGenerationV1,
    BTreeMap<String, Vec<u8>>,
)> {
    use crate::private_kernel_observer::{
        InstalledObserverRoleV1, observe_installed_observer_subject,
    };
    let begin = memcordon_platform::test_support::private_observer_monotonic_ns()?;
    let host_bytes = crate::command::CommandSpec::new(
        "/usr/libexec/memcordon-sealed-agent",
        root,
        Duration::from_secs(30),
    )
    .remove_github_token()
    .args(["package", "verify-private-host", "--json"])
    .run()?;
    let host = crate::private_final_install::FinalHostReadbackV1::parse_bounded(&host_bytes)?;
    let context_bytes = crate::command::CommandSpec::new(
        "/usr/libexec/memcordon-sealed-agent",
        root,
        Duration::from_secs(30),
    )
    .remove_github_token()
    .args(["package", "public-preparation-context-v2", "--json"])
    .run()?;
    let context: ActualPublicPreparationContextV2 =
        crate::private_observer_session::strict_json(&context_bytes, 64 * 1024)?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    if context.schema_version != 2
        || host.source_commit() != intent.suite.observer_subject.source_commit
        || host.version() != intent.suite.observer_subject.release_version
        || host.target() != intent.suite.observer_subject.target
        || host.boot_id() != boot.trim()
        || context.installation_epoch != *host.installation_epoch()
        || context.active_h1_receipt_sha256 != *host.active_h1_receipt_sha256()
        || context.manifest_sha256 != intent.suite.manifest_sha256
        || context.qualification_sha256 != intent.suite.qualification_sha256
        || context.registry_sha256 != intent.suite.policy_recipe.registry_sha256
        || host.public_cli_sha256() != &intent.suite.public_cli_sha256
        || host.agent_sha256() != &intent.probe.agent_sha256
    {
        return fail("actual public H1/context differs from protected static producer");
    }
    let epoch_raw = crate::private_protected_readback::read_protected_raw_case_file(Path::new(
        "/usr/libexec/.memcordon-installation-epoch.json",
    ))?;
    if crate::private_installed_h0::validate_installation_epoch_bytes(&epoch_raw)?
        != context.installation_epoch
    {
        return fail("public generation original epoch bytes differ");
    }
    let host_value: serde_json::Value =
        crate::private_observer_session::strict_json(&host_bytes, 64 * 1024)?;
    let nonce = host_value
        .get("active_run_nonce")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| CiError::Message("actual H1 run nonce absent".into()))?;
    let receipt_name = ["receipt-", nonce, ".json"].concat();
    let h1 = crate::private_protected_readback::read_protected_raw_case_file(
        &Path::new("/var/lib/memcordon/sealed/private-qualification").join(receipt_name),
    )?;
    if hash_bytes(&h1) != context.active_h1_receipt_sha256 {
        return fail("actual public H1 bytes differ");
    }
    let service = observe_installed_observer_subject(InstalledObserverRoleV1::SealedService)?;
    let broker =
        crate::private_kernel_observer::activate_installed_network_broker_for_observation()?;
    let encode =
        |value: &serde_json::Value| crate::private_observer_session::canonical_bytes(value);
    let service_raw = encode(
        &serde_json::json!({"schema_version":1,"pid":service.pid,"start_time_ticks":service.start_ticks,"cgroup_inode":service.cgroup_inode}),
    )?;
    let broker_raw = encode(
        &serde_json::json!({"schema_version":1,"pid":broker.pid,"start_time_ticks":broker.start_ticks,"cgroup_inode":broker.cgroup_inode}),
    )?;
    // The fixed epoch reader independently rejects any live package journal.
    if crate::private_installed_h0::read_fixed_installation_epoch()? != context.installation_epoch {
        return fail("public generation changed or has a pending transaction");
    }
    let transaction = encode(
        &serde_json::json!({"schema_version":1,"pending_journal":false,"installation_epoch":context.installation_epoch,"observed_monotonic_ns":begin}),
    )?;
    let activation = encode(
        &serde_json::json!({"schema_version":1,"installed_receipt_sha256":context.active_h1_receipt_sha256,"manifest_sha256":context.manifest_sha256,"installation_epoch":context.installation_epoch,"observed_monotonic_ns":begin}),
    )?;
    let probe_raw = crate::private_observer_session::canonical_bytes(&intent.probe)?;
    let end = memcordon_platform::test_support::private_observer_monotonic_ns()?;
    let record = ObservedGenerationV1 {
        generation,
        installation_epoch: context.installation_epoch.clone(),
        installed_manifest_sha256: context.manifest_sha256.clone(),
        installed_receipt_sha256: context.active_h1_receipt_sha256.clone(),
        service_identity_sha256: hash_bytes(&service_raw),
        broker_identity_sha256: hash_bytes(&broker_raw),
        transaction_sha256: hash_bytes(&transaction),
        observer_bundle_sha256: hash_bytes(&probe_raw),
        begin_monotonic_ns: begin,
        end_monotonic_ns: end,
    };
    let prefix = Path::new("installed/generations").join(generation.to_string());
    let raw = [
        ("host.json", host_bytes),
        ("preparation-context.json", context_bytes),
        ("installation-epoch.json", epoch_raw),
        ("h1.json", h1),
        ("transaction.json", transaction),
        ("activation.json", activation),
        ("service.json", service_raw),
        ("broker.json", broker_raw),
        ("observer-map.json", probe_raw),
    ]
    .into_iter()
    .map(|(name, bytes)| (prefix.join(name).to_string_lossy().into_owned(), bytes))
    .collect();
    Ok((host, context, record, raw))
}

#[cfg(target_os = "linux")]
pub(crate) fn run(root: &Path, target: &str, path: &Path) -> Result<()> {
    use crate::private_kernel_observer::{
        ExpectedKernelAdapterV1, InstalledObserverRoleV1, observe_installed_observer_subject,
        observe_live_kernel_subject,
    };
    use crate::private_public_producer::{PublicObserverProducerV1, run_public_journal_interval};
    use crate::private_public_raw::PublicLeafKindV1 as Kind;
    use std::os::unix::fs::MetadataExt;
    let intent = ProtectedPublicProducerIntentV2::read(path, target)?;
    let context = crate::certification_context::CertificationContext::capture(
        root,
        "backend-linux-private-v4",
    )?;
    let provenance = context.provenance.as_ref().ok_or_else(|| {
        CiError::Message("public static producer lacks live Actions provenance".into())
    })?;
    let subject = &intent.suite.observer_subject;
    if subject.source_commit != context.source_commit
        || subject.run_id != provenance.run_id.get()
        || subject.run_attempt != provenance.run_attempt.get()
    {
        return fail("public static subject differs from actual live Actions context");
    }
    let token = std::env::var("GITHUB_TOKEN")
        .map_err(|_| CiError::Message("public live Actions readback token absent".into()))?;
    let run_url = format!(
        "https://api.github.com/repos/{}/actions/runs/{}/attempts/{}",
        provenance.repository, subject.run_id, subject.run_attempt
    );
    let read = |url: &str, limit: usize, accept: &str| {
        crate::private_actions_readback::fetch_actions_url(&token, url, limit, accept)
    };
    let run: serde_json::Value = crate::private_observer_session::strict_json(
        &read(&run_url, 1024 * 1024, "application/vnd.github+json")?,
        1024 * 1024,
    )?;
    let spec = crate::private_native::PRODUCERS
        .iter()
        .find(|spec| {
            spec.stage == crate::private_native::NativeRunStageV2::FinalPublic
                && spec.target == target
        })
        .ok_or_else(|| CiError::Message("public producer registration absent".into()))?;
    if run.get("id").and_then(serde_json::Value::as_u64) != Some(subject.run_id)
        || run.get("run_attempt").and_then(serde_json::Value::as_u64)
            != Some(u64::from(subject.run_attempt))
        || run.get("head_sha").and_then(serde_json::Value::as_str)
            != Some(subject.source_commit.as_str())
        || run
            .get("repository")
            .and_then(|value| value.get("id"))
            .and_then(serde_json::Value::as_u64)
            != Some(subject.repository_id)
        || run.get("status").and_then(serde_json::Value::as_str) != Some("in_progress")
        || !run
            .get("conclusion")
            .is_some_and(serde_json::Value::is_null)
        || provenance.job != spec.job_id
    {
        return fail("public approved subject differs from actual running Actions run");
    }
    let jobs = crate::private_actions_readback::read_complete_inventory(
        &format!("{run_url}/jobs?per_page=100"),
        "jobs",
        read,
    )?;
    let jobs = jobs
        .get("jobs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| CiError::Message("public running jobs array absent".into()))?;
    let matching = jobs
        .iter()
        .filter(|job| job.get("id").and_then(serde_json::Value::as_u64) == Some(subject.job_id))
        .collect::<Vec<_>>();
    let [job] = matching.as_slice() else {
        return fail("public enrolled job absent or ambiguous in actual running inventory");
    };
    if job.get("name").and_then(serde_json::Value::as_str) != Some(spec.job_name)
        || job.get("runner_id").and_then(serde_json::Value::as_u64) != Some(subject.runner_id)
        || job.get("run_id").and_then(serde_json::Value::as_u64) != Some(subject.run_id)
        || job.get("run_attempt").and_then(serde_json::Value::as_u64)
            != Some(u64::from(subject.run_attempt))
        || job.get("head_sha").and_then(serde_json::Value::as_str)
            != Some(subject.source_commit.as_str())
        || job.get("status").and_then(serde_json::Value::as_str) != Some("in_progress")
        || !job
            .get("conclusion")
            .is_some_and(serde_json::Value::is_null)
        || !job
            .get("labels")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|labels| {
                labels
                    .iter()
                    .any(|label| label.as_str() == Some(spec.runner_label))
            })
    {
        return fail("public enrolled job/runner differs from live hosted producer");
    }
    let approval_bytes = crate::private_protected_readback::read_protected_raw_case_file(
        Path::new("/etc/memcordon/release-trust/final-public-preparation.v2.json"),
    )?;
    if hash_bytes(&approval_bytes) != intent.preparation_policy_sha256 {
        return fail("public preparation approval file differs from producer pin");
    }
    let approval: ApprovedPublicPreparationPolicyV2 =
        crate::private_observer_session::strict_json(&approval_bytes, 256 * 1024)?;
    crate::private_public_preparation::validate_public_preparation_approval(
        &intent.suite,
        &approval,
    )?;
    let probe = crate::private_probe_bundle::verify_probe_bundle(intent.probe.clone())?;
    let (mut host, mut context, generation, mut generation_raw) =
        observe_generation(root, &intent, 0)?;
    let mut generation_host_bytes = generation_raw
        .get("installed/generations/0/host.json")
        .ok_or_else(|| CiError::Message("public actual generation host source absent".into()))?
        .clone();
    let btf_bytes = crate::private_observer_session::read_bounded_file(
        Path::new("/sys/kernel/btf/vmlinux"),
        64 * 1024 * 1024,
    )?;
    let btf = hash_bytes(&btf_bytes);
    let image_path = std::env::current_exe()?;
    let image_bytes = read_pinned_image(&image_path, &approval.preparer_image_sha256)?;
    let image_sha = hash_bytes(&image_bytes);
    if image_sha != approval.preparer_image_sha256 {
        return fail("live public supervisor image differs from independent preparation approval");
    }
    generation_raw.insert("observer/btf.raw".into(), btf_bytes);
    generation_raw.insert("observer/supervisor-image.raw".into(), image_bytes);
    let descriptor = ObserverSessionDescriptorV1 {
        schema_version: 1,
        session_nonce: String::new(),
        subject: intent.suite.observer_subject.clone(),
        enrolled_host: intent.enrolled_host.clone(),
        boot_id: host.boot_id().into(),
        kernel_btf_sha256: btf.clone(),
        observer_executable_sha256: image_sha,
        generations: vec![generation],
        intervals: Vec::new(),
    };
    let transport = AuthenticatedCustodianTransportV1::connect(&intent.custody_policy)?;
    let mut journal = PublicObserverProducerV1::begin(intent.suite.clone(), descriptor, transport)?;
    let mut prepared_generation = journal.current_generation()?;
    let reader = observe_live_kernel_subject(std::process::id())?;
    let mut service = observe_installed_observer_subject(InstalledObserverRoleV1::SealedService)?;
    let mut broker =
        crate::private_kernel_observer::activate_installed_network_broker_for_observation()?;
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")?;
    let expected =
        |key: DiagnosticSha256,
         control: bool,
         host: &crate::private_final_install::FinalHostReadbackV1,
         service: &crate::private_kernel_observer::LiveKernelSubjectV1,
         broker: &crate::private_kernel_observer::LiveKernelSubjectV1| {
            ExpectedKernelAdapterV1 {
                boot_id: host.boot_id().into(),
                kernel_release: release.trim().into(),
                btf_sha256: btf.clone(),
                probe_map_sha256: probe.attestation_digest(),
                result_key: key,
                coordinator_pid: if control { reader.pid } else { service.pid },
                coordinator_start_time: 0,
                coordinator_start_ticks: if control {
                    reader.start_ticks
                } else {
                    service.start_ticks
                },
                cgroup_inode: if control {
                    reader.cgroup_inode
                } else {
                    service.cgroup_inode
                },
                broker_pid: broker.pid,
                broker_start_ticks: broker.start_ticks,
                broker_cgroup_inode: broker.cgroup_inode,
            }
        };
    let abi = match target {
        "x86_64-unknown-linux-gnu" => {
            memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2::X86_64LinuxGnu
        }
        "aarch64-unknown-linux-gnu" => {
            memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2::Aarch64LinuxGnu
        }
        _ => return fail("public producer requires GNU native ABI"),
    };
    let mut pending_generation = Some(generation_raw);
    let mut historical_positives = Vec::new();
    let mut historical_e0 = None;
    // These are real ordinary public invocations, not selector projections.
    // Composite and historical orchestration must join their own intervals;
    // they are never counted by this loop or by its raw transport.
    for generation_number in 0..=1 {
        if generation_number == 1 {
            let upgrade_bytes = crate::private_protected_readback::read_protected_raw_case_file(
                &intent.upgrade_intent_path,
            )?;
            if hash_bytes(&upgrade_bytes) != intent.upgrade_intent_sha256 {
                return fail("same-A upgrade intent differs from independent static pin");
            }
            let upgrade: serde_json::Value =
                crate::private_observer_session::strict_json(&upgrade_bytes, 16 * 1024)?;
            for (field, digest) in [
                ("archive_sha256", &intent.suite.archive_sha256),
                ("manifest_sha256", &intent.suite.manifest_sha256),
                ("qualification_sha256", &intent.suite.qualification_sha256),
                ("build_sha256", &intent.suite.observer_subject.build_sha256),
                (
                    "certificate_file_sha256",
                    &intent.suite.qualification_certificate_file_sha256,
                ),
                (
                    "certificate_canonical_sha256",
                    &intent.suite.qualification_certificate_payload_sha256,
                ),
            ] {
                if upgrade.get(field) != Some(&serde_json::to_value(digest)?) {
                    return fail(
                        "public upgrade changed independently approved same-A release pins",
                    );
                }
            }
            if upgrade
                .get("source_commit")
                .and_then(serde_json::Value::as_str)
                != Some(intent.suite.observer_subject.source_commit.as_str())
                || upgrade.get("target").and_then(serde_json::Value::as_str) != Some(target)
                || upgrade
                    .get("release_version")
                    .and_then(serde_json::Value::as_str)
                    != Some(intent.suite.observer_subject.release_version.as_str())
            {
                return fail("public same-A upgrade changed static release identity");
            }
            let prior_epoch = host.installation_epoch().clone();
            if std::fs::symlink_metadata(&intent.upgrade_archive_path)?.len()
                != intent.suite.archive_size
            {
                return fail("public same-A upgrade archive size differs from approved original A");
            }
            crate::private_final_install::upgrade_final_same_host(
                root,
                &intent.upgrade_intent_path,
                &intent.upgrade_archive_path,
                &prior_epoch,
            )?;
            let (new_host, new_context, new_generation, mut raw) =
                observe_generation(root, &intent, 1)?;
            if new_host.boot_id() != host.boot_id() || new_host.installation_epoch() == &prior_epoch
            {
                return fail("public upgrade did not observe distinct E1 on exact E0 boot");
            }
            prepared_generation = journal.observe_generation(new_generation)?;
            generation_host_bytes = raw
                .get("installed/generations/1/host.json")
                .ok_or_else(|| CiError::Message("public E1 original host source absent".into()))?
                .clone();
            raw.insert("historical/upgrade-intent.json".into(), upgrade_bytes);
            pending_generation = Some(raw);
            host = new_host;
            context = new_context;
            service = observe_installed_observer_subject(InstalledObserverRoleV1::SealedService)?;
            broker =
                crate::private_kernel_observer::activate_installed_network_broker_for_observation(
                )?;
        }
        for (ordinal, (input, scenario)) in intent
            .cases
            .iter()
            .zip(&intent.suite.scenarios)
            .enumerate()
            .filter(|(ordinal, _)| {
                if generation_number == 0 {
                    *ordinal == 4
                } else {
                    ![0, 20, 24].contains(ordinal)
                }
            })
        {
            let purpose = if generation_number == 0 {
                crate::private_kernel_replay::IntervalPurposeV1::Historical
            } else if scenario.selector == "private_tcp::dual_attempt_namespace_isolation" {
                crate::private_kernel_replay::IntervalPurposeV1::DualContinuous
            } else {
                crate::private_kernel_replay::IntervalPurposeV1::Ordinary
            };
            let case = journal.prepare_case(&scenario.selector, purpose, ordinal as u32)?;
            let template = crate::private_protected_readback::read_protected_raw_case_file(
                &input.contract_template_path,
            )?;
            let fixture = read_pinned_image(&input.fixture_path, &scenario.fixture_sha256)?;
            let parent = std::fs::symlink_metadata(&input.report_directory)?;
            if !parent.is_dir()
                || parent.uid() != intent.suite.public_uid
                || parent.mode() & 0o7777 != 0o700
            {
                return fail(
                    "static public report directory is not the exact nonroot private directory",
                );
            }
            let report_path = input
                .report_directory
                .join(String::from(case.key.clone()))
                .with_extension("json");
            let inputs = crate::private_public_preparation::prepare_public_contract_inputs(
                &intent.suite,
                &prepared_generation,
                &approval,
                &scenario.selector,
                if generation_number == 0 {
                    PublicPreparedRoleV2::HistoricalE0
                } else {
                    PublicPreparedRoleV2::Ordinary
                },
                &template,
                &context.policy_epoch,
                |record| {
                    let entry = serde_json::json!({"selector":record.selector,"challenge":hex::encode(record.challenge),"contract_path":record.contract_path,"contract_sha256":record.contract_file_sha256});
                    let historical = if generation_number == 0 {
                        let mut entry = entry.clone();
                        entry["e0_installation_epoch_sha256"] =
                            serde_json::to_value(&record.installation_epoch)?;
                        entry["e0_h1_receipt_sha256"] =
                            serde_json::to_value(&record.active_h1_receipt_sha256)?;
                        entry
                    } else {
                        serde_json::Value::Null
                    };
                    crate::private_observer_session::canonical_bytes(
                        &serde_json::json!({"schema_version":1,"source_commit":intent.suite.observer_subject.source_commit,"target":target,"manifest_sha256":intent.suite.manifest_sha256,"qualification_sha256":intent.suite.qualification_sha256,"public_cli_sha256":intent.suite.public_cli_sha256,"public_uid":intent.suite.public_uid,"public_gid":intent.suite.public_gid,"historical_e0":historical,"historical_spoof":null,"policy":null,"cases":if generation_number==0 {Vec::<serde_json::Value>::new()}else{vec![entry]}}),
                    )
                },
            )?;
            crate::private_public_preparation::persist_prepared_public_inputs(&inputs)?;
            if inputs.record.challenge != case.challenge || inputs.record.result_key != case.key {
                return fail("public prepared source and controller case recipes differ");
            }
            let prefix = if generation_number == 0 {
                PathBuf::from("historical/e0")
            } else {
                Path::new("cases").join(ordinal.to_string())
            };
            let challenge = hex::encode(case.challenge);
            let expected_report = crate::private_public_v2::ExpectedPublicV2Readback {
                source_commit: &intent.suite.observer_subject.source_commit,
                native_abi: abi,
                archive_sha256: &intent.suite.archive_sha256,
                runtime_manifest_sha256: &intent.suite.manifest_sha256,
                qualification_sha256: &intent.suite.qualification_sha256,
                host_receipt_sha256: host.active_h1_receipt_sha256(),
                report_owner_uid: intent.suite.public_uid,
                outcome: if scenario.selector == "private_tcp::frontend_loss_retired" {
                    crate::private_public_v2::ExpectedPublicV2Outcome::FrontendLost
                } else {
                    crate::private_public_v2::ExpectedPublicV2Outcome::Exited(0)
                },
            };
            let (mut observed, detached) = run_public_journal_interval(
                &mut journal,
                &probe,
                &case,
                expected(case.key.clone(), true, &host, &service, &broker),
                expected(case.key.clone(), false, &host, &service, &broker),
                |journal| {
                    if let Some(raw) = pending_generation.take() {
                        for (path, bytes) in raw {
                            journal.append(path, Kind::Installed, bytes)?;
                        }
                        if generation_number == 0 {
                            journal.append(
                                "installed/static-suite-intent.json".into(),
                                Kind::Installed,
                                crate::private_observer_session::canonical_bytes(&intent.suite)?,
                            )?;
                        }
                    }
                    journal.append(
                        prefix.join("host.json").to_string_lossy().into_owned(),
                        Kind::Installed,
                        generation_host_bytes.clone(),
                    )?;
                    journal.append(
                        prefix
                            .join("prepared-admission.json")
                            .to_string_lossy()
                            .into_owned(),
                        Kind::Request,
                        inputs.admission_bytes.clone(),
                    )?;
                    journal.append(
                        prefix.join("contract.json").to_string_lossy().into_owned(),
                        Kind::Request,
                        inputs.contract_bytes.clone(),
                    )?;
                    journal.append(
                        prefix.join("fixture.raw").to_string_lossy().into_owned(),
                        Kind::Case,
                        fixture.clone(),
                    )?;
                    crate::private_public_dispatch::run_installed_public_source_case(
                        root,
                        &scenario.selector,
                        &challenge,
                        Path::new("/usr/bin/memcordon"),
                        &intent.suite.public_cli_sha256,
                        Path::new(&inputs.record.contract_path),
                        &report_path,
                        &input.fixture_path,
                        None,
                        None,
                        &input.report_directory,
                        intent.suite.public_uid,
                        intent.suite.public_gid,
                        Duration::from_secs(120),
                        &expected_report,
                        &prefix,
                    )
                },
            )?;
            if let Some(raw) = &detached.host_sources {
                observed
                    .live_samples
                    .insert("host-continuity.v1.bin".into(), raw.clone());
            }
            let (provider_record, provider_leaves) =
                crate::private_public_dispatch::read_original_public_provider_sources(
                    &scenario.selector,
                    &challenge,
                    &case.key,
                )?;
            // Dedicated Unix/worker/fault/dual protocols retain their original
            // sources below; they require their own source constructors. The
            // generic/TCP constructor never treats a missing special payload
            // as an empty response or as completed selector evidence.
            {
                for (path, kind, bytes) in
                    crate::private_public_source_facts::record_public_common_sources(
                        &intent.suite,
                        journal.descriptor(),
                        &inputs.admission_bytes,
                        &case,
                        &prefix,
                        target,
                        scenario.recipe.port,
                        &observed,
                        &detached.interval,
                        &provider_record,
                        &provider_leaves,
                    )?
                {
                    journal.append(path, kind, bytes)?;
                }
            }
            {
                let provider =
                    crate::private_public_dispatch::parse_structural_provider_case_from_leaves(
                        &provider_record,
                        &provider_leaves,
                    )?;
                let result = crate::private_public_dispatch::compose_static_final_public_case_v3(
                    &case.selector,
                    case.challenge,
                    &intent.suite,
                    &host,
                    &observed,
                    &provider,
                    &detached.interval,
                )?;
                journal.append(
                    prefix.join("result.json").to_string_lossy().into_owned(),
                    Kind::Case,
                    result,
                )?;
            }
            if generation_number == 0 {
                let provider =
                    crate::private_public_dispatch::parse_structural_provider_case_from_leaves(
                        &provider_record,
                        &provider_leaves,
                    )?;
                let [attempt] = provider.attempts.as_slice() else {
                    return fail("historical E0 did not retain one actual positive attempt");
                };
                if attempt.terminal_bytes.is_none() || attempt.cleanup_bytes.is_none() {
                    return fail("historical E0 source lacks actual terminal/retirement");
                }
                historical_e0 = Some((
                    case.selector.clone(),
                    case.challenge,
                    case.argv.clone(),
                    case.key.clone(),
                    attempt.request_bytes.clone(),
                    host.installation_epoch().clone(),
                    host.active_h1_receipt_sha256().clone(),
                ));
            }
            let history_provider = if generation_number == 0 || ordinal == 16 {
                Some(
                    crate::private_public_dispatch::parse_structural_provider_case_from_leaves(
                        &provider_record,
                        &provider_leaves,
                    )?,
                )
            } else {
                None
            };
            journal.append(
                prefix
                    .join("provider/record.json")
                    .to_string_lossy()
                    .into_owned(),
                Kind::Case,
                provider_record,
            )?;
            for (name, bytes) in provider_leaves {
                journal.append(
                    prefix
                        .join("provider/raw")
                        .join(name)
                        .to_string_lossy()
                        .into_owned(),
                    Kind::Case,
                    bytes,
                )?;
            }
            let mut samples = vec![
                prefix
                    .join("prepared-admission.json")
                    .to_string_lossy()
                    .into_owned(),
            ];
            for (name, bytes) in observed.live_samples {
                let path = prefix
                    .join("samples")
                    .join(name)
                    .to_string_lossy()
                    .into_owned();
                journal.append(path.clone(), Kind::LiveSample, bytes)?;
                samples.push(path);
            }
            journal.append(
                prefix.join("cli/stdio.bin").to_string_lossy().into_owned(),
                Kind::Stdio,
                observed.stdio_bytes,
            )?;
            if let Some(bytes) = observed.report_bytes {
                journal.append(
                    prefix
                        .join("cli/report.json")
                        .to_string_lossy()
                        .into_owned(),
                    Kind::Report,
                    bytes,
                )?;
            }
            let timing = detached
                .interval
                .observation_timing()
                .ok_or_else(|| CiError::Message("public detached actual timing absent".into()))?;
            journal.retain_interval_with_record(
                &case,
                &detached.interval,
                vec![detached.controls_path],
                samples,
                timing.armed_monotonic_ns,
                timing.operation_end_monotonic_ns,
                timing.detached_monotonic_ns,
                Some(prefix.join("interval.json").to_string_lossy().into_owned()),
            )?;
            if let Some(provider) = history_provider {
                let clock = detached.interval.original_clock().ok_or_else(|| {
                    CiError::Message("historical positive original calibrated reader absent".into())
                })?;
                let join = crate::private_public_specialist_replay::target_join(
                    &provider,
                    &detached.interval,
                    clock,
                )?;
                historical_positives.push(LivePublicHistoricalPositiveV1 {
                    selector: case.selector.clone(),
                    challenge: challenge.clone(),
                    host: crate::private_final_install::FinalHostReadbackV1::parse_bounded(
                        &generation_host_bytes,
                    )?,
                    provider,
                    join,
                    interval: detached.interval,
                });
            }
        }
    }
    crate::private_public_abi_live::run_public_abi_sources(
        root,
        target,
        &intent,
        &approval,
        &mut journal,
        &probe,
        &host,
        &generation_host_bytes,
        &context,
        &prepared_generation,
        &service,
        &broker,
    )?;
    crate::private_public_reuse_live::run_public_reuse_sources(
        root,
        target,
        &intent,
        &approval,
        &mut journal,
        &probe,
        &host,
        &context,
        &prepared_generation,
        &service,
        &broker,
    )?;
    crate::private_public_policy_live::run_public_policy_sources(
        root,
        target,
        &intent,
        &approval,
        &mut journal,
        &probe,
        &host,
        &context,
        &prepared_generation,
        &service,
        &broker,
    )?;
    let (selector, e0_challenge, argv, key, original_request, e0_epoch, e0_h1) = historical_e0
        .ok_or_else(|| {
            CiError::Message("public actual E0 source absent before stale replay".into())
        })?;
    let mut replay_case = journal.prepare_case(
        &selector,
        crate::private_kernel_replay::IntervalPurposeV1::Historical,
        25,
    )?;
    replay_case.challenge = e0_challenge;
    replay_case.argv = argv;
    replay_case.key = key.clone();
    replay_case.interval_id.logical_case_key = key.clone();
    let challenge = hex::encode(e0_challenge);
    let mut replay_sources = None;
    let (_, detached) = run_public_journal_interval(
        &mut journal,
        &probe,
        &replay_case,
        expected(key.clone(), true, &host, &service, &broker),
        expected(key.clone(), false, &host, &service, &broker),
        |journal| {
            let output = crate::command::CommandSpec::new(
                "/usr/libexec/memcordon-sealed-agent",
                root,
                Duration::from_secs(30),
            )
            .remove_github_token()
            .args([
                "package",
                "replay-public-release-epoch",
                "--selector",
                selector.as_str(),
                "--challenge",
                challenge.as_str(),
                "--json",
            ])
            .run()?;
            let directory = Path::new("/var/lib/memcordon/sealed/private-public-cases")
                .join(String::from(key.clone()));
            if !matches!(std::fs::symlink_metadata(directory.join("epoch-replay.pending")),Err(error) if error.kind()==std::io::ErrorKind::NotFound)
            {
                return fail("public historical replay left a real pending reservation");
            }
            let record = crate::private_protected_readback::read_protected_raw_case_file(
                &directory.join("epoch-replay.json"),
            )?;
            let rejection = crate::private_protected_readback::read_protected_raw_case_file(
                &directory.join("epoch-replay-rejection.bin"),
            )?;
            if output.strip_suffix(b"\n") != Some(record.as_slice()) {
                return fail("public historical replay command differs from immutable raw record");
            }
            crate::private_public_dispatch::validate_historical_public_epoch_replay_v1(
                &record,
                &rejection,
                &crate::private_public_dispatch::ExpectedHistoricalPublicEpochReplayV1 {
                    selector: &selector,
                    result_key: &key,
                    original_request_bytes: &original_request,
                    e0_installation_epoch_sha256: &e0_epoch,
                    e0_h1_receipt_sha256: &e0_h1,
                    e1_installation_epoch_sha256: host.installation_epoch(),
                    e1_h1_receipt_sha256: host.active_h1_receipt_sha256(),
                },
            )?;
            replay_sources = Some((record.clone(), rejection.clone(), output.clone()));
            for (name, bytes) in [
                ("record.json", record),
                ("rejection.bin", rejection),
                ("request.bin", original_request.clone()),
                ("stdout.bin", output),
            ] {
                journal.append(
                    Path::new("historical/replay")
                        .join(name)
                        .to_string_lossy()
                        .into_owned(),
                    Kind::Case,
                    bytes,
                )?;
            }
            Ok(())
        },
    )?;
    detached.interval.verify_no_allocation(&key)?;
    let timing = detached
        .interval
        .observation_timing()
        .ok_or_else(|| CiError::Message("public stale replay actual timing absent".into()))?;
    journal.retain_interval_with_record(
        &replay_case,
        &detached.interval,
        vec![detached.controls_path],
        Vec::new(),
        timing.armed_monotonic_ns,
        timing.operation_end_monotonic_ns,
        timing.detached_monotonic_ns,
        Some("historical/replay/interval.json".into()),
    )?;
    let spoof_case = journal.prepare_case(
        "private_tcp::caller_identity_and_epoch_bound",
        crate::private_kernel_replay::IntervalPurposeV1::CallerSpoof,
        0,
    )?;
    let spoof_input = &intent.cases[4];
    let spoof_parent = &intent.historical_spoof_report_directory;
    let spoof_meta = std::fs::symlink_metadata(spoof_parent)?;
    if !spoof_meta.is_dir()
        || spoof_meta.uid() != intent.suite.historical_spoof_uid
        || spoof_meta.mode() & 0o7777 != 0o700
    {
        return fail(
            "public historical spoof needs independently provisioned nonroot private report directory",
        );
    }
    let template = crate::private_protected_readback::read_protected_raw_case_file(
        &spoof_input.contract_template_path,
    )?;
    let inputs = crate::private_public_preparation::prepare_public_contract_inputs(
        &intent.suite,
        &prepared_generation,
        &approval,
        &spoof_case.selector,
        PublicPreparedRoleV2::CallerSpoof,
        &template,
        &context.policy_epoch,
        |record| {
            crate::private_observer_session::canonical_bytes(
                &serde_json::json!({"schema_version":1,"source_commit":intent.suite.observer_subject.source_commit,
                "target":target,"manifest_sha256":intent.suite.manifest_sha256,"qualification_sha256":intent.suite.qualification_sha256,
                "public_cli_sha256":intent.suite.public_cli_sha256,"public_uid":intent.suite.public_uid,"public_gid":intent.suite.public_gid,
                "historical_e0":null,"policy":null,"cases":[],"historical_spoof":{"selector":record.selector,"challenge":hex::encode(record.challenge),
                    "contract_path":record.contract_path,"contract_sha256":record.contract_file_sha256,
                    "unauthorized_uid":intent.suite.historical_spoof_uid,"unauthorized_gid":intent.suite.historical_spoof_gid}}),
            )
        },
    )?;
    if inputs.record.result_key != spoof_case.key || inputs.record.challenge != spoof_case.challenge
    {
        return fail("public historical spoof preparation changed controller recipe");
    }
    crate::private_public_preparation::persist_prepared_public_inputs(&inputs)?;
    let spoof_challenge = hex::encode(spoof_case.challenge);
    let spoof_report = spoof_parent
        .join(String::from(spoof_case.key.clone()))
        .with_extension("json");
    let spoof_expected = crate::private_public_v2::ExpectedPublicV2Readback {
        source_commit: &intent.suite.observer_subject.source_commit,
        native_abi: abi,
        archive_sha256: &intent.suite.archive_sha256,
        runtime_manifest_sha256: &intent.suite.manifest_sha256,
        qualification_sha256: &intent.suite.qualification_sha256,
        host_receipt_sha256: host.active_h1_receipt_sha256(),
        report_owner_uid: intent.suite.historical_spoof_uid,
        outcome: crate::private_public_v2::ExpectedPublicV2Outcome::PreallocationRejected,
    };
    let (spoof_observed, spoof_detached) = run_public_journal_interval(
        &mut journal,
        &probe,
        &spoof_case,
        expected(spoof_case.key.clone(), true, &host, &service, &broker),
        expected(spoof_case.key.clone(), false, &host, &service, &broker),
        |journal| {
            journal.append(
                "historical/spoof/prepared-admission.json".into(),
                Kind::Request,
                inputs.admission_bytes.clone(),
            )?;
            journal.append(
                "historical/spoof/contract.json".into(),
                Kind::Request,
                inputs.contract_bytes.clone(),
            )?;
            crate::private_public_dispatch::run_installed_public_source_case(
                root,
                &spoof_case.selector,
                &spoof_challenge,
                Path::new("/usr/bin/memcordon"),
                &intent.suite.public_cli_sha256,
                Path::new(&inputs.record.contract_path),
                &spoof_report,
                &spoof_input.fixture_path,
                None,
                None,
                spoof_parent,
                intent.suite.historical_spoof_uid,
                intent.suite.historical_spoof_gid,
                Duration::from_secs(120),
                &spoof_expected,
                Path::new("historical/spoof"),
            )
        },
    )?;
    spoof_detached
        .interval
        .verify_no_allocation(&spoof_case.key)?;
    let spoof_directory = Path::new("/var/lib/memcordon/sealed/private-public-cases")
        .join(String::from(spoof_case.key.clone()));
    let spoof_stdout = crate::command::CommandSpec::new(
        "/usr/libexec/memcordon-sealed-agent",
        root,
        Duration::from_secs(30),
    )
    .remove_github_token()
    .args([
        "package",
        "verify-public-spoof",
        "--selector",
        spoof_case.selector.as_str(),
        "--challenge",
        spoof_challenge.as_str(),
        "--json",
    ])
    .run()?;
    let spoof_actor = spoof_observed.process.linux_child.as_ref().ok_or_else(|| {
        CiError::Message("public spoof actual supervised caller identity absent".into())
    })?;
    let spoof_pid = spoof_actor.pid;
    let spoof_start = spoof_actor.start_time_ticks;
    let mut spoof_sources = BTreeMap::new();
    let mut spoof_samples = vec!["historical/spoof/prepared-admission.json".into()];
    for (name, bytes) in spoof_observed.live_samples {
        let path = Path::new("historical/spoof/samples")
            .join(name)
            .to_string_lossy()
            .into_owned();
        journal.append(path.clone(), Kind::LiveSample, bytes)?;
        spoof_samples.push(path);
    }
    for (name, native_name) in [
        ("record.json", "spoof.json"),
        ("request.bin", "spoof-request.bin"),
        ("rejection.bin", "spoof-rejection.bin"),
        ("grant-decision.json", "grant-decision.json"),
    ] {
        let bytes = crate::private_protected_readback::read_protected_raw_case_file(
            &spoof_directory.join(native_name),
        )?;
        if name == "record.json" && spoof_stdout.strip_suffix(b"\n") != Some(bytes.as_slice()) {
            return fail("public spoof root readback differs from immutable original");
        }
        if name == "request.bin" && bytes != inputs.contract_bytes {
            return fail(
                "public spoof original authenticated request differs from prepared contract",
            );
        }
        spoof_sources.insert(name.to_owned(), bytes.clone());
        journal.append(
            Path::new("historical/spoof")
                .join(name)
                .to_string_lossy()
                .into_owned(),
            Kind::Case,
            bytes,
        )?;
    }
    journal.append(
        "historical/spoof/stdout.bin".into(),
        Kind::Stdio,
        spoof_stdout.clone(),
    )?;
    journal.append(
        "historical/spoof/cli/stdio.bin".into(),
        Kind::Stdio,
        spoof_observed.stdio_bytes,
    )?;
    if let Some(bytes) = spoof_observed.report_bytes {
        journal.append(
            "historical/spoof/cli/report.json".into(),
            Kind::Report,
            bytes,
        )?;
    }
    let timing = spoof_detached
        .interval
        .observation_timing()
        .ok_or_else(|| CiError::Message("public spoof actual timing absent".into()))?;
    journal.retain_interval_with_record(
        &spoof_case,
        &spoof_detached.interval,
        vec![spoof_detached.controls_path],
        spoof_samples,
        timing.armed_monotonic_ns,
        timing.operation_end_monotonic_ns,
        timing.detached_monotonic_ns,
        Some("historical/spoof/interval.json".into()),
    )?;
    let spoof_record: crate::private_observer_session::ObserverIntervalRecordV1 =
        crate::private_observer_session::strict_json(
            journal.acknowledged_leaf("historical/spoof/interval.json")?,
            64 * 1024,
        )?;
    let spoof_capture = crate::private_kernel_replay::parse_capture_v2_with_budget(
        spoof_detached.interval.capture_bytes()?,
        &spoof_case.key,
        crate::private_kernel_replay::CaptureStageV2::FinalPublic,
    )?;
    crate::private_public_caller_replay::validate_public_caller_sources(
        &intent.suite,
        journal.descriptor(),
        &spoof_record,
        spoof_capture.events(),
        spoof_detached.interval.clock_inputs().ok_or_else(|| {
            CiError::Message("public caller original reader calibration absent".into())
        })?,
        |path| journal.acknowledged_leaf(path).map(ToOwned::to_owned),
    )?;
    let [e0, e1] = historical_positives.as_slice() else {
        return fail("public history lacks exact E0 and E1 original positive intervals");
    };
    let (replay_record, replay_rejection, replay_stdout) = replay_sources
        .ok_or_else(|| CiError::Message("public original stale replay sources absent".into()))?;
    use crate::private_public_epoch_join::{
        ExpectedPublicEpochTransitionV1, ExpectedPublicSpoofV1, PublicEpochPositiveV1,
    };
    let joined = crate::private_public_epoch_join::join_public_epoch_transition_v1(
        &ExpectedPublicEpochTransitionV1 {
            e0: PublicEpochPositiveV1 {
                selector: &e0.selector,
                challenge: &e0.challenge,
                host: &e0.host,
                provider: &e0.provider,
                kernel_join: &e0.join,
                interval: &e0.interval,
            },
            e1: PublicEpochPositiveV1 {
                selector: &e1.selector,
                challenge: &e1.challenge,
                host: &e1.host,
                provider: &e1.provider,
                kernel_join: &e1.join,
                interval: &e1.interval,
            },
            protected_archive_sha256: &intent.suite.archive_sha256,
            upgrade_archive_sha256: &intent.suite.archive_sha256,
            replay_record_bytes: &replay_record,
            replay_rejection_bytes: &replay_rejection,
            replay_stdout: &replay_stdout,
            replay_interval: &detached.interval,
            spoof_record_bytes: &spoof_sources["record.json"],
            spoof_stdout: &spoof_stdout,
            spoof_request_bytes: &spoof_sources["request.bin"],
            spoof_rejection_bytes: &spoof_sources["rejection.bin"],
            spoof_expected: ExpectedPublicSpoofV1 {
                selector: &spoof_case.selector,
                challenge: &spoof_challenge,
                result_key: &spoof_case.key,
                authorized_uid: intent.suite.public_uid,
                unauthorized_uid: intent.suite.historical_spoof_uid,
                unauthorized_gid: intent.suite.historical_spoof_gid,
                registered_peer_pid: spoof_pid,
                registered_peer_start_ticks: spoof_start,
                installation_epoch: host.installation_epoch(),
                active_h1_receipt_sha256: host.active_h1_receipt_sha256(),
                request_bytes: &spoof_sources["request.bin"],
                grant_decision_bytes: &spoof_sources["grant-decision.json"],
                rejection_code: "MCSEALED-PRIVATE-PUBLIC-GRANT-REJECTED",
            },
            spoof_interval: &spoof_detached.interval,
        },
    )?;
    journal.append_representation(
        "historical/epoch-transition.json".into(),
        Kind::Case,
        joined.transcript_bytes().to_vec(),
    )?;
    let caller_facts = crate::private_public_caller_replay::assemble_public_caller_facts(
        journal.acknowledged_leaf("cases/4/common-facts-source.json")?,
        target,
    )?;
    journal.append_representation("cases/4/facts.json".into(), Kind::Case, caller_facts)?;
    let cleanup = journal.observed_cleanup_inventory()?;
    let sealed = journal.seal(
        cleanup,
        memcordon_platform::test_support::private_observer_monotonic_ns()?,
    )?;
    crate::private_public_completion::verify_public_live_all25(&intent.suite, &sealed.origin)?;
    let target_id = match target {
        "x86_64-unknown-linux-gnu" => "linux-x64",
        "aarch64-unknown-linux-gnu" => "linux-arm64",
        _ => return fail("public raw export target differs"),
    };
    let mut output_parent = root.to_path_buf();
    for component in ["target", "ci", "reports", "private-public-raw-v1"] {
        output_parent.push(component);
        match std::fs::symlink_metadata(&output_parent) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => (),
            Ok(_) => return fail("public output parent is not a normal directory"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&output_parent)?
            }
            Err(error) => return Err(error.into()),
        }
    }
    sealed.export_files(&output_parent.join(target_id))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn run(_root: &Path, _target: &str, _path: &Path) -> Result<()> {
    fail("static installed public production requires native GNU Linux")
}
