//! Windows producer artifacts. Independent acceptance remains in the verifier.
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use std::path::Path;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct WindowsAdapterContext {
    pub identity: crate::consumer_readiness_ledger::SourceIdentity,
    pub product: memcordon_readiness_verifier::ProductKey,
    pub lease_id: String,
    pub destination: PathBuf,
    pub fixture_source: crate::windows_installed_cases::SelectedArtifact,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsNormalizedRows {
    pub records: Vec<memcordon_readiness_verifier::CaseRecord>,
    pub artifacts: Vec<memcordon_readiness_verifier::Artifact>,
}

#[derive(Clone, Debug)]
pub struct WindowsComponentAdapterContext {
    pub identity: crate::consumer_readiness_ledger::SourceIdentity,
    pub destination: PathBuf,
    pub fixture_source: crate::windows_installed_cases::SelectedArtifact,
}

/// Retains observed rows after an installed lifetime returns an error. It reads
/// the actual persisted assessment and never converts absent executions into
/// successful rows or changes their original producer identity.
#[cfg(windows)]
pub fn normalize_retained(
    context: &WindowsAdapterContext,
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
) -> crate::Result<WindowsNormalizedRows> {
    use crate::windows_consumer_readiness::native::read;
    let channel_matches = match config.channel {
        crate::windows_causal_acceptance::InstalledChannel::NativeBundle => matches!(
            context.product.channel.as_str(),
            "candidate-native" | "public-native"
        ),
        crate::windows_causal_acceptance::InstalledChannel::CargoPackage => matches!(
            context.product.channel.as_str(),
            "candidate-cargo" | "public-cargo"
        ),
    };
    if config.target != context.product.target
        || config.source_commit != context.identity.source_commit
        || config.version != context.identity.version
        || !channel_matches
        || context.lease_id.is_empty()
        || !config.output_directory.is_absolute()
        || !context.destination.is_absolute()
    {
        return Err(crate::CiError::Message(
            "retained Windows selected configuration differs from original source/cell/lease"
                .into(),
        ));
    }
    let path = config.output_directory.join("installed-assessment.json");
    let mut output = WindowsNormalizedRows {
        records: Vec::new(),
        artifacts: Vec::new(),
    };
    if path.try_exists()? {
        let assessment: crate::windows_installed_cases::InstalledWindowsAssessment =
            serde_json::from_slice(&read(&path, 16 * 1024 * 1024)?)?;
        if assessment.channel != config.channel
            || assessment.target != config.target
            || assessment.source_commit != config.source_commit
            || assessment.version != config.version
            || serde_json::to_vec(&assessment.artifacts)? != serde_json::to_vec(&config.artifacts)?
        {
            return Err(crate::CiError::Message(
                "retained Windows assessment differs from actual selected configuration".into(),
            ));
        }
        if !assessment.positive_cases.is_empty() {
            let rows = normalize_positive(
                context,
                config,
                &config.output_directory.join("windows-readiness-input.json"),
                &assessment.positive_cases,
            )?;
            output.records.extend(rows.records);
            output.artifacts.extend(rows.artifacts);
        }
        if !assessment.loss_cases.is_empty() {
            let rows = normalize_loss(context, config, &assessment.loss_cases)?;
            output.records.extend(rows.records);
            output.artifacts.extend(rows.artifacts);
        }
        if !assessment.capacity_cases.is_empty() {
            let rows = normalize_capacity(
                context,
                config,
                &config.output_directory.join("windows-readiness-input.json"),
                &assessment.capacity_cases,
            )?;
            output.records.extend(rows.records);
            output.artifacts.extend(rows.artifacts);
        }
        if !assessment.refusal_cases.is_empty() {
            let rows = normalize_refusals(context, config, &assessment.refusal_cases)?;
            output.records.extend(rows.records);
            output.artifacts.extend(rows.artifacts);
        }
    }
    let prefix = PathBuf::from(&context.product.target).join(&context.product.channel);
    Bundle::relative(&prefix)?;
    let mut bundle = Bundle {
        destination: context.destination.clone(),
        prefix,
        artifacts: Vec::new(),
        held: Vec::new(),
    };
    if config.output_directory.is_dir() {
        bundle.copy_directory(
            &config.output_directory,
            Path::new("windows-retained-lifetime"),
        )?;
    }
    output.artifacts.extend(bundle.artifacts);
    let mut keys = std::collections::BTreeSet::new();
    if output
        .records
        .iter()
        .any(|record| !keys.insert(record.key.clone()))
    {
        return Err(crate::CiError::Message(
            "retained Windows assessment duplicates an actual finite row".into(),
        ));
    }
    Ok(output)
}

/// Native custody for a selected executable or controller record. Retain this
/// owner across measurement and the operation that consumes the named path.
#[cfg(windows)]
pub struct HeldWindowsArtifact {
    pub bytes: Vec<u8>,
    pub sha256: String,
    _file: std::fs::File,
    _ancestors: Vec<std::fs::File>,
}

/// Compare the named leaf and every retained directory to the original native
/// handles; equal bytes alone do not authorize replacement of a custody record.
#[cfg(windows)]
pub fn verify_named_artifact(held: &HeldWindowsArtifact, path: &Path) -> crate::Result<()> {
    use std::{fs::OpenOptions, io::Read, os::windows::fs::OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};
    let parent = path
        .parent()
        .ok_or_else(|| crate::CiError::Message("held artifact parent absent".into()))?;
    let ancestors = hold_ancestors(parent)?;
    if ancestors.len() != held._ancestors.len() {
        return Err(crate::CiError::Message(
            "held artifact ancestor count changed".into(),
        ));
    }
    let ancestor_paths: Vec<_> = parent
        .ancestors()
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
        .collect();
    for ((before, current), ancestor) in held
        ._ancestors
        .iter()
        .zip(&ancestors)
        .zip(ancestor_paths.into_iter().rev())
    {
        if native_file_identity(before, true, ancestor)?
            != native_file_identity(current, true, ancestor)?
        {
            return Err(crate::CiError::Message(
                "held artifact named ancestor native identity changed".into(),
            ));
        }
    }
    let named = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let mut bytes = Vec::new();
    (&named)
        .take(held.bytes.len() as u64 + 1)
        .read_to_end(&mut bytes)?;
    if native_file_identity(&held._file, false, path)? != native_file_identity(&named, false, path)?
        || bytes != held.bytes
    {
        return Err(crate::CiError::Message(
            "held artifact named native identity or exact bytes changed".into(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub fn hold_artifact(
    path: &Path,
    expected: Option<&str>,
    maximum: u64,
) -> crate::Result<HeldWindowsArtifact> {
    use std::{fs::OpenOptions, io::Read, os::windows::fs::OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};
    if !path.is_absolute() || maximum > 512 * 1024 * 1024 {
        return Err(crate::CiError::Message(
            "Windows native artifact custody requires bounded absolute input".into(),
        ));
    }
    let ancestors = hold_ancestors(path.parent().ok_or_else(|| {
        crate::CiError::Message("Windows native artifact parent missing".into())
    })?)?;
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let identity = native_file_identity(&file, false, path)?;
    let mut bytes = Vec::new();
    (&file).take(maximum + 1).read_to_end(&mut bytes)?;
    let digest = crate::windows_causal_acceptance::sha256(&bytes);
    let named = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let mut named_bytes = Vec::new();
    (&named).take(maximum + 1).read_to_end(&mut named_bytes)?;
    if bytes.len() as u64 > maximum
        || file.metadata()?.len() != bytes.len() as u64
        || native_file_identity(&file, false, path)? != identity
        || native_file_identity(&named, false, path)? != identity
        || named_bytes != bytes
        || expected.is_some_and(|expected| expected != digest)
    {
        return Err(crate::CiError::Message(
            "Windows native artifact named custody or measured bytes differ".into(),
        ));
    }
    Ok(HeldWindowsArtifact {
        bytes,
        sha256: digest,
        _file: file,
        _ancestors: ancestors,
    })
}

#[cfg(windows)]
pub fn copy_owned_artifact(
    source: &Path,
    destination: &Path,
    expected: &str,
) -> crate::Result<HeldWindowsArtifact> {
    let source = hold_artifact(source, Some(expected), 512 * 1024 * 1024)?;
    let _ancestors = hold_ancestors(destination.parent().ok_or_else(|| {
        crate::CiError::Message("Windows owned artifact destination parent missing".into())
    })?)?;
    let _published = publish_receipt(destination, &source.bytes)?;
    hold_artifact(destination, Some(expected), 512 * 1024 * 1024)
}

/// Materialize actual Cargo output into independent receipt custody. The held
/// source may have Cargo aliases; no alias becomes an authoritative image.
#[cfg(windows)]
pub fn copy_compiler_artifact(
    source: &Path,
    build_root: &Path,
    destination: &Path,
    expected: &str,
) -> crate::Result<HeldWindowsArtifact> {
    use std::{
        fs::OpenOptions,
        io::Read,
        os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    };
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        GetFileInformationByHandle,
    };
    if !source.is_absolute()
        || !build_root.is_absolute()
        || !source.starts_with(build_root)
        || source == build_root
        || source
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        || source.strip_prefix(build_root).is_ok_and(|relative| {
            relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        })
    {
        return Err(crate::CiError::Message(
            "compiler artifact crosses original build root".into(),
        ));
    }
    let _source_ancestors = hold_ancestors(
        source
            .parent()
            .ok_or_else(|| crate::CiError::Message("compiler source parent absent".into()))?,
    )?;
    let open = || {
        OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(source)
    };
    let identity = |file: &std::fs::File| -> std::io::Result<(u32, u64, u32, u32, u64)> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: File owns the live handle and info is a valid sized output.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut info) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        crate::windows_receipt_identity::validate_compiler_source(
            source,
            info.dwFileAttributes,
            info.nNumberOfLinks,
        )?;
        Ok((
            info.dwVolumeSerialNumber,
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
            info.dwFileAttributes,
            info.nNumberOfLinks,
            (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
        ))
    };
    let file = open()?;
    let before = identity(&file)?;
    if before.4 == 0 || before.4 > 512 * 1024 * 1024 {
        return Err(crate::CiError::Message(
            "compiler source exceeds executable byte bound".into(),
        ));
    }
    let mut bytes = Vec::new();
    (&file)
        .take(512 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    let named = open()?;
    let mut named_bytes = Vec::new();
    (&named)
        .take(512 * 1024 * 1024 + 1)
        .read_to_end(&mut named_bytes)?;
    if before.4 != bytes.len() as u64
        || identity(&file)? != before
        || identity(&named)? != before
        || named_bytes != bytes
        || crate::windows_causal_acceptance::sha256(&bytes) != expected
    {
        return Err(crate::CiError::Message(
            "held compiler source identity, links or bytes changed".into(),
        ));
    }
    let _destination_ancestors =
        hold_ancestors(destination.parent().ok_or_else(|| {
            crate::CiError::Message("compiler destination parent absent".into())
        })?)?;
    let _published = publish_receipt(destination, &bytes)?;
    let copied = hold_artifact(destination, Some(expected), 512 * 1024 * 1024)?;
    if identity(&file)? != before || identity(&named)? != before {
        return Err(crate::CiError::Message(
            "compiler source changed during independent publication".into(),
        ));
    }
    Ok(copied)
}

#[cfg(windows)]
struct PublicInvocationProjection {
    path: String,
    association_sha256: String,
    arguments: Vec<Vec<u16>>,
    memory: String,
    deadline: String,
}

/// Unwraps only the two actual native readiness frontend helpers. The public
/// invocation remains the exact target vector and ordered public budget tokens.
#[cfg(windows)]
fn normalize_public_invocation(
    bundle: &mut Bundle,
    row: &Path,
    raw: &serde_json::Value,
    cli_sha256: &str,
) -> crate::Result<PublicInvocationProjection> {
    use memcordon_readiness_verifier::{NativeArguments, NativeEnvironment, NativeInvocation};
    use std::os::windows::ffi::OsStringExt;
    let mut argv: Vec<Vec<u16>> = serde_json::from_value(raw["argv_utf16"].clone())?;
    let program: Vec<u16> = serde_json::from_value(raw["program_utf16"].clone())?;
    let public_program: Vec<u16> = serde_json::from_value(raw["public_program_utf16"].clone())?;
    let wide = |text: &str| text.encode_utf16().collect::<Vec<_>>();
    if raw["environment_cleared"] != true || raw["public_executable_sha256"] != cli_sha256 {
        return Err(crate::CiError::Message(
            "actual public invocation differs from measured CLI or declared empty environment"
                .into(),
        ));
    }
    if program != public_program {
        let offset = if argv.first() == Some(&wide("consumer-readiness-windows"))
            && argv.get(1) == Some(&wide("restricted-frontend"))
        {
            2
        } else if argv.first() == Some(&wide("consumer-readiness-windows"))
            && argv.get(1) == Some(&wide("sentinel-frontend"))
        {
            3
        } else {
            return Err(crate::CiError::Message(
                "public invocation has an unknown native frontend wrapper".into(),
            ));
        };
        if argv.get(offset) != Some(&public_program) {
            return Err(crate::CiError::Message(
                "native helper did not invoke exact measured public frontend".into(),
            ));
        }
        argv.drain(..offset + 1);
    }
    let separator = argv
        .iter()
        .position(|argument| *argument == wide("--"))
        .ok_or_else(|| {
            crate::CiError::Message("actual public invocation omits target separator".into())
        })?;
    if separator < 2 || separator + 1 >= argv.len() {
        return Err(crate::CiError::Message(
            "actual public invocation omits budgets or target".into(),
        ));
    }
    let ascii = |value: &[u16]| -> crate::Result<String> {
        if value.is_empty() || value.iter().any(|unit| *unit > 127) {
            return Err(crate::CiError::Message(
                "actual public budget token is not bounded ASCII".into(),
            ));
        }
        String::from_utf16(value).map_err(|error| crate::CiError::Message(error.to_string()))
    };
    let memory = ascii(&argv[0])?;
    let deadline = ascii(&argv[1])?;
    let arguments = argv[separator + 1..].to_vec();
    let report = memcordon_core::InvocationReport {
        syntax: "plus-budgets-v1".into(),
        budget_tokens: vec![
            memcordon_core::BudgetTokenReport {
                kind: memcordon_core::BudgetKindReport::Memory,
                token: memory.clone(),
            },
            memcordon_core::BudgetTokenReport {
                kind: memcordon_core::BudgetKindReport::Time,
                token: deadline.clone(),
            },
        ],
        memory_token: Some(memory.clone()),
        deadline_token: Some(deadline.clone()),
        argv: arguments
            .iter()
            .map(|argument| {
                memcordon_core::NativeArgument::from_os(&std::ffi::OsString::from_wide(argument))
            })
            .collect(),
    };
    let association = crate::windows_causal_acceptance::sha256(&serde_json::to_vec(&report)?);
    let environment = serde_json::to_vec(&NativeEnvironment::WindowsUtf16(Vec::new()))?;
    let environment_path = bundle.retain(&row.join("environment.json"), &environment)?;
    let invocation = NativeInvocation {
        format: "memcordon.consumer-readiness.invocation".into(),
        revision: 1,
        arguments: NativeArguments::WindowsUtf16(arguments.clone()),
        executable_sha256: cli_sha256.into(),
        environment: environment_path,
        environment_sha256: crate::windows_causal_acceptance::sha256(&environment),
        association_sha256: association.clone(),
        budget_tokens: vec![
            memcordon_readiness_verifier::BudgetToken {
                kind: "memory".into(),
                token: memory.clone(),
            },
            memcordon_readiness_verifier::BudgetToken {
                kind: "time".into(),
                token: deadline.clone(),
            },
        ],
        memory_token: Some(memory.clone()),
        deadline_token: Some(deadline.clone()),
    };
    let path = bundle.retain(
        &row.join("invocation.json"),
        &serde_json::to_vec(&invocation)?,
    )?;
    Ok(PublicInvocationProjection {
        path,
        association_sha256: association,
        arguments,
        memory,
        deadline,
    })
}

/// Converts actual native Rust-harness captures into producer rows. The
/// separate verifier decodes the native receipt and decides acceptance.
#[cfg(windows)]
pub fn normalize_positive(
    context: &WindowsAdapterContext,
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    suite_path: &Path,
    observed: &[crate::windows_consumer_readiness::CaseAssessment],
) -> crate::Result<WindowsNormalizedRows> {
    use crate::windows_consumer_readiness::native::read;
    let suite: crate::windows_consumer_readiness::SuiteInput =
        serde_json::from_slice(&read(suite_path, 4 * 1024 * 1024)?)?;
    crate::windows_consumer_readiness::validate_suite(&suite)?;
    normalize_positive_cases(
        context,
        config,
        &suite.cases,
        observed,
        None,
        &config.output_directory.join("windows-owned-inputs.json"),
    )
}

#[cfg(windows)]
fn normalize_positive_cases(
    context: &WindowsAdapterContext,
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    cases: &[crate::windows_consumer_readiness::CaseInput],
    observed: &[crate::windows_consumer_readiness::CaseAssessment],
    namespace: Option<&Path>,
    toolchain_manifest: &Path,
) -> crate::Result<WindowsNormalizedRows> {
    use crate::windows_consumer_readiness::native::read;
    use memcordon_readiness_verifier::*;
    if context.product.target != config.target
        || context.identity.source_commit != config.source_commit
        || context.identity.version != config.version
        || context.fixture_source.sha256 != context.identity.source_tree_sha256
        || context.lease_id.is_empty()
        || !context.destination.is_absolute()
    {
        return Err(crate::CiError::Message(
            "Windows positive producer/source/product association differs".into(),
        ));
    }
    let mut prefix = PathBuf::from(&context.product.target).join(&context.product.channel);
    if let Some(namespace) = namespace {
        Bundle::relative(namespace)?;
        prefix.push(namespace);
    }
    Bundle::relative(&prefix)?;
    let mut bundle = Bundle {
        destination: context.destination.clone(),
        prefix,
        artifacts: Vec::new(),
        held: Vec::new(),
    };
    let fixture = bundle.copy(
        &config.fixture.path,
        Path::new("windows-positive-fixture.exe"),
        Some(&config.fixture.sha256),
    )?;
    let fixture_source = bundle.copy(
        &context.fixture_source.path,
        Path::new("windows-positive-fixture-source.bin"),
        Some(&context.fixture_source.sha256),
    )?;
    let mut records = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for assessment in observed {
        let case = cases
            .iter()
            .find(|case| case.key == assessment.key)
            .ok_or_else(|| {
                crate::CiError::Message(
                    "positive assessment is outside its original finite suite".into(),
                )
            })?;
        let key = CaseKey {
            target: context.product.target.clone(),
            channel: Some(context.product.channel.clone()),
            evidence_class: EvidenceClass::InstalledProduct,
            family: case.key.family.clone(),
            scenario: case.key.scenario.clone(),
        };
        if !seen.insert(key.clone()) {
            return Err(crate::CiError::Message(
                "positive normalization duplicates an observed row".into(),
            ));
        }
        let source = config
            .output_directory
            .join(&case.key.family)
            .join(&case.key.scenario);
        let row = PathBuf::from("windows-positive")
            .join(&case.key.family)
            .join(&case.key.scenario);
        if source.is_dir() {
            bundle.copy_directory(&source, &row.join("raw"))?;
        }
        if let Some(reason) = [
            &assessment.collection,
            &assessment.behavior,
            &assessment.retirement,
        ]
        .into_iter()
        .find_map(|result| result.as_ref().err())
        {
            records.push(CaseRecord {
                key,
                run_id: context.identity.run_id.clone(),
                state: CaseState::Failed,
                reason: Some(reason.clone()),
                evidence: None,
            });
            continue;
        }
        let descriptor_path = bundle.copy(
            &case.descriptor_path,
            &row.join("descriptor.json"),
            Some(&assessment.descriptor_sha256),
        )?;
        let descriptor_bytes = read(&case.descriptor_path, 1024 * 1024)?;
        let descriptor: crate::windows_consumer_readiness::descriptor::Descriptor =
            serde_json::from_slice(&descriptor_bytes)?;
        bundle.copy_directory(&descriptor.output_root, &row.join("products"))?;
        let transcript = bundle.reference(
            &row.join("products").join(
                descriptor
                    .transcript
                    .strip_prefix(&descriptor.output_root)
                    .map_err(|_| {
                        crate::CiError::Message(
                            "actual fixture transcript escapes candidate output".into(),
                        )
                    })?,
            ),
        )?;
        let raw = |name: &str| -> crate::Result<serde_json::Value> {
            let bytes = read(&source.join(name), 16 * 1024 * 1024)?;
            memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)
                .map_err(crate::CiError::Message)?;
            serde_json::from_slice(&bytes).map_err(Into::into)
        };
        let launch = raw("native-invocation.json")?;
        let exit = raw("native-exit.json")?;
        let retired = raw("native-retirement.json")?;
        let invocation =
            normalize_public_invocation(&mut bundle, &row, &launch, &config.cli.sha256)?;
        if !["+4GiB", "+64MiB"].contains(&invocation.memory.as_str())
            || !["+600s", "+10s"].contains(&invocation.deadline.as_str())
        {
            return Err(crate::CiError::Message(
                "positive native budgets differ from the actually provisioned finite workload"
                    .into(),
            ));
        }
        let result_bytes = read(
            &source.join("result.json"),
            crate::windows_causal_acceptance::MAX_REPORT_BYTES,
        )?;
        let result =
            memcordon_core::ResultV1::parse(&result_bytes).map_err(crate::CiError::Message)?;
        if result.invocation.association_sha256 != invocation.association_sha256
            || exit["capture_complete"] != true
        {
            return Err(crate::CiError::Message(
                "positive actual public invocation/result/capture differs".into(),
            ));
        }
        let terminal_bytes = read(
            &source.join("result.terminal-observation.json"),
            memcordon_platform::MAX_TERMINAL_OBSERVATION_BYTES,
        )?;
        let terminal: memcordon_platform::AuthenticatedWindowsTerminalObservation =
            serde_json::from_slice(&terminal_bytes)?;
        if terminal.provider != config.provider {
            return Err(crate::CiError::Message(
                "positive authenticated provider differs from installed selection".into(),
            ));
        }
        let terminal_path = bundle.reference(&row.join("raw/result.terminal-observation.json"))?;
        let provider_request = bundle.retain(
            &row.join("provider-request.bin"),
            &terminal.provider_request,
        )?;
        let request_bytes = read(&source.join("requested-contract.json"), 256 * 1024)?;
        let request_path = bundle.reference(&row.join("raw/requested-contract.json"))?;
        let native_family: Vec<HeldProcessIdentity> =
            serde_json::from_value(retired["held_processes"].clone())?;
        let root_pid = terminal
            .terminal
            .execution()
            .map(|(pid, _, _)| pid)
            .ok_or_else(|| {
                crate::CiError::Message(
                    "positive terminal is not actual execution authority".into(),
                )
            })?;
        let root = native_family
            .iter()
            .find(|identity| identity.pid == root_pid && identity.parent_pid.is_none())
            .ok_or_else(|| crate::CiError::Message("positive held root identity missing".into()))?;
        let origin = if case.key.scenario == "endpoint-mismatch" {
            OutcomeOrigin::ApplicationRefusal
        } else {
            match result.outcome.kind {
                memcordon_core::result_v1::OutcomeKindV1::Completed => OutcomeOrigin::Target,
                memcordon_core::result_v1::OutcomeKindV1::Deadline => OutcomeOrigin::Deadline,
                memcordon_core::result_v1::OutcomeKindV1::ConfirmedMemoryLimit => {
                    OutcomeOrigin::Memory
                }
                memcordon_core::result_v1::OutcomeKindV1::Interrupted => OutcomeOrigin::Interrupted,
                _ => OutcomeOrigin::ProviderFailure,
            }
        };
        let target_status = match &result.outcome.native_termination {
            Some(memcordon_core::ChildTermination::ExitCode { code }) => Some(*code),
            Some(memcordon_core::ChildTermination::WindowsStatus { status }) => {
                Some(*status as i32)
            }
            _ => None,
        };
        let frontend_status =
            i32::try_from(exit["native_status"].as_i64().ok_or_else(|| {
                crate::CiError::Message("native frontend status unavailable".into())
            })?)
            .map_err(|_| {
                crate::CiError::Message("native frontend status exceeds signed DWORD".into())
            })?;
        let native = NativeObservation {
            format: "memcordon.consumer-readiness.native".into(),
            revision: 1,
            run_id: context.identity.run_id.clone(),
            lease_id: Some(context.lease_id.clone()),
            target: config.target.clone(),
            executable_sha256: config.cli.sha256.clone(),
            invocation_sha256: invocation.association_sha256.clone(),
            execution_invocation_sha256: None,
            request_sha256: Some(terminal.terminal.request_sha256.clone()),
            provider_sha256: Some(config.installed_agent.sha256.clone()),
            provider_generation: Some(terminal.provider.generation.as_str().to_owned()),
            runtime_manifest_sha256: Some(String::from(
                terminal.provider.runtime_manifest_sha256.clone(),
            )),
            attempt_id: Some(terminal.terminal.attempt_id.clone()),
            root_pid: Some(root_pid),
            root_birth: Some(root.birth),
            attempt_nonce: Some(terminal.terminal.nonce.clone()),
            held_processes: native_family,
            frontend_status,
            origin,
            target_status,
            authenticated_provider_exchange: true,
            relay_complete: exit["capture_complete"] == true,
            result_named_identity_verified: true,
            result_readback_verified: true,
            application_stage: (origin == OutcomeOrigin::ApplicationRefusal)
                .then(|| "endpoint-policy".into()),
        };
        let proof = &terminal.terminal.retirement_proof;
        let retirement = RetirementObservation {
            format: "memcordon.consumer-readiness.retirement".into(),
            revision: 1,
            run_id: context.identity.run_id.clone(),
            attempt_id: native.attempt_id.clone(),
            root_pid: native.root_pid,
            root_birth: native.root_birth,
            target_reaped_or_absent: proof.target_completion_observed,
            aggregate_empty: proof.native_job_empty_observed,
            relays_retired: proof.relay_closure_observed,
            guardian_retired: proof.guardian_completion_observed
                && retired["guardian_retirement_observed"] == true,
            native_handles_closed: proof.owner_capabilities_closed,
            independently_observed: retired["same_image_processes_absent"] == true,
            namespace_init_reaped: None,
            private_root_closed: None,
            exports_finalized: None,
            account_reservation_retired: None,
            final_job_handles_closed: Some(proof.owner_capabilities_closed),
            active_processes_zero: Some(proof.native_job_empty_observed),
            outstanding: result
                .cleanup
                .outstanding
                .iter()
                .map(|obligation| {
                    serde_json::to_value(obligation)
                        .map_err(crate::CiError::from)
                        .and_then(|value| {
                            value.as_str().map(str::to_owned).ok_or_else(|| {
                                crate::CiError::Message(
                                    "retirement obligation lacks frozen text projection".into(),
                                )
                            })
                        })
                })
                .collect::<crate::Result<Vec<_>>>()?,
            failed_operations: result.cleanup.failed_operations.clone(),
        };
        let native_path = bundle.retain(&row.join("native.json"), &serde_json::to_vec(&native)?)?;
        let retirement_path = bundle.retain(
            &row.join("retirement.json"),
            &serde_json::to_vec(&retirement)?,
        )?;
        let challenge = read(&source.join("challenge.bin"), 32)?;
        if challenge.len() != 32 || challenge != descriptor.challenge {
            return Err(crate::CiError::Message(
                "actual protected challenge differs from executed descriptor".into(),
            ));
        }
        let toolchain_identity = if descriptor.toolchain.is_some() {
            Some(crate::windows_causal_acceptance::sha256(&read(
                toolchain_manifest,
                64 * 1024 * 1024,
            )?))
        } else {
            None
        };
        let input = FixtureInput {
            format: "memcordon.consumer-readiness.input".into(),
            revision: 1,
            run_id: context.identity.run_id.clone(),
            key: key.clone(),
            challenge_sha256: crate::windows_causal_acceptance::sha256(&challenge),
            binary: if key.scenario == "binary-file" {
                (0..=255).collect()
            } else {
                descriptor.stdout.clone()
            },
            target_argv: NativeArguments::WindowsUtf16(
                descriptor
                    .arguments
                    .iter()
                    .map(|argument| argument.encode_utf16().collect())
                    .collect(),
            ),
            deadline_millis: Some(if invocation.deadline == "+10s" {
                10000
            } else {
                600000
            }),
            memory_bytes: Some(if invocation.memory == "+64MiB" {
                64 * 1024 * 1024
            } else {
                4 * 1024 * 1024 * 1024
            }),
            toolchain_identity,
        };
        let input_bytes = serde_json::to_vec(&input)?;
        let input_path = bundle.retain(&row.join("input.json"), &input_bytes)?;
        let token = bundle.retain(
            &row.join("expected-token.json"),
            &serde_json::to_vec(&case.expected_token)?,
        )?;
        let mut semantic = normalize_positive_semantic(
            &mut bundle,
            &row,
            &source,
            &descriptor,
            &key,
            &native,
            &transcript,
            &terminal_path,
            descriptor_path,
            token,
        )?;
        if let Some(expected) = input.toolchain_identity.as_deref() {
            let path = bundle.copy(
                toolchain_manifest,
                &row.join("toolchain-inputs.json"),
                Some(expected),
            )?;
            semantic
                .fixture_behavior
                .as_mut()
                .expect("positive fixture behavior")
                .peer_artifacts
                .push(BehaviorArtifact {
                    role: "toolchain-inputs".into(),
                    path,
                });
            let toolchain = descriptor.toolchain.as_ref().ok_or_else(|| {
                crate::CiError::Message("measured toolchain descriptor missing".into())
            })?;
            let measured: Vec<crate::windows_installed_cases::SelectedArtifact> =
                serde_json::from_slice(&read(toolchain_manifest, 64 * 1024 * 1024)?)?;
            let mut libraries = Vec::new();
            for selected in measured.iter().filter(|selected| {
                toolchain
                    .native_library_directories
                    .iter()
                    .any(|directory| selected.path.starts_with(directory))
            }) {
                let artifact = bundle.copy(
                    &selected.path,
                    &row.join(format!(
                        "raw/selected-native-library-{}.bin",
                        libraries.len()
                    )),
                    Some(&selected.sha256),
                )?;
                libraries
                    .push(serde_json::json!({"original_path":selected.path,"artifact":artifact}));
            }
            let path = bundle.retain(
                &row.join("raw/selected-native-library-inputs.json"),
                &serde_json::to_vec(&libraries)?,
            )?;
            semantic
                .fixture_behavior
                .as_mut()
                .expect("positive fixture behavior")
                .peer_artifacts
                .push(BehaviorArtifact {
                    role: "selected-native-library-inputs".into(),
                    path,
                });
        }
        let semantic_path =
            bundle.retain(&row.join("semantic.json"), &serde_json::to_vec(&semantic)?)?;
        let evidence = CaseEvidence {
            format: "memcordon.consumer-readiness.case".into(),
            revision: 1,
            key: key.clone(),
            run_id: context.identity.run_id.clone(),
            source_commit: context.identity.source_commit.clone(),
            source_tree_sha256: context.identity.source_tree_sha256.clone(),
            lease_id: Some(context.lease_id.clone()),
            fixture: fixture.clone(),
            fixture_source: fixture_source.clone(),
            fixture_sha256: config.fixture.sha256.clone(),
            fixture_source_sha256: context.fixture_source.sha256.clone(),
            input: input_path,
            input_sha256: crate::windows_causal_acceptance::sha256(&input_bytes),
            invocation: invocation.path,
            request: Some(request_path),
            raw_result: Some(bundle.reference(&row.join("raw/result.json"))?),
            provider_request: Some(provider_request),
            authenticated_terminal: Some(terminal_path),
            windows_loss: None,
            execution_invocation: None,
            execution_environment: None,
            transcript: Some(transcript),
            inventory: None,
            qualification: None,
            export_receipt: None,
            prepared_observation: None,
            prepared_native_receipt: None,
            native_observation: native_path,
            retirement: retirement_path,
            semantic_observation: semantic_path,
            component_recipe_id: None,
        };
        let evidence_path =
            bundle.retain(&row.join("evidence.json"), &serde_json::to_vec(&evidence)?)?;
        records.push(CaseRecord {
            key,
            run_id: context.identity.run_id.clone(),
            state: CaseState::Passed,
            reason: None,
            evidence: Some(evidence_path),
        });
        let _ = request_bytes;
    }
    Ok(WindowsNormalizedRows {
        records,
        artifacts: bundle.artifacts,
    })
}

/// Preserves every real capacity constituent and every convergence observation.
/// A concurrent second attempt retains its honest non-global retirement facts.
#[cfg(windows)]
pub fn normalize_capacity(
    context: &WindowsAdapterContext,
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    suite_path: &Path,
    observed: &[crate::windows_readiness_capacity::CapacityAssessment],
) -> crate::Result<WindowsNormalizedRows> {
    use crate::windows_consumer_readiness::native::read;
    use memcordon_readiness_verifier::*;
    let suite: crate::windows_consumer_readiness::SuiteInput =
        serde_json::from_slice(&read(suite_path, 4 * 1024 * 1024)?)?;
    crate::windows_consumer_readiness::validate_suite(&suite)?;
    let base = suite
        .cases
        .iter()
        .find(|case| case.key.family == "W-JOINT" && case.key.scenario == "ordinary")
        .ok_or_else(|| crate::CiError::Message("capacity original joint fixture missing".into()))?;
    let mut bundle = Bundle {
        destination: context.destination.clone(),
        prefix: PathBuf::from(&context.product.target).join(&context.product.channel),
        artifacts: Vec::new(),
        held: Vec::new(),
    };
    let mut output = WindowsNormalizedRows {
        records: Vec::new(),
        artifacts: Vec::new(),
    };
    let mut seen = std::collections::BTreeSet::new();
    for assessment in observed {
        if !crate::windows_readiness_capacity::required_keys().contains(&assessment.key)
            || !seen.insert(assessment.key.clone())
        {
            return Err(crate::CiError::Message(
                "capacity assessment is unknown or duplicated".into(),
            ));
        }
        let key = CaseKey {
            target: context.product.target.clone(),
            channel: Some(context.product.channel.clone()),
            evidence_class: EvidenceClass::InstalledProduct,
            family: assessment.key.family.clone(),
            scenario: assessment.key.scenario.clone(),
        };
        let directory = config
            .output_directory
            .join(&assessment.key.family)
            .join(&assessment.key.scenario);
        let row = PathBuf::from("windows-capacity").join(&assessment.key.scenario);
        bundle.copy_directory(&directory, &row.join("raw"))?;
        if let Some(reason) = [
            &assessment.collection,
            &assessment.behavior,
            &assessment.retirement,
        ]
        .into_iter()
        .find_map(|value| value.as_ref().err())
        {
            output.records.push(CaseRecord {
                key,
                run_id: context.identity.run_id.clone(),
                state: CaseState::Failed,
                reason: Some(reason.clone()),
                evidence: None,
            });
            continue;
        }
        let count = match assessment.key.scenario.as_str() {
            "serial-retirement" => 3,
            "bounded-concurrency" => 2,
            "fresh-positive-after-recovery" => 1,
            _ => unreachable!("checked finite key"),
        };
        if assessment.attempts.len() != count {
            return Err(crate::CiError::Message(
                "capacity omitted a required actual constituent".into(),
            ));
        }
        let mut attempts = Vec::new();
        let mut representative = None;
        let mut challenges = std::collections::BTreeSet::new();
        for (ordinal, attempt) in assessment.attempts.iter().enumerate() {
            if attempt.key != assessment.key {
                return Err(crate::CiError::Message(
                    "capacity constituent belongs to another row".into(),
                ));
            }
            let mut owned = config.clone();
            owned.output_directory = directory.join(format!("attempt-{ordinal}"));
            let mut case = base.clone();
            case.key = assessment.key.clone();
            case.descriptor_path = owned.output_directory.join("input.json");
            let descriptor: crate::windows_consumer_readiness::descriptor::Descriptor =
                serde_json::from_slice(&read(&case.descriptor_path, 1024 * 1024)?)?;
            descriptor.validate().map_err(crate::CiError::Message)?;
            let mut frozen = descriptor.clone();
            frozen.challenge = base.descriptor.challenge.clone();
            frozen.output_root = base.descriptor.output_root.clone();
            frozen.transcript = base.descriptor.transcript.clone();
            frozen.start_gate = base.descriptor.start_gate.clone();
            frozen.completion_gate = base.descriptor.completion_gate.clone();
            if serde_json::to_vec(&frozen)? != serde_json::to_vec(&base.descriptor)?
                || descriptor.challenge.len() != 32
                || descriptor.challenge.iter().all(|byte| *byte == 0)
                || !challenges.insert(descriptor.challenge.clone())
            {
                return Err(crate::CiError::Message(
                    "capacity narrowed the protected joint fixture or reused challenge".into(),
                ));
            }
            case.descriptor = descriptor;
            case.workload_contract = config
                .output_directory
                .join("W-JOINT/ordinary/requested-contract.json");
            let namespace = row.join(format!("attempt-{ordinal}"));
            let nested = normalize_positive_cases(
                context,
                &owned,
                &[case],
                std::slice::from_ref(attempt),
                Some(&namespace),
                &config.output_directory.join("windows-owned-inputs.json"),
            )?;
            let nested_record = nested.records.first().ok_or_else(|| {
                crate::CiError::Message("capacity constituent projection missing".into())
            })?;
            if nested.records.len() != 1 || nested_record.state != CaseState::Passed {
                return Err(crate::CiError::Message(
                    "capacity constituent did not retain complete actual evidence".into(),
                ));
            }
            let evidence = nested_record.evidence.clone().ok_or_else(|| {
                crate::CiError::Message("capacity constituent evidence missing".into())
            })?;
            if representative.is_none() {
                representative = Some(evidence.clone());
            }
            attempts.push(evidence);
            output.artifacts.extend(nested.artifacts);
        }
        let inventory_count = if count == 2 { 2 } else { count + 1 };
        let mut inventories = Vec::new();
        for ordinal in 0..inventory_count {
            let name = format!("inventory-{ordinal}.json");
            let inventory: memcordon_core::WindowsRecoveryInventoryV1 =
                serde_json::from_slice(&read(&directory.join(&name), 256 * 1024)?)?;
            if !inventory.is_consistent()
                || inventory.authority_unsettled()
                || inventory.provider_generation != config.provider.generation.as_str()
            {
                return Err(crate::CiError::Message(
                    "capacity convergence retains unsettled or substituted authority".into(),
                ));
            }
            inventories.push(bundle.reference(&row.join("raw").join(name))?);
        }
        let representative = representative.expect("positive finite constituent count");
        let held = hold_artifact(
            &context.destination.join(&representative),
            None,
            4 * 1024 * 1024,
        )?;
        let mut evidence: CaseEvidence = serde_json::from_slice(&held.bytes)?;
        let semantic_custody = hold_artifact(
            &context.destination.join(&evidence.semantic_observation),
            None,
            4 * 1024 * 1024,
        )?;
        let mut semantic: SemanticObservation = serde_json::from_slice(&semantic_custody.bytes)?;
        let native_custody = hold_artifact(
            &context.destination.join(&evidence.native_observation),
            None,
            4 * 1024 * 1024,
        )?;
        let native: NativeObservation = serde_json::from_slice(&native_custody.bytes)?;
        semantic.windows_capacity = Some(WindowsCapacityEvidence {
            attempts,
            inventories: inventories.clone(),
            overlap_live_association: (count == 2)
                .then(|| bundle.reference(&row.join("raw/overlap-live-association.json")))
                .transpose()?,
            overlap_held_guardian: (count == 2)
                .then(|| bundle.reference(&row.join("raw/overlap-held-guardian.json")))
                .transpose()?,
        });
        semantic.operations.extend(
            [
                format!("capacity-{}", assessment.key.scenario),
                "fresh-admission".into(),
                "capacity-attempts".into(),
            ]
            .into_iter()
            .map(|operation| OperationObservation {
                operation,
                attempt_id: native.attempt_id.clone(),
                root_pid: native.root_pid,
                observer: "owned-native-capacity".into(),
                native_receipt: inventories.last().expect("positive inventories").clone(),
            }),
        );
        semantic
            .counters
            .insert("capacity-attempts".into(), count as u64);
        evidence.semantic_observation =
            bundle.retain(&row.join("semantic.json"), &serde_json::to_vec(&semantic)?)?;
        let evidence_path =
            bundle.retain(&row.join("evidence.json"), &serde_json::to_vec(&evidence)?)?;
        output.records.push(CaseRecord {
            key,
            run_id: context.identity.run_id.clone(),
            state: CaseState::Passed,
            reason: None,
            evidence: Some(evidence_path),
        });
    }
    output.artifacts.extend(bundle.artifacts);
    Ok(output)
}

#[cfg(windows)]
fn normalize_positive_semantic(
    bundle: &mut Bundle,
    row: &Path,
    source: &Path,
    descriptor: &crate::windows_consumer_readiness::descriptor::Descriptor,
    key: &memcordon_readiness_verifier::CaseKey,
    native: &memcordon_readiness_verifier::NativeObservation,
    transcript: &str,
    terminal: &str,
    descriptor_path: String,
    token: String,
) -> crate::Result<memcordon_readiness_verifier::SemanticObservation> {
    use crate::windows_consumer_readiness::native::read;
    use memcordon_readiness_verifier::*;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Event {
        sequence: u32,
        stage: String,
        pid: u32,
        ordinal: Option<u32>,
        value: Vec<u8>,
    }
    let bytes = read(&descriptor.transcript, 16 * 1024 * 1024)?;
    let mut tail = bytes.as_slice();
    let mut events = Vec::<Event>::new();
    while !tail.is_empty() {
        let prefix = tail.get(..4).ok_or_else(|| {
            crate::CiError::Message("positive transcript length truncated".into())
        })?;
        let length = u32::from_le_bytes(prefix.try_into().expect("checked width")) as usize;
        if length > 65536 || events.len() >= 200000 {
            return Err(crate::CiError::Message(
                "positive transcript exceeds finite bounds".into(),
            ));
        }
        let bytes = tail
            .get(4..4 + length)
            .ok_or_else(|| crate::CiError::Message("positive transcript event truncated".into()))?;
        let event: Event = serde_json::from_slice(bytes)?;
        if event.sequence as usize != events.len() || event.pid == 0 {
            return Err(crate::CiError::Message(
                "positive raw event sequence/PID differs".into(),
            ));
        }
        events.push(event);
        tail = &tail[4 + length..];
    }
    let mut peers = Vec::new();
    let products = row.join("products");
    let raw = row.join("raw");
    for (role, path) in [
        ("stdout", "result.stdout.bin"),
        ("stderr", "result.stderr.bin"),
        ("native-retirement", "native-retirement.json"),
        ("native-live-association", "live-observation.json"),
        ("native-listener", "native-listener.json"),
        ("native-tcp-peer", "native-tcp-peer.json"),
        (
            "native-intermediate-family",
            "held-intermediate-family.json",
        ),
    ] {
        if source.join(path).is_file() {
            peers.push(BehaviorArtifact {
                role: role.into(),
                path: bundle.reference(&raw.join(path))?,
            });
        }
    }
    for (role, path) in [
        ("native-argv", "native-argv.json"),
        ("empty-file", "nested/empty.bin"),
        ("binary-file", "nested/all-bytes.bin"),
        ("challenge-file", "nested/challenge.bin"),
        ("named-pipe-server", "named-pipe-server-received.bin"),
        ("named-pipe-client", "named-pipe-client-received.bin"),
        ("compiled-child", "compiled/child-output.bin"),
        ("compiled-test-stdout", "compiled/test-stdout.bin"),
        ("dll-empty", "compiled/dll-empty.bin"),
        ("dll-binary", "compiled/dll-output.bin"),
        ("tcp-server-received", "tcp-server-received.bin"),
        ("tcp-peer-received", "tcp-peer-received.bin"),
    ] {
        if descriptor.output_root.join(path).is_file() {
            peers.push(BehaviorArtifact {
                role: role.into(),
                path: bundle.reference(&products.join(path))?,
            });
        }
    }
    if let Some(toolchain) = &descriptor.toolchain {
        for (field, path) in [
            ("rustc", &toolchain.rustc),
            ("native_linker", &toolchain.native_linker),
            ("library_source", &toolchain.library_source),
            ("test_source", &toolchain.test_source),
            ("child_source", &toolchain.child_source),
            ("dll_source", &toolchain.dll_source),
            ("loader_source", &toolchain.loader_source),
        ] {
            let role = format!("selected-{field}");
            let path = bundle.copy(path, &raw.join(format!("{role}.bin")), None)?;
            peers.push(BehaviorArtifact { role, path });
        }
        for role in [
            "readiness.rlib",
            "child.exe",
            "tests.exe",
            "readiness.dll",
            "loader.exe",
            "run-tests",
            "run-child",
            "run-loader",
        ] {
            for phase in ["created", "retired"] {
                peers.push(BehaviorArtifact {
                    role: format!("native-child-{role}-{phase}"),
                    path: bundle.reference(
                        &products.join(format!("compiled/native-child-{role}.{phase}.json")),
                    )?,
                });
            }
        }
        for artifact in [
            "readiness.rlib",
            "child.exe",
            "tests.exe",
            "readiness.dll",
            "loader.exe",
        ] {
            peers.push(BehaviorArtifact {
                role: format!("generated-{artifact}"),
                path: bundle.reference(&products.join(format!("compiled/{artifact}")))?,
            });
        }
        for source in ["library.rs", "tests.rs", "child.rs", "dll.rs", "loader.rs"] {
            peers.push(BehaviorArtifact {
                role: format!("compiler-source-{source}"),
                path: bundle.reference(&products.join(format!("compiled/{source}")))?,
            });
        }
    }
    let mut counters = std::collections::BTreeMap::new();
    let mut maximum_live = 0;
    let mut maximum_depth = 0;
    for entry in std::fs::read_dir(source)? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with("native-cohort-live-")
            || name.starts_with("native-generation-live-")
            || name.starts_with("native-toolchain-descendant-")
        {
            let role = name.strip_suffix(".json").ok_or_else(|| {
                crate::CiError::Message("native barrier artifact suffix differs".into())
            })?;
            peers.push(BehaviorArtifact {
                role: role.into(),
                path: bundle.reference(&raw.join(name))?,
            });
            if name.starts_with("native-cohort-live-")
                || name.starts_with("native-generation-live-")
            {
                let observed: serde_json::Value =
                    serde_json::from_slice(&read(&path, 1024 * 1024)?)?;
                maximum_live =
                    maximum_live.max(observed["live_children"].as_u64().ok_or_else(|| {
                        crate::CiError::Message("native live barrier count missing".into())
                    })?);
                if name.starts_with("native-generation-live-") {
                    let members:Vec<HeldProcessIdentity>=observed["members"].as_array().ok_or_else(||crate::CiError::Message("native generation member set missing".into()))?.iter()
                        .map(|member|serde_json::from_value(serde_json::json!({"pid":member["pid"],"birth":member["birth"],"parent_pid":member["parent_pid"],"parent_birth":member["parent_birth"],"retirement_observed":false}))).collect::<std::result::Result<_,_>>()?;
                    for member in &members {
                        let mut cursor = member;
                        let mut depth = 0;
                        while cursor.pid != native.root_pid.unwrap_or(0) {
                            if depth >= 16 {
                                return Err(crate::CiError::Message(
                                    "native generation ancestry is cyclic or exceeds bound".into(),
                                ));
                            }
                            cursor = members
                                .iter()
                                .find(|parent| {
                                    Some(parent.pid) == cursor.parent_pid
                                        && Some(parent.birth) == cursor.parent_birth
                                })
                                .ok_or_else(|| {
                                    crate::CiError::Message(
                                        "native generation lacks exact parent identity".into(),
                                    )
                                })?;
                            depth += 1;
                        }
                        maximum_depth = maximum_depth.max(depth);
                    }
                }
            }
        }
    }
    let compiled = descriptor.output_root.join("compiled");
    if compiled.is_dir() {
        for entry in std::fs::read_dir(&compiled)? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if name.starts_with("native-child-") && name.ends_with(".json") {
                let role = name.trim_end_matches(".json").replace('.', "-");
                peers.push(BehaviorArtifact {
                    role,
                    path: bundle.reference(&products.join("compiled").join(name))?,
                });
            }
        }
    }
    let mut operations = std::collections::BTreeSet::<String>::new();
    operations.insert("caller-token-attested".into());
    if key.scenario == "restricted" {
        operations.insert("restricted-token".into());
    }
    for event in &events {
        let names: &[&str] = match event.stage.as_str() {
            "tcp-listener-owned" => &["tcp-owned-listener"],
            "tcp-conflicting-bind" => &["tcp-conflicting-bind"],
            "named-pipe-while-tcp-owned" => &["named-pipe-exchange"],
            "binary-files" => &["allowed-file-write"],
            "toolchain-compiled" => &["locked-rust-compile"],
            "toolchain-test-child-dll-complete" => &[
                "compiled-tests",
                "generated-executable",
                "compiled-dll-loaded",
                "generated-descendant",
            ],
            "tcp-peer-complete" => &["http-exchange"],
            "protected-write-denied" => &["protected-write-denied"],
            "sentinel-handles-excluded" if event.value == 1u32.to_le_bytes() => {
                &["frontend-sentinel-held", "sentinel-not-inherited"]
            }
            "endpoint-policy-refused-before-readiness" => {
                &["second-reserved-listener", "application-endpoint-refusal"]
            }
            "root-exits-with-live-descendant" => &[
                "held-descendant-identity",
                "root-exited-before-held-descendant",
            ],
            "intermediate-exits-with-live-descendant" => &[
                "held-descendant-identity",
                "intermediate-exited-before-held-descendant",
            ],
            "allowed-token-change-retained-job" => &["allowed-token-change-contained"],
            _ => &[],
        };
        operations.extend(names.iter().map(|name| name.to_string()));
    }
    if descriptor
        .output_root
        .join("descendant-output.bin")
        .is_file()
        && native
            .held_processes
            .iter()
            .all(|identity| identity.retirement_observed)
    {
        operations.insert("descendant-natural-completion".into());
    }
    if key.family == "W-CHURN" {
        counters.insert(
            "churn-creations".into(),
            events
                .iter()
                .filter(|event| event.stage == "child-created" && event.ordinal.is_some())
                .count() as u64,
        );
        counters.insert(
            "churn-completions".into(),
            events
                .iter()
                .filter(|event| event.stage == "child-completed" && event.ordinal.is_some())
                .count() as u64,
        );
        counters.insert("churn-generations".into(), maximum_depth);
        counters.insert("max-live-children".into(), maximum_live);
        operations.extend(counters.keys().cloned());
        operations.insert("held-cohort-ancestry".into());
    }
    let mut projected: Vec<OperationObservation> = operations
        .into_iter()
        .map(|operation| OperationObservation {
            operation,
            attempt_id: native.attempt_id.clone(),
            root_pid: native.root_pid,
            observer: "owned-fixture-behavior".into(),
            native_receipt: transcript.into(),
        })
        .collect();
    let mut provider_ops = vec![
        "creation-job-attested",
        "suspended-target-attested",
        "native-handle-list-attested",
    ];
    if native.origin == OutcomeOrigin::Deadline {
        provider_ops.push("deadline-expired");
    }
    if native.origin == OutcomeOrigin::Memory {
        provider_ops.push("memory-limit-confirmed");
    }
    if key.family == "W-CHURN" {
        provider_ops.push("sample-eviction-attested");
    }
    projected.extend(
        provider_ops
            .into_iter()
            .map(|operation| OperationObservation {
                operation: operation.into(),
                attempt_id: native.attempt_id.clone(),
                root_pid: native.root_pid,
                observer: "authenticated-provider".into(),
                native_receipt: terminal.into(),
            }),
    );
    let mut comparisons = Vec::new();
    let mut compare = |role: &str, actual: &Path, expected: Vec<u8>| -> crate::Result<()> {
        let expected_path =
            bundle.retain(&row.join("expected").join(format!("{role}.bin")), &expected)?;
        comparisons.push(ByteComparison {
            role: role.into(),
            actual: bundle.reference(actual)?,
            expected: expected_path,
        });
        Ok(())
    };
    if key.family == "W-IO" {
        if key.scenario.starts_with("argv-") {
            compare(
                "native-argv",
                &products.join("native-argv.json"),
                serde_json::to_vec(&NativeArguments::WindowsUtf16(
                    descriptor
                        .arguments
                        .iter()
                        .map(|arg| arg.encode_utf16().collect())
                        .collect(),
                ))?,
            )?;
        } else if key.scenario == "empty-file" {
            compare("file", &products.join("nested/empty.bin"), Vec::new())?;
        } else if key.scenario == "binary-file" {
            compare(
                "file",
                &products.join("nested/all-bytes.bin"),
                (0..=255).collect(),
            )?;
        } else {
            compare(
                "stdout",
                &raw.join("result.stdout.bin"),
                descriptor.stdout.repeat(128),
            )?;
            compare(
                "stderr",
                &raw.join("result.stderr.bin"),
                descriptor.stderr.repeat(128),
            )?;
        }
    }
    if key.family == "W-JOINT" && key.scenario != "endpoint-mismatch" {
        let frames = |parts: &[Vec<u8>]| {
            let mut bytes = Vec::new();
            for part in parts {
                bytes.extend((part.len() as u32).to_le_bytes());
                bytes.extend(part);
            }
            bytes
        };
        let tcp = frames(&[
            b"GET /readiness HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
            vec![],
            vec![0, 255, 128, 10],
            descriptor.challenge.to_vec(),
        ]);
        compare(
            "tcp",
            &products.join("tcp-server-received.bin"),
            tcp.clone(),
        )?;
        compare("http", &products.join("tcp-server-received.bin"), tcp)?;
        compare(
            "named-pipe",
            &products.join("named-pipe-server-received.bin"),
            frames(&[vec![], vec![0, 255, 128], descriptor.challenge.to_vec()]),
        )?;
        compare(
            "file",
            &products.join("nested/all-bytes.bin"),
            (0..=255).collect(),
        )?;
        compare(
            "descendant",
            &products.join("compiled/child-output.bin"),
            descriptor.challenge.to_vec(),
        )?;
    }
    if key.family == "W-TOOLCHAIN" {
        compare(
            "compiled-child",
            &products.join("compiled/child-output.bin"),
            descriptor.challenge.to_vec(),
        )?;
        compare(
            "dll-empty",
            &products.join("compiled/dll-empty.bin"),
            Vec::new(),
        )?;
        compare(
            "dll-binary",
            &products.join("compiled/dll-output.bin"),
            (0..=255).collect(),
        )?;
    }
    if key.family == "W-DESCENDANT"
        && descriptor
            .output_root
            .join("descendant-output.bin")
            .is_file()
    {
        compare(
            "descendant",
            &products.join("descendant-output.bin"),
            descriptor.challenge.to_vec(),
        )?;
    }
    Ok(SemanticObservation {
        format: "memcordon.consumer-readiness.semantic".into(),
        revision: 1,
        run_id: native.run_id.clone(),
        key: key.clone(),
        challenge: bundle.reference(&raw.join("challenge.bin"))?,
        operations: projected,
        comparisons,
        counters,
        negative_probe: (native.origin == OutcomeOrigin::ApplicationRefusal).then(|| {
            NegativeProbe {
                stage: "endpoint-policy".into(),
                domain: "application".into(),
                native_code: 42,
                receipt: transcript.into(),
            }
        }),
        component_test: None,
        component_actors: None,
        windows_capacity: None,
        windows_refusal: None,
        fixture_behavior: Some(FixtureBehavior {
            descriptor: descriptor_path,
            transcript: transcript.into(),
            expected_token: Some(token),
            peer_artifacts: peers,
            native_binding: None,
        }),
    })
}

/// Projects actual preauthorization captures. Acquisition-only rejection uses
/// a separate nonexecution case and never becomes an invented CLI run.
#[cfg(windows)]
pub fn normalize_refusals(
    context: &WindowsAdapterContext,
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    observed: &[crate::windows_readiness_refusals::RefusalAssessment],
) -> crate::Result<WindowsNormalizedRows> {
    use crate::windows_consumer_readiness::native::read;
    use memcordon_readiness_verifier::*;
    use std::os::windows::ffi::OsStringExt;
    if context.product.target != config.target
        || context.identity.source_commit != config.source_commit
        || context.identity.version != config.version
        || context.lease_id.is_empty()
    {
        return Err(crate::CiError::Message(
            "refusal producer association differs".into(),
        ));
    }
    let mut bundle = Bundle {
        destination: context.destination.clone(),
        prefix: PathBuf::from(&context.product.target).join(&context.product.channel),
        artifacts: Vec::new(),
        held: Vec::new(),
    };
    let fixture = bundle.copy(
        &config.fixture.path,
        Path::new("windows-refusal-fixture.exe"),
        Some(&config.fixture.sha256),
    )?;
    let fixture_source = bundle.copy(
        &context.fixture_source.path,
        Path::new("windows-refusal-fixture-source.bin"),
        Some(&context.fixture_source.sha256),
    )?;
    let active_source = config
        .output_directory
        .join("W-JOINT")
        .join("ordinary")
        .join("requested-contract.json");
    let mut records = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for assessment in observed {
        if !crate::windows_readiness_refusals::required_keys().contains(&assessment.key) {
            return Err(crate::CiError::Message(
                "refusal normalization received unrelated row".into(),
            ));
        }
        let key = CaseKey {
            target: config.target.clone(),
            channel: Some(context.product.channel.clone()),
            evidence_class: EvidenceClass::InstalledProduct,
            family: assessment.key.family.clone(),
            scenario: assessment.key.scenario.clone(),
        };
        if !seen.insert(key.clone()) {
            return Err(crate::CiError::Message(
                "refusal normalization duplicates row".into(),
            ));
        }
        let source = config
            .output_directory
            .join(&key.family)
            .join(&key.scenario);
        let row = PathBuf::from("windows-refusal")
            .join(&key.family)
            .join(&key.scenario);
        let raw = row.join("raw");
        if source.is_dir() {
            bundle.copy_directory(&source, &raw)?;
        }
        if let Some(reason) = [
            &assessment.collection,
            &assessment.behavior,
            &assessment.retirement,
        ]
        .into_iter()
        .find_map(|value| value.as_ref().err())
        {
            records.push(CaseRecord {
                key,
                run_id: context.identity.run_id.clone(),
                state: CaseState::Failed,
                reason: Some(reason.clone()),
                evidence: None,
            });
            continue;
        }
        if key.scenario == "component-substitution" {
            let evidence = AcquisitionCaseEvidence {
                format: "memcordon.consumer-readiness.acquisition-case".into(),
                revision: 1,
                key: key.clone(),
                run_id: context.identity.run_id.clone(),
                source_commit: context.identity.source_commit.clone(),
                source_tree_sha256: context.identity.source_tree_sha256.clone(),
                lease_id: context.lease_id.clone(),
                fixture: fixture.clone(),
                fixture_sha256: config.fixture.sha256.clone(),
                original_acquisition: bundle.reference(&raw.join("original-acquisition.json"))?,
                substituted_acquisition: bundle
                    .reference(&raw.join("substituted-acquisition.json"))?,
                refusal: bundle.reference(&raw.join("acquisition-refusal.json"))?,
                quiescence: bundle.reference(&raw.join("native-quiescence.json"))?,
            };
            let path =
                bundle.retain(&row.join("evidence.json"), &serde_json::to_vec(&evidence)?)?;
            records.push(CaseRecord {
                key,
                run_id: context.identity.run_id.clone(),
                state: CaseState::Passed,
                reason: None,
                evidence: Some(path),
            });
            continue;
        }
        let json = |name: &str| -> crate::Result<serde_json::Value> {
            let bytes = read(&source.join(name), 4 * 1024 * 1024)?;
            memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)
                .map_err(crate::CiError::Message)?;
            serde_json::from_slice(&bytes).map_err(Into::into)
        };
        let launch = json("native-invocation.json")?;
        let exit = json("native-exit.json")?;
        let quiet = json("native-quiescence.json")?;
        let nul = key.scenario == "argv-nul-rejection";
        let executable = if nul {
            &config.fixture.sha256
        } else {
            &config.cli.sha256
        };
        if exit["capture_complete"] != true
            || exit["executable_sha256"] != *executable
            || launch["environment_cleared"] != true
            || quiet["format"] != "memcordon.windows-native-refusal-quiescence"
            || quiet["revision"] != 1
            || quiet["guardian_native_quiescence"] != true
            || quiet["fixture_processes_absent"] != true
            || quiet["installed_agent_sha256"] != config.installed_agent.sha256
            || quiet["runtime_manifest_sha256"] != config.installed_manifest.sha256
            || serde_json::from_value::<memcordon_core::PublicProviderBindingV1>(
                quiet["provider"].clone(),
            )? != config.provider
        {
            return Err(crate::CiError::Message(
                "refusal actual capture/quiescence association differs".into(),
            ));
        }
        let changed = matches!(
            key.scenario.as_str(),
            "revoked-grant" | "wrong-authorized-caller"
        );
        if quiet["owned_policy_restoration_required"] != changed
            || quiet["owned_policy_restoration_completed"] != changed
        {
            return Err(crate::CiError::Message(
                "refusal actual policy restoration differs".into(),
            ));
        }
        let (invocation_path, association, arguments) = if nul {
            if launch["executable_sha256"] != *executable {
                return Err(crate::CiError::Message(
                    "NUL facade measured image differs".into(),
                ));
            }
            let program: Vec<u16> = serde_json::from_value(launch["program_utf16"].clone())?;
            let argv: Vec<Vec<u16>> = serde_json::from_value(launch["argv_utf16"].clone())?;
            let arguments: Vec<Vec<u16>> = std::iter::once(program).chain(argv).collect();
            let report = memcordon_core::InvocationReport {
                syntax: "plus-budgets-v1".into(),
                budget_tokens: Vec::new(),
                memory_token: None,
                deadline_token: None,
                argv: arguments
                    .iter()
                    .map(|arg| {
                        memcordon_core::NativeArgument::from_os(&std::ffi::OsString::from_wide(arg))
                    })
                    .collect(),
            };
            let association =
                crate::windows_causal_acceptance::sha256(&serde_json::to_vec(&report)?);
            let environment = serde_json::to_vec(&NativeEnvironment::WindowsUtf16(Vec::new()))?;
            let environment_path = bundle.retain(&row.join("environment.json"), &environment)?;
            let invocation = NativeInvocation {
                format: "memcordon.consumer-readiness.invocation".into(),
                revision: 1,
                arguments: NativeArguments::WindowsUtf16(arguments.clone()),
                executable_sha256: executable.clone(),
                environment: environment_path,
                environment_sha256: crate::windows_causal_acceptance::sha256(&environment),
                association_sha256: association.clone(),
                budget_tokens: Vec::new(),
                memory_token: None,
                deadline_token: None,
            };
            (
                bundle.retain(
                    &row.join("invocation.json"),
                    &serde_json::to_vec(&invocation)?,
                )?,
                association,
                arguments,
            )
        } else {
            let projection =
                normalize_public_invocation(&mut bundle, &row, &launch, &config.cli.sha256)?;
            (
                projection.path,
                projection.association_sha256,
                projection.arguments,
            )
        };
        let status = i32::try_from(
            exit["native_status"]
                .as_i64()
                .ok_or_else(|| crate::CiError::Message("refusal native status absent".into()))?,
        )
        .map_err(|_| crate::CiError::Message("refusal status exceeds signed DWORD".into()))?;
        let result = if nul {
            None
        } else {
            Some(
                memcordon_core::ResultV1::parse(&read(
                    &source.join("result.json"),
                    crate::windows_causal_acceptance::MAX_REPORT_BYTES,
                )?)
                .map_err(crate::CiError::Message)?,
            )
        };
        if result.as_ref().is_some_and(|result| {
            result.invocation.association_sha256 != association
                || result.outcome.wrapper_status != status
                || result.authorization
                    != if key.scenario == "unsupported-public-request" {
                        memcordon_core::result_v1::AuthorizationV1::NotRequiredForStandard
                    } else {
                        memcordon_core::result_v1::AuthorizationV1::RejectedBeforeRelease
                    }
                || result.launch.target_pid.is_some()
                || result.launch.state != memcordon_core::result_v1::LaunchStateV1::NotCreated
        }) {
            return Err(crate::CiError::Message(
                "refusal result differs from actual public invocation/status or creates target"
                    .into(),
            ));
        }
        let provider_request = if source.join("provider-request.bin").is_file() {
            Some(read(
                &source.join("provider-request.bin"),
                memcordon_core::WINDOWS_MAX_FRAME_BYTES,
            )?)
        } else {
            None
        };
        let provider_association = result
            .as_ref()
            .and_then(|result| result.provider_association.as_ref());
        if provider_request.is_some() != provider_association.is_some() {
            return Err(crate::CiError::Message(
                "refusal provider request/association availability differs".into(),
            ));
        }
        let request_sha256 = provider_request
            .as_ref()
            .map(|bytes| crate::windows_causal_acceptance::sha256(bytes));
        if provider_association.is_some_and(|association| {
            association.provider != config.provider
                || Some(String::from(association.request_sha256.clone())) != request_sha256
        }) {
            return Err(crate::CiError::Message(
                "refusal authenticated provider request differs".into(),
            ));
        }
        let nonce = provider_request
            .as_ref()
            .map(|bytes| serde_json::from_slice::<memcordon_core::WindowsLaunchRequestV1>(bytes))
            .transpose()?
            .map(|request| request.nonce);
        let native = NativeObservation {
            format: "memcordon.consumer-readiness.native".into(),
            revision: 1,
            run_id: context.identity.run_id.clone(),
            lease_id: Some(context.lease_id.clone()),
            target: config.target.clone(),
            executable_sha256: executable.clone(),
            invocation_sha256: association,
            execution_invocation_sha256: None,
            request_sha256,
            provider_sha256: provider_association.map(|_| config.installed_agent.sha256.clone()),
            provider_generation: provider_association
                .map(|_| config.provider.generation.as_str().to_owned()),
            runtime_manifest_sha256: provider_association
                .map(|_| String::from(config.provider.runtime_manifest_sha256.clone())),
            attempt_id: provider_association
                .map(|association| String::from(association.attempt_id.clone())),
            root_pid: None,
            root_birth: None,
            attempt_nonce: nonce,
            held_processes: Vec::new(),
            frontend_status: status,
            origin: OutcomeOrigin::AdmissionRefusal,
            target_status: None,
            authenticated_provider_exchange: provider_association.is_some(),
            relay_complete: true,
            result_named_identity_verified: true,
            result_readback_verified: true,
            application_stage: None,
        };
        let retirement = RetirementObservation {
            format: "memcordon.consumer-readiness.retirement".into(),
            revision: 1,
            run_id: native.run_id.clone(),
            attempt_id: native.attempt_id.clone(),
            root_pid: None,
            root_birth: None,
            target_reaped_or_absent: true,
            aggregate_empty: true,
            relays_retired: false,
            guardian_retired: false,
            native_handles_closed: false,
            independently_observed: true,
            namespace_init_reaped: None,
            private_root_closed: None,
            exports_finalized: None,
            account_reservation_retired: None,
            final_job_handles_closed: None,
            active_processes_zero: None,
            outstanding: Vec::new(),
            failed_operations: Vec::new(),
        };
        let native_path = bundle.retain(&row.join("native.json"), &serde_json::to_vec(&native)?)?;
        let retirement_path = bundle.retain(
            &row.join("retirement.json"),
            &serde_json::to_vec(&retirement)?,
        )?;
        let challenge = read(&source.join("challenge.bin"), 32)?;
        if challenge.len() != 32 || challenge.iter().all(|byte| *byte == 0) {
            return Err(crate::CiError::Message(
                "refusal challenge unavailable".into(),
            ));
        }
        let input = FixtureInput {
            format: "memcordon.consumer-readiness.input".into(),
            revision: 1,
            run_id: native.run_id.clone(),
            key: key.clone(),
            challenge_sha256: crate::windows_causal_acceptance::sha256(&challenge),
            binary: Vec::new(),
            target_argv: NativeArguments::WindowsUtf16(arguments),
            deadline_millis: if nul { None } else { Some(600000) },
            memory_bytes: if nul {
                None
            } else {
                Some(4 * 1024 * 1024 * 1024)
            },
            toolchain_identity: None,
        };
        let input_bytes = serde_json::to_vec(&input)?;
        let input_path = bundle.retain(&row.join("input.json"), &input_bytes)?;
        let quiescence = bundle.reference(&raw.join("native-quiescence.json"))?;
        let refusal = if nul {
            WindowsRefusalEvidence::NativeArgument {
                receipt: bundle.reference(&raw.join("native-argument-refusal.json"))?,
                guardian_quiescence: bundle
                    .reference(&raw.join("native-guardian-quiescence.json"))?,
                frontend: bundle.reference(&raw.join("native-frontend.json"))?,
                quiescence,
            }
        } else if key.scenario == "unsupported-public-request" {
            WindowsRefusalEvidence::UnsupportedPublicRequest {
                guardian_quiescence: bundle
                    .reference(&raw.join("native-guardian-quiescence.json"))?,
                frontend: bundle.reference(&raw.join("native-frontend.json"))?,
                quiescence,
            }
        } else {
            let suite_bytes = read(
                &config.output_directory.join("windows-readiness-input.json"),
                4 * 1024 * 1024,
            )?;
            memcordon_core::canonical_json::reject_duplicate_json_keys(&suite_bytes)
                .map_err(crate::CiError::Message)?;
            let suite: crate::windows_consumer_readiness::SuiteInput =
                serde_json::from_slice(&suite_bytes)?;
            if suite.local_policy != config.output_directory.join("windows-local-policy.json") {
                return Err(crate::CiError::Message(
                    "refusal baseline policy is outside its exact owned input".into(),
                ));
            }
            let baseline_policy =
                bundle.copy(&suite.local_policy, &row.join("baseline-policy.json"), None)?;
            let baseline_contract =
                bundle.copy(&active_source, &row.join("baseline-contract.json"), None)?;
            let prior = suite
                .cases
                .iter()
                .find(|case| case.key.family == "W-JOINT" && case.key.scenario == "ordinary")
                .ok_or_else(|| {
                    crate::CiError::Message("refusal prior measured contract absent".into())
                })?;
            if prior.workload_contract
                != config
                    .output_directory
                    .join("windows-contract-template.json")
            {
                return Err(crate::CiError::Message(
                    "refusal prior contract differs from exact owned template".into(),
                ));
            }
            let prior_contract = bundle.copy(
                &prior.workload_contract,
                &row.join("prior-contract.json"),
                None,
            )?;
            let baseline_activation = bundle.copy(
                &config
                    .output_directory
                    .join("windows-policy-activation.json"),
                &row.join("baseline-activation.json"),
                None,
            )?;
            let prior_activation = bundle.copy(
                &config
                    .output_directory
                    .join("windows-policy-prior-activation.json"),
                &row.join("prior-activation.json"),
                None,
            )?;
            WindowsRefusalEvidence::AuthenticatedAdmission {
                baseline_policy,
                baseline_contract,
                prior_contract,
                prior_activation,
                prior_invocation: bundle.copy(
                    &config
                        .output_directory
                        .join("windows-policy-prior-activation.invocation.json"),
                    &row.join("prior-invocation.json"),
                    None,
                )?,
                prior_exit: bundle.copy(
                    &config
                        .output_directory
                        .join("windows-policy-prior-activation.exit.json"),
                    &row.join("prior-exit.json"),
                    None,
                )?,
                prior_stderr: bundle.copy(
                    &config
                        .output_directory
                        .join("windows-policy-prior-activation.stderr.bin"),
                    &row.join("prior-stderr.bin"),
                    None,
                )?,
                guardian_quiescence: bundle
                    .reference(&raw.join("native-guardian-quiescence.json"))?,
                frontend: bundle.reference(&raw.join("native-frontend.json"))?,
                baseline_activation,
                provider_request: bundle.reference(&raw.join("provider-request.bin"))?,
                requested_contract: bundle.reference(&raw.join("requested-contract.json"))?,
                quiescence,
                policy_apply: if changed {
                    Some(bundle.reference(&raw.join("policy-apply.stdout.json"))?)
                } else {
                    None
                },
                policy_restore: if changed {
                    Some(bundle.reference(&raw.join("policy-restore.stdout.json"))?)
                } else {
                    None
                },
            }
        };
        let semantic = SemanticObservation {
            format: "memcordon.consumer-readiness.semantic".into(),
            revision: 1,
            run_id: native.run_id.clone(),
            key: key.clone(),
            challenge: bundle.reference(&raw.join("challenge.bin"))?,
            operations: vec![OperationObservation {
                operation: if nul {
                    "argv-nul-rejected".into()
                } else {
                    "admission-refused".into()
                },
                attempt_id: native.attempt_id.clone(),
                root_pid: None,
                observer: "owned-native-preauthorization".into(),
                native_receipt: bundle.reference(&raw.join(if nul {
                    "native-argument-refusal.json"
                } else {
                    "result.json"
                }))?,
            }],
            comparisons: Vec::new(),
            counters: std::collections::BTreeMap::new(),
            negative_probe: None,
            component_test: None,
            component_actors: None,
            windows_capacity: None,
            windows_refusal: Some(refusal),
            fixture_behavior: None,
        };
        let semantic_path =
            bundle.retain(&row.join("semantic.json"), &serde_json::to_vec(&semantic)?)?;
        let request = if nul {
            bundle.copy(&active_source, &row.join("requested-contract.json"), None)?
        } else {
            bundle.reference(&raw.join("requested-contract.json"))?
        };
        let evidence = CaseEvidence {
            format: "memcordon.consumer-readiness.case".into(),
            revision: 1,
            key: key.clone(),
            run_id: native.run_id.clone(),
            source_commit: context.identity.source_commit.clone(),
            source_tree_sha256: context.identity.source_tree_sha256.clone(),
            lease_id: Some(context.lease_id.clone()),
            fixture: fixture.clone(),
            fixture_source: fixture_source.clone(),
            fixture_sha256: config.fixture.sha256.clone(),
            fixture_source_sha256: context.fixture_source.sha256.clone(),
            input: input_path,
            input_sha256: crate::windows_causal_acceptance::sha256(&input_bytes),
            invocation: invocation_path,
            request: Some(request),
            raw_result: Some(bundle.reference(&raw.join(if nul {
                "native-argument-refusal.json"
            } else {
                "result.json"
            }))?),
            provider_request: provider_request
                .as_ref()
                .map(|_| bundle.reference(&raw.join("provider-request.bin")))
                .transpose()?,
            authenticated_terminal: None,
            windows_loss: None,
            execution_invocation: None,
            execution_environment: None,
            transcript: Some(bundle.reference(&raw.join("native-quiescence.json"))?),
            inventory: None,
            qualification: None,
            export_receipt: None,
            prepared_observation: None,
            prepared_native_receipt: None,
            native_observation: native_path,
            retirement: retirement_path,
            semantic_observation: semantic_path,
            component_recipe_id: None,
        };
        let evidence_path =
            bundle.retain(&row.join("evidence.json"), &serde_json::to_vec(&evidence)?)?;
        records.push(CaseRecord {
            key,
            run_id: native.run_id,
            state: CaseState::Passed,
            reason: None,
            evidence: Some(evidence_path),
        });
    }
    Ok(WindowsNormalizedRows {
        records,
        artifacts: bundle.artifacts,
    })
}

#[cfg(windows)]
pub fn normalize_loss(
    context: &WindowsAdapterContext,
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    observed: &[crate::windows_readiness_faults::LossAssessment],
) -> crate::Result<WindowsNormalizedRows> {
    use crate::windows_consumer_readiness::native::read;
    use memcordon_readiness_verifier::*;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Recovery {
        schema_version: u32,
        provider_response: memcordon_core::WindowsProviderResponseV3,
        frontend_delivery: Option<memcordon_core::WindowsTerminalDeliveryEvidenceV1>,
    }
    if context.product.target != config.target
        || context.identity.source_commit != config.source_commit
        || context.lease_id.is_empty()
    {
        return Err(crate::CiError::Message(
            "Windows loss producer association differs".into(),
        ));
    }
    let mut bundle = Bundle {
        destination: context.destination.clone(),
        prefix: PathBuf::from(&context.product.target).join(&context.product.channel),
        artifacts: Vec::new(),
        held: Vec::new(),
    };
    let fixture = bundle.copy(
        &config.fixture.path,
        Path::new("windows-loss-fixture.exe"),
        Some(&config.fixture.sha256),
    )?;
    let fixture_source = bundle.copy(
        &context.fixture_source.path,
        Path::new("windows-loss-fixture-source.bin"),
        Some(&context.fixture_source.sha256),
    )?;
    let mut records = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for assessment in observed {
        if !crate::windows_readiness_faults::required_loss_keys().contains(&assessment.key) {
            return Err(crate::CiError::Message(
                "loss normalization received an unrelated row".into(),
            ));
        }
        let key = CaseKey {
            target: config.target.clone(),
            channel: Some(context.product.channel.clone()),
            evidence_class: EvidenceClass::InstalledProduct,
            family: assessment.key.family.clone(),
            scenario: assessment.key.scenario.clone(),
        };
        if !seen.insert(key.clone()) {
            return Err(crate::CiError::Message(
                "loss normalization duplicates a row".into(),
            ));
        }
        let source = config
            .output_directory
            .join(&key.family)
            .join(&key.scenario);
        let row = PathBuf::from("windows-loss")
            .join(&key.family)
            .join(&key.scenario);
        let raw = row.join("raw");
        if source.is_dir() {
            bundle.copy_directory(&source, &raw)?;
        }
        if let Some(reason) = [
            &assessment.collection,
            &assessment.behavior,
            &assessment.retirement,
        ]
        .into_iter()
        .find_map(|result| result.as_ref().err())
        {
            records.push(CaseRecord {
                key,
                run_id: context.identity.run_id.clone(),
                state: CaseState::Failed,
                reason: Some(reason.clone()),
                evidence: None,
            });
            continue;
        }
        let json = |name: &str| -> crate::Result<serde_json::Value> {
            let bytes = read(&source.join(name), 16 * 1024 * 1024)?;
            memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)
                .map_err(crate::CiError::Message)?;
            serde_json::from_slice(&bytes).map_err(Into::into)
        };
        let launch = json("native-invocation.json")?;
        let exit = json("native-exit.json")?;
        let invocation =
            normalize_public_invocation(&mut bundle, &row, &launch, &config.cli.sha256)?;
        let live: memcordon_core::WindowsGuardianAttemptObservation =
            serde_json::from_value(json("live-observation.json")?)?;
        let family = json("native-family-retirement.json")?;
        let recovery: Recovery = serde_json::from_value(json("recovery.stdout.json")?)?;
        let request_bytes = read(
            &source.join("provider-request.bin"),
            memcordon_core::WINDOWS_MAX_FRAME_BYTES,
        )?;
        let root = live
            .live_target_identity
            .as_ref()
            .ok_or_else(|| crate::CiError::Message("loss held root unavailable".into()))?;
        let request_sha256 = String::from(live.association.request_sha256.clone());
        let attempt_id = String::from(live.association.attempt_id.clone());
        if !live.is_consistent()
            || live.association.provider != config.provider
            || crate::windows_causal_acceptance::sha256(&request_bytes) != request_sha256
            || recovery.schema_version != 1
            || exit["capture_complete"] != true
        {
            return Err(crate::CiError::Message(
                "loss raw provider/native capture association differs".into(),
            ));
        }
        let members = family["processes"]
            .as_array()
            .ok_or_else(|| crate::CiError::Message("loss held native family absent".into()))?;
        let held=members.iter().map(|member|->crate::Result<HeldProcessIdentity>{
            if member["held_before_action"]!=true||member["retirement_observed"]!=true{return Err(crate::CiError::Message("loss native member was not held before action or retired".into()));}
            Ok(serde_json::from_value(serde_json::json!({"pid":member["pid"],"birth":member["birth"],"parent_pid":member["parent_pid"],"parent_birth":member["parent_birth"],"retirement_observed":member["retirement_observed"]}))?)
        }).collect::<crate::Result<Vec<_>>>()?;
        let original = if source.join("original-result.json").is_file() {
            Some(
                memcordon_core::ResultV1::parse(&read(
                    &source.join("original-result.json"),
                    crate::windows_causal_acceptance::MAX_REPORT_BYTES,
                )?)
                .map_err(crate::CiError::Message)?,
            )
        } else {
            None
        };
        if original.as_ref().is_some_and(|result| {
            result.invocation.association_sha256 != invocation.association_sha256
        }) {
            return Err(crate::CiError::Message(
                "loss original result differs from actual public invocation".into(),
            ));
        }
        let terminal = match &recovery.provider_response {
            memcordon_core::WindowsProviderResponseV3::Terminal(terminal) => Some(terminal),
            memcordon_core::WindowsProviderResponseV3::Reject { rejection, .. } => {
                rejection.terminal_receipt()
            }
            _ => None,
        };
        let (empty, relays, guardian, handles) = if let Some(terminal) = terminal {
            if terminal.attempt_id != attempt_id
                || terminal.request_sha256 != request_sha256
                || Some(terminal.nonce.as_str()) != live.live_nonce.as_deref()
                || terminal.validate_for_attempt().is_err()
            {
                return Err(crate::CiError::Message(
                    "loss recovered terminal differs from held original attempt".into(),
                ));
            }
            let proof = &terminal.retirement_proof;
            (
                proof.native_job_empty_observed,
                proof.relay_closure_observed,
                proof.guardian_completion_observed,
                proof.owner_capabilities_closed,
            )
        } else {
            if !matches!(
                &recovery.provider_response,
                memcordon_core::WindowsProviderResponseV3::TerminalRetiredV2(_)
            ) {
                return Err(crate::CiError::Message(
                    "loss recovery omitted real terminal or retired tombstone".into(),
                ));
            }
            let original = original.as_ref().ok_or_else(|| {
                crate::CiError::Message(
                    "loss tombstone lacks original actual selected result".into(),
                )
            })?;
            let memcordon_core::result_v1::RuntimeV1::WindowsSealed { observation } =
                &original.runtime
            else {
                return Err(crate::CiError::Message(
                    "loss tombstone lacks original native runtime projection".into(),
                ));
            };
            (
                observation.active_processes_zero,
                observation.relays_retired,
                observation.guardian_reaped,
                observation.final_job_handles_closed,
            )
        };
        let status =
            i32::try_from(exit["native_status"].as_i64().ok_or_else(|| {
                crate::CiError::Message("loss frontend native status absent".into())
            })?)
            .map_err(|_| {
                crate::CiError::Message("loss frontend status exceeds signed DWORD".into())
            })?;
        let native = NativeObservation {
            format: "memcordon.consumer-readiness.native".into(),
            revision: 1,
            run_id: context.identity.run_id.clone(),
            lease_id: Some(context.lease_id.clone()),
            target: config.target.clone(),
            executable_sha256: config.cli.sha256.clone(),
            invocation_sha256: invocation.association_sha256,
            execution_invocation_sha256: None,
            request_sha256: Some(request_sha256),
            provider_sha256: Some(config.installed_agent.sha256.clone()),
            provider_generation: Some(config.provider.generation.as_str().into()),
            runtime_manifest_sha256: Some(String::from(
                config.provider.runtime_manifest_sha256.clone(),
            )),
            attempt_id: Some(attempt_id),
            root_pid: Some(root.process_id),
            root_birth: Some(root.creation_time_100ns),
            attempt_nonce: live.live_nonce.clone(),
            held_processes: held,
            frontend_status: status,
            origin: OutcomeOrigin::ProviderFailure,
            target_status: None,
            authenticated_provider_exchange: true,
            relay_complete: exit["capture_complete"] == true,
            result_named_identity_verified: true,
            result_readback_verified: true,
            application_stage: None,
        };
        let retirement = RetirementObservation {
            format: "memcordon.consumer-readiness.retirement".into(),
            revision: 1,
            run_id: native.run_id.clone(),
            attempt_id: native.attempt_id.clone(),
            root_pid: native.root_pid,
            root_birth: native.root_birth,
            target_reaped_or_absent: native
                .held_processes
                .iter()
                .all(|process| process.retirement_observed),
            aggregate_empty: empty,
            relays_retired: relays,
            guardian_retired: guardian,
            native_handles_closed: handles,
            independently_observed: members.len() == 2,
            namespace_init_reaped: None,
            private_root_closed: None,
            exports_finalized: None,
            account_reservation_retired: None,
            final_job_handles_closed: Some(handles),
            active_processes_zero: Some(empty),
            outstanding: Vec::new(),
            failed_operations: Vec::new(),
        };
        let native_path = bundle.retain(&row.join("native.json"), &serde_json::to_vec(&native)?)?;
        let retirement_path = bundle.retain(
            &row.join("retirement.json"),
            &serde_json::to_vec(&retirement)?,
        )?;
        let challenge = read(&source.join("challenge.bin"), 32)?;
        if challenge.len() != 32 || challenge.iter().all(|byte| *byte == 0) {
            return Err(crate::CiError::Message(
                "loss fresh controller challenge unavailable".into(),
            ));
        }
        let input = FixtureInput {
            format: "memcordon.consumer-readiness.input".into(),
            revision: 1,
            run_id: native.run_id.clone(),
            key: key.clone(),
            challenge_sha256: crate::windows_causal_acceptance::sha256(&challenge),
            binary: Vec::new(),
            target_argv: NativeArguments::WindowsUtf16(invocation.arguments),
            deadline_millis: Some(600000),
            memory_bytes: Some(4 * 1024 * 1024 * 1024),
            toolchain_identity: None,
        };
        let input_bytes = serde_json::to_vec(&input)?;
        let input_path = bundle.retain(&row.join("input.json"), &input_bytes)?;
        let action = bundle.reference(&raw.join("native-loss-action.json"))?;
        let semantic = SemanticObservation {
            format: "memcordon.consumer-readiness.semantic".into(),
            revision: 1,
            run_id: native.run_id.clone(),
            key: key.clone(),
            challenge: bundle.reference(&raw.join("challenge.bin"))?,
            operations: [
                format!("fault-{}", key.scenario),
                "original-cause-retained".into(),
                "independent-retirement".into(),
            ]
            .into_iter()
            .map(|operation| OperationObservation {
                operation,
                attempt_id: native.attempt_id.clone(),
                root_pid: native.root_pid,
                observer: "owned-native-loss".into(),
                native_receipt: action.clone(),
            })
            .collect(),
            comparisons: Vec::new(),
            counters: std::collections::BTreeMap::new(),
            negative_probe: None,
            component_test: None,
            component_actors: None,
            windows_capacity: None,
            windows_refusal: None,
            fixture_behavior: None,
        };
        let semantic_path =
            bundle.retain(&row.join("semantic.json"), &serde_json::to_vec(&semantic)?)?;
        let loss = WindowsLossEvidence {
            action,
            live_observation: bundle.reference(&raw.join("live-observation.json"))?,
            original_result: original
                .as_ref()
                .map(|_| bundle.reference(&raw.join("original-result.json")))
                .transpose()?,
            native_family_retirement: bundle
                .reference(&raw.join("native-family-retirement.json"))?,
            recovery: bundle.reference(&raw.join("recovery.stdout.json"))?,
            recovery_invocation: bundle.reference(&raw.join("recovery-invocation.json"))?,
            recovery_process: bundle.reference(&raw.join("recovery-process.json"))?,
            recovery_stderr: bundle.reference(&raw.join("recovery.stderr.bin"))?,
            original_lease_owner: bundle
                .reference(&raw.join("original-windows-lease-owner.json"))?,
            original_deadlines: bundle.reference(&raw.join("original-windows-deadlines.json"))?,
            recovery_creation: bundle.reference(&raw.join("recovery-creation.json"))?,
            stdout: bundle.reference(&raw.join("stdout.bin"))?,
            stderr: bundle.reference(&raw.join("stderr.bin"))?,
            capture_failure: source
                .join("capture-failure.txt")
                .is_file()
                .then(|| bundle.reference(&raw.join("capture-failure.txt")))
                .transpose()?,
        };
        let evidence = CaseEvidence {
            format: "memcordon.consumer-readiness.case".into(),
            revision: 1,
            key: key.clone(),
            run_id: native.run_id.clone(),
            source_commit: context.identity.source_commit.clone(),
            source_tree_sha256: context.identity.source_tree_sha256.clone(),
            lease_id: Some(context.lease_id.clone()),
            fixture: fixture.clone(),
            fixture_source: fixture_source.clone(),
            fixture_sha256: config.fixture.sha256.clone(),
            fixture_source_sha256: context.fixture_source.sha256.clone(),
            input: input_path,
            input_sha256: crate::windows_causal_acceptance::sha256(&input_bytes),
            invocation: invocation.path,
            request: Some(bundle.reference(&raw.join("requested-contract.json"))?),
            raw_result: loss.original_result.clone(),
            provider_request: Some(bundle.reference(&raw.join("provider-request.bin"))?),
            authenticated_terminal: None,
            windows_loss: Some(loss),
            execution_invocation: None,
            execution_environment: None,
            transcript: None,
            inventory: None,
            qualification: None,
            export_receipt: None,
            prepared_observation: None,
            prepared_native_receipt: None,
            native_observation: native_path,
            retirement: retirement_path,
            semantic_observation: semantic_path,
            component_recipe_id: None,
        };
        let evidence_path =
            bundle.retain(&row.join("evidence.json"), &serde_json::to_vec(&evidence)?)?;
        records.push(CaseRecord {
            key,
            run_id: native.run_id,
            state: CaseState::Passed,
            reason: None,
            evidence: Some(evidence_path),
        });
    }
    Ok(WindowsNormalizedRows {
        records,
        artifacts: bundle.artifacts,
    })
}

/// Retains all support actors in their exact causal facets. Every vector member
/// is a distinct native execution; Rust harness cardinality is never invented.
#[cfg(windows)]
pub fn normalize_actors(
    context: &WindowsComponentAdapterContext,
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    input: &crate::windows_readiness_components::ComponentInput,
    observed: &[crate::windows_readiness_components::ComponentAssessment],
) -> crate::Result<WindowsNormalizedRows> {
    use crate::windows_consumer_readiness::native::read;
    use memcordon_core::WindowsSealedFault::*;
    use memcordon_readiness_verifier::*;
    use std::os::windows::ffi::OsStringExt;
    let facet = |fault: memcordon_core::WindowsSealedFault| match fault {
        GuardianKilledAfterAuthorization
        | FrontendDisconnectedAfterAuthorization
        | FrontendKilledAfterAuthorization
        | ControlWorkerKilledAfterAuthorization
        | ControlServiceKilledAfterAuthorization
        | LauncherWorkerKilledAfterAuthorization
        | LauncherServiceKilledAfterAuthorization
        | AllJobOwnersClosedAfterAuthorization => "postresume",
        Resume | TerminateJob | ActiveProcessQuery | RelayRetire | GuardianReap
        | FinalHandleClose => "cleanup",
        RecordRetire => "after-exit",
        _ => "preauthorization",
    };
    if context.identity.run_id != input.run_id
        || context.identity.source_commit != input.source_commit
        || config.source_commit != input.source_commit
        || config.target != input.native_target
        || input.features != ["test-support", "windows-sealed-runtime"]
        || serde_json::to_vec(&input.selected_components)?
            != serde_json::to_vec(&config.components)?
        || observed.len() > 41
    {
        return Err(crate::CiError::Message("support actors differ from separately measured original source/target/features/components".into()));
    }
    Bundle::relative(&input.artifact_prefix)?;
    let mut bundle = Bundle {
        destination: context.destination.clone(),
        prefix: input.artifact_prefix.clone(),
        artifacts: Vec::new(),
        held: Vec::new(),
    };
    let fixture = bundle.copy(
        &config.cli.path,
        Path::new("actor-executable.exe"),
        Some(&config.cli.sha256),
    )?;
    let fixture_source = bundle.copy(
        &context.fixture_source.path,
        Path::new("actor-source.bin"),
        Some(&context.fixture_source.sha256),
    )?;
    let raw = PathBuf::from("actors/raw");
    bundle.copy_directory(&config.output_directory.join("native-components"), &raw)?;
    let contract = bundle.copy(
        &config
            .output_directory
            .join("W-JOINT")
            .join("ordinary")
            .join("requested-contract.json"),
        Path::new("actors/requested-contract.json"),
        None,
    )?;
    let mut groups = std::collections::BTreeMap::<
        &str,
        Vec<(
            &crate::windows_readiness_components::ComponentAssessment,
            PathBuf,
        )>,
    >::new();
    let mut seen = std::collections::BTreeSet::new();
    for assessment in observed {
        let encoded = serde_json::to_vec(&assessment.selector)?;
        if !seen.insert(encoded) {
            return Err(crate::CiError::Message(
                "support actor selector executed more than once".into(),
            ));
        }
        let name = if assessment.selector["kind"] == "fault" {
            let selected: memcordon_core::WindowsSealedFault =
                serde_json::from_value(assessment.selector["fault"].clone())?;
            if !crate::windows_readiness_components::fault_selectors().contains(&selected) {
                return Err(crate::CiError::Message(
                    "unknown support fault selector".into(),
                ));
            }
            facet(selected)
        } else if assessment.selector["kind"] == "mutant" {
            let selected: memcordon_core::WindowsSealedMutant =
                serde_json::from_value(assessment.selector["mutant"].clone())?;
            if !crate::windows_readiness_components::envelope_mutants().contains(&selected) {
                return Err(crate::CiError::Message(
                    "unknown support mutant selector".into(),
                ));
            }
            "preauthorization"
        } else {
            return Err(crate::CiError::Message(
                "support actor has unknown execution kind".into(),
            ));
        };
        let artifact = assessment.artifacts.first().ok_or_else(|| {
            crate::CiError::Message("support actor lacks owned source artifacts".into())
        })?;
        let directory = artifact
            .path
            .parent()
            .ok_or_else(|| crate::CiError::Message("support actor source directory absent".into()))?
            .to_owned();
        let relative = directory
            .strip_prefix(config.output_directory.join("native-components"))
            .map_err(|_| {
                crate::CiError::Message("support actor source escapes owned component root".into())
            })?;
        Bundle::relative(relative)?;
        groups
            .entry(name)
            .or_default()
            .push((assessment, directory));
    }
    let mut records = Vec::new();
    for (scenario, expected) in [
        ("preauthorization", 26),
        ("postresume", 8),
        ("cleanup", 6),
        ("after-exit", 1),
    ] {
        let key = CaseKey {
            target: input.native_target.clone(),
            channel: None,
            evidence_class: EvidenceClass::NativeComponentRegression,
            family: "W-CAUSAL".into(),
            scenario: scenario.into(),
        };
        let members = groups.remove(scenario).unwrap_or_default();
        let reason = if members.len() != expected {
            Some(format!(
                "actual {scenario} support vector has {} of {expected} distinct executions",
                members.len()
            ))
        } else {
            members.iter().find_map(|(row, _)| {
                [&row.collection, &row.behavior, &row.retirement]
                    .into_iter()
                    .find_map(|result| result.as_ref().err().cloned())
            })
        };
        if let Some(reason) = reason {
            records.push(CaseRecord {
                key,
                run_id: input.run_id.clone(),
                state: CaseState::Failed,
                reason: Some(reason),
                evidence: None,
            });
            continue;
        }
        let row = PathBuf::from("actors/normalized").join(scenario);
        let mut actors = Vec::new();
        for (assessment, directory) in &members {
            let relative = directory
                .strip_prefix(config.output_directory.join("native-components"))
                .expect("checked owned actor root");
            let reference = |name: &str| bundle.reference(&raw.join(relative).join(name));
            let optional = |name: &str| -> crate::Result<Option<String>> {
                directory
                    .join(name)
                    .try_exists()?
                    .then(|| reference(name))
                    .transpose()
            };
            actors.push(ComponentActor {
                recipe_id: input.recipe_id.clone(),
                selection_kind: assessment.selector["kind"]
                    .as_str()
                    .expect("checked selector kind")
                    .into(),
                selection: reference("selection.json")?,
                invocation: reference("actor-invocation.json")?,
                exit: reference("actor-exit.json")?,
                observation: reference("native-observation.json")?,
                provider_request: reference("provider-request.bin")?,
                stdout: reference("stdout.bin")?,
                stderr: reference("stderr.bin")?,
                actor_held: reference("held-frontend-before.json")?,
                native_retirement: reference("native-actor-retirement.json")?,
                control_worker_site: optional("control-worker-native.json")?,
                control_worker_held: optional("held-control-worker-before.json")?,
                settlement_inventory: reference("recovery.json")?,
                settlement_invocation: reference("recovery-invocation.json")?,
                settlement_exit: reference("recovery-exit.json")?,
                settlement_stderr: reference("recovery.stderr.bin")?,
                settlement_deadline: input
                    .artifact_prefix
                    .parent()
                    .ok_or_else(|| {
                        crate::CiError::Message("actor original compiler scope absent".into())
                    })?
                    .join("roles/compiler/native-operation-deadline.json")
                    .to_string_lossy()
                    .replace('\\', "/"),
                held_before: optional("held-before-fault.json")?,
                held_after: optional("held-after-fault.json")?,
                worker_exit: if directory
                    .join("held-control-worker-exit.json")
                    .try_exists()?
                {
                    optional("held-control-worker-exit.json")?
                } else {
                    optional("held-worker-exit.json")?
                },
                frontend_exit: optional("held-frontend-exit.json")?,
                recovery: optional("terminal-recovery.json")?,
                recovery_invocation: optional("terminal-recovery-invocation.json")?,
                recovery_exit: optional("terminal-recovery-exit.json")?,
                recovery_stderr: optional("terminal-recovery.stderr.bin")?,
            });
        }
        let source = &members[0].1;
        let json = |name: &str| -> crate::Result<serde_json::Value> {
            let bytes = read(&source.join(name), 32 * 1024 * 1024)?;
            memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)
                .map_err(crate::CiError::Message)?;
            serde_json::from_slice(&bytes).map_err(Into::into)
        };
        let launch = json("actor-invocation.json")?;
        let exit = json("actor-exit.json")?;
        let held = json("held-frontend-before.json")?;
        let retired = json("native-actor-retirement.json")?;
        let observation = json("native-observation.json")?;
        if launch["run_id"] != input.run_id
            || launch["recipe_id"] != input.recipe_id
            || launch["executable_sha256"] != config.cli.sha256
            || launch["environment_cleared"] != true
            || exit["capture_complete"] != true
            || exit["executable_sha256"] != config.cli.sha256
            || held["held_before_execution"] != true
            || held["native_live_before_release"] != true
            || retired["held_before_execution"] != true
            || retired["retirement_observed"] != true
            || retired["image_sha256"] != config.cli.sha256
            || held["process_id"] != retired["process_id"]
            || held["creation_time_100ns"] != retired["creation_time_100ns"]
        {
            return Err(crate::CiError::Message("support actor execution was not held live before release and retired under measured native identity".into()));
        }
        let status = i32::try_from(
            exit["native_status"]
                .as_i64()
                .ok_or_else(|| crate::CiError::Message("actor native status absent".into()))?,
        )
        .map_err(|_| crate::CiError::Message("actor status exceeds DWORD projection".into()))?;
        if retired["native_status"].as_u64() != Some(u64::from(status as u32)) {
            return Err(crate::CiError::Message(
                "actor held wait status differs from captured exit".into(),
            ));
        }
        let pid = u32::try_from(
            held["process_id"]
                .as_u64()
                .ok_or_else(|| crate::CiError::Message("actor held PID absent".into()))?,
        )
        .map_err(|_| crate::CiError::Message("actor PID exceeds DWORD".into()))?;
        let birth = held["creation_time_100ns"]
            .as_u64()
            .ok_or_else(|| crate::CiError::Message("actor native birth absent".into()))?;
        let program: Vec<u16> = serde_json::from_value(launch["program_utf16"].clone())?;
        let argv: Vec<Vec<u16>> = serde_json::from_value(launch["argv_utf16"].clone())?;
        let arguments: Vec<Vec<u16>> = std::iter::once(program).chain(argv).collect();
        let report = memcordon_core::InvocationReport {
            syntax: "plus-budgets-v1".into(),
            budget_tokens: Vec::new(),
            memory_token: None,
            deadline_token: None,
            argv: arguments
                .iter()
                .map(|arg| {
                    memcordon_core::NativeArgument::from_os(&std::ffi::OsString::from_wide(arg))
                })
                .collect(),
        };
        let association = crate::windows_causal_acceptance::sha256(&serde_json::to_vec(&report)?);
        let environment = serde_json::to_vec(&NativeEnvironment::WindowsUtf16(Vec::new()))?;
        let environment_path = bundle.retain(&row.join("environment.json"), &environment)?;
        let invocation = NativeInvocation {
            format: "memcordon.consumer-readiness.invocation".into(),
            revision: 1,
            arguments: NativeArguments::WindowsUtf16(arguments.clone()),
            executable_sha256: config.cli.sha256.clone(),
            environment: environment_path,
            environment_sha256: crate::windows_causal_acceptance::sha256(&environment),
            association_sha256: association.clone(),
            budget_tokens: Vec::new(),
            memory_token: None,
            deadline_token: None,
        };
        let invocation_path = bundle.retain(
            &row.join("invocation.json"),
            &serde_json::to_vec(&invocation)?,
        )?;
        let provider_request = serde_json::to_vec(&serde_json::from_value::<
            memcordon_core::WindowsLaunchRequestV1,
        >(observation["launch"].clone())?)?;
        let request_sha256 = crate::windows_causal_acceptance::sha256(&provider_request);
        if observation["request_sha256"] != request_sha256
            || !observation["capture_failure"].is_null()
        {
            return Err(crate::CiError::Message(
                "actor captured request serialization or custody differs".into(),
            ));
        }
        let request_path = bundle.retain(&row.join("provider-request.bin"), &provider_request)?;
        let native = NativeObservation {
            format: "memcordon.consumer-readiness.native".into(),
            revision: 1,
            run_id: input.run_id.clone(),
            lease_id: None,
            target: input.native_target.clone(),
            executable_sha256: config.cli.sha256.clone(),
            invocation_sha256: association,
            execution_invocation_sha256: None,
            request_sha256: Some(request_sha256),
            provider_sha256: Some(config.installed_agent.sha256.clone()),
            provider_generation: Some(config.provider.generation.as_str().into()),
            runtime_manifest_sha256: Some(String::from(
                config.provider.runtime_manifest_sha256.clone(),
            )),
            attempt_id: observation["attempt_id"].as_str().map(str::to_owned),
            root_pid: Some(pid),
            root_birth: Some(birth),
            attempt_nonce: observation["launch"]["nonce"].as_str().map(str::to_owned),
            held_processes: vec![HeldProcessIdentity {
                pid,
                birth,
                parent_pid: None,
                parent_birth: None,
                retirement_observed: true,
            }],
            frontend_status: status,
            origin: OutcomeOrigin::ComponentRegression,
            target_status: Some(status),
            authenticated_provider_exchange: true,
            relay_complete: true,
            result_named_identity_verified: true,
            result_readback_verified: true,
            application_stage: None,
        };
        let retirement = RetirementObservation {
            format: "memcordon.consumer-readiness.retirement".into(),
            revision: 1,
            run_id: input.run_id.clone(),
            attempt_id: native.attempt_id.clone(),
            root_pid: Some(pid),
            root_birth: Some(birth),
            target_reaped_or_absent: true,
            aggregate_empty: false,
            relays_retired: false,
            guardian_retired: false,
            native_handles_closed: false,
            independently_observed: true,
            namespace_init_reaped: None,
            private_root_closed: None,
            exports_finalized: None,
            account_reservation_retired: None,
            final_job_handles_closed: None,
            active_processes_zero: None,
            outstanding: Vec::new(),
            failed_operations: Vec::new(),
        };
        let native_path = bundle.retain(&row.join("native.json"), &serde_json::to_vec(&native)?)?;
        let retirement_path = bundle.retain(
            &row.join("retirement.json"),
            &serde_json::to_vec(&retirement)?,
        )?;
        let challenge = read(&source.join("challenge.bin"), 32)?;
        if challenge.len() != 32 || challenge.iter().all(|byte| *byte == 0) {
            return Err(crate::CiError::Message(
                "actor fresh challenge unavailable".into(),
            ));
        }
        let input_bytes = serde_json::to_vec(&FixtureInput {
            format: "memcordon.consumer-readiness.input".into(),
            revision: 1,
            run_id: input.run_id.clone(),
            key: key.clone(),
            challenge_sha256: crate::windows_causal_acceptance::sha256(&challenge),
            binary: Vec::new(),
            target_argv: NativeArguments::WindowsUtf16(arguments),
            deadline_millis: None,
            memory_bytes: None,
            toolchain_identity: None,
        })?;
        let input_path = bundle.retain(&row.join("input.json"), &input_bytes)?;
        let source_relative = source
            .strip_prefix(config.output_directory.join("native-components"))
            .expect("checked source root");
        let semantic = SemanticObservation {
            format: "memcordon.consumer-readiness.semantic".into(),
            revision: 1,
            run_id: input.run_id.clone(),
            key: key.clone(),
            challenge: bundle.reference(&raw.join(source_relative).join("challenge.bin"))?,
            operations: Vec::new(),
            comparisons: Vec::new(),
            counters: std::collections::BTreeMap::from([(
                "actors_executed".into(),
                members.len() as u64,
            )]),
            negative_probe: None,
            component_test: None,
            component_actors: Some(actors),
            windows_capacity: None,
            windows_refusal: None,
            fixture_behavior: None,
        };
        let semantic_path =
            bundle.retain(&row.join("semantic.json"), &serde_json::to_vec(&semantic)?)?;
        let evidence = CaseEvidence {
            format: "memcordon.consumer-readiness.case".into(),
            revision: 1,
            key: key.clone(),
            run_id: input.run_id.clone(),
            source_commit: input.source_commit.clone(),
            source_tree_sha256: context.identity.source_tree_sha256.clone(),
            lease_id: None,
            fixture: fixture.clone(),
            fixture_source: fixture_source.clone(),
            fixture_sha256: config.cli.sha256.clone(),
            fixture_source_sha256: context.fixture_source.sha256.clone(),
            input: input_path,
            input_sha256: crate::windows_causal_acceptance::sha256(&input_bytes),
            invocation: invocation_path,
            request: Some(contract.clone()),
            provider_request: Some(request_path),
            raw_result: None,
            authenticated_terminal: None,
            windows_loss: None,
            execution_invocation: None,
            execution_environment: None,
            transcript: None,
            inventory: None,
            qualification: None,
            export_receipt: None,
            prepared_observation: None,
            prepared_native_receipt: None,
            native_observation: native_path,
            retirement: retirement_path,
            semantic_observation: semantic_path,
            component_recipe_id: Some(input.recipe_id.clone()),
        };
        let evidence_path =
            bundle.retain(&row.join("evidence.json"), &serde_json::to_vec(&evidence)?)?;
        records.push(CaseRecord {
            key,
            run_id: input.run_id.clone(),
            state: CaseState::Passed,
            reason: None,
            evidence: Some(evidence_path),
        });
    }
    Ok(WindowsNormalizedRows {
        records,
        artifacts: bundle.artifacts,
    })
}

#[cfg(windows)]
pub fn normalize_native_tests(
    context: &WindowsComponentAdapterContext,
    input: &crate::windows_readiness_native_tests::NativeTestInput,
    observed: &[crate::windows_readiness_native_tests::NativeTestAssessment],
) -> crate::Result<WindowsNormalizedRows> {
    use memcordon_readiness_verifier::*;
    use std::os::windows::ffi::OsStringExt;
    if context.identity.run_id != input.run_id
        || !context.destination.is_absolute()
        || observed.len() > 32
    {
        return Err(crate::CiError::Message(
            "native component normalization differs from original producer run or finite scope"
                .into(),
        ));
    }
    Bundle::relative(&input.artifact_prefix)?;
    let mut bundle = Bundle {
        destination: context.destination.clone(),
        prefix: input.artifact_prefix.clone(),
        artifacts: Vec::new(),
        held: Vec::new(),
    };
    let fixture = bundle.copy(
        &input.executable.path,
        Path::new("native-test-executable.exe"),
        Some(&input.executable.sha256),
    )?;
    let fixture_source = bundle.copy(
        &context.fixture_source.path,
        Path::new("native-test-source.bin"),
        Some(&context.fixture_source.sha256),
    )?;
    let mut records = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for assessment in observed {
        let stdin = assessment
            .artifacts
            .iter()
            .find(|artifact| {
                artifact
                    .path
                    .file_name()
                    .is_some_and(|name| name == "stdin.json")
            })
            .ok_or_else(|| {
                crate::CiError::Message(
                    "native component assessment omits actual prelaunch input capture".into(),
                )
            })?;
        let source_directory = stdin
            .path
            .parent()
            .ok_or_else(|| crate::CiError::Message("native test source directory absent".into()))?;
        let relative = source_directory
            .strip_prefix(&input.output_directory)
            .map_err(|_| {
                crate::CiError::Message("native test source escapes owned component output".into())
            })?;
        Bundle::relative(relative)?;
        for artifact in &assessment.artifacts {
            let path = artifact
                .path
                .strip_prefix(&input.output_directory)
                .map_err(|_| {
                    crate::CiError::Message(
                        "native test artifact escapes its original output root".into(),
                    )
                })?;
            bundle.copy(&artifact.path, path, Some(&artifact.sha256))?;
        }
        for scenario in &assessment.scenarios {
            // The actual OS sharing failure is the rename row; the physical
            // matrix still remains in custody and covers its other phases.
            if assessment.test_name == crate::windows_readiness_native_tests::WRITER_MATRIX
                && scenario == "rename-error"
                && observed.iter().any(|other| {
                    other.test_name == crate::windows_readiness_native_tests::WRITER_NATIVE_RENAME
                })
            {
                continue;
            }
            let key = CaseKey {
                target: input.native_target.clone(),
                channel: None,
                evidence_class: EvidenceClass::NativeComponentRegression,
                family: assessment.family.clone(),
                scenario: scenario.clone(),
            };
            if !seen.insert(key.clone()) {
                return Err(crate::CiError::Message(
                    "native component normalization duplicates a frozen row".into(),
                ));
            }
            let failed = [
                &assessment.collection,
                &assessment.behavior,
                &assessment.retirement,
            ]
            .into_iter()
            .find_map(|result| result.as_ref().err());
            if let Some(reason) = failed {
                records.push(CaseRecord {
                    key,
                    run_id: input.run_id.clone(),
                    state: CaseState::Failed,
                    reason: Some(reason.clone()),
                    evidence: None,
                });
                continue;
            }
            let raw = |name: &str| -> crate::Result<serde_json::Value> {
                let bytes = crate::windows_consumer_readiness::native::read(
                    &source_directory.join(name),
                    4 * 1024 * 1024,
                )?;
                memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)
                    .map_err(crate::CiError::Message)?;
                serde_json::from_slice(&bytes).map_err(Into::into)
            };
            let launch = raw("native-invocation.json")?;
            let exit = raw("native-exit.json")?;
            let retirement = raw("native-retirement.json")?;
            let argv: Vec<Vec<u16>> = serde_json::from_value(launch["argv_utf16"].clone())?;
            let program: Vec<u16> = serde_json::from_value(launch["program_utf16"].clone())?;
            if launch["environment_cleared"] != true
                || launch["run_id"] != input.run_id
                || launch["recipe_id"] != input.recipe_id
                || launch["executable_sha256"] != input.executable.sha256
                || exit["capture_complete"] != true
                || exit["run_id"] != input.run_id
                || exit["recipe_id"] != input.recipe_id
                || exit["executable_sha256"] != input.executable.sha256
                || retirement["held_before_input_delivery"] != true
                || retirement["retirement_observed"] != true
                || retirement["same_image_helpers_absent"] != true
                || retirement["image_sha256"] != input.executable.sha256
            {
                return Err(crate::CiError::Message(
                    "native component raw capture/retirement binding differs".into(),
                ));
            }
            let status =
                i32::try_from(exit["native_status"].as_i64().ok_or_else(|| {
                    crate::CiError::Message("native test status unavailable".into())
                })?)
                .map_err(|_| {
                    crate::CiError::Message(
                        "native test status exceeds signed DWORD projection".into(),
                    )
                })?;
            let pid = u32::try_from(retirement["process_id"].as_u64().ok_or_else(|| {
                crate::CiError::Message("native test held PID unavailable".into())
            })?)
            .map_err(|_| crate::CiError::Message("native test PID exceeds DWORD".into()))?;
            let birth = retirement["creation_time_100ns"].as_u64().ok_or_else(|| {
                crate::CiError::Message("native test held birth unavailable".into())
            })?;
            let arguments: Vec<Vec<u16>> = std::iter::once(program).chain(argv).collect();
            let public = memcordon_core::InvocationReport {
                syntax: "plus-budgets-v1".into(),
                budget_tokens: Vec::new(),
                memory_token: None,
                deadline_token: None,
                argv: arguments
                    .iter()
                    .map(|argument| {
                        memcordon_core::NativeArgument::from_os(&std::ffi::OsString::from_wide(
                            argument,
                        ))
                    })
                    .collect(),
            };
            let association =
                crate::windows_causal_acceptance::sha256(&serde_json::to_vec(&public)?);
            let row = relative
                .join("normalized")
                .join(format!("{}-{scenario}", assessment.family));
            let environment = serde_json::to_vec(&NativeEnvironment::WindowsUtf16(Vec::new()))?;
            let environment_reference =
                bundle.retain(&row.join("environment.json"), &environment)?;
            let invocation = NativeInvocation {
                format: "memcordon.consumer-readiness.invocation".into(),
                revision: 1,
                arguments: NativeArguments::WindowsUtf16(arguments.clone()),
                executable_sha256: input.executable.sha256.clone(),
                environment: environment_reference,
                environment_sha256: crate::windows_causal_acceptance::sha256(&environment),
                association_sha256: association.clone(),
                budget_tokens: Vec::new(),
                memory_token: None,
                deadline_token: None,
            };
            let invocation = bundle.retain(
                &row.join("invocation.json"),
                &serde_json::to_vec(&invocation)?,
            )?;
            let challenge = crate::windows_consumer_readiness::native::read(
                &source_directory.join("challenge.bin"),
                32,
            )?;
            if challenge.len() != 32 || challenge.iter().all(|byte| *byte == 0) {
                return Err(crate::CiError::Message(
                    "native test actual controller challenge missing".into(),
                ));
            }
            let fixture_input = FixtureInput {
                format: "memcordon.consumer-readiness.input".into(),
                revision: 1,
                run_id: input.run_id.clone(),
                key: key.clone(),
                challenge_sha256: crate::windows_causal_acceptance::sha256(&challenge),
                binary: Vec::new(),
                target_argv: NativeArguments::WindowsUtf16(arguments),
                deadline_millis: None,
                memory_bytes: None,
                toolchain_identity: None,
            };
            let fixture_input_bytes = serde_json::to_vec(&fixture_input)?;
            let fixture_input_path =
                bundle.retain(&row.join("input.json"), &fixture_input_bytes)?;
            let native = NativeObservation {
                format: "memcordon.consumer-readiness.native".into(),
                revision: 1,
                run_id: input.run_id.clone(),
                lease_id: None,
                target: input.native_target.clone(),
                executable_sha256: input.executable.sha256.clone(),
                invocation_sha256: association,
                execution_invocation_sha256: None,
                request_sha256: None,
                provider_sha256: None,
                provider_generation: None,
                runtime_manifest_sha256: None,
                attempt_id: None,
                root_pid: Some(pid),
                root_birth: Some(birth),
                attempt_nonce: None,
                held_processes: vec![HeldProcessIdentity {
                    pid,
                    birth,
                    parent_pid: None,
                    parent_birth: None,
                    retirement_observed: true,
                }],
                frontend_status: status,
                origin: OutcomeOrigin::ComponentRegression,
                target_status: Some(status),
                authenticated_provider_exchange: false,
                relay_complete: exit["capture_complete"] == true,
                result_named_identity_verified: true,
                result_readback_verified: true,
                application_stage: None,
            };
            let native = bundle.retain(&row.join("native.json"), &serde_json::to_vec(&native)?)?;
            let retired = RetirementObservation {
                format: "memcordon.consumer-readiness.retirement".into(),
                revision: 1,
                run_id: input.run_id.clone(),
                attempt_id: None,
                root_pid: Some(pid),
                root_birth: Some(birth),
                target_reaped_or_absent: retirement["retirement_observed"] == true,
                aggregate_empty: retirement["same_image_helpers_absent"] == true,
                relays_retired: exit["capture_complete"] == true,
                guardian_retired: false,
                native_handles_closed: false,
                independently_observed: retirement["held_before_input_delivery"] == true,
                namespace_init_reaped: None,
                private_root_closed: None,
                exports_finalized: None,
                account_reservation_retired: None,
                final_job_handles_closed: None,
                active_processes_zero: None,
                outstanding: Vec::new(),
                failed_operations: Vec::new(),
            };
            let retired =
                bundle.retain(&row.join("retirement.json"), &serde_json::to_vec(&retired)?)?;
            let semantic = SemanticObservation {
                format: "memcordon.consumer-readiness.semantic".into(),
                revision: 1,
                run_id: input.run_id.clone(),
                key: key.clone(),
                challenge: bundle.reference(&relative.join("challenge.bin"))?,
                operations: Vec::new(),
                comparisons: Vec::new(),
                counters: std::collections::BTreeMap::new(),
                negative_probe: None,
                component_test: Some(ComponentTest {
                    fixture_acquisition: None,
                    recipe_id: input.recipe_id.clone(),
                    test_name: assessment.test_name.clone(),
                    native_exit: status,
                    tests_executed: 1,
                    tests_failed: 0,
                    tests_ignored: 0,
                    raw_test_output: bundle.reference(&relative.join("stdout.bin"))?,
                    native_receipt: bundle
                        .reference(&relative.join("authority").join("native-receipt.json"))?,
                    native_retirement: Some(
                        bundle.reference(&relative.join("native-retirement.json"))?,
                    ),
                }),
                component_actors: None,
                windows_capacity: None,
                windows_refusal: None,
                fixture_behavior: None,
            };
            let semantic =
                bundle.retain(&row.join("semantic.json"), &serde_json::to_vec(&semantic)?)?;
            let evidence = CaseEvidence {
                format: "memcordon.consumer-readiness.case".into(),
                revision: 1,
                key: key.clone(),
                run_id: input.run_id.clone(),
                source_commit: context.identity.source_commit.clone(),
                source_tree_sha256: context.identity.source_tree_sha256.clone(),
                lease_id: None,
                fixture: fixture.clone(),
                fixture_source: fixture_source.clone(),
                fixture_sha256: input.executable.sha256.clone(),
                fixture_source_sha256: context.fixture_source.sha256.clone(),
                input: fixture_input_path,
                input_sha256: crate::windows_causal_acceptance::sha256(&fixture_input_bytes),
                invocation,
                request: None,
                raw_result: None,
                provider_request: None,
                authenticated_terminal: None,
                windows_loss: None,
                execution_invocation: None,
                execution_environment: None,
                transcript: None,
                inventory: None,
                qualification: None,
                export_receipt: None,
                prepared_observation: None,
                prepared_native_receipt: None,
                native_observation: native,
                retirement: retired,
                semantic_observation: semantic,
                component_recipe_id: Some(input.recipe_id.clone()),
            };
            let evidence =
                bundle.retain(&row.join("evidence.json"), &serde_json::to_vec(&evidence)?)?;
            records.push(CaseRecord {
                key,
                run_id: input.run_id.clone(),
                state: CaseState::Passed,
                reason: None,
                evidence: Some(evidence),
            });
        }
    }
    Ok(WindowsNormalizedRows {
        records,
        artifacts: bundle.artifacts,
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsRemovalPlan {
    /// Exact paths from the measured package inspection and install receipt.
    pub binary_root: PathBuf,
    pub state_root: PathBuf,
    pub policy_root: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsRemovalObservation {
    pub format: String,
    pub revision: u32,
    pub provider_generation: String,
    pub absent_services: Vec<String>,
    pub absent_paths: Vec<PathBuf>,
    pub installed_image_processes_absent: bool,
    pub fixture_processes_absent: bool,
    pub receipt: crate::windows_installed_cases::SelectedArtifact,
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn absent_owned_services(
    deadline: std::time::Instant,
) -> crate::Result<(Vec<String>, Vec<serde_json::Value>)> {
    use windows_sys::Win32::Foundation::{ERROR_SERVICE_DOES_NOT_EXIST, GetLastError};
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS,
    };
    struct Manager(windows_sys::Win32::System::Services::SC_HANDLE);
    impl Drop for Manager {
        fn drop(&mut self) {
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }
    // SAFETY: read-only local SCM access, with no remote host or database input.
    let raw = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if raw.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    let manager = Manager(raw);
    let mut names = crate::windows_owned_guardian::guardian_slot_names();
    names.extend(
        [
            memcordon_core::WINDOWS_CONTROL_SERVICE_NAME,
            memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME,
            memcordon_core::WINDOWS_SESSION_BROKER_SERVICE_NAME,
        ]
        .map(str::to_owned),
    );
    let mut observed = Vec::new();
    for name in &names {
        if std::time::Instant::now() >= deadline {
            return Err(crate::CiError::Message(
                "reserved cleanup deadline expired during SCM absence observation".into(),
            ));
        }
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: fixed owned service name is terminated; manager remains held.
        let service = unsafe { OpenServiceW(manager.0, wide.as_ptr(), SERVICE_QUERY_STATUS) };
        if !service.is_null() {
            unsafe {
                CloseServiceHandle(service);
            }
            return Err(crate::CiError::Message(format!(
                "owned service remains after uninstall: {name}"
            )));
        }
        let code = unsafe { GetLastError() };
        if code != ERROR_SERVICE_DOES_NOT_EXIST {
            return Err(std::io::Error::from_raw_os_error(code as i32).into());
        }
        observed.push(serde_json::json!({"service_name":name,"api":"OpenServiceW","native_domain":"win32","native_code":code}));
    }
    Ok((names, observed))
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn absent_component_processes(
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    deadline: std::time::Instant,
) -> crate::Result<()> {
    use std::os::windows::{ffi::OsStrExt, io::FromRawHandle};
    use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, GetLastError, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    };
    let fold = |units: &[u16]| {
        units
            .iter()
            .map(|unit| {
                if (65..=90).contains(unit) {
                    unit + 32
                } else {
                    *unit
                }
            })
            .collect::<Vec<_>>()
    };
    let mut names = std::collections::BTreeSet::new();
    for artifact in config
        .installed_components
        .iter()
        .chain(std::iter::once(&config.installed_agent))
    {
        let name = artifact
            .path
            .file_name()
            .ok_or_else(|| crate::CiError::Message("installed image name missing".into()))?;
        let units: Vec<u16> = name.encode_wide().collect();
        if units.iter().any(|unit| *unit > 127) {
            return Err(crate::CiError::Message(
                "installed component census requires exact ASCII package image names".into(),
            ));
        }
        names.insert(fold(&units));
    }
    // SAFETY: read-only local process snapshot; ownership closes its handle on
    // every exit. Only package image-name candidates are queried below.
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error().into());
    }
    let _snapshot = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw) };
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut available = unsafe { Process32FirstW(raw, &mut entry) };
    let mut count = 0;
    while available != 0 {
        if std::time::Instant::now() >= deadline {
            return Err(crate::CiError::Message(
                "reserved cleanup deadline expired during native process census".into(),
            ));
        }
        count += 1;
        if count > 32768 {
            return Err(crate::CiError::Message(
                "native removal process census exceeded finite bound".into(),
            ));
        }
        let length = entry
            .szExeFile
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(entry.szExeFile.len());
        if names.contains(&fold(&entry.szExeFile[..length])) {
            // Fail closed even for another local process using a package image
            // name; it cannot silently substitute for absent owned processes.
            let process =
                unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, entry.th32ProcessID) };
            if process.is_null() {
                return Err(std::io::Error::last_os_error().into());
            }
            let _process = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(process) };
            let mut image = vec![0u16; 32768];
            let mut length = image.len() as u32;
            if unsafe { QueryFullProcessImageNameW(process, 0, image.as_mut_ptr(), &mut length) }
                == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            return Err(crate::CiError::Message(
                "a native package-image process remains after uninstall".into(),
            ));
        }
        available = unsafe { Process32NextW(raw, &mut entry) };
    }
    let code = unsafe { GetLastError() };
    if code != ERROR_NO_MORE_FILES {
        return Err(std::io::Error::from_raw_os_error(code as i32).into());
    }
    Ok(())
}

/// Distinct from installed-generation recovery: missing services are checked as
/// removal facts, never interpreted as a successful recovery response.
#[cfg(windows)]
pub fn observe_removed(
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    plan: &WindowsRemovalPlan,
    output_directory: &Path,
    cleanup_deadline: std::time::Instant,
) -> crate::Result<WindowsRemovalObservation> {
    if std::time::Instant::now() >= cleanup_deadline {
        return Err(crate::CiError::Message(
            "Windows removal observation exhausted reserved cleanup deadline".into(),
        ));
    }
    let mut paths = vec![
        plan.binary_root.clone(),
        plan.state_root.clone(),
        plan.policy_root.clone(),
        config.installed_agent.path.clone(),
        config.installed_manifest.path.clone(),
    ];
    paths.extend(
        config
            .installed_components
            .iter()
            .map(|artifact| artifact.path.clone()),
    );
    paths.sort();
    paths.dedup();
    let mut ancestry = Vec::new();
    let mut path_observations = Vec::new();
    for path in &paths {
        if std::time::Instant::now() >= cleanup_deadline {
            return Err(crate::CiError::Message(
                "reserved cleanup deadline expired during named removal observation".into(),
            ));
        }
        if !path.is_absolute()
            || path.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(crate::CiError::Message(
                "removal observation needs exact normalized measured absolute paths".into(),
            ));
        }
        let mut parent = path
            .parent()
            .ok_or_else(|| crate::CiError::Message("removal path has no parent".into()))?;
        while !parent.try_exists()? {
            parent = parent.parent().ok_or_else(|| {
                crate::CiError::Message("removal path has no existing custody ancestor".into())
            })?;
        }
        ancestry.extend(hold_ancestors(parent)?);
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let code = error.raw_os_error().ok_or_else(|| {
                    crate::CiError::Message(
                        "named removal absence has no actual native error code".into(),
                    )
                })?;
                if ![2, 3].contains(&code) {
                    return Err(error.into());
                }
                path_observations.push(
                    serde_json::json!({"path":path,"native_domain":"win32","native_code":code}),
                );
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(crate::CiError::Message(format!(
                    "owned package path remains after uninstall: {}",
                    path.display()
                )));
            }
        }
    }
    let (absent_services, service_observations) = absent_owned_services(cleanup_deadline)?;
    absent_component_processes(config, cleanup_deadline)?;
    if !memcordon_testkit::windows_processes_for_image(&config.fixture.path)?.is_empty() {
        return Err(crate::CiError::Message(
            "owned fixture family remains after package uninstall".into(),
        ));
    }
    // Recheck every named absence after the SCM and fixture census while the
    // nearest existing native ancestors are still held against replacement.
    for path in &paths {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(crate::CiError::Message(
                    "owned removed path reappeared during observation".into(),
                ));
            }
        }
    }
    let bytes = serde_json::to_vec(
        &serde_json::json!({"format":"memcordon.windows-native-removal","revision":1,
        "provider_generation":config.provider.generation.as_str(),"absent_services":absent_services,
        "absent_paths":paths,"fixture_processes_absent":true,"installed_image_processes_absent":true,
        "native_component_census":"owned-package-image-names-no-live-candidate",
        "service_observations":service_observations,"path_observations":path_observations}),
    )?;
    if !output_directory.starts_with(&config.output_directory)
        || output_directory == config.output_directory
        || output_directory.try_exists()?
    {
        return Err(crate::CiError::Message(
            "removal receipt requires a fresh owned controller directory".into(),
        ));
    }
    let _parent = hold_ancestors(
        output_directory
            .parent()
            .ok_or_else(|| crate::CiError::Message("removal receipt parent missing".into()))?,
    )?;
    std::fs::create_dir(output_directory)?;
    let _output = hold_ancestors(output_directory)?;
    let path = output_directory.join("native-removal.json");
    let _held = publish_receipt(&path, &bytes)?;
    if std::time::Instant::now() >= cleanup_deadline {
        return Err(crate::CiError::Message(
            "removal receipt deadline exhausted; retained observation is not cleanup success"
                .into(),
        ));
    }
    Ok(WindowsRemovalObservation {
        format: "memcordon.windows-native-removal".into(),
        revision: 1,
        provider_generation: config.provider.generation.as_str().into(),
        absent_services,
        absent_paths: paths,
        installed_image_processes_absent: true,
        fixture_processes_absent: true,
        receipt: crate::windows_installed_cases::SelectedArtifact {
            path,
            sha256: crate::windows_causal_acceptance::sha256(&bytes),
        },
    })
}

#[cfg(windows)]
struct Bundle {
    destination: PathBuf,
    prefix: PathBuf,
    artifacts: Vec<memcordon_readiness_verifier::Artifact>,
    held: Vec<std::fs::File>,
}

#[cfg(windows)]
impl Bundle {
    fn relative(path: &Path) -> crate::Result<String> {
        let mut pieces = Vec::new();
        for piece in path.components() {
            let std::path::Component::Normal(piece) = piece else {
                return Err(crate::CiError::Message(
                    "Windows evidence reference must have normalized relative components".into(),
                ));
            };
            let text = piece.to_str().ok_or_else(|| {
                crate::CiError::Message("Windows evidence reference is not portable text".into())
            })?;
            if text.is_empty() || text.contains(['\\', '/', '\0']) {
                return Err(crate::CiError::Message(
                    "Windows evidence reference contains a separator or NUL".into(),
                ));
            }
            pieces.push(text);
        }
        if pieces.is_empty() {
            return Err(crate::CiError::Message(
                "Windows evidence reference is empty".into(),
            ));
        }
        Ok(pieces.join("/"))
    }

    fn reference(&self, path: &Path) -> crate::Result<String> {
        Self::relative(&self.prefix.join(path))
    }

    fn ensure_directory(&mut self, relative: &Path) -> crate::Result<PathBuf> {
        Self::relative(relative)?;
        let mut path = self.destination.clone();
        self.held.extend(hold_ancestors(&path)?);
        for part in relative.components() {
            path.push(part.as_os_str());
            if !path.try_exists()? {
                std::fs::create_dir(&path)?;
            }
            // Parent handles already deny rename; validate and hold this exact
            // new/existing component before creating any descendant beneath it.
            self.held.extend(hold_ancestors(&path)?);
        }
        Ok(path)
    }

    fn retain(&mut self, relative: &Path, bytes: &[u8]) -> crate::Result<String> {
        let reference = self.reference(relative)?;
        if bytes.len() > 512 * 1024 * 1024
            || self.artifacts.len() >= 32768
            || self
                .artifacts
                .iter()
                .any(|artifact| artifact.path == reference)
        {
            return Err(crate::CiError::Message(
                "Windows evidence artifact is oversized, duplicate or exceeds finite file count"
                    .into(),
            ));
        }
        let path = self.destination.join(&self.prefix).join(relative);
        let parent = path
            .parent()
            .ok_or_else(|| crate::CiError::Message("Windows evidence parent missing".into()))?;
        let relative_parent = self
            .prefix
            .join(relative)
            .parent()
            .ok_or_else(|| {
                crate::CiError::Message("Windows evidence relative parent missing".into())
            })?
            .to_owned();
        self.ensure_directory(&relative_parent)?;
        self.held.extend(hold_ancestors(parent)?);
        self.held.push(publish_receipt(&path, bytes)?);
        self.artifacts.push(memcordon_readiness_verifier::Artifact {
            path: reference.clone(),
            length: bytes.len() as u64,
            sha256: crate::windows_causal_acceptance::sha256(bytes),
        });
        Ok(reference)
    }

    fn copy(
        &mut self,
        source: &Path,
        relative: &Path,
        expected: Option<&str>,
    ) -> crate::Result<String> {
        let source = hold_artifact(source, expected, 512 * 1024 * 1024)?;
        let reference = self.retain(relative, &source.bytes)?;
        // Subsequent typed projection reads the same protected source bytes.
        // Keep both named source ancestry and file alive through conversion.
        self.held.extend(source._ancestors);
        self.held.push(source._file);
        Ok(reference)
    }

    fn copy_directory(&mut self, source: &Path, relative: &Path) -> crate::Result<()> {
        let _ancestors = hold_ancestors(source)?;
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            let target = relative.join(entry.file_name());
            if kind.is_dir() {
                self.copy_directory(&entry.path(), &target)?;
            } else if kind.is_file() {
                self.copy(&entry.path(), &target, None)?;
            } else {
                return Err(crate::CiError::Message(
                    "Windows evidence directory contains an aliased or special entry".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCleanup {
    pub output_directory: PathBuf,
    pub artifacts: Vec<crate::windows_installed_cases::SelectedArtifact>,
    pub native_status: Option<i32>,
    pub deadline_exhausted: bool,
    pub recovery: std::result::Result<(), String>,
    pub native_quiescence: std::result::Result<(), String>,
}

#[cfg(windows)]
#[allow(unsafe_code)] // Query-only identity of an exact held native file handle.
fn native_file_identity(
    file: &std::fs::File,
    directory: bool,
    path: &Path,
) -> std::io::Result<(u32, u64)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: held File owns the live handle and info is a correctly sized output.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    crate::windows_receipt_identity::validate(
        path,
        directory,
        info.dwFileAttributes,
        info.nNumberOfLinks,
    )?;
    Ok((
        info.dwVolumeSerialNumber,
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}

#[cfg(windows)]
fn hold_ancestors(path: &Path) -> std::io::Result<Vec<std::fs::File>> {
    use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    if path.components().any(|part| {
        matches!(
            part,
            std::path::Component::ParentDir | std::path::Component::CurDir
        )
    }) {
        return Err(std::io::Error::other(
            "Windows receipt ancestry must be normalized",
        ));
    }
    let mut held = Vec::new();
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(ancestor)?;
        native_file_identity(&file, true, ancestor)?;
        held.push(file);
    }
    Ok(held)
}

#[cfg(windows)]
#[allow(unsafe_code)] // Native checked same-directory WRITE_THROUGH publication.
pub(crate) fn publish_receipt(path: &Path, bytes: &[u8]) -> std::io::Result<std::fs::File> {
    use std::{
        fs::OpenOptions,
        io::{Read, Write},
        os::windows::{ffi::OsStrExt, fs::OpenOptionsExt},
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let pending = path.with_extension("pending");
    let mut held = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&pending)?;
    held.write_all(bytes)?;
    held.sync_all()?;
    let identity = native_file_identity(&held, false, &pending)?;
    let source: Vec<_> = pending.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    if source[..source.len() - 1].contains(&0) || destination[..destination.len() - 1].contains(&0)
    {
        return Err(std::io::Error::other("Windows receipt path contains NUL"));
    }
    // SAFETY: terminated owned UTF16 paths; no overwrite flag, owned same directory.
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let named = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    if native_file_identity(&held, false, path)? != identity
        || native_file_identity(&named, false, path)? != identity
    {
        return Err(std::io::Error::other(
            "Windows receipt named native identity differs",
        ));
    }
    let mut observed = Vec::new();
    (&named)
        .take(bytes.len() as u64 + 1)
        .read_to_end(&mut observed)?;
    if observed != bytes {
        return Err(std::io::Error::other(
            "Windows receipt named native readback differs",
        ));
    }
    drop(held);
    let protected = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    if native_file_identity(&protected, false, path)? != identity {
        return Err(std::io::Error::other(
            "Windows protected receipt identity differs",
        ));
    }
    let mut protected_bytes = Vec::new();
    (&protected)
        .take(bytes.len() as u64 + 1)
        .read_to_end(&mut protected_bytes)?;
    if protected_bytes != bytes {
        return Err(std::io::Error::other(
            "Windows protected receipt readback differs",
        ));
    }
    Ok(protected)
}

/// Captures the materialized public frontend's native target argv and ordered
/// budget tokens. No acceptance policy or expected row generator is consulted.
#[cfg(windows)]
pub(crate) fn retain_public_invocation(
    command: &std::process::Command,
    directory: &Path,
    artifact_prefix: &Path,
    executable_sha256: &str,
) -> crate::Result<Vec<crate::windows_installed_cases::SelectedArtifact>> {
    use std::os::windows::ffi::OsStrExt;
    let arguments: Vec<_> = command.get_args().collect();
    let separator = arguments
        .iter()
        .position(|argument| *argument == std::ffi::OsStr::new("--"))
        .ok_or_else(|| {
            crate::CiError::Message(
                "materialized Windows public invocation has no native target separator".into(),
            )
        })?;
    if separator < 2 || separator + 1 >= arguments.len() {
        return Err(crate::CiError::Message(
            "materialized Windows public invocation omitted ordered budgets or target".into(),
        ));
    }
    let memory = arguments[0]
        .to_str()
        .ok_or_else(|| crate::CiError::Message("native memory budget is not ASCII text".into()))?
        .to_owned();
    let deadline = arguments[1]
        .to_str()
        .ok_or_else(|| crate::CiError::Message("native time budget is not ASCII text".into()))?
        .to_owned();
    let target = &arguments[separator + 1..];
    let public = memcordon_core::InvocationReport {
        syntax: "plus-budgets-v1".into(),
        budget_tokens: vec![
            memcordon_core::BudgetTokenReport {
                kind: memcordon_core::BudgetKindReport::Memory,
                token: memory.clone(),
            },
            memcordon_core::BudgetTokenReport {
                kind: memcordon_core::BudgetKindReport::Time,
                token: deadline.clone(),
            },
        ],
        memory_token: Some(memory.clone()),
        deadline_token: Some(deadline.clone()),
        argv: target
            .iter()
            .map(|argument| memcordon_core::NativeArgument::from_os(argument))
            .collect(),
    };
    let environment = serde_json::to_vec(
        &memcordon_readiness_verifier::NativeEnvironment::WindowsUtf16(Vec::new()),
    )?;
    let environment_path = directory.join("environment.json");
    let mut parts = Vec::new();
    for part in artifact_prefix.components() {
        let std::path::Component::Normal(part) = part else {
            return Err(crate::CiError::Message(
                "Windows invocation artifact prefix must be normalized relative components".into(),
            ));
        };
        parts.push(part.to_str().ok_or_else(|| {
            crate::CiError::Message(
                "Windows invocation artifact prefix is not portable text".into(),
            )
        })?);
    }
    if parts.is_empty() {
        return Err(crate::CiError::Message(
            "Windows invocation artifact prefix is empty".into(),
        ));
    }
    let environment_reference = format!("{}/environment.json", parts.join("/"));
    let _environment = publish_receipt(&environment_path, &environment)?;
    let invocation = memcordon_readiness_verifier::NativeInvocation {
        format: "memcordon.consumer-readiness.invocation".into(),
        revision: 1,
        arguments: memcordon_readiness_verifier::NativeArguments::WindowsUtf16(
            target
                .iter()
                .map(|argument| argument.encode_wide().collect())
                .collect(),
        ),
        executable_sha256: executable_sha256.into(),
        environment: environment_reference,
        environment_sha256: crate::windows_causal_acceptance::sha256(&environment),
        association_sha256: crate::windows_causal_acceptance::sha256(&serde_json::to_vec(&public)?),
        budget_tokens: vec![
            memcordon_readiness_verifier::BudgetToken {
                kind: "memory".into(),
                token: memory.clone(),
            },
            memcordon_readiness_verifier::BudgetToken {
                kind: "time".into(),
                token: deadline.clone(),
            },
        ],
        memory_token: Some(memory),
        deadline_token: Some(deadline),
    };
    let bytes = serde_json::to_vec(&invocation)?;
    let path = directory.join("invocation.json");
    let _invocation = publish_receipt(&path, &bytes)?;
    Ok(vec![
        crate::windows_installed_cases::SelectedArtifact {
            path: environment_path,
            sha256: crate::windows_causal_acceptance::sha256(&environment),
        },
        crate::windows_installed_cases::SelectedArtifact {
            path,
            sha256: crate::windows_causal_acceptance::sha256(&bytes),
        },
    ])
}

/// Each call owns a fresh receipt directory. Repeating convergence never reuses
/// prior observations or treats an earlier successful receipt as current state.
#[cfg(windows)]
pub fn recover_and_observe_quiescence(
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    output_directory: &Path,
    cleanup_deadline: std::time::Instant,
) -> crate::Result<RecoveryCleanup> {
    use std::{fs, time::Duration};
    if !output_directory.is_absolute()
        || !output_directory.starts_with(&config.output_directory)
        || output_directory == config.output_directory
    {
        return Err(crate::CiError::Message("Windows recovery receipt directory must be a fresh descendant of the owned installed output root".into()));
    }
    let parent = output_directory
        .parent()
        .ok_or_else(|| crate::CiError::Message("Windows cleanup receipt parent missing".into()))?;
    let mut _owned_ancestry = hold_ancestors(parent)?;
    fs::create_dir(output_directory)?;
    _owned_ancestry.extend(hold_ancestors(output_directory)?);
    let mut owned_receipts = Vec::new();
    let mut receipt = RecoveryCleanup {
        output_directory: output_directory.to_owned(),
        artifacts: Vec::new(),
        native_status: None,
        deadline_exhausted: false,
        recovery: Err("native recovery was not observed".into()),
        native_quiescence: Err("native quiescence was not observed".into()),
    };
    let remaining = cleanup_deadline.saturating_duration_since(std::time::Instant::now());
    // Leave the native quiescence query and receipt custody inside the caller's
    // reserved cleanup interval; no retry creates a fresh outer budget.
    let command_budget = remaining
        .saturating_sub(Duration::from_secs(2))
        .min(Duration::from_secs(60));
    if command_budget < Duration::from_millis(100) {
        return Err(crate::CiError::Message(
            "reserved Windows cleanup deadline exhausted before native recovery".into(),
        ));
    }
    let convergence_millis = command_budget
        .saturating_sub(Duration::from_millis(100))
        .as_millis()
        .min(30_000)
        .to_string();
    let mut command =
        crate::command::CommandSpec::new(&config.cli.path, output_directory, command_budget)
            .args(["windows-recover", "converge", convergence_millis.as_str()])
            .materialize()?;
    command.env_clear();
    use std::os::windows::ffi::OsStrExt;
    let invocation = serde_json::to_vec(
        &serde_json::json!({"format":"memcordon.windows-native-recovery-invocation","revision":1,
        "cli":config.cli,"provider":config.provider,"cwd":output_directory,
        "argv_utf16":command.get_args().map(|argument|argument.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>(),
        "environment_cleared":true,"command_budget_millis":command_budget.as_millis()}),
    )?;
    let invocation_path = output_directory.join("recovery-invocation.json");
    owned_receipts.push(publish_receipt(&invocation_path, &invocation)?);
    receipt
        .artifacts
        .push(crate::windows_installed_cases::SelectedArtifact {
            path: invocation_path,
            sha256: crate::windows_causal_acceptance::sha256(&invocation),
        });
    let delivery_budget = command_budget.min(
        cleanup_deadline
            .saturating_duration_since(std::time::Instant::now())
            .saturating_sub(Duration::from_secs(2)),
    );
    if delivery_budget < Duration::from_millis(100) {
        return Err(crate::CiError::Message(
            "reserved cleanup deadline exhausted while publishing actual recovery invocation"
                .into(),
        ));
    }
    let output = memcordon_testkit::run_with_deadline_output_limit(
        &mut command,
        delivery_budget,
        4 * 1024 * 1024,
    );
    if let Err(error) = &output {
        let mut partial = vec![("capture-failure.txt", error.to_string().into_bytes())];
        match error {
            memcordon_testkit::ProcessTestError::Timeout { stdout, stderr, .. }
            | memcordon_testkit::ProcessTestError::OutputLimit { stdout, stderr, .. } => {
                partial.push(("partial.stdout.bin", stdout.clone()));
                partial.push(("partial.stderr.bin", stderr.clone()));
            }
            _ => {}
        }
        for (name, bytes) in partial {
            let path = output_directory.join(name);
            owned_receipts.push(publish_receipt(&path, &bytes)?);
            receipt
                .artifacts
                .push(crate::windows_installed_cases::SelectedArtifact {
                    path,
                    sha256: crate::windows_causal_acceptance::sha256(&bytes),
                });
        }
    }
    let recovery = (|| -> crate::Result<()> {
        let output = output.map_err(|error| crate::CiError::Message(error.to_string()))?;
        receipt.native_status = output.status.code();
        for (name, bytes) in [
            ("recovery.stdout.bin", output.stdout.as_slice()),
            ("recovery.stderr.bin", output.stderr.as_slice()),
        ] {
            let path = output_directory.join(name);
            owned_receipts.push(publish_receipt(&path, bytes)?);
            receipt
                .artifacts
                .push(crate::windows_installed_cases::SelectedArtifact {
                    path,
                    sha256: crate::windows_causal_acceptance::sha256(bytes),
                });
        }
        let inventory: memcordon_core::WindowsRecoveryInventoryV1 =
            serde_json::from_slice(&output.stdout)?;
        if !output.status.success()
            || !inventory.is_consistent()
            || inventory.provider_generation != config.provider.generation.as_str()
            || inventory.executing != 0
            || inventory.incomplete_proof != 0
            || inventory.unacknowledged_outboxes != 0
            || inventory.ack_retirement_in_progress != 0
            || inventory.active_admissions != 0
            || inventory.quarantined != 0
        {
            return Err(crate::CiError::Message(
                "actual native recovery did not converge selected provider state".into(),
            ));
        }
        Ok(())
    })();
    receipt.recovery = recovery.map_err(|error| error.to_string());
    receipt.native_quiescence = if std::time::Instant::now() >= cleanup_deadline {
        receipt.deadline_exhausted = true;
        Err(
            "reserved Windows cleanup deadline exhausted; native quiescence remains uncertain"
                .into(),
        )
    } else {
        crate::windows_owned_guardian::GuardianBaseline::quiescent(
            &config.installed_agent.path,
            &config.installed_manifest.path,
            &config.installed_agent.sha256,
            &config.installed_manifest.sha256,
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
    };
    if std::time::Instant::now() >= cleanup_deadline {
        receipt.deadline_exhausted = true;
        receipt.native_quiescence = Err("reserved Windows cleanup deadline exhausted during native query; quiescence remains uncertain".into());
    }
    let path = output_directory.join("cleanup.json");
    let bytes = serde_json::to_vec(&receipt)?;
    owned_receipts.push(publish_receipt(&path, &bytes)?);
    receipt
        .artifacts
        .push(crate::windows_installed_cases::SelectedArtifact {
            path,
            sha256: crate::windows_causal_acceptance::sha256(&bytes),
        });
    if std::time::Instant::now() >= cleanup_deadline {
        return Err(crate::CiError::Message("reserved Windows cleanup deadline exhausted during custody publication; inspect retained raw receipts".into()));
    }
    Ok(receipt)
}
