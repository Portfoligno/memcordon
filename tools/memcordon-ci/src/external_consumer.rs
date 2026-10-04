//! Caller-selected executable consumers. Inputs describe work; they grant no runtime permission.
use crate::{
    CiError, Result,
    command::CommandSpec,
    release::{artifacts, distribution, target},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use memcordon_core::{
    ChildTermination, InvocationReport, NativeArgument,
    result_v1::{CleanupStateV1, OutcomeKindV1, ResultV1},
    workload_contract::{WorkloadContractV1, WorkloadContractV2},
    workload_evidence::WorkloadRequestReport,
};
use memcordon_testkit::ProcessTestError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

const MAX_INPUT_BYTES: u64 = 1024 * 1024;
const MAX_STREAM_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasuredExecutable {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedInput {
    pub path: PathBuf,
    pub record: artifacts::FileRecord,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Selection {
    MeasuredCli,
    NativeArchive,
    CargoPackages,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RequestedContract {
    Standard,
    Process { contract: Box<WorkloadContractV1> },
    PrivateTcp { contract: Box<WorkloadContractV2> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ExpectedCoverage {
    Bytes {
        stdout_sha256: String,
        stderr_sha256: String,
    },
    /// Entire caller-controlled expected inventory; never discovered from candidate --list output.
    Libtest { tests: Vec<String> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalConsumerSpec {
    pub format: String,
    pub revision: u32,
    pub target: String,
    pub version: String,
    pub runtime_features: Vec<String>,
    pub selection: Selection,
    pub selected_inputs: Vec<SelectedInput>,
    pub cli: MeasuredExecutable,
    pub workload: MeasuredExecutable,
    pub working_directory: PathBuf,
    pub arguments: Vec<NativeArgument>,
    pub requested_contract: RequestedContract,
    pub report_format: String,
    pub report_revision: u32,
    pub expected_outcome: OutcomeKindV1,
    pub expected_native_termination: Option<ChildTermination>,
    pub expected_wrapper_status: i32,
    pub coverage: ExpectedCoverage,
    pub outer_deadline_millis: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Assessment {
    Passed,
    Failed { reason: String },
    Uncertain { reason: String },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalConsumerAssessment {
    pub format: String,
    pub revision: u32,
    pub execution: Assessment,
    pub collection: Assessment,
    pub retirement: Assessment,
    pub wrapper_status: Option<i32>,
    pub raw_capture_complete: bool,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub report_sha256: Option<String>,
}
impl ExternalConsumerAssessment {
    pub fn passed(&self) -> bool {
        self.execution == Assessment::Passed
            && self.collection == Assessment::Passed
            && self.retirement == Assessment::Passed
    }
}
fn failure(reason: impl Into<String>) -> CiError {
    CiError::Message(reason.into())
}
fn failed(reason: impl Into<String>) -> Assessment {
    Assessment::Failed {
        reason: reason.into(),
    }
}
fn hash_valid(hash: &str) -> bool {
    hash.len() == Sha256::output_size() * 2
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
fn open_regular(path: &Path, maximum: u64) -> Result<(fs::File, Vec<u8>)> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let before = file.metadata()?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if before.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err(failure("consumer input is a Windows reparse point"));
        }
    }
    if !before.file_type().is_file() || before.len() > maximum {
        return Err(failure("consumer input is not a bounded regular file"));
    }
    let mut bytes = Vec::new();
    (&file).take(maximum + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len()
        || before.len() != after.len()
        || before.modified()? != after.modified()?
    {
        return Err(failure("consumer input changed during bounded read"));
    }
    Ok((file, bytes))
}
fn bounded_regular(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    open_regular(path, maximum).map(|(_, bytes)| bytes)
}
#[allow(unsafe_code)] // One held Windows file identity query; never a subprocess or permission adapter.
fn file_identity(file: &fs::File) -> Result<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        Ok((metadata.dev(), metadata.ino()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: this exact owned regular descriptor remains live across the call.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut information) } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok((
            information.dwVolumeSerialNumber as u64,
            ((information.nFileIndexHigh as u64) << 32) | information.nFileIndexLow as u64,
        ))
    }
}
fn decode_argument(argument: &NativeArgument) -> Result<OsString> {
    let value = match &argument.raw {
        None => OsString::from(&argument.display),
        Some(raw) => {
            let bytes = STANDARD
                .decode(&raw.data)
                .map_err(|_| failure("invalid native argument encoding"))?;
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStringExt;
                if raw.encoding != "unix-bytes-base64" {
                    return Err(failure("native argument platform differs"));
                }
                OsString::from_vec(bytes)
            }
            #[cfg(windows)]
            {
                use std::os::windows::ffi::OsStringExt;
                if raw.encoding != "windows-u16le-base64" || bytes.len() % 2 != 0 {
                    return Err(failure("native argument platform differs"));
                }
                let wide = bytes
                    .chunks_exact(2)
                    .map(|part| u16::from_le_bytes([part[0], part[1]]))
                    .collect::<Vec<_>>();
                OsString::from_wide(&wide)
            }
        }
    };
    if value.as_encoded_bytes().contains(&0)
        || value.as_encoded_bytes().len() > 64 * 1024
        || serde_json::to_value(NativeArgument::from_os(&value))? != serde_json::to_value(argument)?
    {
        return Err(failure("native argument is not canonical or bounded"));
    }
    Ok(value)
}
impl ExternalConsumerSpec {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 > MAX_INPUT_BYTES {
            return Err(failure("external consumer input exceeds bound"));
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(bytes).map_err(failure)?;
        let spec: Self = serde_json::from_slice(bytes)?;
        spec.validate()?;
        Ok(spec)
    }
    pub fn validate(&self) -> Result<()> {
        if self.format != "memcordon.external-consumer"
            || self.revision != 1
            || self.report_format != "result-v1"
            || self.report_revision != 1
            || self.selected_inputs.len() > 32
            || self.arguments.len() > 256
            || !(1..=600_000).contains(&self.outer_deadline_millis)
            || !self.working_directory.is_absolute()
            || !self.cli.path.is_absolute()
            || !self.workload.path.is_absolute()
            || !hash_valid(&self.cli.sha256)
            || !hash_valid(&self.workload.sha256)
        {
            return Err(failure(
                "external consumer format/selection/deadline differs",
            ));
        }
        self.version.parse::<semver::Version>()?;
        if self.runtime_features.len() > 3
            || self.runtime_features.iter().any(|feature| {
                !matches!(
                    feature.as_str(),
                    "sealed-runtime" | "private-tcp" | "windows-sealed-runtime"
                )
            })
            || self.runtime_features.iter().collect::<BTreeSet<_>>().len()
                != self.runtime_features.len()
        {
            return Err(failure("external runtime feature selection differs"));
        }
        if !matches!(
            self.target.as_str(),
            "x86_64-unknown-linux-gnu"
                | "aarch64-unknown-linux-gnu"
                | "x86_64-apple-darwin"
                | "aarch64-apple-darwin"
                | "x86_64-pc-windows-msvc"
                | "aarch64-pc-windows-msvc"
        ) {
            return Err(failure("external target is not supported"));
        }
        let mut paths = BTreeSet::new();
        for input in &self.selected_inputs {
            artifacts::safe_basename(&input.record.name)?;
            if !input.path.is_absolute()
                || !paths.insert(&input.path)
                || !matches!(input.record.kind.as_str(), "crate" | "archive")
                || !hash_valid(&input.record.sha256)
                || input.record.byte_len == 0
                || input.record.byte_len > artifacts::MAX_FILE_BYTES
            {
                return Err(failure("external selected archive/crate input differs"));
            }
        }
        match self.selection {
            Selection::MeasuredCli if !self.selected_inputs.is_empty() => {
                return Err(failure(
                    "measured CLI selection has unexpected artifact inputs",
                ));
            }
            Selection::NativeArchive
                if self.selected_inputs.len() != 1
                    || self.selected_inputs[0].record.kind != "archive"
                    || self.selected_inputs[0].record.target.as_deref()
                        != Some(self.target.as_str())
                    || self.selected_inputs[0].record.package.is_some() =>
            {
                return Err(failure("native archive selection differs"));
            }
            Selection::CargoPackages
                if self.selected_inputs.len() != 4
                    || self.selected_inputs.iter().any(|input| {
                        input.record.kind != "crate" || input.record.target.is_some()
                    })
                    || self
                        .selected_inputs
                        .iter()
                        .filter_map(|input| input.record.package.as_deref())
                        .collect::<BTreeSet<_>>()
                        != crate::release::source::PUBLIC_PACKAGES
                            .into_iter()
                            .collect() =>
            {
                return Err(failure(
                    "Cargo selection must contain all four actual public package inputs",
                ));
            }
            _ => {}
        }
        for argument in &self.arguments {
            decode_argument(argument)?;
        }
        match &self.requested_contract {
            RequestedContract::Standard => {}
            RequestedContract::Process { contract } => contract.validate().map_err(failure)?,
            RequestedContract::PrivateTcp { contract } => contract.validate().map_err(failure)?,
        }
        match &self.coverage {
            ExpectedCoverage::Bytes {
                stdout_sha256,
                stderr_sha256,
            } if hash_valid(stdout_sha256) && hash_valid(stderr_sha256) => {}
            ExpectedCoverage::Libtest { tests }
                if !tests.is_empty()
                    && tests.len() <= 8192
                    && tests.iter().all(|name| {
                        !name.is_empty()
                            && name.len() <= 1024
                            && !name.chars().any(char::is_control)
                    })
                    && tests.iter().collect::<BTreeSet<_>>().len() == tests.len() => {}
            _ => {
                return Err(failure(
                    "external expected coverage is empty, duplicated or malformed",
                ));
            }
        }
        Ok(())
    }
    fn workload_arguments(&self) -> Result<Vec<OsString>> {
        let mut arguments = self
            .arguments
            .iter()
            .map(decode_argument)
            .collect::<Result<Vec<_>>>()?;
        if matches!(self.coverage, ExpectedCoverage::Libtest { .. }) {
            arguments.extend([
                OsString::from("--test-threads=1"),
                OsString::from("--format=pretty"),
                OsString::from("--color=never"),
            ]);
        }
        Ok(arguments)
    }
    fn invocation_digest(&self) -> Result<String> {
        let mut argv = vec![NativeArgument::from_os(self.workload.path.as_os_str())];
        argv.extend(
            self.workload_arguments()?
                .iter()
                .map(|value| NativeArgument::from_os(value)),
        );
        Ok(artifacts::checksum(&serde_json::to_vec(
            &InvocationReport {
                syntax: "plus-budgets-v1".into(),
                budget_tokens: Vec::new(),
                memory_token: None,
                deadline_token: None,
                argv,
            },
        )?))
    }
}

/// Parse finite libtest grammar and require the caller's complete inventory and exact counters.
pub fn require_coverage(bytes: &[u8], expected: &[String]) -> Result<()> {
    if bytes.len() > MAX_STREAM_BYTES || expected.is_empty() {
        return Err(failure("libtest coverage input is empty or oversized"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| failure("libtest stdout is not UTF-8"))?;
    let mut rows = BTreeSet::new();
    let mut header = None;
    let mut summary = None;
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("running ") {
            let count = rest
                .strip_suffix(" tests")
                .or_else(|| rest.strip_suffix(" test"))
                .filter(|value| {
                    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
                })
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or_else(|| failure("libtest header grammar differs"))?;
            if header.replace(count).is_some()
                || !rows.is_empty()
                || summary.is_some()
                || count != expected.len()
                || (count == 1) != rest.ends_with(" test")
            {
                return Err(failure("libtest expected header/count differs"));
            }
        } else if let Some(rest) = line.strip_prefix("test result: ") {
            if header.is_none() || summary.replace(rest).is_some() {
                return Err(failure("libtest emitted multiple summaries"));
            }
        } else if let Some(row) = line.strip_prefix("test ") {
            let (name, status) = row
                .rsplit_once(" ... ")
                .ok_or_else(|| failure("libtest test row grammar differs"))?;
            if header.is_none()
                || summary.is_some()
                || status != "ok"
                || !rows.insert(name.to_owned())
            {
                return Err(failure(
                    "libtest failed, ignored, measured, reordered or duplicated a test",
                ));
            }
        } else {
            return Err(failure("unknown libtest output line"));
        }
    }
    let rest = summary
        .and_then(|row| row.strip_prefix("ok. "))
        .ok_or_else(|| failure("libtest success summary absent"))?;
    let fields = rest.split(';').map(str::trim).collect::<Vec<_>>();
    if fields.len() != 6 || header != Some(expected.len()) {
        return Err(failure("libtest summary grammar differs"));
    }
    let duration = fields[5]
        .strip_prefix("finished in ")
        .and_then(|value| value.strip_suffix('s'))
        .filter(|value| !value.is_empty() && value.len() <= 32)
        .ok_or_else(|| failure("libtest duration grammar differs"))?;
    let (whole, fraction) = duration
        .split_once('.')
        .ok_or_else(|| failure("libtest duration is not a decimal"))?;
    if whole.is_empty()
        || fraction.is_empty()
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|byte| byte.is_ascii_digit())
        || duration
            .parse::<f64>()
            .ok()
            .is_none_or(|value| !value.is_finite())
    {
        return Err(failure("libtest duration is not finite decimal seconds"));
    }
    for (index, label) in [
        " passed",
        " failed",
        " ignored",
        " measured",
        " filtered out",
    ]
    .iter()
    .enumerate()
    {
        let count = fields[index]
            .strip_suffix(label)
            .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
            .ok_or_else(|| failure("libtest counter grammar differs"))?
            .parse::<usize>()
            .map_err(|_| failure("libtest counter overflows"))?;
        if count != if index == 0 { expected.len() } else { 0 } {
            return Err(failure("libtest expected executed counters differ"));
        }
    }
    if expected.iter().cloned().collect::<BTreeSet<_>>() != rows || rows.len() != expected.len() {
        return Err(failure("libtest executed inventory differs"));
    }
    Ok(())
}

pub fn assess_result(
    spec: &ExternalConsumerSpec,
    result: &ResultV1,
    status: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<(Assessment, Assessment)> {
    result.validate().map_err(failure)?;
    if result.tool.name != "memcordon"
        || result.tool.version != spec.version
        || result.tool.os != std::env::consts::OS
        || result.tool.architecture != std::env::consts::ARCH
        || result.tool.runtime_features.iter().collect::<BTreeSet<_>>()
            != spec.runtime_features.iter().collect::<BTreeSet<_>>()
        || result.invocation.association_sha256 != spec.invocation_digest()?
        || result.invocation.requested_memory.is_some()
        || result.invocation.requested_deadline.is_some()
    {
        return Err(failure(
            "external report selected source/invocation association differs",
        ));
    }
    match &spec.requested_contract {
        RequestedContract::Standard
            if result.policy.requested.workload != WorkloadRequestReport::LegacyUnspecified
                || result.private_execution.is_some() =>
        {
            return Err(failure("external standard request was substituted"));
        }
        RequestedContract::Process { contract }
            if result.policy.requested.workload
                != WorkloadRequestReport::StrictV1 {
                    contract: contract.clone(),
                } =>
        {
            return Err(failure("external process contract was substituted"));
        }
        RequestedContract::PrivateTcp { contract }
            if result.private_execution.as_ref().is_none_or(|execution| {
                execution.terminal.admission_metadata.request != **contract
            }) =>
        {
            return Err(failure(
                "external private contract was substituted or absent",
            ));
        }
        _ => {}
    }
    let execution = if status != Some(spec.expected_wrapper_status)
        || result.outcome.wrapper_status != spec.expected_wrapper_status
        || result.outcome.kind != spec.expected_outcome
        || result.outcome.native_termination != spec.expected_native_termination
    {
        failed("external native outcome/wrapper status differs")
    } else {
        let coverage = match &spec.coverage {
            ExpectedCoverage::Bytes {
                stdout_sha256,
                stderr_sha256,
            } => {
                if artifacts::checksum(stdout) == *stdout_sha256
                    && artifacts::checksum(stderr) == *stderr_sha256
                {
                    Ok(())
                } else {
                    Err(failure("external exact byte behavior differs"))
                }
            }
            ExpectedCoverage::Libtest { tests } => require_coverage(stdout, tests),
        };
        coverage.map_or_else(|error| failed(error.to_string()), |_| Assessment::Passed)
    };
    let retirement = if result.cleanup.state == CleanupStateV1::Complete
        && result.cleanup.direct_child_reaped
        && result.cleanup.workload_empty != Some(false)
        && result.cleanup.outstanding.is_empty()
        && result.cleanup.failed_operations.is_empty()
    {
        Assessment::Passed
    } else {
        Assessment::Uncertain {
            reason: "native report retains retirement obligations".into(),
        }
    };
    Ok((execution, retirement))
}

pub fn run_file(input: &Path, destination: &Path) -> Result<ExternalConsumerAssessment> {
    let spec = ExternalConsumerSpec::parse(&bounded_regular(input, MAX_INPUT_BYTES)?)?;
    run(&spec, destination)
}

/// Link an actual PackageConsumer/native materializer to the measured CLI. A
/// list of .crate checksums alone does not establish that a CLI was built from
/// those packages. This non-deserializable payload owns the verified build.
pub fn run_materialized(
    payload: &crate::release::installed_consumer::MaterializedPayload,
    spec: &ExternalConsumerSpec,
    destination: &Path,
) -> Result<ExternalConsumerAssessment> {
    let cli = crate::release::installed_consumer::binary_path(
        &payload.directory,
        "memcordon",
        &payload.distribution.target,
    );
    if !matches!(spec.selection, Selection::MeasuredCli)
        || spec.cli.path != cli
        || spec.target != payload.distribution.target
        || spec.version != payload.source.version().to_string()
        || spec.runtime_features.iter().collect::<BTreeSet<_>>()
            != payload
                .distribution
                .features
                .iter()
                .collect::<BTreeSet<_>>()
    {
        return Err(failure(
            "external consumer does not use the actual owned selected materialization",
        ));
    }
    run(spec, destination)
}
pub fn run(spec: &ExternalConsumerSpec, destination: &Path) -> Result<ExternalConsumerAssessment> {
    spec.validate()?;
    if distribution::native_target()? != spec.target {
        return Err(failure(
            "external consumer must execute on its actual native target",
        ));
    }
    for input in &spec.selected_inputs {
        let bytes = bounded_regular(&input.path, artifacts::MAX_FILE_BYTES)?;
        artifacts::check_bytes(&input.record, &bytes)?;
        match spec.selection {
            Selection::NativeArchive => {
                let members = target::decode_archive(&bytes, &spec.target)?;
                let name = target::binary_name("memcordon", &spec.target);
                if members
                    .get(&name)
                    .is_none_or(|bytes| artifacts::checksum(bytes) != spec.cli.sha256)
                {
                    return Err(failure(
                        "extracted CLI differs from selected native archive",
                    ));
                }
            }
            Selection::CargoPackages => {
                let (name, version) =
                    artifacts::crate_identity(&artifacts::crate_members(&bytes)?)?;
                if input.record.package.as_deref() != Some(name.as_str())
                    || version.to_string() != spec.version
                {
                    return Err(failure("external normalized crate source/version differs"));
                }
            }
            Selection::MeasuredCli => {
                unreachable!("selection validation rejects unexpected CLI artifact inputs")
            }
        }
    }
    let mut held_images = Vec::new();
    for executable in [&spec.cli, &spec.workload] {
        let (file, bytes) = open_regular(&executable.path, artifacts::MAX_FILE_BYTES)?;
        if artifacts::checksum(&bytes) != executable.sha256 {
            return Err(failure("external measured executable differs"));
        }
        target::validate_executable(&bytes, &spec.target)?;
        let identity = file_identity(&file)?;
        held_images.push((executable, file, identity));
    }
    // Fresh directory prevents overwriting caller evidence or accepting a previous report.
    fs::create_dir(destination)?;
    let report_path = destination.canonicalize()?.join("result.json");
    let mut arguments = vec![
        OsString::from("--report-format"),
        OsString::from("result-v1"),
        OsString::from("--report"),
        report_path.as_os_str().to_owned(),
    ];
    let contract = match &spec.requested_contract {
        RequestedContract::Standard => None,
        RequestedContract::Process { contract } => Some(serde_json::to_vec(contract)?),
        RequestedContract::PrivateTcp { contract } => Some(serde_json::to_vec(contract)?),
    };
    if let Some(bytes) = contract {
        let path = destination.canonicalize()?.join("requested-contract.json");
        fs::write(&path, bytes)?;
        arguments.extend([
            OsString::from("--sealed"),
            OsString::from("--workload-contract"),
            path.into_os_string(),
        ]);
    }
    arguments.extend([
        OsString::from("--"),
        spec.workload.path.as_os_str().to_owned(),
    ]);
    arguments.extend(spec.workload_arguments()?);
    let deadline = Duration::from_millis(spec.outer_deadline_millis);
    let mut command = CommandSpec::new(&spec.cli.path, &spec.working_directory, deadline)
        .args(arguments)
        .materialize()?;
    let observation =
        memcordon_testkit::run_with_deadline_output_limit(&mut command, deadline, MAX_STREAM_BYTES);
    let (status, stdout, stderr, outer_retirement, outer_error, raw_capture_complete) =
        match observation {
            Ok(output) => (
                output.status.code(),
                output.stdout,
                output.stderr,
                Assessment::Passed,
                None,
                true,
            ),
            Err(ProcessTestError::Timeout {
                stdout,
                stderr,
                cleanup,
                ..
            }) => {
                let capture_complete = cleanup.is_ok();
                let retirement = cleanup.map_or_else(
                    |error| Assessment::Uncertain { reason: error },
                    |_| Assessment::Passed,
                );
                (
                    None,
                    stdout,
                    stderr,
                    retirement,
                    Some("external outer deadline expired".into()),
                    capture_complete,
                )
            }
            Err(error) => (
                None,
                Vec::new(),
                Vec::new(),
                Assessment::Uncertain {
                    reason: error.to_string(),
                },
                Some(error.to_string()),
                false,
            ),
        };
    fs::write(destination.join("stdout.bin"), &stdout)?;
    fs::write(destination.join("stderr.bin"), &stderr)?;
    let collected = bounded_regular(
        &report_path,
        memcordon_core::result_v1::RESULT_MAX_BYTES as u64,
    );
    let report_sha256 = collected
        .as_ref()
        .ok()
        .map(|bytes| artifacts::checksum(bytes));
    let images_unchanged =
        held_images
            .iter()
            .try_for_each(|(expected, held, identity)| -> Result<()> {
                let (current, bytes) = open_regular(&expected.path, artifacts::MAX_FILE_BYTES)?;
                if file_identity(held)? != *identity
                    || file_identity(&current)? != *identity
                    || artifacts::checksum(&bytes) != expected.sha256
                {
                    return Err(failure(
                        "external selected native image was substituted during execution",
                    ));
                }
                Ok(())
            });
    let parsed = images_unchanged
        .and(collected)
        .and_then(|bytes| ResultV1::parse(&bytes).map_err(failure))
        .and_then(|result| assess_result(spec, &result, status, &stdout, &stderr));
    let (execution, collection, native_retirement) = match parsed {
        Ok((execution, retirement)) => (execution, Assessment::Passed, retirement),
        Err(error) => (
            failed(
                outer_error
                    .clone()
                    .unwrap_or_else(|| "external behavior could not be associated".into()),
            ),
            failed(error.to_string()),
            Assessment::Uncertain {
                reason: "native retirement report unavailable".into(),
            },
        ),
    };
    let result = ExternalConsumerAssessment {
        format: "memcordon.external-consumer-result".into(),
        revision: 1,
        execution: outer_error.map_or(execution, failed),
        collection: if raw_capture_complete {
            collection
        } else {
            Assessment::Uncertain {
                reason: "raw stream collection was unavailable or partial".into(),
            }
        },
        retirement: if outer_retirement == Assessment::Passed {
            native_retirement
        } else {
            outer_retirement
        },
        wrapper_status: status,
        raw_capture_complete,
        stdout_sha256: artifacts::checksum(&stdout),
        stderr_sha256: artifacts::checksum(&stderr),
        report_sha256,
    };
    fs::write(
        destination.join("assessment.json"),
        serde_json::to_vec_pretty(&result)?,
    )?;
    Ok(result)
}
