//! Measured native Rust test executables for the original component producer.
use super::{artifacts, distribution, source};
use crate::{CiError, Result, command::CommandSpec};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub struct MeasuredHarness {
    pub executable: PathBuf,
    pub sha256: String,
    pub compiler_output: PathBuf,
    pub compiler_errors: PathBuf,
    #[cfg(windows)]
    _custody: crate::windows_readiness_adapter::HeldWindowsArtifact,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalNativeDeadline {
    pub format: String,
    pub revision: u32,
    pub source: source::BuildSourceIdentity,
    pub native_target: String,
    pub started_unix_millis: u64,
    pub work_deadline_unix_millis: u64,
    pub cleanup_deadline_unix_millis: u64,
}

fn publish_native_record(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(windows)]
    {
        crate::windows_readiness_adapter::publish_receipt(path, bytes)?;
    }
    #[cfg(not(windows))]
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::File::open(
            path.parent()
                .ok_or_else(|| CiError::Message("native publication parent absent".into()))?,
        )?
        .sync_all()?;
    }
    Ok(())
}

/// The later invocation/cleanup command uses this same original deadline;
/// retries cannot mint a fresh component operation budget.
pub fn original_deadline(
    root: &Path,
    selected: &source::BuildSourceIdentity,
    target: &str,
) -> Result<Instant> {
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| CiError::Message(error.to_string()))?
            .as_millis(),
    )
    .map_err(|error| CiError::Message(error.to_string()))?;
    let path = root.join(".release/native-operation-deadline.json");
    let record = if path.exists() {
        source::read_json::<OriginalNativeDeadline>(&path)?
    } else {
        let record = OriginalNativeDeadline {
            format: "memcordon.consumer-readiness.original-native-deadline".into(),
            revision: 1,
            source: selected.clone(),
            native_target: target.to_owned(),
            started_unix_millis: now,
            work_deadline_unix_millis: now
                .checked_add(140 * 60 * 1000)
                .ok_or_else(|| CiError::Message("native work deadline overflow".into()))?,
            cleanup_deadline_unix_millis: now
                .checked_add(155 * 60 * 1000)
                .ok_or_else(|| CiError::Message("native cleanup deadline overflow".into()))?,
        };
        publish_native_record(&path, &serde_json::to_vec(&record)?)?;
        record
    };
    if record.format != "memcordon.consumer-readiness.original-native-deadline"
        || record.revision != 1
        || record.native_target != target
        || serde_json::to_vec(&record.source)? != serde_json::to_vec(selected)?
        || record
            .work_deadline_unix_millis
            .checked_sub(record.started_unix_millis)
            != Some(140 * 60 * 1000)
        || record
            .cleanup_deadline_unix_millis
            .checked_sub(record.started_unix_millis)
            != Some(155 * 60 * 1000)
        || now < record.started_unix_millis
        || now >= record.work_deadline_unix_millis
    {
        return Err(CiError::Message(
            "original native source/deadline differs or is exhausted".into(),
        ));
    }
    Instant::now()
        .checked_add(Duration::from_millis(
            record.work_deadline_unix_millis - now,
        ))
        .ok_or_else(|| CiError::Message("retained native operation deadline overflow".into()))
}

/// Retain both distinct measured native roles in the original native producer.
/// The descriptor records acquisition only; execution and retirement receipts
/// remain separate prerequisites for normalized component observations.
pub fn build_original_roles(
    root: &Path,
    selected: &source::BuildSourceIdentity,
    target: &str,
    destination: &Path,
    deadline: Instant,
) -> Result<()> {
    selected.recheck(root)?;
    fs::create_dir(destination)?;
    #[cfg(any(target_os = "linux", windows))]
    retain_original_host(root, selected, target, destination, deadline)?;
    let features = if target.ends_with("-unknown-linux-gnu") {
        "private-tcp,test-support"
    } else if target.ends_with("-pc-windows-msvc") {
        "windows-sealed-runtime,test-support"
    } else {
        return Err(CiError::Message(
            "native component roles require a supported readiness target".into(),
        ));
    };
    let operational = build(
        root,
        target,
        "memcordon",
        "sealed_agent",
        Some(features),
        &destination.join("operational"),
        deadline,
    )?;
    let parser = build(
        root,
        target,
        "memcordon-readiness-verifier",
        "contract",
        None,
        &destination.join("parser"),
        deadline,
    )?;
    #[cfg(windows)]
    build_windows_actor(root, selected, target, &destination.join("actor"), deadline)?;
    selected.recheck(root)?;
    publish_native_record(
        &destination.join("measured-harnesses.json"),
        &serde_json::to_vec(&serde_json::json!({
        "format":"memcordon.consumer-readiness.native-harnesses","revision":1,
        "source":selected,"native_target":target,
        "roles":[
            {"role":"operational","package":"memcordon","test":"sealed_agent","features":features,
                "executable":operational.executable,"sha256":operational.sha256,
                "compiler_output":operational.compiler_output,"compiler_errors":operational.compiler_errors},
            {"role":"parser","package":"memcordon-readiness-verifier","test":"contract","features":null,
                "executable":parser.executable,"sha256":parser.sha256,
                "compiler_output":parser.compiler_output,"compiler_errors":parser.compiler_errors}
        ]}))?,
    )?;
    retain_acquisition_origin(root, selected, target, destination)?;
    if Instant::now() >= deadline {
        return Err(CiError::Message(
            "original native component build exceeded its operation deadline".into(),
        ));
    }
    Ok(())
}

fn retain_acquisition_origin(
    root: &Path,
    selected: &source::BuildSourceIdentity,
    target: &str,
    destination: &Path,
) -> Result<()> {
    let expected_job = match target {
        "x86_64-unknown-linux-gnu" => "native-linux-x64",
        "aarch64-unknown-linux-gnu" => "native-linux-arm64",
        "x86_64-pc-windows-msvc" => "native-windows-x64",
        "aarch64-pc-windows-msvc" => "native-windows-arm64",
        _ => {
            return Err(CiError::Message(
                "native acquisition origin target outside frozen set".into(),
            ));
        }
    };
    let job = std::env::var("GITHUB_JOB").map_err(|_| {
        CiError::Message("original native acquisition needs actual job context".into())
    })?;
    if job != expected_job {
        return Err(CiError::Message(
            "original native acquisition job/target association differs".into(),
        ));
    }
    let positive = |name: &str| -> Result<u64> {
        let value = std::env::var(name)
            .map_err(|_| CiError::Message(format!("original native {name} absent")))?;
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(CiError::Message(format!(
                "original native {name} is not positive decimal"
            )));
        }
        value
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| CiError::Message(format!("original native {name} exceeds range")))
    };
    let run = positive("GITHUB_RUN_ID")?;
    let attempt = positive("GITHUB_RUN_ATTEMPT")?;
    let fixture_sha256 = if target.ends_with("-pc-windows-msvc") {
        let (bundle, _) = super::target::TargetBundle::load(&root.join(".release/target"))?;
        if bundle.source != *selected || bundle.distribution.target != target {
            return Err(CiError::Message(
                "original native fixture source/target differs from acquired roles".into(),
            ));
        }
        Some(bundle.fixture.sha256)
    } else {
        None
    };
    publish_native_record(
        &destination.join("acquisition-origin.json"),
        &serde_json::to_vec(&serde_json::json!({
            "format":"memcordon.consumer-readiness.native-acquisition-origin","revision":1,"source":selected,"target":target,
            "job":job,"run_id":run.to_string(),"run_attempt":attempt,
            "harnesses_sha256":artifacts::checksum(&artifacts::read_file(&destination.join("measured-harnesses.json"))?),
            "host_sha256":artifacts::checksum(&artifacts::read_file(&destination.join("native-host.json"))?),
            "deadline_sha256":artifacts::checksum(&artifacts::read_file(&root.join(".release/native-operation-deadline.json"))?),
            "actor_sha256":if target.contains("windows"){Some(artifacts::checksum(&artifacts::read_file(&destination.join("actor/internal-actor-build.json"))?))}else{None},
            "fixture_sha256":fixture_sha256
        }))?,
    )
}

#[cfg(any(target_os = "linux", windows))]
fn retain_original_host(
    root: &Path,
    selected: &source::BuildSourceIdentity,
    target: &str,
    destination: &Path,
    deadline: Instant,
) -> Result<()> {
    let host = super::readiness_product::native_host(root, target, deadline)?;
    let toolchain = crate::config::toolchains(root)?.stable;
    let located = CommandSpec::new("rustup", root, Duration::from_secs(30))
        .args(["which", "--toolchain", &toolchain, "rustc"])
        .bounded_until(deadline)
        .output_quiet()?;
    if !located.status.success() {
        return Err(CiError::Message(
            "original measured compiler unavailable".into(),
        ));
    }
    let compiler = PathBuf::from(
        std::str::from_utf8(&located.stdout)
            .map_err(|_| CiError::Message("original compiler path encoding differs".into()))?
            .trim(),
    );
    let bytes = artifacts::read_file(&compiler)?;
    super::target::validate_executable(&bytes, target)?;
    if artifacts::checksum(&bytes) != host.toolchain_sha256 {
        return Err(CiError::Message(
            "original native compiler changes during acquisition".into(),
        ));
    }
    let version = CommandSpec::new(&compiler, root, Duration::from_secs(30))
        .args(["--version", "--verbose"])
        .bounded_until(deadline)
        .output_quiet()?;
    if !version.status.success()
        || std::str::from_utf8(&version.stdout).ok().map(str::trim)
            != Some(host.toolchain_identity.as_str())
    {
        return Err(CiError::Message(
            "original native compiler verbose identity changes".into(),
        ));
    }
    for (name, bytes) in [
        ("native-compiler.bin", bytes.as_slice()),
        ("compiler-path.stdout", located.stdout.as_slice()),
        ("compiler-path.stderr", located.stderr.as_slice()),
        ("compiler-identity.stdout", version.stdout.as_slice()),
        ("compiler-identity.stderr", version.stderr.as_slice()),
    ] {
        publish_native_record(&destination.join(name), bytes)?;
    }
    publish_native_record(
        &destination.join("native-host.json"),
        &serde_json::to_vec(
            &serde_json::json!({"format":"memcordon.consumer-readiness.original-native-host","revision":1,
        "source":selected,"target":target,"host":host,"compiler":compiler,"compiler_artifact":"native-compiler.bin","compiler_length":bytes.len(),"compiler_sha256":artifacts::checksum(&bytes),
        "compiler_path_stdout":"compiler-path.stdout","compiler_path_stderr":"compiler-path.stderr",
        "compiler_identity_stdout":"compiler-identity.stdout","compiler_identity_stderr":"compiler-identity.stderr"}),
        )?,
    )?;
    Ok(())
}

/// Build the separately measured internal fault actor package. These binaries
/// never replace the ordinary installed consumer or enter its native archive.
#[cfg(windows)]
fn build_windows_actor(
    root: &Path,
    selected: &source::BuildSourceIdentity,
    target: &str,
    destination: &Path,
    deadline: Instant,
) -> Result<()> {
    use memcordon_core::runtime_manifest::{RuntimeComponentRole, RuntimeManifest};
    if !matches!(target, "x86_64-pc-windows-msvc" | "aarch64-pc-windows-msvc")
        || target != distribution::native_target()?
    {
        return Err(CiError::Message(
            "internal actor build requires its actual native Windows target".into(),
        ));
    }
    fs::create_dir(destination)?;
    let build_root = root.join("target/ci/native-readiness-support");
    let toolchain = crate::config::toolchains(root)?.stable;
    let names = [
        ("memcordon", RuntimeComponentRole::PublicCli),
        ("memcordon-sealed-agent", RuntimeComponentRole::SealedAgent),
        (
            "memcordon-target-desktop-bootstrap",
            RuntimeComponentRole::DesktopBootstrap,
        ),
        (
            "memcordon-session-broker",
            RuntimeComponentRole::SessionBroker,
        ),
    ];
    let mut command = CommandSpec::new("rustup", root, Duration::from_secs(45 * 60))
        .args([
            "run",
            &toolchain,
            "cargo",
            "build",
            "--release",
            "--locked",
            "--message-format=json",
            "--package",
            "memcordon",
            "--features",
            "windows-sealed-runtime,test-support",
            "--target",
            target,
        ])
        .arg("--target-dir")
        .arg(&build_root)
        .bounded_until(deadline);
    for (name, _) in &names {
        command = command.arg("--bin").arg(name);
    }
    let output = command.output_quiet()?;
    for (name, bytes) in [
        ("cargo-output.jsonl", output.stdout.as_slice()),
        ("cargo-stderr.bin", output.stderr.as_slice()),
    ] {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination.join(name))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    source::write_json(
        &destination.join("cargo-status.json"),
        &serde_json::json!({"status":output.status.code(),"target":target,"features":["test-support","windows-sealed-runtime"]}),
    )?;
    if !output.status.success() {
        return Err(CiError::Message(
            "actual internal actor compilation failed; original compiler observations retained"
                .into(),
        ));
    }
    let mut emitted = std::collections::BTreeMap::new();
    for message in cargo_metadata::Message::parse_stream(output.stdout.as_slice()) {
        if let cargo_metadata::Message::CompilerArtifact(artifact) =
            message.map_err(|error| CiError::Message(error.to_string()))?
        {
            if names.iter().any(|(name, _)| *name == artifact.target.name) && !artifact.profile.test
            {
                if let Some(path) = artifact.executable {
                    if emitted
                        .insert(artifact.target.name, path.into_std_path_buf())
                        .is_some()
                    {
                        return Err(CiError::Message(
                            "duplicate actual internal actor executable".into(),
                        ));
                    }
                }
            }
        }
    }
    let mut components = Vec::new();
    let mut held = Vec::new();
    for (name, role) in names {
        let actual = emitted.remove(name).ok_or_else(|| {
            CiError::Message("actual Cargo output omitted internal actor component".into())
        })?;
        if !actual.starts_with(&build_root) {
            return Err(CiError::Message(
                "internal actor executable escaped native build root".into(),
            ));
        }
        let bytes = artifacts::read_file(&actual)?;
        super::target::validate_executable(&bytes, target)?;
        let filename = format!("{name}.exe");
        let checksum = artifacts::checksum(&bytes);
        held.push(crate::windows_readiness_adapter::copy_owned_artifact(
            &actual,
            &destination.join(&filename),
            &checksum,
        )?);
        components.push(super::target::runtime_component(role, filename, &bytes));
    }
    selected.recheck(root)?;
    let runtime = RuntimeManifest::windows(
        selected.version().to_string(),
        selected.commit().to_owned(),
        target.to_owned(),
        components,
    )
    .map_err(CiError::Message)?;
    source::write_json(&destination.join("runtime-manifest.json"), &runtime)?;
    source::write_json(
        &destination.join("internal-actor-build.json"),
        &serde_json::json!({"format":"memcordon.consumer-readiness.internal-actor-build","revision":1,"source":selected,"native_target":target,"features":["test-support","windows-sealed-runtime"],"runtime_manifest":runtime}),
    )?;
    Ok(())
}

/// Build exactly one native harness and retain its actual Cargo association.
/// A successful build does not establish a component case or profile readiness.
pub fn build(
    root: &Path,
    target: &str,
    package: &str,
    test: &str,
    features: Option<&str>,
    destination: &Path,
    deadline: Instant,
) -> Result<MeasuredHarness> {
    if !matches!(
        target,
        "x86_64-unknown-linux-gnu"
            | "aarch64-unknown-linux-gnu"
            | "x86_64-pc-windows-msvc"
            | "aarch64-pc-windows-msvc"
    ) || target != distribution::native_target()?
    {
        return Err(CiError::Message(
            "component harness must be built on its actual native target".into(),
        ));
    }
    match (package, test, features) {
        ("memcordon", "sealed_agent", Some("private-tcp,test-support"))
            if target.ends_with("-unknown-linux-gnu") =>
        {
            ()
        }
        ("memcordon", "sealed_agent", Some("windows-sealed-runtime,test-support"))
            if target.ends_with("-pc-windows-msvc") =>
        {
            ()
        }
        ("memcordon-readiness-verifier", "contract", None) => (),
        _ => {
            return Err(CiError::Message(
                "component harness recipe is not a frozen native role".into(),
            ));
        }
    }
    fs::create_dir(destination)?;
    let build_root = root.join("target/ci/native-readiness-components");
    let toolchain = crate::config::toolchains(root)?.stable;
    let mut command = CommandSpec::new("rustup", root, Duration::from_secs(45 * 60))
        .args([
            "run",
            &toolchain,
            "cargo",
            "test",
            "--locked",
            "--release",
            "--no-run",
            "--message-format=json",
            "--package",
            package,
            "--test",
            test,
            "--target",
            target,
        ])
        .arg("--target-dir")
        .arg(&build_root)
        .bounded_until(deadline);
    if let Some(features) = features {
        command = command.args(["--features", features]);
    }
    let output = command.output_quiet()?;
    let compiler_output = destination.join("cargo-output.jsonl");
    let compiler_errors = destination.join("cargo-stderr.bin");
    for (path, bytes) in [
        (&compiler_output, &output.stdout),
        (&compiler_errors, &output.stderr),
    ] {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    source::write_json(
        &destination.join("cargo-status.json"),
        &serde_json::json!({"status":output.status.code(),"package":package,"test":test,"target":target,"features":features}),
    )?;
    if !output.status.success() {
        return Err(CiError::Message(
            "native component harness build failed; actual compiler outputs retained".into(),
        ));
    }
    let mut selected = None;
    for message in cargo_metadata::Message::parse_stream(output.stdout.as_slice()) {
        let message = message
            .map_err(|error| CiError::Message(format!("component Cargo message: {error}")))?;
        if let cargo_metadata::Message::CompilerArtifact(artifact) = message {
            if artifact.target.name == test && artifact.profile.test {
                if let Some(executable) = artifact.executable {
                    if selected.replace(executable.into_std_path_buf()).is_some() {
                        return Err(CiError::Message(
                            "native Cargo emitted duplicate selected test harnesses".into(),
                        ));
                    }
                }
            }
        }
    }
    let selected = selected.ok_or_else(|| {
        CiError::Message("actual Cargo output lacks selected native harness executable".into())
    })?;
    if !selected.starts_with(&build_root) {
        return Err(CiError::Message(
            "native harness executable escapes its typed build root".into(),
        ));
    }
    let bytes = artifacts::read_file(&selected)?;
    super::target::validate_executable(&bytes, target)?;
    let sha256 = artifacts::checksum(&bytes);
    let executable = destination.join(if target.ends_with("-pc-windows-msvc") {
        "native-test-harness.exe"
    } else {
        "native-test-harness"
    });
    #[cfg(windows)]
    let custody =
        crate::windows_readiness_adapter::copy_owned_artifact(&selected, &executable, &sha256)?;
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&executable)?;
        file.write_all(&bytes)?;
        file.set_permissions(fs::Permissions::from_mode(0o555))?;
        file.sync_all()?;
        if artifacts::read_file(&executable)? != bytes {
            return Err(CiError::Message(
                "native test harness copy differs from actual Cargo executable".into(),
            ));
        }
    }
    #[cfg(unix)]
    fs::File::open(destination)?.sync_all()?;
    Ok(MeasuredHarness {
        executable,
        sha256,
        compiler_output,
        compiler_errors,
        #[cfg(windows)]
        _custody: custody,
    })
}
