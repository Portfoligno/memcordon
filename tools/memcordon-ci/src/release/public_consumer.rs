//! Optional read-only consumer of the bytes actually exposed by the registry.
use super::{artifacts, bundle::PreparedBundle, http};
use crate::{
    CiError, Result,
    command::{CommandSpec, rustup_cargo},
    public_reads::map_public_reads_ordered,
};
use memcordon_core::{
    ChildTermination,
    result_v1::{CleanupStateV1, OutcomeKindV1, ResultV1},
};
use std::{
    fs,
    num::NonZeroUsize,
    path::Path,
    time::{Duration, Instant},
};

fn observe(
    command: CommandSpec,
    deadline: Duration,
    diagnostics: &Path,
    name: &str,
) -> Result<memcordon_testkit::ObservedOutput> {
    let observation = memcordon_testkit::run_with_deadline_output_limit(
        &mut command.materialize()?,
        deadline,
        16 * 1024 * 1024,
    );
    let captured = match &observation {
        Ok(output) => Some((&output.stdout, &output.stderr)),
        Err(memcordon_testkit::ProcessTestError::Timeout { stdout, stderr, .. }) => {
            Some((stdout, stderr))
        }
        Err(_) => None,
    };
    if let Some((stdout, stderr)) = captured {
        fs::write(diagnostics.join(name).with_extension("stdout.bin"), stdout)?;
        fs::write(diagnostics.join(name).with_extension("stderr.bin"), stderr)?;
    }
    match observation {
        Ok(output) => Ok(output),
        Err(error) => {
            fs::write(
                diagnostics.join(name).with_extension("error.txt"),
                format!("{error}\n"),
            )?;
            Err(error.into())
        }
    }
}

pub fn run(directory: &Path, toolchain: &str) -> Result<()> {
    let bundle = PreparedBundle::load(directory)?;
    if !bundle.metadata.distribution.public_consumer {
        return Err(CiError::Message("public consumer was not selected".into()));
    }
    let diagnostics = directory.join("public-consumer-results");
    fs::create_dir(&diagnostics)?;
    let budget = http::ReadBudget::new(Instant::now() + Duration::from_secs(300));
    let crates: Vec<_> = bundle
        .metadata
        .files
        .iter()
        .filter(|record| record.kind == "crate")
        .collect();
    map_public_reads_ordered(
        &crates,
        NonZeroUsize::new(4).unwrap(),
        budget.deadline,
        |_, record, _| {
            let mut url = url::Url::parse("https://static.crates.io/crates/")
                .map_err(|_| CiError::Message("registry URL invalid".into()))?;
            url.path_segments_mut()
                .map_err(|_| CiError::Message("registry URL cannot hold a path".into()))?
                .pop_if_empty()
                .push(
                    record
                        .package
                        .as_deref()
                        .ok_or_else(|| CiError::Message("crate package absent".into()))?,
                )
                .push(&record.name);
            let bytes = http::download(
                &http::HttpsTransport,
                &budget,
                &url,
                &[],
                artifacts::MAX_FILE_BYTES,
            )?;
            artifacts::check_bytes(record, &bytes)
        },
    )?;
    #[cfg(unix)]
    let workspace = tempfile::Builder::new()
        .prefix("memcordon-public-consumer-")
        .tempdir_in("/tmp")?;
    #[cfg(not(unix))]
    let workspace = tempfile::Builder::new()
        .prefix("memcordon-public-consumer-")
        .tempdir()?;
    let root = workspace.path();
    let version = &bundle.metadata.source.version;
    let requirement = semver::VersionReq {
        comparators: vec![semver::Comparator {
            op: semver::Op::Exact,
            major: version.major,
            minor: Some(version.minor),
            patch: Some(version.patch),
            pre: version.pre.clone(),
        }],
    }
    .to_string();
    let mut dependencies = toml::Table::new();
    for name in super::source::PUBLIC_PACKAGES {
        dependencies.insert(name.into(), toml::Value::String(requirement.clone()));
    }
    let manifest = toml::Table::from_iter([
        (
            "package".into(),
            toml::Value::Table(toml::Table::from_iter([
                (
                    "name".into(),
                    toml::Value::String("memcordon-public-consumer".into()),
                ),
                ("version".into(), toml::Value::String("0.0.0".into())),
                ("edition".into(), toml::Value::String("2024".into())),
            ])),
        ),
        ("dependencies".into(), toml::Value::Table(dependencies)),
        ("workspace".into(), toml::Value::Table(toml::Table::new())),
    ]);
    fs::write(
        root.join("Cargo.toml"),
        toml::to_string(&manifest).map_err(|error| CiError::Message(error.to_string()))?,
    )?;
    fs::create_dir(root.join("src"))?;
    fs::write(
        root.join("src/main.rs"),
        r#"fn main() {
    let size: memcordon_core::ByteSize = "4MiB".parse().unwrap();
    assert_eq!(size.bytes(), 4 * 1024 * 1024);
    let _policy = memcordon::Policy::new(size);
    let _platform_api: fn(&memcordon_platform::BackendInfo) -> memcordon_core::BackendCapabilityReport = memcordon_platform::capabilities;
    let handles = memcordon_windows_launch_core::ExactHandleListV1::none();
    assert!(handles.roles().is_empty());
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--hold")) {
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
}
"#,
    )?;
    let lockfile = observe(
        rustup_cargo(
            root,
            toolchain,
            ["generate-lockfile"],
            Duration::from_secs(300),
        ),
        Duration::from_secs(300),
        &diagnostics,
        "generate-lockfile",
    )?;
    if !lockfile.status.success() {
        return Err(CiError::Message(
            "published consumer lockfile generation failed".into(),
        ));
    }
    let downstream = observe(
        rustup_cargo(
            root,
            toolchain,
            ["run", "--locked", "--target-dir"],
            Duration::from_secs(900),
        )
        .arg(root.join("consumer-target")),
        Duration::from_secs(900),
        &diagnostics,
        "downstream",
    )?;
    if !downstream.status.success() {
        return Err(CiError::Message(
            "published four-package downstream consumer failed".into(),
        ));
    }
    let installation = observe(
        rustup_cargo(
            root,
            toolchain,
            ["install", "--locked", "--version"],
            Duration::from_secs(1800),
        )
        .arg(requirement)
        .arg("--root")
        .arg(root.join("installed"))
        .arg("memcordon"),
        Duration::from_secs(1800),
        &diagnostics,
        "install",
    )?;
    if !installation.status.success() {
        return Err(CiError::Message("published CLI installation failed".into()));
    }
    let executable = if cfg!(windows) {
        "memcordon.exe"
    } else {
        "memcordon"
    };
    let cli = root.join("installed/bin").join(executable);
    let output = observe(
        CommandSpec::new(&cli, root, Duration::from_secs(30)).arg("--version"),
        Duration::from_secs(30),
        &diagnostics,
        "version",
    )?;
    if !output.status.success()
        || std::str::from_utf8(&output.stdout).map(str::trim)
            != Ok(format!("memcordon {version}").as_str())
    {
        return Err(CiError::Message(
            "published Cargo installation version differs".into(),
        ));
    }
    let workload = root.join("consumer-target/debug").join(if cfg!(windows) {
        "memcordon-public-consumer.exe"
    } else {
        "memcordon-public-consumer"
    });
    for (name, expected) in [
        ("success", OutcomeKindV1::Completed),
        ("deadline", OutcomeKindV1::Deadline),
    ] {
        let report_path = root.join(name).with_extension("json");
        let mut command = CommandSpec::new(&cli, root, Duration::from_secs(30));
        if expected == OutcomeKindV1::Deadline {
            command = command.arg("+200ms");
        }
        command = command
            .arg("--report-format")
            .arg("result-v1")
            .arg("--report")
            .arg(&report_path)
            .arg("--")
            .arg(&workload);
        if expected == OutcomeKindV1::Deadline {
            command = command.arg("--hold");
        }
        let observation = observe(command, Duration::from_secs(30), &diagnostics, name);
        if report_path.exists() {
            fs::write(
                diagnostics.join(name).with_extension("json"),
                artifacts::read_file(&report_path)?,
            )?;
        }
        let output = observation?;
        let report_bytes = artifacts::read_file(&report_path)?;
        fs::write(diagnostics.join(name).with_extension("json"), &report_bytes)?;
        let result = ResultV1::parse(&report_bytes).map_err(CiError::Message)?;
        if result.tool.version != version.to_string()
            || result.outcome.kind != expected
            || output.status.code() != Some(result.outcome.wrapper_status)
            || result.cleanup.state != CleanupStateV1::Complete
            || !result.cleanup.direct_child_reaped
            || result.cleanup.workload_empty != Some(true)
            || (expected == OutcomeKindV1::Completed
                && (result.outcome.wrapper_status != 0
                    || result.outcome.native_termination
                        != Some(ChildTermination::ExitCode { code: 0 })))
        {
            return Err(CiError::Message(format!(
                "published installed consumer {name} execution or retirement differs"
            )));
        }
    }
    Ok(())
}
