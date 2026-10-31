//! One installed Linux invocation owns its package, actors and live test work.
//! Image/compiler preparation is unprivileged; only this fixed native helper
//! performs package/account operations and invokes the ordinary fixture actors.
use super::{
    artifacts,
    distribution::TargetDistribution,
    installed_consumer::MaterializedPayload,
    linux_request_fixture::CallerSession,
    linux_test_execution::{CallerImages, TestInput},
    linux_test_images::PreparedImages,
    source::{self, BuildSourceIdentity},
};
use crate::{
    CiError, Result,
    command::{CommandSpec, require_successful_output},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(clap::Args)]
pub struct PrivilegedArgs {
    #[arg(long)]
    pub input: PathBuf,
    #[arg(long)]
    pub output: PathBuf,
    #[arg(long)]
    pub work_cutoff_millis: u64,
    #[arg(long)]
    pub cleanup_cutoff_millis: u64,
}

/// Actual bytes and file locations consumed by this operation, never a verdict.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    source: BuildSourceIdentity,
    distribution: TargetDistribution,
    directory: PathBuf,
    images: PreparedImages,
    components_only: bool,
}

fn fail(message: impl Into<String>) -> CiError {
    CiError::Message(message.into())
}

pub fn run(
    root: &Path,
    payload: &MaterializedPayload,
    output: &Path,
    work: Instant,
    cleanup: Instant,
) -> Result<()> {
    run_selected(root, payload, output, work, cleanup, false, None)
}

pub fn run_components(root: &Path, output: &Path, work: Instant, cleanup: Instant) -> Result<()> {
    let session = tempfile::Builder::new()
        .prefix("memcordon-components-")
        .tempdir()?;
    let payload = super::installed_consumer::materialize_native(
        &root.join(".release/target"),
        session.path(),
    )?;
    let execution = session.path().join("execution");
    fs::create_dir(&execution)?;
    let relative = output.strip_prefix(root).unwrap_or(output);
    let record = relative.join("helper-command").join("command-output.json");
    let checked = crate::native_paths::record_path(root, &record)?;
    let diagnostics = checked
        .parent()
        .expect("fixed helper record parent")
        .parent()
        .expect("fixed helper diagnostics parent")
        .to_path_buf();
    fs::create_dir_all(&diagnostics)?;
    crate::native_paths::record_path(root, &record)?;
    run_selected(
        root,
        &payload,
        &execution,
        work,
        cleanup,
        true,
        Some(&diagnostics),
    )
}

fn run_selected(
    root: &Path,
    payload: &MaterializedPayload,
    output: &Path,
    work: Instant,
    cleanup: Instant,
    components_only: bool,
    capture_parent: Option<&Path>,
) -> Result<()> {
    if rustix::process::geteuid().is_root() || work >= cleanup || Instant::now() >= work {
        return Err(fail(
            "installed Linux preparation requires an unprivileged caller and live original cutoffs",
        ));
    }
    super::installed_consumer::require_current_runtime(payload)?;
    payload.source.recheck(root)?;
    payload.selected_case_artifacts()?;
    let native_output = output.join("linux");
    fs::create_dir(&native_output)?;
    let images = super::linux_test_images::materialize_until(
        payload,
        root,
        &native_output.join("prepared-images"),
        work,
    )?;
    let input = native_output.join("inputs.json");
    source::write_json_new(
        &input,
        &Inputs {
            source: payload.source.clone(),
            distribution: payload.distribution.clone(),
            directory: payload.directory.clone(),
            images,
            components_only,
        },
    )?;
    let helper_capture = capture_parent
        .unwrap_or(&native_output)
        .join("helper-command");
    fs::create_dir(&helper_capture)?;
    fs::set_permissions(&helper_capture, fs::Permissions::from_mode(0o700))?;
    let native_now = super::linux_test_images::monotonic_millis()?;
    let now = Instant::now();
    let work_millis = native_now
        .checked_add(
            u64::try_from(work.saturating_duration_since(now).as_millis())
                .map_err(|error| CiError::Message(error.to_string()))?,
        )
        .ok_or_else(|| fail("native work cutoff overflow"))?;
    let cleanup_millis = native_now
        .checked_add(
            u64::try_from(cleanup.saturating_duration_since(now).as_millis())
                .map_err(|error| CiError::Message(error.to_string()))?,
        )
        .ok_or_else(|| fail("native cleanup cutoff overflow"))?;
    let child_owner = std::sync::Arc::new(std::sync::Mutex::new(None));
    let io_owner = child_owner.clone();
    let observed = CommandSpec::new("sudo", root, cleanup.saturating_duration_since(now))
        .bounded_until(cleanup)
        .args(["--non-interactive", "--"])
        .arg(std::env::current_exe()?)
        .args(["release", "installed-linux-setup", "--input"])
        .arg(input)
        .arg("--output")
        .arg(native_output.join("native"))
        .arg("--work-cutoff-millis")
        .arg(work_millis.to_string())
        .arg("--cleanup-cutoff-millis")
        .arg(cleanup_millis.to_string())
        .output_quiet_for_installed_helper_with_creation_and_io(
            &helper_capture,
            |child| {
                let birth = crate::linux_consumer_readiness::process_birth(child.id())
                    .map_err(CiError::Message)?;
                let held =
                    crate::linux_consumer_readiness::HeldLinuxProcess::acquire(child.id(), birth)
                        .map_err(CiError::Message)?;
                *child_owner.lock().expect("native helper owner lock") = Some(held);
                Ok(())
            },
            move |_, stdin, _| {
                let mut stdin = stdin.ok_or_else(|| {
                    std::io::Error::other("native helper cancellation input absent")
                })?;
                let mut forwarded = false;
                loop {
                    let retired = io_owner
                        .lock()
                        .expect("native helper owner lock")
                        .as_ref()
                        .ok_or_else(|| {
                            std::io::Error::other("native helper original child not held")
                        })?
                        .exited()
                        .map_err(std::io::Error::other)?;
                    if retired {
                        return Ok(());
                    }
                    if !forwarded && crate::cancellation::observed().is_some() {
                        stdin.write_all(&[3])?;
                        stdin.flush()?;
                        forwarded = true;
                    }
                    if Instant::now() >= cleanup {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "original native helper cleanup cutoff expired",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            },
        )?;
    require_successful_output("direct installed Linux helper", &observed)
}

struct Directory {
    path: PathBuf,
    held: File,
}
impl Directory {
    fn create(parent: &Path, prefix: &str) -> Result<Self> {
        let temporary = tempfile::Builder::new().prefix(prefix).tempdir_in(parent)?;
        let path = temporary.path().to_path_buf();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        let held = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        if held.metadata()?.uid() != 0 {
            return Err(fail("new native fixture root is not root-owned"));
        }
        let path = temporary.keep();
        Ok(Self { path, held })
    }
    fn finish(&self, cutoff: Instant) -> Result<()> {
        let before = self.held.metadata()?;
        let named = fs::symlink_metadata(&self.path)?;
        if !named.is_dir()
            || named.file_type().is_symlink()
            || (before.dev(), before.ino(), before.uid()) != (named.dev(), named.ino(), named.uid())
        {
            return Err(fail("owned fixture root was replaced before retirement"));
        }
        retire_tree(&self.held, 0, &mut 1_000_000, cutoff)?;
        let named = fs::symlink_metadata(&self.path)?;
        if (before.dev(), before.ino()) != (named.dev(), named.ino()) {
            return Err(fail("owned fixture root replaced during retirement"));
        }
        fs::remove_dir(&self.path)?;
        Ok(())
    }
}

struct Actor {
    name: String,
    marker: String,
    group_id: u32,
    session: Option<CallerSession>,
}
impl Actor {
    fn allocate(
        root: &Path,
        name: String,
        marker: String,
        cutoff: Instant,
        cleanup: Instant,
    ) -> Result<Self> {
        let mut nonce = [0_u8; 4];
        getrandom::fill(&mut nonce).map_err(|error| CiError::Message(error.to_string()))?;
        let first = 1_000_000 + u32::from_ne_bytes(nonce) % 1_000_000;
        let mut group_id = None;
        for offset in 0..16 {
            let candidate = first + offset;
            let existing = CommandSpec::new("/usr/bin/getent", root, Duration::from_secs(30))
                .bounded_until(cutoff)
                .args(["group", &candidate.to_string()])
                .output_quiet()?;
            if existing.status.code() == Some(2) && existing.stdout.is_empty() {
                group_id = Some(candidate);
                break;
            }
            require_successful_output("candidate test group lookup", &existing)?;
        }
        let mut owner = Self {
            name,
            marker,
            group_id: group_id
                .ok_or_else(|| fail("no unused bounded test group identifier found"))?,
            session: None,
        };
        // The owner exists before useradd so partial allocation is finalized.
        let creation = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.create(root, cutoff)
        })) {
            Ok(result) => result,
            Err(panic) => {
                let _retirement = crate::cancellation::retirement_scope(cleanup);
                if let Err(error) = owner.finish(root, cleanup) {
                    eprintln!("partial test actor cleanup after unwind: {error}");
                }
                std::panic::resume_unwind(panic)
            }
        };
        if let Err(primary) = creation {
            let _retirement = crate::cancellation::retirement_scope(cleanup);
            return match owner.finish(root, cleanup) {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(CiError::Message(format!(
                    "{primary}; partial actor cleanup: {cleanup}"
                ))),
            };
        }
        Ok(owner)
    }
    fn create(&mut self, root: &Path, cutoff: Instant) -> Result<()> {
        for kind in ["passwd", "group"] {
            let existing = CommandSpec::new("/usr/bin/getent", root, Duration::from_secs(30))
                .bounded_until(cutoff)
                .args([kind, &self.name])
                .output_quiet()?;
            if existing.status.code() != Some(2) || !existing.stdout.is_empty() {
                return Err(fail("temporary actor name is already occupied"));
            }
        }
        let gid = self.group_id.to_string();
        operation(
            root,
            Path::new("/usr/sbin/groupadd"),
            &["--system", "--gid", &gid, &self.name],
            cutoff,
        )?;
        operation(
            root,
            Path::new("/usr/sbin/useradd"),
            &[
                "--system",
                "--gid",
                &gid,
                "--no-create-home",
                "--home-dir",
                "/nonexistent",
                "--shell",
                "/usr/sbin/nologin",
                "--password",
                "!",
                "--comment",
                &self.marker,
                "--groups",
                "memcordon",
                &self.name,
            ],
            cutoff,
        )?;
        let read = |kind: &str| -> Result<u32> {
            let bytes = operation(root, Path::new("/usr/bin/id"), &[kind, &self.name], cutoff)?;
            std::str::from_utf8(&bytes)
                .map_err(|error| CiError::Message(error.to_string()))?
                .trim()
                .parse::<u32>()
                .map_err(|error| CiError::Message(error.to_string()))
        };
        let uid = read("-u")?;
        let gid = read("-g")?;
        if uid == 0 || gid != self.group_id {
            return Err(fail("ordinary test actor resolved to root"));
        }
        self.session = Some(CallerSession {
            uid,
            gid,
            installed_cli: "/usr/libexec/memcordon".into(),
        });
        Ok(())
    }
    fn finish(&self, root: &Path, cutoff: Instant) -> Result<()> {
        let record = CommandSpec::new("/usr/bin/getent", root, Duration::from_secs(30))
            .bounded_until(cutoff)
            .args(["passwd", &self.name])
            .output_quiet()?;
        if !(record.status.code() == Some(2) && record.stdout.is_empty()) {
            require_successful_output("owned test actor readback", &record)?;
            let text = std::str::from_utf8(&record.stdout)
                .map_err(|error| CiError::Message(error.to_string()))?;
            let rows = text.lines().collect::<Vec<_>>();
            if rows.len() != 1 {
                return Err(fail("owned actor account readback is ambiguous"));
            }
            let fields = rows[0].split(':').collect::<Vec<_>>();
            if fields.len() != 7
                || fields[0] != self.name
                || fields[4] != self.marker
                || fields[2].parse::<u32>().ok().is_none_or(|uid| uid == 0)
                || fields[3].parse::<u32>().ok() != Some(self.group_id)
            {
                return Err(fail("refusing to remove a replacement actor account"));
            }
            if let Some(session) = &self.session
                && (fields[2].parse::<u32>().ok() != Some(session.uid)
                    || fields[3].parse::<u32>().ok() != Some(session.gid))
            {
                return Err(fail("owned actor native identity changed"));
            }
            operation(root, Path::new("/usr/sbin/userdel"), &[&self.name], cutoff)?;
        }
        let group = CommandSpec::new("/usr/bin/getent", root, Duration::from_secs(30))
            .bounded_until(cutoff)
            .args(["group", &self.name])
            .output_quiet()?;
        if group.status.code() == Some(2) && group.stdout.is_empty() {
            return Ok(());
        }
        require_successful_output("owned actor group readback", &group)?;
        let text = std::str::from_utf8(&group.stdout)
            .map_err(|error| CiError::Message(error.to_string()))?;
        let fields = text.trim_end_matches('\n').split(':').collect::<Vec<_>>();
        if fields.len() != 4
            || fields[0] != self.name
            || !fields[3].is_empty()
            || fields[2].parse::<u32>().ok() != Some(self.group_id)
        {
            return Err(fail("owned actor group was replaced or gained members"));
        }
        operation(root, Path::new("/usr/sbin/groupdel"), &[&self.name], cutoff).map(|_| ())
    }
}

fn operation(
    root: &Path,
    executable: &Path,
    arguments: &[&str],
    cutoff: Instant,
) -> Result<Vec<u8>> {
    CommandSpec::new(executable, root, Duration::from_secs(300))
        .bounded_until(cutoff)
        .args(arguments.iter().copied())
        .run()
}

struct Session<'a> {
    root: &'a Path,
    admin: Directory,
    working: Directory,
    actors: Vec<Actor>,
    installed: bool,
    selected: Vec<String>,
    source_files: Vec<File>,
    before_network: serde_json::Value,
    cleanup: Instant,
}
impl Session<'_> {
    fn finish(&mut self) -> Result<()> {
        let _retirement = crate::cancellation::retirement_scope(self.cleanup);
        let mut errors = Vec::new();
        if self.installed {
            let result = operation(
                self.root,
                &self.admin.path.join("memcordon-sealed-agent"),
                &["package", "uninstall"],
                self.cleanup,
            );
            if let Err(error) = result {
                errors.push(format!("owned package uninstall: {error}"));
            }
        }
        for actor in self.actors.iter().rev() {
            if let Err(error) = actor.finish(self.root, self.cleanup) {
                errors.push(format!("owned actor cleanup: {error}"));
            }
        }
        for binary in &self.selected {
            match fs::symlink_metadata(Path::new("/usr/libexec").join(binary)) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => errors.push(error.to_string()),
                Ok(_) => errors.push(format!("owned installed binary remains: {binary}")),
            }
        }
        if let Err(error) = assert_absent_runtime(self.root, self.cleanup) {
            errors.push(error.to_string());
        }
        let network = super::linux_current_network::snapshot().and_then(|after| {
            super::linux_current_network::host_network_comparison(&self.before_network, &after)
        });
        match network {
            Ok(comparison) if comparison["unchanged"] == true => (),
            Ok(_) => errors.push("host network configuration changed".into()),
            Err(error) => errors.push(error.to_string()),
        }
        if errors.is_empty() {
            self.source_files.clear();
            if let Err(error) = self.working.finish(self.cleanup) {
                errors.push(error.to_string());
            }
            if let Err(error) = self.admin.finish(self.cleanup) {
                errors.push(error.to_string());
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(CiError::Message(errors.join("; ")))
        }
    }
}

pub fn run_privileged(root: &Path, args: &PrivilegedArgs) -> Result<()> {
    let native_now = super::linux_test_images::monotonic_millis()?;
    if !rustix::process::geteuid().is_root()
        || args.work_cutoff_millis <= native_now
        || args.work_cutoff_millis >= args.cleanup_cutoff_millis
        || args.cleanup_cutoff_millis.saturating_sub(native_now) > 150 * 60 * 1000
    {
        return Err(fail(
            "installed native helper requires root and the original finite cleanup reserve",
        ));
    }
    let cancellation = crate::cancellation::Scope::install()?;
    std::thread::spawn(|| {
        let mut byte = [0_u8; 1];
        match std::io::stdin().read_exact(&mut byte) {
            Ok(()) => {
                if byte != [3] {
                    eprintln!("invalid native helper cancellation input");
                }
                let _ = rustix::process::kill_process(
                    rustix::process::getpid(),
                    rustix::process::Signal::TERM,
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => (),
            Err(error) => {
                eprintln!("native helper cancellation observer failed: {error}");
                let _ = rustix::process::kill_process(
                    rustix::process::getpid(),
                    rustix::process::Signal::TERM,
                );
            }
        }
    });
    let now = Instant::now();
    let native_now = super::linux_test_images::monotonic_millis()?;
    let work = now
        .checked_add(Duration::from_millis(
            args.work_cutoff_millis.saturating_sub(native_now),
        ))
        .ok_or_else(|| fail("work cutoff overflow"))?;
    let cleanup = now
        .checked_add(Duration::from_millis(
            args.cleanup_cutoff_millis.saturating_sub(native_now),
        ))
        .ok_or_else(|| fail("cleanup cutoff overflow"))?;
    let mut input_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&args.input)?;
    let metadata = input_file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > 16 * 1024 * 1024 {
        return Err(fail(
            "native installed inputs are not one bounded regular file",
        ));
    }
    let mut bytes = Vec::new();
    (&mut input_file)
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).map_err(CiError::Message)?;
    let inputs: Inputs = serde_json::from_slice(&bytes)?;
    inputs.source.validate()?;
    inputs.distribution.validate()?;
    let expected = super::distribution::Distribution::read(root)?
        .with_runtime_components()?
        .native()?
        .clone();
    if inputs.distribution != expected {
        return Err(fail(
            "native installed helper requires the closed current runtime distribution",
        ));
    }
    if inputs.distribution.target != super::distribution::native_target()?
        || !inputs.directory.is_absolute()
    {
        return Err(fail(
            "installed helper selected target or materialized root differs",
        ));
    }
    assert_absent_runtime(root, work)?;
    for binary in &inputs.distribution.binaries {
        match fs::symlink_metadata(Path::new("/usr/libexec").join(binary)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(fail(
                    "installed test refuses an occupied or unmanaged installation",
                ));
            }
        }
    }
    let before_network = super::linux_current_network::snapshot()?;
    crate::cancellation::check_admission()?;
    let admin = Directory::create(Path::new("/var/lib"), "memcordon-installed-test-")?;
    let working = match Directory::create(Path::new("/tmp"), "memcordon-installed-test-") {
        Ok(value) => value,
        Err(primary) => {
            let cleanup_result = admin.finish(cleanup);
            return Err(CiError::Message(format!(
                "{primary}; partial native directory cleanup: {cleanup_result:?}"
            )));
        }
    };
    let mut session = Session {
        root,
        admin,
        working,
        actors: Vec::new(),
        installed: false,
        selected: inputs.distribution.binaries.clone(),
        source_files: Vec::new(),
        before_network,
        cleanup,
    };
    let execution = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fs::set_permissions(&session.working.path, fs::Permissions::from_mode(0o755)).map_err(
            |error| {
                CiError::from(error).context(format!(
                    "installed working directory permissions path={}",
                    session.working.path.display()
                ))
            },
        )?;
        execute(&mut session, &inputs, &args.output, work)
            .map_err(|error| error.context("installed Linux workload execution"))
    }));
    let retirement = session
        .finish()
        .map_err(|error| error.context("installed Linux session retirement"));
    let result = match execution {
        Ok(Ok(())) => retirement,
        Ok(Err(primary)) => match retirement {
            Ok(()) => Err(primary),
            Err(cleanup) => Err(CiError::LaneFailures {
                primary: Box::new(primary),
                secondary: Box::new(cleanup),
            }),
        },
        Err(panic) => {
            if let Err(error) = retirement {
                eprintln!("installed cleanup after unwind failed: {error}");
            }
            std::panic::resume_unwind(panic)
        }
    };
    cancellation.finish(result)
}

fn execute(
    session: &mut Session<'_>,
    inputs: &Inputs,
    _output: &Path,
    work: Instant,
) -> Result<()> {
    protect_payload(inputs, &session.admin.path, work, &mut session.source_files).map_err(
        |error| {
            error.context(format!(
                "installed payload protection path={}",
                session.admin.path.display()
            ))
        },
    )?;
    let agent = session.admin.path.join("memcordon-sealed-agent");
    refuse_opaque_install(session.root, &agent, work)
        .map_err(|error| error.context("installed opaque-install refusal"))?;
    session.installed = true; // Even a partially failed install requires owned removal.
    operation(session.root, &agent, &["package", "install"], work)
        .map_err(|error| error.context("installed package install"))?;
    let verified = operation(
        session.root,
        Path::new("/usr/libexec/memcordon-sealed-agent"),
        &["package", "verify", "--json"],
        work,
    )
    .map_err(|error| error.context("installed package verification"))?;
    let manifest_bytes =
        fs::read("/usr/libexec/memcordon-runtime-manifest.json").map_err(|error| {
            CiError::from(error).context(
                "installed manifest read path=/usr/libexec/memcordon-runtime-manifest.json",
            )
        })?;
    let manifest = memcordon_core::runtime_manifest_v2::RuntimeManifestV2::parse(&manifest_bytes)
        .map_err(CiError::Message)?;
    if manifest.source_commit != inputs.source.commit()
        || manifest.version != inputs.source.version().to_string()
        || manifest.target != inputs.distribution.target
        || verified.is_empty()
    {
        return Err(fail(
            "actual installed manifest or package verification differs",
        ));
    }
    let provider = manifest
        .public_binding(&manifest_bytes)
        .map_err(CiError::Message)?;
    let mut nonce = [0_u8; 8];
    getrandom::fill(&mut nonce).map_err(|error| CiError::Message(error.to_string()))?;
    let suffix = hex::encode(nonce);
    let actor = Actor::allocate(
        session.root,
        format!("mc-test-{suffix}"),
        format!("memcordon-test-{suffix}"),
        work,
        session.cleanup,
    )?;
    session.actors.push(actor);
    let foreign = Actor::allocate(
        session.root,
        format!("mc-other-{suffix}"),
        format!("memcordon-other-{suffix}"),
        work,
        session.cleanup,
    )?;
    session.actors.push(foreign);
    let caller = session.actors[0]
        .session
        .as_ref()
        .expect("allocated actor has native credentials");
    let foreign = session.actors[1]
        .session
        .as_ref()
        .expect("allocated foreign actor has native credentials");
    let copied = copy_images(&inputs.images, &session.working.path.join("images"), work)
        .map_err(|error| error.context("installed caller image copy"))?;
    let images =
        CallerImages::materialize(copied, &session.working.path.join("images"), caller, work)
            .map_err(|error| error.context("installed caller image materialization"))?;
    let controllers = session.working.path.join("controllers");
    fs::create_dir(&controllers).map_err(|error| {
        CiError::from(error).context(format!(
            "installed controllers create path={}",
            controllers.display()
        ))
    })?;
    if inputs.components_only {
        for facet in [
            "release-barrier",
            "journal-barrier",
            "crash-before-root-retirement",
            "lost-terminal-response",
        ] {
            let result = (|| -> Result<()> {
                crate::cancellation::check_admission()?;
                let controller = controllers.join(facet);
                fs::create_dir(&controller)?;
                let directory = session.working.path.join(facet);
                fs::create_dir(&directory)?;
                fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
                std::os::unix::fs::chown(&directory, Some(caller.uid), Some(caller.gid))?;
                let observed = super::linux_test_lifetime::experiment(
                    caller,
                    &images,
                    &provider,
                    super::linux_test_lifetime::ExperimentContext {
                        controller: &controller,
                        directory: &directory,
                        scenario: facet,
                        facet,
                        work,
                        cleanup: session.cleanup,
                    },
                )?;
                super::linux_test_lifetime_assertions::assert_experiment(
                    &observed, facet, &provider,
                )?;
                Ok(())
            })();
            result.map_err(|error| {
                error.context(format!(
                    "installed component facet={facet} root={}",
                    session.working.path.display()
                ))
            })?;
        }
        return Ok(());
    }
    let probe = copy_current_probe(&session.working.path, &inputs.distribution.target, work)
        .map_err(|error| {
            error.context(format!(
                "installed current probe copy path={}",
                session.working.path.display()
            ))
        })?;
    super::linux_test_refusals::run(TestInput {
        controller_directory: &controllers,
        caller,
        images: &images,
        provider: &provider,
        directory: &session.working.path.join("request-refusals"),
        work_cutoff: work,
        cleanup_cutoff: session.cleanup,
    })
    .map_err(|error| error.context("installed phase=request-refusals"))?;
    super::linux_test_socket_imports::run_socket_import_refusals(
        caller,
        &images,
        &controllers,
        &session.working.path,
        work,
    )
    .map_err(|error| error.context("installed phase=socket-import-refusals"))?;
    super::linux_test_owners::run_installed(
        session.root,
        caller,
        foreign,
        &probe,
        &images,
        &provider,
        &controllers,
        &session.working.path,
        work,
        session.cleanup,
    )
    .map_err(|error| error.context("installed phase=owners"))?;
    super::linux_test_isolation::run(
        session.root,
        caller,
        foreign,
        &images,
        &provider,
        &session.working.path,
        &controllers,
        work,
        session.cleanup,
    )
    .map_err(|error| error.context("installed phase=isolation"))?;
    super::linux_test_image_cases::run_installed(
        session.root,
        caller,
        &probe,
        &images,
        &provider,
        &controllers,
        &session.working.path,
        work,
        session.cleanup,
    )
    .map_err(|error| error.context("installed phase=image-cases"))?;
    super::linux_test_snapshots::run_installed(
        session.root,
        caller,
        foreign,
        &probe,
        &images,
        &provider,
        &controllers,
        &session.working.path,
        work,
        session.cleanup,
    )
    .map_err(|error| error.context("installed phase=snapshots"))?;
    let scenarios = super::linux_test_scenarios::scenarios()
        .map_err(|error| error.context("installed scenario inventory"))?;
    if scenarios.is_empty() {
        return Err(fail("required installed Linux scenarios are empty"));
    }
    for (ordinal, mut scenario) in scenarios.into_iter().enumerate() {
        let scenario_label = format!(
            "installed scenario family={} scenario={} path={}",
            scenario.key.family,
            scenario.key.scenario,
            session.working.path.join(ordinal.to_string()).display()
        );
        let result = (|| -> Result<()> {
            crate::cancellation::check_admission()?;
            if Instant::now() >= work {
                return Err(fail("original installed work cutoff expired"));
            }
            if scenario.key.family == "L-LIFE-02"
                || super::linux_test_execution::is_isolation_case(&scenario.key)
            {
                return Ok(()); // The concrete live fault/isolation owners above execute these operations.
            }
            if scenario.key.family == "C-STATUS" && scenario.key.scenario == "memory" {
                scenario.mode = "memory-pressure".into();
                scenario.memory = "+128MiB".into();
                scenario.product_deadline = "+30s".into();
            }
            if scenario.key.family == "C-STATUS" && scenario.key.scenario == "deadline" {
                scenario.mode = "deadline-demand".into();
                scenario.arguments.clear();
                scenario.product_deadline = "+2s".into();
            }
            let case_directory = session.working.path.join(ordinal.to_string());
            let controller = controllers.join(ordinal.to_string());
            fs::create_dir(&controller)?;
            eprintln!(
                "installed Linux test: {} / {}",
                scenario.key.family, scenario.key.scenario
            );
            let case = super::linux_test_execution::run_recipe(
                TestInput {
                    controller_directory: &controller,
                    caller,
                    images: &images,
                    provider: &provider,
                    directory: &case_directory,
                    work_cutoff: work,
                    cleanup_cutoff: session.cleanup,
                },
                scenario,
            )
            .map_err(|error| error.context("scenario recipe execution"))?;
            super::linux_test_assertions::assert_case(&case)
                .map_err(|error| error.context("scenario native assertions"))?;
            let acknowledged = caller
                .command(&case.directory, session.cleanup)
                .map_err(|error| error.context("scenario acknowledgment command preparation"))?
                .args(["workload", "acknowledge", "--observation"])
                .arg(case.directory.join("workload-observation.json"))
                .output()
                .map_err(|error| error.context("scenario acknowledgment execution"))?;
            require_successful_output("completed workload acknowledgment", &acknowledged)
                .map_err(|error| error.context("scenario acknowledgment status"))?;
            let acknowledgment = memcordon_core::workload_request::WorkloadAcknowledgmentV1::parse(
                &acknowledged.stdout,
            )
            .map_err(|error| {
                CiError::Message(error.to_string()).context("scenario acknowledgment parse")
            })?;
            if acknowledgment.association != case.locator {
                return Err(fail(
                    "current acknowledgment refers to another actual workload",
                ));
            }
            Ok(())
        })();
        result.map_err(|error| error.context(scenario_label))?;
    }
    super::linux_current_package_fault::interrupt(session.root, &agent, work)
        .map_err(|error| error.context("installed package interrupted-upgrade experiment"))?;
    operation(session.root, &agent, &["package", "upgrade"], work)
        .map_err(|error| error.context("installed package recovery upgrade"))?;
    operation(
        session.root,
        Path::new("/usr/libexec/memcordon-sealed-agent"),
        &["package", "verify", "--json"],
        work,
    )
    .map_err(|error| error.context("installed recovered package verification"))?;
    match fs::symlink_metadata("/usr/libexec/.memcordon-current-package-transaction.json") {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(CiError::from(error).context("installed recovery transaction metadata path=/usr/libexec/.memcordon-current-package-transaction.json")),
        Ok(_) => return Err(fail("current package recovery left its transaction active")),
    }
    if fs::read("/usr/libexec/memcordon-runtime-manifest.json").map_err(|error| {
        CiError::from(error).context(
            "installed recovery manifest read path=/usr/libexec/memcordon-runtime-manifest.json",
        )
    })? != manifest_bytes
    {
        return Err(fail(
            "current package recovery changed selected bytes or left its transaction active",
        ));
    }
    Ok(())
}

fn copy_current_probe(directory: &Path, target: &str, cutoff: Instant) -> Result<PathBuf> {
    if Instant::now() >= cutoff {
        return Err(fail("original helper copy cutoff expired"));
    }
    let current = File::open("/proc/self/exe")?;
    let mut bytes = Vec::new();
    current
        .take(512 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    super::target::validate_executable(&bytes, target)?;
    let output = directory.join("memcordon-ci-probe");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&output)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(output)
}

fn refuse_opaque_install(root: &Path, agent: &Path, cutoff: Instant) -> Result<()> {
    use std::os::unix::fs::FileExt;
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/usr/libexec")?;
    let mut held = File::from(
        rustix::fs::openat(
            &parent,
            ".",
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::TMPFILE | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .map_err(std::io::Error::from)?,
    );
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|error| CiError::Message(error.to_string()))?;
    let bytes = [b"opaque-current-install-fixture\0".as_slice(), &nonce].concat();
    held.write_all(&bytes)?;
    held.sync_all()?;
    let execution = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
        rustix::fs::linkat(
            &held,
            "",
            &parent,
            "memcordon-sealed-agent",
            rustix::fs::AtFlags::EMPTY_PATH,
        )
        .map_err(std::io::Error::from)?;
        let before = super::linux_test_refusals::allocations()?;
        let observed = CommandSpec::new(agent, root, Duration::from_secs(300))
            .bounded_until(cutoff)
            .args(["package", "install"])
            .output_quiet()?;
        if observed.status.code() != Some(125)
            || !String::from_utf8_lossy(&observed.stderr).contains("provider is already installed")
            || super::linux_test_refusals::allocations()? != before
        {
            return Err(fail(
                "installer did not refuse opaque occupied bytes before mutation",
            ));
        }
        let mut after = vec![0; bytes.len()];
        held.read_exact_at(&mut after, 0)?;
        if after != bytes {
            return Err(fail(
                "installer modified the owned opaque installation fixture",
            ));
        }
        Ok(())
    }));
    let cleanup = (|| -> Result<()> {
        let named = match rustix::fs::openat(
            &parent,
            "memcordon-sealed-agent",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Ok(file) => File::from(file),
            Err(rustix::io::Errno::NOENT) => return Ok(()),
            Err(error) => return Err(std::io::Error::from(error).into()),
        };
        let original = held.metadata()?;
        let actual = named.metadata()?;
        if (
            original.dev(),
            original.ino(),
            original.uid(),
            original.mode(),
        ) != (actual.dev(), actual.ino(), actual.uid(), actual.mode())
            || actual.nlink() != 1
        {
            return Err(fail(
                "refusing to unlink a replacement opaque installation fixture",
            ));
        }
        rustix::fs::unlinkat(
            &parent,
            "memcordon-sealed-agent",
            rustix::fs::AtFlags::empty(),
        )
        .map_err(std::io::Error::from)?;
        parent.sync_all()?;
        Ok(())
    })();
    match execution {
        Ok(Ok(())) => cleanup,
        Ok(Err(primary)) => match cleanup {
            Ok(()) => Err(primary),
            Err(secondary) => Err(CiError::Message(format!(
                "{primary}; opaque fixture cleanup: {secondary}"
            ))),
        },
        Err(panic) => {
            if let Err(error) = cleanup {
                eprintln!("opaque fixture cleanup after unwind: {error}");
            }
            std::panic::resume_unwind(panic)
        }
    }
}

fn assert_absent_runtime(root: &Path, cutoff: Instant) -> Result<()> {
    for path in [
        "/var/lib/memcordon",
        "/run/memcordon",
        "/usr/libexec/memcordon-runtime-manifest.json",
        "/usr/libexec/.memcordon-current-package-transaction.json",
        "/usr/lib/systemd/system/memcordon-sealed-agent.service",
        "/usr/lib/systemd/system/memcordon-sealed-agent.socket",
        "/usr/lib/systemd/system/memcordon-sealed-launcher.service",
        "/usr/lib/systemd/system/memcordon-sealed-launcher.socket",
        "/usr/lib/systemd/system/memcordon-sealed-network-launcher.service",
        "/usr/lib/systemd/system/memcordon-sealed-network-launcher.socket",
        "/usr/lib/tmpfiles.d/memcordon.conf",
    ] {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(fail(
                    "installed native runtime state is occupied or remains after owned removal",
                ));
            }
        }
    }
    for unit in [
        "memcordon-sealed-agent.service",
        "memcordon-sealed-agent.socket",
        "memcordon-sealed-launcher.service",
        "memcordon-sealed-launcher.socket",
        "memcordon-sealed-network-launcher.service",
        "memcordon-sealed-network-launcher.socket",
    ] {
        let state = CommandSpec::new("/usr/bin/systemctl", root, Duration::from_secs(30))
            .bounded_until(cutoff)
            .args(["show", "--property=ActiveState", "--value", unit])
            .output_quiet()?;
        let state_text =
            std::str::from_utf8(&state.stdout).map_err(|error| fail(error.to_string()))?;
        if state.status.success() {
            if !matches!(state_text.trim(), "inactive" | "failed") {
                return Err(fail(format!("native service remains active: {unit}")));
            }
        } else {
            let loaded = operation(
                root,
                Path::new("/usr/bin/systemctl"),
                &["show", "--property=LoadState", "--value", unit],
                cutoff,
            )?;
            if loaded != b"not-found\n" {
                return Err(fail(format!(
                    "native service remains loaded or active: {unit}"
                )));
            }
        }
    }
    Ok(())
}

fn protect_payload(
    inputs: &Inputs,
    output: &Path,
    cutoff: Instant,
    held: &mut Vec<File>,
) -> Result<()> {
    let bytes = artifacts::read_file(&inputs.directory.join("runtime-manifest.json"))?;
    let manifest = memcordon_core::runtime_manifest_v2::RuntimeManifestV2::parse(&bytes)
        .map_err(CiError::Message)?;
    if manifest.source_commit != inputs.source.commit()
        || manifest.version != inputs.source.version().to_string()
        || manifest.target != inputs.distribution.target
    {
        return Err(fail("selected product manifest differs before native copy"));
    }
    for component in &manifest.components {
        if !matches!(
            component.path.as_str(),
            "memcordon" | "memcordon-sealed-agent" | "memcordon-arm32-abi-helper"
        ) || component.mode != 0o755
        {
            return Err(fail("unexpected native package member"));
        }
        copy_regular(
            &inputs.directory.join(&component.path),
            &output.join(&component.path),
            component.size,
            &component.sha256,
            0o755,
            cutoff,
        )?;
        held.push(
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(output.join(&component.path))?,
        );
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(output.join("runtime-manifest.json"))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    held.push(file);
    Ok(())
}

fn copy_regular(
    source: &Path,
    target: &Path,
    length: u64,
    sha256: &str,
    mode: u32,
    cutoff: Instant,
) -> Result<()> {
    if Instant::now() >= cutoff || length > 512 * 1024 * 1024 {
        return Err(fail("native input copy exhausted its original bound"));
    }
    let mut held = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)?;
    let before = held.metadata()?;
    if !before.is_file() || before.nlink() != 1 || before.len() != length {
        return Err(fail(
            "native selected input is not the intended regular file",
        ));
    }
    let mut bytes = Vec::new();
    (&mut held).take(length + 1).read_to_end(&mut bytes)?;
    let after = held.metadata()?;
    if (
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
    ) || bytes.len() as u64 != length
        || artifacts::checksum(&bytes) != sha256
    {
        return Err(fail("native selected bytes changed during copy"));
    }
    fs::create_dir_all(
        target
            .parent()
            .ok_or_else(|| fail("native copied member parent absent"))?,
    )?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(target)?;
    output.write_all(&bytes)?;
    output.set_permissions(fs::Permissions::from_mode(mode))?;
    output.sync_all()?;
    Ok(())
}

fn copy_images(input: &PreparedImages, output: &Path, cutoff: Instant) -> Result<PreparedImages> {
    let mut copied = input.clone();
    fs::create_dir(output)?;
    for (manifest, source_root, name) in [
        (&input.runtime, &input.runtime_source, "runtime"),
        (&input.input, &input.input_source, "input"),
        (
            &input.minimal_runtime,
            &input.minimal_runtime_source,
            "minimal",
        ),
    ] {
        manifest.validate().map_err(CiError::Message)?;
        let destination = output.join(name);
        fs::create_dir(&destination)?;
        for entry in manifest.entries.as_slice() {
            let memcordon_core::workload_files::ImageEntryV1::Regular {
                path,
                sha256,
                size,
                executable,
            } = entry
            else {
                return Err(fail(
                    "prepared native image includes unsupported nonregular input",
                ));
            };
            copy_regular(
                &source_root.join(path.as_str()),
                &destination.join(path.as_str()),
                *size,
                &String::from(sha256.clone()),
                if *executable { 0o755 } else { 0o644 },
                cutoff,
            )?;
        }
    }
    copied.runtime_source = output.join("runtime");
    copied.input_source = output.join("input");
    copied.minimal_runtime_source = output.join("minimal");
    Ok(copied)
}

fn retire_tree(
    directory: &File,
    depth: usize,
    remaining: &mut usize,
    cutoff: Instant,
) -> Result<()> {
    use std::os::fd::AsRawFd;
    if depth > 64 {
        return Err(fail("owned directory retirement depth exhausted"));
    }
    for entry in fs::read_dir(Path::new("/proc/self/fd").join(directory.as_raw_fd().to_string()))? {
        if Instant::now() >= cutoff {
            return Err(fail("original native directory cleanup cutoff expired"));
        }
        *remaining = remaining
            .checked_sub(1)
            .ok_or_else(|| fail("owned directory retirement count exhausted"))?;
        let name = entry?.file_name();
        let before = rustix::fs::statat(directory, &name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(std::io::Error::from)?;
        let is_directory = before.st_mode & libc::S_IFMT == libc::S_IFDIR;
        if is_directory {
            let child = File::from(
                rustix::fs::openat2(
                    directory,
                    &name,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                    rustix::fs::ResolveFlags::BENEATH
                        | rustix::fs::ResolveFlags::NO_SYMLINKS
                        | rustix::fs::ResolveFlags::NO_XDEV,
                )
                .map_err(std::io::Error::from)?,
            );
            let held = child.metadata()?;
            if (held.dev(), held.ino()) != (before.st_dev, before.st_ino) {
                return Err(fail("owned child directory replaced before acquisition"));
            }
            retire_tree(&child, depth + 1, remaining, cutoff)?;
        }
        let after = rustix::fs::statat(directory, &name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(std::io::Error::from)?;
        if (before.st_dev, before.st_ino, before.st_mode)
            != (after.st_dev, after.st_ino, after.st_mode)
        {
            return Err(fail("owned directory member replaced before unlink"));
        }
        rustix::fs::unlinkat(
            directory,
            &name,
            if is_directory {
                rustix::fs::AtFlags::REMOVEDIR
            } else {
                rustix::fs::AtFlags::empty()
            },
        )
        .map_err(std::io::Error::from)?;
    }
    Ok(())
}
