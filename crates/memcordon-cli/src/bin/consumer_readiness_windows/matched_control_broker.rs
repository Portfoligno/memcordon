//! Real two-process broker for the additional owned-file measurement.
use super::{
    descriptor::{self, matched, matched_plan::Plan},
    matched_control_io::{Capture, Pipe},
    matched_control_process::{self as native, Caller, Job, Launch, Process},
};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};
use windows_sys::Win32::{
    Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT, SetHandleInformation},
    Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ},
    System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE},
};

fn read(path: &Path, bound: usize) -> io::Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    use std::os::windows::fs::MetadataExt;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.file_attributes() & 0x400 != 0
        || metadata.len() > bound as u64
    {
        return Err(io::Error::other(
            "matched record is not a bounded ordinary file",
        ));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((bound + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > bound {
        return Err(io::Error::other("matched record grew beyond bound"));
    }
    Ok(bytes)
}
fn write(path: &Path, bytes: &[u8], cutoff: Instant) -> io::Result<()> {
    native::live(cutoff)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    file.write_all(bytes)?;
    native::live(cutoff)?;
    file.sync_all()?;
    native::live(cutoff)
}
fn hold_image(path: &Path, expected: &str, cutoff: Instant) -> io::Result<File> {
    use sha2::{Digest, Sha256};
    native::live(cutoff)?;
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let info = memcordon_platform::test_support::windows_held_file_metadata(&file)?;
    if info.attributes & (0x400 | 0x10 | 0x40) != 0
        || info.links != 1
        || info.length == 0
        || info.length > 512 * 1024 * 1024
    {
        return Err(io::Error::other(
            "matched image is not a bounded single-link immutable input",
        ));
    }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        native::live(cutoff)?;
        let count = file.read(&mut buffer)?;
        native::live(cutoff)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("matched image length overflow"))?;
        if total > info.length {
            return Err(io::Error::other("matched image changed"));
        }
        hash.update(&buffer[..count]);
    }
    let observed = hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if observed != expected || total != info.length {
        return Err(io::Error::other("matched held image digest/length differs"));
    }
    Ok(file)
}
fn hold_file(path: &Path, mutable: bool, cutoff: Instant) -> io::Result<File> {
    native::live(cutoff)?;
    let file = OpenOptions::new()
        .read(true)
        .write(mutable)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let info = memcordon_platform::test_support::windows_held_file_metadata(&file)?;
    native::live(cutoff)?;
    if info.attributes & (0x400 | 0x10 | 0x40) != 0 || info.links != 1 {
        return Err(io::Error::other(
            "matched immutable declaration is not a single-link ordinary file",
        ));
    }
    Ok(file)
}
fn held_bytes(mut file: &File, cutoff: Instant) -> io::Result<Vec<u8>> {
    use std::io::{Seek, SeekFrom};
    native::live(cutoff)?;
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    let mut part = [0u8; 4096];
    loop {
        native::live(cutoff)?;
        let count = file.read(&mut part)?;
        native::live(cutoff)?;
        if count == 0 {
            return Ok(bytes);
        }
        if bytes.len() + count > 64 * 1024 {
            return Err(io::Error::other("held matched declaration exceeds64KiB"));
        }
        bytes.extend_from_slice(&part[..count]);
    }
}
fn hold_ancestors(path: &Path, cutoff: Instant) -> io::Result<Vec<File>> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_WRITE,
    };
    let mut chain = path.ancestors().collect::<Vec<_>>();
    chain.reverse();
    let mut files = Vec::new();
    for directory in chain {
        if !directory.is_absolute() {
            return Err(io::Error::other("matched ancestor is not absolute"));
        }
        native::live(cutoff)?;
        let file = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES | 0x20000)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(directory)?;
        let info = memcordon_platform::test_support::windows_held_file_metadata(&file)?;
        native::live(cutoff)?;
        if info.attributes & 0x10 == 0 || info.attributes & 0x400 != 0 {
            return Err(io::Error::other(
                "matched held ancestor is reparse or not a directory",
            ));
        }
        files.push(file);
        if files.len() > 64 {
            return Err(io::Error::other("matched ancestor count exceeds64"));
        }
    }
    Ok(files)
}
fn readback(
    descriptor: &descriptor::Descriptor,
    expected: &super::matched_control_input_record::Expected,
    owners: [&Process; 2],
    deadline: Instant,
) -> io::Result<super::matched_control_input_record::Readback> {
    let path = descriptor.output_root.join("matched-input-readback.json");
    loop {
        native::live(deadline)?;
        for owner in owners {
            if let Some(status) = owner.status(deadline)? {
                return Err(io::Error::other(format!(
                    "matched input capture owner exited before START: native status {status}"
                )));
            }
        }
        match read(&path, 64 * 1024) {
            Ok(bytes) => {
                let value = super::matched_control_input_record::decode(&bytes)
                    .map_err(io::Error::other)?;
                super::matched_control_input_record::validate(&value, expected)
                    .map_err(io::Error::other)?;
                for owner in owners {
                    if owner.status(deadline)?.is_some() {
                        return Err(io::Error::other(
                            "matched input owner exited before both readbacks completed",
                        ));
                    }
                }
                native::live(deadline)?;
                return Ok(value);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                std::thread::sleep(std::time::Duration::from_millis(1))
            }
            Err(error) => return Err(error),
        }
    }
}

fn relay(
    installed: &descriptor::Descriptor,
    installed_digest: [u8; 32],
    direct: &descriptor::Descriptor,
    direct_binding: &descriptor::controller_start::Binding,
    installed_input: &super::matched_control_input_record::Readback,
    front: &mut File,
    direct_in: &mut File,
    work: Instant,
) -> io::Result<()> {
    use descriptor::controller_start::{Binding, Phase, Receiver, Sender};
    let timer =
        memcordon_platform::WindowsSynchronousIoDeadline::start(work).map_err(io::Error::other)?;
    let result = (|| {
        native::live(work)?;
        // This sole stdin endpoint belongs to the original CI-owned broker.
        // No target-local handle scalars are adopted; Stage1 has only STARTv2.
        let mut source = io::stdin().lock();
        let mut header = [0u8; 64];
        source.read_exact(&mut header)?;
        native::live(work)?;
        let length =
            u32::from_le_bytes(header[12..16].try_into().expect("fixed START header")) as usize;
        if length != installed.challenge.len()
            || length > descriptor::controller_start::MAX_CHALLENGE
        {
            return Err(io::Error::other(
                "matched installed START challenge extent differs",
            ));
        }
        let pid = u32::from_le_bytes(header[48..52].try_into().expect("fixed PID"));
        let birth = u64::from_le_bytes(header[52..60].try_into().expect("fixed birth"));
        if installed_input.pid != pid || installed_input.birth != birth {
            return Err(io::Error::other(
                "matched installed START differs from original input readback",
            ));
        }
        let mut bytes = header.to_vec();
        bytes.resize(header.len() + length, 0);
        source.read_exact(&mut bytes[header.len()..])?;
        native::live(work)?;
        let mut extra = [0u8; 1];
        if source.read(&mut extra)? != 0 {
            return Err(io::Error::other(
                "matched START source has extra frame data",
            ));
        }
        let binding = Binding {
            challenge: installed.challenge.clone(),
            descriptor_sha256: installed_digest,
            pid,
            birth,
        };
        Receiver::default().receive(&mut io::Cursor::new(&bytes), &binding, || {
            native::live(work)
        })?;
        // Actual application release is after both readbacks. The original
        // installed frame is unchanged and still checked by its actual root.
        front.write_all(&bytes)?;
        front.flush()?;
        native::live(work)?;
        Sender::default().send(direct_in, direct_binding, Phase::Start, || {
            native::live(work)
        })?;
        if direct.challenge != installed.challenge {
            return Err(io::Error::other("matched challenge input differs"));
        }
        Ok(())
    })();
    let settled = timer.finish().map_err(io::Error::other);
    match result {
        Err(primary) => Err(native::combine(primary, settled)),
        Ok(()) => {
            settled?;
            native::live(work)
        }
    }
}

pub(super) fn run(mut arguments: impl Iterator<Item = OsString>) -> io::Result<i32> {
    let plan_path = PathBuf::from(
        arguments
            .next()
            .ok_or_else(|| io::Error::other("matched broker plan missing"))?,
    );
    let argv: Vec<OsString> = arguments.collect();
    let cli = argv
        .first()
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other("matched installed frontend argv missing"))?;
    let plan: Plan =
        serde_json::from_slice(&read(&plan_path, 64 * 1024)?).map_err(io::Error::other)?;
    let work = super::controller_start_input::deadline_from_clock(&plan.work_clock)?;
    native::live(work)?;
    let broker_identity = super::native::current_identity()?;
    native::live(work)?;
    let mut cleanup_clock = plan.work_clock.clone();
    cleanup_clock.work_cutoff_qpc = plan.cleanup_cutoff_qpc;
    let cleanup = super::controller_start_input::deadline_from_clock(&cleanup_clock)?;
    let actual_fixture = std::env::current_exe()?;
    let mut direct = super::read_descriptor(&plan.direct_descriptor)?;
    let mut installed = super::read_descriptor(&plan.installed_descriptor)?;
    plan.validate(&direct, &installed)
        .map_err(io::Error::other)?;
    let fixture_position = argv
        .len()
        .checked_sub(installed.arguments.len() + 3)
        .ok_or_else(|| io::Error::other("matched installed application argv missing"))?;
    let fixture = PathBuf::from(&argv[fixture_position]);
    let suffix: Vec<OsString> = std::iter::once(OsString::from("--"))
        .chain([
            fixture.as_os_str().to_owned(),
            OsString::from("consumer-readiness-windows"),
            plan.installed_descriptor.as_os_str().to_owned(),
        ])
        .chain(installed.arguments.iter().map(OsString::from))
        .collect();
    if !argv.ends_with(&suffix) {
        return Err(io::Error::other(
            "matched installed command does not name the declared original fixture/descriptor/argv",
        ));
    }
    let mut guards = Vec::new();
    for path in [
        &plan_path,
        &plan.direct_descriptor,
        &plan.installed_descriptor,
        &fixture,
        &cli,
    ] {
        guards.extend(hold_ancestors(
            path.parent()
                .ok_or_else(|| io::Error::other("matched input parent absent"))?,
            work,
        )?);
    }
    let mut cwd_identity = None;
    for declared in &plan.directories {
        let chain = descriptor::matched_plan::hold_chain(&declared.path, work)?;
        let observed = descriptor::matched_plan::observe_directory(
            declared.role,
            &declared.path,
            chain
                .last()
                .ok_or_else(|| io::Error::other("matched declared directory custody absent"))?,
            work,
        )?;
        if observed != *declared {
            return Err(io::Error::other(
                "matched actual directory identity or security differs from the producer",
            ));
        }
        if declared.role == descriptor::matched_plan::DirectoryRole::Cwd {
            cwd_identity = Some((observed.volume_serial, observed.file_index));
        }
        guards.extend(chain);
    }
    let cwd_identity =
        cwd_identity.ok_or_else(|| io::Error::other("matched cwd custody absent"))?;
    let plan_guard = hold_file(&plan_path, false, work)?;
    let mut direct_guard = hold_file(&plan.direct_descriptor, true, work)?;
    let mut installed_guard = hold_file(&plan.installed_descriptor, true, work)?;
    if serde_json::from_slice::<Value>(&held_bytes(&plan_guard, work)?).map_err(io::Error::other)?
        != serde_json::to_value(&plan).map_err(io::Error::other)?
        || serde_json::from_slice::<Value>(&held_bytes(&direct_guard, work)?)
            .map_err(io::Error::other)?
            != serde_json::to_value(&direct).map_err(io::Error::other)?
        || serde_json::from_slice::<Value>(&held_bytes(&installed_guard, work)?)
            .map_err(io::Error::other)?
            != serde_json::to_value(&installed).map_err(io::Error::other)?
    {
        return Err(io::Error::other(
            "held matched plan or descriptor changed before native creation",
        ));
    }
    let image = hold_image(&fixture, &plan.fixture_sha256, work)?;
    let actual_image = hold_image(&actual_fixture, &plan.fixture_sha256, work)?;
    let cli_image = hold_image(&cli, &plan.cli_sha256, work)?;
    let declared_id = memcordon_platform::test_support::windows_held_file_metadata(&image)?;
    let actual_id = memcordon_platform::test_support::windows_held_file_metadata(&actual_image)?;
    native::live(work)?;
    if (declared_id.volume_serial, declared_id.file_index)
        != (actual_id.volume_serial, actual_id.file_index)
    {
        return Err(io::Error::other(
            "matched declared fixture and actual broker image are different native objects",
        ));
    }
    let mut caller = Caller::select(plan.restricted, vec![image, cli_image, actual_image], work)?;
    let selected_token = caller.token_hash(work)?;
    let sentinel = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(plan.record.with_extension("sentinel.bin"))?;
    let identity = memcordon_platform::test_support::windows_held_file_identity(&sentinel)?;
    native::live(work)?;
    if unsafe {
        SetHandleInformation(
            sentinel.as_raw_handle(),
            HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut original_flags = 0;
    if unsafe { GetHandleInformation(sentinel.as_raw_handle(), &mut original_flags) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if original_flags & HANDLE_FLAG_INHERIT == 0 {
        return Err(io::Error::other(
            "matched sentinel inheritance setup failed",
        ));
    }
    for descriptor in [&mut direct, &mut installed] {
        descriptor.sentinel_handles = vec![descriptor::Sentinel {
            handle: sentinel.as_raw_handle() as usize,
            volume_serial_number: identity.volume_serial,
            file_index: identity.file_index,
        }];
    }
    let direct_bytes = serde_json::to_vec(&direct).map_err(io::Error::other)?;
    let installed_bytes = serde_json::to_vec(&installed).map_err(io::Error::other)?;
    for (file, bytes) in [
        (&mut direct_guard, &direct_bytes),
        (&mut installed_guard, &installed_bytes),
    ] {
        use std::io::{Seek, SeekFrom};
        native::live(work)?;
        file.seek(SeekFrom::Start(0))?;
        file.set_len(0)?;
        file.write_all(bytes)?;
        native::live(work)?;
        file.sync_all()?;
        native::live(work)?;
        if held_bytes(file, work)? != *bytes {
            return Err(io::Error::other(
                "held matched sentinel descriptor readback differs",
            ));
        }
    }
    let direct_digest = descriptor::controller_start::descriptor_digest(&direct_bytes);
    let installed_digest = descriptor::controller_start::descriptor_digest(&installed_bytes);
    guards.extend([plan_guard, direct_guard, installed_guard]);
    Caller::retain_inputs(&mut caller, guards)?;
    let environment = plan.environment.clone();
    let job = Job::create(work)?;
    let mut direct_process: Option<Process> = None;
    let mut frontend_process: Option<Process> = None;
    let mut stdout_capture: Option<Capture> = None;
    let mut stderr_capture: Option<Capture> = None;
    let operation = (|| {
        let direct_stdin = Pipe::create(caller.default_acl()?, true, work)?;
        let frontend_stdin = Pipe::create(caller.default_acl()?, true, work)?;
        let parent_stdout = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
        let parent_stderr = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
        let direct_stdout = Pipe::like_original(parent_stdout, work)?;
        let direct_stderr = Pipe::like_original(parent_stderr, work)?;
        let frontend_stdout =
            super::matched_control_io::duplicate_inheritable(parent_stdout, work)?;
        let frontend_stderr =
            super::matched_control_io::duplicate_inheritable(parent_stderr, work)?;
        let direct_argv: Vec<OsString> = [
            fixture.as_os_str().to_owned(),
            OsString::from("consumer-readiness-windows"),
            plan.direct_descriptor.as_os_str().to_owned(),
        ]
        .into_iter()
        .chain(direct.arguments.iter().map(OsString::from))
        .collect();
        direct_process = Some(Process::create(
            Arc::clone(&caller),
            Launch {
                image_role: native::Image::Fixture,
                image: &fixture,
                argv: &direct_argv,
                environment: &environment,
                cwd: &plan.cwd,
                stdio: [
                    direct_stdin.read.as_raw_handle(),
                    direct_stdout.write.as_raw_handle(),
                    direct_stderr.write.as_raw_handle(),
                ],
                job: Some(Arc::clone(&job)),
                work,
                cleanup,
            },
        )?);
        frontend_process = Some(Process::create(
            Arc::clone(&caller),
            Launch {
                image_role: native::Image::Frontend,
                image: &cli,
                argv: &argv,
                environment: &environment,
                cwd: &plan.cwd,
                stdio: [
                    frontend_stdin.read.as_raw_handle(),
                    frontend_stdout.as_raw_handle(),
                    frontend_stderr.as_raw_handle(),
                ],
                job: None,
                work,
                cleanup,
            },
        )?);
        let Pipe {
            read: direct_read,
            write: mut direct_write,
        } = direct_stdin;
        drop(direct_read);
        let Pipe {
            read: frontend_read,
            write: mut frontend_write,
        } = frontend_stdin;
        drop(frontend_read);
        drop(frontend_stdout);
        drop(frontend_stderr);
        let Pipe {
            read: stdout_read,
            write: stdout_write,
        } = direct_stdout;
        drop(stdout_write);
        let Pipe {
            read: stderr_read,
            write: stderr_write,
        } = direct_stderr;
        drop(stderr_write);
        stdout_capture = Some(Capture::start(stdout_read, work));
        stderr_capture = Some(Capture::start(stderr_read, work));
        let target = direct_process.as_ref().expect("created direct owner");
        let front = frontend_process.as_ref().expect("created frontend owner");
        let target_id = (target.pid, target.birth);
        let front_id = (front.pid, front.birth);
        target.resume(work)?;
        front.resume(work)?;
        let expected_input = |descriptor: &descriptor::Descriptor, digest, identity| {
            super::matched_control_input_record::Expected {
                binding: descriptor
                    .matched_control
                    .as_ref()
                    .expect("validated matched binding")
                    .clone(),
                descriptor_sha256: digest,
                token_sha256: selected_token,
                default_acl_bytes: caller
                    .default_acl()
                    .expect("selected default ACL already verified")
                    .len(),
                default_acl_sha256: descriptor::controller_start::descriptor_digest(
                    caller
                        .default_acl()
                        .expect("selected default ACL already verified"),
                ),
                qpc_frequency: plan.work_clock.qpc_frequency,
                cutoff_qpc: plan.work_clock.work_cutoff_qpc,
                identity,
            }
        };
        let direct_input = readback(
            &direct,
            &expected_input(&direct, direct_digest, Some(target_id)),
            [target, front],
            work,
        )?;
        let installed_input = readback(
            &installed,
            &expected_input(&installed, installed_digest, None),
            [target, front],
            work,
        )?;
        super::matched_control_input_record::compare_inputs(&direct_input, &installed_input)
            .map_err(io::Error::other)?;
        if (
            direct_input.cwd_identity.volume_serial,
            direct_input.cwd_identity.file_index,
        ) != cwd_identity
            || memcordon_core::encode_windows_environment_block(&direct_input.environment)
                .map_err(io::Error::other)?
                != memcordon_core::encode_windows_environment_block(&environment)
                    .map_err(io::Error::other)?
        {
            return Err(io::Error::other(
                "matched actual cwd or environment differs from the launch declaration",
            ));
        }
        for owner in [target, front] {
            if owner.status(work)?.is_some() {
                return Err(io::Error::other(
                    "matched original input owner retired before authenticated START",
                ));
            }
        }
        relay(
            &installed,
            installed_digest,
            &direct,
            &descriptor::controller_start::Binding {
                challenge: direct.challenge.clone(),
                descriptor_sha256: direct_digest,
                pid: target_id.0,
                birth: target_id.1,
            },
            &installed_input,
            &mut frontend_write,
            &mut direct_write,
            work,
        )?;
        drop(frontend_write);
        drop(direct_write);
        let direct_status = direct_process
            .as_mut()
            .expect("direct owner")
            .settle(work)?;
        let frontend_status = frontend_process
            .as_mut()
            .expect("frontend owner")
            .settle(work)?;
        let stdout = stdout_capture
            .as_mut()
            .expect("direct stdout owner")
            .finish(work)?;
        let stderr = stderr_capture
            .as_mut()
            .expect("direct stderr owner")
            .finish(work)?;
        write(
            &plan.record.with_extension("direct-stdout.bin"),
            &stdout,
            cleanup,
        )?;
        write(
            &plan.record.with_extension("direct-stderr.bin"),
            &stderr,
            cleanup,
        )?;
        caller.verify_unchanged(cleanup)?;
        let direct_record = matched::decode(&read(
            &direct.output_root.join("application-terminal.json"),
            matched::MAX_RECORD_BYTES,
        )?)
        .map_err(io::Error::other)?;
        let installed_record = matched::decode(&read(
            &installed.output_root.join("application-terminal.json"),
            matched::MAX_RECORD_BYTES,
        )?)
        .map_err(io::Error::other)?;
        for (record, descriptor) in [(&direct_record, &direct), (&installed_record, &installed)] {
            matched::validate(
                record,
                descriptor
                    .matched_control
                    .as_ref()
                    .expect("validated matched binding"),
                plan.restricted && plan.scope == matched::Scope::Envelope,
            )
            .map_err(io::Error::other)?;
            if record.token_sha256 != selected_token
                || record.cutoff_qpc != plan.work_clock.work_cutoff_qpc
                || record.qpc_frequency != plan.work_clock.qpc_frequency
            {
                return Err(io::Error::other(
                    "matched application token/work-clock differs from actual plan input",
                ));
            }
        }
        if direct_record.pid != target_id.0
            || direct_record.birth != target_id.1
            || direct_record.descriptor_sha256 != direct_digest
            || installed_record.descriptor_sha256 != installed_digest
            || installed_record.pid != installed_input.pid
            || installed_record.birth != installed_input.birth
        {
            return Err(io::Error::other(
                "matched application record differs from original native/input bindings",
            ));
        }
        let compared = matched::compare(
            &direct_record,
            &installed_record,
            plan.restricted && plan.scope == matched::Scope::Envelope,
        )
        .map_err(io::Error::other)?;
        let result = json!({"revision":1,"scope":plan.scope,"pair_sha256":plan.pair_sha256,"broker":{"pid":broker_identity.process_id,"birth":broker_identity.creation_time_100ns},"caller":caller.measurement(),"direct":{"pid":target_id.0,"birth":target_id.1,"native_status":direct_status,"job_active_processes":0,"stdout_bytes":stdout.len(),"stderr_bytes":stderr.len(),"stdout_sha256":descriptor::controller_start::descriptor_digest(&stdout),"stderr_sha256":descriptor::controller_start::descriptor_digest(&stderr)},"installed_frontend":{"pid":front_id.0,"birth":front_id.1,"native_status":frontend_status},"comparison":compared,"direct_input":direct_input,"installed_input":installed_input,"direct_record":direct_record,"installed_record":installed_record});
        let bytes = serde_json::to_vec(&result).map_err(io::Error::other)?;
        if bytes.len() > 64 * 1024 {
            return Err(io::Error::other("matched broker result exceeds64KiB"));
        }
        let retained = super::matched_control_report::decode(&bytes).map_err(io::Error::other)?;
        super::matched_control_report::validate(
            &retained,
            &plan,
            &super::matched_control_report::Expected {
                broker: (
                    broker_identity.process_id,
                    broker_identity.creation_time_100ns,
                ),
                direct_descriptor_sha256: direct_digest,
                installed_descriptor_sha256: installed_digest,
                installed_target: (installed_input.pid, installed_input.birth),
                frontend: front_id,
                direct_stdout: super::matched_control_report::StreamEvidence {
                    bytes: stdout.len() as u64,
                    sha256: descriptor::controller_start::descriptor_digest(&stdout),
                },
                direct_stderr: super::matched_control_report::StreamEvidence {
                    bytes: stderr.len() as u64,
                    sha256: descriptor::controller_start::descriptor_digest(&stderr),
                },
            },
        )
        .map_err(io::Error::other)?;
        write(&plan.record, &bytes, cleanup)?;
        if direct_status != 0
            || frontend_status != 0
            || !stdout.is_empty()
            || !stderr.is_empty()
            || !matches!(compared.outcome, matched::ComparisonOutcome::ScopeSuccess)
        {
            return Err(io::Error::other(
                "matched owned positive/negative scope did not complete exactly",
            ));
        }
        Ok(frontend_status as i32)
    })();
    match operation {
        Ok(status) => Ok(status),
        Err(mut primary) => {
            if let Some(process) = direct_process
                .as_mut()
                .filter(|process| process.needs_settlement())
            {
                primary = process.fail(primary, cleanup)
            }
            if let Some(process) = frontend_process
                .as_mut()
                .filter(|process| process.needs_settlement())
            {
                primary = process.fail(primary, cleanup)
            }
            Err(primary)
        }
    }
}
