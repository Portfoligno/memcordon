//! Observe the same original owned-file operations without replaying them.
use super::{
    Descriptor, Transcript,
    descriptor::{self, matched::*},
};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
};

fn qpc() -> io::Result<u64> {
    let mut value = 0i64;
    if unsafe { windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut value) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(value)
        .ok()
        .filter(|v| *v != 0)
        .ok_or_else(|| io::Error::other("matched operation QPC unavailable"))
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    descriptor::controller_start::descriptor_digest(bytes)
}
pub(super) struct Recorder {
    observation: Observation,
    capture_error: Option<io::Error>,
}
impl Recorder {
    pub fn new(descriptor: &Descriptor, descriptor_sha256: [u8; 32]) -> io::Result<Self> {
        let binding = descriptor
            .matched_control
            .clone()
            .ok_or_else(|| io::Error::other("matched descriptor binding absent"))?;
        let clock = descriptor
            .control_clock
            .as_ref()
            .ok_or_else(|| io::Error::other("matched clock absent"))?;
        super::listener_trace::live(clock)?;
        let started = qpc()?;
        let identity = super::native::current_identity()?;
        let token_sha256 = super::matched_control_readback::token_hash(clock)?;
        super::listener_trace::live(clock)?;
        Ok(Self {
            observation: Observation {
                revision: REVISION,
                native_status_domain: NativeStatusDomain::Win32,
                binding,
                descriptor_sha256,
                pid: identity.process_id,
                birth: identity.creation_time_100ns,
                cutoff_qpc: clock.work_cutoff_qpc,
                qpc_frequency: clock.qpc_frequency,
                token_sha256,
                started_qpc: started,
                finished_qpc: started,
                operations: Vec::new(),
                terminal: Terminal::CompletedScope,
            },
            capture_error: None,
        })
    }
    fn sample(&mut self) -> u64 {
        match qpc() {
            Ok(value) => value,
            Err(error) => {
                if self.capture_error.is_none() {
                    self.capture_error = Some(error)
                }
                0
            }
        }
    }
    pub fn publish(mut self, descriptor: &Descriptor) -> io::Result<()> {
        self.observation.finished_qpc = self.sample();
        if let Some(error) = self.capture_error {
            return Err(error);
        }
        validate(
            &self.observation,
            &self.observation.binding,
            !descriptor.denied_write_paths.is_empty(),
        )
        .map_err(io::Error::other)?;
        let bytes = encode(&self.observation).map_err(io::Error::other)?;
        let clock = descriptor.control_clock.as_ref().expect("matched clock");
        super::listener_trace::live(clock)?;
        use std::os::windows::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
            .open(descriptor.output_root.join("application-terminal.json"))?;
        file.write_all(&bytes)?;
        super::listener_trace::live(clock)?;
        file.sync_all()?;
        super::listener_trace::live(clock)
    }
}

fn operation<T>(
    record: &mut Option<&mut Recorder>,
    op: Operation,
    arguments: serde_json::Value,
    call: impl FnOnce() -> io::Result<T>,
    data: impl FnOnce(&T) -> Option<[u8; 32]>,
) -> io::Result<T> {
    let Some(record) = record.as_deref_mut() else {
        return call();
    };
    let before = record.sample();
    let result = call(); // Exactly one original operation; its io::Error owns native status.
    let outcome = match &result {
        Ok(value) => Outcome::Completed {
            data_sha256: data(value),
        },
        Err(error) => {
            if let Some(code) = error.raw_os_error() {
                Outcome::NativeFailure { code }
            } else if op == Operation::VerifyAllBytes {
                Outcome::SemanticFailure {
                    kind: SemanticFailure::ReadbackMismatch,
                }
            } else {
                Outcome::NonNativeFailure
            }
        }
    };
    let after = record.sample();
    let ordinal = (record.observation.operations.len() + 1) as u32;
    if result.is_err() {
        record.observation.terminal = Terminal::FirstFailure { ordinal }
    }
    record.observation.operations.push(OperationRecord {
        ordinal,
        op,
        arguments_sha256: digest(
            &serde_json::to_vec(&arguments).expect("finite operation arguments"),
        ),
        before_qpc: before,
        after_qpc: after,
        outcome,
    });
    result
}

pub(super) fn binary_files(
    descriptor: &Descriptor,
    transcript: &mut Transcript,
    mut record: Option<&mut Recorder>,
) -> io::Result<()> {
    let directory = descriptor.output_root.join("nested");
    operation(
        &mut record,
        Operation::CreateNestedDirectory,
        serde_json::json!(["output", "nested"]),
        || fs::create_dir(&directory),
        |_| None,
    )?;
    operation(
        &mut record,
        Operation::WriteEmptyFile,
        serde_json::json!(["output/nested/empty.bin", digest(&[])]),
        || fs::write(directory.join("empty.bin"), []),
        |_| Some(digest(&[])),
    )?;
    let bytes: Vec<u8> = (0..=255).collect();
    let temporary = directory.join("unrenamed.bin");
    operation(
        &mut record,
        Operation::WriteAllBytesTemporary,
        serde_json::json!(["output/nested/unrenamed.bin", digest(&bytes)]),
        || fs::write(&temporary, &bytes),
        |_| Some(digest(&bytes)),
    )?;
    let renamed = directory.join("all-bytes.bin");
    operation(
        &mut record,
        Operation::RenameAllBytes,
        serde_json::json!(["output/nested/unrenamed.bin", "output/nested/all-bytes.bin"]),
        || fs::rename(&temporary, &renamed),
        |_| None,
    )?;
    let actual = operation(
        &mut record,
        Operation::ReadAllBytes,
        serde_json::json!(["output/nested/all-bytes.bin"]),
        || fs::read(&renamed),
        |bytes| Some(digest(bytes)),
    )?;
    operation(
        &mut record,
        Operation::VerifyAllBytes,
        serde_json::json!([digest(&bytes)]),
        || {
            if actual == bytes {
                Ok(())
            } else {
                Err(io::Error::other("binary file readback differs"))
            }
        },
        |_| Some(digest(&actual)),
    )?;
    operation(
        &mut record,
        Operation::WriteChallenge,
        serde_json::json!(["output/nested/challenge.bin", digest(&descriptor.challenge)]),
        || fs::write(directory.join("challenge.bin"), &descriptor.challenge),
        |_| Some(digest(&descriptor.challenge)),
    )?;
    transcript.event("binary-files", None, &descriptor.challenge)
}

pub(super) fn protected(
    descriptor: &Descriptor,
    transcript: &mut Transcript,
    record: &mut Recorder,
) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    for (path, role) in descriptor
        .denied_write_paths
        .iter()
        .zip([ProtectedRole::Driver, ProtectedRole::Provider])
    {
        let before = record.sample();
        let result = OpenOptions::new().write(true).create_new(true).open(path);
        let native = result.as_ref().err().and_then(io::Error::raw_os_error);
        let after = record.sample();
        let ordinal = (record.observation.operations.len() + 1) as u32;
        let expected = native == Some(5)
            && result
                .as_ref()
                .is_err_and(|error| error.kind() == io::ErrorKind::PermissionDenied);
        let outcome = match &result {
            Ok(_) => Outcome::SemanticFailure {
                kind: SemanticFailure::ProtectedWriteSucceeded,
            },
            Err(_) => native.map_or(Outcome::NonNativeFailure, |code| Outcome::NativeFailure {
                code,
            }),
        };
        record.observation.operations.push(OperationRecord {
            ordinal,
            op: Operation::ProtectedWrite { role },
            arguments_sha256: digest(&serde_json::to_vec(&role).expect("closed protected role")),
            before_qpc: before,
            after_qpc: after,
            outcome,
        });
        if !expected {
            record.observation.terminal = Terminal::FirstFailure { ordinal };
            return match result {
                Ok(_) => Err(io::Error::other(
                    "protected driver/provider write succeeded",
                )),
                Err(error) => Err(error),
            };
        }
        let receipt=serde_json::to_vec(&serde_json::json!({"path_utf16":path.as_os_str().encode_wide().collect::<Vec<_>>(),"win32_code":native})).map_err(io::Error::other)?;
        transcript.event("protected-write-denied", None, &receipt)?;
    }
    Ok(())
}

pub(super) fn execute(
    descriptor: &Descriptor,
    descriptor_digest: [u8; 32],
    transcript: &mut Transcript,
) -> io::Result<()> {
    let mut recorder = Recorder::new(descriptor, descriptor_digest)?;
    let application = (|| {
        binary_files(descriptor, transcript, Some(&mut recorder))?;
        protected(descriptor, transcript, &mut recorder)
    })();
    let captured = recorder.publish(descriptor);
    match application {
        Err(primary) => Err(super::matched_control_process::combine(primary, captured)),
        Ok(()) => captured,
    }
}
