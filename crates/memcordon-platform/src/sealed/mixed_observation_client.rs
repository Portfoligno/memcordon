//! Optional owned evidence directory for a native observer's pre-release barrier.
use memcordon_core::mixed_observation::MixedPreparedObservationV2;
use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, Instant};

thread_local! {static OBSERVER:RefCell<Option<Rc<File>>>=const{RefCell::new(None)};}
pub struct MixedObservationScope {
    previous: Option<Rc<File>>,
}
impl MixedObservationScope {
    /// Preserve the local filesystem error independently of the provider's
    /// authenticated terminal. The submitted bytes cannot attest persistence.
    pub fn record_report_delivery_failure(
        path: &Path,
        submitted: &[u8],
        error: &memcordon_core::Error,
    ) -> Result<(), String> {
        let scope = OBSERVER.with(|scope| scope.borrow().clone());
        let Some(directory) = scope else {
            return Ok(());
        };
        if submitted.len() > 16 * 1024 * 1024 {
            return Err("native report delivery observation exceeds bound".into());
        }
        let destination = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|error| error.to_string())?;
        let metadata = destination.metadata().map_err(|error| error.to_string())?;
        let receipt = serde_json::json!({"format":"memcordon.linux-native-report-delivery-failure","revision":1,
            "report_path":path.as_os_str().as_encoded_bytes(),"submitted_report":submitted,"native_errno":error.os_code,
            "native_error_code":error.code,"destination":{"device":metadata.dev(),"inode":metadata.ino(),"uid":metadata.uid(),
                "gid":metadata.gid(),"mode":metadata.mode(),"is_directory":metadata.is_dir()},
            "frontend_pid":std::process::id()});
        let bytes = serde_json::to_vec(&receipt).map_err(|error| error.to_string())?;
        publish_observation(&directory, "report-delivery-failure.json", &bytes)
    }

    pub fn install(directory: &Path) -> Result<Self, String> {
        if !directory.is_absolute() {
            return Err("mixed observation directory must be absolute".into());
        }
        let held = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(directory)
            .map_err(|error| error.to_string())?;
        let metadata = held.metadata().map_err(|error| error.to_string())?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
            return Err("mixed observation directory is not exclusively owned".into());
        }
        let previous = OBSERVER.with(|scope| scope.replace(Some(Rc::new(held))));
        Ok(Self { previous })
    }
}
impl Drop for MixedObservationScope {
    fn drop(&mut self) {
        OBSERVER.with(|scope| scope.replace(self.previous.take()));
    }
}

pub(super) fn member(root: &File, name: &str, write: bool) -> Result<File, std::io::Error> {
    let name = std::ffi::CString::new(name).expect("fixed validated attempt filename");
    let flags = libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | if write {
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL
        } else {
            libc::O_RDONLY
        };
    let fd = unsafe { libc::openat(root.as_raw_fd(), name.as_ptr(), flags, 0o600) };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

/// A pending member is private evidence, never an observation-ready flag. Any
/// failure retains its exclusive inode/name (or the atomically published final
/// name); recovery must not guess that a partially completed publish is absent.
struct PendingObservation {
    file: File,
    staging: String,
    final_name: String,
    complete: std::fs::Metadata,
}

fn observation_directory(root: &File) -> std::io::Result<()> {
    let metadata = root.metadata()?;
    // SAFETY: geteuid has no arguments and only observes this process's identity.
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() == 0
    {
        return Err(std::io::Error::other(
            "held observation directory custody differs",
        ));
    }
    Ok(())
}

fn observation_stamp(
    metadata: &std::fs::Metadata,
) -> (u64, u64, u64, u64, u32, u32, u32, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.nlink(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn verify_observation(
    root: &File,
    name: &str,
    held: &File,
    expected: &std::fs::Metadata,
    bytes: &[u8],
) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    observation_directory(root)?;
    let named = member(root, name, false)?;
    let before = held.metadata()?;
    // SAFETY: geteuid only observes the current process's effective identity.
    if !before.is_file()
        || before.uid() != unsafe { libc::geteuid() }
        || before.nlink() != 1
        || before.mode() & 0o7777 != 0o600
        || before.len() != bytes.len() as u64
        || observation_stamp(&before) != observation_stamp(expected)
        || observation_stamp(&named.metadata()?) != observation_stamp(expected)
    {
        return Err(std::io::Error::other(
            "observation held/named inode, size or custody differs",
        ));
    }
    let mut held_chunk = [0; 65536];
    let mut named_chunk = [0; 65536];
    let mut offset = 0;
    while offset < bytes.len() {
        let count = held_chunk.len().min(bytes.len() - offset);
        held.read_exact_at(&mut held_chunk[..count], offset as u64)?;
        named.read_exact_at(&mut named_chunk[..count], offset as u64)?;
        let expected_bytes = &bytes[offset..offset + count];
        if &held_chunk[..count] != expected_bytes || &named_chunk[..count] != expected_bytes {
            return Err(std::io::Error::other(
                "observation complete held/named byte readback differs",
            ));
        }
        offset += count;
    }
    if observation_stamp(&held.metadata()?) != observation_stamp(expected)
        || observation_stamp(&named.metadata()?) != observation_stamp(expected)
    {
        return Err(std::io::Error::other(
            "observation custody changed during complete readback",
        ));
    }
    observation_directory(root)
}

impl PendingObservation {
    fn prepare(root: &File, name: &str, bytes: &[u8]) -> std::io::Result<Self> {
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
            return Err(std::io::Error::other("observation final basename differs"));
        }
        observation_directory(root)?;
        let staging = format!(".memcordon-observation-{name}.pending");
        let mut file = member(root, &staging, true)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        let complete = file.metadata()?;
        verify_observation(root, &staging, &file, &complete, bytes)?;
        Ok(Self {
            file,
            staging,
            final_name: name.to_owned(),
            complete,
        })
    }

    fn publish(self, root: &File, bytes: &[u8]) -> std::io::Result<()> {
        verify_observation(root, &self.staging, &self.file, &self.complete, bytes)?;
        let staging =
            std::ffi::CString::new(self.staging.as_str()).expect("validated private basename");
        let final_name =
            std::ffi::CString::new(self.final_name.as_str()).expect("validated final basename");
        // SAFETY: both NUL-terminated basenames belong to the same retained
        // directory descriptor. RENAME_NOREPLACE atomically preserves existing
        // evidence, without exposing the link-count transition of link/unlink.
        if unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                root.as_raw_fd(),
                staging.as_ptr(),
                root.as_raw_fd(),
                final_name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        root.sync_all()?;
        let published = self.file.metadata()?;
        // Rename may change ctime. Every other held native fact and all bytes
        // must remain unchanged, and final readback pins the new ctime too.
        let stable = |metadata: &std::fs::Metadata| {
            (
                metadata.dev(),
                metadata.ino(),
                metadata.len(),
                metadata.nlink(),
                metadata.uid(),
                metadata.gid(),
                metadata.mode(),
                metadata.mtime(),
                metadata.mtime_nsec(),
            )
        };
        if stable(&published) != stable(&self.complete) {
            return Err(std::io::Error::other(
                "observation native owner changed across atomic publication",
            ));
        }
        verify_observation(root, &self.final_name, &self.file, &published, bytes)
    }
}

fn publish_observation(root: &File, name: &str, bytes: &[u8]) -> Result<(), String> {
    PendingObservation::prepare(root, name, bytes)
        .and_then(|pending| pending.publish(root, bytes))
        .map_err(|error| format!("observation publication failed; final={name}; private staging/final evidence retained: {error}"))
}

#[cfg(test)]
#[path = "../../tests/support/mixed_observation_publication.rs"]
mod publication_tests;

/// State for the optional original-owner retirement exchange. Local observer
/// failure is retained separately while the frontend continues reading the
/// actual authenticated native terminal.
pub(super) struct RetirementExchange {
    pub cleanup_deadline: Instant,
    pub enrollment: memcordon_core::mixed_observation::MixedRetirementEnrollmentV1,
    pub enrollment_bytes: Vec<u8>,
    pub enrollment_sha256: memcordon_core::DiagnosticSha256,
    accepted: bool,
    witness: Option<memcordon_core::DiagnosticSha256>,
    result: bool,
    pub error: Option<String>,
}
impl RetirementExchange {
    pub(super) fn prepare(
        prepared: &MixedPreparedObservationV2,
        bytes: &[u8],
    ) -> Result<Option<Self>, String> {
        use memcordon_core::mixed_observation::*;
        let scope = OBSERVER.with(|scope| scope.borrow().clone());
        let Some(directory) = scope else {
            return Ok(None);
        };
        let configuration = match read_retirement_member(&directory, "retirement-observer.json") {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.to_string()),
        };
        let observer: MixedRetirementObserverV1 = parse_retirement(&configuration)?;
        observer.validate()?;
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|e| e.to_string())?;
        if observer.boot_identity.as_str() != boot.trim()
            || crate::sealed::client::monotonic_millis()?
                >= observer.observer_work_deadline_monotonic_millis
        {
            return Err("retirement observer original boot/cutoff differs".into());
        }
        let sampled = Instant::now();
        let remaining = observer
            .observer_cleanup_deadline_monotonic_millis
            .checked_sub(crate::sealed::client::monotonic_millis()?)
            .ok_or("original observer cleanup cutoff expired")?;
        let cleanup_deadline = sampled
            .checked_add(Duration::from_millis(remaining))
            .ok_or("original observer cleanup cutoff overflow")?;
        let enrollment = MixedRetirementEnrollmentV1 {
            format: "memcordon.mixed-retirement-enrollment".into(),
            revision: 1,
            binding: MixedRetirementBindingV1 {
                attempt_id: prepared.admission.attempt_id.clone(),
                admission_nonce: prepared.admission.admission_nonce,
                prepared_sha256: retirement_digest(bytes),
            },
            observer,
        };
        let enrollment_bytes = encode_retirement(&enrollment)?;
        Ok(Some(Self {
            cleanup_deadline,
            enrollment,
            enrollment_sha256: retirement_digest(&enrollment_bytes),
            enrollment_bytes,
            accepted: false,
            witness: None,
            result: false,
            error: None,
        }))
    }
    pub(super) fn accepted(&mut self, bytes: &[u8]) -> Result<(), String> {
        use memcordon_core::mixed_observation::*;
        let receipt: MixedRetirementEnrolledV1 = parse_retirement(bytes)?;
        if self.accepted
            || receipt.format != "memcordon.mixed-retirement-enrolled"
            || receipt.revision != 1
            || receipt.binding != self.enrollment.binding
            || receipt.enrollment_sha256 != self.enrollment_sha256
        {
            return Err("retirement acceptance association/order differs".into());
        }
        self.accepted = true;
        record_retirement(&self.enrollment.binding, "retirement-enrolled.json", bytes)
    }
    pub(super) fn release_allowed(&self) -> bool {
        self.accepted
    }
    pub(super) fn observe(
        &mut self,
        prepared: &MixedPreparedObservationV2,
        bytes: &[u8],
        return_limit: Option<Instant>,
    ) -> Result<(Vec<u8>, Instant), String> {
        use memcordon_core::mixed_observation::*;
        let witness: MixedRetirementObservationV1 = parse_retirement(bytes)?;
        witness.validate()?;
        if !self.accepted
            || self.witness.is_some()
            || self.result
            || witness.binding != self.enrollment.binding
            || witness.enrollment_sha256 != self.enrollment_sha256
            || witness.boot_identity != self.enrollment.observer.boot_identity
            || witness.caller != prepared.caller
            || witness.target != prepared.target
            || witness.namespace_init != prepared.namespace_init
            || witness.guardian != prepared.guardian
            || witness.observation_deadline_monotonic_millis
                > self
                    .enrollment
                    .observer
                    .observer_work_deadline_monotonic_millis
            || witness.cleanup_deadline_monotonic_millis
                > self
                    .enrollment
                    .observer
                    .observer_cleanup_deadline_monotonic_millis
        {
            return Err("retirement witness original association/order differs".into());
        }
        let sampled = Instant::now();
        let now = crate::sealed::client::monotonic_millis()?;
        let remaining = witness
            .observation_deadline_monotonic_millis
            .checked_sub(now)
            .ok_or("retirement witness cutoff expired")?;
        let cutoff = sampled
            .checked_add(Duration::from_millis(remaining))
            .ok_or("retirement witness cutoff overflow")?;
        let cutoff = return_limit.map_or(cutoff, |limit| limit.min(cutoff));
        let cleanup = sampled
            .checked_add(Duration::from_millis(
                witness
                    .cleanup_deadline_monotonic_millis
                    .checked_sub(now)
                    .ok_or("retirement cleanup cutoff expired")?,
            ))
            .ok_or("retirement cleanup cutoff overflow")?;
        if return_limit.is_some_and(|limit| cleanup > limit) {
            return Err("retirement cleanup cutoff exceeds original frontend envelope".into());
        }
        self.cleanup_deadline = self.cleanup_deadline.min(cleanup);
        let digest = retirement_digest(bytes);
        self.witness = Some(digest.clone());
        let observed = (|| -> Result<MixedRetirementAcknowledgmentV1, String> {
            record_retirement(&self.enrollment.binding, "retirement-prepared.json", bytes)?;
            let directory = OBSERVER
                .with(|scope| scope.borrow().clone())
                .ok_or("retirement observer scope lost")?;
            let name = format!(
                "{}.retirement-observer-ack.json",
                self.enrollment.binding.attempt_id.as_str()
            );
            loop {
                if Instant::now() >= cutoff {
                    return Err("original retirement observation deadline expired".into());
                }
                match read_retirement_member(&directory, &name) {
                    Ok(bytes) => {
                        let ack: MixedRetirementAcknowledgmentV1 = parse_retirement(&bytes)?;
                        if ack.format != "memcordon.mixed-retirement-acknowledgment"
                            || ack.revision != 1
                            || ack.binding != self.enrollment.binding
                            || ack.enrollment_sha256 != self.enrollment_sha256
                            || ack.witness_sha256 != digest
                        {
                            return Err(
                                "retirement observer acknowledgement association differs".into()
                            );
                        }
                        if Instant::now() >= cutoff {
                            return Err("retirement observer acknowledgement arrived late".into());
                        }
                        return Ok(ack);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        std::thread::sleep(Duration::from_millis(1))
                    }
                    Err(error) => return Err(error.to_string()),
                }
            }
        })();
        let ack = match observed {
            Ok(ack) => ack,
            Err(detail) => {
                self.error = Some(detail.clone());
                MixedRetirementAcknowledgmentV1 {
                    format: "memcordon.mixed-retirement-acknowledgment".into(),
                    revision: 1,
                    binding: self.enrollment.binding.clone(),
                    enrollment_sha256: self.enrollment_sha256.clone(),
                    witness_sha256: digest,
                    disposition: MixedRetirementDispositionV1::Aborted {
                        detail: memcordon_core::BoundedText::new(&detail).unwrap_or_else(|_| {
                            memcordon_core::BoundedText::new("retirement observer failed")
                                .expect("fixed detail")
                        }),
                    },
                }
            }
        };
        if let MixedRetirementDispositionV1::Aborted { detail } = &ack.disposition {
            self.error = Some(detail.as_str().into());
        }
        Ok((encode_retirement(&ack)?, cutoff))
    }
    pub(super) fn finished(&mut self, bytes: &[u8]) -> Result<(), String> {
        use memcordon_core::mixed_observation::*;
        let result: MixedRetirementObserverResultV1 = parse_retirement(bytes)?;
        result.validate()?;
        if !self.accepted
            || self.result
            || result.format != "memcordon.mixed-retirement-observer-result"
            || result.revision != 1
            || result.binding != self.enrollment.binding
            || result.enrollment_sha256 != self.enrollment_sha256
            || result.witness_sha256 != self.witness
            || (matches!(result.outcome, MixedRetirementOutcomeV1::Acknowledged)
                && self.witness.is_none())
        {
            return Err("retirement observer result association/order differs".into());
        }
        self.result = true;
        if let MixedRetirementOutcomeV1::Failed { stage, detail } = &result.outcome {
            self.error = Some(format!(
                "retirement observer {stage:?}: {}",
                detail.as_str()
            ));
        }
        record_retirement(&self.enrollment.binding, "retirement-result.json", bytes)
    }
    pub(super) fn terminal_error(mut self) -> Option<String> {
        if !self.result {
            self.error = Some("enrolled retirement observer result is absent".into());
        }
        self.error
    }
}
fn read_retirement_member(directory: &File, name: &str) -> std::io::Result<Vec<u8>> {
    use memcordon_core::mixed_observation::RETIREMENT_OBSERVATION_BYTES;
    let mut file = member(directory, name, false)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != unsafe { libc::geteuid() }
        || before.nlink() != 1
        || before.mode() & 0o7777 != 0o600
        || before.len() > RETIREMENT_OBSERVATION_BYTES as u64
    {
        return Err(std::io::Error::other(
            "retirement observer member custody differs",
        ));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((RETIREMENT_OBSERVATION_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    let stamp = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.nlink(),
            m.uid(),
            m.mode(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    let named = member(directory, name, false)?;
    if bytes.len() as u64 != before.len()
        || stamp(&before) != stamp(&file.metadata()?)
        || stamp(&before) != stamp(&named.metadata()?)
    {
        return Err(std::io::Error::other(
            "retirement observer member changed while reading",
        ));
    }
    Ok(bytes)
}
fn record_retirement(
    binding: &memcordon_core::mixed_observation::MixedRetirementBindingV1,
    suffix: &str,
    bytes: &[u8],
) -> Result<(), String> {
    if bytes.len() > memcordon_core::mixed_observation::RETIREMENT_OBSERVATION_BYTES {
        return Err("retirement observer member exceeds existing bound before publication".into());
    }
    let directory = OBSERVER
        .with(|scope| scope.borrow().clone())
        .ok_or("retirement observer scope lost")?;
    let name = format!("{}.{suffix}", binding.attempt_id.as_str());
    publish_observation(&directory, &name, bytes)?;
    if read_retirement_member(&directory, &name).map_err(|e| e.to_string())? != bytes {
        return Err("retirement observer persisted bytes differ".into());
    }
    Ok(())
}

/// Persist exactly the bytes sent to the authenticated provider, before send.
/// This receipt records an invocation; it grants no admission authority.
pub(super) fn record_request(attempt: [u8; 16], bytes: &[u8]) -> Result<(), String> {
    record_member(attempt, "provider-request.bin", bytes)
}

/// Retain the authenticated provider's original terminal bytes before local
/// report delivery. This observation does not certify report persistence.
pub(super) fn record_terminal(attempt: [u8; 16], bytes: &[u8]) -> Result<(), String> {
    record_member(attempt, "provider-terminal.json", bytes)
}
pub(super) fn record_legacy_frame(
    attempt: [u8; 16],
    terminal: bool,
    bytes: &[u8],
) -> Result<(), String> {
    record_member(
        attempt,
        if terminal {
            "legacy-provider-terminal.bin"
        } else {
            "legacy-provider-request.bin"
        },
        bytes,
    )
}

fn record_member(attempt: [u8; 16], suffix: &str, bytes: &[u8]) -> Result<(), String> {
    let scope = OBSERVER.with(|scope| scope.borrow().clone());
    let Some(directory) = scope else {
        return Ok(());
    };
    let identity = attempt
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    publish_observation(&directory, &format!("{identity}.{suffix}"), bytes)
}

pub(super) fn observe(
    bytes: &[u8],
    value: &MixedPreparedObservationV2,
    deadline: Instant,
) -> Result<(), String> {
    observe_phase(
        bytes,
        value,
        deadline,
        "prepared.json",
        "observer-ack.json",
        "memcordon.mixed-observer-acknowledgment",
    )
}

/// Opt-in final-policy-check observation under the same exclusively held scope.
pub(super) fn observe_release(
    bytes: &[u8],
    value: &memcordon_core::mixed_observation::MixedReleaseObservationV2,
    deadline: Instant,
) -> Result<(), String> {
    value.validate()?;
    let scope = OBSERVER.with(|scope| scope.borrow().clone());
    let Some(directory) = scope else {
        return Ok(());
    };
    let mut configuration = match member(&directory, "release-observer.json", false) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    let metadata = configuration
        .metadata()
        .map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() > 1024
    {
        return Err("mixed release observer configuration custody differs".into());
    }
    let mut selected = Vec::new();
    Read::by_ref(&mut configuration)
        .take(1025)
        .read_to_end(&mut selected)
        .map_err(|error| error.to_string())?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&selected)?;
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Configuration {
        format: String,
        revision: u32,
    }
    let configuration: Configuration =
        serde_json::from_slice(&selected).map_err(|error| error.to_string())?;
    if configuration.format != "memcordon.mixed-release-observer" || configuration.revision != 2 {
        return Err("mixed release observer configuration format differs".into());
    }
    observe_phase(
        bytes,
        &value.prepared,
        deadline,
        "release-prepared.json",
        "release-observer-ack.json",
        "memcordon.mixed-release-observer-acknowledgment",
    )
}

fn observe_phase(
    bytes: &[u8],
    value: &MixedPreparedObservationV2,
    deadline: Instant,
    observation_name: &str,
    acknowledgment_name: &str,
    acknowledgment_format: &str,
) -> Result<(), String> {
    let scope = OBSERVER.with(|scope| scope.borrow().clone());
    let Some(directory) = scope else {
        return Ok(());
    };
    value.validate()?;
    let attempt = value.admission.attempt_id.as_str();
    if attempt.len() != 32
        || !attempt
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("mixed observation attempt filename differs".into());
    }
    publish_observation(&directory, &format!("{attempt}.{observation_name}"), bytes)?;
    loop {
        if Instant::now() >= deadline {
            return Err("mixed native observer barrier deadline expired".into());
        }
        match member(
            &directory,
            &format!("{attempt}.{acknowledgment_name}"),
            false,
        ) {
            Ok(mut file) => {
                let metadata = file.metadata().map_err(|error| error.to_string())?;
                if !metadata.is_file()
                    || metadata.uid() != unsafe { libc::geteuid() }
                    || metadata.nlink() != 1
                    || metadata.mode() & 0o7777 != 0o600
                    || metadata.len() > 8192
                {
                    return Err("mixed observer acknowledgement custody differs".into());
                }
                let mut bytes = Vec::new();
                Read::by_ref(&mut file)
                    .take(8193)
                    .read_to_end(&mut bytes)
                    .map_err(|error| error.to_string())?;
                memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
                let ack: memcordon_core::mixed_observation::MixedObserverAcknowledgmentV2 =
                    serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
                if ack.format != acknowledgment_format
                    || ack.revision != 2
                    || ack.attempt_id != value.admission.attempt_id
                    || ack.admission_nonce != value.admission.admission_nonce
                    || ack.target != value.target
                    || ack.observer.pid == 0
                    || ack.observer.birth == 0
                {
                    return Err("mixed observer acknowledgement association differs".into());
                }
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}
