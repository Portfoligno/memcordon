//! Closed, capability-only storage for original image file descriptions.
//! The coordinator remains the policy and named-association authority.
#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use memcordon_platform::test_support::{
    ImageCustodyPeer, ImageCustodySocket, ProcessIdentity, image_custody_current_peer,
    image_custody_cutoff_nanos, image_custody_deadline, image_custody_fd_budget,
};
use sha2::{Digest, Sha256};

#[path = "linux_image_custody_wire.rs"]
mod wire;
use wire::{Binding, Frame, decode, encode};
pub use wire::{Identity, Role};
#[path = "linux_image_custody_diagnostic.rs"]
mod diagnostic;
use diagnostic::{NativeCheck, Phase};

const SLOTS: usize = 128;
const MAX_SHARDS: usize = 2048;
const MAX_PATH_BYTES: usize = 4096;
#[path = "linux_image_custody_plan.rs"]
pub mod capacity;
pub const CHILD_ARGUMENT: &str = "--internal-linux-image-custodian";
pub const CHILD_ARGUMENT_COUNT: usize = 7;
pub const CHILD_ARGUMENT_BYTES: usize = 128;

impl Identity {
    fn of(file: &File) -> io::Result<Self> {
        Self::of_observed(file, None)
    }
    fn of_observed(file: &File, operand: Option<diagnostic::ImageOperand>) -> io::Result<Self> {
        let metadata = file.metadata().map_err(|error| match operand {
            Some(operand) => {
                diagnostic::image_failure(error, diagnostic::ImageCheck::Metadata { operand })
            }
            None => error,
        })?;
        let flags = rustix::fs::fcntl_getfl(file).map_err(|error| {
            let error = io::Error::from(error);
            match operand {
                Some(operand) => diagnostic::image_failure(
                    error,
                    diagnostic::ImageCheck::DescriptorFlags { operand },
                ),
                None => error,
            }
        })?;
        let is_file = metadata.is_file();
        let is_directory = metadata.is_dir();
        if (!is_file && !is_directory)
            || flags.contains(rustix::fs::OFlags::PATH)
            || flags & rustix::fs::OFlags::ACCMODE != rustix::fs::OFlags::RDONLY
        {
            let original =
                invalid("custodian accepts only readonly file or directory capabilities");
            return Err(match operand {
                Some(operand) => diagnostic::image_failure(
                    original,
                    diagnostic::ImageCheck::Capability {
                        operand,
                        is_file,
                        is_directory,
                        flags: flags.bits(),
                    },
                ),
                None => original,
            });
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

impl Role {
    fn local(self) -> super::linux_image_custody::Role {
        match self {
            Self::AdministrativeFile => super::linux_image_custody::Role::AdministrativeFile,
            Self::AdministrativeDirectory => {
                super::linux_image_custody::Role::AdministrativeDirectory
            }
            Self::EvidenceDirectory => super::linux_image_custody::Role::EvidenceDirectory,
        }
    }
    fn admits(self, file: &File) -> io::Result<bool> {
        let metadata = file.metadata()?;
        Ok(match self {
            Self::AdministrativeFile => metadata.is_file(),
            _ => metadata.is_dir(),
        })
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn live(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::ErrorKind::TimedOut.into())
    } else {
        Ok(())
    }
}

fn same(actual: &Binding, expected: &Binding) -> bool {
    actual.nonce == expected.nonce
        && actual.sequence == expected.sequence
        && actual.slot == expected.slot
        && actual.path.as_os_str() == expected.path.as_os_str()
        && actual.identity == expected.identity
        && actual.role == expected.role
}

fn valid_path(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let normalized: PathBuf = path.components().collect();
    path.is_absolute()
        && path.as_os_str().as_bytes().len() <= MAX_PATH_BYTES
        && !path.as_os_str().as_bytes().contains(&0)
        && normalized.as_os_str() == path.as_os_str()
        && !path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
}

fn executable_digest(file: &File, deadline: Instant) -> io::Result<Vec<u8>> {
    live(deadline)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > memcordon_readiness_verifier::MAX_ARTIFACT_BYTES {
        return Err(invalid(
            "qualified custodian executable exceeds existing evidence bound",
        ));
    }
    let mut hash = Sha256::new();
    let mut offset = 0u64;
    let mut buffer = [0; 64 * 1024];
    loop {
        live(deadline)?;
        let count = file.read_at(&mut buffer, offset)?;
        if count == 0 {
            break;
        }
        offset = offset
            .checked_add(count as u64)
            .ok_or_else(|| invalid("custodian executable size overflow"))?;
        if offset > before.len() {
            return Err(invalid("custodian executable grew during qualification"));
        }
        hash.update(&buffer[..count]);
    }
    live(deadline)?;
    let after = file.metadata()?;
    let stamp = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mode(),
            m.nlink(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    if offset != before.len() || stamp(&before) != stamp(&after) {
        return Err(invalid(
            "original qualified executable changed during hashing",
        ));
    }
    live(deadline)?;
    Ok(hash.finalize().to_vec())
}

struct Shard {
    child: Child,
    process: ProcessIdentity,
    peer: ImageCustodyPeer,
    socket: ImageCustodySocket,
    nonce: String,
    sequence: u64,
    count: usize,
    retired: bool,
    _nonce_owner: tempfile::TempDir,
}

struct UnsettledOwners {
    shards: Vec<Shard>,
    handoffs: usize,
}

static UNSETTLED_OWNERS: std::sync::Mutex<UnsettledOwners> =
    std::sync::Mutex::new(UnsettledOwners {
        shards: Vec::new(),
        handoffs: 0,
    });

/// Last nonblocking process-owner observation before the driver exits. An
/// unresolved report transfers the ACTUAL Child/socket here, never just a PID.
/// Even a later exit cannot turn its missed original settlement into success.
pub fn observe_transferred_cleanup() -> io::Result<()> {
    let mut owners = UNSETTLED_OWNERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    owners
        .shards
        .retain_mut(|shard| match shard.child.try_wait() {
            Ok(Some(_)) => {
                shard.retired = true;
                false
            }
            Ok(None) | Err(_) => true,
        });
    if owners.handoffs == 0 {
        return Ok(());
    }
    let identities: Vec<_> = owners
        .shards
        .iter()
        .take(8)
        .map(|shard| (shard.process.pid, shard.process.birth))
        .collect();
    Err(io::Error::other(format!(
        "original image custody required unresolved native-owner handoff; handoffs={}; remaining={}; original-identities-prefix={identities:?}; omitted-identities={}",
        owners.handoffs,
        owners.shards.len(),
        owners.shards.len().saturating_sub(identities.len())
    )))
}

impl Shard {
    fn check(&mut self, deadline: Instant) -> io::Result<()> {
        self.check_observed(
            deadline,
            &mut Phase::CheckCutoff(NativeCheck::Other),
            NativeCheck::Other,
        )
    }

    fn check_observed(
        &mut self,
        deadline: Instant,
        phase: &mut Phase,
        point: NativeCheck,
    ) -> io::Result<()> {
        *phase = Phase::CheckCutoff(point);
        live(deadline)?;
        *phase = Phase::ObserveNativeExit(point);
        if self.child.try_wait()?.is_some() {
            return Err(invalid("original custody process is no longer live"));
        }
        *phase = Phase::CheckCutoff(point);
        live(deadline)?;
        *phase = Phase::ObserveNativeBirth(point);
        if !self.process.still_exists()? {
            return Err(invalid("original custody process is no longer live"));
        }
        *phase = Phase::CheckCutoff(point);
        live(deadline)
    }

    fn next(
        &mut self,
        slot: usize,
        role: Role,
        path: &Path,
        identity: Identity,
    ) -> io::Result<Binding> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| invalid("custody sequence overflow"))?;
        Ok(Binding {
            nonce: self.nonce.clone(),
            sequence: self.sequence,
            slot,
            path: path.into(),
            identity,
            role,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Witness {
    shard: usize,
    slot: usize,
    pub path: PathBuf,
    pub identity: Identity,
    pub role: Role,
}

#[derive(Default)]
pub struct Custodians {
    shards: Vec<Shard>,
    originals: BTreeMap<(Role, PathBuf), Witness>,
    cleanup: Option<Instant>,
    executable: Option<File>,
    driver_path: Option<PathBuf>,
    executable_hash: Option<Vec<u8>>,
    failed: bool,
    failed_originals: Vec<File>,
    plan: Option<capacity::Plan>,
    retirement_failure: Option<String>,
}

impl Custodians {
    pub fn owner_count(&self) -> usize {
        self.originals.len()
    }

    pub(super) fn pin_driver(
        &mut self,
        path: PathBuf,
        expected: File,
        deadline: Instant,
    ) -> io::Result<()> {
        live(deadline)?;
        if self.driver_path.is_some() || self.executable.is_some() || !self.shards.is_empty() {
            return Err(invalid(
                "qualified custody driver is immutable after acquisition",
            ));
        }
        let hash = executable_digest(&expected, deadline)?;
        live(deadline)?;
        let named = File::open(&path)?;
        if Identity::of(&expected)? != Identity::of(&named)?
            || executable_digest(&named, deadline)? != hash
        {
            return Err(invalid(
                "qualified driver path differs from retained source executable",
            ));
        }
        self.driver_path = Some(path);
        self.executable = Some(expected);
        self.executable_hash = Some(hash);
        Ok(())
    }

    pub fn configure(&mut self, plan: capacity::Plan) -> io::Result<()> {
        if self.plan.is_some() || !self.shards.is_empty() || self.failed {
            return Err(invalid(
                "custody capacity plan is not a one-shot preparation",
            ));
        }
        if plan.channels > MAX_SHARDS {
            return Err(invalid(
                "complete image plan exceeds bounded custodian process inventory",
            ));
        }
        self.plan = Some(plan);
        Ok(())
    }

    pub fn reserve(&self) -> io::Result<()> {
        if UNSETTLED_OWNERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .handoffs
            != 0
        {
            return Err(invalid(
                "unresolved original native custody forbids later admissions or leases",
            ));
        }
        let budget = image_custody_fd_budget()?;
        if budget.open_descriptors.saturating_add(
            capacity::TRANSIENT_OWNERS + capacity::PARTIAL_WRITERS + capacity::JOURNAL_OWNERS,
        ) as u64
            >= budget.soft_limit
        {
            return Err(invalid(
                "image custody must preserve planned transient/journal/cleanup descriptors",
            ));
        }
        Ok(())
    }

    fn start(
        &mut self,
        deadline: Instant,
        cleanup: Instant,
        phase: &mut Phase,
    ) -> io::Result<usize> {
        *phase = Phase::ReserveDescriptors;
        live(deadline)?;
        let budget = image_custody_fd_budget()?;
        let plan = self
            .plan
            .ok_or_else(|| invalid("image custody has no complete descriptor plan"))?;
        if budget.soft_limit < (SLOTS + capacity::TRANSIENT_OWNERS + 4) as u64
            || budget.open_descriptors.saturating_add(
                capacity::TRANSIENT_OWNERS + capacity::PARTIAL_WRITERS + capacity::JOURNAL_OWNERS,
            ) as u64
                >= budget.soft_limit
            || self.shards.len() >= plan.channels
            || self.shards.len() >= MAX_SHARDS
        {
            return Err(invalid(
                "image custody lacks measured process/channel cleanup headroom",
            ));
        }
        if self.driver_path.is_none() {
            *phase = Phase::QualifyDriver;
            self.pin_driver(
                std::env::current_exe()?,
                File::open("/proc/self/exe")?,
                deadline,
            )?;
        }
        let executable_path = self.driver_path.as_ref().expect("qualified driver path");
        *phase = Phase::HashOriginalDriver;
        let current_hash =
            executable_digest(self.executable.as_ref().expect("held executable"), deadline)?;
        if let Some(expected) = &self.executable_hash {
            if expected != &current_hash {
                return Err(invalid("original driver content qualification changed"));
            }
        } else {
            self.executable_hash = Some(current_hash);
        }
        *phase = Phase::PrepareNonce;
        let nonce_owner = tempfile::tempdir()?;
        let nonce = nonce_owner
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("custody nonce is not UTF8"))?
            .to_owned();
        *phase = Phase::ObserveParent;
        let parent = ProcessIdentity::current()?;
        let credentials = image_custody_current_peer()?;
        *phase = Phase::ExportCutoffs;
        let work_ns = image_custody_cutoff_nanos(deadline)?;
        let cleanup_ns = image_custody_cutoff_nanos(cleanup)?;
        *phase = Phase::CreateSocket;
        let (socket, child_socket) = ImageCustodySocket::pair()?;
        *phase = Phase::Spawn;
        let child = Command::new(executable_path)
            .arg(CHILD_ARGUMENT)
            .args([
                nonce.clone(),
                parent.pid.to_string(),
                parent.birth.to_string(),
                credentials.uid.to_string(),
                credentials.gid.to_string(),
                work_ns.to_string(),
                cleanup_ns.to_string(),
            ])
            .stdin(child_socket.into_stdio())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        // Install the process owner BEFORE any fallible identity/hello proof.
        let index = self.shards.len();
        self.shards.push(Shard {
            process: ProcessIdentity {
                pid: child.id(),
                birth: 0,
            },
            peer: ImageCustodyPeer {
                pid: child.id(),
                uid: credentials.uid,
                gid: credentials.gid,
            },
            child,
            socket,
            nonce,
            sequence: 0,
            count: 0,
            retired: false,
            _nonce_owner: nonce_owner,
        });
        self.cleanup = Some(self.cleanup.map_or(cleanup, |old| old.min(cleanup)));
        let shard = &mut self.shards[index];
        *phase = Phase::ObserveChildIdentity;
        shard.process = ProcessIdentity::for_pid(shard.child.id())?;
        *phase = Phase::OpenChildImage;
        let image = File::open(
            Path::new("/proc")
                .join(shard.child.id().to_string())
                .join("exe"),
        )?;
        *phase = Phase::CheckChildImageIdentity;
        let child_identity = Identity::of_observed(&image, Some(diagnostic::ImageOperand::Child))?;
        let held_identity = Identity::of_observed(
            self.executable.as_ref().expect("held executable"),
            Some(diagnostic::ImageOperand::HeldDriver),
        )?;
        if child_identity != held_identity {
            return Err(diagnostic::image_failure(
                invalid("custodian executable differs from original qualified driver"),
                diagnostic::ImageCheck::IdentityMismatch {
                    child_device: child_identity.device,
                    child_inode: child_identity.inode,
                    held_device: held_identity.device,
                    held_inode: held_identity.inode,
                },
            ));
        }
        *phase = Phase::HashChildImage;
        if executable_digest(&image, deadline)?
            != *self.executable_hash.as_ref().expect("original driver hash")
        {
            return Err(invalid(
                "custodian actual executable differs from original qualified driver bytes",
            ));
        }
        *phase = Phase::ReceiveHello;
        let packet = shard.socket.receive(shard.peer, deadline)?;
        *phase = Phase::DecodeHello;
        let hello = decode(&packet.bytes)?;
        *phase = Phase::CheckHello;
        match hello {
            Frame::Hello { nonce, pid, birth }
                if packet.descriptor.is_none()
                    && nonce == shard.nonce
                    && pid == shard.process.pid
                    && birth == shard.process.birth => {}
            _ => {
                return Err(invalid(
                    "custody child hello differs from owned native process",
                ));
            }
        }
        shard.check_observed(deadline, phase, NativeCheck::Hello)?;
        Ok(index)
    }

    /// Caller has already checked the current role/named edge. The child ACK
    /// is required before the sender's original capability can be released.
    pub fn admit(
        &mut self,
        role: Role,
        path: &Path,
        candidate: File,
        deadline: Instant,
        cleanup: Instant,
    ) -> io::Result<(Witness, File)> {
        let existing = self.originals.contains_key(&(role, path.into()));
        let started = Instant::now();
        let mut phase = Phase::ValidateAdmission;
        let result = self.admit_original(role, path, &candidate, deadline, cleanup, &mut phase);
        let result = result.map_err(|error| self.admission_failure(error, phase, started));
        match result {
            Ok(witness) if existing => {
                let lease = match self.borrow(&witness, deadline) {
                    Ok(file) => file,
                    Err(error) => {
                        self.failed_originals.push(candidate);
                        self.failed = true;
                        return Err(self.admission_failure(error, Phase::ReuseLease, started));
                    }
                };
                Ok((witness, lease))
            }
            Ok(witness) => Ok((witness, candidate)),
            Err(error) => {
                // An unacknowledged transfer never loses its last sender.
                self.failed_originals.push(candidate);
                self.failed = true;
                Err(error)
            }
        }
    }

    fn admission_failure(&self, error: io::Error, phase: Phase, started: Instant) -> io::Error {
        diagnostic::failure(
            error,
            diagnostic::Observation {
                phase,
                elapsed: started.elapsed(),
                completed: self.originals.len(),
                shards: self.shards.len(),
                last_shard_slots: self.shards.last().map(|shard| shard.count),
            },
        )
    }

    fn admit_original(
        &mut self,
        role: Role,
        path: &Path,
        candidate: &File,
        deadline: Instant,
        cleanup: Instant,
        phase: &mut Phase,
    ) -> io::Result<Witness> {
        live(deadline)?;
        if self.failed || !valid_path(path) {
            return Err(invalid("invalid or failed original custody admission"));
        }
        if !role.admits(candidate)? {
            return Err(invalid(
                "custody capability type differs from original role",
            ));
        }
        let identity = Identity::of(candidate)?;
        if let Some(original) = self.originals.get(&(role, path.into())).cloned() {
            if original.identity != identity {
                return Err(invalid("named image replaced original custody inode"));
            }
            // The public admission returns an identity-checked duplicate of
            // this slot, never the fresh pathname-derived candidate.
            return Ok(original);
        }
        *phase = Phase::ReserveDescriptors;
        self.reserve()?;
        let plan = self
            .plan
            .ok_or_else(|| invalid("image custody complete plan absent"))?;
        if self.originals.len() >= plan.remote_files.saturating_add(plan.directory_owners) {
            return Err(invalid(
                "image custody exceeds original finite manifest/directory plan",
            ));
        }
        let index = match self.shards.last() {
            Some(shard) if shard.count < SLOTS => self.shards.len() - 1,
            _ => self.start(deadline, cleanup, phase)?,
        };
        let shard = &mut self.shards[index];
        shard.check_observed(deadline, phase, NativeCheck::BeforeSend)?;
        *phase = Phase::PrepareBinding;
        let binding = shard.next(shard.count, role, path, identity)?;
        *phase = Phase::EncodeAdmission;
        let bytes = encode(&Frame::Admit {
            binding: binding.clone(),
        })?;
        *phase = Phase::SendAdmission;
        shard.socket.send(&bytes, Some(candidate), deadline)?;
        *phase = Phase::ReceiveAck;
        let packet = shard.socket.receive(shard.peer, deadline)?;
        *phase = Phase::DecodeAck;
        let ack = decode(&packet.bytes)?;
        *phase = Phase::CheckAck;
        match ack {
            Frame::Ack { binding: actual }
                if packet.descriptor.is_none() && same(&actual, &binding) => {}
            _ => {
                self.failed = true;
                return Err(invalid(
                    "custody admission ACK differs; sender retains original",
                ));
            }
        }
        shard.check_observed(deadline, phase, NativeCheck::AfterAck)?;
        shard.count += 1;
        let witness = Witness {
            shard: index,
            slot: binding.slot,
            path: path.into(),
            identity,
            role,
        };
        self.originals.insert((role, path.into()), witness.clone());
        Ok(witness)
    }

    pub fn borrow(&mut self, original: &Witness, deadline: Instant) -> io::Result<File> {
        let result = self.borrow_original(original, deadline);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn borrow_original(&mut self, original: &Witness, deadline: Instant) -> io::Result<File> {
        live(deadline)?;
        if self.failed {
            return Err(invalid("custody already failed"));
        }
        self.reserve()?;
        let shard = self
            .shards
            .get_mut(original.shard)
            .ok_or_else(|| invalid("custody shard absent"))?;
        shard.check(deadline)?;
        let binding = shard.next(
            original.slot,
            original.role,
            &original.path,
            original.identity,
        )?;
        shard.socket.send(
            &encode(&Frame::Borrow {
                binding: binding.clone(),
            })?,
            None,
            deadline,
        )?;
        let packet = shard.socket.receive(shard.peer, deadline)?;
        match decode(&packet.bytes)? {
            Frame::Ack { binding: actual } if same(&actual, &binding) => {}
            _ => return Err(invalid("original custody lease response differs")),
        }
        let file = packet
            .descriptor
            .ok_or_else(|| invalid("custody lease capability absent"))?;
        if Identity::of(&file)? != original.identity || !original.role.admits(&file)? {
            return Err(invalid("custody lease changed original identity/type"));
        }
        shard.check(deadline)?;
        Ok(file)
    }

    /// Only the outer report owner may call this after its last association
    /// consumer. Every process is attempted even if an earlier channel fails.
    pub fn finish(&mut self, deadline: Instant) -> io::Result<()> {
        let deadline = self.cleanup.map_or(deadline, |old| old.min(deadline));
        self.cleanup = Some(deadline);
        let mut failures = RetirementErrors::default();
        for shard in &mut self.shards {
            if shard.retired {
                continue;
            }
            let result = (|| -> io::Result<()> {
                shard.check(deadline)?;
                shard.sequence = shard
                    .sequence
                    .checked_add(1)
                    .ok_or_else(|| invalid("custody finish sequence overflow"))?;
                shard.socket.send(
                    &encode(&Frame::Finish {
                        nonce: shard.nonce.clone(),
                        sequence: shard.sequence,
                        count: shard.count,
                    })?,
                    None,
                    deadline,
                )?;
                let packet = shard.socket.receive(shard.peer, deadline)?;
                match decode(&packet.bytes)? {
                    Frame::Finished {
                        nonce,
                        sequence,
                        count,
                    } if packet.descriptor.is_none()
                        && nonce == shard.nonce
                        && sequence == shard.sequence
                        && count == shard.count =>
                    {
                        Ok(())
                    }
                    _ => Err(invalid("custody final ownership acknowledgement differs")),
                }
            })();
            if let Err(error) = result {
                failures.push(format!("custody finish: {error}"));
                // Stop only this retained Child, never an unowned PID. This
                // is failed cleanup, never qualification or successful ACK.
                match shard.child.try_wait() {
                    Ok(None) => {
                        if let Err(error) = shard.child.kill() {
                            failures.push(format!("custody owned child stop: {error}"));
                        }
                    }
                    Ok(Some(_)) => {}
                    Err(error) => failures.push(format!("custody owned child state: {error}")),
                }
            }
        }
        for shard in &mut self.shards {
            if shard.retired {
                continue;
            }
            loop {
                match shard.child.try_wait() {
                    Ok(Some(status)) => {
                        shard.retired = true;
                        if Instant::now() >= deadline {
                            failures.push("native custody exit was not observed before original cleanup cutoff".to_owned());
                        }
                        if !status.success() {
                            failures
                                .push(format!("custody child retired unsuccessfully: {status}"));
                        }
                        break;
                    }
                    Ok(None) if Instant::now() < deadline => std::thread::sleep(
                        Duration::from_millis(1)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    ),
                    Ok(None) => {
                        failures.push(
                            "custody process remains owned at original cleanup cutoff".to_owned(),
                        );
                        if let Err(error) = shard.child.kill() {
                            failures
                                .push(format!("owned custody stop at original cutoff: {error}"));
                        }
                        break;
                    }
                    Err(error) => {
                        failures.push(format!("custody child retirement observation: {error}"));
                        break;
                    }
                }
            }
        }
        self.failed = true;
        if !failures.is_empty() {
            let message = failures.message();
            if self.retirement_failure.is_none() {
                self.retirement_failure = Some(message);
            }
        }
        match &self.retirement_failure {
            Some(error) => Err(io::Error::other(error.clone())),
            None => Ok(()),
        }
    }
}

#[derive(Default)]
struct RetirementErrors {
    messages: Vec<String>,
    omitted: usize,
}

impl RetirementErrors {
    fn push(&mut self, mut message: String) {
        if self.messages.len() >= 8 {
            self.omitted = self.omitted.saturating_add(1);
            return;
        }
        const BOUND: usize = 512;
        if message.len() > BOUND {
            let mut boundary = BOUND;
            while !message.is_char_boundary(boundary) {
                boundary -= 1;
            }
            message.truncate(boundary);
            message.push_str(" [truncated]");
        }
        self.messages.push(message);
    }
    fn is_empty(&self) -> bool {
        self.messages.is_empty() && self.omitted == 0
    }
    fn message(&self) -> String {
        format!(
            "{}; omitted-retirement-errors={}",
            self.messages.join("; "),
            self.omitted
        )
    }
}

impl Drop for Custodians {
    fn drop(&mut self) {
        // Explicit finish is the checked path. Unwind/error fallback must not
        // detach a live owner or introduce a renewed cleanup allowance.
        if let Some(deadline) = self.cleanup
            && self.shards.iter().any(|shard| !shard.retired)
            && let Err(error) = self.finish(deadline)
        {
            eprintln!("original image custody retirement incomplete: {error}");
        }
        if self.shards.iter().any(|shard| !shard.retired) {
            let mut owners = UNSETTLED_OWNERS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for shard in self.shards.drain(..) {
                if !shard.retired {
                    owners.handoffs = owners.handoffs.saturating_add(1);
                    owners.shards.push(shard);
                }
            }
        }
    }
}

/// Called before ordinary CLI parsing, exclusively for the closed child role.
pub fn run_child(arguments: &[String]) -> io::Result<()> {
    if arguments.len() != CHILD_ARGUMENT_COUNT
        || arguments
            .iter()
            .any(|argument| argument.len() > CHILD_ARGUMENT_BYTES)
    {
        return Err(invalid("invalid custody child arguments"));
    }
    let nonce = &arguments[0];
    if nonce.len() > 128
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(invalid("invalid custody challenge"));
    }
    let number = |index: usize| {
        arguments[index]
            .parse::<u64>()
            .map_err(|_| invalid("invalid custody numeric argument"))
    };
    let parent_pid = u32::try_from(number(1)?).map_err(io::Error::other)?;
    let parent_birth = arguments[2].parse::<u128>().map_err(io::Error::other)?;
    let peer = ImageCustodyPeer {
        pid: parent_pid,
        uid: u32::try_from(number(3)?).map_err(io::Error::other)?,
        gid: u32::try_from(number(4)?).map_err(io::Error::other)?,
    };
    let deadline = image_custody_deadline(number(5)?)?;
    let cleanup = image_custody_deadline(number(6)?)?;
    if deadline > cleanup
        || memcordon_platform::test_support::image_custody_parent_pid()? != parent_pid
        || ProcessIdentity::for_pid(parent_pid)?.birth != parent_birth
    {
        return Err(invalid("custody parent/cutoff binding differs"));
    }
    let socket = ImageCustodySocket::take_stdin()?;
    let budget = image_custody_fd_budget()?;
    if budget
        .open_descriptors
        .saturating_add(SLOTS + capacity::TRANSIENT_OWNERS) as u64
        >= budget.soft_limit
    {
        return Err(invalid(
            "custody child cannot reserve its bounded slot/ancillary inventory",
        ));
    }
    let process = ProcessIdentity::current()?;
    socket.send(
        &encode(&Frame::Hello {
            nonce: nonce.clone(),
            pid: process.pid,
            birth: process.birth,
        })?,
        None,
        deadline,
    )?;
    let mut originals: Vec<(Binding, std::sync::Arc<File>)> = Vec::new();
    let mut original_owners = super::linux_image_custody::CustodyPool::default();
    let mut sequence = 0;
    loop {
        let packet = socket.receive(peer, cleanup)?;
        match decode(&packet.bytes)? {
            Frame::Admit { binding } => {
                live(deadline)?;
                if binding.nonce != *nonce
                    || binding.sequence != sequence + 1
                    || binding.slot != originals.len()
                    || originals.len() >= SLOTS
                    || !valid_path(&binding.path)
                {
                    return Err(invalid("invalid custody admission binding"));
                }
                let file = packet
                    .descriptor
                    .ok_or_else(|| invalid("admission capability absent"))?;
                if Identity::of(&file)? != binding.identity || !binding.role.admits(&file)? {
                    return Err(invalid("admission native identity/type differs"));
                }
                let file = original_owners.admit(binding.role.local(), &binding.path, file)?;
                if original_owners.owner_count() != originals.len() + 1 {
                    return Err(invalid(
                        "custody admission duplicates an existing original role/path slot",
                    ));
                }
                sequence = binding.sequence;
                originals.push((binding.clone(), file));
                socket.send(&encode(&Frame::Ack { binding })?, None, deadline)?;
            }
            Frame::Borrow { binding } => {
                live(deadline)?;
                if packet.descriptor.is_some()
                    || !valid_path(&binding.path)
                    || binding.nonce != *nonce
                    || binding.sequence != sequence + 1
                {
                    return Err(invalid("invalid custody lease binding"));
                }
                let (original, file) = originals
                    .get(binding.slot)
                    .ok_or_else(|| invalid("custody slot absent"))?;
                if original.path.as_os_str() != binding.path.as_os_str()
                    || original.role != binding.role
                    || original.identity != binding.identity
                    || Identity::of(file)? != binding.identity
                {
                    return Err(invalid("custody lease original differs"));
                }
                sequence = binding.sequence;
                socket.send(&encode(&Frame::Ack { binding })?, Some(file), deadline)?;
            }
            Frame::Finish {
                nonce: actual,
                sequence: next,
                count,
            } if packet.descriptor.is_none()
                && actual == *nonce
                && next == sequence + 1
                && count == originals.len() =>
            {
                socket.send(
                    &encode(&Frame::Finished {
                        nonce: actual,
                        sequence: next,
                        count,
                    })?,
                    None,
                    cleanup,
                )?;
                return Ok(());
            }
            _ => return Err(invalid("unexpected custody command")),
        }
    }
}

#[cfg(test)]
#[path = "../../tests/private/linux_image_custodian.rs"]
mod native_tests;
