//! Failure-only observations; never a custody or qualification decision.
use std::{error::Error, fmt, io, time::Duration};

#[derive(Clone, Copy, Debug)]
pub(super) enum ImageOperand {
    Child,
    HeldDriver,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ImageCheck {
    Metadata {
        operand: ImageOperand,
    },
    DescriptorFlags {
        operand: ImageOperand,
    },
    Capability {
        operand: ImageOperand,
        is_file: bool,
        is_directory: bool,
        flags: u32,
    },
    IdentityMismatch {
        child_device: u64,
        child_inode: u64,
        held_device: u64,
        held_inode: u64,
    },
}
impl fmt::Display for ImageCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Metadata { operand } => write!(f, "metadata; operand={operand:?}"),
            Self::DescriptorFlags { operand } => write!(f, "descriptor-flags; operand={operand:?}"),
            Self::Capability {
                operand,
                is_file,
                is_directory,
                flags,
            } => write!(
                f,
                "capability; operand={operand:?}; is-file={is_file}; is-directory={is_directory}; flags={flags}"
            ),
            Self::IdentityMismatch {
                child_device,
                child_inode,
                held_device,
                held_inode,
            } => write!(
                f,
                "identity-mismatch; child-device={child_device}; child-inode={child_inode}; held-device={held_device}; held-inode={held_inode}"
            ),
        }
    }
}

struct ImageFailure {
    original: io::Error,
    check: ImageCheck,
}
impl fmt::Display for ImageFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "original-kind={:?}; original-raw-os-error={:?}; child-image={}",
            self.original.kind(),
            self.original.raw_os_error(),
            self.check
        )
    }
}
impl fmt::Debug for ImageFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl Error for ImageFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.original)
    }
}
pub(super) fn image_failure(original: io::Error, check: ImageCheck) -> io::Error {
    io::Error::new(original.kind(), ImageFailure { original, check })
}

#[derive(Clone, Copy, Debug)]
pub(super) enum NativeCheck {
    Other,
    Hello,
    BeforeSend,
    AfterAck,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Phase {
    ValidateAdmission,
    ReserveDescriptors,
    QualifyDriver,
    HashOriginalDriver,
    PrepareNonce,
    ObserveParent,
    ExportCutoffs,
    CreateSocket,
    Spawn,
    ObserveChildIdentity,
    OpenChildImage,
    CheckChildImageIdentity,
    HashChildImage,
    ReceiveHello,
    DecodeHello,
    CheckHello,
    CheckCutoff(NativeCheck),
    ObserveNativeExit(NativeCheck),
    ObserveNativeBirth(NativeCheck),
    PrepareBinding,
    EncodeAdmission,
    SendAdmission,
    ReceiveAck,
    DecodeAck,
    CheckAck,
    ReuseLease,
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CheckCutoff(point) => write!(f, "CheckCutoff({point:?})"),
            Self::ObserveNativeExit(point) => write!(f, "ObserveNativeExit({point:?})"),
            Self::ObserveNativeBirth(point) => write!(f, "ObserveNativeBirth({point:?})"),
            other => write!(f, "{other:?}"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Observation {
    pub phase: Phase,
    pub elapsed: Duration,
    pub completed: usize,
    pub shards: usize,
    pub last_shard_slots: Option<usize>,
}

struct Failure {
    original: io::Error,
    observation: Observation,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only the closed child-image context may expose already observed identity operands.
        // No arbitrary error Display, path or nonce is emitted.
        // The complete initiating error remains available through Error::source.
        let image = self
            .original
            .get_ref()
            .and_then(|value| value.downcast_ref::<ImageFailure>());
        let original = image.map_or(&self.original, |value| &value.original);
        write!(
            f,
            "original-kind={:?}; original-raw-os-error={:?}; custody-admission phase={}; elapsed-micros={}; completed={}; shards={}; last-shard-slots={:?}",
            original.kind(),
            original.raw_os_error(),
            self.observation.phase,
            self.observation.elapsed.as_micros(),
            self.observation.completed,
            self.observation.shards,
            self.observation.last_shard_slots
        )?;
        if let Some(image) = image {
            write!(f, "; child-image={}", image.check)?;
        }
        Ok(())
    }
}
impl fmt::Debug for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.original)
    }
}

pub(super) fn failure(original: io::Error, observation: Observation) -> io::Error {
    io::Error::new(
        original.kind(),
        Failure {
            original,
            observation,
        },
    )
}
