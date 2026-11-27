//! Static context around existing operations; the original error stays owned.
use std::{fmt, io};

#[derive(Clone, Copy, Debug)]
pub enum Operation {
    ListenerLocalAddress,
    CompetingBind,
    TranscriptConflictingBind,
    TranscriptListenerOwned,
    ChallengeWrite,
    PeerStdoutCreate,
    PeerStdoutDuplicate,
    PeerStdoutValidate,
    CurrentExecutable,
    PeerCommandSpawn,
    TranscriptSpawnIntent,
    PendingPeerIdentity,
    TranscriptPendingAdmission,
    PeerRecipientAdmission,
    RegistryMetadataHandoff,
    PeerIdentity,
    TranscriptPeerCreated,
    Toolchain(ToolchainOperation),
}

#[derive(Clone, Copy, Debug)]
pub enum SourceRole {
    Library,
    Tests,
    Child,
    Dll,
    Loader,
}

impl SourceRole {
    fn label(self) -> &'static str {
        match self {
            Self::Library => "library",
            Self::Tests => "tests",
            Self::Child => "child",
            Self::Dll => "dll",
            Self::Loader => "loader",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum CompilerDirectoryRole {
    OutsideInputRoot,
    InputRoot,
    InputAncestor,
    NativeLibraryDirectory,
    LinkerDirectory,
}

impl CompilerDirectoryRole {
    fn label(self) -> &'static str {
        match self {
            Self::OutsideInputRoot => "outside-input-root",
            Self::InputRoot => "input-root",
            Self::InputAncestor => "input-ancestor",
            Self::NativeLibraryDirectory => "native-library-directory",
            Self::LinkerDirectory => "linker-directory",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum CompilerOperation {
    QualifySelection,
    QualifyCommand,
    QualifyClock,
    DirectoryOwnerBound,
    DirectoryOpen(CompilerDirectoryRole),
    DirectoryMetadata(CompilerDirectoryRole),
    DirectoryNamedOpen(CompilerDirectoryRole),
    DirectoryRetainedMetadata(CompilerDirectoryRole),
    DirectoryNamedMetadata(CompilerDirectoryRole),
    DirectoryNamedIdentity(CompilerDirectoryRole),
    LinkerOpen,
    LinkerMetadata,
    LinkerRead,
    LinkerMeasure,
    LinkerNamedOpen,
    LinkerRetainedMetadata,
    LinkerNamedMetadata,
    LinkerNamedIdentity,
    CompilerOpen,
    CompilerMetadata,
    CompilerRead,
    ParentIdentity,
    CompilerSpawn,
    CaptureStart,
    ChildRetain,
    ChildIdentity,
    CheckpointInitialize,
    CheckpointPublish,
    DebugObservation,
    ChildRetirement,
    ChildWait,
    CaptureReceive,
    RetirementReceipt,
    ChildStatus,
}

impl CompilerOperation {
    fn labels(self) -> (&'static str, &'static str) {
        use CompilerOperation::*;
        match self {
            QualifySelection => ("qualify-selection", "fixture"),
            QualifyCommand => ("qualify-command", "fixture"),
            QualifyClock => ("qualify-clock", "fixture"),
            DirectoryOwnerBound => ("directory-owner-bound", "fixture"),
            DirectoryOpen(role) => ("directory-open", role.label()),
            DirectoryMetadata(role) => ("directory-metadata", role.label()),
            DirectoryNamedOpen(role) => ("directory-named-open", role.label()),
            DirectoryRetainedMetadata(role) => ("directory-retained-metadata", role.label()),
            DirectoryNamedMetadata(role) => ("directory-named-metadata", role.label()),
            DirectoryNamedIdentity(role) => ("directory-named-identity", role.label()),
            LinkerOpen => ("linker-open", "linker"),
            LinkerMetadata => ("linker-metadata", "linker"),
            LinkerRead => ("linker-read", "linker"),
            LinkerMeasure => ("linker-measure", "linker"),
            LinkerNamedOpen => ("linker-named-open", "linker"),
            LinkerRetainedMetadata => ("linker-retained-metadata", "linker"),
            LinkerNamedMetadata => ("linker-named-metadata", "linker"),
            LinkerNamedIdentity => ("linker-named-identity", "linker"),
            CompilerOpen => ("compiler-open", "compiler"),
            CompilerMetadata => ("compiler-metadata", "compiler"),
            CompilerRead => ("compiler-read", "compiler"),
            ParentIdentity => ("parent-identity", "fixture"),
            CompilerSpawn => ("compiler-spawn", "compiler"),
            CaptureStart => ("capture-start", "compiler"),
            ChildRetain => ("child-retain", "compiler"),
            ChildIdentity => ("child-identity", "compiler"),
            CheckpointInitialize => ("checkpoint-initialize", "fixture"),
            CheckpointPublish => ("checkpoint-publish", "fixture"),
            DebugObservation => ("debug-observation", "compiler"),
            ChildRetirement => ("child-retirement", "compiler"),
            ChildWait => ("child-wait", "compiler"),
            CaptureReceive => ("capture-receive", "compiler"),
            RetirementReceipt => ("retirement-receipt", "fixture"),
            ChildStatus => ("child-status", "compiler"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ToolchainOperation {
    ObserverSession,
    ObserverDeadlineArm,
    ObserverFrameRead,
    ObserverDeadlineSettle,
    CompilerConsole,
    CreateCompiledDirectory,
    ValidateClock,
    SampleDeadline,
    PublicationDeadline,
    RetainPublicationParent,
    CopySource(SourceRole),
    CompileLibrary,
}

impl ToolchainOperation {
    fn label(self) -> &'static str {
        match self {
            Self::ObserverSession => "observer-session",
            Self::ObserverDeadlineArm => "observer-deadline-arm",
            Self::ObserverFrameRead => "observer-frame-read",
            Self::ObserverDeadlineSettle => "observer-deadline-settle",
            Self::CompilerConsole => "compiler-console",
            Self::CreateCompiledDirectory => "create-compiled-directory",
            Self::ValidateClock => "validate-clock",
            Self::SampleDeadline => "sample-deadline",
            Self::PublicationDeadline => "publication-deadline",
            Self::RetainPublicationParent => "retain-publication-parent",
            Self::CopySource(_) => "copy-source",
            Self::CompileLibrary => "compile-library",
        }
    }
}

impl Operation {
    pub fn label(self) -> &'static str {
        match self {
            Self::ListenerLocalAddress => "listener-local-address",
            Self::CompetingBind => "competing-bind-expected-WSAEADDRINUSE",
            Self::TranscriptConflictingBind => "transcript-conflicting-bind",
            Self::TranscriptListenerOwned => "transcript-listener-owned",
            Self::ChallengeWrite => "tcp-challenge-write",
            Self::PeerStdoutCreate => "peer-stdout-create-owned-file",
            Self::PeerStdoutDuplicate => "peer-stdout-duplicate-held-file",
            Self::PeerStdoutValidate => "peer-stdout-validate-after-retirement",
            Self::CurrentExecutable => "current-executable-lookup",
            Self::PeerCommandSpawn => "peer-command-spawn",
            Self::TranscriptSpawnIntent => "transcript-peer-spawn-intent",
            Self::PendingPeerIdentity => "pending-peer-identity",
            Self::TranscriptPendingAdmission => "transcript-peer-pending-admission",
            Self::PeerRecipientAdmission => "peer-recipient-admission",
            Self::RegistryMetadataHandoff => "peer-registry-metadata-handoff",
            Self::PeerIdentity => "peer-created-identity",
            Self::TranscriptPeerCreated => "transcript-peer-created",
            Self::Toolchain(operation) => operation.label(),
        }
    }
}

#[derive(Debug)]
pub struct Failure {
    operation: Operation,
    original: io::Error,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Operation::Toolchain(operation) = self.operation {
            if matches!(operation, ToolchainOperation::CompileLibrary) {
                if let Some(failure) = compiler_failure(&self.original) {
                    let (stage, resource) = failure.operation.labels();
                    write!(
                        f,
                        "toolchain-failure-v2; operation=compile-library; source-role=none; compiler-operation={stage}; resource-role={resource}; raw-os-error="
                    )?;
                    write_code(f, &failure.original)?;
                    return write!(f, "; end\n{}", self.original);
                }
            }
            let role = match operation {
                ToolchainOperation::CopySource(role) => role.label(),
                _ => "none",
            };
            write!(
                f,
                "toolchain-failure-v1; operation={}; source-role={role}; raw-os-error=",
                operation.label()
            )?;
            write_code(f, &self.original)?;
            return write!(f, "; end\n{}", self.original);
        }
        write!(
            f,
            "{} [original_native_code={:?}]: {}",
            self.operation.label(),
            self.original.raw_os_error(),
            self.original
        )
    }
}

fn write_code(f: &mut fmt::Formatter<'_>, error: &io::Error) -> fmt::Result {
    match original_code(error) {
        Some(code) => write!(f, "{code}"),
        None => f.write_str("none"),
    }
}

#[derive(Debug)]
struct CompilerFailure {
    operation: CompilerOperation,
    original: io::Error,
}

impl fmt::Display for CompilerFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (stage, role) = self.operation.labels();
        write!(f, "{stage} [{role}]: {}", self.original)
    }
}

impl std::error::Error for CompilerFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

#[derive(Debug)]
struct SecondaryContext {
    original: io::Error,
    detail: String,
}

impl fmt::Display for SecondaryContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}; {}", self.original, self.detail)
    }
}

impl std::error::Error for SecondaryContext {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

pub fn with_secondary(original: io::Error, detail: String) -> io::Error {
    io::Error::new(original.kind(), SecondaryContext { original, detail })
}

#[derive(Clone, Copy, Debug)]
pub enum ConsoleApi {
    ProcessListBefore,
    Allocate,
    ProcessListAfter,
    Free,
}

impl ConsoleApi {
    pub fn label(self) -> &'static str {
        match self {
            Self::ProcessListBefore => "GetConsoleProcessList-before",
            Self::Allocate => "AllocConsole",
            Self::ProcessListAfter => "GetConsoleProcessList-after",
            Self::Free => "FreeConsole",
        }
    }
}

#[derive(Debug)]
struct ConsoleFailure(ConsoleApi, io::Error);

impl fmt::Display for ConsoleFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}; console-api={}", self.1, self.0.label())
    }
}

impl std::error::Error for ConsoleFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.1)
    }
}

pub fn console_error(api: ConsoleApi, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), ConsoleFailure(api, error))
}

pub fn console_failure_detail(error: &io::Error) -> Option<(&'static str, Option<i32>)> {
    let failure = error.get_ref()?.downcast_ref::<ConsoleFailure>()?;
    Some((failure.0.label(), failure.1.raw_os_error()))
}

fn compiler_failure(original: &io::Error) -> Option<&CompilerFailure> {
    let mut cause: &(dyn std::error::Error + 'static) = original;
    for _ in 0..8 {
        if let Some(failure) = cause.downcast_ref::<CompilerFailure>() {
            return Some(failure);
        }
        cause = match cause.downcast_ref::<io::Error>() {
            Some(error) => error.get_ref()?,
            None => cause.source()?,
        };
    }
    None
}

pub fn compiler_context<T>(operation: CompilerOperation, result: io::Result<T>) -> io::Result<T> {
    result.map_err(|original| compiler_error(operation, original))
}

pub fn compiler_error(operation: CompilerOperation, original: io::Error) -> io::Error {
    io::Error::new(
        original.kind(),
        CompilerFailure {
            operation,
            original,
        },
    )
}

impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

fn original_code(original: &io::Error) -> Option<i32> {
    let mut cause: &(dyn std::error::Error + 'static) = original;
    for _ in 0..8 {
        if let Some(code) = cause
            .downcast_ref::<io::Error>()
            .and_then(io::Error::raw_os_error)
        {
            return Some(code);
        }
        cause = cause.source()?;
    }
    None
}

pub fn wrap(operation: Operation, original: io::Error) -> io::Error {
    io::Error::new(
        original.kind(),
        Failure {
            operation,
            original,
        },
    )
}

pub fn context<T>(operation: Operation, result: io::Result<T>) -> io::Result<T> {
    result.map_err(|original| wrap(operation, original))
}
