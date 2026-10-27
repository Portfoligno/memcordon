//! Diagnostic trigger hints. Native held owners remain the sole sampling authority.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::io;

pub const RECORD_BOUND: usize = 128 * 1024;
pub const MEMBER_BOUND: usize = 64;
pub const OPERATION_PARAMETER_BOUND: usize = 1024;
const OPERATION_CAUSE_BOUND: usize = 512;

struct OperationError {
    operation: &'static str,
    parameters: String,
    cause_text: String,
    original: io::Error,
}

fn bounded_error_cause(cause: &io::Error) -> String {
    struct Prefix(String);
    impl std::fmt::Write for Prefix {
        fn write_str(&mut self, text: &str) -> std::fmt::Result {
            let mut end = (OPERATION_CAUSE_BOUND - self.0.len()).min(text.len());
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            self.0.push_str(&text[..end]);
            if end != text.len() {
                Err(std::fmt::Error)
            } else {
                Ok(())
            }
        }
    }
    let mut prefix = Prefix(String::with_capacity(OPERATION_CAUSE_BOUND));
    if std::fmt::write(&mut prefix, format_args!("{cause}")).is_err() {
        prefix
            .0
            .push_str(" [cause-format-incomplete; omitted-bytes=unknown]");
    }
    prefix.0
}

fn bounded_error_text(text: &str, bound: usize) -> String {
    let end = text
        .char_indices()
        .map(|(start, ch)| start + ch.len_utf8())
        .take_while(|end| *end <= bound)
        .last()
        .unwrap_or(0);
    if end == text.len() {
        text.to_owned()
    } else {
        format!("{} [omitted-bytes={}]", &text[..end], text.len() - end)
    }
}

impl std::fmt::Display for OperationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "operation={}; kind={:?}; raw-os-error={:?}; {}; cause={}",
            self.operation,
            self.original.kind(),
            self.original.raw_os_error(),
            self.parameters,
            self.cause_text
        )
    }
}

impl std::fmt::Debug for OperationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for OperationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

/// Add bounded failure-only context while retaining the original native cause.
pub fn operation_error(
    operation: &'static str,
    parameters: String,
    original: io::Error,
) -> io::Error {
    io::Error::new(
        original.kind(),
        OperationError {
            operation,
            parameters: bounded_error_text(&parameters, OPERATION_PARAMETER_BOUND),
            cause_text: bounded_error_cause(&original),
            original,
        },
    )
}

/// Successful ordinary-file rename sets ARCHIVE (MS-FSA FileRenameInformation).
/// Every other field remains bound to the independently verified prepared file.
pub fn published_identity(
    prepared: (u32, u64, u32, u32, u64),
) -> io::Result<(u32, u64, u32, u32, u64)> {
    const NORMAL: u32 = 0x80;
    const ARCHIVE: u32 = 0x20;
    if prepared.2 != NORMAL || prepared.3 != 1 {
        return Err(io::Error::other(
            "helper diagnostic prepared attributes/link differ",
        ));
    }
    Ok((prepared.0, prepared.1, ARCHIVE, prepared.3, prepared.4))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Identity {
    pub pid: u32,
    pub birth: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Survivor {
    pub identity: Identity,
    pub parent: Identity,
    pub image_sha256: String,
}

#[derive(Clone, Debug)]
pub struct Hint {
    pub compiler: Identity,
    pub binding: Value,
    pub sequence: u64,
    pub survivors: Vec<Survivor>,
}

pub fn binding_fixture(hint: &Hint) -> io::Result<Identity> {
    identity(&hint.binding["parent"])
}

fn invalid() -> io::Error {
    io::Error::other("compiler helper diagnostic hint association differs")
}

fn identity(value: &Value) -> io::Result<Identity> {
    let pid = value["process_id"]
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid != 0)
        .ok_or_else(invalid)?;
    let birth = value["creation_time_100ns"]
        .as_u64()
        .filter(|birth| *birth != 0)
        .ok_or_else(invalid)?;
    Ok(Identity {
        pid,
        birth: u128::from(birth),
    })
}

/// Ordinary completed compilers and snapshots spanning two transitions are
/// not sampling failures. They must not disable a later compiler round.
pub fn candidate(phase: &Value, debug: &Value) -> io::Result<Option<(Identity, u64)>> {
    let state = &debug["state"];
    let compiler = identity(&debug["binding"]["original_child"])?;
    if state["last_event"]["kind"] != "exit-process"
        || state["last_event"]["pid"].as_u64() != Some(u64::from(compiler.pid))
        || state.get("pending_event") != Some(&Value::Null)
        || state["active"]["active_count"] == 0
        || state["active"]["members"]
            .as_array()
            .is_some_and(Vec::is_empty)
        || phase["binding"] != debug["binding"]
    {
        return Ok(None);
    }
    let sequence = debug["transition_sequence"].as_u64().ok_or_else(invalid)?;
    if phase["transition_sequence"]
        .as_u64()
        .is_none_or(|phase| phase >= sequence)
    {
        return Ok(None);
    }
    Ok(Some((compiler, sequence)))
}

pub fn hint(
    phase: &Value,
    debug: &Value,
    challenge: &[u8],
    fixture: Identity,
    clock: (u64, u64),
    images: &BTreeSet<String>,
) -> io::Result<Hint> {
    for record in [phase, debug] {
        if record["format"] != "memcordon.windows-toolchain-current-state"
            || record["revision"] != 1
            || record["diagnostic_only"] != true
            || record["transition_snapshot_not_live_probe"] != true
        {
            return Err(invalid());
        }
    }
    let binding = &debug["binding"];
    let sequence = debug["transition_sequence"]
        .as_u64()
        .filter(|sequence| *sequence != 0)
        .ok_or_else(invalid)?;
    let phase_sequence = phase["transition_sequence"]
        .as_u64()
        .filter(|sequence| *sequence != 0)
        .ok_or_else(invalid)?;
    let selected = binding["selected_image_sha256"]
        .as_str()
        .ok_or_else(invalid)?;
    if binding != &phase["binding"]
        || sequence <= phase_sequence
        || binding["challenge"] != serde_json::json!(challenge)
        || identity(&binding["parent"])? != fixture
        || binding["native_work_cutoff_ticks"].as_u64() != Some(clock.0)
        || binding["native_work_frequency"].as_u64() != Some(clock.1)
        || clock.0 == 0
        || clock.1 == 0
        || !images.contains(selected)
        || binding["role"]
            .as_str()
            .is_none_or(|role| role.is_empty() || role.len() > 128)
        || debug["phase"] != "before-debug-wait"
    {
        return Err(invalid());
    }
    let compiler = identity(&binding["original_child"])?;
    let state = &debug["state"];
    let active = &state["active"];
    let members = active["members"].as_array().ok_or_else(invalid)?;
    if compiler == fixture
        || state["original_child_pid"].as_u64() != Some(u64::from(compiler.pid))
        || state["last_event"]["kind"] != "exit-process"
        || state["last_event"]["pid"].as_u64() != Some(u64::from(compiler.pid))
        || state.get("pending_event") != Some(&Value::Null)
        || state["continued"] != true
        || active["complete"] != true
        || active["omitted_count"] != 0
        || active["active_count"].as_u64() != Some(members.len() as u64)
        || members.is_empty()
        || members.len() > MEMBER_BOUND
    {
        return Err(invalid());
    }
    let mut seen = BTreeSet::new();
    let mut survivors = Vec::new();
    for member in members {
        let parse = |pid: &str, birth: &str| -> io::Result<Identity> {
            identity(
                &serde_json::json!({"process_id":member[pid],"creation_time_100ns":member[birth]}),
            )
        };
        let identity = parse("pid", "birth")?;
        let parent = parse("parent_pid", "parent_birth")?;
        let image = member["image_sha256"].as_str().ok_or_else(invalid)?;
        if identity == compiler
            || identity == fixture
            || identity == parent
            || !seen.insert(identity)
            || !images.contains(image)
            || member["held_process_owner"] != true
            || member["image_observation"] != "creation-event-owned-file"
        {
            return Err(invalid());
        }
        survivors.push(Survivor {
            identity,
            parent,
            image_sha256: image.to_owned(),
        });
    }
    survivors.sort_by_key(|survivor| survivor.identity);
    Ok(Hint {
        compiler,
        binding: binding.clone(),
        sequence,
        survivors,
    })
}

pub fn encode(hint: &Hint, samples: &[Value], second_pass: bool) -> io::Result<Vec<u8>> {
    let value = serde_json::json!({"format":"memcordon.windows-held-compiler-helper-activity","revision":1,
        "diagnostic_only":true,"compiler_acceptance":false,"wait_reason_known":false,
        "unchanged_counters_do_not_prove_deadlock":true,"wct_invoked":false,
        "wct_blocker":"session close has no documented finite timeout; effective privilege is query-only evidence",
        "trigger_binding":hint.binding,"trigger_sequence":hint.sequence,
        "second_pass_attempted":second_pass,"samples":samples,
        "sampled_survivors":samples.len(),"omitted_survivors":hint.survivors.len().saturating_sub(samples.len()),
        "survivor_inventory_complete":samples.len()==hint.survivors.len()});
    let bytes = serde_json::to_vec(&value).map_err(io::Error::other)?;
    if samples.len() > MEMBER_BOUND || bytes.len() > RECORD_BOUND {
        return Err(io::Error::other(
            "held helper activity diagnostic exceeds finite bound",
        ));
    }
    Ok(bytes)
}

#[cfg(windows)]
pub fn live(deadline: std::time::Instant) -> io::Result<()> {
    if std::time::Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original helper diagnostic cutoff exhausted",
        ))
    } else {
        Ok(())
    }
}

#[cfg(windows)]
pub fn encode_until(
    hint: &Hint,
    samples: &[Value],
    second: bool,
    deadline: std::time::Instant,
) -> io::Result<Vec<u8>> {
    live(deadline)?;
    let bytes = encode(hint, samples, second)?;
    live(deadline)?;
    Ok(bytes)
}

#[cfg(windows)]
pub fn publish(
    directory: &std::path::Path,
    path: &std::path::Path,
    bytes: &[u8],
    deadline: std::time::Instant,
) -> io::Result<std::fs::File> {
    use std::io::{Read, Write};
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::*;
    live(deadline)?;
    if bytes.len() > RECORD_BOUND || path.parent() != Some(directory) {
        return Err(io::Error::other(
            "helper diagnostic publication path/bound differs",
        ));
    }
    let identity =
        |file: &std::fs::File, is_directory: bool| -> io::Result<(u32, u64, u32, u32, u64)> {
            let info = memcordon_testkit::windows_held_file_metadata(file).map_err(|error| {
                operation_error(
                    "GetFileInformationByHandle",
                    format!("expected-directory={is_directory}"),
                    error,
                )
            })?;
            if info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || (info.attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != is_directory
                || (!is_directory && info.links != 1)
            {
                return Err(io::Error::other(
                    "helper diagnostic native file type/link differs",
                ));
            }
            Ok((
                info.volume_serial,
                info.file_index,
                info.attributes,
                info.links,
                info.length,
            ))
        };
    let parent = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(directory)
        .map_err(|error| {
            operation_error(
                "open-publication-parent",
                "access=read; share=read|write; backup-semantics=true; open-reparse-point=true"
                    .into(),
                error,
            )
        })?;
    let parent_identity = identity(&parent, true)
        .map_err(|error| operation_error("query-publication-parent", String::new(), error))?;
    live(deadline)?;
    let mut staged = tempfile::NamedTempFile::new_in(directory).map_err(|error| {
        operation_error(
            "create-publication-stage",
            format!("parent={parent_identity:?}"),
            error,
        )
    })?;
    live(deadline)?;
    staged.write_all(bytes).map_err(|error| {
        operation_error(
            "write-publication-stage",
            format!("bytes={}", bytes.len()),
            error,
        )
    })?;
    live(deadline)?;
    staged.as_file().sync_all().map_err(|error| {
        operation_error(
            "sync-publication-stage",
            format!("bytes={}", bytes.len()),
            error,
        )
    })?;
    let written = identity(staged.as_file(), false)
        .map_err(|error| operation_error("query-written-stage", String::new(), error))?;
    live(deadline)?;
    let mut check = Vec::new();
    let mut staged_readback = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(staged.path())
        .map_err(|error| {
            operation_error(
                "open-staged-readback",
                format!("written={written:?}; access=read; share=read|write|delete"),
                error,
            )
        })?;
    if identity(&staged_readback, false).map_err(|error| {
        operation_error(
            "query-staged-readback",
            format!("written={written:?}"),
            error,
        )
    })? != written
    {
        return Err(io::Error::other(
            "staged helper diagnostic named identity differs",
        ));
    }
    // Retain the same object while closing its last data-writing handle.
    let mut staged_path = staged.into_temp_path();
    live(deadline)?;
    let rename_owner = memcordon_testkit::windows_open_synchronous_rename_source(
        &parent,
        staged_path
            .file_name()
            .ok_or_else(|| io::Error::other("helper diagnostic stage filename missing"))?,
        &staged_readback,
        deadline,
    )?;
    let rename_identity = identity(rename_owner.as_file(), false).map_err(|error| {
        operation_error("query-rename-source", format!("written={written:?}"), error)
    })?;
    if (
        rename_identity.0,
        rename_identity.1,
        rename_identity.3,
        rename_identity.4,
    ) != (written.0, written.1, written.3, written.4)
    {
        return Err(io::Error::other(
            "helper diagnostic rename source identity differs",
        ));
    }
    memcordon_testkit::windows_prepare_persistent_stage(rename_owner.as_file(), deadline).map_err(
        |error| {
            operation_error(
                "prepare-rename-source",
                format!("source={rename_identity:?}; parent={parent_identity:?}"),
                error,
            )
        },
    )?;
    let expected = identity(rename_owner.as_file(), false).map_err(|error| {
        operation_error(
            "query-prepared-source",
            format!("source={rename_identity:?}"),
            error,
        )
    })?;
    let published = published_identity(expected)?;
    if identity(&staged_readback, false).map_err(|error| {
        operation_error(
            "query-prepared-readback",
            format!("expected={expected:?}"),
            error,
        )
    })? != expected
    {
        return Err(io::Error::other(
            "helper diagnostic prepared source identity differs",
        ));
    }
    std::io::Read::by_ref(&mut staged_readback)
        .take(RECORD_BOUND as u64 + 1)
        .read_to_end(&mut check)
        .map_err(|error| {
            operation_error(
                "read-staged-readback",
                format!("expected={expected:?}"),
                error,
            )
        })?;
    if check != bytes {
        return Err(io::Error::other(
            "staged helper diagnostic readback differs",
        ));
    }
    live(deadline)?;
    if identity(&parent, true).map_err(|error| {
        operation_error(
            "query-parent-before-rename",
            format!("expected={parent_identity:?}"),
            error,
        )
    })? != parent_identity
    {
        return Err(io::Error::other(
            "helper diagnostic rename parent identity differs",
        ));
    }
    let committed = rename_owner.rename(
        path.file_name()
            .ok_or_else(|| io::Error::other("helper diagnostic filename missing"))?,
        deadline,
    )?;
    // Native success moved the name. Disarm cleanup before ANY fallible check:
    // the old temporary name could otherwise be reused by an unrelated file.
    staged_path.disable_cleanup(true);
    committed.verify(deadline)?;
    drop(rename_owner);
    live(deadline)?;
    let mut named = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| {
            operation_error(
                "open-published-readback",
                format!("expected={published:?}; access=read; share=read|delete"),
                error,
            )
        })?;
    let actual = identity(&named, false).map_err(|error| {
        operation_error(
            "query-published-readback",
            format!("expected={published:?}"),
            error,
        )
    })?;
    live(deadline)?;
    check.clear();
    std::io::Read::by_ref(&mut named)
        .take(RECORD_BOUND as u64 + 1)
        .read_to_end(&mut check)
        .map_err(|error| {
            operation_error(
                "read-published-readback",
                format!("expected={published:?}"),
                error,
            )
        })?;
    let held_after = identity(&named, false).map_err(|error| {
        operation_error(
            "query-final-held-readback",
            format!("expected={published:?}"),
            error,
        )
    })?;
    let retained_stage_after = identity(&staged_readback, false).map_err(|error| {
        operation_error(
            "query-retained-stage-after-rename",
            format!("expected={published:?}"),
            error,
        )
    })?;
    let parent_after = identity(&parent, true).map_err(|error| {
        operation_error(
            "query-parent-after-rename",
            format!("expected={parent_identity:?}"),
            error,
        )
    })?;
    let bytes_equal = check == bytes;
    if published != actual
        || held_after != actual
        || retained_stage_after != published
        || !bytes_equal
        || parent_after != parent_identity
    {
        return Err(io::Error::other(format!(
            "helper diagnostic atomic named custody/readback differs; prepared={expected:?}; expected-published={published:?}; named={actual:?}; held-after={held_after:?}; retained-stage-after={retained_stage_after:?}; bytes-equal={bytes_equal}; parent-before={parent_identity:?}; parent-after={parent_after:?}"
        )));
    }
    live(deadline)?;
    drop(staged_readback);
    Ok(named)
}
