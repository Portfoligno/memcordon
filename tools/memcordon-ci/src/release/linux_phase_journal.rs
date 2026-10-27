//! Read-only journal probes; a superseded generation never authorizes action.
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
    time::Instant,
};

const BOUND: u64 = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Stamp {
    pub device: u64,
    pub inode: u64,
    pub length: u64,
    pub links: u64,
    pub uid: u32,
    pub mode: u32,
    pub ctime: i64,
    pub ctime_ns: i64,
    pub mtime: i64,
    pub mtime_ns: i64,
}
impl Stamp {
    fn get(file: &File) -> Result<Self, String> {
        let m = file.metadata().map_err(|e| e.to_string())?;
        Ok(Self {
            device: m.dev(),
            inode: m.ino(),
            length: m.len(),
            links: m.nlink(),
            uid: m.uid(),
            mode: m.mode(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
        })
    }
    fn protected(&self, uid: u32) -> bool {
        self.uid == uid
            && self.mode & 0o177777 == 0o100600
            && self.links == 1
            && self.length <= BOUND
    }
    fn protected_unlinked(&self, uid: u32) -> bool {
        self.uid == uid
            && self.mode & 0o177777 == 0o100600
            && self.links == 0
            && self.length <= BOUND
    }
    fn unlinked_from(&self, before: &Self) -> bool {
        if before.links == 0 {
            return self == before;
        }
        self.device == before.device
            && self.inode == before.inode
            && self.length == before.length
            && self.uid == before.uid
            && self.mode == before.mode
            && self.links == 0
            && before.links == 1
            && self.mtime == before.mtime
            && self.mtime_ns == before.mtime_ns
    }
}

pub struct Snapshot {
    pub bytes: Vec<u8>,
    pub record: Value,
    pub held: File,
}
pub enum Capture {
    Stable(Snapshot),
    GenerationAdvanced {
        before: Stamp,
        held: Stamp,
        named: Stamp,
        association: Value,
    },
    Deadline {
        stage: &'static str,
        before: Option<Stamp>,
        held: Option<Stamp>,
        named: Option<Stamp>,
    },
    Fatal {
        stage: &'static str,
        error: String,
        before: Option<Stamp>,
        held: Option<Stamp>,
        named: Option<Stamp>,
    },
}
impl Capture {
    pub fn diagnostic(&self) -> Value {
        match self {
            Self::Stable(_) => json!({"outcome":"stable","diagnostic_only":true}),
            Self::GenerationAdvanced {
                before,
                held,
                named,
                ..
            } => {
                json!({"outcome":"authenticated-generation-advance","before":before,"held":held,"named":named,"diagnostic_only":true})
            }
            Self::Deadline {
                stage,
                before,
                held,
                named,
            } => {
                json!({"outcome":"original-deadline","stage":stage,"before":before,"held":held,"named":named,"diagnostic_only":true})
            }
            Self::Fatal {
                stage,
                error,
                before,
                held,
                named,
            } => {
                json!({"outcome":"fatal","stage":stage,"error":error,"before":before,"held":held,"named":named,"diagnostic_only":true})
            }
        }
    }
}

pub fn decode(bytes: &[u8], attempt: &str) -> Result<Value, String> {
    if bytes.is_empty() || bytes.len() as u64 > BOUND {
        return Err("phase journal extent differs".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
    let (body, digest) = text
        .rsplit_once("digest=")
        .ok_or("phase journal checksum absent")?;
    if digest != format!("{}\n", super::artifacts::checksum(body.as_bytes())) {
        return Err("phase journal checksum differs".into());
    }
    let mut lines = body.lines();
    if lines.next() != Some("format=memcordon.private-native-journal")
        || lines.next() != Some("revision=1")
        || lines.next().and_then(|line| line.strip_prefix("cgroup=")) != Some(attempt)
    {
        return Err("phase journal envelope differs".into());
    }
    let payload = lines
        .next()
        .and_then(|line| line.strip_prefix("payload="))
        .ok_or("phase journal payload absent")?;
    if lines.next().is_some() {
        return Err("phase journal extra envelope fields".into());
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(payload.as_bytes())?;
    let record: Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
    if record["attempt_id"] != attempt {
        return Err("phase journal original attempt differs".into());
    }
    Ok(record)
}

fn same_association(old: &Value, new: &Value) -> Result<(), String> {
    for name in [
        "attempt_id",
        "boot_identity",
        "frontend",
        "caller_envelope_digest",
        "admission_metadata",
        "mixed_admission_metadata",
        "binding",
        "mixed_worker",
        "mixed_control",
    ] {
        if old[name] != new[name] {
            return Err(format!(
                "phase journal immutable association changed: {name}"
            ));
        }
    }
    for actor in ["frontend", "mixed_worker"] {
        if actor == "mixed_worker" && old[actor].is_null() {
            continue;
        }
        if old[actor]["pid"]
            .as_u64()
            .is_none_or(|pid| pid == 0 || pid > i32::MAX as u64)
            || old[actor]["start_time"]
                .as_u64()
                .is_none_or(|birth| birth == 0)
        {
            return Err(format!("phase journal original actor absent: {actor}"));
        }
    }
    if old["boot_identity"].as_str().is_none_or(str::is_empty)
        || old["caller_envelope_digest"].is_null()
    {
        return Err("phase journal immutable admission association absent".into());
    }
    // These facts may first appear as native preparation progresses, but an
    // already observed ownership fact cannot be replaced or removed.
    for name in [
        "guardian",
        "namespace_init",
        "target",
        "network_namespace_inode",
        "mixed_cgroup_identity",
        "mixed_staging_identity",
        "mixed_root_staging_intent",
        "mixed_export_intent",
        "mixed_export_identity",
    ] {
        if !old[name].is_null() && old[name] != new[name] {
            return Err(format!("phase journal retained ownership changed: {name}"));
        }
    }
    Ok(())
}

fn open(parent: &File, attempt: &str) -> Result<File, String> {
    rustix::fs::openat(
        parent,
        attempt,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|e| e.to_string())
}
fn read(file: &mut File) -> Result<Vec<u8>, String> {
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    Read::by_ref(file)
        .take(BOUND + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    Ok(bytes)
}

pub fn capture(
    parent: &File,
    attempt: &str,
    uid: u32,
    expected: Option<&Value>,
    deadline: Instant,
) -> Capture {
    capture_checked(parent, attempt, uid, expected, deadline, || Ok(()))
}

pub fn capture_checked(
    parent: &File,
    attempt: &str,
    uid: u32,
    expected: Option<&Value>,
    deadline: Instant,
    after_read: impl FnOnce() -> Result<(), String>,
) -> Capture {
    capture_with_hooks(
        parent,
        attempt,
        uid,
        expected,
        deadline,
        || Ok(()),
        after_read,
    )
}

pub fn capture_with_hooks(
    parent: &File,
    attempt: &str,
    uid: u32,
    expected: Option<&Value>,
    deadline: Instant,
    before_metadata: impl FnOnce() -> Result<(), String>,
    after_read: impl FnOnce() -> Result<(), String>,
) -> Capture {
    if Instant::now() >= deadline {
        return Capture::Deadline {
            stage: "initial",
            before: None,
            held: None,
            named: None,
        };
    }
    let mut stage = "initial";
    let (mut before, mut held, mut named) = (None, None, None);
    let mut association = None;
    let probe = (|| -> Result<Option<Snapshot>, String> {
        if attempt.len() != 32
            || !attempt
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("phase journal attempt invalid".into());
        }
        let parent_before = parent.metadata().map_err(|e| e.to_string())?;
        if !parent_before.is_dir()
            || parent_before.uid() != uid
            || parent_before.mode() & 0o022 != 0
            || parent_before.nlink() == 0
        {
            return Err("phase journal held parent custody differs".into());
        }
        stage = "open-held-generation";
        let mut file = open(parent, attempt)?;
        before_metadata()?;
        before = Some(Stamp::get(&file)?);
        if !before.as_ref().unwrap().protected(uid)
            && !before.as_ref().unwrap().protected_unlinked(uid)
        {
            return Err("phase journal held custody differs".into());
        }
        stage = "decode-held-generation";
        let bytes = read(&mut file)?;
        let record = decode(&bytes, attempt)?;
        same_association(&record, &record)?;
        if let Some(expected) = expected {
            same_association(expected, &record)?;
        }
        after_read()?;
        stage = "recheck-generation";
        held = Some(Stamp::get(&file)?);
        let mut current = open(parent, attempt)?;
        named = Some(Stamp::get(&current)?);
        let old = before.as_ref().unwrap();
        let pinned = held.as_ref().unwrap();
        let current_stamp = named.as_ref().unwrap();
        if !current_stamp.protected(uid) {
            return Err("phase journal named custody differs".into());
        }
        let parent_after = parent.metadata().map_err(|e| e.to_string())?;
        if (
            parent_before.dev(),
            parent_before.ino(),
            parent_before.uid(),
            parent_before.mode(),
            parent_before.nlink(),
        ) != (
            parent_after.dev(),
            parent_after.ino(),
            parent_after.uid(),
            parent_after.mode(),
            parent_after.nlink(),
        ) {
            return Err("phase journal held parent changed".into());
        }
        if old == pinned && pinned == current_stamp {
            return Ok(Some(Snapshot {
                bytes,
                record,
                held: file,
            }));
        }
        if old.device == current_stamp.device && old.inode == current_stamp.inode {
            return Err("phase journal in-place mutation".into());
        }
        if !pinned.unlinked_from(old) || read(&mut file)? != bytes || Stamp::get(&file)? != *pinned
        {
            return Err("phase journal superseded inode mutated beyond unlink".into());
        }
        stage = "authenticate-replacement";
        let replacement = read(&mut current)?;
        let replacement_record = decode(&replacement, attempt)?;
        same_association(&record, &replacement_record)?;
        if let Some(expected) = expected {
            same_association(expected, &replacement_record)?;
        }
        association = Some(replacement_record);
        let replacement_after = Stamp::get(&current)?;
        if replacement_after != *current_stamp {
            return Err("phase journal replacement changed during proof".into());
        }
        let final_named = open(parent, attempt)?;
        if Stamp::get(&final_named)? != replacement_after {
            return Err("phase journal replacement advanced during proof".into());
        }
        // The replacement was authenticated, but it is NOT selected: the
        // caller must reobserve and validate a stable generation.
        Ok(None)
    })();
    match probe {
        Ok(_) if Instant::now() >= deadline => Capture::Deadline {
            stage,
            before,
            held,
            named,
        },
        Ok(Some(snapshot)) => Capture::Stable(snapshot),
        Ok(None) => Capture::GenerationAdvanced {
            before: before.unwrap(),
            held: held.unwrap(),
            named: named.unwrap(),
            association: association.unwrap(),
        },
        Err(error) => Capture::Fatal {
            stage,
            error,
            before,
            held,
            named,
        },
    }
}
