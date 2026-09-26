//! Independent root-held objects for the explicitly approved recovery source.
//! Handles remain open across deletion/replacement, preventing inode recycling
//! or path substitution from being represented as the original object.
use crate::private_candidate_producer::PreparedCandidateCaseV1;
use crate::private_candidate_reuse_facts::{ReuseAfterObjectsV1, ReuseHeldObjectsV1};
use crate::private_observer_session::{ObservedGenerationV1, strict_json};
use crate::{CiError, Result};
use memcordon_core::private_reuse_source_v1::*;
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub(crate) struct CandidateReuseLiveV1 {
    pub(crate) directory: PathBuf,
    #[cfg(target_os = "linux")]
    directory_file: std::fs::File,
    #[cfg(target_os = "linux")]
    marker_file: std::fs::File,
    #[cfg(target_os = "linux")]
    record_file: std::fs::File,
    pub(crate) pins: [(u64, u64); 3],
    pub(crate) original_marker: Vec<u8>,
    pub(crate) original_record: Vec<u8>,
    pub(crate) originals: BTreeMap<String, Vec<u8>>,
    pub(crate) helper: Option<crate::private_public_live::HeldPublicTargetSamplesV1>,
}
fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}
#[cfg(target_os = "linux")]
fn open(path: &Path, directory: bool) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(
            libc::O_NOFOLLOW | libc::O_CLOEXEC | if directory { libc::O_DIRECTORY } else { 0 },
        )
        .open(path)?)
}
#[cfg(target_os = "linux")]
fn read(file: &std::fs::File) -> Result<Vec<u8>> {
    use std::io::{Read, Seek};
    let mut held = file.try_clone()?;
    held.rewind()?;
    let mut bytes = Vec::new();
    held.take(128 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > 128 * 1024 {
        return fail("Reuse exact held object byte bound differs");
    }
    Ok(bytes)
}
#[cfg(target_os = "linux")]
fn object(file: &std::fs::File, bytes: &[u8]) -> Result<ReuseSourceObjectV1> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() != bytes.len() as u64
    {
        return fail("Reuse original held file protection differs");
    }
    Ok(ReuseSourceObjectV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode(),
        nlink: metadata.nlink(),
        size: metadata.len(),
        bytes_sha256: hash_bytes(bytes),
    })
}
#[cfg(target_os = "linux")]
impl CandidateReuseLiveV1 {
    pub(crate) fn hold(directory: &Path, marker: &[u8], record: &[u8]) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let directory_file = open(directory, true)?;
        let dm = directory_file.metadata()?;
        if !dm.is_dir() || dm.uid() != 0 || dm.mode() & 0o777 != 0o700 {
            return fail("Reuse original held directory protection differs");
        }
        let marker_file = open(&directory.join("attempt.json.new"), false)?;
        let record_file = open(&directory.join("attempt.json"), false)?;
        let marker_bytes = read(&marker_file)?;
        let record_bytes = read(&record_file)?;
        if marker_bytes != marker || record_bytes != record {
            return fail("Reuse independently held originals differ from first capture");
        }
        let mo = object(&marker_file, &marker_bytes)?;
        let ro = object(&record_file, &record_bytes)?;
        if (mo.device, mo.inode) == (ro.device, ro.inode) {
            return fail("Reuse original marker aliases canonical journal");
        }
        Ok(Self {
            directory: directory.to_owned(),
            directory_file,
            marker_file,
            record_file,
            pins: [
                (dm.dev(), dm.ino()),
                (mo.device, mo.inode),
                (ro.device, ro.inode),
            ],
            original_marker: marker_bytes,
            original_record: record_bytes,
            originals: BTreeMap::new(),
            helper: None,
        })
    }
    pub(crate) fn sample_if_ready(
        &mut self,
        phase: ReuseSourcePhaseV1,
        case: &PreparedCandidateCaseV1,
        generation: &ObservedGenerationV1,
        image: &DiagnosticSha256,
    ) -> Result<bool> {
        use std::io::Write;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        if self.helper.is_some() {
            return Ok(true);
        }
        let (admission_name, gate_name, ack_name) = names(phase);
        if matches!(std::fs::symlink_metadata(self.directory.join(gate_name)),Err(error)if error.kind()==std::io::ErrorKind::NotFound)
        {
            return Ok(false);
        }
        let read_native = |name: &str| {
            crate::private_protected_readback::read_protected_raw_case_file(
                &self.directory.join(name),
            )
        };
        let gate_bytes = read_native(gate_name)?;
        let admission_bytes = read_native(admission_name)?;
        let gate: ReuseSourceGateV1 = strict_json(&gate_bytes, 128 * 1024)?;
        let admission: ReuseSourceAdmissionV1 = strict_json(&admission_bytes, 128 * 1024)?;
        if case.recipe.reuse_source_sha256.as_ref() != Some(&reuse_source_revision_sha256())
            || gate.schema_version != 1
            || gate.phase != phase
            || gate.source_revision_sha256 != reuse_source_revision_sha256()
            || gate.selector != case.selector
            || gate.parent_result_key != case.key
            || gate.challenge != case.challenge
            || gate.admission_sha256 != hash_bytes(&admission_bytes)
            || gate.helper != admission.helper
            || admission.schema_version != 1
            || admission.protocol != "candidate-owned-retirement-recovery-v1"
            || admission.source_revision_sha256 != reuse_source_revision_sha256()
            || admission.phase != phase
            || admission.selector != case.selector
            || admission.parent_result_key != case.key
            || admission.challenge != case.challenge
            || admission.installation_epoch != generation.installation_epoch
            || admission.candidate_manifest_sha256 != generation.installed_manifest_sha256
            || admission.installed_inspection_sha256 != generation.installed_receipt_sha256
            || admission.service_generation_sha256.bytes() == &[0; 32]
            || admission.admission_monotonic_ns == 0
            || gate.observed_monotonic_ns < admission.admission_monotonic_ns
            || (gate.directory_device, gate.directory_inode) != self.pins[0]
        {
            return fail("Reuse actual source gate/admission/generation differs");
        }
        let begin = memcordon_platform::test_support::private_observer_monotonic_ns()?;
        let marker_bytes = read(&self.marker_file)?;
        let record_bytes = read(&self.record_file)?;
        let marker = object(&self.marker_file, &marker_bytes)?;
        let record = object(&self.record_file, &record_bytes)?;
        if marker_bytes != self.original_marker
            || record_bytes != self.original_record
            || marker != gate.marker
            || record != gate.record
            || (marker.device, marker.inode) != self.pins[1]
            || (record.device, record.inode) != self.pins[2]
        {
            return fail("Reuse source gate substitutes original independent objects");
        }
        for (name, pin) in [
            ("attempt.json.new", self.pins[1]),
            ("attempt.json", self.pins[2]),
        ] {
            let reopened = open(&self.directory.join(name), false)?;
            let metadata = reopened.metadata()?;
            if (metadata.dev(), metadata.ino()) != pin {
                return fail("Reuse held/path object substitution before ACK");
            }
        }
        let dm = self.directory_file.metadata()?;
        let reopened = open(&self.directory, true)?;
        let rm = reopened.metadata()?;
        if (dm.dev(), dm.ino()) != self.pins[0] || (rm.dev(), rm.ino()) != self.pins[0] {
            return fail("Reuse original held directory substituted");
        }
        let helper = crate::private_public_live::sample_held_target_raw(
            gate.helper.pid,
            gate.helper.start_time_ticks,
            image,
        )?;
        if helper.begin_monotonic_ns < gate.observed_monotonic_ns {
            return fail("Reuse actual helper sample precedes gate");
        }
        let end = memcordon_platform::test_support::private_observer_monotonic_ns()?;
        let held = ReuseHeldObjectsV1 {
            schema_version: 1,
            directory_device: dm.dev(),
            directory_inode: dm.ino(),
            marker,
            record,
            marker_bytes,
            record_bytes,
            begin_monotonic_ns: begin,
            end_monotonic_ns: end,
        };
        if read_native(gate_name)? != gate_bytes || read_native(admission_name)? != admission_bytes
        {
            return fail("Reuse original gate/admission changed before ACK");
        }
        let ack = serde_json::to_vec(&ReuseSourceAckV1 {
            schema_version: 1,
            source_revision_sha256: reuse_source_revision_sha256(),
            phase,
            parent_result_key: case.key.clone(),
            gate_sha256: hash_bytes(&gate_bytes),
        })?;
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.directory.join(ack_name))?;
        file.write_all(&ack)?;
        file.sync_all()?;
        self.directory_file.sync_all()?;
        self.originals
            .insert("admission.json".into(), admission_bytes);
        self.originals.insert("gate.json".into(), gate_bytes);
        self.originals.insert("ack.json".into(), ack);
        self.originals
            .insert("objects.json".into(), serde_json::to_vec(&held)?);
        self.helper = Some(helper);
        Ok(true)
    }
    pub(crate) fn retain_after(&mut self, phase: ReuseSourcePhaseV1) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let report_name = match phase {
            ReuseSourcePhaseV1::Blocked => "reuse-blocked-source-v1.json",
            ReuseSourcePhaseV1::Recover => "reuse-recovered-source-v1.json",
        };
        let report_bytes = crate::private_protected_readback::read_protected_raw_case_file(
            &self.directory.join(report_name),
        )?;
        let report: ReuseSourceReportV1 = strict_json(&report_bytes, 128 * 1024)?;
        let current = open(&self.directory.join("attempt.json"), false)?;
        let bytes = read(&current)?;
        let object = object(&current, &bytes)?;
        let dm = self.directory_file.metadata()?;
        let after = ReuseAfterObjectsV1 {
            schema_version: 1,
            directory_device: dm.dev(),
            directory_inode: dm.ino(),
            old_marker_nlink: self.marker_file.metadata()?.nlink(),
            old_record_nlink: self.record_file.metadata()?.nlink(),
            current_record: object,
            current_bytes: bytes,
            observed_monotonic_ns: memcordon_platform::test_support::private_observer_monotonic_ns(
            )?,
        };
        if report.phase != phase
            || report.before_bytes != self.original_record
            || report.marker_bytes != self.original_marker
        {
            return fail("Reuse actual source report changes independently held originals");
        }
        self.originals.insert("report.json".into(), report_bytes);
        self.originals
            .insert("after.json".into(), serde_json::to_vec(&after)?);
        Ok(())
    }
}
fn names(phase: ReuseSourcePhaseV1) -> (&'static str, &'static str, &'static str) {
    match phase {
        ReuseSourcePhaseV1::Blocked => (
            "reuse-blocked-admission-v1.json",
            "reuse-blocked-ready-v1.json",
            "reuse-blocked-ready-v1.ack",
        ),
        ReuseSourcePhaseV1::Recover => (
            "reuse-recovery-admission-v1.json",
            "reuse-recovery-ready-v1.json",
            "reuse-recovery-ready-v1.ack",
        ),
    }
}
#[cfg(not(target_os = "linux"))]
impl CandidateReuseLiveV1 {
    pub(crate) fn hold(_directory: &Path, _marker: &[u8], _record: &[u8]) -> Result<Self> {
        fail("Reuse actual held source requires native Linux")
    }
    pub(crate) fn sample_if_ready(
        &mut self,
        _phase: ReuseSourcePhaseV1,
        _case: &PreparedCandidateCaseV1,
        _generation: &ObservedGenerationV1,
        _image: &DiagnosticSha256,
    ) -> Result<bool> {
        fail("Reuse actual held source requires native Linux")
    }
    pub(crate) fn retain_after(&mut self, _phase: ReuseSourcePhaseV1) -> Result<()> {
        fail("Reuse actual held source requires native Linux")
    }
}
