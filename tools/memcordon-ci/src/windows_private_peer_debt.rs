//! Negative release barriers; native process owners supply retirement proof.
use memcordon_platform::test_support::ProcessIdentity;

#[derive(Default)]
pub struct PeerDebt {
    spawn_uncertain: bool,
    admitted: Option<ProcessIdentity>,
    metadata_started: bool,
    admission_started: bool,
    metadata_references: u32,
}

impl PeerDebt {
    pub fn note_spawn(&mut self) {
        if self.admitted.is_none() {
            self.spawn_uncertain = true;
        }
    }
    pub fn mark_unknown(&mut self) {
        self.spawn_uncertain = true;
    }
    pub fn begin_admission(&mut self) -> Result<(), String> {
        self.mark_unknown();
        if self.admission_started {
            return Err("private peer admission cannot retry".into());
        }
        self.admission_started = true;
        Ok(())
    }
    /// Called only after the exact native object has entered the family owner.
    /// This removes uncertainty, and supplies no native exit/cleanup authority.
    pub fn admitted(&mut self, identity: ProcessIdentity) -> Result<(), String> {
        if !self.admission_started
            || identity.pid == 0
            || identity.birth == 0
            || self.admitted.is_some()
        {
            self.mark_unknown();
            return Err("private peer owner admission order differs".into());
        }
        self.admitted = Some(identity);
        self.spawn_uncertain = false;
        Ok(())
    }
    pub fn require_admitted(&mut self, identity: ProcessIdentity) -> Result<(), String> {
        if self.spawn_uncertain || self.admitted != Some(identity) {
            self.mark_unknown();
            return Err("private peer publication lacks prior exact admission".into());
        }
        Ok(())
    }
    pub fn begin_metadata(&mut self) -> Result<(), String> {
        if self.metadata_started {
            return Err("private metadata transfer cannot retry".into());
        }
        self.metadata_started = true;
        Ok(())
    }
    pub fn record_metadata(&mut self, count: u32) {
        self.metadata_references = count;
    }
    pub fn release_barrier(&self) -> Result<(), String> {
        if self.spawn_uncertain {
            Err("private peer spawn/admission uncertainty remains charged".into())
        } else if self.metadata_references as usize
            > memcordon_platform::windows_private_fixture_binding::MAX_DIRECTORY_REFERENCES
        {
            Err("private metadata debt exceeds finite role bound".into())
        } else {
            Ok(())
        }
    }
}
