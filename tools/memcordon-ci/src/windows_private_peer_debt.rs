//! Negative release barriers; native process owners supply retirement proof.
use memcordon_platform::test_support::ProcessIdentity;
use std::time::Instant;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum SpawnState {
    #[default]
    NoGrant,
    Writing([u8; 32]),
    Granted([u8; 32]),
    Admitting,
    Admitted(ProcessIdentity),
    JobRetired,
    Poisoned,
}

#[derive(Default)]
pub struct PeerDebt {
    spawn: SpawnState,
    metadata_started: bool,
    metadata_references: u32,
}

impl PeerDebt {
    pub fn begin_grant(&mut self, grant: [u8; 32]) -> Result<(), String> {
        if self.spawn != SpawnState::NoGrant {
            self.mark_unknown();
            return Err("private peer spawn authorization cannot retry".into());
        }
        self.spawn = SpawnState::Writing(grant);
        Ok(())
    }
    pub fn complete_grant(
        &mut self,
        grant: [u8; 32],
        completed: Instant,
        cutoff: Instant,
    ) -> Result<(), String> {
        if self.spawn != SpawnState::Writing(grant) || completed >= cutoff {
            self.mark_unknown();
            return Err(
                "private peer spawn authorization was late or differed from the original send"
                    .into(),
            );
        }
        self.spawn = SpawnState::Granted(grant);
        Ok(())
    }
    pub fn require_unadmitted_grant(&self, grant: [u8; 32]) -> Result<(), String> {
        if self.spawn != SpawnState::Granted(grant) {
            return Err("private peer grant is absent, ambiguous, or followed by admission".into());
        }
        Ok(())
    }
    /// The caller validates the original native Job and checks all retained owners.
    pub fn settle_extinct_job(&mut self, grant: [u8; 32]) -> Result<(), String> {
        if let Err(error) = self.require_unadmitted_grant(grant) {
            self.mark_unknown();
            return Err(error);
        }
        self.spawn = SpawnState::JobRetired;
        Ok(())
    }
    pub fn mark_unknown(&mut self) {
        self.spawn = SpawnState::Poisoned;
    }
    pub fn begin_admission(&mut self) -> Result<(), String> {
        if !matches!(self.spawn, SpawnState::Granted(_)) {
            self.mark_unknown();
            return Err("private peer admission requires one completed grant".into());
        }
        self.spawn = SpawnState::Admitting;
        Ok(())
    }
    /// Called only after the exact native object has entered the family owner.
    /// This removes uncertainty, and supplies no native exit/cleanup authority.
    pub fn admitted(&mut self, identity: ProcessIdentity) -> Result<(), String> {
        if self.spawn != SpawnState::Admitting || identity.pid == 0 || identity.birth == 0 {
            self.mark_unknown();
            return Err("private peer owner admission order differs".into());
        }
        self.spawn = SpawnState::Admitted(identity);
        Ok(())
    }
    pub fn require_admitted(&mut self, identity: ProcessIdentity) -> Result<(), String> {
        if self.spawn != SpawnState::Admitted(identity) {
            self.mark_unknown();
            return Err("private peer publication lacks prior exact admission".into());
        }
        Ok(())
    }
    pub fn begin_metadata(&mut self) -> Result<(), String> {
        if self.metadata_started || self.spawn != SpawnState::NoGrant {
            self.mark_unknown();
            return Err("private metadata transfer cannot retry".into());
        }
        self.metadata_started = true;
        Ok(())
    }
    pub fn record_metadata(&mut self, count: u32) {
        self.metadata_references = count;
    }
    pub fn release_barrier(&self) -> Result<(), String> {
        if !matches!(
            self.spawn,
            SpawnState::NoGrant | SpawnState::Admitted(_) | SpawnState::JobRetired
        ) {
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
