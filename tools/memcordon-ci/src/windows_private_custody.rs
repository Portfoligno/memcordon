//! Original directory guards and exact process owners for one provider attempt.
use crate::windows_private_peer_debt::PeerDebt;
use crate::{CiError, Result, windows_native_files::HeldWindowsArtifact};
use memcordon_platform::{
    test_support::{ProcessIdentity, WindowsImageProcess, WindowsPendingChildProcess},
    windows_private_fixture_binding::{
        DIRECTORY_QUERY_ACCESS, DirectoryReference, DirectoryRole, DirectoryTransfer,
        PrivateFixtureBinding,
    },
};
use std::{
    fs::File,
    path::Path,
    sync::{Arc, Mutex},
    time::Instant,
};

pub(crate) enum LocalInputCustody {
    Directory(Arc<File>),
    File(Arc<HeldWindowsArtifact>),
}
impl LocalInputCustody {
    fn file(&self) -> &File {
        match self {
            Self::Directory(file) => file,
            Self::File(artifact) => artifact.private_file(),
        }
    }
}
pub(crate) struct PrivateFixtureCustody {
    fixture: Arc<HeldWindowsArtifact>,
    local: LocalInputCustody,
    output: Vec<Arc<File>>,
    pub family: Arc<Mutex<Vec<WindowsImageProcess>>>,
    cleanup: Mutex<Vec<Arc<WindowsPendingChildProcess>>>,
    debt: Mutex<PeerDebt>,
    binding: PrivateFixtureBinding,
}

impl PrivateFixtureCustody {
    pub fn new(
        fixture: Arc<HeldWindowsArtifact>,
        local: LocalInputCustody,
        output: Vec<Arc<File>>,
        binding: PrivateFixtureBinding,
    ) -> Self {
        Self {
            fixture,
            local,
            output,
            binding,
            family: Arc::new(Mutex::new(Vec::new())),
            cleanup: Mutex::new(Vec::new()),
            debt: Mutex::new(PeerDebt::default()),
        }
    }
    pub fn binding(&self) -> &PrivateFixtureBinding {
        &self.binding
    }

    pub fn note_spawn_uncertainty(&self) -> Result<()> {
        let mut debt = self
            .debt
            .lock()
            .map_err(|_| CiError::Message("private peer ownership poisoned".into()))?;
        debt.note_spawn();
        Ok(())
    }
    pub fn mark_unknown_spawn(&self) {
        // Recovery can retain/quarantine ownership; it never authorizes release.
        self.debt
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .mark_unknown();
    }

    pub fn duplicate_into(
        &self,
        recipient: &WindowsImageProcess,
        work: Instant,
    ) -> Result<DirectoryTransfer> {
        let expected = self
            .binding
            .directory_expectation()
            .map_err(CiError::Message)?;
        let roles = expected.roles().map_err(CiError::Message)?;
        let sources = self
            .fixture
            .private_ancestor_files()
            .iter()
            .chain(std::iter::once(self.local.file()))
            .chain(self.output.iter().map(Arc::as_ref))
            .collect::<Vec<_>>();
        if roles.len() != sources.len() {
            return Err(CiError::Message(
                "original private metadata source extent differs".into(),
            ));
        }
        {
            let family = self
                .family
                .lock()
                .map_err(|_| CiError::Message("private family ownership poisoned".into()))?;
            if !family
                .iter()
                .any(|held| held.same_object_reference(recipient))
            {
                return Err(CiError::Message(
                    "private metadata recipient is not an original retained object".into(),
                ));
            }
        }
        {
            let mut debt = self
                .debt
                .lock()
                .map_err(|_| CiError::Message("private metadata debt poisoned".into()))?;
            debt.begin_metadata().map_err(CiError::Message)?;
        }
        let mut duplicated = 0;
        let timer = memcordon_platform::WindowsSynchronousIoDeadline::start(work)
            .map_err(std::io::Error::other)?;
        let primary = (|| -> Result<DirectoryTransfer> {
            let mut references = Vec::new();
            for ((role, index), source) in roles.into_iter().zip(sources) {
                let handle = if role == DirectoryRole::LocalMarkerFile {
                    recipient.duplicate_marker_metadata(source, work, &mut duplicated)?
                } else {
                    recipient.duplicate_directory_metadata(source, work, &mut duplicated)?
                };
                references.push(DirectoryReference {
                    role,
                    index,
                    handle,
                    access_mask: DIRECTORY_QUERY_ACCESS,
                });
            }
            let transfer = DirectoryTransfer {
                version: expected.transfer_version(),
                manifest_sha256: expected.manifest_sha256,
                references,
            };
            transfer.validate(&expected).map_err(CiError::Message)?;
            Ok(transfer)
        })();
        self.debt
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record_metadata(duplicated);
        let settled = timer
            .finish()
            .map_err(std::io::Error::other)
            .map_err(CiError::from);
        match (primary, settled) {
            (Err(primary), Err(secondary)) => Err(CiError::LaneFailures {
                primary: Box::new(primary),
                secondary: Box::new(secondary),
            }),
            (Err(primary), Ok(())) => Err(primary),
            (Ok(_), Err(secondary)) => Err(secondary),
            (Ok(transfer), Ok(())) => {
                if Instant::now() >= work {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "original metadata transfer cutoff elapsed after settlement",
                    )
                    .into());
                }
                Ok(transfer)
            }
        }
    }

    pub fn admit_peer(
        &self,
        root: &WindowsImageProcess,
        root_local_handle: u64,
        expected: ProcessIdentity,
        fixture: &Path,
        work: Instant,
    ) -> Result<WindowsImageProcess> {
        self.note_spawn_uncertainty()?;
        {
            let mut debt = self
                .debt
                .lock()
                .map_err(|_| CiError::Message("private peer debt poisoned".into()))?;
            debt.begin_admission().map_err(CiError::Message)?;
        }
        let pending = Arc::new(root.duplicate_pending_child(root_local_handle, work)?);
        // This actual native owner is retained BEFORE any identity/image/token
        // query or post-duplication cutoff can reject admission.
        {
            let locked = self.cleanup.lock();
            let poisoned = locked.is_err();
            let mut cleanup = locked.unwrap_or_else(|poisoned| poisoned.into_inner());
            if !cleanup.is_empty() {
                cleanup.push(pending);
                self.mark_unknown_spawn();
                return Err(CiError::Message(
                    "private pending peer count differs".into(),
                ));
            }
            cleanup.push(Arc::clone(&pending));
            if poisoned {
                self.mark_unknown_spawn();
                return Err(CiError::Message(
                    "private cleanup owner retained after poisoned admission state".into(),
                ));
            }
        }
        let peer = pending.admit(root, expected, fixture, work)?;
        {
            let mut family = self
                .family
                .lock()
                .map_err(|_| CiError::Message("private peer family poisoned".into()))?;
            if family.iter().any(|held| held.identity == peer.identity) {
                self.mark_unknown_spawn();
                return Err(CiError::Message(
                    "private peer identity already charged".into(),
                ));
            }
            family.push(peer.clone());
        }
        let mut debt = self
            .debt
            .lock()
            .map_err(|_| CiError::Message("private peer admission state poisoned".into()))?;
        debt.admitted(peer.identity).map_err(CiError::Message)?;
        Ok(peer)
    }

    pub(crate) fn admit_direct_root(
        &self,
        broker: &WindowsImageProcess,
        broker_local_handle: u64,
        expected: ProcessIdentity,
        selected: &[u8; 32],
        work: Instant,
    ) -> Result<WindowsImageProcess> {
        let pending = Arc::new(broker.duplicate_pending_direct_root(broker_local_handle, work)?);
        {
            let locked = self.cleanup.lock();
            let poisoned = locked.is_err();
            let mut cleanup = locked.unwrap_or_else(|poisoned| poisoned.into_inner());
            let repeated = !cleanup.is_empty();
            cleanup.push(Arc::clone(&pending));
            if poisoned || repeated {
                return Err(CiError::Message(
                    "direct root cleanup owner retained after repeated/poisoned admission".into(),
                ));
            }
        }
        let root = pending.admit_selected_direct_root(
            broker,
            expected,
            self.fixture.private_file(),
            selected,
            work,
        )?;
        let mut family = self
            .family
            .lock()
            .map_err(|_| CiError::Message("direct root family poisoned".into()))?;
        if !family.is_empty() {
            return Err(CiError::Message(
                "direct root requires a fresh independent custody ledger".into(),
            ));
        }
        family.push(root.clone());
        Ok(root)
    }

    pub fn admitted_peer(&self, expected: ProcessIdentity) -> Result<WindowsImageProcess> {
        let mut debt = self
            .debt
            .lock()
            .map_err(|_| CiError::Message("private peer ownership poisoned".into()))?;
        debt.require_admitted(expected).map_err(CiError::Message)?;
        drop(debt);
        let found = self
            .family
            .lock()
            .map_err(|_| CiError::Message("private family ownership poisoned".into()))?
            .iter()
            .find(|process| process.identity == expected)
            .cloned()
            .ok_or_else(|| CiError::Message("admitted private peer object absent".into()));
        if found.is_err() {
            self.mark_unknown_spawn();
        }
        found
    }

    pub fn prove_retired(&self, cleanup: Instant) -> Result<()> {
        self.debt
            .lock()
            .map_err(|_| CiError::Message("private retirement ownership poisoned".into()))?
            .release_barrier()
            .map_err(CiError::Message)?;
        let family = self
            .family
            .lock()
            .map_err(|_| CiError::Message("private retirement family poisoned".into()))?
            .clone();
        if family.is_empty() {
            return Err(CiError::Message(
                "private original root object was not retained".into(),
            ));
        }
        for process in family {
            if Instant::now() >= cleanup || !process.has_exited()? {
                return Err(CiError::Message(
                    "private original family object retirement is unproved".into(),
                ));
            }
        }
        let pending = self
            .cleanup
            .lock()
            .map_err(|_| CiError::Message("private cleanup ownership poisoned".into()))?
            .clone();
        for process in pending {
            if Instant::now() >= cleanup || !process.has_exited()? {
                return Err(CiError::Message(
                    "private cleanup recipient native retirement is unproved".into(),
                ));
            }
        }
        if Instant::now() >= cleanup {
            return Err(CiError::Message(
                "original private retirement cutoff exhausted".into(),
            ));
        }
        Ok(())
    }
}
