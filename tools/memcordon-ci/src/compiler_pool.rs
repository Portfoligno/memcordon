//! Invocation-owned GNU jobserver; each Cargo root spends one implicit slot.
use crate::{CiError, Result, work_outcome::WriterSettlement};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    sync::{Arc, Mutex},
    time::Instant,
};

#[derive(Debug)]
struct Pool {
    directory: Option<tempfile::TempDir>,
    fifo: File,
    budget: usize,
    parallel: bool,
    returned: Mutex<[bool; 2]>,
    admitted: Mutex<[bool; 2]>,
    started: Instant,
    events: Mutex<(Vec<serde_json::Value>, u64)>,
}

/// A root reservation is donated only after that exact command tree settles.
#[derive(Clone, Debug)]
pub struct CompilerOwner {
    pool: Arc<Pool>,
    ordinal: usize,
}

/// Only successful one-use admission can construct this child protocol value.
pub(crate) struct AdmittedCompilerProtocol {
    makeflags: String,
    _owner: CompilerOwner,
}

impl AdmittedCompilerProtocol {
    pub(crate) fn makeflags(&self) -> &str {
        &self.makeflags
    }
}

pub fn pair(budget: usize, parallel: bool) -> Result<[CompilerOwner; 2]> {
    if !(1..=4).contains(&budget)
        || (parallel && budget < 2)
        || crate::preparation::active_group().is_some_and(|group| budget > group.compiler_jobs())
    {
        return Err(CiError::Message(
            "invalid inherited compiler pool budget".into(),
        ));
    }
    let directory = tempfile::Builder::new()
        .prefix("memcordon-jobserver-")
        .tempdir_in("/tmp")?;
    let path = directory.path().join("tokens");
    nix::unistd::mkfifo(
        &path,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .map_err(|error| CiError::Message(format!("create compiler jobserver: {error}")))?;
    // RDWR does not wait for a peer. CLOEXEC is retained: Cargo opens the named
    // FIFO itself, so rustup receives no ambient descriptor inheritance.
    let mut fifo = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)?;
    let metadata = fifo.metadata()?;
    if !metadata.file_type().is_fifo()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(CiError::Message(
            "compiler jobserver FIFO custody differs".into(),
        ));
    }
    let roots = if parallel { 2 } else { 1 };
    fifo.write_all(&vec![b'+'; budget - roots])?;
    let pool = Arc::new(Pool {
        directory: Some(directory),
        fifo,
        budget,
        parallel,
        returned: Mutex::new([false; 2]),
        admitted: Mutex::new([false; 2]),
        started: Instant::now(),
        events: Mutex::new((Vec::new(), 0)),
    });
    Ok([
        CompilerOwner {
            pool: pool.clone(),
            ordinal: 0,
        },
        CompilerOwner { pool, ordinal: 1 },
    ])
}

impl CompilerOwner {
    pub(crate) fn admit(&self) -> Result<AdmittedCompilerProtocol> {
        let returned = self.pool.returned.lock().expect("compiler reservations");
        let mut admitted = self.pool.admitted.lock().expect("compiler admission");
        if returned[self.ordinal] || admitted[self.ordinal] {
            return Err(CiError::Message(
                "compiler root reservation already admitted or returned".into(),
            ));
        }
        if !self.pool.parallel && (0..2).any(|index| admitted[index] && !returned[index]) {
            return Err(CiError::Message(
                "serial compiler root is still owned".into(),
            ));
        }
        let path = self
            .pool
            .directory
            .as_ref()
            .expect("owned compiler namespace")
            .path()
            .join("tokens");
        let held = self.pool.fifo.metadata()?;
        let named = std::fs::symlink_metadata(&path)?;
        if !named.file_type().is_fifo()
            || named.dev() != held.dev()
            || named.ino() != held.ino()
            || named.uid() != held.uid()
            || named.mode() != held.mode()
            || named.nlink() != 1
        {
            return Err(CiError::Message(
                "compiler jobserver named identity differs".into(),
            ));
        }
        let text = path
            .to_str()
            .filter(|text| !text.chars().any(char::is_whitespace))
            .ok_or_else(|| {
                CiError::Message("compiler jobserver path is not protocol-safe".into())
            })?;
        admitted[self.ordinal] = true;
        self.record("admitted", None);
        Ok(AdmittedCompilerProtocol {
            makeflags: format!("-j --jobserver-auth=fifo:{text}"),
            _owner: self.clone(),
        })
    }

    pub fn settle(&self, writers: WriterSettlement) -> Result<()> {
        if !writers.permits_reading() {
            self.record("writer-settlement-unverified", None);
            return Ok(());
        }
        let mut returned = self.pool.returned.lock().expect("compiler reservations");
        if returned[self.ordinal] {
            return Err(CiError::Message(
                "compiler reservation returned twice".into(),
            ));
        }
        if self.pool.parallel {
            // At most two bytes are donated. No write waits for a consumer.
            if let Err(error) = (&self.pool.fifo).write_all(b"+") {
                self.record("donation-failed", Some(error.to_string()));
                return Err(error.into());
            }
        }
        returned[self.ordinal] = true;
        self.record(
            if self.pool.parallel {
                "settled-and-donated"
            } else {
                "settled-serial-reservation"
            },
            None,
        );
        Ok(())
    }

    fn record(&self, stage: &str, error: Option<String>) {
        let mut events = self.pool.events.lock().expect("compiler pool telemetry");
        if events.0.len() < 16 {
            let event = serde_json::json!({"root":self.ordinal,"stage":stage,"elapsed_micros":self.pool.started.elapsed().as_micros(),"error":error});
            eprintln!("[ci compiler-pool] {event}");
            events.0.push(event);
        } else {
            events.1 = events.1.saturating_add(1);
        }
    }

    pub fn budget(&self) -> usize {
        self.pool.budget
    }

    pub fn diagnostic(&self) -> serde_json::Value {
        let events = self.pool.events.lock().expect("compiler pool telemetry");
        serde_json::json!({"format":"memcordon.owned-cargo-jobserver","revision":1,
            "transport":"private-fifo","aggregate-compiler-budget":self.pool.budget,
            "root-ordinal":self.ordinal,"reserved-implicit-roots":if self.pool.parallel {2} else {1},
            "initial-explicit-tokens":self.pool.budget-if self.pool.parallel {2} else {1},
            "donation":"only after owned command writer settlement","events":events.0,"omitted-events":events.1,"clock":"pool-owner-monotonic-elapsed","observation-only":true})
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        let admitted = self.admitted.get_mut().expect("compiler admission");
        let returned = self.returned.get_mut().expect("compiler reservations");
        if (0..2).any(|index| admitted[index] && !returned[index]) {
            // An uncertain tree may still own FIFO descriptors. Never destroy
            // its named protocol endpoint or pretend this is settled cleanup.
            let path = self
                .directory
                .take()
                .expect("owned compiler namespace")
                .keep();
            eprintln!(
                "unsettled compiler jobserver namespace retained: {}",
                path.display()
            );
        }
    }
}
