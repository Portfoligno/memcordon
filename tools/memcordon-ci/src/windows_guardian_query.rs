//! Diagnostic custody for the original nested query; never association authority.
use memcordon_testkit::ObservedOutput;
use std::{io, sync::Mutex};

pub const STREAM_BOUND: usize = 16 * 1024;
const RECORD_BOUND: usize = 32 * 1024;

/// Even an invariant/poison failure must not drop the newly acquired witness.
/// The callback executes once; an unexpected second owner remains retained too.
pub fn adopt<T>(slot: &Mutex<Vec<T>>, owner: T) -> io::Result<()> {
    let (mut owners, poisoned) = match slot.lock() {
        Ok(owners) => (owners, false),
        Err(poisoned) => (poisoned.into_inner(), true),
    };
    let occupied = !owners.is_empty();
    owners.push(owner);
    if poisoned || occupied {
        return Err(io::Error::other(
            "original guardian custody slot poisoned or occupied; all owners retained",
        ));
    }
    Ok(())
}

pub struct Trace {
    binding: serde_json::Value,
    guardian: Option<serde_json::Value>,
    stage: &'static str,
    output: Option<ObservedOutput>,
    poisoned: bool,
}
pub struct Snapshot {
    pub record: Vec<u8>,
    pub stdout: Option<Vec<u8>>,
    pub stderr: Option<Vec<u8>>,
}

impl Trace {
    pub fn new(binding: serde_json::Value) -> Self {
        Self {
            binding,
            guardian: None,
            stage: "not-started",
            output: None,
            poisoned: false,
        }
    }
    pub fn guardian(&mut self, identity: serde_json::Value) {
        self.guardian = Some(identity);
    }
    pub fn stage(&mut self, stage: &'static str) {
        self.stage = stage;
    }
    pub fn captured(&mut self, output: ObservedOutput) {
        self.output = Some(output);
    }
    pub fn failure(&self) -> Option<io::Error> {
        self.output.as_ref().filter(|output| !output.status.success()).map(|output| io::Error::other(format!(
            "positive live guardian association query failed; operation=__observe-windows-guardian; nested-status={:?}; diagnostic-extension=guardian-query.json", output.status.code())))
    }
    pub fn snapshot(&self) -> io::Result<Option<Snapshot>> {
        if self.guardian.is_none() {
            return Ok(None);
        }
        let (stdout, stderr) = self.output.as_ref().map_or((&[][..], &[][..]), |output| {
            (output.stdout.as_slice(), output.stderr.as_slice())
        });
        if stdout.len() > STREAM_BOUND || stderr.len() > STREAM_BOUND {
            return Err(io::Error::other(
                "original guardian query capture exceeds existing stream bound",
            ));
        }
        let digest = |bytes: &[u8]| hex::encode(<sha2::Sha256 as sha2::Digest>::digest(bytes));
        let record = serde_json::to_vec(&serde_json::json!({
            "format":"memcordon.windows-original-guardian-query","revision":1,"diagnostic_only":true,
            "operation":"__observe-windows-guardian","binding":self.binding,"original_guardian":self.guardian,
            "stage":self.stage,"diagnostic_lock_poisoned":self.poisoned,"output_observed":self.output.is_some(),
            "status_code":self.output.as_ref().and_then(|output|output.status.code()),
            "status_success":self.output.as_ref().map(|output|output.status.success()),
            "termination":if self.output.is_some(){"returned-output"}else{"not-observed"},
            "stdout":self.output.as_ref().map(|_|serde_json::json!({"artifact_extension":"guardian-query.stdout.bin","length":stdout.len(),"sha256":digest(stdout)})),
            "stderr":self.output.as_ref().map(|_|serde_json::json!({"artifact_extension":"guardian-query.stderr.bin","length":stderr.len(),"sha256":digest(stderr)})),
        })).map_err(io::Error::other)?;
        if record.len() > RECORD_BOUND {
            return Err(io::Error::other(
                "original guardian query diagnostic record exceeds bound",
            ));
        }
        Ok(Some(Snapshot {
            record,
            stdout: self.output.as_ref().map(|_| stdout.to_vec()),
            stderr: self.output.as_ref().map(|_| stderr.to_vec()),
        }))
    }
}

pub fn update<T>(trace: &Mutex<Trace>, update: impl FnOnce(&mut Trace) -> T) -> T {
    match trace.lock() {
        Ok(mut trace) => update(&mut trace),
        Err(poisoned) => {
            let mut trace = poisoned.into_inner();
            trace.poisoned = true;
            update(&mut trace)
        }
    }
}
