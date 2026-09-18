//! Bounded parent observations; logical I/O is not physical storage attribution.
use std::collections::VecDeque;
use std::time::Duration;

pub const RETAINED: usize = 16;
#[derive(Clone, Debug)]
pub struct Times {
    pub creation_100ns: u64,
    pub kernel_100ns: u64,
    pub user_100ns: u64,
}
#[derive(Clone, Debug)]
pub struct Io {
    pub read_operations: u64,
    pub write_operations: u64,
    pub other_operations: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub other_bytes: u64,
}
#[derive(Clone, Debug)]
pub struct Counters {
    pub pid: u32,
    pub times: Result<Times, i32>,
    pub io: Result<Io, i32>,
}
#[derive(Clone, Debug)]
pub struct Sample {
    pub elapsed: Duration,
    pub query_duration: Duration,
    pub counters: Counters,
}
#[derive(Debug, Default)]
pub struct History {
    pub first: Option<Sample>,
    pub recent: VecDeque<Sample>,
    pub samples: u64,
    next: Duration,
    unsupported: bool,
}
impl History {
    pub fn due(&self, elapsed: Duration) -> bool {
        !self.unsupported && elapsed >= self.next
    }
    pub fn observe(&mut self, elapsed: Duration, finished: Duration, counters: Option<Counters>) {
        let Some(counters) = counters else {
            self.unsupported = true;
            return;
        };
        self.next = finished.saturating_add(Duration::from_secs(1));
        let sample = Sample {
            elapsed,
            query_duration: finished.saturating_sub(elapsed),
            counters,
        };
        self.samples += 1;
        self.first.get_or_insert_with(|| sample.clone());
        if self.recent.len() == RETAINED {
            self.recent.pop_front();
        }
        self.recent.push_back(sample);
    }
    pub fn json(&self) -> String {
        let first = self.first.as_ref().map_or("null".into(), sample_json);
        let recent = self
            .recent
            .iter()
            .map(sample_json)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"scope\":\"direct_child_process\",\"io_kind\":\"logical_process_counters_not_physical_disk\",\"samples\":{},\"unsupported\":{},\"first\":{},\"recent\":[{}]}}",
            self.samples, self.unsupported, first, recent
        )
    }
}
fn sample_json(sample: &Sample) -> String {
    let times = match &sample.counters.times {
        Ok(value) => format!(
            "{{\"creation_100ns\":{},\"kernel_100ns\":{},\"user_100ns\":{}}}",
            value.creation_100ns, value.kernel_100ns, value.user_100ns
        ),
        Err(code) => format!("{{\"os_error\":{code}}}"),
    };
    let io = match &sample.counters.io {
        Ok(value) => format!(
            "{{\"read_operations\":{},\"write_operations\":{},\"other_operations\":{},\"read_bytes\":{},\"write_bytes\":{},\"other_bytes\":{}}}",
            value.read_operations,
            value.write_operations,
            value.other_operations,
            value.read_bytes,
            value.write_bytes,
            value.other_bytes
        ),
        Err(code) => format!("{{\"os_error\":{code}}}"),
    };
    format!(
        "{{\"elapsed_ns\":{},\"query_ns\":{},\"pid\":{},\"times\":{},\"io\":{}}}",
        sample.elapsed.as_nanos(),
        sample.query_duration.as_nanos(),
        sample.counters.pid,
        times,
        io
    )
}
