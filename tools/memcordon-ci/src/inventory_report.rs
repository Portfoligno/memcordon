//! Bounded asynchronous machine snapshots, independent of stderr backpressure.
use super::{OPERATIONS, Shared};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, mpsc};
use std::time::Duration;
static DIRECTORY: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
static LOST: AtomicU64 = AtomicU64::new(0);
pub fn set_report_directory(directory: Option<PathBuf>) -> std::io::Result<()> {
    if let Some(path) = &directory {
        std::fs::create_dir_all(path)?;
    }
    *DIRECTORY
        .get_or_init(|| Mutex::new(None))
        .lock()
        .expect("report configuration poisoned") = directory;
    Ok(())
}
fn quoted(value: &str) -> String {
    let mut text = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => text.push_str("\\\""),
            '\\' => text.push_str("\\\\"),
            c if c < ' ' => text.push_str(&format!("\\u{:04x}", c as u32)),
            c => text.push(c),
        }
    }
    text.push('"');
    text
}
pub(super) fn persist(shared: &Shared, complete: Option<bool>, wait: bool) {
    let directory = DIRECTORY
        .get_or_init(|| Mutex::new(None))
        .lock()
        .expect("report configuration poisoned")
        .clone();
    let Some(directory) = directory else { return };
    let sample = shared.observation.snapshot();
    let actors=sample.actors.iter().map(|actor| {
        let op=actor.operation.map_or("null".to_owned(),|op|quoted(&format!("{:?}",OPERATIONS[op])));
        let counters=actor.counters.as_ref().map_or("null".to_owned(),|c|format!("{{\"published_ns\":{},\"counts\":{:?},\"inclusive_ns\":{:?},\"exclusive_ns\":{:?},\"bytes_returned\":{},\"read_calls\":{},\"read_ns\":{},\"hash_ns\":{},\"panics\":{},\"idle_ns\":{},\"task_other_ns\":{}}}",c.published_ns,c.counts,c.inclusive_ns,c.exclusive_ns,c.bytes,c.read_calls,c.read_ns,c.hash_ns,c.panics,c.idle_ns,c.task_other_ns));
        format!("{{\"task_id\":{},\"operation\":{op},\"active_coherent\":{},\"started_ns\":{},\"path_sample\":{},\"counters\":{counters}}}",actor.task.map_or("null".to_owned(),|id|id.to_string()),actor.generation.is_some(),actor.started_ns,quoted(&actor.path))
    }).collect::<Vec<_>>().join(",");
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let root: String = shared
        .root
        .as_os_str()
        .to_string_lossy()
        .chars()
        .take(256)
        .collect();
    let events = sample
        .events
        .iter()
        .map(|event| {
            format!(
                "{{\"task\":{},\"parent\":{},\"ordinal\":{},\"state\":\"{:?}\",\"at_ns\":{}}}",
                event.id,
                event.parent.map_or("null".to_owned(), |id| id.to_string()),
                event.ordinal.map_or("null".to_owned(), |id| id.to_string()),
                event.state,
                event.at_ns
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let payload = format!(
        "{{\"schema\":1,\"file_counters_scope\":\"windows_linux_native_pipeline\",\"sequence\":{sequence},\"root_id\":{},\"root_sample\":{},\"root_complete\":{},\"elapsed_ns\":{},\"sample\":\"actor_publication_vector\",\"files_attempted\":{},\"files_completed\":{},\"files_validated\":{},\"files_committed\":{},\"manifest_bytes_committed\":{},\"outstanding\":{},\"lost_reports\":{},\"overwritten_events\":{},\"events\":[{events}],\"actors\":[{actors}]}}\n",
        sample.root_id,
        quoted(&root),
        complete.map_or("null", |ok| if ok { "true" } else { "false" }),
        sample.elapsed_ns,
        sample.tasks.files_attempted,
        sample.tasks.files_completed,
        sample.tasks.files_validated,
        sample.tasks.files_committed,
        sample.tasks.committed_bytes,
        sample.outstanding,
        LOST.load(Ordering::Relaxed),
        sample.overwritten_events
    );
    type Record = (PathBuf, String, mpsc::SyncSender<()>);
    static WRITER: OnceLock<mpsc::SyncSender<Record>> = OnceLock::new();
    let sender = WRITER.get_or_init(|| {
        let (sender, receiver) = mpsc::sync_channel::<Record>(8);
        std::thread::spawn(move || {
            for (path, payload, ack) in receiver {
                let written = std::fs::File::create(path).and_then(|mut file| {
                    file.write_all(payload.as_bytes())?;
                    file.sync_all()
                });
                if written.is_err() {
                    LOST.fetch_add(1, Ordering::Relaxed);
                }
                let _ = ack.try_send(());
            }
        });
        sender
    });
    if payload.len() > 65536 {
        LOST.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let (ack, done) = mpsc::sync_channel(1);
    if sender
        .try_send((
            directory.join(if sequence.is_multiple_of(2) {
                "inventory-0.json"
            } else {
                "inventory-1.json"
            }),
            payload,
            ack,
        ))
        .is_err()
    {
        LOST.fetch_add(1, Ordering::Relaxed);
    } else if wait {
        let _ = done.recv_timeout(Duration::from_millis(100));
    }
}
