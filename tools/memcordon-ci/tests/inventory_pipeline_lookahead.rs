use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::Duration;

use memcordon_ci::Result;
use memcordon_ci::inventory_pipeline::{InventoryBackend, InventorySession, Node, ValidatedDigest};
use memcordon_ci::inventory_workers::CAPACITY;

struct Backend {
    started: mpsc::Sender<usize>,
    gate: Arc<(Mutex<bool>, Condvar)>,
    hints: Hints,
}

enum Hints {
    Accurate,
    Unknown,
    StaleAllLeaf,
}

impl InventoryBackend for Backend {
    type Entry = usize;
    type Prepared = usize;
    type Expansion = usize;
    type File = usize;
    type Record = usize;

    fn is_leaf_hint(&self, entry: &usize) -> bool {
        match self.hints {
            Hints::Accurate => *entry >= 3,
            Hints::Unknown => false,
            Hints::StaleAllLeaf => true,
        }
    }

    fn prepare(&self, entry: usize) -> Result<usize> {
        if (100..131).contains(&entry) {
            self.started.send(entry).unwrap();
            let (lock, wake) = &*self.gate;
            drop(
                wake.wait_while(lock.lock().unwrap(), |open| !*open)
                    .unwrap(),
            );
        }
        Ok(entry)
    }

    fn classify(
        &self,
        entry: usize,
        visited: &mut BTreeSet<PathBuf>,
    ) -> Result<Node<usize, usize, usize>> {
        assert!(visited.insert(PathBuf::from(entry.to_string())));
        Ok(if entry < 3 {
            Node::Expand(entry)
        } else {
            Node::File(entry, entry)
        })
    }

    fn expand(&self, entry: usize) -> Result<(Vec<usize>, usize)> {
        let children = match entry {
            0 => std::iter::once(1).chain(1000..1016).collect(),
            1 => std::iter::once(2).chain(2000..2016).collect(),
            2 => (100..131).collect(),
            _ => panic!("only directories expand"),
        };
        Ok((children, entry))
    }

    fn read(&self, entry: usize, _: &mut [u8]) -> Result<ValidatedDigest> {
        Ok(ValidatedDigest {
            digest: entry.to_string(),
            bytes: 1,
        })
    }

    fn set_digest(&self, entry: &mut usize, digest: ValidatedDigest) {
        assert_eq!(digest.digest, entry.to_string());
    }
}

#[test]
fn wide_ancestor_siblings_do_not_starve_deep_leaf_preparation() {
    run_fixture(Hints::Accurate, CAPACITY - 1);
}

#[test]
fn missing_or_stale_hints_preserve_progress_and_authoritative_classification() {
    run_fixture(Hints::Unknown, 1);
    run_fixture(Hints::StaleAllLeaf, 1);
}

fn run_fixture(hints: Hints, required_concurrency: usize) {
    let (started, observed) = mpsc::channel();
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let backend = Backend {
        started,
        gate: gate.clone(),
        hints,
    };
    let worker = std::thread::spawn(move || {
        InventorySession::new()
            .unwrap()
            .measure(backend, 0, &mut BTreeSet::new())
    });
    let mut concurrent = BTreeSet::new();
    for _ in 0..required_concurrency {
        match observed.recv_timeout(Duration::from_secs(2)) {
            Ok(entry) => {
                concurrent.insert(entry);
            }
            Err(_) => break,
        }
    }
    // Release every worker even when the concurrency assertion will fail.
    let (lock, wake) = &*gate;
    *lock.lock().unwrap() = true;
    wake.notify_all();
    let records = worker.join().unwrap().unwrap();
    assert_eq!(records.len(), 66, "all ancestor siblings remain measured");
    assert_eq!(records.iter().copied().collect::<BTreeSet<_>>().len(), 66);
    assert_eq!(
        concurrent.len(),
        required_concurrency,
        "ready siblings of suspended ancestors must not consume the deep frontier window"
    );
}
