use memcordon_ci::rehearsal_support::{
    protocol::{BudgetPreset, FixtureRecord, REVISION},
    server::publish_readiness,
};
use serde::{Serialize, Serializer, ser::SerializeMap};
use std::{
    fs,
    net::{Ipv4Addr, SocketAddrV4},
    sync::mpsc,
    time::Duration,
};

struct PausedRecord {
    record: FixtureRecord,
    entered: mpsc::Sender<()>,
    resume: mpsc::Receiver<()>,
    fail: bool,
}

impl Serialize for PausedRecord {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("revision", &self.record.revision)?;
        self.entered.send(()).map_err(serde::ser::Error::custom)?;
        self.resume
            .recv_timeout(Duration::from_secs(5))
            .map_err(serde::ser::Error::custom)?;
        if self.fail {
            return Err(serde::ser::Error::custom(
                "record serialization interrupted",
            ));
        }
        map.serialize_entry("address", &self.record.address)?;
        map.serialize_entry("session", &self.record.session)?;
        map.serialize_entry("budget", &self.record.budget)?;
        map.serialize_entry("expires_unix_ms", &self.record.expires_unix_ms)?;
        map.end()
    }
}

fn record() -> FixtureRecord {
    FixtureRecord {
        revision: REVISION,
        address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345),
        session: "abcdef0123456789".repeat(4),
        budget: BudgetPreset::Normal20min,
        expires_unix_ms: 1791316230000,
    }
}

#[test]
fn readiness_is_invisible_during_partial_json_and_complete_on_first_observation() {
    let directory = tempfile::tempdir().unwrap();
    let ready = directory.path().join("ready.json");
    let expected = record();
    let (entered, observed) = mpsc::channel();
    let (resume, blocked) = mpsc::channel();
    let path = ready.clone();
    let value = PausedRecord {
        record: expected.clone(),
        entered,
        resume: blocked,
        fail: false,
    };
    let writer = std::thread::spawn(move || publish_readiness(&path, &value));
    observed.recv_timeout(Duration::from_secs(5)).unwrap();
    let visible_while_partial = ready.exists();
    resume.send(()).unwrap();
    writer.join().unwrap().unwrap();
    assert!(
        !visible_while_partial,
        "readers must never see the published name before complete JSON"
    );
    let bytes = fs::read(&ready).unwrap();
    assert_eq!(bytes.last(), Some(&b'\n'));
    let observed: FixtureRecord = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        serde_json::to_value(observed).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn failed_readiness_serialization_publishes_nothing_and_cleans_staging() {
    let directory = tempfile::tempdir().unwrap();
    let ready = directory.path().join("ready.json");
    let (entered, observed) = mpsc::channel();
    let (resume, blocked) = mpsc::channel();
    let path = ready.clone();
    let value = PausedRecord {
        record: record(),
        entered,
        resume: blocked,
        fail: true,
    };
    let writer = std::thread::spawn(move || publish_readiness(&path, &value));
    observed.recv_timeout(Duration::from_secs(5)).unwrap();
    resume.send(()).unwrap();
    assert!(writer.join().unwrap().is_err());
    assert!(!ready.exists());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn readiness_never_replaces_an_existing_fixture_record() {
    let directory = tempfile::tempdir().unwrap();
    let ready = directory.path().join("ready.json");
    let previous = b"another fixture owns this published readiness name\n";
    fs::write(&ready, previous).unwrap();
    assert!(publish_readiness(&ready, &record()).is_err());
    assert_eq!(fs::read(&ready).unwrap(), previous);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}
