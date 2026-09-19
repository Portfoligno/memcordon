use super::{Channel, Message, private_pair};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

pub fn complete_exec_receipt_survives_post_write_deadline() {
    let (left, right) = private_pair().unwrap();
    let mut sender = Channel::new(left, 17).unwrap();
    let mut receiver = Channel::new(right, 17).unwrap();
    sender.expire_send_after_write = true;
    sender
        .send(Message::Released, Instant::now() + Duration::from_secs(2))
        .expect("a complete exec receipt needs no second deadline-bound write");
    assert_eq!(sender.sent, 1);
    assert!(sender.frame_started);
    assert!(!sender.invalidated);
    drop(sender);
    let deadline = Instant::now() + Duration::from_secs(2);
    receiver.expect(Message::Released, deadline).unwrap();
    assert_eq!(receiver.received, 1);
    assert_eq!(receiver.receive(deadline).unwrap(), None);
}

pub fn buffered_child_status_does_not_delay_inventory() {
    let (left, right) = private_pair().unwrap();
    let mut frontend = Channel::new(left, 13).unwrap();
    let mut guardian = Channel::new(right, 13).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    assert_eq!(frontend.poll_child_status(false).unwrap(), None);
    assert!(matches!(
        guardian.receive(deadline).unwrap(),
        Some(Message::Observe { .. })
    ));
    frontend.inventory_query = Some(1);

    // Model one socket read that has already buffered a delayed status reply
    // followed by two inventory chunks. Keep the peer open and idle: waiting
    // for socket readiness cannot help consume these complete buffered frames.
    for (sequence, message) in [
        Message::Status {
            raw: Some(37 << 8),
            reaped: false,
        },
        Message::InventoryChunk {
            query: 1,
            bytes: vec![1, 2],
            finished: false,
        },
        Message::InventoryChunk {
            query: 1,
            bytes: vec![3, 4],
            finished: true,
        },
    ]
    .into_iter()
    .enumerate()
    {
        let bytes = serde_json::to_vec(&super::Frame {
            version: 2,
            run: 13,
            sequence: sequence.try_into().unwrap(),
            message,
        })
        .unwrap();
        let length = u16::try_from(bytes.len()).unwrap();
        frontend.input.extend_from_slice(&length.to_be_bytes());
        frontend.input.extend_from_slice(&bytes);
    }

    assert_eq!(frontend.receive_available().unwrap(), None);
    assert_eq!(frontend.receive_available().unwrap(), None);
    assert_eq!(frontend.receive_available().unwrap(), None);
    assert_eq!(frontend.inventory_payload, vec![1, 2, 3, 4]);
    assert!(frontend.inventory_finished);
    assert_eq!(frontend.poll_child_status(false).unwrap(), Some(37 << 8));
    assert_eq!(frontend.reaped_status, None);
    assert!(!frontend.child_status_pending);
    assert_eq!(frontend.received, 3);
    assert!(frontend.input.is_empty());
    assert_eq!(frontend.receive_waits, 0);
    drop(guardian);
}

pub fn delayed_child_status_retains_observation_and_reaping() {
    let (left, right) = private_pair().unwrap();
    let mut frontend = Channel::new(left, 7).unwrap();
    let mut guardian = Channel::new(right, 7).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    assert_eq!(frontend.poll_child_status(false).unwrap(), None);
    assert!(matches!(
        guardian.receive(deadline).unwrap(),
        Some(Message::Observe { .. })
    ));
    assert_eq!(frontend.poll_child_status(false).unwrap(), None);
    assert_eq!(guardian.receive_available().unwrap(), None);

    // A scheduler delay beyond the old synchronous reply timeout must not turn
    // an already successful exit into a monitor failure or create a second query.
    std::thread::sleep(Duration::from_millis(120));
    let status = 37 << 8;
    guardian
        .send(
            Message::Status {
                raw: Some(status),
                reaped: false,
            },
            deadline,
        )
        .unwrap();
    assert_eq!(frontend.poll_child_status(false).unwrap(), Some(status));
    assert_eq!(frontend.poll_child_status(true).unwrap(), None);
    assert!(matches!(
        guardian.receive(deadline).unwrap(),
        Some(Message::Reap { .. })
    ));
    guardian
        .send(
            Message::Status {
                raw: None,
                reaped: false,
            },
            deadline,
        )
        .unwrap();
    assert_eq!(frontend.poll_child_status(true).unwrap(), None);
    assert_eq!(frontend.poll_child_status(false).unwrap(), Some(status));
    assert_eq!(frontend.poll_child_status(true).unwrap(), None);
    assert!(matches!(
        guardian.receive(deadline).unwrap(),
        Some(Message::Reap { .. })
    ));
    guardian
        .send(
            Message::Status {
                raw: Some(status),
                reaped: true,
            },
            deadline,
        )
        .unwrap();
    assert_eq!(frontend.poll_child_status(true).unwrap(), Some(status));
    assert_eq!(frontend.poll_child_status(true).unwrap(), Some(status));
    assert_eq!(guardian.receive_available().unwrap(), None);
}

pub fn delayed_child_status_cannot_be_confused_with_inventory() {
    let (left, right) = private_pair().unwrap();
    let mut frontend = Channel::new(left, 11).unwrap();
    let mut guardian = Channel::new(right, 11).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    assert_eq!(frontend.poll_child_status(false).unwrap(), None);
    assert!(matches!(
        guardian.receive(deadline).unwrap(),
        Some(Message::Observe { .. })
    ));
    frontend
        .send(
            Message::InventoryQuery {
                query: 1,
                metric: None,
            },
            deadline,
        )
        .unwrap();
    frontend.inventory_query = Some(1);
    guardian
        .expect(
            Message::InventoryQuery {
                query: 1,
                metric: None,
            },
            deadline,
        )
        .unwrap();
    guardian
        .send(Message::ForceRequested { at: 42 }, deadline)
        .unwrap();
    guardian
        .send(
            Message::Status {
                raw: Some(0),
                reaped: false,
            },
            deadline,
        )
        .unwrap();
    let reply = || Message::InventoryChunk {
        query: 1,
        bytes: Vec::new(),
        finished: true,
    };
    guardian.send(reply(), deadline).unwrap();
    let Some(Some(Message::ForceRequested { at })) = frontend.receive_available().unwrap() else {
        panic!("force receipt missing before delayed inventory response");
    };
    frontend
        .force_receipt
        .store(at, std::sync::atomic::Ordering::Release);
    assert_eq!(frontend.receive_available().unwrap(), None);
    assert_eq!(frontend.receive_available().unwrap(), None);
    assert!(frontend.inventory_finished);
    assert_eq!(frontend.force_receipt.load(Ordering::Acquire), 42);
    assert_eq!(frontend.poll_child_status(false).unwrap(), Some(0));
    assert_eq!(frontend.poll_child_status(true).unwrap(), None);
    assert!(matches!(
        guardian.receive(deadline).unwrap(),
        Some(Message::Reap { .. })
    ));
    drop(guardian);
    assert!(frontend.poll_child_status(true).is_err());
}
