#[path = "../src/windows_toolchain_sampling.rs"]
mod sampling;
use sampling::Identity;
use serde_json::{Value, json};
use std::collections::BTreeSet;

#[test]
fn native_operation_context_retains_original_error_and_bounds_rendering() {
    let original = std::io::Error::from_raw_os_error(87);
    let kind = original.kind();
    let seed = "參數";
    let parameters = seed.repeat(sampling::OPERATION_PARAMETER_BOUND.div_ceil(seed.len()) + 1);
    let error = sampling::operation_error("open-rename-source", parameters, original);
    assert_eq!(error.kind(), kind);
    let cause = error
        .get_ref()
        .unwrap()
        .source()
        .unwrap()
        .downcast_ref::<std::io::Error>()
        .unwrap();
    assert_eq!(cause.raw_os_error(), Some(87));
    let rendered = error.to_string();
    assert!(rendered.starts_with("operation=open-rename-source;"));
    assert!(rendered.contains("raw-os-error=Some(87)"));
    assert!(rendered.contains("omitted-bytes="));
    assert!(rendered.len() <= 2048);
    let debug = format!("{error:?}");
    assert!(debug.contains("raw-os-error=Some(87)"));
    assert!(debug.len() <= 2048);
}

#[test]
fn arbitrary_native_cause_stops_at_bound_and_is_not_rendered_again() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    #[derive(Debug)]
    struct HugeCause(Arc<AtomicUsize>);
    impl std::fmt::Display for HugeCause {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            for _ in 0..sampling::OPERATION_PARAMETER_BOUND {
                self.0.fetch_add(1, Ordering::Relaxed);
                formatter.write_str("native cause λ ")?;
            }
            Ok(())
        }
    }
    impl std::error::Error for HugeCause {}
    let writes = Arc::new(AtomicUsize::new(0));
    let original = std::io::Error::other(HugeCause(writes.clone()));
    let error = sampling::operation_error("read-staged-readback", String::new(), original);
    let captured_writes = writes.load(Ordering::Relaxed);
    assert!(captured_writes > 0 && captured_writes < sampling::OPERATION_PARAMETER_BOUND);
    let display = error.to_string();
    let debug = format!("{error:?}");
    assert!(display.contains("cause-format-incomplete; omitted-bytes=unknown"));
    assert!(display.len() <= 2048 && debug.len() <= 2048);
    assert_eq!(writes.load(Ordering::Relaxed), captured_writes);
    assert!(
        error
            .get_ref()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .is_some()
    );
}

#[test]
fn publication_requires_exact_rename_attribute_transition() {
    let prepared = (7, 11, 0x80, 1, 823);
    let published = sampling::published_identity(prepared).unwrap();
    assert_eq!(published, (7, 11, 0x20, 1, 823));
    for attributes in [0x20, 0x100, 1, 0x81] {
        assert!(sampling::published_identity((7, 11, attributes, 1, 823)).is_err());
    }
    assert!(sampling::published_identity((7, 11, 0x80, 2, 823)).is_err());
    for invalid in [
        (7, 11, 0x80, 1, 823),
        (7, 11, 0x100, 1, 823),
        (7, 11, 1, 1, 823),
        (7, 11, 0x21, 1, 823),
        (8, 11, 0x20, 1, 823),
        (7, 12, 0x20, 1, 823),
        (7, 11, 0x20, 2, 823),
        (7, 11, 0x20, 1, 824),
    ] {
        assert_ne!(published, invalid);
    }
}

fn records() -> (Value, Value, BTreeSet<String>) {
    use sha2::{Digest, Sha256};
    let compiler = hex::encode(Sha256::digest(b"selected compiler"));
    let helper = hex::encode(Sha256::digest(b"selected helper"));
    let binding = json!({"challenge":b"challenge","native_work_cutoff_ticks":9000,"native_work_frequency":1000,
        "original_child":{"process_id":20,"creation_time_100ns":200},"parent":{"process_id":10,"creation_time_100ns":100},
        "role":"child.exe","selected_image_sha256":compiler});
    let phase = json!({"format":"memcordon.windows-toolchain-current-state","revision":1,"diagnostic_only":true,
        "transition_snapshot_not_live_probe":true,"binding":binding,"transition_sequence":14});
    let mut debug = phase.clone();
    debug["transition_sequence"] = 21.into();
    debug["phase"] = "before-debug-wait".into();
    debug["state"] = json!({"original_child_pid":20,"last_event":{"kind":"exit-process","pid":20},
        "pending_event":null,"continued":true,"ack_validated":false,"active":{"complete":true,"active_count":1,"omitted_count":0,
        "members":[{"pid":30,"birth":300,"parent_pid":25,"parent_birth":250,"image_sha256":helper,
        "held_process_owner":true,"image_observation":"creation-event-owned-file"}]}});
    (phase, debug, BTreeSet::from([compiler, helper]))
}

#[test]
fn newest_root_exit_is_a_hint_not_ack_rejection_or_retirement_authority() {
    let (phase, debug, images) = records();
    let hint = sampling::hint(
        &phase,
        &debug,
        b"challenge",
        Identity {
            pid: 10,
            birth: 100,
        },
        (9000, 1000),
        &images,
    )
    .unwrap();
    assert_eq!(
        sampling::binding_fixture(&hint).unwrap(),
        Identity {
            pid: 10,
            birth: 100
        }
    );
    assert_eq!(
        hint.compiler,
        Identity {
            pid: 20,
            birth: 200
        }
    );
    assert_eq!(
        hint.survivors[0].identity,
        Identity {
            pid: 30,
            birth: 300
        }
    );
    assert_eq!(
        hint.survivors[0].parent,
        Identity {
            pid: 25,
            birth: 250
        }
    );
    assert!(images.contains(&hint.survivors[0].image_sha256));
    let encoded = sampling::encode(&hint, &[], false).unwrap();
    let value: Value = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(value["second_pass_attempted"], false);
    assert_eq!(value["omitted_survivors"], 1);
    assert_eq!(value["wait_reason_known"], false);
    assert_eq!(value["compiler_acceptance"], false);
}

#[test]
fn stale_foreign_omitted_and_changed_inventory_hints_refuse_sampling() {
    let (phase, debug, images) = records();
    for mutate in [
        |v: &mut Value| v["transition_sequence"] = 13.into(),
        |v: &mut Value| v["binding"]["challenge"] = json!(b"foreign"),
        |v: &mut Value| v["state"]["pending_event"] = json!([30, 1]),
        |v: &mut Value| v["state"]["active"]["complete"] = false.into(),
        |v: &mut Value| v["state"]["active"]["omitted_count"] = 1.into(),
        |v: &mut Value| v["state"]["active"]["members"][0]["held_process_owner"] = false.into(),
    ] {
        let mut changed = debug.clone();
        mutate(&mut changed);
        assert!(
            sampling::hint(
                &phase,
                &changed,
                b"challenge",
                Identity {
                    pid: 10,
                    birth: 100
                },
                (9000, 1000),
                &images
            )
            .is_err()
        );
    }
    assert!(
        sampling::hint(
            &phase,
            &debug,
            b"challenge",
            Identity {
                pid: 10,
                birth: 101
            },
            (9000, 1000),
            &images
        )
        .is_err()
    );
    assert!(
        sampling::hint(
            &phase,
            &debug,
            b"challenge",
            Identity {
                pid: 10,
                birth: 100
            },
            (9001, 1000),
            &images
        )
        .is_err()
    );
}

#[test]
fn diagnostic_payload_limit_is_not_a_thread_or_retirement_acceptance_rule() {
    let (phase, debug, images) = records();
    let hint = sampling::hint(
        &phase,
        &debug,
        b"challenge",
        Identity {
            pid: 10,
            birth: 100,
        },
        (9000, 1000),
        &images,
    )
    .unwrap();
    assert!(
        sampling::encode(
            &hint,
            &[json!({"oversized":vec![0u8;sampling::RECORD_BOUND]})],
            true
        )
        .is_err()
    );
    let bytes = sampling::encode(
        &hint,
        &[json!({"complete":false,"second":null,"error":"original cutoff expired"})],
        true,
    )
    .unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["samples"][0]["complete"], false);
    assert_eq!(value["samples"][0]["second"], Value::Null);
    assert_eq!(value["unchanged_counters_do_not_prove_deadlock"], true);
    assert_eq!(value["wct_invoked"], false);
}

#[test]
fn ordinary_completed_or_in_progress_compilers_leave_later_helper_round_eligible() {
    let (phase, debug, _) = records();
    let mut completed = debug.clone();
    completed["state"]["active"] =
        json!({"members":[],"active_count":0,"complete":true,"omitted_count":0});
    assert!(sampling::candidate(&phase, &completed).unwrap().is_none());
    let mut child_exit = debug.clone();
    child_exit["state"]["last_event"]["pid"] = 30.into();
    assert!(sampling::candidate(&phase, &child_exit).unwrap().is_none());
    let mut newer_phase = phase.clone();
    newer_phase["transition_sequence"] = 22.into();
    assert!(sampling::candidate(&newer_phase, &debug).unwrap().is_none());
    let mut next_compiler = phase.clone();
    next_compiler["binding"]["original_child"]["process_id"] = 40.into();
    assert!(
        sampling::candidate(&next_compiler, &debug)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        sampling::candidate(&phase, &debug).unwrap(),
        Some((
            Identity {
                pid: 20,
                birth: 200
            },
            21
        ))
    );
}

#[cfg(windows)]
#[test]
fn native_publication_keeps_atomic_readback_and_refuses_expired_replacement() {
    use std::io::{Read, Seek, SeekFrom};
    use std::time::{Duration, Instant};
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("activity.json");
    let (phase, debug, images) = records();
    let hint = sampling::hint(
        &phase,
        &debug,
        b"challenge",
        Identity {
            pid: 10,
            birth: 100,
        },
        (9000, 1000),
        &images,
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    assert!(sampling::encode_until(&hint, &[], false, Instant::now()).is_err());
    let initial = sampling::encode_until(&hint, &[], false, deadline).unwrap();
    assert!(sampling::publish(root.path(), &path, &initial, Instant::now()).is_err());
    assert!(!path.exists());
    let mut original = sampling::publish(root.path(), &path, &initial, deadline).unwrap();
    let original_native = memcordon_testkit::windows_held_file_metadata(&original).unwrap();
    assert_eq!(
        original_native.attributes,
        windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_ARCHIVE
    );
    assert_eq!(std::fs::read(&path).unwrap(), initial);
    for invalid in [
        "",
        ".",
        "..",
        "alternate:stream",
        "sub/name",
        "sub\\name",
        "nul\0name",
    ] {
        assert!(
            sampling::publish(root.path(), &root.path().join(invalid), &initial, deadline).is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), initial);
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    }
    let next = sampling::encode_until(
        &hint,
        &[json!({"complete":false,"second":null})],
        true,
        deadline,
    )
    .unwrap();
    assert!(sampling::publish(root.path(), &path, &next, Instant::now()).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), initial);
    let replacement = sampling::publish(root.path(), &path, &next, deadline).unwrap();
    let replacement_native = memcordon_testkit::windows_held_file_metadata(&replacement).unwrap();
    assert_eq!(replacement_native.attributes, original_native.attributes);
    assert_eq!(
        replacement_native.volume_serial,
        original_native.volume_serial
    );
    assert_ne!(replacement_native.file_index, original_native.file_index);
    assert_eq!(std::fs::read(&path).unwrap(), next);
    original.seek(SeekFrom::Start(0)).unwrap();
    let mut retained_bytes = Vec::new();
    original.read_to_end(&mut retained_bytes).unwrap();
    assert_eq!(retained_bytes, initial);
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    assert_eq!(original.metadata().unwrap().len(), initial.len() as u64);
    assert_eq!(replacement.metadata().unwrap().len(), next.len() as u64);
}
