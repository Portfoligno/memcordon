use memcordon_readiness_verifier::{
    CaseKey, EvidenceClass, current::linux_status::verify_case, sha256,
};
use serde_json::{Value, json};

fn key(family: &str, scenario: &str) -> CaseKey {
    CaseKey {
        target: "aarch64-unknown-linux-gnu".into(),
        channel: Some("candidate-native".into()),
        evidence_class: EvidenceClass::InstalledProduct,
        family: family.into(),
        scenario: scenario.into(),
    }
}
fn native(wait: i32) -> Value {
    json!({"target":{"pid":44,"birth":99},"target_namespace_pid":2,"exec_observed":true,"release_monotonic_millis":1000,"native_wait_status":wait})
}
fn result(native: &Value, kind: &str, termination: Value, wrapper: i32) -> Value {
    json!({"release":"released","runtime":{"kind":"linux-private","native":native},"outcome":{"kind":kind,"native_termination":termination,"wrapper_status":wrapper}})
}
fn row(sequence: u64, challenge: &str, operation: &str, observation: Value) -> Value {
    json!({"format":"memcordon.linux-readiness-transcript","revision":1,"sequence":sequence,"challenge":challenge,"root_pid":2,"root_birth":99,"operation":operation,"observation":observation})
}
fn input(mode: &str) -> Value {
    let challenge = sha256(b"original prelaunch challenge");
    json!({"challenge":challenge,"target_argv":{"encoding":"unix_bytes","values":[mode.as_bytes(),challenge.as_bytes()]}})
}

#[test]
fn actual_reserved_target_exits_remain_completed_and_never_become_wrapper_failures() {
    for code in [0, 42, 123, 124, 125, 126, 127] {
        let scenario = match code {
            0 => "zero".into(),
            42 => "nonzero".into(),
            _ => format!("exit-{code}"),
        };
        let native = native(code << 8);
        let mut input = input("bytes-argv-status");
        input["target_argv"]["values"]
            .as_array_mut()
            .unwrap()
            .push(json!(code.to_string().as_bytes()));
        let bytes = (u8::MIN..=u8::MAX).collect::<Vec<_>>();
        input["binary"] = json!(bytes);
        let challenge = input["challenge"].as_str().unwrap();
        let rows = vec![
            row(
                1,
                challenge,
                "native-argv-observed",
                json!({"argv":input["target_argv"]["values"],"native_exit_status":code}),
            ),
            row(2, challenge, "byte-vector", json!({"bytes":bytes})),
        ];
        let actual = result(
            &native,
            "completed",
            json!({"kind":"exit-code","code":code}),
            code,
        );
        verify_case(&key("C-STATUS", &scenario), &input, &actual, &native, &rows).unwrap();
        let mut changed = actual.clone();
        changed["outcome"]["kind"] = json!("deadline");
        assert!(
            verify_case(
                &key("C-STATUS", &scenario),
                &input,
                &changed,
                &native,
                &rows
            )
            .is_err()
        );
    }
}

#[test]
fn deadline_requires_original_release_clock_and_actual_pidfd_wait_after_duration() {
    let native = native(9);
    let mut input = input("deadline-demand");
    input["deadline_millis"] = json!(100);
    let mut rows = vec![
        row(
            1,
            input["challenge"].as_str().unwrap(),
            "deadline-demand-started",
            json!({}),
        ),
        json!({"format":"memcordon.linux-deadline-observation","revision":1,"target":native["target"],"release_monotonic_millis":1000,"wait_observed_monotonic_millis":1100,"deadline_millis":100,"target_pidfd_readable":true}),
    ];
    let actual = result(
        &native,
        "deadline",
        json!({"kind":"unix-signal","signal":9}),
        123,
    );
    verify_case(
        &key("C-STATUS", "deadline"),
        &input,
        &actual,
        &native,
        &rows,
    )
    .unwrap();
    rows[1]["wait_observed_monotonic_millis"] = json!(1099);
    assert!(
        verify_case(
            &key("C-STATUS", "deadline"),
            &input,
            &actual,
            &native,
            &rows
        )
        .is_err()
    );
    rows[1]["wait_observed_monotonic_millis"] = json!(1100);
    rows[1]["target_pidfd_readable"] = json!(false);
    assert!(
        verify_case(
            &key("C-STATUS", "deadline"),
            &input,
            &actual,
            &native,
            &rows
        )
        .is_err()
    );
}

#[test]
fn confirmed_memory_requires_actual_cgroup_limit_and_local_oom_kill() {
    let mut native = native(9);
    native["memory_max_bytes"] = json!(128 * 1024 * 1024);
    native["memory_oom_event_count"] = json!(1);
    native["memory_oom_kill_count"] = json!(1);
    let mut input = input("memory-pressure");
    input["memory_bytes"] = native["memory_max_bytes"].clone();
    let rows = vec![row(
        1,
        input["challenge"].as_str().unwrap(),
        "memory-pressure-ready",
        json!({"chunk_bytes":1024*1024}),
    )];
    let actual = result(
        &native,
        "confirmed-memory-limit",
        json!({"kind":"unix-signal","signal":9}),
        124,
    );
    verify_case(&key("C-STATUS", "memory"), &input, &actual, &native, &rows).unwrap();
    native["memory_oom_kill_count"] = json!(0);
    let changed = result(
        &native,
        "confirmed-memory-limit",
        json!({"kind":"unix-signal","signal":9}),
        124,
    );
    assert!(verify_case(&key("C-STATUS", "memory"), &input, &changed, &native, &rows).is_err());
}

#[test]
fn root_first_requires_actual_held_descendant_to_outlive_original_root() {
    let native = native(0);
    let input = input("root-first");
    let challenge = input["challenge"].as_str().unwrap();
    let mut rows = vec![
        row(
            1,
            challenge,
            "root-exiting-before-held-descendant",
            json!({"pid":3,"birth":100,"parent_pid":2,"members":[]}),
        ),
        json!({"format":"memcordon.linux-root-first-native","revision":1,"root":native["target"],"descendant":{"pid":45,"birth":100,"namespace_pid":3},"root_pidfd_readable_before_descendant_exit":true,"descendant_pidfd_readable_when_root_retired":false,"descendant_pidfd_readable_after_completion":true}),
        json!({"format":"memcordon.linux-orphan-completion","revision":1,"challenge":challenge,"pid":3,"birth":100,"original_parent_pid":2,"original_parent_birth":99,"reparented_pid":1}),
    ];
    let actual = result(
        &native,
        "completed",
        json!({"kind":"exit-code","code":0}),
        0,
    );
    verify_case(
        &key("C-LIFETIME", "root-first"),
        &input,
        &actual,
        &native,
        &rows,
    )
    .unwrap();
    rows[1]["descendant_pidfd_readable_when_root_retired"] = json!(true);
    assert!(
        verify_case(
            &key("C-LIFETIME", "root-first"),
            &input,
            &actual,
            &native,
            &rows
        )
        .is_err()
    );
}
