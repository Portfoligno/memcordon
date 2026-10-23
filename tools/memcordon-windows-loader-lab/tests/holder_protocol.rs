use memcordon_core::WindowsProcessIdentityV1;
use memcordon_windows_loader_lab::holder_protocol::{
    self, Binding, Frame, Outcome, ReadyPolicy, Stage,
};
use memcordon_windows_loader_lab::selected_policy::{
    ComparisonOutcome, Domain, PolicyFingerprint, VerifiedPolicy,
};

// Wire-shape fixture only. Bound-descriptor admission and forged semantic
// digests are exercised through the actual selected_policy implementation.
fn policy(domain: Domain) -> VerifiedPolicy {
    VerifiedPolicy {
        fingerprint: PolicyFingerprint {
            schema_version: 1,
            selection: domain.selection(),
            domain,
            sha256: "11".repeat(32),
        },
        comparison: ComparisonOutcome::Exact,
        observed_control: if domain == Domain::Gate {
            0x9004
        } else {
            0xb014
        },
    }
}

fn identity() -> WindowsProcessIdentityV1 {
    WindowsProcessIdentityV1 {
        process_id: 1234,
        creation_time_100ns: 134371190330874018,
    }
}
fn binding() -> Binding {
    Binding {
        diagnostic_id: "aa".repeat(32),
        request_sha256: "bb".repeat(32),
    }
}
fn ready() -> Frame {
    Frame {
        schema_version: holder_protocol::FRAME_SCHEMA_VERSION,
        identity: identity(),
        observed_request: Some(binding()),
        outcome: Outcome::Ready {
            policy: Box::new(ReadyPolicy {
                session_id: 2,
                desktop: "Diagnostic\\Restricted".into(),
                station_sha256: "cc".repeat(32),
                desktop_sha256: "dd".repeat(32),
                station_policy: policy(Domain::Station),
                desktop_policy: policy(Domain::Desktop),
                gate: "Local\\diagnostic-bound-gate".into(),
                gate_sddl: "D:P(A;;GA;;;SY)".into(),
                gate_sha256: "ee".repeat(32),
                gate_policy: policy(Domain::Gate),
                target_envelope_sha256: "ff".repeat(32),
            }),
        },
    }
}
fn failure(binding: Option<Binding>) -> Frame {
    Frame::failure(
        identity(),
        binding,
        Stage::WindowStation,
        "CreateWindowStationW",
        Some(5),
        "Access denied",
        &["restore failed: 6".into()],
    )
}
fn decode(bytes: &[u8], ended: bool) -> Result<Option<Frame>, String> {
    holder_protocol::decode_initial(bytes, &identity(), &binding(), ended)
}

#[test]
fn ready_requires_complete_typed_frame_and_exact_observed_request() {
    let frame = ready();
    let bytes = holder_protocol::encode(&frame).unwrap();
    for length in 0..bytes.len() {
        assert_eq!(decode(&bytes[..length], false).unwrap(), None);
    }
    assert_eq!(decode(&bytes, false).unwrap(), Some(frame));
    let mut unbound = ready();
    unbound.observed_request = None;
    assert!(holder_protocol::encode(&unbound).is_err());
    let mut mismatch = ready();
    mismatch.observed_request.as_mut().unwrap().request_sha256 = "99".repeat(32);
    assert!(decode(&holder_protocol::encode(&mismatch).unwrap(), false).is_err());
}

#[test]
fn semantic_ready_fields_require_versioned_domains_selections_and_consistent_claims() {
    for field in [
        "domain",
        "selection",
        "schema",
        "digest",
        "outcome",
        "missing",
    ] {
        let mut wire = serde_json::to_value(ready()).unwrap();
        let policy = &mut wire["outcome"]["policy"];
        match field {
            "domain" => policy["station_policy"]["fingerprint"]["domain"] = "gate".into(),
            "selection" => policy["station_policy"]["fingerprint"]["selection"] = 7.into(),
            "schema" => policy["station_policy"]["fingerprint"]["schema_version"] = 2.into(),
            "digest" => policy["station_policy"]["fingerprint"]["sha256"] = "not-a-digest".into(),
            "outcome" => {
                policy["station_policy"]["comparison"] = "desktop-sacl-auto-inherited".into()
            }
            "missing" => {
                policy.as_object_mut().unwrap().remove("station_policy");
            }
            _ => unreachable!(),
        }
        let mut bytes = serde_json::to_vec(&wire).unwrap();
        bytes.push(b'\n');
        assert!(
            decode(&bytes, true).is_err(),
            "accepted invalid semantic {field}"
        );
    }
    let mut stale = ready();
    stale.schema_version = 1;
    assert!(holder_protocol::encode(&stale).is_err());
    let mut mismatch = ready();
    if let Outcome::Ready { policy } = &mut mismatch.outcome {
        policy.desktop_policy.comparison = ComparisonOutcome::DesktopSaclAutoInherited;
    }
    assert!(
        holder_protocol::encode(&mismatch).is_err(),
        "AI claim lacks matching observed control"
    );
}

#[test]
fn failure_retains_primary_native_cause_and_separate_cleanup_never_ready() {
    for observed in [None, Some(binding())] {
        let frame = failure(observed.clone());
        let bytes = holder_protocol::encode(&frame).unwrap();
        let parsed = decode(&bytes, true).unwrap().unwrap();
        assert_eq!(parsed.observed_request, observed);
        let Outcome::Failure {
            stage,
            operation,
            native_code,
            detail,
            cleanup,
        } = parsed.outcome
        else {
            panic!("failure cannot become ready")
        };
        assert_eq!(stage, Stage::WindowStation);
        assert_eq!(operation, "CreateWindowStationW");
        assert_eq!(native_code, Some(5));
        assert_eq!(detail, "Access denied");
        assert_eq!(cleanup, ["restore failed: 6"]);
    }
    let mut foreign = binding();
    foreign.diagnostic_id = "99".repeat(32);
    assert!(
        decode(
            &holder_protocol::encode(&failure(Some(foreign))).unwrap(),
            true
        )
        .is_err()
    );
}

#[test]
fn final_drain_preserves_complete_failure_but_missing_or_partial_evidence_stays_unknown() {
    let bytes = holder_protocol::encode(&failure(Some(binding()))).unwrap();
    let split = bytes.len() / 2;
    let mut captured = bytes[..split].to_vec();
    assert!(decode(&captured, false).unwrap().is_none());
    assert!(decode(&captured, true).is_err());
    captured.extend_from_slice(&bytes[split..]);
    assert!(matches!(
        decode(&captured, true).unwrap().unwrap().outcome,
        Outcome::Failure { .. }
    ));
    assert!(decode(&[], true).unwrap_err().contains("absent"));
    assert!(
        decode(b"not-json\n", true)
            .unwrap_err()
            .contains("malformed")
    );
}

#[test]
fn frame_and_total_transport_bounds_reject_overflow_concatenation_and_unknown_fields() {
    let mut bytes = holder_protocol::encode(&ready()).unwrap();
    bytes.extend_from_slice(b"\n");
    assert!(decode(&bytes, false).unwrap_err().contains("trailing"));
    let mut concatenated = holder_protocol::encode(&failure(None)).unwrap();
    concatenated.extend_from_slice(&holder_protocol::encode(&ready()).unwrap());
    assert!(decode(&concatenated, true).is_err());
    for length in [
        holder_protocol::MAX_FRAME_BYTES,
        holder_protocol::MAX_FRAME_BYTES + 1,
    ] {
        assert!(decode(&vec![b'x'; length], false).is_err());
    }
    for mutation in ["unknown", "version", "pid", "birth", "policy", "kind"] {
        let mut wire = serde_json::to_value(ready()).unwrap();
        match mutation {
            "unknown" => wire["unrecognized"] = true.into(),
            "version" => wire["schema_version"] = 1.into(),
            "pid" => wire["identity"]["process_id"] = 9.into(),
            "birth" => wire["identity"]["creation_time_100ns"] = 9.into(),
            "policy" => wire["outcome"]["policy"]["unexpected"] = true.into(),
            "kind" => wire["outcome"]["kind"] = "not-a-kind".into(),
            _ => unreachable!(),
        }
        let mut bytes = serde_json::to_vec(&wire).unwrap();
        bytes.push(b'\n');
        assert!(decode(&bytes, true).is_err(), "accepted {mutation}");
    }
    let wire = String::from_utf8(holder_protocol::encode(&ready()).unwrap()).unwrap();
    let duplicated = wire.replacen(
        "\"schema_version\":2",
        "\"schema_version\":2,\"schema_version\":2",
        1,
    );
    assert!(decode(duplicated.as_bytes(), true).is_err());
}

#[test]
fn bounded_failure_factory_truncates_unicode_explicitly_and_encode_still_enforces_wire_budget() {
    let huge = "🦀".repeat(4096);
    let frame = Frame::failure(
        identity(),
        None,
        Stage::Request,
        &huge,
        None,
        &huge,
        &vec![huge.clone(); 10],
    );
    let bytes = holder_protocol::encode(&frame).unwrap();
    assert!(bytes.len() <= holder_protocol::MAX_FRAME_BYTES);
    let parsed = decode(&bytes, true).unwrap().unwrap();
    let Outcome::Failure {
        operation,
        detail,
        cleanup,
        ..
    } = parsed.outcome
    else {
        unreachable!()
    };
    assert!(operation.ends_with("[truncated]") && detail.ends_with("[truncated]"));
    assert_eq!(cleanup.len(), 4);
    assert!(cleanup.last().unwrap().contains("additional cleanup"));
    let mut too_large = ready();
    if let Outcome::Ready { policy } = &mut too_large.outcome {
        policy.gate_sddl = "x".repeat(holder_protocol::MAX_FRAME_BYTES);
    }
    assert!(holder_protocol::encode(&too_large).is_err());
}

#[test]
fn source_failure_budget_counts_escaped_wire_bytes_without_losing_primary_fields() {
    let hostile = "\u{1}\n\"\\🦀".repeat(holder_protocol::MAX_FRAME_BYTES);
    let frame = Frame::failure(
        identity(),
        Some(binding()),
        Stage::Desktop,
        &hostile,
        Some(5),
        &hostile,
        &vec![hostile.clone(); 10],
    );
    let bytes = holder_protocol::encode(&frame).unwrap();
    assert!(bytes.len() <= holder_protocol::MAX_FRAME_BYTES);
    let parsed = decode(&bytes, true).unwrap().unwrap();
    let Outcome::Failure {
        stage,
        native_code,
        operation,
        detail,
        cleanup,
    } = parsed.outcome
    else {
        unreachable!()
    };
    assert_eq!(stage, Stage::Desktop);
    assert_eq!(native_code, Some(5));
    assert!(operation.ends_with("[truncated]") && detail.ends_with("[truncated]"));
    assert_eq!(cleanup.len(), 4);
    assert!(cleanup.last().unwrap().contains("additional cleanup"));
}

#[test]
fn actual_release_decision_never_treats_failure_or_retired_expired_ready_as_permission() {
    let ready = ready();
    assert!(holder_protocol::ready_policy(&ready, false, false).is_ok());
    for (ended, expired) in [(true, false), (false, true), (true, true)] {
        assert!(holder_protocol::ready_policy(&ready, ended, expired).is_err());
    }
    let failed = failure(Some(binding()));
    let original = holder_protocol::ready_policy(&failed, false, false).unwrap_err();
    assert!(
        original.contains("CreateWindowStationW")
            && original.contains("Some(5)")
            && original.contains("Access denied")
            && original.contains("restore failed: 6")
    );
    assert_eq!(
        holder_protocol::ready_policy(&failed, true, true).unwrap_err(),
        original
    );
}

#[cfg(windows)]
#[test]
fn real_child_exit_is_separate_from_stale_parent_last_error() {
    use std::{
        os::windows::io::AsRawHandle,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    use windows_sys::Win32::Foundation::{ERROR_INVALID_HANDLE, SetLastError};
    let mut child = Command::new(env!("CARGO_BIN_EXE_memcordon-windows-loader-lab"))
        .arg("--invalid-holder-protocol-test-option")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let cutoff = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert_eq!(status.code(), Some(2));
                break;
            }
            Ok(None) if Instant::now() < cutoff => std::thread::sleep(Duration::from_millis(5)),
            result => {
                let killed = child.kill();
                let settled = child.wait();
                panic!(
                    "bounded invalid-CLI child did not settle: {result:?}; kill={killed:?}; wait={settled:?}"
                );
            }
        }
    }
    unsafe {
        SetLastError(109);
    }
    assert_eq!(
        unsafe { holder_protocol::query_exit(child.as_raw_handle().cast()) }.unwrap(),
        2
    );
    unsafe {
        SetLastError(109);
    }
    let failed = unsafe { holder_protocol::query_exit(std::ptr::null_mut()) }.unwrap_err();
    assert_eq!(failed.native_code, ERROR_INVALID_HANDLE);
    assert!(failed.to_string().contains("GetExitCodeProcess"));
}
