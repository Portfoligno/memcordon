use memcordon_windows_loader_lab::helper_wait_protocol::*;

fn request() -> Request {
    Request {
        nonce: [1; 32],
        challenge_sha256: [2; 32],
        observer_sha256: [3; 32],
        helper_sha256: [4; 32],
        target_machine: 0xaa64,
        root: Identity {
            pid: 1,
            birth: u128::MAX,
        },
        compiler: Identity {
            pid: 2,
            birth: u128::from(u64::MAX) + 1,
        },
        helper: Identity { pid: 3, birth: 3 },
        helper_parent: Identity { pid: 4, birth: 4 },
        process_handle: 8,
        threads: vec![Thread {
            handle: 12,
            tid: 10,
            birth: 1,
        }],
        omitted_threads: 0,
        frequency: 1000,
        trigger_qpc: 100,
        launch_qpc: 200,
        work_cutoff_qpc: 1000,
        cleanup_cutoff_qpc: 2000,
    }
}
fn frame(request: &Request, sequence: u32, qpc: u64, result: ResultKind) -> Frame {
    Frame {
        binding: request.digest().unwrap(),
        sequence,
        qpc,
        result,
    }
}
fn result() -> ThreadResult {
    ThreadResult {
        ordinal: 0,
        lifecycle: ThreadLifecycle::QueriedLive,
        exit_status: None,
        tid: 10,
        birth: 1,
        before_qpc: 300,
        after_qpc: 400,
        binding_before: true,
        binding_after: true,
        cycle: Some(false),
        complete: true,
        native_error: None,
        reported_nodes: Some(1),
        nodes: vec![Node {
            object_type: 8,
            status: 3,
            process_id: 3,
            thread_id: 10,
            wait_time: 7,
            context_switches: 8,
        }],
    }
}
fn observer() -> Identity {
    Identity {
        pid: 50,
        birth: u128::MAX,
    }
}
fn sequence(request: &Request) -> Vec<Frame> {
    vec![
        frame(
            request,
            0,
            250,
            ResultKind::Begin {
                observer: observer(),
                threads: 1,
                omitted: 0,
            },
        ),
        frame(request, 1, 450, ResultKind::Thread(result())),
        frame(
            request,
            2,
            500,
            ResultKind::End {
                processed: 1,
                queried: 1,
                complete: true,
            },
        ),
    ]
}

#[test]
fn actual_codec_preserves_full_births_and_rejects_noncanonical_or_unbounded_requests() {
    let original = request();
    let bytes = original.encode().unwrap();
    assert_eq!(Request::decode(&bytes).unwrap(), original);
    for length in 0..bytes.len() {
        assert!(Request::decode(&bytes[..length]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Request::decode(&trailing).is_err());
    assert!(Request::decode(&vec![0; REQUEST_BOUND + 1]).is_err());
    let mut bad = original.clone();
    bad.threads = vec![bad.threads[0]; THREAD_BOUND + 1];
    assert!(bad.encode().is_err());
    let mut bad = original.clone();
    bad.threads.push(bad.threads[0]);
    assert!(bad.encode().is_err());
    let mut bad = original.clone();
    bad.process_handle = bad.threads[0].handle;
    assert!(bad.encode().is_err());
    let mut bad = original.clone();
    bad.launch_qpc = bad.work_cutoff_qpc;
    assert!(bad.encode().is_err());
    let mut bad = bytes;
    bad[std::mem::size_of_val(b"MCWCTREQ")] = u8::MAX;
    assert!(Request::decode(&bad).is_err());
}

#[test]
fn incremental_frames_require_exact_binding_order_birth_counts_and_original_cutoff() {
    let request = request();
    let records = sequence(&request);
    let mut stream = Stream::new(request.clone(), observer()).unwrap();
    for frame in &records {
        let bytes = frame.encode().unwrap();
        let admitted = stream.frames().len();
        for (offset, byte) in bytes.iter().enumerate() {
            stream.push(&[*byte], 600).unwrap();
            assert_eq!(
                stream.frames().len(),
                admitted + usize::from(offset + 1 == bytes.len())
            );
        }
    }
    stream.finish_input().unwrap();
    assert_eq!(stream.frames(), records);
    for mutate in 0..10 {
        let mut bad = records.clone();
        match mutate {
            0 => bad[0].binding[0] ^= 1,
            1 => bad[1].sequence = 0,
            2 => {
                if let ResultKind::Thread(ref mut t) = bad[1].result {
                    t.birth += 1
                }
            }
            3 => {
                if let ResultKind::Thread(ref mut t) = bad[1].result {
                    t.after_qpc = t.before_qpc - 1
                }
            }
            4 => {
                if let ResultKind::Thread(ref mut t) = bad[1].result {
                    t.binding_after = false
                }
            }
            5 => {
                bad[2].result = ResultKind::End {
                    processed: 0,
                    queried: 0,
                    complete: true,
                }
            }
            6 => bad[0].qpc = request.work_cutoff_qpc,
            7 => {
                bad[0].result = ResultKind::Begin {
                    observer: observer(),
                    threads: 1,
                    omitted: 1,
                }
            }
            8 => {
                if let ResultKind::Thread(ref mut t) = bad[1].result {
                    t.nodes.clear();
                    t.reported_nodes = Some(0);
                }
            }
            _ => {
                if let ResultKind::Begin {
                    ref mut observer, ..
                } = bad[0].result
                {
                    observer.birth -= 1;
                }
            }
        }
        let mut stream = Stream::new(request.clone(), observer()).unwrap();
        assert!(bad.iter().any(|f| {
            stream
                .push(&f.encode().unwrap(), request.work_cutoff_qpc - 1)
                .is_err()
        }));
        assert!(stream.finish_input().is_err());
    }
    let mut stream = Stream::new(request.clone(), observer()).unwrap();
    assert!(
        stream
            .push(&records[0].encode().unwrap(), request.work_cutoff_qpc)
            .is_err()
    );
    let mut changed = request.clone();
    changed.observer_sha256[0] ^= 1;
    let mut stream = Stream::new(changed, observer()).unwrap();
    assert!(stream.push(&records[0].encode().unwrap(), 600).is_err());
    let mut stream = Stream::new(request.clone(), observer()).unwrap();
    assert!(stream.push(&vec![0; OUTPUT_BOUND + 1], 600).is_err());
    let mut stream = Stream::new(request, observer()).unwrap();
    assert!(stream.push(&u32::MAX.to_le_bytes(), 600).is_err());
}

#[test]
fn failed_query_never_exposes_initialized_count_or_cycle_as_valid_output() {
    let request = request();
    let mut records = sequence(&request);
    let ResultKind::Thread(ref mut value) = records[1].result else {
        panic!("thread fixture")
    };
    value.complete = false;
    value.native_error = Some(5);
    value.nodes.clear();
    value.reported_nodes = None;
    value.cycle = None;
    records[2].result = ResultKind::End {
        processed: 1,
        queried: 1,
        complete: false,
    };
    let mut stream = Stream::new(request.clone(), observer()).unwrap();
    for frame in &records {
        stream.push(&frame.encode().unwrap(), 600).unwrap();
    }
    stream.finish_input().unwrap();
    let ResultKind::Thread(ref mut value) = records[1].result else {
        panic!("thread fixture")
    };
    value.reported_nodes = Some(16);
    value.cycle = Some(false);
    let mut stream = Stream::new(request, observer()).unwrap();
    stream.push(&records[0].encode().unwrap(), 600).unwrap();
    assert!(stream.push(&records[1].encode().unwrap(), 600).is_err());
}

#[test]
fn refusal_partial_and_omitted_results_never_claim_complete_observation() {
    let mut request = request();
    request.omitted_threads = 1;
    let mut stream = Stream::new(request.clone(), observer()).unwrap();
    let records = [
        frame(
            &request,
            0,
            250,
            ResultKind::Begin {
                observer: observer(),
                threads: 1,
                omitted: 1,
            },
        ),
        frame(
            &request,
            1,
            300,
            ResultKind::Refused {
                stage: Stage::Privilege,
                native_error: Some(5),
                binding_failure: None,
            },
        ),
        frame(
            &request,
            2,
            400,
            ResultKind::End {
                processed: 0,
                queried: 0,
                complete: false,
            },
        ),
    ];
    for frame in &records {
        stream.push(&frame.encode().unwrap(), 600).unwrap();
    }
    stream.finish_input().unwrap();
    let mut partial = Stream::new(request, observer()).unwrap();
    let bytes = records[0].encode().unwrap();
    partial.push(&bytes[..bytes.len() - 1], 600).unwrap();
    assert!(partial.finish_input().is_err());
    let mut bad = result();
    bad.nodes[0].object_type = u32::MAX;
    assert!(
        frame(&self::request(), 0, 250, ResultKind::Thread(bad))
            .encode()
            .is_err()
    );
}

fn three_threads() -> Request {
    let mut request = request();
    request.threads.extend([
        Thread {
            handle: 16,
            tid: 11,
            birth: 2,
        },
        Thread {
            handle: 20,
            tid: 12,
            birth: 3,
        },
    ]);
    request
}

fn exited_sequence(request: &Request) -> Vec<Frame> {
    let mut first = sequence(request).remove(0);
    first.result = ResultKind::Begin {
        observer: observer(),
        threads: 3,
        omitted: 0,
    };
    let exited = ThreadResult {
        ordinal: 1,
        lifecycle: ThreadLifecycle::ExitedBeforeQuery,
        exit_status: Some(23),
        tid: 11,
        birth: 2,
        before_qpc: 460,
        after_qpc: 470,
        binding_before: false,
        binding_after: false,
        cycle: None,
        complete: false,
        native_error: None,
        reported_nodes: None,
        nodes: Vec::new(),
    };
    let mut last = result();
    last.ordinal = 2;
    last.tid = 12;
    last.birth = 3;
    last.before_qpc = 490;
    last.after_qpc = 500;
    last.nodes[0].thread_id = 12;
    vec![
        first,
        frame(request, 1, 450, ResultKind::Thread(result())),
        frame(request, 2, 480, ResultKind::Thread(exited)),
        frame(request, 3, 510, ResultKind::Thread(last)),
        frame(
            request,
            4,
            520,
            ResultKind::End {
                processed: 3,
                queried: 2,
                complete: false,
            },
        ),
    ]
}

fn admitted(request: &Request, frames: &[Frame]) -> std::io::Result<Stream> {
    let mut stream = Stream::new(request.clone(), observer())?;
    for frame in frames {
        stream.push(&frame.encode()?, 900)?;
    }
    stream.finish_input()?;
    Ok(stream)
}

#[test]
fn exact_exited_original_thread_is_one_incomplete_outcome_between_live_queries() {
    let request = three_threads();
    let frames = exited_sequence(&request);
    let stream = admitted(&request, &frames).unwrap();
    assert_eq!(stream.frames(), frames);
    for change in [
        |frames: &mut Vec<Frame>| {
            if let ResultKind::Thread(thread) = &mut frames[2].result {
                thread.ordinal = 2;
            }
        },
        |frames: &mut Vec<Frame>| {
            if let ResultKind::Thread(thread) = &mut frames[2].result {
                thread.tid = 12;
            }
        },
        |frames: &mut Vec<Frame>| {
            if let ResultKind::Thread(thread) = &mut frames[2].result {
                thread.birth = 3;
            }
        },
        |frames: &mut Vec<Frame>| {
            if let ResultKind::Thread(thread) = &mut frames[2].result {
                thread.exit_status = None;
            }
        },
        |frames: &mut Vec<Frame>| {
            if let ResultKind::Thread(thread) = &mut frames[2].result {
                thread.reported_nodes = Some(0);
            }
        },
        |frames: &mut Vec<Frame>| {
            if let ResultKind::Thread(thread) = &mut frames[2].result {
                thread.binding_before = true;
            }
        },
        |frames: &mut Vec<Frame>| {
            if let ResultKind::Thread(thread) = &mut frames[2].result {
                thread.complete = true;
            }
        },
        |frames: &mut Vec<Frame>| {
            if let ResultKind::Thread(thread) = &mut frames[2].result {
                thread.after_qpc = 459;
            }
        },
        |frames: &mut Vec<Frame>| {
            frames[4].result = ResultKind::End {
                processed: 3,
                queried: 3,
                complete: false,
            }
        },
        |frames: &mut Vec<Frame>| {
            frames[4].result = ResultKind::End {
                processed: 3,
                queried: 2,
                complete: true,
            }
        },
    ] {
        let mut changed = frames.clone();
        change(&mut changed);
        assert!(admitted(&request, &changed).is_err());
    }
    let mut unknown = frames[2].encode().unwrap();
    let word = size_of::<u32>();
    let lifecycle_offset = word
        + b"MCWCTRES".len()
        + word
        + frames[2].binding.len()
        + word
        + size_of::<u64>()
        + word
        + word;
    unknown[lifecycle_offset..lifecycle_offset + word].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(Frame::decode(&unknown[word..]).is_err());
}

#[test]
fn exited_after_query_invalidates_causal_binding_and_cannot_claim_complete() {
    let request = request();
    let mut frames = sequence(&request);
    let ResultKind::Thread(thread) = &mut frames[1].result else {
        panic!("thread fixture");
    };
    thread.lifecycle = ThreadLifecycle::ExitedAfterQuery;
    thread.exit_status = Some(0);
    thread.binding_after = false;
    thread.complete = false;
    frames[2].result = ResultKind::End {
        processed: 1,
        queried: 1,
        complete: false,
    };
    admitted(&request, &frames).unwrap();
    frames[2].result = ResultKind::End {
        processed: 1,
        queried: 1,
        complete: true,
    };
    assert!(admitted(&request, &frames).is_err());
}

#[test]
fn precise_binding_refusal_keeps_prior_query_and_never_skips_unknown_failure() {
    let request = three_threads();
    let failure = BindingFailure {
        scope: BindingScope::Thread,
        boundary: BindingBoundary::BeforeQuery,
        operation: BindingOperation::GetTimes,
        reason: BindingReason::NativeError,
        ordinal: Some(1),
        expected: BindingIdentity {
            pid: Some(3),
            tid: Some(11),
            birth: Some(2),
        },
        observed: BindingIdentity {
            pid: Some(3),
            tid: Some(11),
            birth: None,
        },
        wait_status: None,
        native_error: Some(5),
        before_qpc: 460,
        after_qpc: 470,
    };
    let original = exited_sequence(&request);
    let make = |failure: BindingFailure| {
        vec![
            original[0].clone(),
            original[1].clone(),
            frame(
                &request,
                2,
                480,
                ResultKind::Refused {
                    stage: Stage::Binding,
                    native_error: failure.native_error,
                    binding_failure: Some(failure),
                },
            ),
            frame(
                &request,
                3,
                490,
                ResultKind::End {
                    processed: 1,
                    queried: if failure.boundary == BindingBoundary::AfterQuery {
                        2
                    } else {
                        1
                    },
                    complete: false,
                },
            ),
        ]
    };
    let stream = admitted(&request, &make(failure)).unwrap();
    assert_eq!(stream.frames()[1], original[1]);
    for change in [
        |failure: &mut BindingFailure| failure.ordinal = Some(2),
        |failure: &mut BindingFailure| failure.expected.birth = Some(u128::MAX),
        |failure: &mut BindingFailure| failure.native_error = None,
        |failure: &mut BindingFailure| failure.reason = BindingReason::IdentityMismatch,
        |failure: &mut BindingFailure| failure.reason = BindingReason::Exited,
        |failure: &mut BindingFailure| failure.after_qpc = 459,
    ] {
        let mut changed = failure;
        change(&mut changed);
        assert!(admitted(&request, &make(changed)).is_err());
    }
    let mut after = failure;
    after.boundary = BindingBoundary::AfterQuery;
    admitted(&request, &make(after)).unwrap();
    let mut mismatch = failure;
    mismatch.reason = BindingReason::IdentityMismatch;
    mismatch.operation = BindingOperation::CompareIdentity;
    mismatch.native_error = None;
    mismatch.observed.birth = Some(3);
    admitted(&request, &make(mismatch)).unwrap();
    let mut process = failure;
    process.scope = BindingScope::Process;
    process.expected = BindingIdentity {
        pid: Some(3),
        tid: None,
        birth: Some(3),
    };
    process.observed = process.expected;
    process.reason = BindingReason::Exited;
    process.operation = BindingOperation::Wait;
    process.wait_status = Some(0);
    process.native_error = None;
    admitted(&request, &make(process)).unwrap();
    let mut frames = make(failure);
    frames.insert(3, frame(&request, 3, 485, ResultKind::Thread(result())));
    assert!(admitted(&request, &frames).is_err());
}
