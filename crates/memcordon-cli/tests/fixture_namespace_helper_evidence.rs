#[path = "private/fixture_namespace_helper_evidence.rs"]
pub mod evidence;
#[path = "private/fixture_namespace_hit_receipt.rs"]
pub mod hit_receipt;
#[path = "private/fixture_namespace_debug_profile.rs"]
pub mod profile;
use evidence::*;
use hit_receipt::{Metadata, Receipt};
use profile::{DebugRegisters, Stop};
use std::{collections::BTreeMap, io};

fn stop() -> Stop {
    Stop {
        pid: 7,
        tid: 9,
        exception: profile::SINGLE_STEP,
        first_chance: true,
        exception_address: 1,
        rip: 1,
        registers: DebugRegisters {
            dr: [0; 4],
            dr6: 1,
            dr7: 0x401,
            eflags: 0x246,
        },
        rax: 0,
        r14: 0,
        rbx: 0,
        rcx: 0x100,
        rdx: 12,
        r8: 0x200,
        r9: 4,
        rsp: 0x1000,
    }
}
fn memory(map: &BTreeMap<u64, Vec<u8>>, address: u64, size: usize) -> io::Result<Vec<u8>> {
    map.get(&address)
        .filter(|bytes| bytes.len() >= size)
        .map(|bytes| bytes[..size].to_vec())
        .ok_or_else(|| io::Error::from_raw_os_error(299))
}
fn oa(name_len: u16, max_len: u16) -> BTreeMap<u64, Vec<u8>> {
    let mut attributes = vec![0; 48];
    attributes[..4].copy_from_slice(&48u32.to_le_bytes());
    attributes[8..16].copy_from_slice(&0xabcdu64.to_le_bytes());
    attributes[16..24].copy_from_slice(&0x300u64.to_le_bytes());
    attributes[24..28].copy_from_slice(&0x40u32.to_le_bytes());
    attributes[32..40].copy_from_slice(&u64::MAX.to_le_bytes()); // Never dereferenced.
    let mut descriptor = vec![0; 16];
    descriptor[..2].copy_from_slice(&name_len.to_le_bytes());
    descriptor[2..4].copy_from_slice(&max_len.to_le_bytes());
    descriptor[8..16].copy_from_slice(&0x400u64.to_le_bytes());
    BTreeMap::from([
        (0x200, attributes),
        (0x300, descriptor),
        (0x400, vec![0x5c, 0, 0x41, 0]),
    ])
}

#[test]
fn public_oa_capture_preserves_exact_utf16_and_opaque_root_only() {
    let map = oa(4, 6);
    let value = MemoryBudget::default()
        .object_attributes(0x200, &mut |a, n| memory(&map, a, n))
        .unwrap();
    assert_eq!(value.root_handle, 0xabcd);
    assert_eq!(value.attributes, 0x40);
    assert_eq!(value.security_descriptor_pointer, u64::MAX);
    assert_eq!(value.name.unwrap().utf16_le_hex, "5c004100");
    let mut null_name = oa(0, 0);
    null_name.get_mut(&0x200).unwrap()[16..24].fill(0);
    assert!(
        MemoryBudget::default()
            .object_attributes(0x200, &mut |a, n| memory(&null_name, a, n))
            .unwrap()
            .name
            .is_none()
    );
}

#[test]
fn remote_structure_failures_are_explicit_and_never_empty_success() {
    assert_eq!(
        CaptureError::Read(Some(299)).io_error().kind(),
        io::ErrorKind::Other
    );
    for (len, max, error) in [
        (3, 4, CaptureError::OddUnicode),
        (4, 3, CaptureError::OddUnicode),
        (6, 4, CaptureError::InvalidLength),
        (514, 514, CaptureError::InvalidLength),
    ] {
        let map = oa(len, max);
        assert_eq!(
            MemoryBudget::default()
                .object_attributes(0x200, &mut |a, n| memory(&map, a, n))
                .unwrap_err(),
            error
        );
    }
    let map = oa(4, 4);
    assert_eq!(
        MemoryBudget::default()
            .object_attributes(0, &mut |a, n| memory(&map, a, n))
            .unwrap_err(),
        CaptureError::Null
    );
    assert_eq!(
        MemoryBudget::default()
            .object_attributes(u64::MAX, &mut |a, n| memory(&map, a, n))
            .unwrap_err(),
        CaptureError::Overflow
    );
    assert_eq!(
        MemoryBudget::default()
            .object_attributes(0x200, &mut |_, _| Ok(vec![0]))
            .unwrap_err(),
        CaptureError::Partial
    );
    assert_eq!(
        MemoryBudget::default()
            .object_attributes(0x200, &mut |_, _| Err(io::Error::from_raw_os_error(299)))
            .unwrap_err(),
        CaptureError::Read(Some(299))
    );
    let mut null_buffer = oa(4, 4);
    null_buffer.get_mut(&0x300).unwrap()[8..16].fill(0);
    assert_eq!(
        MemoryBudget::default()
            .object_attributes(0x200, &mut |a, n| memory(&null_buffer, a, n))
            .unwrap_err(),
        CaptureError::Null
    );
}

#[test]
fn failed_directory_attempt_then_success_keeps_order_and_only_valid_output() {
    let mut trace = Trace::default();
    let mut map = oa(4, 4);
    map.insert(0x100, 0x777u64.to_le_bytes().to_vec());
    let mut raw = stop();
    raw.rdx = 0xf;
    let before = trace
        .operands(0x867cf, raw, &mut |a, n| memory(&map, a, n))
        .unwrap()
        .unwrap();
    match before {
        Operands::Before(input) => {
            assert_eq!(input.args[1], 0xf);
            assert!(input.fifth_argument.is_none());
        }
        _ => panic!("before call"),
    }
    raw.rax = 0xfeed0000c0000022;
    raw.rcx = u64::MAX; // Volatile post-call RCX is not reused.
    let failed = trace
        .operands(0x867d6, raw, &mut |_, _| {
            panic!("failed output must not be read")
        })
        .unwrap()
        .unwrap();
    match failed {
        Operands::After(output) => {
            assert_eq!(output.status, Some(0xc0000022u32 as i32));
            assert!(output.successful_output_handle.is_none());
        }
        _ => panic!("after call"),
    }
    raw = stop();
    raw.rdx = 2;
    trace
        .operands(0x8687a, raw, &mut |a, n| memory(&map, a, n))
        .unwrap();
    raw.rax = 0;
    let recovered = trace
        .operands(0x86881, raw, &mut |a, n| memory(&map, a, n))
        .unwrap()
        .unwrap();
    match recovered {
        Operands::After(output) => assert_eq!(output.successful_output_handle, Some(0x777)),
        _ => panic!("after fallback"),
    }
    map.get_mut(&0x200).unwrap()[8..16].copy_from_slice(&0x777u64.to_le_bytes());
    raw.rdx = 0xf;
    let child = trace
        .operands(0x86b2d, raw, &mut |a, n| memory(&map, a, n))
        .unwrap()
        .unwrap();
    match child {
        Operands::Before(input) => assert_eq!(input.object_attributes.unwrap().root_handle, 0x777),
        _ => panic!("child input"),
    }
}

#[test]
fn token_scalar_uses_precall_fifth_argument_and_both_output_bounds() {
    let mut map = BTreeMap::from([
        (0x1020, 0x500u64.to_le_bytes().to_vec()),
        (0x500, 4u32.to_le_bytes().to_vec()),
        (0x200, 9u32.to_le_bytes().to_vec()),
    ]);
    let mut trace = Trace::default();
    let mut raw = stop();
    trace
        .operands(0x8653f, raw, &mut |a, n| memory(&map, a, n))
        .unwrap();
    raw.rcx = u64::MAX;
    raw.r8 = u64::MAX;
    raw.r9 = 0;
    raw.rax = 0;
    let after = trace
        .operands(0x86546, raw, &mut |a, n| memory(&map, a, n))
        .unwrap()
        .unwrap();
    match after {
        Operands::After(output) => {
            assert_eq!(output.scalar, Some(9));
            assert_eq!(output.observed_return_length, Some(4));
        }
        _ => panic!("paired scalar"),
    }
    map.insert(0x500, 8u32.to_le_bytes().to_vec());
    let mut trace = Trace::default();
    raw = stop();
    trace
        .operands(0x8653f, raw, &mut |a, n| memory(&map, a, n))
        .unwrap();
    assert_eq!(
        trace
            .operands(0x86546, raw, &mut |a, n| memory(&map, a, n))
            .unwrap_err(),
        CaptureError::InvalidLength
    );
    assert_eq!(trace.failure, Some((0x86546, CaptureError::InvalidLength)));
    let mut trace = Trace::default();
    raw = stop();
    raw.rdx = 42;
    trace
        .operands(0x8659c, raw, &mut |a, n| memory(&map, a, n))
        .unwrap();
    let output = trace
        .operands(0x865a3, raw, &mut |a, n| memory(&map, a, n))
        .unwrap()
        .unwrap();
    match output {
        Operands::After(output) => assert!(output.scalar.is_none()),
        _ => panic!("reserved content unobserved"),
    }
}

#[test]
fn pointer_void_returns_are_not_status_and_call_pairs_cannot_skip() {
    let mut trace = Trace::default();
    let mut raw = stop();
    trace
        .operands(0x864de, raw, &mut |_, _| panic!("no unrelated reads"))
        .unwrap();
    raw.rax = u64::MAX;
    let after = trace
        .operands(0x864e3, raw, &mut |_, _| panic!("no output decode"))
        .unwrap()
        .unwrap();
    match after {
        Operands::After(output) => assert!(output.status.is_none()),
        _ => panic!("pointer/void"),
    }
    assert_eq!(
        trace
            .operands(0x86546, raw, &mut |_, _| panic!("no unmatched read"))
            .unwrap_err(),
        CaptureError::PairMismatch
    );
}

fn unpack(encoded: &str) -> Vec<u64> {
    let bytes = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap());
    let (mut value, mut shift) = (0u64, 0);
    let mut values = Vec::new();
    for byte in bytes {
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            values.push(value);
            value = 0;
            shift = 0;
        } else {
            shift += 7;
        }
    }
    assert_eq!(shift, 0);
    values
}
#[test]
fn packed_raw_inputs_roundtrip_all_bits_and_budget_exhaustion_is_explicit() {
    assert_eq!(
        unpack(&pack(&[0, 1, u64::MAX, 1 << 63])),
        vec![0, 1, u64::MAX, 1 << 63]
    );
    let metadata = Metadata {
        event_ordinal: usize::MAX,
        flags: u32::MAX,
        first_chance: u32::MAX,
        received_qpc: Some(u64::MAX),
    };
    let mut raw = stop();
    raw.rax = u64::MAX;
    raw.r14 = 1 << 63;
    raw.rbx = u64::MAX - 1;
    let receipt = Receipt::capture(metadata, raw, None);
    let mut trace = Trace::default();
    let index = trace
        .record(0x86450, 1, &receipt, raw.registers, None)
        .unwrap();
    trace.readback(index, raw.registers, raw.registers, true);
    assert_eq!(unpack(&trace.records[0].2), raw_values(metadata, raw));
    for ordinal in 1..profile::helper_profile::MAX_CHECKPOINT_STOPS {
        let mut receipt = receipt.clone();
        receipt.metadata.event_ordinal = ordinal;
        trace
            .record(0x86450, 0, &receipt, raw.registers, None)
            .unwrap();
    }
    assert_eq!(
        trace
            .record(0x86450, 0, &receipt, raw.registers, None)
            .unwrap_err(),
        CaptureError::TraceBudget
    );
    assert_eq!(trace.omitted, 1);
    assert!(serde_json::to_vec(&trace).unwrap().len() <= TRACE_BYTES);
    let map = oa(4, 4);
    let mut budget = MemoryBudget::default();
    let mut exhausted = false;
    for _ in 0..MEMORY_BYTES {
        if budget
            .object_attributes(0x200, &mut |a, n| memory(&map, a, n))
            .is_err()
        {
            exhausted = true;
            break;
        }
    }
    assert!(exhausted);
}

#[test]
fn worst_case_combined_report_keeps_raw_rejection_trace_and_cleanup_within_64k() {
    let mut raw = stop();
    raw.pid = u32::MAX;
    raw.tid = u32::MAX;
    raw.exception = u32::MAX;
    raw.exception_address = u64::MAX;
    raw.rip = u64::MAX;
    raw.registers = DebugRegisters {
        dr: [u64::MAX; 4],
        dr6: u64::MAX,
        dr7: u64::MAX,
        eflags: u32::MAX,
    };
    raw.rax = u64::MAX;
    raw.r14 = u64::MAX;
    raw.rbx = u64::MAX;
    raw.rcx = u64::MAX;
    raw.rdx = u64::MAX;
    raw.r8 = u64::MAX;
    raw.r9 = u64::MAX;
    raw.rsp = u64::MAX;
    let saved = DebugRegisters {
        dr: [u64::MAX; 4],
        dr6: !(0xf | (7 << 13)),
        dr7: !(0xff | (1 << 13)),
        eflags: !(1 << 8),
    };
    let planner = profile::Planner::arm(
        saved,
        u64::MAX - u64::from(profile::SIZE_OF_IMAGE) - 4096,
        u32::MAX,
        u32::MAX,
    )
    .unwrap();
    let metadata = Metadata {
        event_ordinal: usize::MAX,
        flags: u32::MAX,
        first_chance: u32::MAX,
        received_qpc: Some(u64::MAX),
    };
    let mut receipt = Receipt::capture(metadata, raw, Some(&planner));
    receipt.readback = Some(raw.registers);
    receipt.registers_after = Some(raw.registers);
    receipt.observation = Some(profile::Observation {
        site: profile::Site::DirectoryInitializationReturn,
        status: Some(i32::MIN),
        slot: usize::MAX,
    });
    receipt.initializer_planned = Some(hit_receipt::InitializerFacts {
        source: Some(profile::Site::DirectoryInitializationReturn.name()),
        status: Some(i32::MIN),
        thread_token_cleared: true,
    });
    receipt.state_after = Some(profile::State::AwaitRestoreThreadToken);
    receipt.stage = hit_receipt::ReceiptStage::EntryArguments;
    let selected = profile::helper_profile::Selected {
        raw_rbx: u64::MAX,
        status: i32::MIN,
        source: profile::helper_profile::Source::Call {
            call: u32::MAX,
            returned: u32::MAX,
        },
    };
    let expected = receipt.expected.as_mut().unwrap();
    expected.state = profile::State::AwaitRestoreThreadToken;
    expected.addresses = std::array::from_fn(|slot| {
        Some(profile::ExpectedSite {
            site: profile::Site::DirectoryInitializationReturn.name(),
            slot,
            rva: u32::MAX,
            address: Some(u64::MAX),
        })
    });
    expected.helper_selected = Some(selected);
    expected.initializer_source = Some(profile::Site::DirectoryInitializationReturn.name());
    expected.initializer_status = Some(i32::MIN);
    expected.thread_token_cleared = true;
    let mut outer = hit_receipt::Receipts::default();
    for _ in 0..hit_receipt::ACCEPTED_STAGE_LIMIT {
        let mut accepted = receipt.clone();
        accepted.transition_verified = true;
        outer.record(accepted);
    }
    receipt.failed = true;
    receipt.rejection = Some(profile::HitRejection::ControlRegister);
    outer.record(receipt.clone());
    let mut trace = Trace::default();
    for index in 0..profile::helper_profile::MAX_CHECKPOINT_STOPS {
        // Maximal-width alternating data defeats the previous-register delta.
        let mut noisy = receipt.clone();
        if index % 2 != 0 {
            for value in [
                &mut noisy.raw.rax,
                &mut noisy.raw.r14,
                &mut noisy.raw.rbx,
                &mut noisy.raw.rcx,
                &mut noisy.raw.rdx,
                &mut noisy.raw.r8,
                &mut noisy.raw.r9,
                &mut noisy.raw.rsp,
            ] {
                *value = 0;
            }
            noisy.raw.registers = DebugRegisters {
                dr: [0; 4],
                dr6: 0,
                dr7: 0,
                eflags: 0,
            };
        }
        match trace.record(0x86450, index % 2, &noisy, raw.registers, None) {
            Ok(record) => trace.readback(record, raw.registers, raw.registers, true),
            Err(CaptureError::TraceBudget) => break,
            Err(error) => panic!("unexpected {error:?}"),
        }
    }
    assert_eq!(trace.failure, Some((0x86450, CaptureError::TraceBudget)));
    assert!(serde_json::to_vec(&trace).unwrap().len() > TRACE_BYTES - 2048);
    let mut trace = serde_json::to_value(trace).unwrap();
    // Reserve the complete production trace budget, including its unused tail.
    trace["reserved_capacity"] = serde_json::json!("");
    let remaining = TRACE_BYTES - serde_json::to_vec(&trace).unwrap().len();
    trace["reserved_capacity"] = serde_json::json!("x".repeat(remaining));
    assert_eq!(serde_json::to_vec(&trace).unwrap().len(), TRACE_BYTES);
    let registers = serde_json::json!({"dr0_dr3":([u64::MAX;4]),"dr6":u64::MAX,"dr7":u64::MAX,"eflags":u32::MAX});
    let call_window = serde_json::json!({"state":"Complete","api":u64::MAX,"result":u64::MAX,"pre":{"pid":u32::MAX,"tid":u32::MAX,"received_qpc":u64::MAX,"api":u64::MAX,"before":registers,"planned":registers,"readback":registers,"expected_entry":u64::MAX,"verified":true},"post":{"pid":u32::MAX,"tid":u32::MAX,"received_qpc":u64::MAX,"api":u64::MAX,"result":u64::MAX,"before_restore":registers,"expected":registers,"planner_state":"AwaitRestoreThreadToken","restore_readback":registers,"restored":true,"intact":true}});
    let mut policy = serde_json::json!({"handles_released":true,"raw_candidate_capacity":""});
    policy["raw_candidate_capacity"] = serde_json::json!(
        "x".repeat(DIRECTORY_POLICY_BYTES - serde_json::to_vec(&policy).unwrap().len())
    );
    assert_eq!(
        serde_json::to_vec(&policy).unwrap().len(),
        DIRECTORY_POLICY_BYTES
    );
    let report = serde_json::json!({"original_failure":{"raw_error":5,"full_record":"original-before-debug-replay.json"},"diagnostic_only":true,"acceptance_authority":false,"hit_receipts":outer,"helper_trace":trace,"helper_selected":selected,"call_window":call_window,"session_directory_policy":policy,"cleanup_complete":true,"restore_verified":true,"exit_continued":true,"process_wait_observed":true,"reader_joined":true,"watchdog_joined":true,"provider_guards_released":true,"capture_finished_qpc":u64::MAX,"original_cutoff_qpc":u64::MAX,"diagnostic_stop_qpc":u64::MAX,"host_profile":{"bounded_metadata":"x".repeat(40000)},"events":[],"replay_result":{"opened":false,"error":5}});
    let fitted = fit_report(report).unwrap();
    assert!(serde_json::to_vec(&fitted).unwrap().len() < 64 * 1024);
    assert_eq!(fitted["original_failure"]["raw_error"], 5);
    assert_eq!(
        fitted["hit_receipts"]["first_rejected"]["raw"]["rbx"],
        u64::MAX
    );
    assert_eq!(
        fitted["hit_receipts"]["accepted_stages"]
            .as_array()
            .unwrap()
            .len(),
        hit_receipt::ACCEPTED_STAGE_LIMIT
    );
    assert!(
        !fitted["helper_trace"]["records"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(fitted["cleanup_complete"], true);
    assert_eq!(fitted["session_directory_policy"]["handles_released"], true);
    assert_eq!(fitted["call_window"]["post"]["restored"], true);
    assert_eq!(fitted["capture_evidence_complete"], false);
    assert_eq!(
        fitted["record_budget"]["omitted_summaries"][0]["field"],
        "host_profile"
    );
}
