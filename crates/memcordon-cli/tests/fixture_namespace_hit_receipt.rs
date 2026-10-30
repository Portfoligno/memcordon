#[path = "private/fixture_namespace_hit_receipt.rs"]
pub mod hit_receipt;
#[path = "private/fixture_namespace_debug_profile.rs"]
pub mod profile;

use hit_receipt::*;
use profile::*;

fn capture(planner: &Planner, site: Site, ordinal: usize, status: u32) -> Receipt {
    let mut registers = planner.registers();
    let slot = if site == Site::DirectoryInitializationReturn && planner.state() == State::InHelper
    {
        2
    } else {
        site.slot()
    };
    registers.dr6 |= 1 << slot;
    let address = site_address(0x180000000, site).unwrap();
    Receipt::capture(
        Metadata {
            event_ordinal: ordinal,
            flags: 0,
            first_chance: 1,
            received_qpc: Some(100),
        },
        Stop {
            pid: 7,
            tid: 9,
            exception: SINGLE_STEP,
            first_chance: true,
            exception_address: address,
            rip: address,
            registers,
            rax: 0xfeed000000000000 | u64::from(status),
            r14: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            r8: 0,
            r9: 0,
            rsp: 0,
        },
        Some(planner),
    )
}

fn planner() -> Planner {
    Planner::arm(
        DebugRegisters {
            dr: [0; 4],
            dr6: 0,
            dr7: 0,
            eflags: 0x204,
        },
        0x180000000,
        7,
        9,
    )
    .unwrap()
}

fn helper_trace(planner: &mut Planner, status: u32) {
    fn distance(rva: u32) -> usize {
        let node = helper_profile::checkpoint(rva).unwrap();
        if node.kind == "selected-ebx" {
            0
        } else {
            1 + node
                .successors
                .iter()
                .map(|rva| distance(*rva))
                .min()
                .unwrap()
        }
    }
    while planner
        .snapshot(planner.registers())
        .helper_selected
        .is_none()
    {
        let expected = planner.snapshot(planner.registers());
        let site = expected.addresses[..2]
            .iter()
            .flatten()
            .min_by_key(|site| distance(site.rva))
            .unwrap();
        let mut receipt = capture(
            planner,
            Site::Helper {
                rva: site.rva,
                slot: site.slot,
            },
            0,
            status,
        );
        receipt.raw.rbx = u64::from(status);
        planner.on_hit(receipt.raw).unwrap();
    }
}

#[test]
fn all_initializer_stages_keep_raw_returns_and_ignored_restore_separate() {
    let mut planner = planner();
    let mut receipts = Receipts::default();
    for (ordinal, site) in [
        Site::Entry,
        Site::InitEnter,
        Site::ThreadTokenReturn,
        Site::ClearThreadTokenReturn,
        Site::ProcessTokenReturn,
        Site::DirectoryInitializationReturn,
        Site::RestoreThreadTokenReturn,
        Site::Initialization,
        Site::Native,
    ]
    .into_iter()
    .enumerate()
    {
        let status = if site == Site::RestoreThreadTokenReturn {
            0xc0000022
        } else {
            0
        };
        if site == Site::DirectoryInitializationReturn {
            helper_trace(&mut planner, status);
        }
        let mut receipt = capture(&planner, site, ordinal, status);
        receipt.observation = Some(planner.on_hit(receipt.raw).unwrap());
        let after = planner.snapshot(planner.registers());
        receipt.initializer_planned = Some(InitializerFacts {
            source: after.initializer_source,
            status: after.initializer_status,
            thread_token_cleared: after.thread_token_cleared,
        });
        receipt.admitted = true;
        receipt.transition_attempted = true;
        receipt.transition_verified = true;
        receipt.stage = ReceiptStage::Complete;
        receipt.state_after = Some(planner.state());
        receipt.registers_after = Some(planner.registers());
        receipts.record(receipt);
    }
    assert_eq!(receipts.accepted_stages.len(), Site::ALL.len());
    assert_eq!(receipts.omitted, 0);
    assert_eq!(receipts.accepted, Site::ALL.len());
    let restore = &receipts.accepted_stages[6];
    assert_eq!(restore.raw.rax, 0xfeed0000c0000022);
    assert_eq!(
        restore.observation.unwrap().status,
        Some(0xc0000022u32 as i32)
    );
    assert_eq!(restore.initializer_planned.unwrap().status, Some(0));
    assert_eq!(
        restore.initializer_planned.unwrap().source,
        Some(Site::DirectoryInitializationReturn.name())
    );
    let serialized = serde_json::to_value(&receipts).unwrap();
    assert_eq!(
        serialized["accepted_stages"][6]["raw"]["rax"],
        restore.raw.rax
    );
    assert_eq!(
        serialized["accepted_stages"][6]["observation"]["status"],
        -1073741790
    );
    assert_eq!(
        serialized["accepted_stages"][6]["initializer_planned"]["status"],
        0
    );
}

#[test]
fn bounded_acceptance_retains_first_failure_and_exact_omissions() {
    let planner = planner();
    let mut receipts = Receipts::default();
    for ordinal in 0..ACCEPTED_STAGE_LIMIT + 2 {
        let mut receipt = capture(&planner, Site::Entry, ordinal, 0);
        receipt.transition_verified = true;
        receipts.record(receipt);
    }
    assert_eq!(receipts.accepted_stages.len(), ACCEPTED_STAGE_LIMIT);
    assert_eq!(receipts.omitted, 2);
    let mut failure = capture(&planner, Site::Entry, 100, 0xc0000022);
    failure.failed = true;
    failure.stage = ReceiptStage::Readback;
    failure.rejection = Some(HitRejection::ReadbackStatus);
    failure.readback = Some(failure.raw.registers);
    receipts.record(failure.clone());
    failure.metadata.event_ordinal = 101;
    receipts.record(failure);
    assert_eq!(
        receipts
            .first_rejected
            .as_ref()
            .unwrap()
            .metadata
            .event_ordinal,
        100
    );
    assert_eq!(
        receipts.first_rejected.as_ref().unwrap().raw.rax,
        0xfeed0000c0000022
    );
    assert!(receipts.first_rejected.as_ref().unwrap().readback.is_some());
    assert_eq!(
        receipts
            .first_observed
            .as_ref()
            .unwrap()
            .metadata
            .event_ordinal,
        0
    );
    assert_eq!(receipts.omitted, 3);
    assert_eq!(receipts.rejected, 2);
    // Leave room inside the existing 64 KiB replay envelope for event/custody facts.
    assert!(serde_json::to_vec(&receipts).unwrap().len() < 32 * 1024);
}

#[test]
fn admitted_return_facts_survive_failed_native_transition() {
    let mut planner = planner();
    for site in [Site::Entry, Site::InitEnter, Site::ProcessTokenReturn] {
        let receipt = capture(&planner, site, 0, 0);
        planner.on_hit(receipt.raw).unwrap();
    }
    helper_trace(&mut planner, 0xc0000022);
    let mut receipt = capture(
        &planner,
        Site::DirectoryInitializationReturn,
        17,
        0xc0000022,
    );
    let original = planner.registers();
    let mut next = planner.clone();
    receipt.observation = Some(next.on_hit(receipt.raw).unwrap());
    let after = next.snapshot(next.registers());
    receipt.initializer_planned = Some(InitializerFacts {
        source: after.initializer_source,
        status: after.initializer_status,
        thread_token_cleared: after.thread_token_cleared,
    });
    receipt.admitted = true;
    receipt.transition_attempted = true;
    receipt.failed = true;
    receipt.stage = ReceiptStage::Readback;
    receipt.rejection = Some(HitRejection::ControlRegister);
    let mut readback = next.registers();
    readback.dr7 ^= 1 << 13;
    receipt.readback = Some(readback);
    assert_eq!(
        next.verify_readback_typed(readback),
        Err(HitRejection::ControlRegister)
    );
    let mut receipts = Receipts::default();
    receipts.record(receipt);
    let failed = receipts.first_rejected.unwrap();
    assert_eq!(failed.raw.rax, 0xfeed0000c0000022);
    assert_eq!(
        failed.observation.unwrap().status,
        Some(0xc0000022u32 as i32)
    );
    assert_eq!(
        failed.initializer_planned.unwrap().status,
        Some(0xc0000022u32 as i32)
    );
    assert!(!failed.transition_verified);
    assert!(receipts.accepted_stages.is_empty());
    assert_eq!(planner.registers(), original);
}
