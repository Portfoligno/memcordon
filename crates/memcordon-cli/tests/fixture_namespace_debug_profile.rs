#[path = "private/fixture_namespace_hit_receipt.rs"]
mod hit_receipt;
#[path = "private/fixture_namespace_debug_profile.rs"]
mod profile;
use profile::*;

#[test]
fn cleanup_requires_observed_exit_wait_joins_and_no_pending_event() {
    let facts = CleanupFacts {
        exit_continued: true,
        process_signaled: true,
        reader_joined: true,
        watchdog_joined: true,
        pending_event: false,
        registers_live: true,
        restore_verified: true,
    };
    assert!(facts.complete());
    for missing in 0..6 {
        let mut incomplete = facts;
        match missing {
            0 => incomplete.exit_continued = false,
            1 => incomplete.process_signaled = false,
            2 => incomplete.reader_joined = false,
            3 => incomplete.watchdog_joined = false,
            4 => incomplete.pending_event = true,
            _ => incomplete.restore_verified = false,
        }
        assert!(!incomplete.complete());
    }
    let mut dead_registers = facts;
    dead_registers.registers_live = false;
    dead_registers.restore_verified = false;
    assert!(dead_registers.complete());
    assert!(!CleanupFacts::default().complete());
    assert!(
        !CleanupFacts {
            exit_continued: true,
            ..Default::default()
        }
        .complete()
    );
    assert!(
        !CleanupFacts {
            process_signaled: true,
            ..Default::default()
        }
        .complete()
    );
}

fn saved() -> DebugRegisters {
    DebugRegisters {
        dr: [11, 22, 33, 44],
        dr6: 0xffff_0ff0,
        dr7: 1 << 10,
        eflags: 0x202,
    }
}
fn hit(planner: &Planner, site: Site, status: u32) -> Stop {
    let mut registers = planner.registers();
    registers.dr6 |= 1 << site.slot();
    registers.eflags = 0x10246;
    Stop {
        pid: 7,
        tid: 9,
        exception: SINGLE_STEP,
        first_chance: true,
        exception_address: site_address(0x180000000, site).unwrap(),
        rip: site_address(0x180000000, site).unwrap(),
        registers,
        rax: u64::from(status),
        r14: u64::from(status),
        rbx: u64::from(status),
        rcx: 0,
        rdx: 0,
        r8: 0,
        r9: 0,
        rsp: 0,
    }
}

fn initializer(planner: &mut Planner, status: u32) {
    planner.on_hit(hit(planner, Site::InitEnter, 0)).unwrap();
    planner
        .on_hit(hit(planner, Site::ProcessTokenReturn, 0))
        .unwrap();
    helper_trace(planner, status);
    planner
        .on_hit(stage_hit(
            planner,
            Site::DirectoryInitializationReturn,
            status,
        ))
        .unwrap();
}

fn helper_trace(planner: &mut Planner, status: u32) {
    while planner
        .snapshot(planner.registers())
        .helper_selected
        .is_none()
    {
        let expected = planner.snapshot(planner.registers());
        let site = expected.addresses[..2]
            .iter()
            .flatten()
            .min_by_key(|site| {
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
                distance(site.rva)
            })
            .unwrap();
        let mut stop = hit(
            planner,
            Site::Helper {
                rva: site.rva,
                slot: site.slot,
            },
            status,
        );
        stop.rbx = u64::from(status);
        planner.on_hit(stop).unwrap();
    }
}

fn stage_hit(planner: &Planner, site: Site, status: u32) -> Stop {
    let mut stop = hit(planner, site, status);
    if site == Site::DirectoryInitializationReturn {
        stop.registers.dr6 = (stop.registers.dr6 & !15) | 4;
    }
    stop
}

#[test]
fn helper_graph_is_closed_acyclic_and_bounded_with_exact_call_pairs() {
    fn longest(
        rva: u32,
        visiting: &mut Vec<u32>,
        memo: &mut std::collections::BTreeMap<u32, usize>,
    ) -> usize {
        if let Some(length) = memo.get(&rva) {
            return *length;
        }
        assert!(!visiting.contains(&rva));
        visiting.push(rva);
        let node = helper_profile::checkpoint(rva).unwrap();
        assert!(node.successors.len() <= 2);
        let result = 1 + node
            .successors
            .iter()
            .map(|next| longest(*next, visiting, memo))
            .max()
            .unwrap_or(0);
        visiting.pop();
        memo.insert(rva, result);
        result
    }
    assert_eq!(helper_profile::checkpoints().len(), 130);
    assert_eq!(
        longest(0x86450, &mut Vec::new(), &mut Default::default()),
        helper_profile::MAX_CHECKPOINT_STOPS
    );
    for node in helper_profile::checkpoints() {
        if node.kind == "call-entry" {
            assert_eq!(node.successors.len(), 1);
            assert_eq!(
                helper_profile::paired_call(node.successors[0]).unwrap().rva,
                node.rva
            );
            assert_eq!(
                helper_profile::checkpoint(node.successors[0]).unwrap().kind,
                "call-return"
            );
        }
        assert!(longest(node.rva, &mut Vec::new(), &mut Default::default()) <= 93);
    }
}

fn helper_path(from: u32, target: u32) -> Option<Vec<u32>> {
    if from == target {
        return Some(vec![from]);
    }
    helper_profile::checkpoint(from)
        .unwrap()
        .successors
        .iter()
        .filter_map(|next| {
            let mut tail = helper_path(*next, target)?;
            tail.insert(0, from);
            Some(tail)
        })
        .min_by_key(Vec::len)
}

#[test]
fn helper_fallback_retry_and_cleanup_preserve_selected_status_lineage() {
    use helper_profile::*;
    for (waypoints, expected_call, final_status) in [
        (
            vec![
                0x867cf, 0x867d6, 0x8687a, 0x86881, 0x86b2d, 0x86b34, 0x866ba,
            ],
            0x86b2d,
            0xc0000022u32,
        ),
        (
            vec![
                0x867cf, 0x867d6, 0x8687a, 0x86881, 0x86b2d, 0x86b34, 0x867e7, 0x866ba,
            ],
            0x86b2d,
            0,
        ),
        (vec![0x8653f, 0x86546, 0x866ba], 0x8653f, 0xc0000022),
        (
            vec![0x868f2, 0x868f9, 0x199d4a, 0x199d51, 0x866ba],
            0x199d4a,
            0xc0000022,
        ),
    ] {
        let mut route = vec![0x86450];
        for target in waypoints {
            let tail =
                helper_path(*route.last().unwrap(), target).expect("verified connected test route");
            route.extend(tail.into_iter().skip(1));
        }
        let mut machine = Machine::default();
        let mut rbx = 0;
        let mut rax = 0;
        let mut pending = None;
        for rva in route {
            if let Some(status) = pending.take() {
                rbx = status;
            }
            if let Some(call) = paired_call(rva) {
                rax = if call.rva == expected_call {
                    u64::from(final_status)
                } else if call.rva == 0x867cf {
                    0xc0000022
                } else if call.rva == 0x868f2 {
                    0xc0000023
                } else {
                    0
                };
                if call_kind(call.rva) != CallKind::Other {
                    pending = Some(rax);
                } else {
                    rax = 0xfeedface;
                } // Ignored pointer/cleanup result cannot select status.
            }
            if rva == 0x8663e {
                rbx = 0;
            }
            if rva == 0x86cbb {
                pending = Some(0xc000009a);
            }
            let slot = machine
                .frontier
                .iter()
                .position(|candidate| *candidate == rva)
                .unwrap();
            machine.hit(rva, slot, rax, rbx).unwrap();
        }
        let selected = machine.selected.unwrap();
        assert_eq!(selected.status, final_status as i32);
        assert!(matches!(selected.source, Source::Call {call,..} if call == expected_call));
    }
}

#[test]
fn helper_requires_selected_result_and_rejects_wrong_frontier_without_committing() {
    let mut planner = Planner::arm(saved(), 0x180000000, 7, 9).unwrap();
    planner.on_hit(hit(&planner, Site::Entry, 0)).unwrap();
    planner.on_hit(hit(&planner, Site::InitEnter, 0)).unwrap();
    planner
        .on_hit(hit(&planner, Site::ProcessTokenReturn, 0))
        .unwrap();
    let expected = planner.registers();
    assert_eq!(
        planner.on_hit(stage_hit(
            &planner,
            Site::DirectoryInitializationReturn,
            0xc0000022
        )),
        Err(HitRejection::HitState)
    );
    assert_eq!(planner.registers(), expected);
    let mut wrong = hit(
        &planner,
        Site::Helper {
            rva: 0x86450,
            slot: 1,
        },
        0,
    );
    wrong.registers.dr6 = (wrong.registers.dr6 & !15) | 2;
    assert_eq!(planner.on_hit(wrong), Err(HitRejection::HitState));
    assert_eq!(planner.registers(), expected);
    helper_trace(&mut planner, 0xc0000022);
    assert_eq!(
        planner.on_hit(stage_hit(&planner, Site::DirectoryInitializationReturn, 0)),
        Err(HitRejection::HitState)
    );
    planner
        .on_hit(stage_hit(
            &planner,
            Site::DirectoryInitializationReturn,
            0xc0000022,
        ))
        .unwrap();
    planner
        .on_hit(hit(&planner, Site::Initialization, 0xc0000022))
        .unwrap();
    assert_eq!(planner.state(), State::Observed);
    assert_eq!(planner.registers().dr[3], saved().dr[3]);
}

#[test]
fn unknown_selected_ebx_write_is_rejected_without_losing_the_committed_frontier() {
    let denied = 0xc0000022;
    let mut planner = Planner::arm(saved(), 0x180000000, 7, 9).unwrap();
    for site in [Site::Entry, Site::InitEnter, Site::ProcessTokenReturn] {
        planner.on_hit(hit(&planner, site, 0)).unwrap();
    }
    for rva in helper_path(0x86450, 0x866ba).unwrap() {
        let snapshot = planner.snapshot(planner.registers());
        let slot = snapshot
            .addresses
            .iter()
            .flatten()
            .find(|site| site.rva == rva)
            .unwrap()
            .slot;
        let mut stop = hit(&planner, Site::Helper { rva, slot }, denied);
        if rva == 0x866ba {
            let original = planner.registers();
            stop.rbx ^= 1;
            assert_eq!(planner.on_hit(stop), Err(HitRejection::HitState));
            assert_eq!(planner.registers(), original);
            assert!(planner.snapshot(original).helper_selected.is_none());
            stop.rbx ^= 1;
        }
        planner.on_hit(stop).unwrap();
    }
    let selected = planner
        .snapshot(planner.registers())
        .helper_selected
        .unwrap();
    assert_eq!(selected.status, denied as i32);
    assert!(matches!(
        selected.source,
        helper_profile::Source::Call { call: 0x8653f, .. }
    ));
}

#[test]
fn modeled_ebx_overwrites_never_retain_stale_or_nonzero_extended_sources() {
    for stale_rbx in [0, 1u64 << 32] {
        let mut route = vec![0x86450];
        for target in [0x86546, 0x86574, 0x866ba] {
            route.extend(
                helper_path(*route.last().unwrap(), target)
                    .unwrap()
                    .into_iter()
                    .skip(1),
            );
        }
        let mut machine = helper_profile::Machine::default();
        let mut second_returned = false;
        for rva in route {
            if rva == 0x86574 {
                second_returned = true;
            }
            let rax = if second_returned { 0xc0000022 } else { 0 };
            let rbx = if second_returned && rva != 0x86574 {
                stale_rbx
            } else {
                0
            };
            let slot = machine
                .frontier
                .iter()
                .position(|candidate| *candidate == rva)
                .unwrap();
            let result = machine.hit(rva, slot, rax, rbx);
            if rva == 0x866ba {
                assert!(result.is_err());
            } else {
                result.unwrap();
            }
        }
        assert!(machine.selected.is_none());
    }
}

#[test]
fn every_initializer_return_route_correlates_its_source_and_preserves_restore_status() {
    use Site::*;
    let denied = 0xc0000022;
    let cases = [
        vec![(ProcessTokenReturn, denied)],
        vec![
            (ProcessTokenReturn, 0),
            (DirectoryInitializationReturn, denied),
        ],
        vec![(ProcessTokenReturn, 0), (DirectoryInitializationReturn, 0)],
        vec![(ThreadTokenReturn, denied)],
        vec![(ThreadTokenReturn, 0), (ClearThreadTokenReturn, denied)],
        vec![
            (ThreadTokenReturn, 0),
            (ClearThreadTokenReturn, 0),
            (ProcessTokenReturn, denied),
            (RestoreThreadTokenReturn, 0),
        ],
        vec![
            (ThreadTokenReturn, 0),
            (ClearThreadTokenReturn, 0),
            (ProcessTokenReturn, 0),
            (DirectoryInitializationReturn, denied),
            (RestoreThreadTokenReturn, denied),
        ],
        vec![
            (ThreadTokenReturn, 0),
            (ClearThreadTokenReturn, 0),
            (ProcessTokenReturn, 0),
            (DirectoryInitializationReturn, 0),
            (RestoreThreadTokenReturn, denied),
        ],
    ];
    for route in cases {
        let mut planner = Planner::arm(saved(), 0x180000000, 7, 9).unwrap();
        planner.on_hit(hit(&planner, Entry, 0)).unwrap();
        planner.on_hit(hit(&planner, InitEnter, 0)).unwrap();
        let mut source = None;
        let mut final_status = 0;
        for (site, status) in route {
            if site == DirectoryInitializationReturn {
                helper_trace(&mut planner, status);
            }
            let mut stop = stage_hit(&planner, site, status);
            stop.rax |= 0xfeed_beef_0000_0000;
            stop.r14 = 0x12345678; // Return breakpoints precede the R14 assignment.
            let observation = planner.on_hit(stop).unwrap();
            assert_eq!(observation.status, Some(status as i32));
            planner.verify_readback(planner.registers()).unwrap();
            assert_eq!(planner.registers().dr[3], saved().dr[3]);
            if site != RestoreThreadTokenReturn
                && ((status as i32) < 0 || site == DirectoryInitializationReturn)
            {
                source = Some(site.name());
                final_status = status;
            }
        }
        assert_eq!(planner.state(), State::AwaitInitialization);
        let facts = planner.snapshot(planner.registers());
        assert_eq!(facts.initializer_source, source);
        assert_eq!(facts.initializer_status, Some(final_status as i32));
        let original = planner.registers();
        let mut wrong = hit(&planner, Initialization, final_status ^ 1);
        assert_eq!(planner.on_hit(wrong), Err(HitRejection::HitState));
        assert_eq!(planner.registers(), original);
        assert_eq!(planner.state(), State::AwaitInitialization);
        wrong.r14 = u64::from(final_status);
        planner.on_hit(wrong).unwrap();
        if final_status as i32 >= 0 {
            assert_eq!(planner.state(), State::AwaitNative);
            planner.on_hit(hit(&planner, Native, 0)).unwrap();
        }
        assert_eq!(planner.state(), State::Observed);
        assert_eq!(planner.registers().dr, saved().dr);
    }
}

#[test]
fn initializer_stages_reject_missing_or_foreign_evidence_without_committing() {
    use Site::*;
    let mut planner = Planner::arm(saved(), 0x180000000, 7, 9).unwrap();
    planner.on_hit(hit(&planner, Entry, 0)).unwrap();
    // An aggregate hit without the immediate return evidence is incomplete.
    assert_eq!(
        planner.on_hit(hit(&planner, Initialization, 0xc0000022)),
        Err(HitRejection::HitState)
    );
    for site in [
        InitEnter,
        ThreadTokenReturn,
        ClearThreadTokenReturn,
        ProcessTokenReturn,
        DirectoryInitializationReturn,
        RestoreThreadTokenReturn,
        Initialization,
    ] {
        let status = if site == DirectoryInitializationReturn || site == Initialization {
            0xc0000022
        } else {
            0
        };
        if site == DirectoryInitializationReturn {
            helper_trace(&mut planner, status);
        }
        for mutation in 0..12 {
            let mut candidate = planner.clone();
            let before = candidate.registers();
            let state = candidate.state();
            let mut stop = stage_hit(&candidate, site, status);
            match mutation {
                0 => stop.pid += 1,
                1 => stop.tid += 1,
                2 => stop.first_chance = false,
                3 => stop.rip += 1,
                4 => stop.exception_address += 1,
                5 => stop.registers.dr6 |= 1 << 13,
                6 => stop.registers.eflags |= 1 << 8,
                7 => stop.registers.dr7 ^= 1 << 13,
                8 => stop.exception ^= 1,
                9 => stop.registers.dr6 &= !15,
                10 => stop.registers.dr[3] ^= 1,
                _ => stop.registers.dr6 = (stop.registers.dr6 & !15) | 8,
            }
            assert!(candidate.on_hit(stop).is_err());
            assert_eq!(candidate.registers(), before);
            assert_eq!(candidate.state(), state);
        }
        planner.on_hit(stage_hit(&planner, site, status)).unwrap();
    }
    assert_eq!(planner.state(), State::Observed);
}

#[test]
fn exact_one_shot_native_and_initialization_paths_preserve_current_flags() {
    for lazy in [None, Some(0), Some(0xc0000022)] {
        let mut planner = Planner::arm(saved(), 0x180000000, 7, 9).unwrap();
        planner.verify_readback(planner.registers()).unwrap();
        assert_eq!(planner.state(), State::ArmedEntry);
        assert_eq!(planner.registers().dr[3], 44);
        assert_eq!(
            planner
                .on_hit(hit(&planner, Site::Entry, 0))
                .unwrap()
                .status,
            None
        );
        assert_eq!(
            planner.registers().dr[0],
            site_address(0x180000000, Site::InitEnter).unwrap()
        );
        assert_eq!(planner.registers().dr7 & 0x3f, 1 | (1 << 2) | (1 << 4));
        if let Some(status) = lazy {
            initializer(&mut planner, status);
            let observation = planner
                .on_hit(hit(&planner, Site::Initialization, status))
                .unwrap();
            assert_eq!(observation.status, Some(status as i32));
            if status as i32 >= 0 {
                assert_eq!(planner.state(), State::AwaitNative);
                assert_eq!(planner.registers().dr[2], 33);
                assert_eq!(planner.registers().dr7 & 0x3f, 1 << 2);
            }
        }
        if planner.state() != State::Observed {
            assert_eq!(
                planner
                    .on_hit(hit(&planner, Site::Native, 0xc0000022))
                    .unwrap()
                    .status,
                Some(0xc0000022u32 as i32)
            );
        }
        assert_eq!(planner.state(), State::Observed);
        let restored = planner.registers();
        assert_eq!(restored.dr, saved().dr);
        assert_eq!(restored.dr7, saved().dr7);
        assert_eq!(restored.eflags, 0x10246);
        assert_eq!(restored.dr6 & 7, 0);
        assert!(planner.on_hit(hit(&planner, Site::Native, 0)).is_err());
    }
}

#[test]
fn fixed_one_dr7_representation_preserves_raw_receipts_and_all_transitions() {
    for lazy in [None, Some(0), Some(0xc0000022)] {
        let initial = DebugRegisters {
            dr: [0; 4],
            dr6: 0,
            dr7: 0,
            eflags: 0x204,
        };
        let mut planner = Planner::arm(initial, 0x180000000, 7, 9).unwrap();
        assert_eq!(planner.registers().dr7, 1);
        for fixed_one in [0, DR7_FIXED_ONE_MASK] {
            let mut readback = planner.registers();
            readback.dr7 ^= fixed_one;
            planner.verify_readback_typed(readback).unwrap();
        }
        let mut stop = hit(&planner, Site::Entry, 0);
        stop.registers.dr7 = 0x401;
        stop.registers.dr6 = 0xfffe0ff1;
        stop.registers.eflags = 0x246;
        let expected = planner.snapshot(stop.registers);
        assert_eq!(expected.registers.dr7, 1);
        assert!(expected.ownership.control_register_equal);
        assert!(!expected.ownership.control_register_raw_equal);
        assert_eq!(expected.ownership.dr7_fixed_one_equivalence_mask, 0x400);
        let receipt = serde_json::to_value(expected).unwrap();
        assert_eq!(receipt["registers"]["dr7"], 1);
        assert_eq!(receipt["ownership"]["control_register_raw_equal"], false);
        assert_eq!(receipt["ownership"]["control_register_equal"], true);
        assert_eq!(
            receipt["ownership"]["dr7_fixed_one_equivalence_mask"],
            0x400
        );
        let captured = hit_receipt::Receipt::capture(
            hit_receipt::Metadata {
                event_ordinal: 16,
                flags: 0,
                first_chance: 1,
                received_qpc: None,
            },
            stop,
            Some(&planner),
        );
        let captured = serde_json::to_value(captured).unwrap();
        assert_eq!(captured["raw"]["registers"]["dr7"], 0x401);
        assert_eq!(captured["expected"]["registers"]["dr7"], 1);
        assert_eq!(
            captured["expected"]["ownership"]["control_register_equal"],
            true
        );
        planner.on_hit(stop).unwrap();
        assert_eq!(stop.registers.dr7, 0x401);
        assert_eq!(planner.state(), State::AwaitResult);
        assert_eq!(planner.registers().dr6, 0xfffe0ff0);
        assert_eq!(planner.registers().eflags, 0x246);
        if let Some(status) = lazy {
            initializer(&mut planner, status);
            let mut stop = hit(&planner, Site::Initialization, status);
            stop.registers.dr7 ^= DR7_FIXED_ONE_MASK;
            planner.on_hit(stop).unwrap();
        }
        if planner.state() != State::Observed {
            let mut stop = hit(&planner, Site::Native, 0xc0000022);
            stop.registers.dr7 ^= DR7_FIXED_ONE_MASK;
            planner.on_hit(stop).unwrap();
        }
        assert_eq!(planner.state(), State::Observed);
        for fixed_one in [0, DR7_FIXED_ONE_MASK] {
            let mut readback = planner.registers();
            readback.dr7 = fixed_one;
            planner.verify_readback_typed(readback).unwrap();
            let restored = planner.restore(readback).unwrap();
            assert_eq!(restored.dr7, fixed_one);
            assert!(dr7_equivalent(restored.dr7, initial.dr7));
        }
    }
}

#[test]
fn every_other_dr7_bit_still_rejects_without_changing_the_plan() {
    for bit in 0..u64::BITS {
        if 1u64 << bit == DR7_FIXED_ONE_MASK {
            continue;
        }
        let mut planner = Planner::arm(saved(), 0x180000000, 7, 9).unwrap();
        let original = planner.registers();
        let mut stop = hit(&planner, Site::Entry, 0);
        stop.registers.dr7 ^= 1u64 << bit;
        assert!(!dr7_equivalent(stop.registers.dr7, original.dr7));
        assert_eq!(planner.on_hit(stop), Err(HitRejection::ControlRegister));
        assert_eq!(planner.state(), State::ArmedEntry);
        assert_eq!(planner.registers(), original);
        assert_eq!(
            planner.verify_readback_typed(stop.registers),
            Err(HitRejection::ControlRegister)
        );
        assert!(planner.restore(stop.registers).is_err());
    }
}

#[test]
fn unrelated_exception_or_debug_state_is_never_consumed() {
    for mutation in 0..11 {
        let mut planner = Planner::arm(saved(), 0x180000000, 7, 9).unwrap();
        let mut stop = hit(&planner, Site::Entry, 0);
        match mutation {
            0 => stop.pid += 1,
            1 => stop.tid += 1,
            2 => stop.first_chance = false,
            3 => stop.exception = 0x80000003,
            4 => stop.rip += 1,
            5 => stop.exception_address += 1,
            6 => stop.registers.dr6 |= 2,
            7 => stop.registers.dr6 |= 1 << 14,
            8 => stop.registers.dr[3] += 1,
            9 => stop.registers.dr7 |= 1 << 6,
            _ => stop.registers.dr7 |= 1 << 16,
        }
        assert!(planner.on_hit(stop).is_err());
        assert_eq!(planner.state(), State::ArmedEntry);
    }
    for mutation in 0..4 {
        let mut value = saved();
        match mutation {
            0 => value.dr7 |= 1,
            1 => value.dr7 |= 1 << 13,
            2 => value.dr6 |= 1 << 15,
            _ => value.eflags |= 1 << 8,
        };
        assert!(Planner::arm(value, 0x180000000, 7, 9).is_err());
    }
    let planner = Planner::arm(saved(), 0x180000000, 7, 9).unwrap();
    let mut value = planner.registers();
    value.dr6 |= 1;
    assert!(planner.verify_readback(value).is_err());
    value.dr6 |= 1 << 32;
    let restored = planner.restore(value).unwrap();
    assert_eq!(restored.dr6 & (1 << 32), 1 << 32);
    assert_eq!(restored.dr6 & 7, 0);
}

#[test]
fn abi_uses_low_width_values_and_exact_bounded_utf16_argument() {
    let name: Vec<u16> = "alias\\event".encode_utf16().chain(Some(0)).collect();
    let bytes: Vec<u8> = name.iter().flat_map(|value| value.to_le_bytes()).collect();
    validate_entry(
        0xabcd000000100000,
        0x123400000000,
        100,
        0x100000,
        &name,
        &bytes,
    )
    .unwrap();
    assert!(validate_entry(0x100001, 0, 100, 0x100000, &name, &bytes).is_err());
    assert!(validate_entry(0x100000, 1, 100, 0x100000, &name, &bytes).is_err());
    assert!(validate_entry(0x100000, 0, u64::MAX, 0x100000, &name, &bytes).is_err());
    assert!(validate_entry(0x100000, 0, 100, 0x100000, &name, &bytes[..bytes.len() - 1]).is_err());
    let mut changed = bytes.clone();
    changed[0] ^= 1;
    assert!(validate_entry(0x100000, 0, 100, 0x100000, &name, &changed).is_err());
    assert!(validate_entry(0, 0, 0, 0, &[], &[]).is_err());
    assert!(validate_entry(0, 0, 1, 0, &[65, 0, 0], &[65, 0, 0, 0, 0, 0]).is_err());
}

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn fixture() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x1a0000];
    bytes[..2].copy_from_slice(b"MZ");
    put32(&mut bytes, 0x3c, 0x108);
    bytes[0x108..0x10c].copy_from_slice(b"PE\0\0");
    put16(&mut bytes, 0x10c, MACHINE);
    put16(&mut bytes, 0x10e, 1);
    put16(&mut bytes, 0x11c, 240);
    let optional = 0x120;
    put16(&mut bytes, optional, MAGIC);
    put32(&mut bytes, optional + 56, SIZE_OF_IMAGE);
    put32(&mut bytes, optional + 108, 1);
    put32(&mut bytes, optional + 112, 0x1000);
    put32(&mut bytes, optional + 116, 40);
    let section = optional + 240;
    put32(&mut bytes, section + 12, 0x1000);
    put32(&mut bytes, section + 16, 0x19f000);
    put32(&mut bytes, section + 20, 0x1000);
    put32(&mut bytes, section + 36, 0x20000000);
    put32(&mut bytes, 0x1000 + 20, 1);
    put32(&mut bytes, 0x1000 + 24, 1);
    put32(&mut bytes, 0x1000 + 28, 0x1100);
    put32(&mut bytes, 0x1000 + 32, 0x1200);
    put32(&mut bytes, 0x1000 + 36, 0x1300);
    put32(&mut bytes, 0x1100, Site::Entry.rva());
    put32(&mut bytes, 0x1200, 0x1400);
    bytes[0x1400..0x140b].copy_from_slice(b"OpenEventW\0");
    for site in Site::ALL {
        let offset = site.rva() as usize;
        bytes[offset..offset + site.bytes().len()].copy_from_slice(site.bytes());
    }
    for range in helper_profile::byte_extents() {
        let start = range.rva as usize;
        bytes[start..start + range.length].copy_from_slice(&range.bytes);
    }
    bytes
}

#[test]
fn profile_hash_sections_exports_and_mapped_preimages_fail_closed() {
    let bytes = fixture();
    validate_pe_profile(&bytes).unwrap();
    validate_runtime_header(&bytes[..4096]).unwrap();
    for range in helper_profile::byte_extents() {
        let mut changed = bytes.clone();
        changed[range.rva as usize + range.length - 1] ^= 1;
        assert!(validate_pe_profile(&changed).is_err());
    }
    for site in Site::ALL {
        let mut changed = bytes.clone();
        changed[site.rva() as usize] ^= 1;
        assert!(validate_pe_profile(&changed).is_err());
        assert!(
            validate_site_bytes(
                site,
                &changed[site.rva() as usize..site.rva() as usize + site.bytes().len()]
            )
            .is_err()
        );
    }
    assert!(validate_file(&bytes).is_err());
    assert!(validate_file(&vec![0; FILE_LEN]).is_err());
    for mutation in 0..7 {
        let mut changed = bytes.clone();
        match mutation {
            0 => changed[0x87700] ^= 1,
            1 => put16(&mut changed, 0x10c, 0xaa64),
            2 => put32(&mut changed, 0x120 + 56, SIZE_OF_IMAGE + 1),
            3 => put32(&mut changed, 0x120 + 240 + 36, 0),
            4 => put32(&mut changed, 0x1100, Site::Native.rva()),
            5 => put32(&mut changed, 0x1200, u32::MAX),
            _ => put32(&mut changed, 0x120 + 240 + 16, u32::MAX),
        };
        assert!(validate_pe_profile(&changed).is_err());
    }
    assert!(validate_runtime_header(&bytes[..100]).is_err());
    assert!(validate_runtime_header(&bytes[..4097]).is_err());
    assert!(site_address(u64::MAX, Site::Entry).is_err());
    assert_eq!(IMAGE_SHA256.len(), 64);
}

#[test]
fn limits_and_remaining_budget_never_create_another_timeout() {
    assert_eq!(stop_qpc(10, 30).unwrap(), 20);
    assert!(stop_qpc(30, 30).is_err());
    assert!(stop_qpc(29, 30).is_err());
    assert_eq!(wait_millis(0, 100, 1000).unwrap(), 10);
    assert_eq!(wait_millis(99, 100, 1000).unwrap(), 1);
    assert_eq!(wait_millis(100, 100, 1000).unwrap(), 0);
    assert!(wait_millis(0, 1, 0).is_err());
    let mut limit = Limit::default();
    for _ in 0..EVENT_LIMIT - 1 {
        limit.event(false).unwrap();
    }
    assert!(limit.event(false).is_err());
    limit.event(true).unwrap();
    limit.output(OUTPUT_LIMIT - 1).unwrap();
    assert!(limit.output(1).is_err());
    assert_eq!(SIZE_OF_IMAGE, 0x3ed000);
}

#[test]
fn every_strict_ownership_predicate_is_typed_without_changing_state() {
    let mut planner = Planner::arm(saved(), 0x180000000, 7, 9).unwrap();
    let mut rf_only = hit(&planner, Site::Entry, 0);
    rf_only.registers.eflags = planner.registers().eflags | (1 << 16);
    planner.on_hit(rf_only).unwrap();
    assert_eq!(planner.registers().eflags, rf_only.registers.eflags);
    // Arm validates the whole image extent, so a later site cannot overflow.
    assert!(Planner::arm(saved(), u64::MAX - u64::from(Site::Entry.rva()), 7, 9).is_err());
    for index in 0..4 {
        let mut planner = Planner::arm(saved(), 0x180000000, 7, 9).unwrap();
        let expected = planner.registers();
        let mut stop = hit(&planner, Site::Entry, 0);
        stop.registers.dr[index] ^= 1;
        assert_eq!(planner.on_hit(stop), Err(HitRejection::AddressRegisters));
        assert_eq!(planner.registers(), expected);
        assert_eq!(planner.state(), State::ArmedEntry);
    }
    for (bit, rejection) in [
        (3, HitRejection::UnrelatedStatus),
        (13, HitRejection::UnrelatedStatus),
        (14, HitRejection::UnrelatedStatus),
        (15, HitRejection::UnrelatedStatus),
    ] {
        let mut planner = Planner::arm(saved(), 0x180000000, 7, 9).unwrap();
        let mut stop = hit(&planner, Site::Entry, 0);
        stop.registers.dr6 |= 1 << bit;
        assert_eq!(planner.on_hit(stop), Err(rejection));
        assert_eq!(planner.state(), State::ArmedEntry);
    }
    for mutation in 0..10 {
        let mut planner = Planner::arm(saved(), 0x180000000, 7, 9).unwrap();
        let expected = planner.registers();
        let mut stop = hit(&planner, Site::Entry, 0);
        let rejection = match mutation {
            0 => {
                stop.registers.dr7 ^= 1 << 6;
                HitRejection::ControlRegister
            }
            1 => {
                stop.registers.eflags |= 1 << 8;
                HitRejection::TrapFlag
            }
            2 => {
                stop.registers.dr6 |= 2;
                HitRejection::HitState
            }
            3 => {
                stop.pid += 1;
                HitRejection::OwnerProcess
            }
            4 => {
                stop.tid += 1;
                HitRejection::OwnerThread
            }
            5 => {
                stop.exception ^= 1;
                HitRejection::ExceptionCode
            }
            6 => {
                stop.first_chance = false;
                HitRejection::FirstChance
            }
            7 => {
                stop.rip += 1;
                HitRejection::InstructionPointer
            }
            8 => {
                stop.exception_address += 1;
                HitRejection::ExceptionAddress
            }
            _ => {
                stop.registers.dr6 = (stop.registers.dr6 & !15) | 4;
                HitRejection::HitState
            }
        };
        assert_eq!(planner.on_hit(stop), Err(rejection));
        assert_eq!(planner.registers(), expected);
        assert_eq!(planner.state(), State::ArmedEntry);
    }
    let planner = Planner::arm(saved(), 0x180000000, 7, 9).unwrap();
    let mut readback = planner.registers();
    readback.dr6 |= 1;
    assert_eq!(
        planner.verify_readback_typed(readback),
        Err(HitRejection::ReadbackStatus)
    );
    assert_eq!(
        HitRejection::AddressOverflow.io_error().to_string(),
        site_address(u64::MAX, Site::Entry).unwrap_err().to_string()
    );
}

#[test]
fn simultaneous_mismatches_retain_all_raw_facts_and_first_cause() {
    use hit_receipt::*;
    let mut planner = Planner::arm(saved(), 0x180000000, 7, 9).unwrap();
    let mut stop = hit(&planner, Site::Entry, 0);
    stop.registers.dr[0] = u64::MAX;
    stop.registers.dr7 = u64::MAX;
    stop.registers.dr6 = u64::MAX;
    stop.registers.eflags = u32::MAX;
    stop.rax = u64::MAX;
    stop.r14 = u64::MAX - 1;
    let mut receipt = Receipt::capture(
        Metadata {
            event_ordinal: 16,
            flags: 128,
            first_chance: 2,
            received_qpc: Some(999),
        },
        stop,
        Some(&planner),
    );
    let facts = receipt.expected.unwrap().ownership;
    assert!(
        !facts.address_registers_equal
            && !facts.control_register_equal
            && !facts.unrelated_status_clear
            && !facts.trap_flag_clear
    );
    assert_eq!(facts.unrelated_status_value, 8 | (7 << 13));
    assert_eq!(facts.trap_flag_value, 1 << 8);
    receipt.rejection = Some(planner.on_hit(stop).unwrap_err());
    receipt.failed = true;
    receipt.stage = ReceiptStage::Validation;
    assert_eq!(receipt.rejection, Some(HitRejection::AddressRegisters));
    let json = serde_json::to_value(&receipt).unwrap();
    assert_eq!(json["raw"]["registers"]["dr"][0].as_u64(), Some(u64::MAX));
    assert_eq!(json["raw"]["rax"].as_u64(), Some(u64::MAX));
    assert_eq!(json["metadata"]["first_chance"], 2);
    assert_eq!(json["expected"]["addresses"][0]["site"], "entry");
    assert_eq!(json["expected"]["addresses"][0]["slot"], 0);
    assert!(!receipt.admitted && !receipt.transition_attempted && !receipt.transition_verified);
    assert_eq!(receipt.state_after, Some(State::ArmedEntry));
}

#[test]
fn first_rejected_stop_survives_prior_success_and_later_cleanup_failure() {
    use hit_receipt::*;
    let mut planner = Planner::arm(saved(), 0x180000000, 7, 9).unwrap();
    let metadata = Metadata {
        event_ordinal: 16,
        flags: 0,
        first_chance: 1,
        received_qpc: Some(100),
    };
    let stop = hit(&planner, Site::Entry, 0);
    let mut observed = Receipt::capture(metadata, stop, Some(&planner));
    let mut receipts = Receipts::default();
    assert!(receipts.first_observed.is_none()); // A failed context read creates no Stop.
    assert!(!observed.admitted && !observed.transition_verified);
    planner.on_hit(stop).unwrap();
    observed.admitted = true;
    observed.transition_attempted = true;
    observed.transition_verified = true;
    observed.stage = ReceiptStage::Complete;
    observed.state_after = Some(planner.state());
    observed.registers_after = Some(planner.registers());
    receipts.record(observed);
    let mut stop = hit(&planner, Site::Native, 0);
    stop.registers.dr7 ^= 1;
    let mut rejected = Receipt::capture(
        Metadata {
            event_ordinal: 17,
            ..metadata
        },
        stop,
        Some(&planner),
    );
    rejected.stage = ReceiptStage::Validation;
    rejected.rejection = Some(planner.on_hit(stop).unwrap_err());
    rejected.failed = true;
    receipts.record(rejected.clone());
    rejected.metadata.event_ordinal = 18;
    receipts.record(rejected);
    assert_eq!(
        (
            receipts.observed,
            receipts.accepted,
            receipts.rejected,
            receipts.omitted
        ),
        (3, 1, 2, 1)
    );
    assert_eq!(receipts.first_observed.unwrap().metadata.event_ordinal, 16);
    assert_eq!(receipts.first_rejected.unwrap().metadata.event_ordinal, 17);
    let mut missing = Receipt::capture(metadata, stop, None);
    missing.rejection = Some(HitRejection::MissingPlanner);
    assert!(
        missing.expected.is_none()
            && missing.state_after.is_none()
            && missing.registers_after.is_none()
    );
    assert!(missing.readback.is_none());
}

#[test]
fn partial_transition_receipts_do_not_claim_a_committed_plan() {
    use hit_receipt::*;
    let planner = Planner::arm(saved(), 0x180000000, 7, 9).unwrap();
    for stage in [
        ReceiptStage::EntryArguments,
        ReceiptStage::HelperOperands,
        ReceiptStage::SetRegisters,
        ReceiptStage::Readback,
    ] {
        let stop = hit(&planner, Site::Entry, 0);
        let mut receipt = Receipt::capture(
            Metadata {
                event_ordinal: 16,
                flags: 0,
                first_chance: 1,
                received_qpc: None,
            },
            stop,
            Some(&planner),
        );
        receipt.stage = stage;
        receipt.admitted = true;
        receipt.failed = true;
        receipt.transition_attempted =
            matches!(stage, ReceiptStage::SetRegisters | ReceiptStage::Readback);
        if matches!(stage, ReceiptStage::Readback) {
            let mut actual = planner.registers();
            actual.dr6 |= 1;
            receipt.readback = Some(actual);
            receipt.rejection = Some(planner.verify_readback_typed(actual).unwrap_err());
        }
        let mut receipts = Receipts::default();
        receipts.record(receipt);
        assert_eq!(receipts.accepted, 0);
        let retained = receipts.first_rejected.unwrap();
        assert_eq!(retained.state_after, Some(State::ArmedEntry));
        assert_eq!(retained.registers_after, Some(planner.registers()));
        assert!(!retained.transition_verified);
        if matches!(stage, ReceiptStage::Readback) {
            assert_eq!(retained.readback.unwrap().dr6 & 7, 1);
            assert_eq!(retained.rejection, Some(HitRejection::ReadbackStatus));
        }
    }
}
