use crate::windows::{
    loader_debug::reduce_loader_causal_frontier_for_test,
    process::{
        loader_failure_evidence_ranks_for_test, render_loader_control_matrix_failure_for_test,
        select_loader_failure_evidence_for_test,
    },
};

const CELLS: [&str; 6] = [
    "canonical-minimal-system-none-snaps-off",
    "canonical-minimal-system-minimal-pump-snaps-off",
    "canonical-minimal-system-full-observer-snaps-off",
    "canonical-minimal-system-none-snaps-on",
    "canonical-minimal-system-minimal-pump-snaps-on",
    "canonical-minimal-system-full-observer-snaps-on",
];

#[test]
fn loader_failure_rank_is_total_and_selects_full_observer_snaps_on_in_every_order() {
    assert_eq!(
        loader_failure_evidence_ranks_for_test(),
        [
            (CELLS[0], "native-exit"),
            (CELLS[1], "mandatory-pump-snaps-off"),
            (CELLS[2], "full-observer-snaps-off"),
            (CELLS[3], "native-exit"),
            (CELLS[4], "mandatory-pump-snaps-on"),
            (CELLS[5], "full-observer-snaps-on"),
        ]
    );

    let mut order = [0, 1, 2, 3, 4, 5];
    let mut permutations = 0_usize;
    loop {
        assert_eq!(
            select_loader_failure_evidence_for_test(&order).unwrap(),
            CELLS[5],
            "full-observer + snaps-on must win independently of matrix iteration order: {order:?}",
        );
        permutations += 1;
        if !next_permutation(&mut order) {
            break;
        }
    }
    assert_eq!(permutations, 720);

    assert_eq!(
        select_loader_failure_evidence_for_test(&[1, 5]).unwrap(),
        CELLS[5],
        "a richer later trace must upgrade an earlier minimal trace",
    );
    assert_eq!(
        select_loader_failure_evidence_for_test(&[5, 1]).unwrap(),
        CELLS[5],
        "a weaker later trace must not downgrade the selected diagnostic",
    );
}

#[test]
fn loader_matrix_prefix_keeps_every_failed_cell_and_native_status_before_bulk_detail() {
    let bulk = format!("root-attestation={}", "x".repeat(32_768));
    let rendered =
        render_loader_control_matrix_failure_for_test(&[0, 1, 2, 3, 4, 5], &bulk).unwrap();

    assert!(rendered.starts_with(
        "loader_control_matrix=v6 dimensions=debugger-relation-x-loader-snaps environment=canonical-minimal-system selected_cell=canonical-minimal-system-full-observer-snaps-on selected_rank=full-observer-snaps-on selected_native=0xc0000142 completed=6 results=["
    ));
    assert_eq!(rendered.matches(":outcome=failed:").count(), 6);
    let mut cursor = 0_usize;
    for (index, cell) in CELLS.iter().enumerate() {
        let expected = format!(
            "cell={cell}:outcome=failed:native=0xc0000142:phase=pre-initial-breakpoint-static-loader:child_trace={}:detail_sha256=",
            index != 0 && index != 3,
        );
        let relative = rendered[cursor..]
            .find(&expected)
            .unwrap_or_else(|| panic!("matrix omitted the typed failed outcome for {cell}"));
        cursor += relative + expected.len();
        let digest = &rendered[cursor..cursor + 64];
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
        cursor += 64;
    }
    let bulk_offset = rendered.find(&bulk).unwrap();
    assert!(
        cursor < bulk_offset,
        "all typed outcomes must precede bulk detail"
    );
    assert!(
        rendered[..bulk_offset].ends_with("selected_failure=["),
        "bulk evidence must be isolated behind the selected-failure boundary",
    );
}

#[test]
fn bounded_loader_causal_frontier_retains_decisive_tails_and_deterministic_overflow() {
    let first = reduce_loader_causal_frontier_for_test(128);
    let second = reduce_loader_causal_frontier_for_test(128);
    assert_eq!(
        first, second,
        "the compact diagnostic must be deterministic"
    );
    assert!(first.len() <= 8_192);

    for (field, expected) in [
        ("exit=", "0xc0000142"),
        ("exit_status_symbol=", "STATUS_DLL_INIT_FAILED"),
        ("pre_initial_breakpoint=", "true"),
        ("application_entry_possible=", "false"),
        ("candidate_modules_count=", "4"),
        ("candidate_modules_retained=", "4"),
        ("candidate_modules_overflow=", "0"),
        ("unload_tail_count=", "2"),
        ("unload_tail_retained=", "2"),
        ("unload_tail_overflow=", "0"),
        ("loader_snap_tail_count=", "1"),
        ("loader_snap_tail_retained=", "1"),
        ("loader_snap_tail_overflow=", "0"),
        ("missing_direct_roots_count=", "128"),
    ] {
        assert_eq!(field_value(&first, field), expected, "field {field}");
    }
    assert!(first.contains("FAILING-INITIALIZER.DLL"));
    assert!(first.contains("LdrpCallInitRoutine returned STATUS_DLL_INIT_FAILED"));

    let ordered = [
        "candidate_modules_count=",
        "unload_tail_count=",
        "loader_snap_tail_count=",
        "exception_tail_count=",
        "missing_direct_roots_count=",
        "missing_direct_roots=[",
    ];
    let mut cursor = 0_usize;
    for field in ordered {
        let relative = first[cursor..]
            .find(field)
            .unwrap_or_else(|| panic!("diagnostic omitted ordered field {field}"));
        cursor += relative + field.len();
    }

    for field in [
        "candidate_modules_sha256=",
        "unload_tail_sha256=",
        "loader_snap_tail_sha256=",
        "missing_direct_roots_sha256=",
    ] {
        let digest = field_value(&first, field);
        assert_eq!(digest.len(), 64, "field {field}");
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(digest, field_value(&second, field));
    }
    let overflow = field_value(&first, "missing_direct_roots_overflow_bytes=")
        .parse::<usize>()
        .unwrap();
    assert!(overflow > 0, "maximal root evidence must exercise overflow");
    assert_eq!(
        overflow,
        field_value(&second, "missing_direct_roots_overflow_bytes=")
            .parse::<usize>()
            .unwrap()
    );
}

fn field_value<'a>(source: &'a str, field: &str) -> &'a str {
    let start = source
        .find(field)
        .unwrap_or_else(|| panic!("diagnostic omitted field {field}"))
        + field.len();
    let end = source[start..]
        .find(|character: char| character.is_ascii_whitespace())
        .map_or(source.len(), |offset| start + offset);
    &source[start..end]
}

fn next_permutation(values: &mut [usize]) -> bool {
    let Some(pivot) = (0..values.len() - 1).rfind(|index| values[*index] < values[*index + 1])
    else {
        return false;
    };
    let successor = (pivot + 1..values.len())
        .rfind(|index| values[*index] > values[pivot])
        .expect("a permutation pivot has a successor");
    values.swap(pivot, successor);
    values[pivot + 1..].reverse();
    true
}
