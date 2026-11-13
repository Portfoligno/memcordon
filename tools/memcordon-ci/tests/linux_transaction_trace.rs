use memcordon_ci::linux_transaction_trace::{self as trace, Parent, TraceWindow};
use std::time::{Duration, Instant};
const X64: u32 = 0xc000003e;
const ARM64: u32 = 0xc00000b7;
fn entry(architecture: u32, number: u64, args: [u64; 6]) -> Vec<u8> {
    let mut packet = vec![0; 80];
    packet[0] = 1;
    packet[4..8].copy_from_slice(&architecture.to_ne_bytes());
    packet[24..32].copy_from_slice(&number.to_ne_bytes());
    for (slot, value) in packet[32..].chunks_exact_mut(8).zip(args) {
        slot.copy_from_slice(&value.to_ne_bytes());
    }
    packet
}
fn exit(architecture: u32, value: i64, error: bool) -> Vec<u8> {
    let mut packet = vec![0; 33];
    packet[0] = 2;
    packet[4..8].copy_from_slice(&architecture.to_ne_bytes());
    packet[24..32].copy_from_slice(&value.to_ne_bytes());
    packet[32] = u8::from(error);
    packet
}
#[test]
fn native_rename_variants_preserve_actual_operand_registers_and_flags() {
    for (architecture, number) in [(X64, 264), (X64, 316), (ARM64, 38), (ARM64, 276)] {
        for cwd in [u64::MAX - 99, u64::from(u32::MAX - 99)] {
            let packet = entry(architecture, number, [cwd, 0x1234, 7, 0x5678, 2, 0]);
            let selected = trace::rename_entry(&packet, architecture).unwrap().unwrap();
            assert_eq!(
                (selected.architecture, selected.number),
                (architecture, number)
            );
            assert_eq!(
                (selected.source_address, selected.target_address),
                (0x1234, 0x5678)
            );
            assert_eq!((selected.source_fd, selected.target_fd), (-100, 7));
            assert_eq!(
                selected.flags,
                if [316, 276].contains(&number) { 2 } else { 0 }
            );
            assert!(
                trace::rename_entry(&packet, if architecture == X64 { ARM64 } else { X64 })
                    .is_err()
            );
        }
    }
    let selected = trace::rename_entry(&entry(X64, 82, [12, 34, 0, 0, 0, 0]), X64)
        .unwrap()
        .unwrap();
    assert_eq!((selected.source_address, selected.target_address), (12, 34));
    assert_eq!(
        (selected.source_fd, selected.target_fd, selected.flags),
        (-100, -100, 0)
    );
    assert!(
        trace::rename_entry(&entry(X64, 1, [0; 6]), X64)
            .unwrap()
            .is_none()
    );
    assert!(
        trace::rename_entry(&exit(X64, 0, false), X64)
            .unwrap()
            .is_none()
    );
    assert!(trace::rename_entry(&entry(X64, 82, [0; 6])[..79], X64).is_err());
}
#[test]
fn strict_exit_cannot_be_invented_from_entry_failure_or_foreign_architecture() {
    for architecture in [X64, ARM64] {
        assert_eq!(
            trace::successful_exit(&exit(architecture, 0, false), architecture).unwrap(),
            0
        );
        assert_eq!(
            trace::successful_exit(&exit(architecture, 17, false), architecture).unwrap(),
            17
        );
        assert!(trace::successful_exit(&exit(architecture, -4, true), architecture).is_err());
        assert!(trace::successful_exit(&exit(architecture, -4, false), architecture).is_err());
        assert!(trace::successful_exit(&exit(architecture, 0, true), architecture).is_err());
        assert!(trace::successful_exit(&entry(architecture, 82, [0; 6]), architecture).is_err());
        assert!(trace::successful_exit(&exit(architecture, 0, false)[..32], architecture).is_err());
    }
    assert!(trace::successful_exit(&exit(X64, 0, false), ARM64).is_err());
}
#[test]
fn actual_absolute_and_relative_operands_require_both_original_parent_identities() {
    let source = b"/usr/libexec/.memcordon-journal-a1";
    let target = b"/usr/libexec/.memcordon-current-package-transaction.json";
    let selected = trace::select(
        source,
        target,
        b".memcordon-journal-",
        b".memcordon-current-package-transaction.json",
        true,
        -1,
        -1,
    )
    .unwrap()
    .unwrap();
    assert_eq!(selected.source.leaf, b".memcordon-journal-a1");
    assert_eq!(
        selected.target.leaf,
        b".memcordon-current-package-transaction.json"
    );
    assert_eq!(
        selected.source.parent,
        Parent::Absolute(b"/usr/libexec".to_vec())
    );
    assert_eq!(
        selected.target.parent,
        Parent::Absolute(b"/usr/libexec".to_vec())
    );
    let relative = trace::select(
        b"pending",
        b"published",
        b"pending",
        b"published",
        false,
        6,
        -100,
    )
    .unwrap()
    .unwrap();
    assert_eq!(relative.source.parent, Parent::Descriptor(6));
    assert_eq!(relative.target.parent, Parent::Descriptor(-100));
    trace::require_parents((7, 900), (7, 900), (7, 900)).unwrap();
    assert!(trace::require_parents((7, 900), (7, 901), (7, 900)).is_err());
    assert!(trace::require_parents((7, 900), (7, 900), (8, 900)).is_err());
    // Matching leaves alone do not establish the other actual parent.
    let wrong = trace::select(
        source,
        b"/elsewhere/.memcordon-current-package-transaction.json",
        b".memcordon-journal-",
        b".memcordon-current-package-transaction.json",
        true,
        6,
        7,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        wrong.target.parent,
        Parent::Absolute(b"/elsewhere".to_vec())
    );
    assert!(trace::require_parents((7, 900), (7, 900), (7, 901)).is_err());
    let bytes = trace::select(b"p\xff", b"done", b"p", b"done", true, 6, 7)
        .unwrap()
        .unwrap();
    assert_eq!(bytes.source.leaf, b"p\xff");
}
#[test]
fn malformed_paths_and_wrong_selectors_never_qualify_as_selected_publication() {
    assert!(
        trace::select(b"", b"published", b"pending", b"published", false, 6, 7)
            .unwrap()
            .is_none()
    );
    assert!(
        trace::select(b"pending", b"", b"pending", b"published", false, 6, 7)
            .unwrap()
            .is_none()
    );
    assert!(
        trace::select(
            b"unrelated/nested/source",
            b"other/tree/target",
            b"pending",
            b"published",
            false,
            6,
            7
        )
        .unwrap()
        .is_none()
    );
    assert!(
        trace::select(
            b"unrelated/nested/source",
            b"published",
            b"pending",
            b"published",
            false,
            6,
            7
        )
        .unwrap()
        .is_none()
    );
    assert!(
        trace::select(
            b"pending",
            b"unrelated/nested/target",
            b"pending",
            b"published",
            false,
            6,
            7
        )
        .unwrap()
        .is_none()
    );
    for source in [
        b"/a/../pending".as_slice(),
        b"/a/./pending",
        b"/a//pending",
        b"dir/pending",
        b"pending/",
        b"pending\0",
    ] {
        assert!(
            trace::select(source, b"published", b"pending", b"published", false, 6, 7).is_err(),
            "{source:?}"
        );
    }
    assert!(
        trace::select(
            b"pending",
            b"published",
            b"pending",
            b"published",
            false,
            -1,
            7
        )
        .is_err()
    );
    for selector in [b"".as_slice(), b".", b"..", b"a/b"] {
        assert!(
            trace::select(
                b"pending",
                b"published",
                selector,
                b"published",
                false,
                6,
                7
            )
            .is_err()
        );
    }
    for (source, target, prefix) in [
        (b"pending".as_slice(), b"published".as_slice(), true),
        (b"other", b"published", false),
        (b"pending", b"wrong", false),
    ] {
        assert!(
            trace::select(source, target, b"pending", b"published", prefix, 6, 7)
                .unwrap()
                .is_none()
        );
    }
    assert!(
        trace::select(
            &vec![b'a'; 257],
            b"published",
            b"a",
            b"published",
            true,
            6,
            7
        )
        .is_err()
    );
}
#[test]
fn streaming_past_old_caps_retains_only_fixed_diagnostics_and_original_cutoff() {
    let start = Instant::now();
    let cutoff = start + Duration::from_secs(10);
    let mut window = TraceWindow::default();
    for index in 0..66000 {
        window.check(start, cutoff).unwrap();
        window
            .record(&if index % 2 == 0 {
                entry(X64, 1, [0; 6])
            } else {
                exit(X64, 0, false)
            })
            .unwrap();
    }
    let publication = entry(X64, 82, [12, 34, 0, 0, 0, 0]);
    window.record(&publication).unwrap();
    window.candidate();
    window.operands(b"/usr/libexec/pending", b"/usr/libexec/published");
    window.reject("different-parent");
    window.record(&exit(X64, 0, false)).unwrap();
    let diagnostic = window.diagnostic();
    assert_eq!(diagnostic["stops"], 66002);
    assert_eq!(diagnostic["entries"], 33001);
    assert_eq!(diagnostic["exits"], 33001);
    assert_eq!(diagnostic["recent"].as_array().unwrap().len(), 8);
    assert_eq!(diagnostic["candidates"], 1);
    assert_eq!(diagnostic["rejections"], 1);
    assert_eq!(diagnostic["last_rejection"], "different-parent");
    assert!(serde_json::to_vec(&diagnostic).unwrap().len() < 4096);
    assert!(trace::rename_entry(&publication, X64).unwrap().is_some());
    assert!(window.check(cutoff, cutoff).is_err());
    assert!(
        window
            .check(cutoff + Duration::from_nanos(1), cutoff)
            .is_err()
    );
    window.operands(&vec![1; 4096], &vec![2; 4096]);
    assert_eq!(
        window.diagnostic()["last_source_bytes"]
            .as_array()
            .unwrap()
            .len(),
        256
    );
    assert_eq!(
        window.diagnostic()["last_target_bytes"]
            .as_array()
            .unwrap()
            .len(),
        256
    );
    assert!(window.record(&[0; 23]).is_err());
    assert!(window.record(&[0; 129]).is_err());
}
