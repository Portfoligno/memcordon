#[path = "../src/bin/consumer_readiness_windows/matched_control_sd_diagnostic.rs"]
pub mod diagnostic;
use diagnostic::{RelativeResult, State, inspect};

#[test]
fn live_zero_output_mints_only_exact_native_extent_from_the_same_owned_words() {
    let mut words = buffer();
    words[34] = u32::from_ne_bytes([11, 12, 13, 14]);
    words[35] = u32::from_ne_bytes([21, 22, 23, 24]);
    let supplied = std::mem::size_of_val(words.as_slice()) as u32;
    let original: Vec<_> = words.iter().flat_map(|word| word.to_ne_bytes()).collect();
    for length in [supplied, supplied - 5] {
        let extent = diagnostic::validate_zero(
            &words,
            supplied,
            || true,
            |bound| {
                assert_eq!(bound, supplied);
                RelativeResult::Returned(1)
            },
            || 1,
            || length,
        )
        .unwrap();
        assert_eq!(extent.byte_len(), length as usize);
        assert_eq!(extent.bytes(), original[..length as usize]);
        assert_eq!(extent.facts().native_length, Some(length));
    }
    assert_eq!(
        words
            .iter()
            .flat_map(|word| word.to_ne_bytes())
            .collect::<Vec<_>>(),
        original,
        "extent extraction must preserve every original descriptor byte"
    );
}

#[test]
fn typed_extent_cannot_be_minted_from_unavailable_invalid_or_expired_observations() {
    let words = buffer();
    let supplied = std::mem::size_of_val(words.as_slice()) as u32;
    for (relative, valid, length, expected) in [
        (
            RelativeResult::Unavailable,
            1,
            supplied,
            State::ExportUnavailable,
        ),
        (
            RelativeResult::Returned(0),
            1,
            supplied,
            State::RelativeInvalid,
        ),
        (
            RelativeResult::Returned(1),
            0,
            supplied,
            State::NativeInvalid,
        ),
        (
            RelativeResult::Returned(1),
            1,
            0,
            State::LengthOutsideBuffer,
        ),
        (
            RelativeResult::Returned(1),
            1,
            supplied + 1,
            State::LengthOutsideBuffer,
        ),
    ] {
        let facts = match diagnostic::validate_zero(
            &words,
            supplied,
            || true,
            |_| relative,
            || valid,
            || length,
        ) {
            Ok(_) => panic!("invalid observation minted a descriptor extent"),
            Err(facts) => facts,
        };
        assert_eq!(facts.state, expected);
    }
    let mut checks = 0;
    let failed = diagnostic::validate_zero(
        &words,
        supplied,
        || {
            checks += 1;
            checks < 4
        },
        |_| RelativeResult::Returned(1),
        || 1,
        || supplied,
    );
    let Err(facts) = failed else {
        panic!("cutoff after native length must prevent extent authority");
    };
    assert_eq!(facts.state, State::Cutoff);
    assert_eq!(facts.native_length, Some(supplied));
}

#[test]
fn byte_materialization_is_bounded_and_physical_oversize_cannot_mint_an_extent() {
    let words = buffer();
    let physical = std::mem::size_of_val(words.as_slice());
    assert!(diagnostic::bytes_for_extent(&words, physical + 1).is_none());
    assert_eq!(
        diagnostic::bytes_for_extent(&words, physical)
            .unwrap()
            .len(),
        physical
    );
    let mut oversized = vec![0; 8192 / std::mem::size_of::<u32>() + 1];
    oversized[0] = words[0];
    let Err(facts) = diagnostic::validate_zero(
        &oversized,
        physical as u32,
        || panic!("oversize owner must not enter native validation"),
        |_| panic!("oversize owner must not enter native validation"),
        || panic!("oversize owner must not enter native validation"),
        || panic!("oversize owner must not enter native validation"),
    ) else {
        panic!("oversize physical owner minted an extent");
    };
    assert_eq!(facts.state, State::BufferBoundInvalid);
    let malformed = vec![0; words.len()];
    let Err(facts) = diagnostic::validate_zero(
        &malformed,
        physical as u32,
        || panic!("malformed header must not enter native validation"),
        |_| panic!("malformed header must not enter native validation"),
        || panic!("malformed header must not enter native validation"),
        || panic!("malformed header must not enter native validation"),
    ) else {
        panic!("malformed header minted an extent");
    };
    assert_eq!(facts.state, State::HeaderInvalid);
}

fn buffer() -> Vec<u32> {
    let mut words = vec![0; 36];
    let control = 0x8000_u16.to_ne_bytes();
    words[0] = u32::from_ne_bytes([1, 0, control[0], control[1]]);
    words
}

#[test]
fn structural_query_uses_readable_bound_then_native_validity_before_observed_length() {
    let words = buffer();
    let bound = std::mem::size_of_val(words.as_slice()) as u32;
    let calls = std::cell::RefCell::new(Vec::new());
    let facts = inspect(
        &words,
        bound,
        || true,
        |supplied| {
            assert_eq!(supplied, bound);
            calls.borrow_mut().push("relative");
            RelativeResult::Returned(1)
        },
        || {
            calls.borrow_mut().push("native");
            1
        },
        || {
            calls.borrow_mut().push("length");
            bound - 4
        },
    );
    assert_eq!(*calls.borrow(), ["relative", "native", "length"]);
    assert_eq!(facts.revision, Some(1));
    assert_eq!(facts.control, Some(0x8000));
    assert_eq!(facts.relative_structural_valid, Some(1));
    assert_eq!(facts.native_valid, Some(1));
    assert_eq!(
        facts.native_length,
        Some(bound - 4),
        "capacity is not an observed descriptor length"
    );
    assert_eq!(facts.state, State::Observed);
}

#[test]
fn invalid_buffer_or_header_never_reaches_any_pointer_based_native_query() {
    let mut words = buffer();
    let bound = std::mem::size_of_val(words.as_slice()) as u32;
    for supplied in [0, 19, bound + 1, 8193] {
        let facts = inspect(
            &words,
            supplied,
            || panic!("no query"),
            |_| panic!("no relative query"),
            || panic!("no native query"),
            || panic!("no length query"),
        );
        assert_eq!(facts.state, State::BufferBoundInvalid);
        assert!(facts.native_length.is_none());
    }
    for header in [[0, 0, 0, 0], [1, 0, 0, 0]] {
        words[0] = u32::from_ne_bytes(header);
        let facts = inspect(
            &words,
            bound,
            || panic!("no query"),
            |_| panic!("no relative query"),
            || panic!("no native query"),
            || panic!("no length query"),
        );
        assert_eq!(facts.state, State::HeaderInvalid);
        assert!(facts.relative_structural_valid.is_none());
    }
    let facts = inspect(
        &[],
        bound,
        || panic!("no query"),
        |_| panic!("no relative query"),
        || panic!("no native query"),
        || panic!("no length query"),
    );
    assert_eq!(facts.state, State::BufferBoundInvalid);
}

#[test]
fn unavailable_invalid_or_expired_validation_never_blindly_queries_descriptor_length() {
    let words = buffer();
    let bound = std::mem::size_of_val(words.as_slice()) as u32;
    for (relative, state) in [
        (RelativeResult::Unavailable, State::ExportUnavailable),
        (RelativeResult::Cutoff, State::Cutoff),
        (RelativeResult::Returned(0), State::RelativeInvalid),
    ] {
        let facts = inspect(
            &words,
            bound,
            || true,
            |_| relative,
            || panic!("native validity must not run"),
            || panic!("length must not run"),
        );
        assert_eq!(facts.state, state);
        assert!(facts.native_length.is_none());
    }
    let facts = inspect(
        &words,
        bound,
        || true,
        |_| RelativeResult::Returned(1),
        || 0,
        || panic!("invalid descriptor length is undefined"),
    );
    assert_eq!(facts.state, State::NativeInvalid);
    assert!(facts.native_length.is_none());
    let facts = inspect(
        &words,
        bound,
        || false,
        |_| panic!("original cutoff expired"),
        || panic!("original cutoff expired"),
        || panic!("original cutoff expired"),
    );
    assert_eq!(facts.state, State::Cutoff);
    let mut checks = 0;
    let facts = inspect(
        &words,
        bound,
        || {
            checks += 1;
            checks < 3
        },
        |_| RelativeResult::Returned(1),
        || 1,
        || panic!("cutoff expired before length"),
    );
    assert_eq!(facts.state, State::Cutoff);
    assert!(facts.native_length.is_none());
}

#[test]
fn native_length_outside_buffer_remains_an_observation_never_capacity_substitution() {
    let words = buffer();
    let bound = std::mem::size_of_val(words.as_slice()) as u32;
    for length in [0, bound + 1] {
        let facts = inspect(
            &words,
            bound,
            || true,
            |_| RelativeResult::Returned(1),
            || 1,
            || length,
        );
        assert_eq!(facts.state, State::LengthOutsideBuffer);
        assert_eq!(facts.native_length, Some(length));
        assert!(format!("{facts:?}").len() < 512);
    }
}
