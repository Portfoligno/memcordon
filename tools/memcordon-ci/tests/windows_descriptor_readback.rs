#![deny(unsafe_code, dead_code)]

#[path = "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/kernel_descriptor_length.rs"]
mod kernel_descriptor_length;

use kernel_descriptor_length::validate_lengths;

#[test]
fn successful_zero_required_length_uses_actual_bounded_descriptor_length() {
    assert_eq!(validate_lengths(216, 0, 216), Ok(()));
    assert_eq!(validate_lengths(216, 0, 128), Ok(()));
    assert_eq!(validate_lengths(216, 216, 216), Ok(()));
    assert_eq!(validate_lengths(216, 200, 128), Ok(()));
}

#[test]
fn required_length_never_replaces_owned_or_actual_descriptor_bounds() {
    for (allocated, reported, actual) in [
        (0, 0, 0),
        (0, 0, 1),
        (216, 0, 0),
        (216, 216, 0),
        (216, 0, 217),
        (216, 217, 128),
        (216, 128, 216),
        (216, u32::MAX, 216),
        (216, 0, u32::MAX),
    ] {
        assert!(validate_lengths(allocated, reported, actual).is_err());
    }
}
