//! Pure bounds for copying only the public native TypeName buffer.
use super::protocol::NAME_UNITS_BOUND;
pub fn native_type_name_extent(
    start: usize,
    returned: usize,
    pointer: usize,
    length: u16,
    maximum: u16,
) -> bool {
    start.checked_add(returned).is_some()
        && length != 0
        && length % 2 == 0
        && maximum % 2 == 0
        && length <= maximum
        && usize::from(length) / size_of::<u16>() <= NAME_UNITS_BOUND
        && pointer % std::mem::align_of::<u16>() == 0
        && pointer
            .checked_sub(start)
            .and_then(|offset| offset.checked_add(usize::from(maximum)))
            .is_some_and(|end| end <= returned)
}
