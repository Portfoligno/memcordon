#[path = "private/fixture_namespace_context_storage.rs"]
mod storage;
use std::mem::{align_of, offset_of, size_of};
use storage::ContextStorage;

#[test]
fn sole_field_preserves_data_and_is_aligned_at_each_actual_address() {
    type Sample = [u64; 2];
    assert_eq!(align_of::<ContextStorage<Sample>>(), 16);
    assert_eq!(offset_of!(ContextStorage<Sample>, 0), 0);
    assert_eq!(size_of::<ContextStorage<Sample>>(), size_of::<Sample>());
    let mut stack = ContextStorage([17u64, 29]);
    assert_eq!(std::ptr::addr_of!(stack.0) as usize % 16, 0);
    stack.0[1] = 41;
    assert_eq!(stack.0, [17, 41]);
    let heap: Vec<_> = (0..32)
        .map(|index| ContextStorage([index, !index]))
        .collect();
    for (index, value) in heap.iter().enumerate() {
        assert_eq!(
            value as *const _ as usize,
            std::ptr::addr_of!(value.0) as usize
        );
        assert_eq!(std::ptr::addr_of!(value.0) as usize % 16, 0);
        assert_eq!(value.0, [index as u64, !(index as u64)]);
    }
}
