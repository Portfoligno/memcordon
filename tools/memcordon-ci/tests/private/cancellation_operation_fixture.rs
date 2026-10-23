//! Narrow an already admitted test owner without attempting admission again.
use super::{GroupGuard, active_group};
use crate::Result;
use std::time::Instant;

pub(crate) fn with_work_deadline<T>(
    deadline: Instant,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let mut group = active_group().expect("cancellation fixture requires an admitted owner");
    group.deadline = group.deadline.min(deadline);
    let _guard = GroupGuard::install(group);
    operation()
}
