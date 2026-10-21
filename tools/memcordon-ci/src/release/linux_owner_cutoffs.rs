//! Bind native owner cleanup authority before acquiring its first resource.
use std::time::Instant;

pub(super) fn bind(
    original_work: &mut Option<Instant>,
    original_cleanup: &mut Option<Instant>,
    work: Instant,
    cleanup: Instant,
) -> Result<(), &'static str> {
    if work >= cleanup {
        return Err("native owner work cutoff must precede its cleanup cutoff");
    }
    match (*original_work, *original_cleanup) {
        (None, None) => {
            *original_work = Some(work);
            *original_cleanup = Some(cleanup);
            Ok(())
        }
        (Some(original_work), Some(original_cleanup))
            if original_work == work && original_cleanup == cleanup =>
        {
            Ok(())
        }
        _ => Err("native owner original work/cleanup cutoffs changed or are incomplete"),
    }
}
