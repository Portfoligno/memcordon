/// Validate lengths only after a successful native query and descriptor validation.
/// A zero required-length output adds no bound beyond the retained allocation.
pub(super) fn validate_lengths(
    allocated: u32,
    reported: u32,
    actual: u32,
) -> Result<(), &'static str> {
    if allocated == 0 {
        return Err("descriptor allocation is empty");
    }
    if reported > allocated {
        return Err("reported descriptor length exceeds owned allocation");
    }
    if actual == 0 || actual > allocated {
        return Err("actual descriptor length exceeds owned allocation or is empty");
    }
    if reported != 0 && actual > reported {
        return Err("actual descriptor length exceeds nonzero native reported length");
    }
    Ok(())
}
