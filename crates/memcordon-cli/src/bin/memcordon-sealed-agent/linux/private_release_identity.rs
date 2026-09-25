//! Target-observed credential and usable-capability projection for one fixed
//! candidate release selector. The native owner and CI must join it to their
//! separate protected identity and process observations.

pub(crate) const SELECTOR: &str = "private_tcp::target_credentials_and_capabilities_dropped";

pub(crate) fn expected_projection() -> [u8; 33] {
    let mut projection = [0_u8; 33];
    projection[32] = 1;
    projection
}

pub(crate) fn observe_target_projection() -> Result<[u8; 33], String> {
    // SAFETY: this prctl form reads a scalar process property and does not
    // mutate privilege state. A failed query cannot satisfy the fixture.
    let no_new_privs = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if no_new_privs != 1 {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: no-new-privileges differs".into());
    }
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-FIXTURE: status: {error}"))?;
    let mut projection = [0_u8; 33];
    for (index, field) in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"]
        .into_iter()
        .enumerate()
    {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .ok_or("MCSEALED-PRIVATE-RELEASE-FIXTURE: capability field absent")?;
        let bits = u64::from_str_radix(value.trim(), 16)
            .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-FIXTURE: capability: {error}"))?;
        projection[index * 8..(index + 1) * 8].copy_from_slice(&bits.to_le_bytes());
        if bits != 0 {
            return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: usable capability present".into());
        }
    }
    projection[32] = u8::try_from(no_new_privs)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE-FIXTURE: no-new-privileges out of range")?;
    if projection != expected_projection() {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: credential projection differs".into());
    }
    Ok(projection)
}
