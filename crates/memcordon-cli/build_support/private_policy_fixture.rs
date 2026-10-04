use crate::private_policy_fixture_schema::ReviewedPolicyFixtureV1;

pub(crate) const SOURCE_RELATIVE: &str =
    "src/bin/memcordon-sealed-agent/linux/fixtures/private_policy_branches_v1.json";
pub(crate) const OUTPUT_NAME: &str = "private_policy_branches_v1.json";

fn normalize_line_endings(source: &[u8]) -> Result<Vec<u8>, String> {
    let mut normalized = Vec::with_capacity(source.len());
    let mut bytes = source.iter().copied();

    while let Some(byte) = bytes.next() {
        match byte {
            b'\r' => match bytes.next() {
                Some(b'\n') => normalized.push(b'\n'),
                Some(_) | None => {
                    return Err(
                        "MCSEALED-PRIVATE-RELEASE: policy fixture contains a bare carriage return"
                            .into(),
                    );
                }
            },
            byte => normalized.push(byte),
        }
    }
    Ok(normalized)
}

/// Accept checkout line endings while retaining the reviewed byte encoding.
pub(crate) fn canonicalize(source: &[u8]) -> Result<Vec<u8>, String> {
    let normalized = normalize_line_endings(source)?;
    let body = normalized
        .strip_suffix(b"\n")
        .ok_or("MCSEALED-PRIVATE-RELEASE: policy fixture newline absent")?;
    let fixture: ReviewedPolicyFixtureV1 =
        serde_json::from_slice(body).map_err(|error| error.to_string())?;
    fixture.validate_expected().map_err(str::to_owned)?;

    let mut canonical = serde_json::to_vec(&fixture).map_err(|error| error.to_string())?;
    if canonical.as_slice() != body {
        return Err("MCSEALED-PRIVATE-RELEASE: policy fixture is not canonical".into());
    }
    canonical.push(b'\n');
    Ok(canonical)
}
