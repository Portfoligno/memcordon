pub(crate) fn normalize(
    arguments: &[Vec<u8>],
    lifetime: &[u8],
    expected_target: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, &'static str> {
    let suffix: [&[u8]; 5] = [
        b"--image-entrypoint",
        b"owned-readiness",
        b"--wait-for",
        lifetime,
        b"--",
    ];
    let markers = arguments
        .windows(suffix.len())
        .enumerate()
        .filter(|(_, values)| {
            values
                .iter()
                .zip(suffix)
                .all(|(value, expected)| value == expected)
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if markers.len() != 1 {
        return Err("actual lifecycle frontend entrypoint argument association differs");
    }
    let target = &arguments[markers[0] + suffix.len()..];
    if target != expected_target {
        return Err("actual lifecycle native target arguments changed");
    }
    Ok(target.to_vec())
}
