//! Raw effect comparisons only. Native execution, identity, and retirement are
//! independently joined by the platform verifier before these checks are used.
use crate::{NativeArguments, VerificationResult};

fn binary_vector(bytes: &[u8]) -> VerificationResult<()> {
    if bytes.iter().copied().ne(u8::MIN..=u8::MAX) {
        return Err("raw binary vector omits or changes a byte value".into());
    }
    Ok(())
}

pub fn verify_raw_streams(
    kind: &str,
    binary: &[u8],
    stdout: &[u8],
    stderr: &[u8],
) -> VerificationResult<()> {
    let stderr_binary = binary.iter().copied().rev().collect::<Vec<_>>();
    verify_raw_streams_expected(kind, binary, &stderr_binary, stdout, stderr)
}

pub fn verify_raw_streams_expected(
    kind: &str,
    binary: &[u8],
    stderr_binary: &[u8],
    stdout: &[u8],
    stderr: &[u8],
) -> VerificationResult<()> {
    if kind == "empty-input" {
        if !binary.is_empty()
            || !stderr_binary.is_empty()
            || !stdout.is_empty()
            || !stderr.is_empty()
        {
            return Err("actual empty-input streams contain bytes".into());
        }
        return Ok(());
    }
    if !["binary-streams", "bounded-large-output"].contains(&kind) {
        return Err("unknown raw stream effect".into());
    }
    binary_vector(binary)?;
    if stderr_binary != binary
        && stderr_binary
            .iter()
            .copied()
            .ne(binary.iter().copied().rev())
    {
        return Err("original stderr operand is not the declared complete byte vector".into());
    }
    if stdout.is_empty()
        || stdout.len() != stderr.len()
        || !stdout.len().is_multiple_of(binary.len())
        || stdout
            .iter()
            .copied()
            .ne(binary.iter().copied().cycle().take(stdout.len()))
        || stderr
            .iter()
            .copied()
            .ne(stderr_binary.iter().copied().cycle().take(stderr.len()))
    {
        return Err("actual stdout/stderr bytes are truncated, mixed, or differ from complete independent vectors".into());
    }
    if kind == "bounded-large-output" && stdout.len() < 2 * 1024 * 1024 {
        return Err(
            "actual large stream output did not exceed the frozen two MiB bound per stream".into(),
        );
    }
    Ok(())
}

pub fn verify_binary_file(expected: &[u8], actual: &[u8]) -> VerificationResult<()> {
    binary_vector(expected)?;
    if expected != actual {
        return Err("actual binary file bytes differ from original input".into());
    }
    Ok(())
}

pub fn verify_native_argv(
    expected: &NativeArguments,
    observed: &NativeArguments,
    scenario: &str,
) -> VerificationResult<()> {
    let target = match expected {
        NativeArguments::UnixBytes(_) => "aarch64-unknown-linux-gnu",
        NativeArguments::WindowsUtf16(_) => "aarch64-pc-windows-msvc",
    };
    crate::wire::validate_arguments(expected, target)?;
    crate::wire::validate_arguments(observed, target)?;
    if serde_json::to_value(expected).map_err(|error| error.to_string())?
        != serde_json::to_value(observed).map_err(|error| error.to_string())?
    {
        return Err("actual native argv differs from the original prelaunch operands".into());
    }
    if scenario != "native-argv" {
        return Err("unknown native argv effect".into());
    }
    let values: Vec<Vec<u32>> = match observed {
        NativeArguments::UnixBytes(values) => values
            .iter()
            .map(|value| value.iter().map(|byte| u32::from(*byte)).collect())
            .collect(),
        NativeArguments::WindowsUtf16(values) => values
            .iter()
            .map(|value| value.iter().map(|unit| u32::from(*unit)).collect())
            .collect(),
    };
    for marker in [
        u32::from(b' '),
        u32::from(b'\t'),
        u32::from(b'"'),
        u32::from(b'\\'),
    ] {
        if !values.iter().any(|value| value.contains(&marker)) {
            return Err(
                "native argv omitted a frozen whitespace, quote, or backslash operand".into(),
            );
        }
    }
    if !values.iter().any(Vec::is_empty)
        || !values
            .iter()
            .flatten()
            .any(|unit| *unit > u32::from(u8::MAX >> 1))
    {
        return Err("native argv omitted the empty or non-ASCII operand".into());
    }
    if let NativeArguments::UnixBytes(values) = observed
        && !values
            .iter()
            .any(|value| std::str::from_utf8(value).is_err())
    {
        return Err("Unix native argv omitted its raw non-UTF8 operand".into());
    }
    Ok(())
}
