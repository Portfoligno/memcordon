//! Complete-line progress observations remain independent of console admission.
use crate::cargo_progress::CargoProgress;
use memcordon_testkit::OutputStream;
use std::time::Duration;

/// Return escaped console text only when its existing quota admits emission.
/// Diagnostic observations always receive bounded, already-redacted text.
pub fn observe_complete_line(
    bytes: &[u8],
    secrets: &[String],
    remaining_console: &mut usize,
    progress: Option<&mut CargoProgress>,
    elapsed: Duration,
    stream: OutputStream,
) -> Option<String> {
    if bytes.len() > 8192 {
        return None;
    }
    let mut text = String::from_utf8_lossy(bytes).into_owned();
    for secret in secrets.iter().filter(|secret| !secret.is_empty()) {
        text = text.replace(secret, "[redacted]");
    }
    let lower = text.to_ascii_lowercase();
    if [
        "authorization:",
        "access_token",
        "refresh_token",
        "password=",
        "token=",
    ]
    .iter()
    .any(|field| lower.contains(field))
    {
        text = "[sensitive HTTP material redacted]".into();
    }
    let safe: String = text.chars().flat_map(char::escape_default).collect();
    if let Some(observed) = progress {
        observed.observe_line(elapsed, stream, &safe);
        observed.observe_artifact(elapsed, &text);
    }
    if *remaining_console == 0 {
        return None;
    }
    *remaining_console = remaining_console.saturating_sub(safe.len());
    Some(safe)
}
