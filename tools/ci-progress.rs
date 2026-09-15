//! Bounded phase diagnostics; stdout belongs to the fingerprint protocol.
use std::time::Instant;

pub fn phase<T, E>(label: &str, operation: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
    let started = Instant::now();
    eprintln!("[native fingerprint] start {label}");
    let result = operation();
    let status = if result.is_ok() { "complete" } else { "failed" };
    eprintln!(
        "[native fingerprint] {status} {label} elapsed_ms={}",
        started.elapsed().as_millis()
    );
    result
}
