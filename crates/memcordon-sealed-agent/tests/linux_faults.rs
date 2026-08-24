#![cfg(target_os = "linux")]

// Privileged fault selectors share the isolated marker and typed-outcome harness in
// `linux_sealed`; this target remains as a compile-only guard against stale CI selectors.
