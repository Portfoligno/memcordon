//! Bounded supplementary launcher diagnostics; SCM convergence remains the error.

fn bounded_detail(text: &str) -> String {
    let text = format!("{text:?}");
    let limit = 4096;
    if text.len() <= limit {
        return text;
    }
    let mut head = limit / 2;
    while !text.is_char_boundary(head) {
        head -= 1;
    }
    let mut tail = text.len() - limit / 2;
    while !text.is_char_boundary(tail) {
        tail += 1;
    }
    format!(
        "{} [diagnostic omitted {} bytes] {}",
        &text[..head],
        tail - head,
        &text[tail..],
    )
}

pub(super) fn launcher_startup_stage(service_exit: u32) -> Option<&'static str> {
    (service_exit == 0x4d43_0202).then_some("state-recovery")
}

pub(super) fn launcher_failure_suffix(
    name: &str,
    service_exit: u32,
    minimum_tick: Option<u64>,
    read: impl FnOnce(u32, u64) -> Result<Option<String>, String>,
) -> String {
    if name != memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME {
        return String::new();
    }
    let Some(minimum_tick) = minimum_tick.filter(|tick| *tick != 0) else {
        return "; launcher_startup_diagnostic_status=freshness-unavailable".into();
    };
    match read(service_exit, minimum_tick) {
        Ok(Some(diagnostic)) => format!(
            "; launcher_startup_diagnostic_status=available; original_launcher_startup_failure={}",
            bounded_detail(&diagnostic),
        ),
        Ok(None) => "; launcher_startup_diagnostic_status=absent".into(),
        Err(error) => format!(
            "; launcher_startup_diagnostic_status=rejected-or-read-error; launcher_startup_diagnostic_error={}",
            bounded_detail(&error),
        ),
    }
}
