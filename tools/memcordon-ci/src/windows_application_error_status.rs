//! Fixed, identifier-free status protocol for the optional Windows observer.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    not(all(target_os = "windows", target_arch = "x86_64")),
    allow(dead_code)
)]
pub(crate) enum ObserverStatus {
    Matched,
    NoMatch,
    Unavailable,
    Timeout,
    MalformedResult,
    ReceiptAbsent,
}

#[cfg_attr(
    not(all(target_os = "windows", target_arch = "x86_64")),
    allow(dead_code)
)]
pub(crate) fn selected_candidate_native_x64_lane(
    actions: Option<&str>,
    workflow: Option<&str>,
    repository: Option<&str>,
    job: Option<&str>,
    candidate_native: bool,
) -> bool {
    actions == Some("true")
        && workflow == Some("Release")
        && repository == Some("Portfoligno/memcordon")
        && job == Some("candidate-windows-x64-native")
        && candidate_native
}

#[cfg_attr(
    not(all(target_os = "windows", target_arch = "x86_64")),
    allow(dead_code)
)]
impl ObserverStatus {
    pub(crate) const fn token(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::NoMatch => "no_match",
            Self::Unavailable => "unavailable",
            Self::Timeout => "timeout",
            Self::MalformedResult => "malformed_result",
            Self::ReceiptAbsent => "receipt_absent",
        }
    }

    /// Accept only the child's complete, fixed-token protocol. Event details,
    /// stderr, extra lines, and partial output are never propagated.
    pub(crate) fn from_child_output(success: bool, stdout: &[u8], stderr: &[u8]) -> Self {
        if !success || !stderr.is_empty() {
            return Self::MalformedResult;
        }
        match stdout {
            b"matched\n" => Self::Matched,
            b"no_match\n" => Self::NoMatch,
            b"unavailable\n" => Self::Unavailable,
            b"timeout\n" => Self::Timeout,
            b"malformed_result\n" => Self::MalformedResult,
            _ => Self::MalformedResult,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ObserverStatus, selected_candidate_native_x64_lane};

    fn selected(job: &str, delivery_is_candidate_native: bool) -> bool {
        selected_candidate_native_x64_lane(
            Some("true"),
            Some("Release"),
            Some("Portfoligno/memcordon"),
            Some(job),
            delivery_is_candidate_native,
        )
    }

    #[test]
    fn selects_only_the_release_x64_native_job() {
        assert!(selected("candidate-windows-x64-native", true));
        assert!(!selected_candidate_native_x64_lane(
            None, None, None, None, true,
        ));
        assert!(!selected_candidate_native_x64_lane(
            Some("false"),
            Some("Release"),
            Some("Portfoligno/memcordon"),
            Some("candidate-windows-x64-native"),
            true,
        ));
        assert!(!selected_candidate_native_x64_lane(
            Some("true"),
            Some("Release"),
            Some("fork/memcordon"),
            Some("candidate-windows-x64-native"),
            true,
        ));
        assert!(!selected_candidate_native_x64_lane(
            Some("true"),
            Some("Other workflow"),
            Some("Portfoligno/memcordon"),
            Some("candidate-windows-x64-native"),
            true,
        ));
        assert!(!selected("candidate-windows-x64-native", false));
        assert!(!selected("candidate-windows-x64-cargo", true));
        assert!(!selected("candidate-windows-arm64-native", true));
        assert!(!selected("candidate-windows-arm64-cargo", true));
    }

    #[test]
    fn observer_outcomes_remain_distinct() {
        assert_eq!(
            ObserverStatus::from_child_output(true, b"no_match\n", b""),
            ObserverStatus::NoMatch
        );
        assert_ne!(ObserverStatus::NoMatch, ObserverStatus::ReceiptAbsent);
        assert_ne!(ObserverStatus::NoMatch, ObserverStatus::Timeout);
        assert_ne!(ObserverStatus::NoMatch, ObserverStatus::MalformedResult);
        assert_eq!(
            ObserverStatus::from_child_output(true, b"timeout\n", b""),
            ObserverStatus::Timeout
        );
        assert_eq!(
            ObserverStatus::from_child_output(true, b"matched\nextra\n", b""),
            ObserverStatus::MalformedResult
        );
        assert_eq!(
            ObserverStatus::from_child_output(false, b"no_match\n", b""),
            ObserverStatus::MalformedResult
        );
    }

    #[test]
    fn child_protocol_rejects_unbounded_diagnostics() {
        assert_eq!(
            ObserverStatus::from_child_output(true, b"matched\n", b"raw event data"),
            ObserverStatus::MalformedResult
        );
        assert_eq!(
            ObserverStatus::from_child_output(true, b"unknown\n", b""),
            ObserverStatus::MalformedResult
        );
    }
}
