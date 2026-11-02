//! One nonblocking owned-lane observation; never settlement or retirement proof.
use std::time::Instant;

pub enum WriterStatus {
    NoQuarantinedObserved,
    Unavailable,
    Unconfirmed {
        detail: String,
        native_code: Option<u32>,
    },
}

enum Sample {
    Cutoff,
    Observed {
        status: WriterStatus,
        completed_before_cutoff: bool,
    },
}

#[derive(Default)]
pub struct Observation {
    sample: Option<Sample>,
}

impl Observation {
    /// `query` must be the existing bounded, nonblocking owned registry query.
    /// Return the original quiescence value without interpreting diagnostics.
    pub fn observe(
        &mut self,
        quiescent: bool,
        cutoff: Instant,
        query: impl FnOnce() -> WriterStatus,
    ) -> bool {
        if !quiescent && self.sample.is_none() {
            self.sample = Some(if Instant::now() >= cutoff {
                Sample::Cutoff
            } else {
                let status = query();
                Sample::Observed {
                    status,
                    completed_before_cutoff: Instant::now() < cutoff,
                }
            });
        }
        quiescent
    }

    pub fn detail(&self) -> Option<String> {
        let sample = self.sample.as_ref()?;
        let (status, completed_before_cutoff) = match sample {
            Sample::Cutoff => return Some("owned-writer-registry=unavailable-original-cutoff; retirement-proof=false; admission-binding=unavailable".into()),
            Sample::Observed { status, completed_before_cutoff } => (status, completed_before_cutoff),
        };
        let text = match status {
            WriterStatus::NoQuarantinedObserved => "no-quarantined-lane-observed".into(),
            WriterStatus::Unavailable => "unavailable-nonblocking-query".into(),
            WriterStatus::Unconfirmed {
                detail,
                native_code,
            } => {
                let mut end = detail.len().min(4096);
                while !detail.is_char_boundary(end) {
                    end -= 1;
                }
                format!(
                    "unconfirmed; recorded-publisher-win32-code={native_code:?}; detail-truncated={}; detail={}",
                    end != detail.len(),
                    &detail[..end]
                )
            }
        };
        Some(format!(
            "owned-writer-registry={text}; completed-before-original-cutoff={completed_before_cutoff}; retirement-proof=false; admission-binding=unavailable"
        ))
    }
}
