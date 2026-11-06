//! One nonblocking owned-lane observation; never settlement or retirement proof.
use std::time::Instant;

pub enum WriterStatus {
    LocalSnapshot { detail: String },
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
            WriterStatus::LocalSnapshot { detail } => {
                let mut end = detail.len().min(8192);
                while !detail.is_char_boundary(end) {
                    end -= 1;
                }
                format!(
                    "local-lifecycle-snapshot; historical-filename-correlation-only=true; detail-truncated={}; detail={}",
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
