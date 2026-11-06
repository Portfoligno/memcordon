//! Two bounded historical samples; neither changes settlement authority.
use super::writer_lifecycle::{self as model, Snapshot};
use std::time::Instant;

pub enum WriterStatus {
    LocalSnapshot {
        detail: String,
        snapshot: Box<Snapshot>,
    },
}

struct Sample {
    sampled_at: Instant,
    status: Option<WriterStatus>,
    completed_before_cutoff: bool,
    detail_truncated: bool,
}

#[derive(Default)]
pub struct Observation {
    first: Option<Sample>,
    later: Option<Sample>,
    later_due: Option<Instant>,
    original_cutoff: Option<Instant>,
    cutoff_changed: bool,
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
        self.observe_at(Instant::now(), quiescent, cutoff, query)
    }

    /// The supplied instant permits deterministic scheduling tests without waits.
    pub fn observe_at(
        &mut self,
        now: Instant,
        quiescent: bool,
        cutoff: Instant,
        query: impl FnOnce() -> WriterStatus,
    ) -> bool {
        if quiescent {
            return quiescent;
        }
        if self
            .original_cutoff
            .is_some_and(|original| original != cutoff)
        {
            self.cutoff_changed = true;
            return quiescent;
        }
        let first = self.first.is_none();
        if !first && (self.later.is_some() || self.later_due.is_none_or(|due| now < due)) {
            return quiescent;
        }
        if first {
            self.original_cutoff = Some(cutoff);
            let remaining = cutoff.saturating_duration_since(now);
            self.later_due = cutoff.checked_sub(remaining / 4);
        }
        let mut detail_truncated = false;
        let status = if now >= cutoff || Instant::now() >= cutoff {
            None
        } else {
            let mut status = query();
            let WriterStatus::LocalSnapshot { detail, snapshot } = &mut status;
            let mut end = detail.len().min(model::RECORD_BYTES);
            while !detail.is_char_boundary(end) {
                end -= 1;
            }
            detail_truncated = end != detail.len();
            detail.truncate(end);
            snapshot.records.truncate(model::JOURNAL_RECORDS);
            Some(status)
        };
        let sample = Sample {
            sampled_at: now,
            completed_before_cutoff: status.is_some() && Instant::now() < cutoff,
            status,
            detail_truncated,
        };
        if first {
            self.first = Some(sample);
        } else {
            self.later = Some(sample);
        }
        quiescent
    }

    pub fn detail(&self) -> Option<String> {
        fn render(sample: &Sample, first_at: Instant, ordinal: u8) -> String {
            let elapsed = sample
                .sampled_at
                .saturating_duration_since(first_at)
                .as_millis();
            let text = match &sample.status {
                None => "unavailable-original-cutoff".into(),
                Some(WriterStatus::LocalSnapshot { detail, .. }) => format!(
                    "local-lifecycle-snapshot; historical-filename-correlation-only=true; detail-truncated={}; detail={detail}",
                    sample.detail_truncated
                ),
            };
            format!(
                "sample-ordinal={ordinal}; sampled-after-first-ms={elapsed}; owned-writer-registry={text}; completed-before-original-cutoff={}; retirement-proof=false; admission-binding=unavailable",
                sample.completed_before_cutoff
            )
        }
        let first = self.first.as_ref()?;
        let mut text = format!(
            "first-false-quiescence=[{}]",
            render(first, first.sampled_at, 1)
        );
        if let Some(later) = &self.later {
            text.push_str(&format!(
                "; later-pre-cutoff=[{}]",
                render(later, first.sampled_at, 2)
            ));
            if let (
                Some(WriterStatus::LocalSnapshot {
                    snapshot: before, ..
                }),
                Some(WriterStatus::LocalSnapshot {
                    snapshot: after, ..
                }),
            ) = (&first.status, &later.status)
            {
                text.push_str(&format!(
                    "; temporal-comparison={}",
                    model::temporal_comparison(before, after)
                ));
            }
        } else {
            text.push_str(if self.cutoff_changed {
                "; later-pre-cutoff=unavailable-cutoff-changed"
            } else {
                "; later-pre-cutoff=unavailable-not-sampled"
            });
        }
        Some(text)
    }

    pub fn final_name_detail(&self, tokens: &[String]) -> Option<String> {
        self.first.as_ref()?;
        let text = match self.later.as_ref().map(|sample| &sample.status) {
            Some(Some(WriterStatus::LocalSnapshot { snapshot, .. })) => {
                model::filename_correlations(snapshot, tokens).to_string()
            }
            Some(None) => "unavailable-original-cutoff".into(),
            None => "unavailable-later-sample".into(),
        };
        Some(format!(
            "last-successful-name-sample-vs-later={text}; current-file-binding=false; retirement-proof=false"
        ))
    }
}
