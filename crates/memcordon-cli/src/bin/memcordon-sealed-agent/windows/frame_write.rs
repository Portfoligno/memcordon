//! Existing frame encoding with scalar progress only; no native I/O or authority.
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameWritePhase {
    Serialize,
    Length,
    Payload,
    Drain,
}

#[derive(Debug)]
pub struct FrameWriteError {
    pub phase: FrameWritePhase,
    pub expected_bytes: usize,
    pub transferred_bytes: usize,
    pub native_code: Option<u32>,
    pub peer_closed: bool,
    pub(super) detail: String,
}

impl FrameWriteError {
    pub fn new(
        phase: FrameWritePhase,
        expected_bytes: usize,
        transferred_bytes: usize,
        native_code: Option<u32>,
        peer_closed: bool,
        detail: String,
    ) -> Self {
        Self {
            phase,
            expected_bytes,
            transferred_bytes,
            native_code,
            peer_closed,
            detail,
        }
    }
}

impl std::fmt::Display for FrameWriteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "MCSEALED-WINDOWS-PIPE-WRITE: phase={:?} expected_bytes={} transferred_bytes={} native_code={:?} peer_closed={} detail={}",
            self.phase,
            self.expected_bytes,
            self.transferred_bytes,
            self.native_code,
            self.peer_closed,
            self.detail
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProgressPhase {
    Serialize,
    HeaderWrite,
    PayloadWrite,
    Drain,
    WatcherFinish,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProgressOutcome {
    Attempted,
    ReturnedOk,
    ReturnedError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct WriteProgress {
    pub phase: ProgressPhase,
    pub outcome: ProgressOutcome,
    pub expected_bytes: Option<usize>,
    pub transferred_bytes: usize,
    pub native_code: Option<u32>,
    pub observed_write_count: Option<usize>,
    pub native_call_succeeded: Option<bool>,
}

pub type ErrorFactory = fn(FrameWritePhase, usize, usize, Option<u32>, String) -> FrameWriteError;

fn progress(
    phase: ProgressPhase,
    outcome: ProgressOutcome,
    expected_bytes: Option<usize>,
    transferred_bytes: usize,
) -> WriteProgress {
    WriteProgress {
        phase,
        outcome,
        expected_bytes,
        transferred_bytes,
        native_code: None,
        observed_write_count: None,
        native_call_succeeded: None,
    }
}

pub fn write_frame_using<T: Serialize>(
    value: &T,
    mut write: impl FnMut(&[u8]) -> Result<usize, (Option<u32>, usize, String)>,
    observe: &mut dyn FnMut(WriteProgress),
    error_factory: ErrorFactory,
) -> Result<(), FrameWriteError> {
    observe(progress(
        ProgressPhase::Serialize,
        ProgressOutcome::Attempted,
        None,
        0,
    ));
    let serialized = (|| {
        let payload = serde_json::to_vec(value).map_err(|error| {
            error_factory(FrameWritePhase::Serialize, 0, 0, None, error.to_string())
        })?;
        if let Ok(limit) = memcordon_core::windows_response_frame_limit(
            &payload[..payload
                .len()
                .min(memcordon_core::WINDOWS_RESPONSE_PREFIX_BYTES)],
        ) {
            if payload.len() > limit {
                return Err(error_factory(
                    FrameWritePhase::Serialize,
                    payload.len(),
                    0,
                    None,
                    "diagnostic control frame exceeds its reserved bound".into(),
                ));
            }
        }
        if payload.len() > memcordon_core::WINDOWS_MAX_FRAME_BYTES {
            return Err(error_factory(
                FrameWritePhase::Serialize,
                payload.len(),
                0,
                None,
                "Windows provider frame exceeds the protocol bound".into(),
            ));
        }
        let length = u32::try_from(payload.len()).map_err(|_| {
            error_factory(
                FrameWritePhase::Serialize,
                payload.len(),
                0,
                None,
                "Windows provider frame length is not representable".into(),
            )
        })?;
        Ok((payload, length.to_le_bytes()))
    })();
    let (payload, header) = match serialized {
        Ok(value) => {
            observe(progress(
                ProgressPhase::Serialize,
                ProgressOutcome::ReturnedOk,
                Some(value.0.len()),
                0,
            ));
            value
        }
        Err(error) => {
            observe(progress(
                ProgressPhase::Serialize,
                ProgressOutcome::ReturnedError,
                (error.expected_bytes != 0).then_some(error.expected_bytes),
                0,
            ));
            return Err(error);
        }
    };
    for (phase, observed_phase, segment) in [
        (
            FrameWritePhase::Length,
            ProgressPhase::HeaderWrite,
            header.as_slice(),
        ),
        (
            FrameWritePhase::Payload,
            ProgressPhase::PayloadWrite,
            payload.as_slice(),
        ),
    ] {
        let mut transferred = 0;
        while transferred < segment.len() {
            let remaining = &segment[transferred..];
            observe(progress(
                observed_phase,
                ProgressOutcome::Attempted,
                Some(segment.len()),
                transferred,
            ));
            match write(remaining) {
                Ok(written) if written > 0 && written <= remaining.len() => {
                    transferred += written;
                    let mut observation = progress(
                        observed_phase,
                        ProgressOutcome::ReturnedOk,
                        Some(segment.len()),
                        transferred,
                    );
                    observation.observed_write_count = Some(written);
                    observation.native_call_succeeded = Some(true);
                    observe(observation);
                }
                Ok(written) => {
                    let mut observation = progress(
                        observed_phase,
                        ProgressOutcome::ReturnedError,
                        Some(segment.len()),
                        transferred,
                    );
                    observation.observed_write_count = Some(written);
                    observation.native_call_succeeded = Some(true);
                    observe(observation);
                    return Err(error_factory(
                        phase,
                        segment.len(),
                        transferred,
                        None,
                        "zero-progress or invalid native write count".into(),
                    ));
                }
                Err((code, written, detail)) => {
                    let total = transferred.saturating_add(written);
                    let mut observation = progress(
                        observed_phase,
                        ProgressOutcome::ReturnedError,
                        Some(segment.len()),
                        total,
                    );
                    observation.native_code = code;
                    observation.observed_write_count = Some(written);
                    observation.native_call_succeeded = Some(false);
                    observe(observation);
                    return Err(error_factory(phase, segment.len(), total, code, detail));
                }
            }
        }
    }
    Ok(())
}

pub fn complete_frame_using<T: Serialize>(
    value: &T,
    write: impl FnMut(&[u8]) -> Result<usize, (Option<u32>, usize, String)>,
    observe: &mut dyn FnMut(WriteProgress),
    error_factory: ErrorFactory,
    drain: impl FnOnce() -> Result<(), FrameWriteError>,
    finish: impl FnOnce() -> Result<(), String>,
) -> Result<(), FrameWriteError> {
    let result = write_frame_using(value, write, observe, error_factory).and_then(|()| {
        observe(progress(
            ProgressPhase::Drain,
            ProgressOutcome::Attempted,
            None,
            0,
        ));
        let drained = drain();
        let mut observation = progress(
            ProgressPhase::Drain,
            if drained.is_ok() {
                ProgressOutcome::ReturnedOk
            } else {
                ProgressOutcome::ReturnedError
            },
            None,
            0,
        );
        observation.native_call_succeeded = Some(drained.is_ok());
        if let Err(error) = &drained {
            observation.native_code = error.native_code;
        }
        observe(observation);
        drained
    });
    observe(progress(
        ProgressPhase::WatcherFinish,
        ProgressOutcome::Attempted,
        None,
        0,
    ));
    let settled = finish();
    observe(progress(
        ProgressPhase::WatcherFinish,
        if settled.is_ok() {
            ProgressOutcome::ReturnedOk
        } else {
            ProgressOutcome::ReturnedError
        },
        None,
        0,
    ));
    match (result, settled) {
        (Err(mut primary), Err(secondary)) => {
            primary.detail.push_str("; transport settlement: ");
            primary.detail.push_str(&secondary);
            Err(primary)
        }
        (Err(primary), _) => Err(primary),
        (Ok(()), Err(detail)) => Err(error_factory(FrameWritePhase::Drain, 0, 0, None, detail)),
        (Ok(()), Ok(())) => Ok(()),
    }
}
