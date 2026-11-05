//! Fixed test-only observation envelope; phase bytes never establish settlement.
use memcordon_platform::{DeliveryObservation, DeliveryStage, ObservationProvenance};
use serde::Serialize;
use std::io;
pub const EVIDENCE_BYTES: usize = DeliveryObservation::TEST_EVIDENCE_BYTES;
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum WriterPhase {
    Entered = 1,
    PayloadRead,
    PayloadDecoded,
    BeforeWrite,
    BeforeRename,
    BeforeAck,
    Diagnostics,
    Complete,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceOutcome {
    Failed,
    Uncertain,
    Busy,
    InitializationFailed,
}
#[derive(Serialize)]
struct WriterObservation {
    phases: Vec<WriterPhase>,
    os_error: Option<i32>,
    malformed: bool,
    truncated: bool,
    provenance: ObservationProvenance,
    writer_pid: Option<u32>,
    frame_transferred: bool,
    cleanup_outstanding: bool,
}
pub fn encode(
    outcome: EvidenceOutcome,
    stage: DeliveryStage,
    os_error: Option<i32>,
    observation: Option<DeliveryObservation>,
) -> io::Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Evidence {
        schema: u32,
        outcome: EvidenceOutcome,
        stage: DeliveryStage,
        os_error: Option<i32>,
        writer_exit_code: Option<i32>,
        writer: Option<WriterObservation>,
    }
    let writer = observation
        .map(|observed| -> io::Result<_> {
            if observed.writer_phase_count > observed.writer_phases.len() {
                return Err(io::Error::other("writer evidence phase extent invalid"));
            }
            let phases = observed.writer_phases[..observed.writer_phase_count]
                .iter()
                .map(|phase| match phase {
                    1 => Ok(WriterPhase::Entered),
                    2 => Ok(WriterPhase::PayloadRead),
                    3 => Ok(WriterPhase::PayloadDecoded),
                    4 => Ok(WriterPhase::BeforeWrite),
                    5 => Ok(WriterPhase::BeforeRename),
                    6 => Ok(WriterPhase::BeforeAck),
                    7 => Ok(WriterPhase::Diagnostics),
                    8 => Ok(WriterPhase::Complete),
                    _ => Err(io::Error::other("writer evidence phase invalid")),
                })
                .collect::<io::Result<Vec<_>>>()?;
            Ok(WriterObservation {
                phases,
                os_error: observed.writer_phase_error,
                malformed: observed.writer_phase_malformed,
                truncated: observed.writer_phase_truncated,
                provenance: observed.provenance,
                writer_pid: observed.writer_pid.map(std::num::NonZeroU32::get),
                frame_transferred: observed.frame_transferred,
                cleanup_outstanding: observed.cleanup_outstanding,
            })
        })
        .transpose()?;
    let mut bytes = serde_json::to_vec(&Evidence {
        schema: 1,
        outcome,
        stage,
        os_error,
        writer_exit_code: observation.and_then(|observed| observed.exit_code),
        writer,
    })
    .map_err(io::Error::other)?;
    bytes.push(b'\n');
    if bytes.len() > EVIDENCE_BYTES {
        return Err(io::Error::other(
            "writer evidence exceeds existing envelope",
        ));
    }
    Ok(bytes)
}
