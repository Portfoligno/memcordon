//! One bounded native-path/byte frame for an isolated result I/O owner.
use std::io::{self, Read};

pub const MAX_PAYLOAD: usize = 64 * 1024 * 1024;
const MAGIC: &[u8] = b"MCRW";
const VERSION: u8 = 2;
const REPORT: u8 = 1;
const DELAY: u8 = 2;
const PREFIX: usize = size_of::<[u8; 8]>();
pub(crate) const HEADER: usize = PREFIX + 4 * size_of::<u64>();

pub struct WriterFrame {
    pub diagnostics: Vec<u8>,
    pub report_path: Option<Vec<u8>>,
    pub report: Option<Vec<u8>>,
    #[cfg(feature = "test-support")]
    pub barrier: Option<(memcordon_core::ReportWritePhase, Vec<u8>)>,
    #[cfg(feature = "test-support")]
    pub delay_before_write: bool,
}

impl WriterFrame {
    pub fn encode(&self, bound: usize) -> io::Result<Vec<u8>> {
        let mut output = self.header(bound)?;
        for bytes in self.pieces() {
            output.extend_from_slice(bytes);
        }
        Ok(output)
    }

    pub(crate) fn pieces(&self) -> [&[u8]; 4] {
        let marker = {
            #[cfg(feature = "test-support")]
            {
                self.barrier
                    .as_ref()
                    .map(|(_, bytes)| bytes.as_slice())
                    .unwrap_or_default()
            }
            #[cfg(not(feature = "test-support"))]
            {
                &[]
            }
        };
        [
            self.report_path.as_deref().unwrap_or_default(),
            self.report.as_deref().unwrap_or_default(),
            self.diagnostics.as_slice(),
            marker,
        ]
    }

    pub(crate) fn header(&self, bound: usize) -> io::Result<Vec<u8>> {
        if self.report_path.is_some() != self.report.is_some() {
            return Err(io::Error::other("writer path/report presence differs"));
        }
        let path = self.report_path.as_deref().unwrap_or_default();
        let report = self.report.as_deref().unwrap_or_default();
        if self.report.is_some() && (path.is_empty() || report.is_empty() || path.contains(&0)) {
            return Err(io::Error::other("invalid writer report/path bytes"));
        }
        let mut flags = if self.report.is_some() { REPORT } else { 0 };
        let mut phase = 0;
        let mut marker: &[u8] = &[];
        #[cfg(feature = "test-support")]
        {
            if self.delay_before_write {
                flags |= DELAY;
            }
            if let Some((value, bytes)) = &self.barrier {
                phase = match value {
                    memcordon_core::ReportWritePhase::BeforeWrite => 1,
                    memcordon_core::ReportWritePhase::BeforeRename => 2,
                    memcordon_core::ReportWritePhase::BeforeAck => 3,
                };
                marker = bytes;
                if marker.is_empty() || marker.contains(&0) {
                    return Err(io::Error::other("invalid writer fixture barrier"));
                }
            }
        }
        let pieces = [path, report, self.diagnostics.as_slice(), marker];
        let length = pieces
            .iter()
            .try_fold(HEADER, |total, bytes| total.checked_add(bytes.len()))
            .ok_or_else(|| io::Error::other("writer frame length overflow"))?;
        if length > bound.min(MAX_PAYLOAD) {
            return Err(io::Error::other(
                "writer frame exceeds reserved payload capacity",
            ));
        }
        let mut output = Vec::with_capacity(HEADER);
        output.extend_from_slice(MAGIC);
        output.extend([VERSION, flags, phase, 0]);
        for bytes in pieces {
            output.extend(
                u64::try_from(bytes.len())
                    .map_err(io::Error::other)?
                    .to_le_bytes(),
            );
        }
        Ok(output)
    }

    pub fn read(input: &mut impl Read) -> io::Result<Self> {
        let mut header = [0_u8; HEADER];
        input.read_exact(&mut header)?;
        let (magic, remaining) = header.split_at(MAGIC.len());
        if magic != MAGIC {
            return Err(io::Error::other("unsupported writer frame magic"));
        }
        let (settings, remaining) = remaining.split_at(size_of::<[u8; 4]>());
        let [version, flags, phase, reserved]: [u8; 4] =
            settings.try_into().expect("fixed frame settings");
        let allowed = if cfg!(feature = "test-support") {
            REPORT | DELAY
        } else {
            REPORT
        };
        if version != VERSION
            || flags & !allowed != 0
            || reserved != 0
            || (!cfg!(feature = "test-support") && phase != 0)
        {
            return Err(io::Error::other("unsupported writer frame settings"));
        }
        let mut lengths = [0_usize; 4];
        for (target, bytes) in lengths
            .iter_mut()
            .zip(remaining.chunks_exact(size_of::<u64>()))
        {
            *target = usize::try_from(u64::from_le_bytes(
                bytes.try_into().expect("fixed frame length"),
            ))
            .map_err(io::Error::other)?;
        }
        let [path_len, report_len, diagnostics_len, marker_len] = lengths;
        let total = lengths
            .iter()
            .try_fold(HEADER, |total, length| total.checked_add(*length))
            .ok_or_else(|| io::Error::other("writer frame length overflow"))?;
        if total > MAX_PAYLOAD
            || (flags & REPORT != 0) != (path_len > 0 && report_len > 0)
            || (flags & REPORT == 0 && (path_len != 0 || report_len != 0))
            || ((phase == 0) != (marker_len == 0))
            || phase > 3
        {
            return Err(io::Error::other("inconsistent or oversized writer frame"));
        }
        let mut path = vec![0; path_len];
        let mut report = vec![0; report_len];
        let mut diagnostics = vec![0; diagnostics_len];
        let mut marker = vec![0; marker_len];
        for segment in [&mut path, &mut report, &mut diagnostics, &mut marker] {
            input.read_exact(segment)?;
        }
        let mut extra = [0_u8; size_of::<u8>()];
        if input.read(&mut extra)? != 0 {
            return Err(io::Error::other("extra writer frame/input bytes"));
        }
        // No output starts before the complete one-frame input has reached EOF.
        if path.contains(&0) || marker.contains(&0) {
            return Err(io::Error::other("writer native path contains NUL"));
        }
        Ok(Self {
            diagnostics,
            report_path: (flags & REPORT != 0).then_some(path),
            report: (flags & REPORT != 0).then_some(report),
            #[cfg(feature = "test-support")]
            barrier: match phase {
                0 => None,
                1 => Some((memcordon_core::ReportWritePhase::BeforeWrite, marker)),
                2 => Some((memcordon_core::ReportWritePhase::BeforeRename, marker)),
                3 => Some((memcordon_core::ReportWritePhase::BeforeAck, marker)),
                _ => unreachable!("checked writer fixture phase"),
            },
            #[cfg(feature = "test-support")]
            delay_before_write: flags & DELAY != 0,
        })
    }
}
