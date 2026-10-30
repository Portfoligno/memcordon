//! Bounded ACK consumption after readiness, with an empty reader on entry.
use std::io::{self, BufRead};

pub fn read_ack(
    input: &mut impl BufRead,
    expected: &[u8],
    mut ready: impl FnMut() -> io::Result<bool>,
    mut live: impl FnMut() -> io::Result<()>,
) -> io::Result<()> {
    let mut acknowledgement = Vec::new();
    loop {
        live()?;
        if !ready()? {
            continue;
        }
        let exposed = input.fill_buf()?;
        if exposed.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "diagnostic acknowledgement EOF",
            ));
        }
        let newline = exposed.iter().position(|byte| *byte == b'\n');
        let span = newline.map_or(exposed.len(), |index| index + 1);
        if acknowledgement
            .len()
            .checked_add(span)
            .is_none_or(|length| length > 128)
        {
            return Err(io::Error::other("diagnostic acknowledgement bound"));
        }
        acknowledgement.extend_from_slice(&exposed[..span]);
        // Drain the ENTIRE exposed slice before another readiness poll unless
        // its terminating newline has completed the one expected frame.
        input.consume(span);
        live()?;
        if newline.is_some() {
            return if acknowledgement == expected {
                Ok(())
            } else {
                Err(io::Error::other(
                    "diagnostic release acknowledgement mismatch",
                ))
            };
        }
    }
}
