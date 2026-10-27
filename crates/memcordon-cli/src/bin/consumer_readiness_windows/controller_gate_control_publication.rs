//! An opaque permit exists only after the original failure was offered and flushed.
use std::io::{self, Write};
pub(super) struct Permit(());

pub(super) fn publish(
    original: &io::Error,
    context: &serde_json::Value,
    writer: &mut impl Write,
) -> io::Result<Permit> {
    let value = serde_json::json!({"format":"memcordon.original-gate-failure-before-control","revision":1,"diagnostic_only":true,
        "operation":"OpenEventW-controller-wait","desired_access":0x0010_0000_u32,"original_raw_os_error":original.raw_os_error(),
        "original_kind":format!("{:?}",original.kind()),"binding":context,"control":"pending"});
    let bytes = serde_json::to_vec(&value).map_err(io::Error::other)?;
    if bytes.len() > 2048 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "original gate failure publication exceeds bound",
        ));
    }
    writer.write_all(b"original-gate-failure-before-control ")?;
    writer.write_all(&bytes)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(Permit(()))
}
