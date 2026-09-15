//! Bounded native reply validation; these bytes confer no activation authority.

/// Borrow only the bytes initialized by the native reparse query.
/// Header and payload interpretation belong to the caller's diagnostic parser.
pub fn initialized_reparse_bytes(buffer: &[u8], returned: usize) -> std::io::Result<&[u8]> {
    buffer.get(..returned).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "native reparse data exceeds buffer",
        )
    })
}
