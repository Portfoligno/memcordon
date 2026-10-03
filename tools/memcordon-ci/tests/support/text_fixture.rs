pub(crate) fn canonical_lf_utf8(source: &[u8], label: &str) -> Result<String, String> {
    let mut canonical = Vec::with_capacity(source.len());
    let mut bytes = source.iter().copied();
    while let Some(byte) = bytes.next() {
        match byte {
            b'\r' => match bytes.next() {
                Some(b'\n') => canonical.push(b'\n'),
                Some(_) | None => return Err(format!("{label} contains a bare carriage return")),
            },
            byte => canonical.push(byte),
        }
    }
    if !canonical.ends_with(b"\n") {
        return Err(format!("{label} lacks a trailing newline"));
    }
    String::from_utf8(canonical).map_err(|error| format!("{label} is not UTF-8: {error}"))
}

pub(crate) fn crlf_from_lf(source: &str) -> String {
    let mut converted = String::with_capacity(source.len());
    for segment in source.split_inclusive('\n') {
        if let Some(body) = segment.strip_suffix('\n') {
            converted.push_str(body);
            converted.push_str("\r\n");
        } else {
            converted.push_str(segment);
        }
    }
    converted
}
