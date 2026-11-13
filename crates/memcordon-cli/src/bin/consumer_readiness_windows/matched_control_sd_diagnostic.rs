//! Same-buffer structural validation and its separate scalar observations.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    BufferBoundInvalid,
    HeaderInvalid,
    ExportUnavailable,
    Cutoff,
    RelativeInvalid,
    NativeInvalid,
    LengthOutsideBuffer,
    Observed,
}

#[derive(Clone, Copy, Debug)]
pub struct DescriptorFacts {
    pub state: State,
    pub revision: Option<u8>,
    pub control: Option<u16>,
    pub relative_structural_valid: Option<u8>,
    pub native_valid: Option<i32>,
    pub native_length: Option<u32>,
}

pub enum RelativeResult {
    Unavailable,
    Cutoff,
    Returned(u8),
}

/// Minted only by the live validation sequence, borrowing that exact buffer.
/// Diagnostic facts cannot be converted back into this value.
pub struct ValidatedExtent<'a> {
    words: &'a [u32],
    bytes: usize,
    facts: DescriptorFacts,
}
impl std::fmt::Debug for ValidatedExtent<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedExtent")
            .field("bytes", &self.bytes)
            .field("facts", &self.facts)
            .finish()
    }
}
impl ValidatedExtent<'_> {
    pub fn byte_len(&self) -> usize {
        self.bytes
    }
    pub fn bytes(&self) -> Vec<u8> {
        bytes_for_extent(self.words, self.bytes)
            .expect("validated live extent remains in its buffer")
    }
    pub fn facts(&self) -> DescriptorFacts {
        self.facts
    }
}

/// Safe materialization only; callers must establish what the extent means.
pub fn bytes_for_extent(words: &[u32], extent: usize) -> Option<Vec<u8>> {
    if extent == 0 || extent > std::mem::size_of_val(words) {
        return None;
    }
    Some(
        words
            .iter()
            .flat_map(|word| word.to_ne_bytes())
            .take(extent)
            .collect(),
    )
}

pub fn inspect(
    words: &[u32],
    supplied: u32,
    live: impl FnMut() -> bool,
    relative: impl FnOnce(u32) -> RelativeResult,
    valid: impl FnOnce() -> i32,
    length: impl FnOnce() -> u32,
) -> DescriptorFacts {
    match validate_zero(words, supplied, live, relative, valid, length) {
        Ok(extent) => extent.facts(),
        Err(facts) => facts,
    }
}

/// The successful kernel query owns initialized, aligned words. Only the fixed
/// self-relative header is read here; component offsets are never traversed.
/// The length-aware native validator receives the original buffer bound, with
/// RequiredInformation=0 (structure only, never component/policy acceptance).
pub fn validate_zero(
    words: &[u32],
    supplied: u32,
    mut live: impl FnMut() -> bool,
    relative: impl FnOnce(u32) -> RelativeResult,
    valid: impl FnOnce() -> i32,
    length: impl FnOnce() -> u32,
) -> Result<ValidatedExtent<'_>, DescriptorFacts> {
    let mut facts = DescriptorFacts {
        state: State::BufferBoundInvalid,
        revision: None,
        control: None,
        relative_structural_valid: None,
        native_valid: None,
        native_length: None,
    };
    // SECURITY_DESCRIPTOR_RELATIVE has a four-byte header and four DWORD
    // offsets. Capacity is a readable allocation bound, not descriptor length.
    let header_bytes = std::mem::size_of::<[u32; 5]>();
    if supplied as usize > std::mem::size_of_val(words)
        || (supplied as usize) < header_bytes
        || supplied > 8192
        || std::mem::size_of_val(words) > 8192
    {
        return Err(facts);
    }
    let header = words[0].to_ne_bytes();
    let revision = header[0];
    let control = u16::from_ne_bytes([header[2], header[3]]);
    facts.revision = Some(revision);
    facts.control = Some(control);
    if revision != 1 || control & 0x8000 == 0 {
        facts.state = State::HeaderInvalid;
        return Err(facts);
    }
    facts.state = State::Cutoff;
    if !live() {
        return Err(facts);
    }
    let relative = match relative(supplied) {
        RelativeResult::Unavailable => {
            facts.state = State::ExportUnavailable;
            return Err(facts);
        }
        RelativeResult::Cutoff => return Err(facts),
        RelativeResult::Returned(value) => value,
    };
    facts.relative_structural_valid = Some(relative);
    if relative == 0 {
        facts.state = State::RelativeInvalid;
        return Err(facts);
    }
    if !live() {
        return Err(facts);
    }
    let valid = valid();
    facts.native_valid = Some(valid);
    if valid == 0 {
        facts.state = State::NativeInvalid;
        return Err(facts);
    }
    if !live() {
        return Err(facts);
    }
    facts.native_length = Some(length());
    if !live() {
        return Err(facts);
    }
    facts.state = if facts
        .native_length
        .is_some_and(|length| length >= header_bytes as u32 && length <= supplied)
    {
        State::Observed
    } else {
        State::LengthOutsideBuffer
    };
    if facts.state == State::Observed {
        Ok(ValidatedExtent {
            words,
            bytes: facts.native_length.expect("observed native length") as usize,
            facts,
        })
    } else {
        Err(facts)
    }
}
