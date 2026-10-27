//! Bounded diagnostics only; selected phase coverage remains exact set equality.
use std::collections::BTreeSet;

const PHASE_KINDS: &[&str] = &["combined", "packages", "lifecycle"];
const NAME_PREFIX_BYTES: usize = 128;

fn summary(names: &BTreeSet<String>, limit: usize) -> String {
    let selected: Vec<_> = names
        .iter()
        .take(limit)
        .map(|name| {
            let mut end = name.len().min(NAME_PREFIX_BYTES);
            while !name.is_char_boundary(end) {
                end -= 1;
            }
            (&name[..end], name.len() - end)
        })
        .collect();
    format!(
        "count={}; names(prefix,omitted_bytes)={selected:?}; omitted_names={}",
        names.len(),
        names.len().saturating_sub(selected.len())
    )
}

pub fn difference(
    expected: &BTreeSet<String>,
    actual: &BTreeSet<String>,
    platform_count: usize,
) -> Option<String> {
    if expected == actual {
        return None;
    }
    let limit = platform_count.saturating_mul(PHASE_KINDS.len());
    let missing = expected.difference(actual).cloned().collect();
    let unexpected = actual.difference(expected).cloned().collect();
    Some(format!(
        "stress artifact inventory differs from selected phases; expected=[{}]; actual=[{}]; missing=[{}]; unexpected=[{}]",
        summary(expected, limit),
        summary(actual, limit),
        summary(&missing, limit),
        summary(&unexpected, limit)
    ))
}
