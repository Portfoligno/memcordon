//! Bounded diagnostics for complete, sorted input comparisons.
//! Repeated paths are paired in their stored occurrence order, matching the
//! ordered manifest comparison; counts describe that alignment, not a set diff.
use super::Input;
use std::fmt::Write;

const SAMPLE_LIMIT: usize = 8;
const PATH_HEX_LIMIT: usize = 512;

pub(super) fn describe(before: &[Input], after: &[Input]) -> String {
    let (mut left, mut right) = (0, 0);
    let (mut added, mut removed, mut changed) = (0_usize, 0_usize, 0_usize);
    let mut samples = Vec::new();
    while left < before.len() || right < after.len() {
        let (kind, input, fields) = match (before.get(left), after.get(right)) {
            (Some(old), Some(new)) if old.path == new.path => {
                left += 1;
                right += 1;
                if old == new {
                    continue;
                }
                changed += 1;
                let fields = [
                    (old.kind != new.kind, "kind"),
                    (old.mode != new.mode, "mode"),
                    (old.digest != new.digest, "digest"),
                ]
                .into_iter()
                .filter_map(|(different, name)| different.then_some(name))
                .collect::<Vec<_>>()
                .join(",");
                ("changed", new, fields)
            }
            (Some(old), Some(new)) if old.path < new.path => {
                left += 1;
                removed += 1;
                ("removed", old, String::new())
            }
            (Some(old), None) => {
                left += 1;
                removed += 1;
                ("removed", old, String::new())
            }
            (_, Some(new)) => {
                right += 1;
                added += 1;
                ("added", new, String::new())
            }
            (None, None) => unreachable!(),
        };
        if samples.len() < SAMPLE_LIMIT {
            // Native paths already use hexadecimal encoding. Character-based
            // truncation also remains safe for malformed serialized contexts.
            let path: String = input.path.chars().take(PATH_HEX_LIMIT).collect();
            let truncated = path.len() != input.path.len();
            samples.push(format!(
                "{kind} path_hex={path:?} path_truncated={truncated} fields={fields}"
            ));
        }
    }
    let total = added + removed + changed;
    let mut result = format!(
        "added={added} removed={removed} changed={changed} samples={} omitted={}",
        samples.len(),
        total.saturating_sub(samples.len())
    );
    for sample in samples {
        write!(result, "; {sample}").expect("writing to String cannot fail");
    }
    result
}
