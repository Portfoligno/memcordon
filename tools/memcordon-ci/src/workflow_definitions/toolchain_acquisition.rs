//! Explicit authored retries for bootstrap rustup acquisition, before a driver exists.
use super::text;
use serde_yaml::Value;

/// Preserve the original command, prerequisite and execution context. The sum
/// of configured timeouts is preserved; Actions overhead is not a shared clock.
pub fn steps(id: &str, original: Value) -> [Value; 3] {
    let fields = original.as_mapping().expect("authored acquisition mapping");
    let command = fields
        .get(text("run"))
        .and_then(Value::as_str)
        .expect("literal acquisition command");
    let words: Vec<_> = command.split_whitespace().collect();
    assert!(words.starts_with(&["rustup", "toolchain", "install"]));
    assert!(words.len() >= 6 && words[4..6] == ["--profile", "minimal"]);
    assert!(
        !id.is_empty()
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    );
    for key in fields.keys() {
        assert!(
            matches!(
                key.as_str(),
                Some("name" | "run" | "if" | "env" | "working-directory" | "timeout-minutes")
            ),
            "unsupported acquisition metadata: {key:?}"
        );
    }
    let minutes = fields
        .get(text("timeout-minutes"))
        .and_then(Value::as_u64)
        .expect("positive acquisition budget");
    assert!(
        minutes >= 3,
        "three acquisition attempts require at least three minutes"
    );
    let name = fields
        .get(text("name"))
        .and_then(Value::as_str)
        .unwrap_or("Install pinned toolchain");
    std::array::from_fn(|index| {
        let mut attempt = fields.clone();
        attempt.insert(
            text("name"),
            text(&format!("{name} (attempt {}/3)", index + 1)),
        );
        attempt.insert(text("id"), text(&format!("{id}_{}", index + 1)));
        attempt.insert(
            text("timeout-minutes"),
            Value::Number((minutes / 3 + u64::from((index as u64) < minutes % 3)).into()),
        );
        if index < 2 {
            attempt.insert(text("continue-on-error"), Value::Bool(true));
        }
        if index > 0 {
            attempt.insert(
                text("if"),
                text(&format!(
                    "${{{{ !cancelled() && steps.{id}_{index}.outcome == 'failure' }}}}"
                )),
            );
        }
        Value::Mapping(attempt)
    })
}
