//! Native keyed counters; additional fields never substitute for OOM evidence.
use std::collections::BTreeMap;

pub fn parse(bytes: &[u8]) -> Result<BTreeMap<String, u64>, String> {
    let text = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
    let mut result = BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let name = fields.next().ok_or("memory counter name absent")?;
        let value = fields.next().ok_or("memory counter value absent")?;
        if fields.next().is_some()
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || result.contains_key(name)
        {
            return Err("native memory counters duplicated/malformed".into());
        }
        let parsed = value.parse::<u64>().map_err(|error| error.to_string())?;
        if parsed.to_string() != value {
            return Err("native memory counter decimal differs".into());
        }
        result.insert(name.to_owned(), parsed);
    }
    let required = ["high", "low", "max", "oom", "oom_group_kill", "oom_kill"];
    if required.iter().any(|name| !result.contains_key(*name))
        || result
            .keys()
            .any(|name| !required.contains(&name.as_str()) && name != "sock_throttled")
    {
        return Err(format!(
            "native memory event inventory differs; observed-keys={:?}",
            result.keys().collect::<Vec<_>>()
        ));
    }
    Ok(result)
}

pub fn require_monotonic(
    before: &BTreeMap<String, u64>,
    after: &BTreeMap<String, u64>,
) -> Result<(), String> {
    if !before.keys().eq(after.keys()) {
        return Err("native memory event inventory changed during interval".into());
    }
    if before.iter().any(|(name, value)| after[name] < *value) {
        return Err("native memory counters moved backwards".into());
    }
    Ok(())
}
