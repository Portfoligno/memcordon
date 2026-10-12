pub(crate) struct Allocation<'a> {
    pub run_id: &'a str,
    pub recipe_id: &'a str,
    pub target: &'a str,
    pub artifact_prefix: &'a str,
    pub work_deadline: u64,
    pub cleanup_deadline: u64,
}

pub(crate) fn matches(intent: &serde_json::Value, expected: &Allocation<'_>) -> bool {
    intent["identity"]["run_id"] == expected.run_id
        && intent["target"] == expected.target
        && intent["recipe_id"] == expected.recipe_id
        && intent["artifact_prefix"] == expected.artifact_prefix
        && intent["work_deadline_unix_millis"] == expected.work_deadline
        && intent["cleanup_deadline_unix_millis"] == expected.cleanup_deadline
        && expected.work_deadline < expected.cleanup_deadline
}
