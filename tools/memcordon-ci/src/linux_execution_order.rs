//! Local installed execution order; the source scenario catalogue stays intact.
pub fn prioritize_bytes<T>(scenarios: Vec<T>, key: impl Fn(&T) -> (&str, &str)) -> Vec<T> {
    let (mut early, later): (Vec<_>, Vec<_>) = scenarios.into_iter().partition(|scenario| {
        let (family, name) = key(scenario);
        matches!(family, "C-IO" | "L-MIX-05")
            && matches!(
                name,
                "binary-streams" | "empty-message" | "empty-input" | "bounded-large-output"
            )
    });
    early.extend(later);
    early
}
