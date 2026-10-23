//! Ordinary reporting stops on cancellation; existing owners and ready saves retire.
use super::text;
use serde_yaml::Value;

fn ordinary_guard(value: &mut Value) {
    if let Some(guard) = value.as_str().filter(|guard| guard.contains("always()")) {
        *value = text(&guard.replace("always()", "!cancelled()"));
    }
}

pub(super) fn apply(document: &mut Value) {
    let jobs = document["jobs"].as_mapping_mut().expect("authored jobs");
    for (_, job) in jobs {
        if let Some(guard) = job.get_mut("if") {
            ordinary_guard(guard);
        }
        for step in job["steps"].as_sequence_mut().expect("authored steps") {
            let action = step["uses"].as_str().unwrap_or_default();
            let run = step["run"].as_str().unwrap_or_default();
            let reporting = action.starts_with("actions/upload-artifact@")
                || action == "./.github/actions/upload-artifact"
                || run.contains(" seal-producer ")
                || (run.contains(" consumer-readiness-loader-diagnostic ")
                    && !run.ends_with(" --cleanup"));
            let probe = action.starts_with("actions/cache/restore@")
                && step["with"]["lookup-only"].as_bool() == Some(true);
            if (reporting || probe)
                && let Some(guard) = step.get_mut("if")
            {
                ordinary_guard(guard);
            }
        }
    }
}
