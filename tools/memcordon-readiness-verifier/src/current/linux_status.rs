//! Linux status and root-first effects. The caller separately binds the actual
//! prepared owner, selected input bytes, namespaces, export and final retirement.
use crate::{CaseKey, NativeArguments, VerificationResult};
use serde_json::Value;

fn uint(value: &Value) -> VerificationResult<u64> {
    value
        .as_u64()
        .ok_or("actual native unsigned fact absent".into())
}
fn exact_row<'a>(rows: &'a [Value], operation: &str) -> VerificationResult<&'a Value> {
    let rows = rows
        .iter()
        .filter(|row| row["operation"] == operation)
        .collect::<Vec<_>>();
    if rows.len() != 1 {
        return Err(format!(
            "actual Linux {operation} observation is missing or duplicated"
        ));
    }
    Ok(rows[0])
}
fn header(value: &Value, format: &str) -> VerificationResult<()> {
    if value["format"] != format || value["revision"] != 1 {
        return Err("native Linux status/lifetime observation header differs".into());
    }
    Ok(())
}

fn root_rows(rows: &[Value], challenge: &str, native: &Value) -> VerificationResult<()> {
    let mut sequence = 0u64;
    for row in rows
        .iter()
        .filter(|row| row["format"] == "memcordon.linux-readiness-transcript")
    {
        sequence = sequence
            .checked_add(1)
            .ok_or("native transcript sequence overflow")?;
        header(row, "memcordon.linux-readiness-transcript")?;
        if row["sequence"] != sequence
            || row["challenge"] != challenge
            || row["root_pid"] != native["target_namespace_pid"]
            || row["root_birth"] != native["target"]["birth"]
        {
            return Err("Linux effect came from another original target/challenge/sequence".into());
        }
    }
    if sequence == 0 {
        return Err("actual Linux status/lifetime transcript absent".into());
    }
    Ok(())
}

fn direct_exit(result: &Value, native: &Value, code: i32) -> VerificationResult<()> {
    let raw = native["native_wait_status"]
        .as_i64()
        .ok_or("actual native direct wait absent")?;
    if raw < 0
        || raw > i64::from(u16::MAX)
        || raw & 0x7f != 0
        || (raw >> 8) & 0xff != i64::from(code)
        || result["outcome"]["kind"] != "completed"
        || result["outcome"]["native_termination"]["kind"] != "exit-code"
        || result["outcome"]["native_termination"]["code"] != code
        || result["outcome"]["wrapper_status"] != code
    {
        return Err("actual direct target exit and wrapper outcome differ from the original requested status".into());
    }
    Ok(())
}

pub fn verify_case(
    key: &CaseKey,
    input: &Value,
    result: &Value,
    native: &Value,
    rows: &[Value],
) -> VerificationResult<()> {
    if !key.target.ends_with("-unknown-linux-gnu")
        || result["runtime"]["native"] != *native
        || result["runtime"]["kind"] != "linux-private"
        || result["release"] != "released"
        || native["exec_observed"] != true
    {
        return Err("Linux status/lifetime lacks an actual current native execution".into());
    }
    let challenge = input["challenge"]
        .as_str()
        .ok_or("original status/lifetime challenge absent")?;
    let challenge_bytes: [u8; 32] = hex::decode(challenge)
        .map_err(|error| error.to_string())?
        .try_into()
        .map_err(|_| "native status challenge has another byte width")?;
    if challenge_bytes.iter().all(|byte| *byte == 0) {
        return Err("native status challenge is all zero".into());
    }
    root_rows(rows, challenge, native)?;
    if (key.family == "C-LIFETIME" && key.scenario == "root-first")
        || (key.family == "L-LIFE-01" && key.scenario == "root-first-resource-descendant")
    {
        return root_first(input, result, native, rows);
    }
    if key.family != "C-STATUS" {
        return Err("unsupported Linux status/lifetime group".into());
    }
    let code = match key.scenario.as_str() {
        "zero" => Some(0),
        "nonzero" => Some(42),
        "exit-123" => Some(123),
        "exit-124" => Some(124),
        "exit-125" => Some(125),
        "exit-126" => Some(126),
        "exit-127" => Some(127),
        "deadline" | "memory" => None,
        _ => return Err("unknown current Linux status scenario".into()),
    };
    let arguments: NativeArguments =
        serde_json::from_value(input["target_argv"].clone()).map_err(|error| error.to_string())?;
    crate::wire::validate_arguments(&arguments, &key.target)?;
    let NativeArguments::UnixBytes(arguments) = arguments else {
        return Err("Linux status input uses another native argv encoding".into());
    };
    if arguments.get(1).map(Vec::as_slice) != Some(challenge.as_bytes()) {
        return Err("status invocation challenge differs from actual transcript".into());
    }
    if let Some(code) = code {
        direct_exit(result, native, code)?;
        if arguments.first().map(Vec::as_slice) != Some(b"bytes-argv-status".as_slice())
            || arguments.get(2).map(Vec::as_slice) != Some(code.to_string().as_bytes())
        {
            return Err(
                "native status fixture operands differ from original requested case".into(),
            );
        }
        let observed = exact_row(rows, "native-argv-observed")?;
        if observed["observation"]["native_exit_status"] != code
            || observed["observation"]["argv"]
                != serde_json::to_value(&arguments).map_err(|error| error.to_string())?
        {
            return Err("actual target argv/status differs from prelaunch input".into());
        }
        let bytes: Vec<u8> =
            serde_json::from_value(exact_row(rows, "byte-vector")?["observation"]["bytes"].clone())
                .map_err(|error| error.to_string())?;
        let expected: Vec<u8> =
            serde_json::from_value(input["binary"].clone()).map_err(|error| error.to_string())?;
        super::byte_effects::verify_binary_file(&expected, &bytes)?;
        return Ok(());
    }
    let raw = native["native_wait_status"]
        .as_i64()
        .ok_or("resource outcome lacks actual native target wait")?;
    let signal = raw & 0x7f;
    if raw < 0
        || raw > i64::from(u16::MAX)
        || !(1..0x7f).contains(&signal)
        || result["outcome"]["native_termination"]["kind"] != "unix-signal"
        || result["outcome"]["native_termination"]["signal"] != signal
    {
        return Err("resource termination differs from actual native signal wait".into());
    }
    if key.scenario == "memory" {
        if arguments.first().map(Vec::as_slice) != Some(b"memory-pressure".as_slice())
            || result["outcome"]["kind"] != "confirmed-memory-limit"
            || result["outcome"]["wrapper_status"] != 124
            || signal != 9
            || uint(&native["memory_oom_event_count"])? == 0
            || uint(&native["memory_oom_kill_count"])? == 0
            || uint(&input["memory_bytes"])? == 0
            || native["memory_max_bytes"] != input["memory_bytes"]
            || exact_row(rows, "memory-pressure-ready")?["observation"]["chunk_bytes"]
                != 1024 * 1024
        {
            return Err(
                "confirmed Linux memory limit lacks actual bounded cgroup OOM and allocator demand"
                    .into(),
            );
        }
    } else {
        if arguments.first().map(Vec::as_slice) != Some(b"deadline-demand".as_slice())
            || result["outcome"]["kind"] != "deadline"
            || result["outcome"]["wrapper_status"] != 123
        {
            return Err("deadline case substitutes a target exit or another fixture mode".into());
        }
        exact_row(rows, "deadline-demand-started")?;
        let observed = rows
            .iter()
            .filter(|row| row["format"] == "memcordon.linux-deadline-observation")
            .collect::<Vec<_>>();
        if observed.len() != 1 {
            return Err(
                "actual deadline target pidfd/monotonic observation absent or duplicated".into(),
            );
        }
        let observed = observed[0];
        header(observed, "memcordon.linux-deadline-observation")?;
        let release = uint(&native["release_monotonic_millis"])?;
        let waited = uint(&observed["wait_observed_monotonic_millis"])?;
        let duration = uint(&input["deadline_millis"])?;
        if duration == 0
            || observed["target"] != native["target"]
            || observed["release_monotonic_millis"] != release
            || observed["deadline_millis"] != duration
            || observed["target_pidfd_readable"] != true
            || waited
                .checked_sub(release)
                .is_none_or(|elapsed| elapsed < duration)
        {
            return Err("native deadline observation renewed the original cutoff or lacks genuine held demand".into());
        }
    }
    Ok(())
}

fn root_first(
    input: &Value,
    result: &Value,
    native: &Value,
    rows: &[Value],
) -> VerificationResult<()> {
    direct_exit(result, native, 0)?;
    let args: NativeArguments =
        serde_json::from_value(input["target_argv"].clone()).map_err(|error| error.to_string())?;
    let NativeArguments::UnixBytes(args) = args else {
        return Err("root-first input uses another native argv encoding".into());
    };
    if args.first().map(Vec::as_slice) != Some(b"root-first".as_slice())
        || args.get(1).map(Vec::as_slice) != input["challenge"].as_str().map(str::as_bytes)
    {
        return Err(
            "actual root-first fixture mode/challenge differs from original invocation".into(),
        );
    }
    let child = &exact_row(rows, "root-exiting-before-held-descendant")?["observation"];
    let observations = rows
        .iter()
        .filter(|row| row["format"] == "memcordon.linux-root-first-native")
        .collect::<Vec<_>>();
    let completions = rows
        .iter()
        .filter(|row| row["format"] == "memcordon.linux-orphan-completion")
        .collect::<Vec<_>>();
    if observations.len() != 1 || completions.len() != 1 {
        return Err(
            "root-first lacks actual held descendant and native completion observations".into(),
        );
    }
    let held = observations[0];
    let completion = completions[0];
    header(held, "memcordon.linux-root-first-native")?;
    header(completion, "memcordon.linux-orphan-completion")?;
    uint(&held["descendant"]["birth"])?;
    if held["root"] != native["target"]
        || held["root_pidfd_readable_before_descendant_exit"] != true
        || held["descendant_pidfd_readable_when_root_retired"] != false
        || held["descendant_pidfd_readable_after_completion"] != true
        || uint(&held["descendant"]["pid"])? == 0
        || held["descendant"]["pid"] == native["target"]["pid"]
        || held["descendant"]["namespace_pid"] != child["pid"]
        || held["descendant"]["birth"] != child["birth"]
        || child["parent_pid"] != native["target_namespace_pid"]
        || completion["challenge"] != input["challenge"]
        || completion["pid"] != child["pid"]
        || completion["birth"] != child["birth"]
        || completion["original_parent_pid"] != native["target_namespace_pid"]
        || completion["original_parent_birth"] != native["target"]["birth"]
        || completion["reparented_pid"] != 1
    {
        return Err("root-first replaced native parent/child ownership or lost the actual root-first pidfd ordering".into());
    }
    Ok(())
}
