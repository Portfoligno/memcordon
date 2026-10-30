//! Immediate assertions over the operation's real product data and held owners.
use super::linux_test_execution::ExecutedCase;
use crate::{CiError, Result};
use serde_json::Value;
use std::collections::BTreeSet;

fn fail(message: &str) -> CiError {
    CiError::Message(message.into())
}
fn number(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .ok_or_else(|| fail("required native integer absent"))
}
fn bytes(value: &Value) -> Result<Vec<u8>> {
    Ok(serde_json::from_value(value.clone())?)
}
pub(super) fn operation<'a>(rows: &'a [Value], name: &str) -> Result<&'a Value> {
    let mut found = rows.iter().filter(|row| row["operation"] == name);
    let row = found
        .next()
        .ok_or_else(|| fail("required fixture operation absent"))?;
    if found.next().is_some() {
        return Err(fail("required fixture operation repeated"));
    }
    Ok(&row["observation"])
}
fn transcript(data: &[u8], case: &ExecutedCase, native: &Value) -> Result<Vec<Value>> {
    if data.len() > 32 * 1024 * 1024 {
        return Err(fail("fixture transcript exceeds bound"));
    }
    let mut rows = Vec::new();
    for line in data
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        memcordon_core::canonical_json::reject_duplicate_json_keys(line)
            .map_err(CiError::Message)?;
        let row: Value = serde_json::from_slice(line)?;
        if row["format"] != "memcordon.linux-readiness-transcript"
            || row["revision"] != 1
            || row["challenge"] != case.challenge
            || number(&row["sequence"])? != rows.len() as u64 + 1
            || row["root_pid"] != native["target_namespace_pid"]
            || row["root_birth"] != native["target"]["birth"]
        {
            return Err(fail(
                "fixture transcript differs from live target/challenge/sequence",
            ));
        }
        rows.push(row);
    }
    if rows.is_empty() {
        return Err(fail("fixture never reached its required operation"));
    }
    Ok(rows)
}
fn raw_streams(kind: &str, stdout: &[u8], stderr: &[u8]) -> Result<()> {
    if kind == "empty-input" {
        return if stdout.is_empty() && stderr.is_empty() {
            Ok(())
        } else {
            Err(fail("empty input produced bytes"))
        };
    }
    let vector: Vec<u8> = (u8::MIN..=u8::MAX).collect();
    let reversed: Vec<_> = vector.iter().copied().rev().collect();
    if stdout.is_empty()
        || stdout.len() != stderr.len()
        || !stdout.len().is_multiple_of(vector.len())
        || stdout
            .iter()
            .copied()
            .ne(vector.iter().copied().cycle().take(stdout.len()))
        || stderr
            .iter()
            .copied()
            .ne(reversed.iter().copied().cycle().take(stderr.len()))
        || kind == "bounded-large-output" && stdout.len() < 2 * 1024 * 1024
    {
        return Err(fail("independent stdout/stderr byte products differ"));
    }
    Ok(())
}
fn credentials(observed: &Value, native: &Value) -> Result<()> {
    for (field, expected) in [("uid", "target_uid"), ("gid", "target_gid")] {
        let values = observed[field]
            .as_array()
            .ok_or_else(|| fail("native credential columns absent"))?;
        if values.len() != 4 || values.iter().any(|value| value != &native[expected]) {
            return Err(fail("held child credentials differ"));
        }
    }
    if observed["groups"] != serde_json::json!([])
        || observed["cap_effective"] != 0
        || observed["cap_permitted"] != 0
        || observed["cap_ambient"] != 0
        || observed["no_new_privileges"] != 1
    {
        return Err(fail("held child retained forbidden authority"));
    }
    Ok(())
}
fn retired(case: &ExecutedCase, native: &Value) -> Result<()> {
    let retired = case.retirement["held_processes"]
        .as_array()
        .ok_or_else(|| fail("held process retirement absent"))?;
    let check = |snapshot: &Value| -> Result<()> {
        if !retired.iter().any(|record| {
            record["pid"] == snapshot["process_id"]
                && record["birth"] == snapshot["birth"]
                && record["pidfd_readable"] == true
        }) {
            return Err(fail("held native process has not retired"));
        }
        Ok(())
    };
    for process in case.controller["processes"]
        .as_array()
        .ok_or_else(|| fail("actual held processes absent"))?
    {
        if process["role"] == "target" {
            credentials(&process["credentials"], native)?;
        }
        check(&process["snapshot"])?;
    }
    let required_stages: &[&str] =
        if case.key.family == "L-MIX-04" && case.key.scenario == "cooperation" {
            &["same-attempt-cooperation-held"]
        } else if matches!(
            case.key.family.as_str(),
            "L-MIX-01" | "L-IMG-03" | "L-LIFE-03"
        ) || case.key.family == "L-ID-01" && case.key.scenario == "generated-descendants"
        {
            &[
                "descendant-competing-bind-held",
                "joint-descendant-tree-held",
                "offline-compiler-held",
                "joint-generated-child-held",
            ]
        } else {
            &[]
        };
    if !required_stages.is_empty() {
        let stages = case.controller["held_stages"]
            .as_array()
            .ok_or_else(|| fail("required live child phases absent"))?;
        for required in required_stages {
            let mut found = stages
                .iter()
                .filter(|stage| stage["operation"] == *required);
            let selected = found
                .next()
                .ok_or_else(|| fail("required live child phase did not occur"))?;
            if found.next().is_some() || selected["children"].as_array().is_none_or(Vec::is_empty) {
                return Err(fail("required live child phase duplicated or empty"));
            }
        }
    }
    if let Some(stages) = case.controller["held_stages"].as_array() {
        for stage in stages {
            for child in stage["children"]
                .as_array()
                .ok_or_else(|| fail("held stage children absent"))?
            {
                credentials(&child["credentials"], native)?;
                let snapshot = &child["snapshot"];
                let identity = &child["identity"];
                if identity["pid"] != snapshot["process_id"]
                    || identity["birth"] != snapshot["birth"]
                    || !identity["parent_pid"].is_u64()
                    || !identity["parent_birth"].is_u64()
                {
                    return Err(fail("held child native parent identity differs"));
                }
                for (field, expected) in [
                    ("mount", "mount_namespace"),
                    ("pid", "pid_namespace"),
                    ("network", "network_namespace"),
                    ("ipc", "ipc_namespace"),
                ] {
                    if snapshot[field] != native[expected] {
                        return Err(fail("held child escaped target namespace"));
                    }
                }
                check(snapshot)?;
            }
        }
    }
    Ok(())
}

pub(super) fn assert_case(case: &ExecutedCase) -> Result<()> {
    assert_case_with(case, |_, _, _| {
        Err(CiError::Message(format!(
            "direct Linux assertions unavailable for {}/{}",
            case.key.family, case.key.scenario
        )))
    })
}

/// A specialized native experiment compares its actual held object here after
/// the common request, process and cleanup assertions have succeeded.
pub(super) fn assert_case_with(
    case: &ExecutedCase,
    assertion: impl FnOnce(&[Value], &Value, &Value) -> Result<()>,
) -> Result<()> {
    if case.key.family == "L-LIFE-05" && case.key.scenario == "report-persistence-failure" {
        return report_failure(case);
    }
    let result = case
        .result
        .as_ref()
        .ok_or_else(|| fail("report persistence assertion requires its explicit recovery path"))?;
    result.validate().map_err(CiError::Message)?;
    let result = serde_json::to_value(result)?;
    let request = serde_json::to_value(&case.request)?;
    let declared = request["runtime"]["layout"]["output_files"]
        .as_array()
        .ok_or_else(|| fail("declared caller outputs absent"))?;
    let refused_export =
        case.key.family == "L-IMG-04" && case.key.scenario != "export-concurrent-writer";
    if !refused_export && declared.len() != case.outputs.len()
        || refused_export && (declared.len() != 1 || !case.outputs.is_empty())
    {
        return Err(fail(
            "caller output delivery omitted or added a declared member",
        ));
    }
    let mut output_names = BTreeSet::new();
    for name in declared {
        let name = name
            .as_str()
            .ok_or_else(|| fail("declared caller output name absent"))?;
        if !output_names.insert(name)
            || !refused_export
                && case
                    .outputs
                    .iter()
                    .filter(|(path, _)| path.as_str() == name)
                    .count()
                    != 1
        {
            return Err(fail("caller output names changed or repeated"));
        }
    }
    if !declared.is_empty()
        && result["output_delivery"]
            != if refused_export {
                "incomplete"
            } else {
                "complete"
            }
    {
        return Err(fail("caller outputs were not completely delivered"));
    }
    let locator = serde_json::to_value(&case.locator)?;
    let digest = String::from(
        case.request
            .digest()
            .map_err(|error| fail(&error.to_string()))?,
    );
    let native = &result["runtime"]["native"];
    let held_cancel = case.key.family == "C-CANCEL" && case.key.scenario == "held-before-release";
    if result["workload_attempt"] != locator
        || result["provider"] != locator["provider"]
        || result["request"]["request_sha256"] != digest
        || locator["request_sha256"] != digest
        || result["runtime"]["kind"] != "linux-private"
        || result["runtime"]["profile"] != "linux-private-workload-v1"
        || result["cleanup"]["state"] != "complete"
        || result["delivery"] != "complete"
        || native["boot_id"] != locator["boot_id"]
        || number(&native["target_uid"])? == 0
        || number(&native["target_gid"])? == 0
        || native["target_uid"] == native["caller_uid"]
        || native["target_uid"] == native["init_uid"]
        || native["supplementary_groups"] != serde_json::json!([])
        || native["no_new_privileges"] != true
        || native["capabilities_empty"] != true
        || native["init_nondumpable"] != true
        || native["exec_observed"] != !held_cancel
        || result["release"]
            != if held_cancel {
                "not-released"
            } else {
                "released"
            }
    {
        return Err(fail(
            "current result binding/native boundary/cleanup differs",
        ));
    }
    let obligations = result["cleanup"]["obligations"]
        .as_array()
        .ok_or_else(|| fail("native cleanup obligations absent"))?;
    let mut settled = BTreeSet::new();
    for obligation in obligations {
        let name = obligation["resource"]
            .as_str()
            .ok_or_else(|| fail("cleanup resource absent"))?;
        if obligation["settled"] != true || !settled.insert(name) {
            return Err(fail("duplicate or unsettled native cleanup"));
        }
    }
    for name in [
        "target",
        "aggregate",
        "guardian",
        "namespace-init",
        "relays",
        "control-handles",
        "root-references",
        "staging",
        "footprint",
    ] {
        if !settled.contains(name) {
            return Err(fail("native cleanup omitted an owned resource"));
        }
    }
    let prepared: Value = serde_json::from_slice(&case.prepared)?;
    if prepared["association"] != locator
        || prepared["request"] != result["request"]
        || prepared["native"]["exec_observed"] != false
    {
        return Err(fail("prepared request/attempt differs"));
    }
    if !held_cancel {
        let ack: Value = serde_json::from_slice(
            case.prepared_ack
                .as_ref()
                .ok_or_else(|| fail("prepared acknowledgment absent"))?,
        )?;
        if ack["association"] != locator
            || ack["prepared_sha256"] != super::artifacts::checksum(&case.prepared)
        {
            return Err(fail("prepared acknowledgment differs from actual gate"));
        }
    } else if case.prepared_ack.is_some() {
        return Err(fail("held cancellation unexpectedly acknowledged release"));
    }
    for field in [
        "boot_id",
        "caller",
        "target",
        "target_namespace_pid",
        "namespace_init",
        "guardian",
        "root_device",
        "root_inode",
        "cgroup_device",
        "cgroup_inode",
        "caller_uid",
        "target_uid",
        "target_gid",
        "caller_namespaces",
        "mount_namespace",
        "pid_namespace",
        "network_namespace",
        "ipc_namespace",
        "user_namespace",
        "filter_abi",
        "filter_instruction_sha256",
        "entrypoint_sha256",
    ] {
        if prepared["native"][field] != native[field] {
            return Err(fail("native identity changed after preparation"));
        }
    }
    retired(case, native)?;
    let termination = &result["outcome"]["native_termination"];
    if !termination.is_null() {
        let wait = native["native_wait_status"]
            .as_i64()
            .ok_or_else(|| fail("native direct wait absent"))?;
        if wait < 0
            || wait > i64::from(u16::MAX)
            || match termination["kind"].as_str() {
                Some("exit-code") => {
                    wait & 0x7f != 0 || termination["code"].as_i64() != Some((wait >> 8) & 0xff)
                }
                Some("unix-signal") => {
                    !(1..0x7f).contains(&(wait & 0x7f))
                        || termination["signal"].as_i64() != Some(wait & 0x7f)
                }
                _ => true,
            }
        {
            return Err(fail("typed target termination differs from native wait"));
        }
    }
    let family = case.key.family.as_str();
    let scenario = case.key.scenario.as_str();
    if matches!(family, "C-IO" | "L-MIX-05")
        && matches!(
            scenario,
            "binary-streams" | "empty-input" | "bounded-large-output"
        )
    {
        raw_streams(scenario, &case.stdout, &case.stderr)?;
        return completed(&result, 0);
    }
    if held_cancel {
        if !case.stdout.is_empty() || !case.stderr.is_empty() {
            return Err(fail("unreleased cancellation produced target bytes"));
        }
        return cancelled(case, &result, native, "cancellation");
    }
    if family == "L-LIFE-05" && scenario == "relay-backpressure" {
        let end = case
            .stdout
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or_else(|| fail("relay pressure phase absent"))?
            + 1;
        let rows = transcript(&case.stdout[..end], case, native)?;
        let observed = &case.controller["relay_pressure"];
        let capacity = number(&observed["pipe"]["capacity"])?;
        let queued = number(&observed["pipe"]["queued"])?;
        if operation(&rows, "relay-pressure-ready")?["bytes_per_stream"] != 2097152
            || observed["frontend"] != native["caller"]
            || observed["target"] != native["target"]
            || observed["reader_stopped"] != true
            || observed["reader_resumed"] != true
            || observed["original_target_input_gated"] != true
            || observed["release_byte_queued_before_reader_stop"] != 1
            || observed["target_alive"] != true
            || observed["bytes_consumed_by_observer"] != 0
            || queued == 0
            || capacity
                .checked_sub(queued)
                .is_none_or(|remaining| remaining >= 4096)
            || observed["blocked_write"]["descriptor"] != observed["descriptor"]
            || observed["blocked_write"]["length"] != 256
            || observed["blocked_write"]["wait_channel"] != "pipe_write"
            || number(&observed["pipe"]["inode"])? == 0
        {
            return Err(fail(
                "relay pressure lacked actual live blocked writer and full pipe",
            ));
        }
        raw_streams("bounded-large-output", &case.stdout[end..], &case.stderr)?;
        return completed(&result, 0);
    }
    let rows = transcript(&case.stdout, case, native)?;
    match (family, scenario) {
        ("L-IMG-04", scenario) => {
            let candidate = &case.controller["export_candidate"];
            let kind = match scenario {
                "export-symlink" | "export-traversal" => libc::S_IFLNK,
                "export-fifo" => libc::S_IFIFO,
                "export-device" => libc::S_IFCHR,
                "export-socket" => libc::S_IFSOCK,
                "export-concurrent-writer" => libc::S_IFREG,
                _ => return Err(fail("unknown required export scenario")),
            };
            if candidate["scenario"] != scenario
                || candidate["output_empty_before_release"] != true
                || number(&candidate["inode"])? == 0
                || number(&candidate["mode"])? & libc::S_IFMT as u64 != kind as u64
            {
                return Err(fail(
                    "original export node shape or delivery ordering differs",
                ));
            }
            for name in [
                "export-object-ready",
                "export-object-controller-release",
                "export-object-completed",
            ] {
                operation(&rows, name)?;
            }
            if scenario == "export-concurrent-writer" {
                let writer = &case.controller["export_writer_native"];
                let retired = operation(&rows, "export-writer-retired")?;
                if writer["pidfd_readable_after_stop"] != true
                    || writer["target_alive_after_writer"] != true
                    || writer["first"]["bytes"] == writer["second"]["bytes"]
                    || writer["first"]["inode"] != writer["second"]["inode"]
                    || writer["first"]["inode"] != writer["final"]["inode"]
                    || retired["pid"] != writer["writer"]["pid"]
                    || retired["native_wait_completed"] != true
                    || retired["raw_wait_status"] != 0
                    || retired["before_root_release"] != true
                    || case.outputs.len() != 1
                    || case.outputs[0].1 != bytes(&writer["final"]["bytes"])?
                {
                    return Err(fail(
                        "live writer mutation, retirement or final exported bytes differ",
                    ));
                }
            } else if case.controller["rejected_export_output_empty"] != true
                || !case.outputs.is_empty()
                || result["output_delivery"] != "incomplete"
            {
                return Err(fail("unsafe export produced caller output"));
            }
            completed(&result, 0)?;
        }
        ("C-ADMISSION", "positive") => {
            let bind = operation(&rows, "bind-zero-and-competing-bind")?;
            let endpoint: std::net::SocketAddrV4 = bind["endpoint"]
                .as_str()
                .ok_or_else(|| fail("admitted TCP endpoint absent"))?
                .parse()
                .map_err(|error: std::net::AddrParseError| fail(&error.to_string()))?;
            let http = operation(&rows, "http-round-trip")?;
            if !endpoint.ip().is_loopback()
                || endpoint.port() == 0
                || bind["native_errno"] != 98
                || bind["listener_retained"] != true
                || http["endpoint"] != bind["endpoint"]
                || bytes(&http["request"])?
                    != b"GET /readiness HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                || bytes(&http["response"])?
                    != b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nreadiness"
            {
                return Err(fail("native admitted TCP/HTTP operation differs"));
            }
            let empty = operation(&rows, "http-empty-body-round-trip")?;
            if !bytes(&empty["body"])?.is_empty()
                || bytes(&empty["response"])? != b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
            {
                return Err(fail("native empty HTTP response differs"));
            }
            operation(&rows, "tcp-endpoints-closed")?;
            completed(&result, 0)?;
        }
        ("L-MIX-03", "listener-and-file-transfer") => {
            let transfer = operation(&rows, "scm-rights-regular-and-listener")?;
            if bytes(&transfer["file_bytes"])? != b"descriptor-readiness"
                || bytes(&transfer["network_bytes"])? != b"rights-listener"
            {
                return Err(fail("native transferred file/listener bytes differ"));
            }
            for (original, received) in [
                ("file_device", "received_file_device"),
                ("file_inode", "received_file_inode"),
                ("listener_device", "received_listener_device"),
                ("listener_inode", "received_listener_inode"),
            ] {
                if number(&transfer[original])? == 0 || transfer[original] != transfer[received] {
                    return Err(fail("native transferred handle identity differs"));
                }
            }
            completed(&result, 0)?;
        }
        ("L-ISO-03", "own-abstract-positive") => {
            let observed = operation(&rows, "unix-abstract-round-trip")?;
            if bytes(&observed["bytes"])? != b"abstract-unix-readiness"
                || bytes(&observed["name"])? != case.challenge.as_bytes()
            {
                return Err(fail("owned abstract endpoint bytes differ"));
            }
            completed(&result, 0)?;
        }
        ("L-ISO-02", "host-run-socket") => {
            let observed = operation(&rows, "forbidden-unix-path-denied")?;
            if observed["path"] != "/run/memcordon/sealed-agent.sock"
                || observed["native_errno"] != 2
                || bytes(&operation(&rows, "private-unix-pair-positive")?["bytes"])?
                    != case.challenge.as_bytes()
            {
                return Err(fail(
                    "host socket refusal or neighboring private positive differs",
                ));
            }
            completed(&result, 0)?;
        }
        ("C-LIFETIME", "root-first") | ("L-LIFE-01", "root-first-resource-descendant") => {
            root_first(case, &rows, &result, native)?
        }
        (
            "C-STATUS",
            "zero" | "nonzero" | "exit-123" | "exit-124" | "exit-125" | "exit-126" | "exit-127",
        ) => {
            let code = match scenario {
                "zero" => 0,
                "nonzero" => 42,
                _ => scenario
                    .strip_prefix("exit-")
                    .expect("matched exit scenario")
                    .parse::<i32>()
                    .map_err(|_| fail("invalid status"))?,
            };
            completed(&result, code)?;
            let observed = operation(&rows, "native-argv-observed")?;
            if observed["argv"] != serde_json::to_value(&case.arguments)?
                || observed["native_exit_status"] != code
            {
                return Err(fail("actual argv/status differs"));
            }
        }
        ("C-STATUS" | "L-LIFE-03", "memory") => {
            if result["outcome"]["kind"] != "confirmed-memory-limit"
                || result["outcome"]["wrapper_status"] != 124
                || termination["signal"] != 9
                || number(&native["memory_oom_event_count"])? == 0
                || number(&native["memory_oom_kill_count"])? == 0
                || native["memory_max_bytes"] != serde_json::to_value(case.memory_bytes)?
            {
                return Err(fail(
                    "memory limit lacks real cgroup OOM and native termination",
                ));
            }
            operation(
                &rows,
                if family == "L-LIFE-03" {
                    "memory-pressure-descendant-held"
                } else {
                    "memory-pressure-ready"
                },
            )?;
        }
        ("C-STATUS" | "L-LIFE-03", "deadline") => {
            let observed = &case.controller["deadline_observation"];
            let release = number(&native["release_monotonic_millis"])?;
            let duration = case
                .deadline_millis
                .ok_or_else(|| fail("original duration absent"))?;
            if result["outcome"]["kind"] != "deadline"
                || result["outcome"]["wrapper_status"] != 123
                || observed["target"] != native["target"]
                || observed["target_pidfd_readable"] != true
                || observed["release_monotonic_millis"] != release
                || observed["deadline_millis"] != duration
                || number(&observed["wait_observed_monotonic_millis"])?
                    < release
                        .checked_add(duration)
                        .ok_or_else(|| fail("deadline overflow"))?
            {
                return Err(fail(
                    "native deadline observation renewed or lost original target",
                ));
            }
        }
        ("C-CANCEL", "after-release") => {
            operation(&rows, "deadline-demand-started")?;
            cancelled(case, &result, native, "cancellation")?;
        }
        ("L-LIFE-03", "cancellation") => cancelled(case, &result, native, "resource_cancellation")?,
        ("C-IO", "native-argv") => {
            let observed = operation(&rows, "native-argv-observed")?;
            if observed["argv"] != serde_json::to_value(&case.arguments)?
                || bytes(&operation(&rows, "byte-vector")?["bytes"])?
                    != (0..=255).collect::<Vec<u8>>()
                || case.stderr != (0..=255).collect::<Vec<u8>>()
            {
                return Err(fail("native argv/byte effects differ"));
            }
            completed(&result, 0)?;
        }
        ("C-IO", "binary-file") => {
            let expected: Vec<u8> = (0..=255).collect();
            if bytes(&operation(&rows, "binary-file-readback")?["bytes"])? != expected
                || case
                    .outputs
                    .iter()
                    .filter(|(path, data)| {
                        path.as_str() == "work/binary-file.bin" && data == &expected
                    })
                    .count()
                    != 1
                || !case.stderr.is_empty()
            {
                return Err(fail("binary file output differs"));
            }
            completed(&result, 0)?;
        }
        ("C-IO" | "L-MIX-05", "empty-message") => {
            let observed = operation(&rows, "empty-message-exchanged")?;
            if bytes(&observed["received_length_prefix"])? != [0; 4]
                || !bytes(&observed["payload"])?.is_empty()
            {
                return Err(fail("empty message changed"));
            }
            completed(&result, 0)?;
        }
        ("L-MIX-02", "endpoint-mismatch") => {
            let observed = operation(&rows, "application-endpoint-mismatch")?;
            if observed["intended"] == observed["observed"]
                || observed["both_listeners_retained"] != true
                || observed["readiness_reached"] != false
                || observed["application_status"] != 42
            {
                return Err(fail(
                    "endpoint mismatch did not reach genuine neighboring listeners",
                ));
            }
            completed(&result, 42)?;
        }
        ("L-MIX-04", "cooperation") => {
            let observed = operation(&rows, "same-attempt-cooperation-complete")?;
            if observed["native_status"] != 0
                || bytes(&observed["server_received"])? != case.challenge.as_bytes()
            {
                return Err(fail("same-attempt cooperation bytes/status differ"));
            }
            completed(&result, 0)?;
        }
        ("L-ISO-01", probe @ ("ipv6" | "udp" | "raw" | "packet" | "netlink"))
        | ("L-ISO-05", probe @ ("pidfd-getfd" | "ptrace" | "namespace-entry")) => {
            let observed = operation(&rows, "native-authority-denied")?;
            let errno = match probe {
                "ipv6" | "packet" | "netlink" => 97,
                "udp" | "raw" => 93,
                _ => 1,
            };
            if observed["probe"] != probe
                || observed["native_errno"] != errno
                || observed["result"] != -1
            {
                return Err(fail("native kernel authority denial differs"));
            }
            completed(&result, 0)?;
        }
        (
            "L-ID-01",
            "fixed-sandbox-credentials"
            | "empty-groups-and-capabilities"
            | "unprivileged-caller-inputs",
        )
        | ("C-PARSER", "valid-current-result") => {
            operation(&rows, "native-argv-observed")?;
            completed(&result, 0)?;
        }
        ("L-MIX-01", "joint-build-tcp-unix-http")
        | ("L-ID-01", "generated-descendants")
        | ("L-IMG-03", "dynamic-rust-build-and-exec" | "image-only-entrypoint")
        | ("L-LIFE-03", "reserved-target-exit") => {
            for name in [
                "unix-stream-pair-round-trip",
                "unix-path-round-trip",
                "unix-abstract-round-trip",
                "scm-rights-regular-and-listener",
                "http-round-trip",
                "http-empty-body-round-trip",
                "offline-rust-compile-and-test",
                "generated-executable-binary-product",
                "joint-unix-rights-held-through-build",
                "joint-descendant-tree-naturally-retired",
                "tcp-endpoints-closed",
            ] {
                operation(&rows, name)?;
            }
            if bytes(&operation(&rows, "unix-stream-pair-round-trip")?["bytes"])? != b"R"
                || bytes(&operation(&rows, "unix-path-round-trip")?["bytes"])?
                    != b"path-unix-readiness"
                || bytes(&operation(&rows, "unix-abstract-round-trip")?["bytes"])?
                    != b"abstract-unix-readiness"
                || operation(&rows, "offline-rust-compile-and-test")?["native_status"] != 0
                || operation(&rows, "offline-rust-compile-and-test")?["tcp_listener_still_bound"]
                    != true
                || operation(&rows, "joint-descendant-tree-naturally-retired")?["tcp_listener_still_bound"]
                    != true
            {
                return Err(fail(
                    "joint native operations or live listener ownership differ",
                ));
            }
            completed(&result, if family == "L-LIFE-03" { 125 } else { 0 })?;
        }
        _ => assertion(&rows, &result, native)?,
    }
    Ok(())
}
fn completed(result: &Value, code: i32) -> Result<()> {
    if result["outcome"]["kind"] != "completed"
        || result["outcome"]["wrapper_status"] != code
        || result["outcome"]["native_termination"]["kind"] != "exit-code"
        || result["outcome"]["native_termination"]["code"] != code
    {
        return Err(fail("target-origin application status differs"));
    }
    Ok(())
}
fn cancelled(case: &ExecutedCase, result: &Value, native: &Value, field: &str) -> Result<()> {
    let observed = &case.controller[field];
    if observed["frontend"] != native["caller"]
        || observed["signal"] != 2
        || observed["native_signal_result"] != 0
        || result["outcome"]["kind"] != "interrupted"
        || result["outcome"]["wrapper_status"] != 130
    {
        return Err(fail("native cancellation lost original frontend/signal"));
    }
    Ok(())
}
fn root_first(case: &ExecutedCase, rows: &[Value], result: &Value, native: &Value) -> Result<()> {
    completed(result, 0)?;
    let child = operation(rows, "root-exiting-before-held-descendant")?;
    let held = &case.controller["root_first_native"];
    let mut completions = case
        .outputs
        .iter()
        .filter(|(path, _)| path.as_str() == "work/orphan-completion.json");
    let (_, data) = completions
        .next()
        .ok_or_else(|| fail("root-first descendant completion absent"))?;
    if completions.next().is_some() {
        return Err(fail("root-first completion duplicated"));
    }
    let completion: Value = serde_json::from_slice(data)?;
    let expected: Vec<u8> = (0..=255).collect();
    if held["root"] != native["target"]
        || held["root_pidfd_readable_before_descendant_exit"] != true
        || held["descendant_pidfd_readable_when_root_retired"] != false
        || held["descendant_pidfd_readable_after_completion"] != true
        || number(&held["descendant"]["pid"])? == 0
        || held["descendant"]["pid"] == native["target"]["pid"]
        || held["descendant"]["namespace_pid"] != child["pid"]
        || held["descendant"]["birth"] != child["birth"]
        || child["parent_pid"] != native["target_namespace_pid"]
        || completion["challenge"] != case.challenge
        || completion["pid"] != child["pid"]
        || completion["birth"] != child["birth"]
        || completion["original_parent_pid"] != native["target_namespace_pid"]
        || completion["original_parent_birth"] != native["target"]["birth"]
        || completion["reparented_pid"] != 1
        || case
            .outputs
            .iter()
            .filter(|(path, bytes)| {
                path.as_str() == "work/orphan-descendant.bin" && bytes == &expected
            })
            .count()
            != 1
    {
        return Err(fail(
            "root-first live descendant, native ordering, or byte product differs",
        ));
    }
    Ok(())
}
fn report_failure(case: &ExecutedCase) -> Result<()> {
    if case.result.is_some() || !case.outputs.is_empty() {
        return Err(fail("report failure manufactured result/output bytes"));
    }
    let terminal: Value = serde_json::from_slice(
        case.recovery
            .as_ref()
            .ok_or_else(|| fail("actual report failure recovery absent"))?,
    )?;
    let prepared: Value = serde_json::from_slice(&case.prepared)?;
    let ack: Value = serde_json::from_slice(
        case.prepared_ack
            .as_ref()
            .ok_or_else(|| fail("prepared acknowledgment absent"))?,
    )?;
    let locator = serde_json::to_value(&case.locator)?;
    let native = &terminal["native"];
    let directory = &case.controller["report_directory"];
    let digest = String::from(
        case.request
            .digest()
            .map_err(|error| fail(&error.to_string()))?,
    );
    if terminal["format"] != "memcordon.linux-workload-terminal"
        || terminal["revision"] != 1
        || terminal["association"] != locator
        || prepared["association"] != locator
        || terminal["request"] != prepared["request"]
        || terminal["request"]["request_sha256"] != digest
        || ack["association"] != locator
        || ack["prepared_sha256"] != super::artifacts::checksum(&case.prepared)
        || terminal["release"] != "released"
        || terminal["outcome"]["kind"] != "exited"
        || terminal["outcome"]["code"] != 0
        || native["native_wait_status"] != 0
        || terminal["cleanup"]["state"] != "complete"
        || directory["uid"] != native["caller_uid"]
        || directory["before_mode"] != 0o40700
        || directory["blocked_mode"] != 0o40500
        || directory["restored_mode"] != 0o40700
        || directory["same_native_inode"] != true
        || number(&directory["inode"])? == 0
        || directory["result_absent"] != true
        || directory["frontend_wait"]["frontend"] != native["caller"]
        || directory["frontend_wait"]["status"] != 125
        || directory["frontend_wait"]["raw_wait_status"] != 32000
        || directory["recovery_wait"]["status"] != 0
        || directory["recovery_wait"]["raw_wait_status"] != 0
    {
        return Err(fail(
            "report failure or current recovery association differs",
        ));
    }
    let rows = transcript(&case.stdout, case, native)?;
    if operation(&rows, "native-argv-observed")?["native_exit_status"] != 0
        || bytes(&operation(&rows, "byte-vector")?["bytes"])? != (0..=255).collect::<Vec<u8>>()
        || !case
            .stderr
            .windows(b"Permission denied".len())
            .any(|window| window == b"Permission denied")
    {
        return Err(fail(
            "report failure lacked actual target bytes/persistence denial",
        ));
    }
    retired(case, native)
}
