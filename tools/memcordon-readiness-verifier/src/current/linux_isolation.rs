//! Independent joins for current native isolation experiments.
use super::{CaseEvidenceV2, ProductObservationV2};
use crate::{ComponentBuild, VerificationResult};
use serde_json::Value;

pub fn verify_observed_case(
    evidence: &CaseEvidenceV2,
    input: &Value,
    source_commit: &str,
    resolver: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    if (evidence.key.family == "L-ISO-04" && evidence.key.scenario == "opath")
        || (evidence.key.family == "L-ISO-05"
            && ["extra-host-fd", "stdio-host-socket"].contains(&evidence.key.scenario.as_str()))
    {
        let semantic = crate::validate_json_document(&resolver(&evidence.semantic_observation)?)?;
        let extra = &semantic["extra"];
        let original = crate::validate_json_document(&resolver(
            extra["frontend"]
                .as_str()
                .ok_or("original frontend descriptor observation absent")?,
        )?)?;
        let source = &extra["source"];
        let actual_controller =
            crate::validate_json_document(&resolver(&evidence.native_observation)?)?;
        let stdin = evidence.key.scenario == "stdio-host-socket";
        let opaque = evidence.key.scenario == "opath";
        let mapped = &original[if stdin {
            "stdin_descriptor"
        } else {
            "extra_descriptor"
        }];
        if extra["format"] != "memcordon.current-isolation-descriptor"
            || extra["revision"] != 1
            || extra["scenario"] != evidence.key.scenario
            || extra["held_across_invocation"] != true
            || json_bytes(&extra["positive_bytes"])?.len() != 32
            || source["uid"] != 0
            || source["inode"].as_u64().is_none_or(|value| value == 0)
            || mapped["target_descriptor"] != if stdin { 0 } else { 128 }
            || original["format"] != "memcordon.current-original-frontend"
            || original["revision"] != 1
        {
            return Err("original hostile descriptor source/exec-stop evidence differs".into());
        }
        validate_original_descriptor_source(mapped, source, if stdin { 0 } else { 128 })?;
        let flags = source["flags"]
            .as_u64()
            .ok_or("original descriptor flags absent")?;
        if opaque {
            if source["mode"] != 0o100444
                || source["links"] != 1
                || flags & 0o10000000 == 0
                || extra["source_path"]
                    .as_str()
                    .is_none_or(|path| !super::linux::unix_absolute(path))
            {
                return Err("O_PATH negative did not receive original O_PATH host file".into());
            }
        } else if source["mode"] != 0o140777
            || source["links"] != 0
            || flags & 3 != 2
            || !extra["source_path"].is_null()
        {
            return Err(
                "hostile descriptor negative did not receive original connected socket".into(),
            );
        }
        return super::linux::verify_execution(
            evidence,
            input,
            source_commit,
            resolver,
            &|rows, result, native| {
                if original["provider"] != result["provider"]
                    || original["request_sha256"] != result["request"]["request_sha256"]
                    || original["process"] != native["caller"]
                    || original["caller_uid"] != native["caller_uid"]
                    || original["caller_gid"].as_u64().is_none_or(|gid| gid == 0)
                    || original["caller_gid"] != actual_controller["caller_inputs"]["bundle"]["gid"]
                    || result["outcome"]["kind"] != "completed"
                    || result["outcome"]["native_termination"]["code"] != 0
                {
                    return Err("hostile descriptor observation belongs to another original frontend/attempt".into());
                }
                if opaque {
                    let denial = super::linux::operation(rows, "native-outside-file-denied")?;
                    if denial["kind"] != "opath"
                        || denial["native_descriptor"] != 128
                        || denial["native_result"] != -1
                        || denial["native_errno"] != 9
                        || json_bytes(&denial["path"])?
                            != extra["source_path"]
                                .as_str()
                                .ok_or("O_PATH source path absent")?
                                .as_bytes()
                        || json_bytes(
                            &super::linux::operation(rows, "neighboring-private-file")?["bytes"],
                        )? != b"private-read-write-positive"
                    {
                        return Err(
                            "actual target retained hostile O_PATH authority or lost private IO"
                                .into(),
                        );
                    }
                } else {
                    let observed = super::linux::operation(rows, "native-descriptor-isolation")?;
                    let stdio = observed["stdio"]
                        .as_array()
                        .filter(|rows| rows.len() == 3)
                        .ok_or("actual target stdio inventory absent")?;
                    for (index, entry) in stdio.iter().enumerate() {
                        if entry["descriptor"] != index
                            || entry["inode"].as_u64().is_none_or(|value| value == 0)
                            || entry["mode"]
                                .as_u64()
                                .is_none_or(|mode| mode & 0o170000 != 0o010000)
                        {
                            return Err("target received a host socket rather than actual provider byte pipes".into());
                        }
                    }
                    if observed["extra_descriptor"] != 128
                        || observed["native_errno"] != 9
                        || json_bytes(
                            &super::linux::operation(rows, "private-unix-pair-positive")?["bytes"],
                        )? != input["challenge"]
                            .as_str()
                            .ok_or("descriptor positive challenge absent")?
                            .as_bytes()
                    {
                        return Err(
                            "target retained hostile extra FD or lost private socket positive"
                                .into(),
                        );
                    }
                }
                Ok(())
            },
        );
    }
    if evidence.key.family == "L-ISO-02"
        && [
            "input-socket",
            "imported-socket",
            "host-tree-mount-import-rejected",
        ]
        .contains(&evidence.key.scenario.as_str())
    {
        let document = |path: &str| crate::validate_json_document(&resolver(path)?);
        let semantic = document(&evidence.semantic_observation)?;
        let invocation = document(&evidence.invocation)?;
        let namespace = document(&evidence.native_observation)?;
        if namespace["format"] != "memcordon.current-import-native-observation"
            || namespace["revision"] != 1
            || namespace["before"] != namespace["after"]
            || namespace["events"] != serde_json::json!([])
        {
            return Err("source socket packing changed a native allocation namespace".into());
        }
        super::linux_owners::validate_native_namespace_census(&namespace["before"])?;
        let snapshot = document(
            semantic["snapshot"]
                .as_str()
                .ok_or("actual socket input snapshot absent")?,
        )?;
        if semantic["format"] != "memcordon.current-socket-import-refusal"
            || semantic["revision"] != 1
            || semantic["scenario"] != evidence.key.scenario
            || input
                != &serde_json::json!({"format":"memcordon.current-socket-import-input","revision":1,"key":evidence.key,"run_id":evidence.run_id,"scenario":evidence.key.scenario})
            || snapshot["format"] != "memcordon.workload-snapshot"
            || snapshot["revision"] != 1
            || snapshot["target"] != evidence.key.target
            || snapshot["entries"]
                != serde_json::json!([{"kind":"regular","path":"socket","sha256":crate::sha256(b""),"size":0,"executable":false}])
            || snapshot["entrypoints"] != serde_json::json!([])
            || snapshot["library_directories"] != serde_json::json!([])
        {
            return Err(
                "packing refusal did not exercise actual declared current regular socket source"
                    .into(),
            );
        }
        let socket = &semantic["socket"];
        let member = &semantic["source_member"];
        let uid = invocation["caller_uid"]
            .as_u64()
            .filter(|value| *value > 0)
            .ok_or("ordinary packing caller UID absent")?;
        if socket["mode"] != 0o140666
            || socket["uid"] != uid
            || socket["links"] != 1
            || socket["inode"].as_u64().is_none_or(|value| value == 0)
            || socket["descriptor_inode"]
                .as_u64()
                .is_none_or(|value| value == 0)
            || socket["path"]
                .as_str()
                .is_none_or(|path| !super::linux::unix_absolute(path))
        {
            return Err("original live source socket custody differs".into());
        }
        if evidence.key.scenario == "input-socket" {
            if member["mode"] != socket["mode"]
                || member["uid"] != socket["uid"]
                || member["inode"] != socket["inode"]
                || !member["symlink_target"].is_null()
            {
                return Err("input member is not actual original source socket".into());
            }
        } else if evidence.key.scenario == "imported-socket"
            && (member["mode"] != 0o120777 || member["symlink_target"] != socket["path"])
        {
            return Err("imported member is not actual symlink to original held socket".into());
        }
        if evidence.key.scenario == "host-tree-mount-import-rejected" {
            let tree = &semantic["host_tree"];
            let spec = document(
                semantic["pack_spec"]
                    .as_str()
                    .ok_or("actual host tree import specification absent")?,
            )?;
            if tree["mode"] != 0o40755
                || tree["uid"] != 0
                || tree["inode"].as_u64().is_none_or(|value| value == 0)
                || tree["path"]
                    .as_str()
                    .is_none_or(|path| !super::linux::unix_absolute(path))
                || json_bytes(&tree["marker_bytes"])?.len() != 32
                || tree["marker_bytes"] != tree["after_bytes"]
                || spec["host_tree"]
                    != serde_json::json!({"source":tree["path"],"mount_target":"/imported-host"})
                || member["mode"] != 0o100444
                || member["uid"] != 0
                || !member["symlink_target"].is_null()
            {
                return Err(
                    "actual host tree/mount import instruction or valid regular baseline differs"
                        .into(),
                );
            }
        } else if !semantic["host_tree"].is_null() {
            return Err("socket source probe contains another host import mechanism".into());
        }
        let status = invocation["child"]["raw_wait_status"]
            .as_i64()
            .ok_or("actual packing child direct wait absent")?;
        if invocation["format"] != "memcordon.current-socket-import-invocation"
            || invocation["revision"] != 1
            || invocation["caller_gid"]
                .as_u64()
                .is_none_or(|value| value == 0)
            || invocation["child"]["pid"]
                .as_u64()
                .is_none_or(|value| value == 0)
            || invocation["child"]["birth"].as_u64().is_none()
            || invocation["child"]["held_before_input"] != true
            || invocation["child"]["retired"] != true
            || invocation["output_present"] != false
            || status & 0x7f != 0
            || (status >> 8) & 0xff == 0
            || evidence.request.is_some()
            || evidence.raw_result.is_some()
            || evidence.attempt_observation.is_some()
            || evidence.authenticated_terminal.is_some()
            || evidence.recovery.is_some()
            || !evidence.outputs.is_empty()
        {
            return Err("socket source rejection did not retain genuine preallocation failure and original child wait".into());
        }
        let arguments: crate::NativeArguments =
            serde_json::from_value(invocation["arguments"].clone())
                .map_err(|error| error.to_string())?;
        let crate::NativeArguments::UnixBytes(arguments) = arguments else {
            return Err("packing arguments are not native Unix bytes".into());
        };
        if arguments.len() != 6
            || arguments[0] != b"workload"
            || arguments[1] != b"pack"
            || arguments[2] != b"--spec"
            || arguments[4] != b"--output"
            || arguments[3].first() != Some(&b'/')
            || arguments[5].first() != Some(&b'/')
        {
            return Err("actual source socket packaging invocation differs".into());
        }
        let stderr = resolver(&evidence.stderr)?;
        let expected_error = if evidence.key.scenario == "host-tree-mount-import-rejected" {
            stderr
                .windows(b"unknown field".len())
                .any(|part| part == b"unknown field")
                && stderr
                    .windows(b"host_tree".len())
                    .any(|part| part == b"host_tree")
        } else {
            stderr
                .windows(b"os error 6".len())
                .any(|part| part == b"os error 6")
        };
        if !resolver(&evidence.stdout)?.is_empty() || !expected_error {
            return Err("packing failure is not native nonregular source open rejection".into());
        }
        if crate::sha256(&resolver(&evidence.fixture)?) != evidence.fixture_sha256 {
            return Err("selected packing CLI bytes substituted".into());
        }
        return Ok(());
    }
    if evidence.key.family == "L-ISO-06" && evidence.key.scenario == "no-host-proc-import" {
        let semantic = crate::validate_json_document(&resolver(&evidence.semantic_observation)?)?;
        let host = &semantic["extra"];
        let pid = host["host_pid"]
            .as_u64()
            .filter(|value| *value > 0)
            .ok_or("original host PID absent")?;
        let source = host["source"]
            .as_str()
            .ok_or("original host proc marker absent")?;
        let probe = format!("/proc/{pid}/root{source}");
        if host["format"] != "memcordon.current-isolation-path"
            || host["revision"] != 1
            || host["scenario"] != "no-host-proc-import"
            || host["host_birth"].as_u64().is_none()
            || host["probe"] != probe
            || host["uid"] != 0
            || host["mode"] != 0o100444
            || host["links"] != 1
            || host["inode"].as_u64().is_none_or(|value| value == 0)
            || json_bytes(&host["positive_bytes"])?.len() != 32
            || host["positive_bytes"] != host["after_bytes"]
            || host["held_across_invocation"] != true
        {
            return Err("original host proc object/counterpart custody differs".into());
        }
        return super::linux::verify_execution(
            evidence,
            input,
            source_commit,
            resolver,
            &|rows, result, native| {
                let absent = super::linux::operation(rows, "isolation-host-proc-absent")?;
                if absent["host_pid"] != pid
                    || absent["host_birth"] != host["host_birth"]
                    || ![1, 2, 13]
                        .iter()
                        .any(|value| absent["native_errno"] == *value)
                    || absent["self_pid"] != native["target_namespace_pid"]
                    || absent["pid_namespace"] != native["pid_namespace"]
                    || result["outcome"]["kind"] != "completed"
                    || result["outcome"]["native_termination"]["code"] != 0
                {
                    return Err(
                        "original host proc absence does not join actual target namespace".into(),
                    );
                }
                let denial = super::linux::operation(rows, "native-outside-file-denied")?;
                if denial["kind"] != "proc-root"
                    || json_bytes(&denial["path"])? != probe.as_bytes()
                    || denial["native_result"] != -1
                    || ![1, 2, 13, 40]
                        .iter()
                        .any(|value| denial["native_errno"] == *value)
                    || json_bytes(
                        &super::linux::operation(rows, "neighboring-private-file")?["bytes"],
                    )? != b"private-read-write-positive"
                {
                    return Err(
                        "host proc import denial lost exact native open/private positive".into(),
                    );
                }
                Ok(())
            },
        );
    }
    if evidence.key.family == "L-ISO-03" && evidence.key.scenario == "host-abstract" {
        let semantic = crate::validate_json_document(&resolver(&evidence.semantic_observation)?)?;
        let host = &semantic["extra"];
        let name = host["name"].as_str().ok_or("host abstract name absent")?;
        if host["format"] != "memcordon.current-isolation-host-abstract"
            || host["revision"] != 1
            || !name.starts_with("memcordon-host-")
            || name.strip_prefix("memcordon-host-")
                != Some(hex::encode(json_bytes(&host["positive_bytes"])?).as_str())
            || json_bytes(&host["positive_bytes"])?.len() != 32
            || host["descriptor_inode"]
                .as_u64()
                .is_none_or(|value| value == 0)
            || host["native_accept_errno"] != 11
            || host["held_across_invocation"] != true
        {
            return Err("original reachable host abstract listener facts differ".into());
        }
        let host_inode = host["network_namespace"]
            .as_str()
            .and_then(|value| value.strip_prefix("net:["))
            .and_then(|value| value.strip_suffix(']'))
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or("host abstract network namespace absent")?;
        return super::linux::verify_execution(
            evidence,
            input,
            source_commit,
            resolver,
            &|rows, result, native| {
                let denial = super::linux::operation(rows, "isolation-peer-denied")?;
                if result["outcome"]["kind"] != "completed"
                    || result["outcome"]["native_termination"]["code"] != 0
                    || denial["kind"] != "abstract"
                    || denial["endpoint"] != name
                    || ![1, 2, 111]
                        .iter()
                        .any(|code| denial["native_errno"] == *code)
                    || native["network_namespace"]["inode"] == host_inode
                {
                    return Err(
                        "native abstract target denial does not join original host listener".into(),
                    );
                }
                if json_bytes(&denial["neighbor_bytes"])?
                    != input["challenge"]
                        .as_str()
                        .ok_or("abstract target challenge absent")?
                        .as_bytes()
                    || json_bytes(
                        &super::linux::operation(rows, "isolation-private-tcp-positive")?["bytes"],
                    )? != input["challenge"]
                        .as_str()
                        .ok_or("abstract target challenge absent")?
                        .as_bytes()
                {
                    return Err("host abstract denial lost private socket positive bytes".into());
                }
                Ok(())
            },
        );
    }
    if evidence.key.family == "L-ISO-04"
        && [
            "symlink",
            "dotdot",
            "proc-root",
            "proc-cwd",
            "proc-fd",
            "hardlink",
            "mount-alias",
        ]
        .contains(&evidence.key.scenario.as_str())
    {
        let semantic = crate::validate_json_document(&resolver(&evidence.semantic_observation)?)?;
        let host = &semantic["extra"];
        let source = host["source"]
            .as_str()
            .ok_or("original marker source absent")?;
        let supplied = host["probe"]
            .as_str()
            .ok_or("original hostile probe path absent")?;
        let pid = host["host_pid"]
            .as_u64()
            .filter(|value| *value > 0)
            .ok_or("original host process absent")?;
        if host["format"] != "memcordon.current-isolation-path"
            || host["revision"] != 1
            || host["scenario"] != evidence.key.scenario
            || !super::linux::unix_absolute(source)
            || host["host_birth"].as_u64().is_none()
            || host["inode"].as_u64().is_none_or(|value| value == 0)
            || host["mode"] != 0o100444
            || host["uid"] != 0
            || host["links"] != 1
            || json_bytes(&host["positive_bytes"])?.len() != 32
            || host["after_bytes"] != host["positive_bytes"]
            || host["held_across_invocation"] != true
        {
            return Err("original host file identity/content/custody differs".into());
        }
        let expected = match evidence.key.scenario.as_str() {
            "proc-root" => format!("/proc/{pid}/root{source}"),
            "proc-cwd" => format!(
                "/proc/{pid}/cwd/{}{}",
                "../".repeat(128),
                source.trim_start_matches('/')
            ),
            "proc-fd" => format!(
                "/proc/{pid}/fd/{}",
                host["descriptor"]
                    .as_u64()
                    .filter(|value| *value >= 3)
                    .ok_or("original open host descriptor absent")?
            ),
            _ => source.into(),
        };
        if supplied != expected {
            return Err("host alias does not refer to original retained host object".into());
        }
        return super::linux::verify_execution(
            evidence,
            input,
            source_commit,
            resolver,
            &|rows, result, _native| {
                if result["outcome"]["kind"] != "completed"
                    || result["outcome"]["native_termination"]["kind"] != "exit-code"
                    || result["outcome"]["native_termination"]["code"] != 0
                {
                    return Err(
                        "outside alias target did not complete real denial operation".into(),
                    );
                }
                let alias = super::linux::operation(rows, "isolation-path-alias")?;
                let probe = match evidence.key.scenario.as_str() {
                    "symlink" => "/work/isolation-symbolic-alias".into(),
                    "dotdot" => format!("/work/../../{}", source.trim_start_matches('/')),
                    _ => supplied.to_string(),
                };
                if alias["kind"] != evidence.key.scenario
                    || alias["source"] != source
                    || alias["probe"] != probe
                {
                    return Err(
                        "native alias creation/operand differs from original host source".into(),
                    );
                }
                match evidence.key.scenario.as_str() {
                    "hardlink" => {
                        if json_bytes(
                            &super::linux::operation(rows, "isolation-private-hardlink-positive")?
                                ["bytes"],
                        )? != input["challenge"]
                            .as_str()
                            .ok_or("hard link challenge absent")?
                            .as_bytes()
                        {
                            return Err(
                                "host hard link denial lost neighboring private hard link positive"
                                    .into(),
                            );
                        }
                        if ![1, 2, 13, 18]
                            .iter()
                            .any(|value| alias["native_import_errno"] == *value)
                        {
                            return Err("actual host hard link import did not fail natively".into());
                        }
                    }
                    "mount-alias" => {
                        if alias["native_import_errno"] != 1 {
                            return Err("actual native bind mount import was not denied".into());
                        }
                    }
                    _ => {
                        if !alias["native_import_errno"].is_null() {
                            return Err("native alias unexpectedly failed before open probe".into());
                        }
                    }
                }
                let denial = super::linux::operation(rows, "native-outside-file-denied")?;
                if denial["kind"] != evidence.key.scenario
                    || json_bytes(&denial["path"])? != probe.as_bytes()
                    || denial["native_result"] != -1
                    || ![1, 2, 13, 40]
                        .iter()
                        .any(|value| denial["native_errno"] == *value)
                {
                    return Err("outside alias did not reach exact native denied open".into());
                }
                let positive = super::linux::operation(rows, "neighboring-private-file")?;
                if json_bytes(&positive["bytes"])? != b"private-read-write-positive" {
                    return Err("outside denial lost real neighboring private file positive".into());
                }
                Ok(())
            },
        );
    }
    if matches!(
        (evidence.key.family.as_str(), evidence.key.scenario.as_str()),
        ("L-MIX-04", "cross-attempt")
            | ("L-ISO-03", "other-attempt-abstract")
            | ("L-ISO-06", "same-sandbox-uid-cross-attempt")
            | ("L-ISO-06", "foreign-resource-handle")
            | ("L-ISO-06", "stale-resource-owner")
    ) {
        return verify_pair(evidence, input, source_commit, resolver);
    }
    if evidence.key.family == "L-ISO-02" && evidence.key.scenario == "host-temp-socket" {
        let semantic = crate::validate_json_document(&resolver(&evidence.semantic_observation)?)?;
        let host = &semantic["extra"];
        let path = host["path"].as_str().ok_or("host socket path absent")?;
        if host["format"] != "memcordon.current-isolation-host-path"
            || host["revision"] != 1
            || host["scenario"] != "host-temp-socket"
            || !super::linux::unix_absolute(path)
            || host["inode"].as_u64().is_none_or(|value| value == 0)
            || host["descriptor_inode"]
                .as_u64()
                .is_none_or(|value| value == 0)
            || host["links"] != 1
            || host["uid"] != 0
            || host["mode"].as_u64() != Some(0o140666)
            || host["native_accept_errno"] != 11
            || host["positive_connection_observed"] != true
            || host["held_across_invocation"] != true
        {
            return Err("original host Unix listener custody/positive/queue facts differ".into());
        }
        return super::linux::verify_execution(
            evidence,
            input,
            source_commit,
            resolver,
            &|rows, result, _native| {
                if result["outcome"]["kind"] != "completed"
                    || result["outcome"]["native_termination"]["kind"] != "exit-code"
                    || result["outcome"]["native_termination"]["code"] != 0
                {
                    return Err("host socket denial target did not exit successfully".into());
                }
                let denial = super::linux::operation(rows, "forbidden-unix-path-denied")?;
                if denial["path"] != path
                    || ![1, 2, 13, 20, 111]
                        .iter()
                        .any(|value| denial["native_errno"] == *value)
                {
                    return Err("native Unix denial does not name original host socket".into());
                }
                let bytes = super::linux::operation(rows, "private-unix-pair-positive")?["bytes"]
                    .as_array()
                    .ok_or("private pair native bytes absent")?
                    .iter()
                    .map(|value| {
                        value
                            .as_u64()
                            .and_then(|value| u8::try_from(value).ok())
                            .ok_or("private pair byte invalid")
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if bytes
                    != input["challenge"]
                        .as_str()
                        .ok_or("original challenge absent")?
                        .as_bytes()
                {
                    return Err("private neighboring socket byte roundtrip differs".into());
                }
                Ok(())
            },
        );
    }
    if evidence.key.family != "L-ISO-01"
        || !["host-tcp", "nonloopback"].contains(&evidence.key.scenario.as_str())
    {
        return Err("current isolation scenario has no authored native oracle".into());
    }
    let semantic = crate::validate_json_document(&resolver(&evidence.semantic_observation)?)?;
    let host = &semantic["extra"];
    let endpoint: std::net::SocketAddr = host["address"]
        .as_str()
        .ok_or("host listener endpoint absent")?
        .parse()
        .map_err(|_| "host endpoint invalid")?;
    let positive: std::net::SocketAddr = host["positive_peer"]
        .as_str()
        .ok_or("host listener positive absent")?
        .parse()
        .map_err(|_| "host positive invalid")?;
    if host["format"] != "memcordon.current-isolation-host"
        || host["revision"] != 1
        || host["scenario"] != evidence.key.scenario
        || endpoint.ip().is_loopback() != (evidence.key.scenario == "host-tcp")
        || endpoint.ip().is_unspecified()
        || endpoint.port() == 0
        || positive.ip() != endpoint.ip()
        || positive.port() == 0
        || host["socket_inode"].as_u64().is_none_or(|value| value == 0)
        || host["network_namespace"]
            .as_str()
            .is_none_or(|value| !value.starts_with("net:["))
        || host["native_accept_errno"] != 11
        || host["held_across_invocation"] != true
    {
        return Err("original live host listener/positive/native queue facts differ".into());
    }
    super::linux::verify_execution(
        evidence,
        input,
        source_commit,
        resolver,
        &|rows, result, native| {
            if result["outcome"]["kind"] != "completed"
                || result["outcome"]["native_termination"]["kind"] != "exit-code"
                || result["outcome"]["native_termination"]["code"] != 0
            {
                return Err("isolated target did not finish actual denial probe".into());
            }
            let denial = super::linux::operation(rows, "isolation-peer-denied")?;
            if denial["endpoint"] != endpoint.to_string()
                || ![1, 101, 111, 113]
                    .iter()
                    .any(|value| denial["native_errno"] == *value)
            {
                return Err("native denial does not refer to held host listener".into());
            }
            if denial["kind"] != "tcp"
                || json_bytes(
                    &super::linux::operation(rows, "isolation-private-tcp-positive")?["bytes"],
                )? != input["challenge"]
                    .as_str()
                    .ok_or("host denial challenge absent")?
                    .as_bytes()
            {
                return Err("host denial lost neighboring private TCP positive".into());
            }
            let host_inode = host["network_namespace"]
                .as_str()
                .and_then(|value| value.strip_prefix("net:["))
                .and_then(|value| value.strip_suffix(']'))
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or("host namespace inode absent")?;
            if native["network_namespace"]["inode"] == host_inode {
                return Err("target retained the host listener network namespace".into());
            }
            Ok(())
        },
    )
}

fn verify_pair(
    evidence: &CaseEvidenceV2,
    input: &Value,
    source_commit: &str,
    resolver: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    let semantic = crate::validate_json_document(&resolver(&evidence.semantic_observation)?)?;
    let extra = &semantic["extra"];
    let kind = if evidence.key.scenario == "foreign-resource-handle" {
        "proc-fd"
    } else if evidence.key.family == "L-ISO-03" {
        "abstract"
    } else {
        "tcp"
    };
    if extra["format"] != "memcordon.current-isolation-pair"
        || extra["revision"] != 1
        || extra["kind"] != kind
    {
        return Err("current two-attempt experiment role differs".into());
    }
    let peer: CaseEvidenceV2 = serde_json::from_value(crate::validate_json_document(&resolver(
        extra["peer_case"]
            .as_str()
            .ok_or("actual peer evidence absent")?,
    )?)?)
    .map_err(|error| error.to_string())?;
    let peer_input_bytes = resolver(
        extra["peer_input"]
            .as_str()
            .ok_or("actual peer input absent")?,
    )?;
    let peer_input = crate::validate_json_document(&peer_input_bytes)?;
    if peer.key != evidence.key
        || peer.run_id != evidence.run_id
        || peer.lease_id != evidence.lease_id
        || peer.source_commit != evidence.source_commit
        || peer.source_tree_sha256 != evidence.source_tree_sha256
        || peer.fixture_sha256 != evidence.fixture_sha256
        || peer.fixture_source != evidence.fixture_source
        || peer.input
            != extra["peer_input"]
                .as_str()
                .ok_or("peer input reference absent")?
        || crate::sha256(&peer_input_bytes) != peer.input_sha256
        || crate::sha256(&resolver(&peer.fixture)?) != peer.fixture_sha256
    {
        return Err("actual peer invocation belongs to another case/source allocation".into());
    }
    let controller = crate::validate_json_document(&resolver(&evidence.native_observation)?)?;
    let intervention = &controller["intervention"];
    let outer_locator = crate::validate_json_document(&resolver(
        evidence
            .attempt_observation
            .as_deref()
            .ok_or("holder locator absent")?,
    )?)?;
    let peer_locator = crate::validate_json_document(&resolver(
        peer.attempt_observation
            .as_deref()
            .ok_or("peer locator absent")?,
    )?)?;
    if outer_locator["attempt"] == peer_locator["attempt"]
        || intervention["format"] != "memcordon.current-isolation-pair-intervention"
        || intervention["revision"] != 1
        || intervention["original_association"] != outer_locator
        || intervention["before"]["association"] != outer_locator
        || intervention["kind"] != kind
    {
        return Err("pair controller did not retain two distinct original attempts".into());
    }
    let before = intervention["before"]["processes"]
        .as_array()
        .ok_or("original holder native holds absent")?;
    let after = intervention["after"]
        .as_array()
        .ok_or("original holder live post-peer observations absent")?;
    if before.len() != 5
        || after.len() != 5
        || before
            .iter()
            .zip(after)
            .any(|(before, after)| &before["snapshot"] != after)
    {
        return Err("original holder native owner/namespace changed during peer invocation".into());
    }
    super::linux::verify_execution(
        evidence,
        input,
        source_commit,
        resolver,
        &|rows, result, native| {
            let ready = super::linux::operation(rows, "isolation-listener-ready")?;
            let retired = super::linux::operation(rows, "isolation-listener-retired")?;
            if intervention["ready"]["observation"] != *ready
                || ready["tcp"] != retired["tcp"]
                || ready["abstract_name"] != retired["abstract_name"]
                || ready["tcp_descriptor"] != retired["tcp_descriptor"]
                || ready["abstract_descriptor"] != retired["abstract_descriptor"]
                || result["outcome"]["kind"] != "completed"
                || result["outcome"]["native_termination"]["code"] != 0
            {
                return Err(
                    "original listener endpoints were not retained through the experiment".into(),
                );
            }
            let endpoint = if kind == "proc-fd" {
                let pid = native["target"]["pid"]
                    .as_u64()
                    .filter(|value| *value > 0)
                    .ok_or("original foreign target PID absent")?;
                let descriptor = ready["tcp_descriptor"]
                    .as_u64()
                    .filter(|value| *value >= 3)
                    .ok_or("original foreign listener fd absent")?;
                let endpoint = format!("/proc/{pid}/fd/{descriptor}");
                let original = &intervention["foreign_descriptor"];
                if original["path"] != endpoint
                    || original["mode"] != 0o140777
                    || original["uid"] != native["target_uid"]
                    || original["inode"].as_u64().is_none_or(|value| value == 0)
                {
                    return Err(
                        "foreign handle probe did not select actual original live listener object"
                            .into(),
                    );
                }
                endpoint
            } else if kind == "tcp" {
                ready["tcp"]
                    .as_str()
                    .ok_or("original TCP listener endpoint absent")?
                    .to_string()
            } else {
                String::from_utf8(json_bytes(&ready["abstract_name"])?)
                    .map_err(|error| error.to_string())?
            };
            if ready["positive_bytes"]
                != serde_json::json!(
                    input["challenge"]
                        .as_str()
                        .ok_or("holder challenge absent")?
                        .as_bytes()
                )
                || intervention["endpoint"] != endpoint
            {
                return Err("original native listener positive/endpoint differs".into());
            }
            super::linux::verify_execution(
                &peer,
                &peer_input,
                source_commit,
                resolver,
                &|peer_rows, peer_result, peer_native| {
                    let denial = super::linux::operation(peer_rows, "isolation-peer-denied")?;
                    if json_bytes(
                        &super::linux::operation(peer_rows, "isolation-private-tcp-positive")?["bytes"],
                    )? != peer_input["challenge"]
                        .as_str()
                        .ok_or("peer challenge absent")?
                        .as_bytes()
                    {
                        return Err("cross-attempt denial lost neighboring TCP positive".into());
                    }
                    if denial["kind"] != kind
                        || peer_result["provider"] != result["provider"]
                        || denial["endpoint"] != endpoint
                        || ![1, 2, 13, 101, 111, 113]
                            .iter()
                            .any(|code| denial["native_errno"] == *code)
                        || json_bytes(&denial["neighbor_bytes"])?
                            != peer_input["challenge"]
                                .as_str()
                                .ok_or("peer challenge absent")?
                                .as_bytes()
                        || peer_result["outcome"]["kind"] != "completed"
                        || peer_result["outcome"]["native_termination"]["code"] != 0
                    {
                        return Err(
                            "cross-attempt denial or neighboring private socket IO differs".into(),
                        );
                    }
                    if kind == "proc-fd" {
                        let positive =
                            super::linux::operation(peer_rows, "isolation-private-opath-positive")?;
                        if positive["mode"]
                            .as_u64()
                            .is_none_or(|mode| mode & 0o170000 != 0o100000)
                            || positive["inode"].as_u64().is_none_or(|value| value == 0)
                            || json_bytes(&positive["bytes"])?
                                != peer_input["challenge"]
                                    .as_str()
                                    .ok_or("foreign handle positive challenge absent")?
                                    .as_bytes()
                        {
                            return Err("foreign handle denial lost actual neighboring private O_PATH file access".into());
                        }
                    }
                    if evidence.key.scenario == "stale-resource-owner" {
                        let captures = extra["stale"]
                            .as_object()
                            .filter(|fields| fields.len() == 4)
                            .ok_or("original stale-resource captures absent")?;
                        let raw = |leaf: &str| {
                            resolver(
                                captures
                                    .get(leaf)
                                    .and_then(Value::as_str)
                                    .ok_or("original stale-resource capture reference absent")?,
                            )
                        };
                        let observation = crate::validate_json_document(&raw("observation.json")?)?;
                        let terminal = crate::validate_json_document(&raw("terminal.json")?)?;
                        super::linux_component_lifecycle::closed(
                            &terminal,
                            &[
                                "format",
                                "revision",
                                "association",
                                "request",
                                "release",
                                "native",
                                "outcome",
                                "cleanup",
                                "output_delivery",
                                "failures",
                            ],
                        )?;
                        super::linux_component_lifecycle::cleanup(&terminal["cleanup"])?;
                        if terminal["format"] != "memcordon.linux-workload-terminal"
                            || terminal["revision"] != 1
                            || terminal["association"] != peer_locator
                            || terminal["request"] != peer_result["request"]
                            || terminal["native"] != *peer_native
                            || terminal["release"] != "released"
                            || terminal["outcome"] != serde_json::json!({"kind":"exited","code":0})
                            || terminal["failures"] != serde_json::json!([])
                            || observation["format"]
                                != "memcordon.current-stale-resource-observation"
                            || observation["revision"] != 1
                            || observation["association"] != peer_locator
                            || observation["caller_uid"] != peer_native["caller_uid"]
                            || observation["caller_gid"]
                                .as_u64()
                                .is_none_or(|gid| gid == 0)
                            || observation["caller_gid"]
                                != crate::validate_json_document(&resolver(
                                    &peer.native_observation,
                                )?)?["caller_inputs"]["bundle"]["gid"]
                            || observation["child"]["pid"]
                                .as_u64()
                                .is_none_or(|value| value == 0)
                            || observation["child"]["birth"].as_u64().is_none()
                            || observation["child"]["held_before_input"] != true
                            || observation["child"]["retired"] != true
                            || observation["child"]["raw_wait_status"] != 0
                            || !raw("stdout.bin")?.is_empty()
                            || !raw("stderr.bin")?.is_empty()
                        {
                            return Err("retired native owner was resurrected/rebound or cleanup lost original facts".into());
                        }
                        let name = hex::encode(json_bytes(&peer_locator["attempt"])?);
                        let expected = [
                            format!("/var/lib/memcordon/workload-inputs/{name}"),
                            format!("/run/memcordon/private-root-{name}"),
                            format!("/var/lib/memcordon/workload-resources/{name}"),
                            format!("/sys/fs/cgroup/memcordon-sealed/{name}"),
                        ];
                        for phase in ["resources_before", "resources_after"] {
                            let resources = observation[phase]
                                .as_array()
                                .filter(|resources| resources.len() == 4)
                                .ok_or("retired native resource owner census absent")?;
                            for (resource, path) in resources.iter().zip(&expected) {
                                super::linux_component_lifecycle::closed(
                                    resource,
                                    &["path", "absent", "errno"],
                                )?;
                                if resource["path"] != *path
                                    || resource["absent"] != true
                                    || resource["errno"] != 2
                                {
                                    return Err("stale native owner still has or created an original allocation".into());
                                }
                            }
                        }
                    } else if extra["stale"] != serde_json::json!({}) {
                        return Err(
                            "pair experiment contains an unselected stale-owner intervention"
                                .into(),
                        );
                    }
                    for namespace in [
                        "mount_namespace",
                        "pid_namespace",
                        "network_namespace",
                        "ipc_namespace",
                    ] {
                        if peer_native[namespace] == native[namespace] {
                            return Err("distinct attempts share a private namespace".into());
                        }
                    }
                    if evidence.key.family == "L-ISO-06"
                        && native["target_uid"] != peer_native["target_uid"]
                    {
                        return Err("same sandbox UID isolation was not actually exercised".into());
                    }
                    if peer_native["target"] == native["target"]
                        || (peer_native["root_device"] == native["root_device"]
                            && peer_native["root_inode"] == native["root_inode"])
                    {
                        return Err("pair experiments reused original target/root identity".into());
                    }
                    Ok(())
                },
            )
        },
    )
}

fn json_bytes(value: &Value) -> VerificationResult<Vec<u8>> {
    value
        .as_array()
        .ok_or("native byte vector absent")?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| u8::try_from(value).ok())
                .ok_or_else(|| "native byte vector invalid".into())
        })
        .collect()
}

/// Compare the original exec-stop kernel descriptor facts with its held source.
/// This accepts descriptive bytes only and never creates a native descriptor.
pub fn validate_original_descriptor_source(
    mapped: &Value,
    source: &Value,
    slot: u64,
) -> VerificationResult<()> {
    super::linux_component_lifecycle::closed(
        mapped,
        &[
            "device",
            "inode",
            "mode",
            "uid",
            "flags",
            "target_descriptor",
            "fdinfo",
        ],
    )?;
    super::linux_component_lifecycle::closed(
        source,
        &["device", "inode", "mode", "uid", "links", "flags"],
    )?;
    if ![0, 128].contains(&slot)
        || mapped["target_descriptor"] != slot
        || source["uid"] != 0
        || source["inode"].as_u64().is_none_or(|value| value == 0)
        || source["device"].as_u64().is_none()
    {
        return Err("original descriptor slot or native source identity absent".into());
    }
    for field in ["device", "inode", "mode", "uid", "flags"] {
        if mapped[field] != source[field] {
            return Err("frontend received a substituted hostile descriptor".into());
        }
    }
    let flags = source["flags"]
        .as_u64()
        .filter(|flags| flags & 0o2000000 == 0)
        .ok_or("original exec descriptor flags absent or close-on-exec")?;
    let fdinfo = mapped["fdinfo"]
        .as_str()
        .filter(|text| text.len() <= 16384)
        .ok_or("original kernel fdinfo absent/boundedness invalid")?;
    let values = |name: &str, radix: u32| -> VerificationResult<u64> {
        let rows = fdinfo
            .lines()
            .filter_map(|line| line.strip_prefix(name))
            .collect::<Vec<_>>();
        if rows.len() != 1 {
            return Err("original kernel descriptor flags/inode absent or duplicated".into());
        }
        u64::from_str_radix(rows[0].trim(), radix).map_err(|error| error.to_string())
    };
    if values("flags:", 8)? != flags
        || values("ino:", 10)?
            != source["inode"]
                .as_u64()
                .ok_or("original descriptor inode absent")?
    {
        return Err("actual kernel descriptor flags/inode differ from source hold".into());
    }
    Ok(())
}

pub fn verify_case(
    evidence: &CaseEvidenceV2,
    input: &Value,
    product: Option<&ProductObservationV2>,
    build: Option<&ComponentBuild>,
    version: &str,
    resolver: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    if build.is_some() || product.is_none() {
        return Err("installed isolation requires selected actual product".into());
    }
    let product = product.expect("selected product checked");
    if product.key.target != evidence.key.target
        || Some(&product.key.channel) != evidence.key.channel.as_ref()
        || product.source_commit != evidence.source_commit
        || product.source_tree_sha256 != evidence.source_tree_sha256
        || product.version != version
        || evidence.lease_id.as_deref() != Some(product.lifecycle.lease_id.as_str())
    {
        return Err("isolation experiment belongs to another selected product".into());
    }
    if evidence.key.family == "L-ISO-02"
        && [
            "input-socket",
            "imported-socket",
            "host-tree-mount-import-rejected",
        ]
        .contains(&evidence.key.scenario.as_str())
    {
        let cli = product
            .components
            .iter()
            .filter(|component| component.role == "cli")
            .collect::<Vec<_>>();
        if cli.len() != 1 || cli[0].installed_sha256 != evidence.fixture_sha256 {
            return Err("socket import refusal did not use selected installed CLI bytes".into());
        }
    } else {
        let result = crate::validate_json_document(&resolver(
            evidence
                .raw_result
                .as_deref()
                .ok_or("actual isolation result absent")?,
        )?)?;
        if result["provider"]["runtime_manifest_sha256"]
            != crate::sha256(&resolver(&product.runtime_manifest)?)
            || result["provider"]["generation"] != format!("{version}:{}", product.source_commit)
        {
            return Err("isolation invocation used another measured installed provider".into());
        }
    }
    verify_observed_case(evidence, input, &evidence.source_commit, resolver)
}
