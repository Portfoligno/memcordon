//! Independent request/result and native transcript joins for current Linux cells.
use super::{CaseEvidenceV2, ProductObservationV2};
use crate::{ComponentBuild, VerificationResult};
use serde_json::Value;
pub(super) fn unix_absolute(path: &str) -> bool {
    path.starts_with('/') && !path.as_bytes().contains(&0)
}
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub(super) fn closed(value: &Value, fields: &[&str]) -> VerificationResult<()> {
    let object = value.as_object().ok_or("expected closed current object")?;
    if object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str())) {
        return Err("unknown or missing current wire field".into());
    }
    Ok(())
}
fn bytes(value: &Value) -> VerificationResult<Vec<u8>> {
    serde_json::from_value(value.clone()).map_err(|e| e.to_string())
}
fn number(value: &Value) -> VerificationResult<u64> {
    value
        .as_u64()
        .ok_or("native unsigned observation absent".into())
}

// Independent field-order encoder for the declared request revision. It never
// calls the product parser or accepts administrator-contract fields.
fn canonical(value: &Value, out: &mut Vec<u8>) -> VerificationResult<()> {
    if let Some(object) = value.as_object() {
        let fields: &[&str] = if object.contains_key("format") {
            &["format", "revision", "runtime", "requirements"]
        } else if object.contains_key("profile") {
            &["kind", "profile", "inputs", "layout"]
        } else if object.contains_key("runtime_digest") {
            &["runtime_digest", "input_digest", "entrypoint"]
        } else if object.contains_key("writable_roots") {
            &["writable_roots", "output_files"]
        } else if object.contains_key("byte_limit") {
            &["id", "path", "byte_limit", "generated_execution"]
        } else if object.contains_key("local_port") {
            &["kind", "id", "local_port", "peer"]
        } else if object.contains_key("writable_root") {
            &["kind", "id", "writable_root"]
        } else if object.contains_key("operation") {
            &["kind", "id", "operation"]
        } else if object.contains_key("id") {
            &["kind", "id"]
        } else if object.contains_key("port") {
            &["kind", "port"]
        } else {
            &["kind"]
        };
        closed(value, fields)?;
        out.push(b'{');
        for (index, key) in fields.iter().enumerate() {
            if index != 0 {
                out.push(b',');
            }
            serde_json::to_writer(&mut *out, key).map_err(|e| e.to_string())?;
            out.push(b':');
            canonical(&value[*key], out)?;
        }
        out.push(b'}');
    } else if let Some(array) = value.as_array() {
        out.push(b'[');
        for (index, item) in array.iter().enumerate() {
            if index != 0 {
                out.push(b',');
            }
            canonical(item, out)?;
        }
        out.push(b']');
    } else {
        serde_json::to_writer(out, value).map_err(|e| e.to_string())?;
    }
    Ok(())
}
pub fn request_digest(bytes: &[u8]) -> VerificationResult<String> {
    if bytes.len() > 65536 {
        return Err("current request exceeds bound".into());
    }
    let mut value = crate::validate_json_document(bytes)?;
    if value["format"] != "memcordon.workload-request"
        || value["revision"] != 1
        || value["runtime"]["kind"] != "linux-private"
        || value["runtime"]["profile"] != "linux-private-workload-v1"
    {
        return Err("Linux current request identity differs".into());
    }
    let requirements = value["requirements"]
        .as_array_mut()
        .ok_or("requirement inventory absent")?;
    if requirements.len() > 64 {
        return Err("requirement inventory exceeds bound".into());
    }
    requirements.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
    let mut ids = BTreeSet::new();
    for requirement in requirements.iter() {
        let id = requirement["id"].as_str().ok_or("requirement ID absent")?;
        if id.is_empty() || !ids.insert(id) {
            return Err("invalid/duplicate requirement ID".into());
        }
        if !matches!(
            requirement["kind"].as_str(),
            Some(
                "tcp_listener"
                    | "unix_stream_pair"
                    | "unix_seqpacket_pair"
                    | "unix_path_stream"
                    | "unix_abstract_stream"
                    | "intra_attempt_descriptor_transfer"
                    | "generated_executable"
                    | "expected_denial"
            )
        ) {
            return Err("unknown current requirement variant".into());
        }
    }
    let roots = value["runtime"]["layout"]["writable_roots"]
        .as_array()
        .ok_or("writable root inventory absent")?;
    if roots.len() > 16 {
        return Err("writable root inventory exceeds bound".into());
    }
    let mut root_ids = BTreeSet::new();
    let mut total = 0_u64;
    for root in roots {
        let id = root["id"].as_str().ok_or("writable root ID absent")?;
        let path = root["path"].as_str().ok_or("private root path absent")?;
        let size = number(&root["byte_limit"])?;
        if id.is_empty()
            || !root_ids.insert(id)
            || size == 0
            || path.is_empty()
            || path.len() > 4096
            || path.starts_with('/')
            || path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || root["generated_execution"].as_bool().is_none()
        {
            return Err("invalid private writable root declaration".into());
        }
        total = total
            .checked_add(size)
            .ok_or("writable root budget overflow")?;
    }
    if total > 16 * 1024 * 1024 * 1024 {
        return Err("writable root budget exceeds bound".into());
    }
    for requirement in value["requirements"]
        .as_array()
        .expect("checked requirement array")
    {
        if let Some(root) = requirement["writable_root"].as_str() {
            if !root_ids.contains(root) {
                return Err("requirement names an undeclared writable root".into());
            }
            if requirement["kind"] == "generated_executable"
                && !roots.iter().any(|declared| {
                    declared["id"] == root && declared["generated_execution"] == true
                })
            {
                return Err("generated execution was not requested for its writable root".into());
            }
        }
    }
    let mut encoded = Vec::new();
    canonical(&value, &mut encoded)?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

pub(super) fn result_join(
    result: &Value,
    locator: &Value,
    digest: &str,
    source_commit: &str,
    released: bool,
) -> VerificationResult<()> {
    closed(
        result,
        &[
            "format",
            "revision",
            "tool",
            "invocation",
            "request",
            "provider",
            "workload_attempt",
            "release",
            "outcome",
            "cleanup",
            "delivery",
            "output_delivery",
            "diagnostics",
            "provider_failure",
            "request_rejection",
            "windows_rejection",
            "windows_attempt",
            "runtime",
        ],
    )?;
    closed(
        &result["request"],
        &[
            "request_sha256",
            "invocation_sha256",
            "resource_policy_sha256",
            "runtime_sha256",
            "input_sha256",
        ],
    )?;
    closed(
        &result["provider"],
        &["generation", "source_commit", "runtime_manifest_sha256"],
    )?;
    closed(
        locator,
        &[
            "format",
            "revision",
            "attempt",
            "challenge",
            "request_sha256",
            "boot_id",
            "provider",
            "control",
        ],
    )?;
    closed(
        &locator["provider"],
        &["generation", "source_commit", "runtime_manifest_sha256"],
    )?;
    closed(&locator["control"], &["pid", "birth"])?;
    closed(&result["runtime"], &["kind", "profile", "native"])?;
    closed(&result["cleanup"], &["state", "obligations"])?;
    if result["format"] != "memcordon.result"
        || result["revision"] != 3
        || locator["format"] != "memcordon.workload-attempt"
        || locator["revision"] != 1
        || result["workload_attempt"] != *locator
        || result["provider"] != locator["provider"]
        || result["request"]["request_sha256"] != digest
        || locator["request_sha256"] != digest
        || result["provider"]["source_commit"] != source_commit
        || result["runtime"]["kind"] != "linux-private"
        || result["runtime"]["profile"] != "linux-private-workload-v1"
    {
        return Err(
            "current result belongs to another request, product or original attempt".into(),
        );
    }
    let native = &result["runtime"]["native"];
    closed(
        native,
        &[
            "caller_namespaces",
            "user_namespace",
            "boot_id",
            "caller",
            "target",
            "target_namespace_pid",
            "namespace_init",
            "guardian",
            "caller_uid",
            "target_uid",
            "target_gid",
            "cgroup_device",
            "cgroup_inode",
            "init_uid",
            "init_nondumpable",
            "mount_namespace",
            "pid_namespace",
            "network_namespace",
            "ipc_namespace",
            "root_device",
            "root_inode",
            "filter_abi",
            "filter_instruction_sha256",
            "entrypoint_sha256",
            "supplementary_groups",
            "no_new_privileges",
            "capabilities_empty",
            "exec_observed",
            "release_monotonic_millis",
            "exec_observed_monotonic_millis",
            "native_wait_status",
            "memory_oom_kill_count",
            "memory_oom_event_count",
            "memory_max_bytes",
        ],
    )?;
    for field in ["caller", "target", "namespace_init", "guardian"] {
        closed(&native[field], &["pid", "birth"])?;
        if number(&native[field]["pid"])? == 0
            || number(&native[field]["pid"])? > u64::from(u32::MAX)
        {
            return Err("native process identity exceeds its actual range".into());
        }
        number(&native[field]["birth"])?;
    }
    let caller_namespaces = native["caller_namespaces"]
        .as_array()
        .ok_or("original caller namespace inventory absent")?;
    if caller_namespaces.len() != 5 {
        return Err("original caller namespace inventory count differs".into());
    }
    for namespace in caller_namespaces.iter().chain([
        &native["user_namespace"],
        &native["mount_namespace"],
        &native["pid_namespace"],
        &native["network_namespace"],
        &native["ipc_namespace"],
    ]) {
        closed(namespace, &["device", "inode"])?;
        number(&namespace["device"])?;
        if number(&namespace["inode"])? == 0 {
            return Err("native namespace inode absent".into());
        }
    }
    if result["windows_attempt"] != Value::Null || result["windows_rejection"] != Value::Null {
        return Err("Linux result contains another platform's attempt evidence".into());
    }
    let termination = &result["outcome"]["native_termination"];
    if termination != &Value::Null {
        let status = native["native_wait_status"]
            .as_i64()
            .ok_or("native target termination lacks actual wait status")?;
        match termination["kind"].as_str() {
            Some("exit-code")
                if status & 0x7f == 0
                    && termination["code"].as_i64() == Some((status >> 8) & 0xff) => {}
            Some("unix-signal")
                if (1..0x7f).contains(&(status & 0x7f))
                    && termination["signal"].as_i64() == Some(status & 0x7f) => {}
            _ => return Err("result target status differs from native direct wait".into()),
        }
    } else if result["outcome"]["kind"] == "completed" {
        return Err("completed current result lacks direct native target wait".into());
    }
    if native["boot_id"] != locator["boot_id"]
        || number(&native["target_uid"])? == 0
        || number(&native["target_gid"])? == 0
        || native["target_uid"] == native["caller_uid"]
        || native["target_uid"] == native["init_uid"]
        || native["supplementary_groups"]
            .as_array()
            .is_none_or(|groups| !groups.is_empty())
        || native["no_new_privileges"] != true
        || native["capabilities_empty"] != true
        || native["init_nondumpable"] != true
        || native["exec_observed"] != released
        || result["release"] != if released { "released" } else { "not-released" }
    {
        return Err("current native credential/release observations violate Linux profile".into());
    }
    if released {
        if number(&native["release_monotonic_millis"])?
            > number(&native["exec_observed_monotonic_millis"])?
        {
            return Err("native release/exec observation order differs".into());
        }
    } else if !native["release_monotonic_millis"].is_null()
        || !native["exec_observed_monotonic_millis"].is_null()
    {
        return Err("unreleased attempt claims native release/exec timestamps".into());
    }
    if result["cleanup"]["state"] != "complete" || result["delivery"] != "complete" {
        return Err("current original result delivery or cleanup incomplete".into());
    }
    let obligations = result["cleanup"]["obligations"]
        .as_array()
        .ok_or("cleanup inventory absent")?;
    let mut seen = BTreeSet::new();
    for obligation in obligations {
        closed(obligation, &["resource", "settled"])?;
        let name = obligation["resource"]
            .as_str()
            .ok_or("cleanup resource absent")?;
        if obligation["settled"] != true || !seen.insert(name) {
            return Err("forged or duplicate cleanup settlement".into());
        }
    }
    for required in [
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
        if !seen.contains(required) {
            return Err("current cleanup omits a real native resource".into());
        }
    }
    Ok(())
}

fn transcript(bytes: &[u8], challenge: &str, native: &Value) -> VerificationResult<Vec<Value>> {
    if bytes.len() > 32 * 1024 * 1024 {
        return Err("current transcript exceeds bound".into());
    }
    let mut rows = Vec::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let row = crate::validate_json_document(line)?;
        if row["format"] != "memcordon.linux-readiness-transcript"
            || row["revision"] != 1
            || row["challenge"] != challenge
            || number(&row["sequence"])? != rows.len() as u64 + 1
            || row["root_pid"] != native["target_namespace_pid"]
            || row["root_birth"] != native["target"]["birth"]
        {
            return Err(
                "fixture transcript lost original target/challenge/sequence association".into(),
            );
        }
        rows.push(row);
    }
    if rows.is_empty() {
        return Err("native fixture transcript is empty".into());
    }
    Ok(rows)
}

pub(super) fn operation<'a>(rows: &'a [Value], name: &str) -> VerificationResult<&'a Value> {
    let found = rows
        .iter()
        .filter(|row| row["operation"] == name)
        .collect::<Vec<_>>();
    if found.len() != 1 {
        return Err(format!(
            "required original native operation {name} absent/duplicated"
        ));
    }
    Ok(&found[0]["observation"])
}

fn credentials(observed: &Value, native: &Value) -> VerificationResult<()> {
    for (field, expected) in [("uid", "target_uid"), ("gid", "target_gid")] {
        let values = observed[field]
            .as_array()
            .ok_or("actual native credential columns absent")?;
        if values.len() != 4 || values.iter().any(|value| value != &native[expected]) {
            return Err("actual native sandbox credential columns differ".into());
        }
    }
    if observed["groups"] != serde_json::json!([])
        || observed["cap_effective"] != 0
        || observed["cap_permitted"] != 0
        || observed["cap_ambient"] != 0
        || observed["no_new_privileges"] != 1
    {
        return Err("actual native descendant groups/capabilities/NNP differ".into());
    }
    Ok(())
}
fn semantic(key: &crate::CaseKey, rows: &[Value], challenge: &str) -> VerificationResult<()> {
    match (key.family.as_str(), key.scenario.as_str()) {
        ("C-ADMISSION", "positive") => {
            let bind = operation(rows, "bind-zero-and-competing-bind")?;
            let endpoint: std::net::SocketAddrV4 = bind["endpoint"]
                .as_str()
                .ok_or("actual admitted TCP endpoint absent")?
                .parse()
                .map_err(|error: std::net::AddrParseError| error.to_string())?;
            let http = operation(rows, "http-round-trip")?;
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
                return Err("actual admitted request TCP/HTTP effects differ".into());
            }
            let empty = operation(rows, "http-empty-body-round-trip")?;
            if !bytes(&empty["body"])?.is_empty()
                || bytes(&empty["response"])? != b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
            {
                return Err("admitted native empty HTTP response differs".into());
            }
            operation(rows, "tcp-endpoints-closed")?;
        }
        ("L-MIX-01", "joint-build-tcp-unix-http")
        | ("L-LIFE-03", "reserved-target-exit")
        | ("L-ID-01", "generated-descendants")
        | ("L-IMG-03", "dynamic-rust-build-and-exec" | "image-only-entrypoint") => {
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
                operation(rows, name)?;
            }
            if bytes(&operation(rows, "unix-stream-pair-round-trip")?["bytes"])? != b"R"
                || bytes(&operation(rows, "unix-path-round-trip")?["bytes"])?
                    != b"path-unix-readiness"
                || bytes(&operation(rows, "unix-abstract-round-trip")?["bytes"])?
                    != b"abstract-unix-readiness"
            {
                return Err("actual Unix transport payload changed".into());
            }
            if operation(rows, "offline-rust-compile-and-test")?["native_status"] != 0
                || operation(rows, "offline-rust-compile-and-test")?["tcp_listener_still_bound"]
                    != true
                || operation(rows, "joint-descendant-tree-naturally-retired")?["tcp_listener_still_bound"]
                    != true
            {
                return Err("compiler/build/native descendant lifecycle differs".into());
            }
            if bytes(&operation(rows, "http-empty-body-round-trip")?["body"])? != b"" {
                return Err("empty HTTP payload changed".into());
            }
        }
        ("L-MIX-02", "endpoint-mismatch") => {
            let observed = operation(rows, "application-endpoint-mismatch")?;
            if observed["intended"] == observed["observed"]
                || observed["both_listeners_retained"] != true
                || observed["readiness_reached"] != false
                || observed["application_status"] != 42
            {
                return Err(
                    "endpoint mismatch is not an actual neighboring application refusal".into(),
                );
            }
        }
        ("L-MIX-04", "cooperation") => {
            let observed = operation(rows, "same-attempt-cooperation-complete")?;
            if observed["native_status"] != 0
                || bytes(&observed["server_received"])? != challenge.as_bytes()
            {
                return Err("same-attempt native cooperation payload/status differs".into());
            }
        }
        ("C-IO" | "L-MIX-05", "empty-message") => {
            let observed = operation(rows, "empty-message-exchanged")?;
            if bytes(&observed["received_length_prefix"])? != [0; 4]
                || !bytes(&observed["payload"])?.is_empty()
            {
                return Err("actual empty message changed".into());
            }
        }
        ("L-MIX-03", "listener-and-file-transfer") => {
            let transfer = operation(rows, "scm-rights-regular-and-listener")?;
            if bytes(&transfer["file_bytes"])? != b"descriptor-readiness"
                || bytes(&transfer["network_bytes"])? != b"rights-listener"
            {
                return Err("actual descriptor transfer payload differs".into());
            }
            for (original, received) in [
                ("file_device", "received_file_device"),
                ("file_inode", "received_file_inode"),
                ("listener_device", "received_listener_device"),
                ("listener_inode", "received_listener_inode"),
            ] {
                if number(&transfer[original])? == 0 || transfer[original] != transfer[received] {
                    return Err("transferred native file/listener identity differs".into());
                }
            }
        }
        ("L-ISO-03", "own-abstract-positive") => {
            let observed = operation(rows, "unix-abstract-round-trip")?;
            if bytes(&observed["bytes"])? != b"abstract-unix-readiness"
                || bytes(&observed["name"])? != challenge.as_bytes()
            {
                return Err("actual per-attempt abstract endpoint/payload differs".into());
            }
        }
        ("L-ISO-02", "host-run-socket") => {
            let denied = operation(rows, "forbidden-unix-path-denied")?;
            if denied["path"] != "/run/memcordon/sealed-agent.sock"
                || denied["native_errno"] != 2
                || bytes(&operation(rows, "private-unix-pair-positive")?["bytes"])?
                    != challenge.as_bytes()
            {
                return Err(
                    "private root reached host service socket or lost neighboring Unix IO".into(),
                );
            }
        }
        ("L-ISO-01", probe @ ("ipv6" | "udp" | "raw" | "packet" | "netlink")) => {
            let observed = operation(rows, "native-authority-denied")?;
            let errno = if matches!(probe, "ipv6" | "packet" | "netlink") {
                97
            } else {
                93
            };
            if observed["probe"] != probe
                || observed["native_errno"] != errno
                || observed["result"] != -1
            {
                return Err("actual selected native socket/filter denial differs".into());
            }
        }
        ("L-ISO-05", probe @ ("pidfd-getfd" | "ptrace" | "namespace-entry")) => {
            let observed = operation(rows, "native-authority-denied")?;
            if observed["probe"] != probe
                || observed["native_errno"] != 1
                || observed["result"] != -1
            {
                return Err("actual cross-process or namespace authority denial differs".into());
            }
        }
        _ => {
            return Err(format!(
                "case has no independently pinned current Linux semantic recipe: {key:?}"
            ));
        }
    }
    Ok(())
}

pub fn verify_case(
    evidence: &CaseEvidenceV2,
    input: &Value,
    product: Option<&ProductObservationV2>,
    component_build: Option<&ComponentBuild>,
    version: &str,
    resolver: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    if let Some(build) = component_build {
        return super::linux_components::verify_case(evidence, input, build, version, resolver);
    }
    let product = product.ok_or("current installed Linux product association absent")?;
    if evidence.key.family == "L-SNAPSHOT" {
        return super::linux_snapshots::verify_case(
            evidence,
            input,
            Some(product),
            None,
            version,
            resolver,
        );
    }
    if matches!(evidence.key.family.as_str(), "L-IMG-01" | "L-IMG-02") {
        return super::linux_images::verify_case(
            evidence,
            input,
            Some(product),
            None,
            version,
            resolver,
        );
    }
    if matches!(
        (evidence.key.family.as_str(), evidence.key.scenario.as_str()),
        ("L-MIX-04", "cross-attempt")
            | ("L-ISO-01", "host-tcp" | "nonloopback")
            | (
                "L-ISO-02",
                "host-temp-socket"
                    | "input-socket"
                    | "imported-socket"
                    | "host-tree-mount-import-rejected"
            )
            | ("L-ISO-03", "host-abstract" | "other-attempt-abstract")
            | ("L-ISO-04", _)
            | ("L-ISO-05", "stdio-host-socket" | "extra-host-fd")
            | ("L-ISO-06", _)
    ) {
        return super::linux_isolation::verify_case(
            evidence,
            input,
            Some(product),
            None,
            version,
            resolver,
        );
    }
    if matches!(
        evidence.key.family.as_str(),
        "C-PACKAGE" | "C-INSTALL-CURRENT"
    ) {
        return super::linux_package::verify_case(evidence, input, product, resolver);
    }
    if evidence.key.family == "C-ADMISSION" && evidence.key.scenario != "positive"
        || evidence.key.family == "L-VER-01"
    {
        return super::linux_refusals::verify_case(evidence, input, product, resolver);
    }
    if matches!(evidence.key.family.as_str(), "C-OWNER" | "L-LIFE-02")
        || evidence.key.family == "C-LIFETIME" && evidence.key.scenario != "root-first"
        || evidence.key.family == "C-CANCEL"
            && !["held-before-release", "after-release"].contains(&evidence.key.scenario.as_str())
    {
        return super::linux_owners::verify_case(
            evidence,
            input,
            Some(product),
            None,
            version,
            resolver,
        );
    }
    let result = crate::validate_json_document(&resolver(
        evidence
            .raw_result
            .as_deref()
            .ok_or("current raw result absent")?,
    )?)?;
    let manifest = resolver(&product.runtime_manifest)?;
    let observed_manifest = crate::validate_json_document(&manifest)?;
    if observed_manifest["format"] != "memcordon.runtime-manifest"
        || observed_manifest["revision"] != 2
        || result["provider"]["runtime_manifest_sha256"] != hex::encode(Sha256::digest(&manifest))
    {
        return Err(
            "current native result provider is not the exact selected manifest bytes".into(),
        );
    }
    verify_observed_case(evidence, input, &product.source_commit, resolver)
}
pub fn verify_observed_case(
    evidence: &CaseEvidenceV2,
    input: &Value,
    source_commit: &str,
    resolver: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    verify_execution_inner(evidence, input, source_commit, resolver, None)
}

/// Reuse the same original request, native execution and physical retirement
/// joins while a separate finite current actor verifies its own byte effects.
pub(super) fn verify_execution(
    evidence: &CaseEvidenceV2,
    input: &Value,
    source_commit: &str,
    resolver: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
    semantic: &dyn Fn(&[Value], &Value, &Value) -> VerificationResult<()>,
) -> VerificationResult<()> {
    verify_execution_inner(evidence, input, source_commit, resolver, Some(semantic))
}
fn verify_execution_inner(
    evidence: &CaseEvidenceV2,
    input: &Value,
    source_commit: &str,
    resolver: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
    current_semantic: Option<&dyn Fn(&[Value], &Value, &Value) -> VerificationResult<()>>,
) -> VerificationResult<()> {
    if evidence.key.family == "L-LIFE-05" && evidence.key.scenario == "report-persistence-failure" {
        return verify_report_failure(evidence, input, source_commit, resolver);
    }
    let request_path = evidence
        .request
        .as_deref()
        .ok_or("current request artifact absent")?;
    let request_bytes = resolver(request_path)?;
    let digest = request_digest(&request_bytes)?;
    let request = crate::validate_json_document(&request_bytes)?;
    let result = crate::validate_json_document(&resolver(
        evidence
            .raw_result
            .as_deref()
            .ok_or("current raw result absent")?,
    )?)?;
    let locator = crate::validate_json_document(&resolver(
        evidence
            .attempt_observation
            .as_deref()
            .ok_or("original attempt locator absent")?,
    )?)?;
    let held_cancel =
        evidence.key.family == "C-CANCEL" && evidence.key.scenario == "held-before-release";
    result_join(&result, &locator, &digest, source_commit, !held_cancel)?;
    super::linux_wire::verify_start(
        &resolver(
            input["start"]
                .as_str()
                .ok_or("original native start artifact absent")?,
        )?,
        &request,
        &result["request"],
        input,
    )?;
    let declared = request["runtime"]["layout"]["output_files"]
        .as_array()
        .ok_or("current declared output inventory absent")?;
    let refused_export =
        evidence.key.family == "L-IMG-04" && evidence.key.scenario != "export-concurrent-writer";
    if (!refused_export && declared.len() != evidence.outputs.len())
        || (refused_export && (declared.len() != 1 || !evidence.outputs.is_empty()))
    {
        return Err("caller retained output inventory omits or adds a declared file".into());
    }
    let mut output_names = BTreeSet::new();
    for output in declared {
        let relative = output
            .as_str()
            .ok_or("declared output path is not a string")?;
        if !output_names.insert(relative) {
            return Err("duplicate declared output".into());
        }
        if refused_export {
            continue;
        }
        let suffix = format!("/outputs/{relative}");
        let actual = evidence
            .outputs
            .iter()
            .filter(|path| path.ends_with(&suffix))
            .collect::<Vec<_>>();
        if actual.len() != 1 {
            return Err("caller materialized output path differs from original declaration".into());
        }
        resolver(actual[0])?;
    }
    if !declared.is_empty()
        && result["output_delivery"]
            != if refused_export {
                "incomplete"
            } else {
                "complete"
            }
    {
        return Err("declared caller output byte delivery is incomplete".into());
    }
    let native = &result["runtime"]["native"];
    let prepared_bytes = resolver(
        input["prepared"]
            .as_str()
            .ok_or("original held prepared artifact absent")?,
    )?;
    let prepared = crate::validate_json_document(&prepared_bytes)?;
    let ack = if held_cancel {
        Value::Null
    } else {
        crate::validate_json_document(&resolver(
            input["prepared_ack"]
                .as_str()
                .ok_or("original prepared acknowledgment absent")?,
        )?)?
    };
    if prepared["format"] != "memcordon.linux-workload-prepared"
        || prepared["revision"] != 1
        || prepared["association"] != locator
        || prepared["request"] != result["request"]
        || prepared["native"]["exec_observed"] != false
        || prepared["native"]["exec_observed_monotonic_millis"] != Value::Null
        || prepared["native"]["native_wait_status"] != Value::Null
        || if held_cancel {
            !input["prepared_ack"].is_null()
        } else {
            ack["format"] != "memcordon.workload-prepared-ack"
                || ack["revision"] != 1
                || ack["association"] != locator
                || ack["prepared_sha256"] != hex::encode(Sha256::digest(&prepared_bytes))
        }
    {
        return Err("original pre-release prepared gate/ack association differs".into());
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
            return Err(format!(
                "pre-release native {field} changed before terminal"
            ));
        }
    }
    let challenge = input["challenge"]
        .as_str()
        .ok_or("original fixture challenge absent")?;
    if challenge.len() != 64
        || challenge.bytes().all(|byte| byte == b'0')
        || !challenge.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("invalid original fixture challenge".into());
    }
    let stdout = resolver(&evidence.stdout)?;
    let stderr = resolver(&evidence.stderr)?;
    if native["entrypoint_sha256"] != evidence.fixture_sha256
        || hex::encode(Sha256::digest(resolver(&evidence.fixture)?)) != evidence.fixture_sha256
    {
        return Err(
            "native sealed first image is not the exact retained selected fixture bytes".into(),
        );
    }
    let raw_stream = matches!(evidence.key.family.as_str(), "C-IO" | "L-MIX-05")
        && ["binary-streams", "empty-input", "bounded-large-output"]
            .contains(&evidence.key.scenario.as_str());
    if evidence.key.family == "C-CANCEL"
        && ["held-before-release", "after-release"].contains(&evidence.key.scenario.as_str())
    {
        let controller = crate::validate_json_document(&resolver(&evidence.native_observation)?)?;
        let cancellation = &controller["cancellation"];
        if cancellation["format"] != "memcordon.linux-native-cancellation"
            || cancellation["revision"] != 1
            || cancellation["phase"] != evidence.key.scenario
            || cancellation["frontend"] != native["caller"]
            || cancellation["signal"] != 2
            || cancellation["native_signal_result"] != 0
            || result["outcome"]["kind"] != "interrupted"
            || result["outcome"]["wrapper_status"] != 130
        {
            return Err("original native cancellation/source signal/outcome differs".into());
        }
        if held_cancel {
            if !stdout.is_empty() || !stderr.is_empty() {
                return Err("held cancellation observed target byte effects before release".into());
            }
        } else {
            let rows = transcript(&stdout, challenge, native)?;
            operation(&rows, "deadline-demand-started")?;
        }
    } else if evidence.key.family == "L-LIFE-05" && evidence.key.scenario == "relay-backpressure" {
        let end = stdout
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or("relay pressure readiness line absent")?
            + 1;
        let readiness = transcript(&stdout[..end], challenge, native)?;
        if operation(&readiness, "relay-pressure-ready")?["bytes_per_stream"] != 2097152 {
            return Err("original relay pressure configured bytes differ".into());
        }
        let held = crate::validate_json_document(&resolver(&evidence.native_observation)?)?;
        let pressure = &held["relay_pressure"];
        let capacity = number(&pressure["pipe"]["capacity"])?;
        let queued = number(&pressure["pipe"]["queued"])?;
        let write_syscall = if evidence.key.target.starts_with("aarch64-") {
            64
        } else if evidence.key.target.starts_with("x86_64-") {
            1
        } else {
            return Err("unsupported native relay ABI".into());
        };
        if pressure["format"] != "memcordon.linux-current-relay-pressure"
            || pressure["revision"] != 1
            || pressure["frontend"] != native["caller"]
            || pressure["target"] != native["target"]
            || pressure["reader_stopped"] != true
            || pressure["reader_resumed"] != true
            || pressure["original_target_input_gated"] != true
            || pressure["release_byte_queued_before_reader_stop"] != 1
            || pressure["target_alive"] != true
            || pressure["bytes_consumed_by_observer"] != 0
            || ![1, 2]
                .iter()
                .any(|descriptor| pressure["descriptor"] == *descriptor)
            || queued == 0
            || capacity.checked_sub(queued).is_none_or(|free| free >= 4096)
            || pressure["blocked_write"]["syscall"] != write_syscall
            || pressure["blocked_write"]["descriptor"] != pressure["descriptor"]
            || pressure["blocked_write"]["length"] != 256
            || pressure["blocked_write"]["wait_channel"] != "pipe_write"
            || number(&pressure["pipe"]["inode"])? == 0
            || result["outcome"]["wrapper_status"] != 0
        {
            return Err(
                "actual original relay pipe did not fill under stopped-reader backpressure".into(),
            );
        }
        super::byte_effects::verify_raw_streams_expected(
            "bounded-large-output",
            &bytes(&input["binary"])?,
            &bytes(&input["stderr_binary"])?,
            &stdout[end..],
            &stderr,
        )?;
    } else if raw_stream {
        super::byte_effects::verify_raw_streams_expected(
            &evidence.key.scenario,
            &bytes(&input["binary"])?,
            &bytes(&input["stderr_binary"])?,
            &stdout,
            &stderr,
        )?;
    } else {
        let mut rows = transcript(&stdout, challenge, native)?;
        if evidence.key.family == "L-IMG-04" {
            let controller =
                crate::validate_json_document(&resolver(&evidence.native_observation)?)?;
            super::linux_exports::verify(evidence, &result, native, &rows, &controller, resolver)?;
        } else if evidence.key.family == "L-ID-01"
            && [
                "fixed-sandbox-credentials",
                "empty-groups-and-capabilities",
                "unprivileged-caller-inputs",
            ]
            .contains(&evidence.key.scenario.as_str())
            || evidence.key.family == "C-PARSER" && evidence.key.scenario == "valid-current-result"
        {
            if native["target_uid"] == native["caller_uid"]
                || number(&native["target_gid"])? == 0
                || native["supplementary_groups"] != serde_json::json!([])
                || native["capabilities_empty"] != true
                || native["no_new_privileges"] != true
                || result["outcome"]["native_termination"]["kind"] != "exit-code"
                || result["outcome"]["native_termination"]["code"] != 0
            {
                return Err(
                    "actual fixed sandbox credentials/filter or direct execution status differs"
                        .into(),
                );
            }
            let actual = operation(&rows, "native-argv-observed")?;
            if actual["native_exit_status"] != 0 {
                return Err("actual credential probe fixture failed".into());
            }
        } else if evidence.key.family == "C-LIFETIME" && evidence.key.scenario == "root-first"
            || evidence.key.family == "L-LIFE-01"
                && evidence.key.scenario == "root-first-resource-descendant"
        {
            let held = crate::validate_json_document(&resolver(&evidence.native_observation)?)?;
            rows.push(held["root_first_native"].clone());
            let completion = evidence
                .outputs
                .iter()
                .filter(|path| path.ends_with("/outputs/work/orphan-completion.json"))
                .collect::<Vec<_>>();
            let binary = evidence
                .outputs
                .iter()
                .filter(|path| path.ends_with("/outputs/work/orphan-descendant.bin"))
                .collect::<Vec<_>>();
            if completion.len() != 1 || binary.len() != 1 {
                return Err(
                    "original root-first completion/binary exports missing or duplicated".into(),
                );
            }
            rows.push(crate::validate_json_document(&resolver(completion[0])?)?);
            super::byte_effects::verify_binary_file(
                &bytes(&input["binary"])?,
                &resolver(binary[0])?,
            )?;
            super::linux_status::verify_case(&evidence.key, input, &result, native, &rows)?;
        } else if evidence.key.family == "L-LIFE-03" {
            let held = crate::validate_json_document(&resolver(&evidence.native_observation)?)?;
            for name in [
                "unix-stream-pair-round-trip",
                "unix-path-round-trip",
                "unix-abstract-round-trip",
                "scm-rights-regular-and-listener",
                "http-round-trip",
                "http-empty-body-round-trip",
                "joint-generated-child-held",
            ] {
                operation(&rows, name)?;
            }
            match evidence.key.scenario.as_str() {
                "reserved-target-exit" => {
                    semantic(&evidence.key, &rows, challenge)?;
                    if operation(&rows, "joint-reserved-application-exit")?["requested_exit_code"]
                        != 125
                        || result["outcome"]["kind"] != "completed"
                        || result["outcome"]["wrapper_status"] != 125
                        || result["outcome"]["native_termination"]["code"] != 125
                        || native["native_wait_status"] != 125 * 256
                    {
                        return Err("resource-rich reserved target exit was reclassified".into());
                    }
                }
                "memory" => {
                    let allocator = operation(&rows, "memory-pressure-descendant-held")?;
                    let phases = held["held_stages"]
                        .as_array()
                        .ok_or("resource phase inventory absent")?;
                    let pressure: Vec<_> = phases
                        .iter()
                        .filter(|phase| phase["operation"] == "memory-pressure-descendant-held")
                        .collect();
                    if pressure.len() != 1
                        || pressure[0]["children"]
                            .as_array()
                            .is_none_or(|children| children.len() != 1)
                    {
                        return Err("actual held pressure allocator is absent/duplicated".into());
                    }
                    let child = &pressure[0]["children"][0];
                    if allocator["chunk_bytes"] != 1048576
                        || held["resource_allocator"]["continued"] != true
                        || held["resource_allocator"]["pid"] != child["identity"]["pid"]
                        || held["resource_allocator"]["birth"] != child["identity"]["birth"]
                        || child["identity"]["parent_pid"] != native["target"]["pid"]
                        || child["identity"]["parent_birth"] != native["target"]["birth"]
                        || child["namespace_pid"] != allocator["native_tree"]["pid"]
                        || native["memory_max_bytes"] != input["memory_bytes"]
                        || native["memory_oom_event_count"]
                            .as_u64()
                            .is_none_or(|value| value == 0)
                        || native["memory_oom_kill_count"]
                            .as_u64()
                            .is_none_or(|value| value == 0)
                        || result["outcome"]["kind"] != "confirmed-memory-limit"
                        || result["outcome"]["wrapper_status"] != 124
                        || result["outcome"]["native_termination"]["kind"] != "unix-signal"
                        || result["outcome"]["native_termination"]["signal"] != 9
                    {
                        return Err("resource-rich memory pressure lacks actual memcg cause".into());
                    }
                }
                "deadline" => {
                    let observed = &held["deadline_observation"];
                    let release = number(&native["release_monotonic_millis"])?;
                    let deadline = number(&input["deadline_millis"])?;
                    if observed["target"] != native["target"]
                        || observed["target_pidfd_readable"] != true
                        || observed["release_monotonic_millis"] != release
                        || observed["deadline_millis"] != deadline
                        || number(&observed["wait_observed_monotonic_millis"])?
                            < release
                                .checked_add(deadline)
                                .ok_or("resource deadline overflow")?
                        || result["outcome"]["kind"] != "deadline"
                        || result["outcome"]["wrapper_status"] != 123
                    {
                        return Err("resource-rich original deadline/native wait differs".into());
                    }
                }
                "cancellation" => {
                    let cancellation = &held["resource_cancellation"];
                    if cancellation["frontend"] != native["caller"]
                        || cancellation["signal"] != 2
                        || cancellation["native_signal_result"] != 0
                        || result["outcome"]["kind"] != "interrupted"
                        || result["outcome"]["wrapper_status"] != 130
                    {
                        return Err(
                            "resource-rich cancellation lacks original frontend signal".into()
                        );
                    }
                }
                _ => return Err("unknown resource-rich lifecycle scenario".into()),
            }
        } else if evidence.key.family == "C-STATUS" {
            let held = crate::validate_json_document(&resolver(&evidence.native_observation)?)?;
            if !held["deadline_observation"].is_null() {
                rows.push(held["deadline_observation"].clone());
            }
            super::linux_status::verify_case(&evidence.key, input, &result, native, &rows)?;
        } else if evidence.key.family == "C-IO" && evidence.key.scenario == "native-argv" {
            let observed = operation(&rows, "native-argv-observed")?;
            let argv: Vec<Vec<u8>> = serde_json::from_value(observed["argv"].clone())
                .map_err(|error| error.to_string())?;
            let expected: crate::NativeArguments =
                serde_json::from_value(input["target_argv"].clone())
                    .map_err(|error| error.to_string())?;
            super::byte_effects::verify_native_argv(
                &expected,
                &crate::NativeArguments::UnixBytes(argv),
                "native-argv",
            )?;
            let vector = bytes(&input["binary"])?;
            if bytes(&operation(&rows, "byte-vector")?["bytes"])? != vector || stderr != vector {
                return Err("native argv fixture byte vector or stderr changed".into());
            }
            if result["outcome"]["native_termination"]["kind"] != "exit-code"
                || observed["native_exit_status"] != result["outcome"]["native_termination"]["code"]
            {
                return Err(
                    "actual native argv exit status differs from direct native wait".into(),
                );
            }
        } else if evidence.key.family == "C-IO" && evidence.key.scenario == "binary-file" {
            let expected = bytes(&input["binary"])?;
            super::byte_effects::verify_binary_file(
                &expected,
                &bytes(&operation(&rows, "binary-file-readback")?["bytes"])?,
            )?;
            let files = evidence
                .outputs
                .iter()
                .filter(|path| path.ends_with("/outputs/work/binary-file.bin"))
                .collect::<Vec<_>>();
            if files.len() != 1 {
                return Err("binary file output is missing or duplicated".into());
            }
            super::byte_effects::verify_binary_file(&expected, &resolver(files[0])?)?;
            if !stderr.is_empty() {
                return Err("binary file fixture produced unexpected stderr".into());
            }
        } else {
            if let Some(verify) = current_semantic {
                verify(&rows, &result, native)?;
            } else {
                semantic(&evidence.key, &rows, challenge)?;
            }
        }
    }
    let held = crate::validate_json_document(&resolver(&evidence.native_observation)?)?;
    if evidence.key.family == "L-ISO-02" && evidence.key.scenario == "host-run-socket" {
        let socket = &held["host_service_socket"];
        if socket["path"] != "/run/memcordon/sealed-agent.sock"
            || socket["uid"] != 0
            || number(&socket["device"])? == 0
            || number(&socket["inode"])? == 0
            || number(&socket["mode"])? & 0o170000 != 0o140000
            || socket["provider_control"] != locator["control"]
            || socket["named_identity_preserved"] != true
        {
            return Err(
                "host service positive neighbor was not the original provider socket/control"
                    .into(),
            );
        }
    }
    if held["native"] != Value::Null {
        let caller_inputs = &held["caller_inputs"];
        if caller_inputs["format"] != "memcordon.linux-caller-input-observation"
            || caller_inputs["revision"] != 1
            || caller_inputs["runtime_digest"] != request["runtime"]["inputs"]["runtime_digest"]
            || caller_inputs["input_digest"] != request["runtime"]["inputs"]["input_digest"]
            || caller_inputs["bundle"]["uid"] != native["caller_uid"]
            || number(&caller_inputs["bundle"]["inode"])? == 0
            || number(&caller_inputs["bundle"]["length"])? == 0
        {
            return Err("original ordinary caller pack/source association differs".into());
        }
        let sources = caller_inputs["sources"]
            .as_array()
            .ok_or("actual caller input source custody absent")?;
        if sources.len() != 2 {
            return Err("ordinary caller source inventory differs".into());
        }
        for role in ["runtime", "input"] {
            let found = sources
                .iter()
                .filter(|source| source["role"] == role)
                .collect::<Vec<_>>();
            if found.len() != 1
                || found[0]["uid"] != native["caller_uid"]
                || number(&found[0]["inode"])? == 0
                || number(&found[0]["mode"])? & 0o200 == 0
            {
                return Err(
                    "actual source root is not owned and writable by the ordinary caller".into(),
                );
            }
        }
        if held["association"] != locator
            || held["native"]["target"] != native["target"]
            || held["root"]["device"] != native["root_device"]
            || held["root"]["inode"] != native["root_inode"]
        {
            return Err("independently held original native owner/root differs".into());
        }
        let retirement = crate::validate_json_document(&resolver(&evidence.retirement)?)?;
        if matches!(
            evidence.key.family.as_str(),
            "L-MIX-01" | "L-IMG-03" | "L-LIFE-03"
        ) || evidence.key.family == "L-ID-01" && evidence.key.scenario == "generated-descendants"
            || evidence.key.family == "L-MIX-04" && evidence.key.scenario == "cooperation"
        {
            let stages = held["held_stages"]
                .as_array()
                .ok_or("live child-held phase observations absent")?;
            let required: &[&str] = if evidence.key.family == "L-MIX-04" {
                &["same-attempt-cooperation-held"]
            } else {
                &[
                    "descendant-competing-bind-held",
                    "joint-descendant-tree-held",
                    "offline-compiler-held",
                    "joint-generated-child-held",
                ]
            };
            for operation in required {
                let found = stages
                    .iter()
                    .filter(|stage| stage["operation"] == *operation)
                    .collect::<Vec<_>>();
                if found.len() != 1 {
                    return Err(format!(
                        "actual held child phase {operation} missing or duplicated"
                    ));
                }
                let children = found[0]["children"]
                    .as_array()
                    .ok_or("actual held phase children absent")?;
                if children.is_empty() {
                    return Err(
                        "actual held child phase contains no independently held native child"
                            .into(),
                    );
                }
                for child in children {
                    credentials(&child["credentials"], native)?;
                    let snapshot = &child["snapshot"];
                    let identity = &child["identity"];
                    if identity["pid"] != snapshot["process_id"]
                        || identity["birth"] != snapshot["birth"]
                        || identity["parent_pid"].as_u64().is_none()
                        || identity["parent_birth"].as_u64().is_none()
                    {
                        return Err("actual native child parent/creation observation absent".into());
                    }
                    for (observed, expected) in [
                        ("mount", "mount_namespace"),
                        ("pid", "pid_namespace"),
                        ("network", "network_namespace"),
                        ("ipc", "ipc_namespace"),
                    ] {
                        if snapshot[observed] != native[expected] {
                            return Err("held child escaped original target namespaces".into());
                        }
                    }
                    if !retirement["held_processes"]
                        .as_array()
                        .is_some_and(|records| {
                            records.iter().any(|record| {
                                record["pid"] == snapshot["process_id"]
                                    && record["birth"] == snapshot["birth"]
                                    && record["pidfd_readable"] == true
                            })
                        })
                    {
                        return Err(
                            "original held child lacks actual native pidfd retirement".into()
                        );
                    }
                }
            }
        }
        for process in held["processes"]
            .as_array()
            .ok_or("original held processes absent")?
        {
            let snapshot = &process["snapshot"];
            if process["role"] == "target" {
                credentials(&process["credentials"], native)?;
            }
            if !retirement["held_processes"]
                .as_array()
                .is_some_and(|records| {
                    records.iter().any(|record| {
                        record["pid"] == snapshot["process_id"]
                            && record["birth"] == snapshot["birth"]
                            && record["pidfd_readable"] == true
                    })
                })
            {
                return Err("native held process lacks actual original pidfd retirement".into());
            }
        }
    }
    Ok(())
}

fn verify_report_failure(
    evidence: &CaseEvidenceV2,
    input: &Value,
    source_commit: &str,
    resolver: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    if evidence.raw_result.is_some() || !evidence.outputs.is_empty() {
        return Err("failed report persistence invented an original result or outputs".into());
    }
    let document = |path: &str| crate::validate_json_document(&resolver(path)?);
    let request_bytes = resolver(
        evidence
            .request
            .as_deref()
            .ok_or("report failure original request absent")?,
    )?;
    let request = crate::validate_json_document(&request_bytes)?;
    let locator = document(
        evidence
            .attempt_observation
            .as_deref()
            .ok_or("report failure original locator absent")?,
    )?;
    let prepared_bytes = resolver(
        input["prepared"]
            .as_str()
            .ok_or("report failure original prepared absent")?,
    )?;
    let prepared = crate::validate_json_document(&prepared_bytes)?;
    let ack = document(
        input["prepared_ack"]
            .as_str()
            .ok_or("report failure original prepared ack absent")?,
    )?;
    let terminal = document(
        evidence
            .recovery
            .as_deref()
            .ok_or("report failure actual recovery carrier absent")?,
    )?;
    let controller = document(&evidence.native_observation)?;
    let native = &terminal["native"];
    let proof = &controller["report_directory"];
    if prepared["format"] != "memcordon.linux-workload-prepared"
        || prepared["revision"] != 1
        || prepared["association"] != locator
        || terminal["association"] != locator
        || terminal["format"] != "memcordon.linux-workload-terminal"
        || terminal["revision"] != 1
        || terminal["request"] != prepared["request"]
        || terminal["request"]["request_sha256"] != request_digest(&request_bytes)?
        || locator["provider"]["source_commit"] != source_commit
        || ack["format"] != "memcordon.workload-prepared-ack"
        || ack["revision"] != 1
        || ack["association"] != locator
        || ack["prepared_sha256"] != hex::encode(Sha256::digest(&prepared_bytes))
        || terminal["release"] != "released"
        || terminal["outcome"]["kind"] != "exited"
        || terminal["outcome"]["code"] != 0
        || native["native_wait_status"] != 0
        || proof["uid"] != native["caller_uid"]
        || proof["before_mode"] != 0o40700
        || proof["blocked_mode"] != 0o40500
        || proof["restored_mode"] != 0o40700
        || proof["same_native_inode"] != true
        || number(&proof["inode"])? == 0
        || proof["result_absent"] != true
        || proof["frontend_wait"]["frontend"] != native["caller"]
        || proof["frontend_wait"]["status"] != 125
        || proof["frontend_wait"]["raw_wait_status"] != 32000
        || proof["recovery_wait"]["status"] != 0
        || proof["recovery_wait"]["raw_wait_status"] != 0
    {
        return Err("actual original report failure/native recovery association differs".into());
    }
    super::linux_wire::verify_start(
        &resolver(
            input["start"]
                .as_str()
                .ok_or("report failure exact Start absent")?,
        )?,
        &request,
        &terminal["request"],
        input,
    )?;
    super::linux_component_lifecycle::recovery_native(&terminal, &prepared["native"])?;
    super::linux_component_lifecycle::cleanup(&terminal["cleanup"])?;
    let fixture = resolver(&evidence.fixture)?;
    if hex::encode(Sha256::digest(&fixture)) != evidence.fixture_sha256
        || native["entrypoint_sha256"] != evidence.fixture_sha256
    {
        return Err("report failure target image is not original selected fixture".into());
    }
    let challenge = input["challenge"]
        .as_str()
        .ok_or("report failure original challenge absent")?;
    let rows = transcript(&resolver(&evidence.stdout)?, challenge, native)?;
    if operation(&rows, "native-argv-observed")?["native_exit_status"] != 0
        || bytes(&operation(&rows, "byte-vector")?["bytes"])? != bytes(&input["binary"])?
        || !resolver(&evidence.stderr)?
            .windows(b"Permission denied".len())
            .any(|window| window == b"Permission denied")
    {
        return Err(
            "report failure lost original target byte effects or actual delivery cause".into(),
        );
    }
    let retired = document(&evidence.retirement)?;
    for identity in [
        &native["caller"],
        &native["target"],
        &native["namespace_init"],
        &native["guardian"],
    ] {
        if !retired["held_processes"]
            .as_array()
            .is_some_and(|processes| {
                processes.iter().any(|process| {
                    process["pid"] == identity["pid"]
                        && process["birth"] == identity["birth"]
                        && process["pidfd_readable"] == true
                })
            })
        {
            return Err("report failure has no actual original native owner retirement".into());
        }
    }
    Ok(())
}

pub fn verify_lifecycle(
    product: &ProductObservationV2,
    resolver: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    super::validate_native_inventory(&product.key.target, &product.lifecycle.native)?;
    let mut checked = BTreeSet::new();
    for resource in &product.lifecycle.native {
        if !checked.insert(&resource.evidence) {
            continue;
        }
        let observed = crate::validate_json_document(&resolver(&resource.evidence)?)?;
        if observed["format"] != "memcordon.linux-installed-absence"
            || observed["revision"] != 1
            || observed["lease_id"] != product.lifecycle.lease_id
        {
            return Err("Linux native finalization observation has another original lease".into());
        }
        let paths = observed["paths"]
            .as_array()
            .ok_or("Linux native path census absent")?;
        let images = observed["package_images"]
            .as_array()
            .ok_or("actual installed image absence observations absent")?;
        let mut expected_images = vec!["/usr/libexec/memcordon-runtime-manifest.json"];
        for component in &product.components {
            expected_images.push(match component.role.as_str() {
                "public-cli" => "/usr/libexec/memcordon",
                "sealed-agent" => "/usr/libexec/memcordon-sealed-agent",
                _ => return Err("unknown Linux installed component role".into()),
            });
        }
        if images.len() != expected_images.len() {
            return Err("installed image absence inventory differs".into());
        }
        for path in expected_images {
            if images
                .iter()
                .filter(|image| image["path"] == path && image["absent"] == true)
                .count()
                != 1
            {
                return Err("actual selected installed image or runtime manifest remains".into());
            }
        }
        for required in [
            "/sys/fs/cgroup/memcordon-sealed",
            "/run/memcordon",
            "/var/lib/memcordon/workload-attempts",
            "/var/lib/memcordon/workload-inputs",
            "/var/lib/memcordon/workload-resources",
        ] {
            let matches = paths
                .iter()
                .filter(|entry| entry["path"] == required)
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                return Err("Linux native census omits/duplicates a required original root".into());
            }
            let path = matches[0];
            if path["absent"] != true
                && (path["kind"] != "directory"
                    || number(&path["inode"])? == 0
                    || path["children"]
                        .as_array()
                        .is_none_or(|children| !children.is_empty()))
            {
                return Err("Linux native cleanup root remains allocated or unknown".into());
            }
        }
        let processes = observed["processes"]
            .as_array()
            .ok_or("Linux original held process settlement absent")?;
        let mut identities = BTreeSet::new();
        for process in processes {
            if number(&process["pid"])? == 0
                || process["pidfd_readable"] != true
                || !identities.insert((number(&process["pid"])?, number(&process["birth"])?))
            {
                return Err("Linux native process retirement is duplicated or unresolved".into());
            }
        }
        let units = observed["units"]
            .as_array()
            .ok_or("Linux native unit retirement absent")?;
        for name in [
            "memcordon-sealed-agent.service",
            "memcordon-sealed-agent.socket",
            "memcordon-sealed-launcher.service",
            "memcordon-sealed-launcher.socket",
            "memcordon-sealed-network-launcher.service",
            "memcordon-sealed-network-launcher.socket",
        ] {
            let entries = units
                .iter()
                .filter(|unit| unit["unit"] == name)
                .collect::<Vec<_>>();
            if entries.len() != 1
                || entries[0]["load_state"] != "not-found"
                || entries[0]["active_state"] != "inactive"
            {
                return Err("actual selected provider service/socket remains or is unknown".into());
            }
        }
    }
    Ok(())
}
