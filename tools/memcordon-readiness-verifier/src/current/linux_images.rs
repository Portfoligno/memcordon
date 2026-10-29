//! Independent initial ELF, mapped object and fresh snapshot custody joins.
use super::{CaseEvidenceV2, ProductObservationV2};
use crate::{ComponentBuild, VerificationResult};
use serde_json::Value;
use std::collections::BTreeSet;
fn bytes(value: &Value) -> VerificationResult<Vec<u8>> {
    serde_json::from_value(value.clone()).map_err(|error| error.to_string())
}
fn integer(value: &Value) -> VerificationResult<u64> {
    value
        .as_u64()
        .ok_or_else(|| "current image native integer absent".into())
}
pub struct Elf {
    pub interpreter: Option<String>,
    pub needed: Vec<String>,
    pub paths: Vec<String>,
    pub dynamic: Option<(usize, usize)>,
    pub needed_offsets: Vec<u64>,
}
pub fn inspect_elf(bytes: &[u8], target: &str) -> VerificationResult<Elf> {
    let take = |offset: usize, count: usize| {
        bytes
            .get(offset..offset.checked_add(count).ok_or("ELF extent overflow")?)
            .ok_or("ELF extent invalid")
    };
    let word = |offset: usize| -> VerificationResult<u16> {
        Ok(u16::from_le_bytes(
            take(offset, 2)?.try_into().map_err(|_| "ELF word absent")?,
        ))
    };
    let scalar = |offset: usize| -> VerificationResult<u64> {
        Ok(u64::from_le_bytes(
            take(offset, 8)?
                .try_into()
                .map_err(|_| "ELF scalar absent")?,
        ))
    };
    if take(0, 6)? != b"\x7fELF\x02\x01"
        || word(54)? != 56
        || word(18)?
            != if target.starts_with("aarch64-") {
                183
            } else if target.starts_with("x86_64-") {
                62
            } else {
                return Err("unsupported current ELF target".into());
            }
    {
        return Err("selected current ELF class/ABI differs".into());
    }
    let count = usize::from(word(56)?);
    let offset = usize::try_from(scalar(32)?).map_err(|_| "ELF header offset overflow")?;
    if count == 0 || count > 512 {
        return Err("ELF program header inventory invalid".into());
    }
    let mut result = Elf {
        interpreter: None,
        needed: Vec::new(),
        paths: Vec::new(),
        dynamic: None,
        needed_offsets: Vec::new(),
    };
    let mut loads = Vec::new();
    for index in 0..count {
        let at = offset
            .checked_add(index * 56)
            .ok_or("ELF program header overflow")?;
        let kind = u32::from_le_bytes(take(at, 4)?.try_into().map_err(|_| "ELF kind absent")?);
        let file = usize::try_from(scalar(at + 8)?).map_err(|_| "ELF offset overflow")?;
        let length = usize::try_from(scalar(at + 32)?).map_err(|_| "ELF length overflow")?;
        take(file, length)?;
        match kind {
            1 => loads.push((scalar(at + 16)?, file, length)),
            2 => {
                if result.dynamic.replace((file, length)).is_some()
                    || length > 1024 * 1024
                    || length % 16 != 0
                {
                    return Err("ELF dynamic table ambiguous/bounded".into());
                }
            }
            3 => {
                let text = take(file, length)?;
                if text.len() < 2
                    || text.len() > 4096
                    || text.last() != Some(&0)
                    || text[..text.len() - 1].contains(&0)
                {
                    return Err("ELF interpreter malformed".into());
                }
                let text = std::str::from_utf8(&text[..text.len() - 1])
                    .map_err(|_| "ELF interpreter not UTF-8")?;
                if !text.starts_with('/') || result.interpreter.replace(text.into()).is_some() {
                    return Err("ELF interpreter relative/duplicated".into());
                }
            }
            _ => {}
        }
    }
    let Some((dynamic, length)) = result.dynamic else {
        return Ok(result);
    };
    let mut strings = None;
    let mut size = None;
    let mut paths = Vec::new();
    let mut terminated = false;
    for at in (dynamic..dynamic + length).step_by(16) {
        let kind = scalar(at)?;
        let value = scalar(at + 8)?;
        match kind {
            0 => {
                terminated = true;
                break;
            }
            1 => result.needed_offsets.push(value),
            5 => {
                if strings.replace(value).is_some() {
                    return Err("ELF string table duplicated".into());
                }
            }
            10 => {
                if size.replace(value).is_some() {
                    return Err("ELF string span duplicated".into());
                }
            }
            15 | 29 => paths.push(value),
            _ => {}
        }
    }
    if !terminated || result.needed_offsets.len() > 128 || paths.len() > 32 {
        return Err("ELF dynamic inventory unterminated/excessive".into());
    }
    if result.needed_offsets.is_empty() && paths.is_empty() {
        return Ok(result);
    }
    let strings = strings.ok_or("ELF dynamic strings absent")?;
    let size = usize::try_from(size.ok_or("ELF dynamic string span absent")?)
        .map_err(|_| "ELF string span overflow")?;
    let candidates: Vec<_> = loads
        .iter()
        .filter_map(|(address, file, length)| {
            strings
                .checked_sub(*address)
                .and_then(|relative| usize::try_from(relative).ok())
                .filter(|relative| relative.checked_add(size).is_some_and(|end| end <= *length))
                .and_then(|relative| file.checked_add(relative))
        })
        .collect();
    if candidates.len() != 1 {
        return Err("ELF string address has no unique file range".into());
    }
    let table = take(candidates[0], size)?;
    let string = |offset: u64| -> VerificationResult<String> {
        let at = usize::try_from(offset).map_err(|_| "ELF string index overflow")?;
        let remaining = table.get(at..).ok_or("ELF string outside table")?;
        let end = remaining
            .iter()
            .position(|byte| *byte == 0)
            .ok_or("ELF string not terminated")?;
        if end == 0 || end > 4096 {
            return Err("ELF string empty/excessive".into());
        }
        Ok(std::str::from_utf8(&remaining[..end])
            .map_err(|_| "ELF dynamic string not UTF-8")?
            .into())
    };
    result.needed = result
        .needed_offsets
        .iter()
        .map(|offset| string(*offset))
        .collect::<VerificationResult<_>>()?;
    result.paths = paths
        .into_iter()
        .map(string)
        .collect::<VerificationResult<_>>()?;
    Ok(result)
}
fn regular<'a>(snapshot: &'a Value, path: &str) -> VerificationResult<&'a Value> {
    let mut path = path.to_owned();
    let mut seen = BTreeSet::new();
    let entries = snapshot["entries"]
        .as_array()
        .ok_or("image snapshot entries absent")?;
    for _ in 0..64 {
        if !seen.insert(path.clone()) {
            return Err("image snapshot link cycle".into());
        }
        let found: Vec<_> = entries
            .iter()
            .filter(|entry| entry["path"] == path)
            .collect();
        if found.len() != 1 {
            return Err("image snapshot member missing/ambiguous".into());
        }
        match found[0]["kind"].as_str() {
            Some("regular") => return Ok(found[0]),
            Some("symlink") => {
                path = found[0]["target"]
                    .as_str()
                    .ok_or("image alias target absent")?
                    .into()
            }
            _ => return Err("unknown current image member".into()),
        }
    }
    Err("image link inventory excessive".into())
}
pub fn verify_relative_runpath_probe(
    original: &[u8],
    probe: &[u8],
    at: usize,
    target: &str,
) -> VerificationResult<String> {
    inspect_elf(original, target)?;
    let elf = inspect_elf(probe, target)?;
    let end = at.checked_add(16).ok_or("loader patch overflow")?;
    let dynamic = elf.dynamic.ok_or("loader probe has no dynamic table")?;
    if original.len() != probe.len()
        || at < dynamic.0
        || end > dynamic.0 + dynamic.1
        || (at - dynamic.0) % 16 != 0
        || original.get(..at) != probe.get(..at)
        || original.get(end..) != probe.get(end..)
        || original.get(at..end) != Some([0_u8; 16].as_slice())
        || probe.get(at..at + 8) != Some(29_u64.to_le_bytes().as_slice())
        || elf.paths.len() != 1
        || elf.paths[0].starts_with('/')
        || !elf.needed.contains(&elf.paths[0])
    {
        return Err("loader negative is not a single relative RUNPATH mutation".into());
    }
    Ok(elf.paths[0].clone())
}
fn mapped(maps: &[u8], node: &Value) -> VerificationResult<()> {
    let device = integer(&node["device"])?;
    let inode = integer(&node["inode"])?;
    let major = ((device & 0x00000000000fff00) >> 8) | ((device & 0xfffff00000000000) >> 32);
    let minor = (device & 0xff) | ((device & 0x00000ffffff00000) >> 12);
    let text = std::str::from_utf8(maps).map_err(|_| "native maps not UTF-8")?;
    let mut executable = false;
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 5 {
            return Err("native maps row truncated".into());
        }
        let Some((a, b)) = fields[3].split_once(':') else {
            return Err("native map device malformed".into());
        };
        if u64::from_str_radix(a, 16).ok() == Some(major)
            && u64::from_str_radix(b, 16).ok() == Some(minor)
            && fields[4].parse::<u64>().ok() == Some(inode)
        {
            let flags = fields[1].as_bytes();
            if flags.len() != 4 || flags[1] == b'w' && flags[3] == b's' {
                return Err("image has a writable shared mapping".into());
            }
            if flags[2] == b'x' {
                if flags[1] == b'w' {
                    return Err("initial code mapping is writable".into());
                }
                executable = true;
            }
        }
    }
    if !executable {
        return Err("selected immutable code object is not actually mapped executable".into());
    }
    Ok(())
}
pub fn verify_observed_case(
    evidence: &CaseEvidenceV2,
    input: &Value,
    source_commit: &str,
    resolver: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    if evidence.key.family == "L-IMG-02" {
        return verify_negative(evidence, input, source_commit, resolver);
    }
    if evidence.key.family != "L-IMG-01"
        || ![
            "first-image",
            "interpreter",
            "shared-library",
            "snapshot-writable-alias",
        ]
        .contains(&evidence.key.scenario.as_str())
    {
        return Err("current image scenario has no authored native oracle".into());
    }
    let semantic = crate::validate_json_document(&resolver(&evidence.semantic_observation)?)?;
    let extra = &semantic["extra"];
    let runtime_bytes = bytes(&extra["runtime_canonical"])?;
    let runtime = crate::validate_json_document(&runtime_bytes)?;
    let request = crate::validate_json_document(&resolver(
        evidence
            .request
            .as_deref()
            .ok_or("current image request absent")?,
    )?)?;
    let elf = inspect_elf(&resolver(&evidence.fixture)?, &evidence.key.target)?;
    let path = extra["path"]
        .as_str()
        .ok_or("current image selected path absent")?;
    let expected = match evidence.key.scenario.as_str() {
        "first-image" | "snapshot-writable-alias" => "bin/owned-readiness".to_owned(),
        "interpreter" => regular(
            &runtime,
            elf.interpreter
                .as_deref()
                .ok_or("selected ELF interpreter absent")?
                .strip_prefix('/')
                .ok_or("ELF interpreter not absolute")?,
        )?["path"]
            .as_str()
            .ok_or("interpreter regular path absent")?
            .into(),
        "shared-library" => {
            let name = elf
                .needed
                .first()
                .ok_or("selected ELF dynamic library absent")?;
            let mut selected = None;
            for directory in runtime["library_directories"]
                .as_array()
                .ok_or("snapshot library search absent")?
            {
                let candidate = format!(
                    "{}/{name}",
                    directory
                        .as_str()
                        .ok_or("snapshot library directory malformed")?
                );
                if let Ok(entry) = regular(&runtime, &candidate) {
                    selected = Some(
                        entry["path"]
                            .as_str()
                            .ok_or("library regular path absent")?
                            .to_owned(),
                    );
                    break;
                }
            }
            selected.ok_or("first ELF dependency has no selected immutable object")?
        }
        _ => unreachable!(),
    };
    if path != expected
        || extra["format"] != "memcordon.linux-current-image-custody"
        || extra["revision"] != 1
        || extra["scenario"] != evidence.key.scenario
        || runtime["format"] != "memcordon.workload-snapshot"
        || runtime["revision"] != 1
        || runtime["target"] != evidence.key.target
        || crate::sha256(&runtime_bytes) != request["runtime"]["inputs"]["runtime_digest"]
    {
        return Err("current image object is not original selected ELF/snapshot dependency".into());
    }
    super::linux::verify_execution(
        evidence,
        input,
        source_commit,
        resolver,
        &|rows, result, native| {
            let node = &extra["protected"];
            let source = &extra["source"];
            let entry = regular(&runtime, path)?;
            let observed = super::linux::operation(rows, "image-custody-ready")?;
            if extra["root"]["device"] != native["root_device"]
                || extra["root"]["inode"] != native["root_inode"]
                || node["uid"] != 0
                || node["links"] != 1
                || integer(&node["inode"])? == 0
                || integer(&node["mode"])? & 0o222 != 0
                || node["sha256"] != entry["sha256"]
                || node["length"] != entry["size"]
                || node != &extra["protected_after"]
                || source["uid"] != native["caller_uid"]
                || integer(&source["mode"])? & 0o200 == 0
                || source["sha256"] != node["sha256"]
                || (source["device"] == node["device"] && source["inode"] == node["inode"])
                || extra["executable"]["sha256"] != evidence.fixture_sha256
                || native["entrypoint_sha256"] != evidence.fixture_sha256
                || observed["scenario"] != evidence.key.scenario
                || observed["path"] != format!("/{path}")
                || observed["device"] != node["device"]
                || observed["inode"] != node["inode"]
                || observed["sha256"] != node["sha256"]
                || ![1, 13, 26, 30]
                    .iter()
                    .any(|code| observed["write_errno"] == *code)
                || bytes(&observed["private_positive"])?
                    != input["challenge"]
                        .as_str()
                        .ok_or("image challenge absent")?
                        .as_bytes()
                || result["outcome"]["kind"] != "completed"
                || result["outcome"]["wrapper_status"] != 0
                || native["native_wait_status"] != 0
            {
                return Err("actual fresh immutable image/source alias/byte effects differ".into());
            }
            mapped(&bytes(&extra["maps"])?, node)?;
            mapped(&bytes(&observed["maps"])?, node)?;
            super::linux::operation(rows, "image-custody-complete")?;
            if evidence.key.scenario == "snapshot-writable-alias" {
                let alias = &extra["alias"];
                let original = resolver(&evidence.fixture)?;
                let mut changed = original.clone();
                *changed.first_mut().ok_or("empty alias source fixture")? ^= 0xff;
                for (role, operation, before, after, byte) in [
                    ("mutation", "hold-write", &original, &changed, changed[0]),
                    ("restoration", "write", &changed, &original, original[0]),
                ] {
                    let path = alias[format!("{role}_receipt")]
                        .as_str()
                        .ok_or("caller alias receipt absent")?;
                    let helper = crate::validate_json_document(&resolver(path)?)?;
                    let prefix = path
                        .strip_suffix("probe-receipt.json")
                        .ok_or("caller alias receipt role invalid")?;
                    let wait = crate::validate_json_document(&resolver(&format!(
                        "{prefix}probe-wait.json"
                    ))?)?;
                    let request = crate::validate_json_document(&resolver(&format!(
                        "{prefix}probe-input.json"
                    ))?)?;
                    super::linux::closed(
                        &helper,
                        &[
                            "format", "revision", "request", "uid", "gid", "pid", "birth",
                            "opened", "changed", "named", "restored",
                        ],
                    )?;
                    super::linux::closed(
                        &request,
                        &[
                            "format",
                            "revision",
                            "operation",
                            "path",
                            "device",
                            "inode",
                            "offset",
                            "bytes",
                            "replacement",
                            "backup",
                        ],
                    )?;
                    super::linux::closed(
                        &wait,
                        &[
                            "pid",
                            "birth",
                            "held_before_input",
                            "retired",
                            "raw_wait_status",
                        ],
                    )?;
                    if helper["format"] != "memcordon.current-snapshot-probe-receipt"
                        || helper["revision"] != 1
                        || helper["uid"] != native["caller_uid"]
                        || helper["gid"] != source["gid"]
                        || helper["uid"].as_u64().is_none_or(|uid| uid == 0)
                        || helper["pid"].as_u64().is_none_or(|pid| pid == 0)
                        || helper["birth"].as_u64().is_none()
                        || helper["request"] != request
                        || request["format"] != "memcordon.current-snapshot-probe"
                        || request["revision"] != 1
                        || !request["replacement"].is_null()
                        || !request["backup"].is_null()
                        || request["operation"] != operation
                        || request["offset"] != 0
                        || bytes(&request["bytes"])? != [byte]
                        || request["device"] != source["device"]
                        || request["inode"] != source["inode"]
                        || wait["pid"] != helper["pid"]
                        || wait["birth"] != helper["birth"]
                        || wait["held_before_input"] != true
                        || wait["retired"] != true
                        || wait["raw_wait_status"] != 0
                    {
                        return Err("alias effect lacks original ordinary caller request and Child settlement".into());
                    }
                    for field in ["opened", "changed", "named"] {
                        let file = &helper[field];
                        super::linux::closed(
                            file,
                            &[
                                "device", "inode", "uid", "gid", "mode", "links", "length",
                                "sha256", "flags",
                            ],
                        )?;
                        if ["device", "inode", "uid", "gid", "mode", "links", "length"]
                            .iter()
                            .any(|key| file[*key] != source[*key])
                            || file["flags"].as_u64().is_none_or(|flags| {
                                flags & 3 != if field == "named" { 0 } else { 2 }
                            })
                            || file["sha256"]
                                != crate::sha256(if field == "opened" { before } else { after })
                        {
                            return Err(
                                "ordinary caller alias file identity or exact byte effect differs"
                                    .into(),
                            );
                        }
                    }
                    if role == "mutation" && alias["changed"] != helper["changed"] {
                        return Err(
                            "alias changed observation not bound to actual caller receipt".into(),
                        );
                    }
                }
                if alias["changed"]["device"] != source["device"]
                    || alias["changed"]["inode"] != source["inode"]
                    || alias["changed"]["sha256"] == source["sha256"]
                    || alias["protected_during_change"] != *node
                    || alias["restored"]["sha256"] != source["sha256"]
                    || alias["restored"]["device"] != source["device"]
                    || alias["restored"]["inode"] != source["inode"]
                {
                    return Err("writable caller source alias changed held protected snapshot or lost restoration".into());
                }
            }
            Ok(())
        },
    )
}
fn verify_negative(
    evidence: &CaseEvidenceV2,
    input: &Value,
    source_commit: &str,
    resolver: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    let scenario = evidence.key.scenario.as_str();
    if !["ld-injection", "rpath-injection", "loader-config"].contains(&scenario) {
        return Err("unknown current loader negative".into());
    }
    let proof = crate::validate_json_document(&resolver(&evidence.semantic_observation)?)?;
    if evidence.request.as_deref() != proof["request"].as_str()
        || evidence.invocation
            != proof["start"]
                .as_str()
                .ok_or("original loader start reference absent")?
    {
        return Err("loader capture references another original request/invocation".into());
    }
    let read = |field: &str| -> VerificationResult<Vec<u8>> {
        resolver(
            proof[field]
                .as_str()
                .ok_or_else(|| format!("loader evidence {field} absent"))?,
        )
    };
    let request = crate::validate_json_document(&read("request")?)?;
    let runtime_bytes = read("runtime_snapshot")?;
    let runtime = crate::validate_json_document(&runtime_bytes)?;
    let input_bytes = read("input_snapshot")?;
    let snapshot = crate::validate_json_document(&input_bytes)?;
    let result = crate::validate_json_document(&resolver(
        evidence
            .raw_result
            .as_deref()
            .ok_or("loader result absent")?,
    )?)?;
    super::linux::closed(
        &result,
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
    super::linux::closed(
        &result["request"],
        &[
            "request_sha256",
            "invocation_sha256",
            "resource_policy_sha256",
            "runtime_sha256",
            "input_sha256",
        ],
    )?;
    super::linux::closed(&result["runtime"], &["kind", "profile"])?;
    super::linux::closed(
        &result["outcome"],
        &["kind", "native_termination", "wrapper_status"],
    )?;
    super::linux::closed(&result["cleanup"], &["state", "obligations"])?;
    let frontend = crate::validate_json_document(&read("frontend")?)?;
    if proof["format"] != "memcordon.current-linux-image-negative"
        || proof["revision"] != 1
        || proof["scenario"] != scenario
        || proof["lease_id"] != evidence.lease_id.as_deref().ok_or("loader lease absent")?
        || input["format"] != "memcordon.current-linux-image-negative-input"
        || input["revision"] != 1
        || input["key"] != serde_json::to_value(&evidence.key).map_err(|error| error.to_string())?
        || input["run_id"] != evidence.run_id
        || evidence.source_commit != source_commit
        || proof["provider"]["source_commit"] != source_commit
        || proof["before"] != proof["after"]
        || crate::sha256(&runtime_bytes) != request["runtime"]["inputs"]["runtime_digest"]
        || crate::sha256(&input_bytes) != request["runtime"]["inputs"]["input_digest"]
        || result["format"] != "memcordon.result"
        || result["revision"] != 3
        || result["release"] != "not-released"
        || result["runtime"]["kind"] != "preparation-failed"
        || result["outcome"]["kind"] != "launch-failure"
        || result["delivery"] != "complete"
        || result["outcome"]["wrapper_status"] != 125
        || !result["outcome"]["native_termination"].is_null()
        || proof["wait"]["status"] != 125
        || proof["wait"]["raw_wait_status"] != 125 * 256
        || !resolver(&evidence.stdout)?.is_empty()
        || frontend["format"] != "memcordon.current-original-frontend"
        || frontend["revision"] != 1
        || frontend["process"] != proof["wait"]["process"]
        || frontend["process"]["pid"]
            .as_u64()
            .is_none_or(|value| value == 0)
        || frontend["process"]["birth"].as_u64().is_none()
        || frontend["provider"] != proof["provider"]
        || frontend["request_sha256"] != result["request"]["request_sha256"]
        || frontend["caller_uid"]
            .as_u64()
            .is_none_or(|value| value == 0)
    {
        return Err("loader negative changed original request/source/native outcome".into());
    }
    super::linux_wire::verify_start(&read("start")?, &request, &result["request"], input)?;
    let original = resolver(&evidence.fixture)?;
    if crate::sha256(&original) != evidence.fixture_sha256 {
        return Err("loader original ELF differs from selected source fixture".into());
    }
    let _ = inspect_elf(&original, &evidence.key.target)?;
    match scenario {
        "rpath-injection" => {
            let probe = read("probe")?;
            let at = usize::try_from(integer(&proof["mutation"]["offset"])?)
                .map_err(|_| "loader patch offset overflow")?;
            if verify_relative_runpath_probe(&original, &probe, at, &evidence.key.target)?
                != proof["mutation"]["search"]
                || regular(&runtime, "bin/owned-readiness")?["sha256"] != crate::sha256(&probe)
            {
                return Err(
                    "loader negative is not the retained single relative RUNPATH mutation".into(),
                );
            }
        }
        "loader-config" => {
            let config = bytes(&proof["mutation"]["bytes"])?;
            if proof["mutation"]["path"] != "etc/ld.so.preload"
                || config != b"/work/caller-loader-injection.so\n"
                || regular(&snapshot, "etc/ld.so.preload")?["sha256"] != crate::sha256(&config)
                || regular(&snapshot, "etc/ld.so.preload")?["size"] != config.len()
            {
                return Err(
                    "loader configuration negative does not contain actual preload input".into(),
                );
            }
        }
        "ld-injection" => {
            if input["loader_path"].is_null()
                || result["request_rejection"]["code"] != "unsupported-requirement"
                || !result["request_rejection"]["detail"]
                    .as_str()
                    .is_some_and(|text| text.contains("initial loader environment"))
                || !result["workload_attempt"].is_null()
                || evidence.attempt_observation.is_some()
                || evidence.recovery.is_some()
            {
                return Err(
                    "loader environment rejection invented allocation/locator or lost native cause"
                        .into(),
                );
            }
            let start = crate::validate_json_document(&read("start")?)?;
            let native = bytes(&start["native_launch"])?;
            let mut remaining = native.as_slice();
            fn take<'a>(raw: &mut &'a [u8], count: usize) -> VerificationResult<&'a [u8]> {
                let (head, tail) = raw
                    .split_at_checked(count)
                    .ok_or("truncated loader invocation")?;
                *raw = tail;
                Ok(head)
            }
            fn word(raw: &mut &[u8]) -> VerificationResult<usize> {
                Ok(u32::from_be_bytes(
                    take(raw, 4)?
                        .try_into()
                        .map_err(|_| "loader invocation word")?,
                ) as usize)
            }
            fn value<'a>(raw: &mut &'a [u8]) -> VerificationResult<&'a [u8]> {
                let count = word(raw)?;
                if count > 65536 {
                    return Err("loader invocation value exceeds bound".into());
                }
                take(raw, count)
            }
            take(&mut remaining, 10)?;
            value(&mut remaining)?;
            let arguments = word(&mut remaining)?;
            if arguments > 4096 {
                return Err("loader argv exceeds bound".into());
            }
            for _ in 0..arguments {
                value(&mut remaining)?;
            }
            let count = word(&mut remaining)?;
            if count > 8192 {
                return Err("loader environment exceeds bound".into());
            }
            let mut observed = None;
            for _ in 0..count {
                let name = value(&mut remaining)?;
                let data = value(&mut remaining)?;
                if name == b"LD_LIBRARY_PATH" && observed.replace(data).is_some() {
                    return Err("duplicate actual loader override".into());
                }
            }
            let expected = bytes(&input["loader_path"])?;
            if expected.is_empty() || observed != Some(expected.as_slice()) {
                return Err(
                    "original native invocation lacks the actual caller loader override".into(),
                );
            }
        }
        _ => unreachable!(),
    }
    if scenario != "ld-injection" {
        let association = crate::validate_json_document(&resolver(
            evidence
                .attempt_observation
                .as_deref()
                .ok_or("rejected loader original locator absent")?,
        )?)?;
        super::linux::closed(
            &association,
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
        super::linux::closed(
            &association["provider"],
            &["generation", "source_commit", "runtime_manifest_sha256"],
        )?;
        super::linux::closed(&association["control"], &["pid", "birth"])?;
        let recovery = crate::validate_json_document(&resolver(
            evidence
                .recovery
                .as_deref()
                .ok_or("rejected loader cleanup carrier absent")?,
        )?)?;
        let journal = crate::validate_json_document(&read("journal")?)?;
        let ack = crate::validate_json_document(&read("ack")?)?;
        super::linux::closed(
            &recovery,
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
        super::linux::closed(
            &ack,
            &["format", "revision", "association", "record_retired"],
        )?;
        super::linux::closed(
            &journal,
            &[
                "format",
                "revision",
                "attempt_id",
                "boot_id",
                "phase",
                "release",
                "cleanup_cutoff_nanos",
                "cleanup_boot_id",
                "request_sha256",
                "association",
                "request",
                "native",
                "outcome",
                "terminal",
                "caller_uid",
                "frontend",
                "worker",
                "control",
                "intents",
                "guardian",
                "namespace_init",
                "target",
                "cgroup",
                "staging",
                "input_staging",
                "root",
                "network_namespace_inode",
                "output_files",
                "outstanding",
                "errors",
            ],
        )?;
        if result["workload_attempt"] != association
            || association["provider"] != proof["provider"]
            || result["provider"] != proof["provider"]
            || recovery["format"] != "memcordon.linux-workload-terminal"
            || recovery["revision"] != 1
            || recovery["association"] != association
            || recovery["request"] != result["request"]
            || recovery["release"] != "not-released"
            || !recovery["native"].is_null()
            || recovery["outcome"]["kind"] != "setup-failure"
            || journal["association"] != association
            || journal["format"] != "memcordon.private-workload-journal"
            || journal["revision"] != 1
            || journal["request"] != result["request"]
            || !journal["native"].is_null()
            || journal["intents"]["target"] != false
            || journal["intents"]["namespace_init"] != false
            || ack["format"] != "memcordon.workload-acknowledgment"
            || ack["revision"] != 1
            || ack["association"] != association
            || ack["record_retired"] != true
            || proof["recovery_wait"]["status"] != 0
            || proof["recovery_wait"]["raw_wait_status"] != 0
        {
            return Err(
                "rejected loader retained execution or lost exact cleanup/ACK association".into(),
            );
        }
        let expected = if scenario == "rpath-injection" {
            "ELF loader search contains unsupported or relative authority"
        } else {
            "ELF loader configuration is outside the declared immutable library catalogue"
        };
        if !recovery["failures"].as_array().is_some_and(|failures| {
            failures
                .iter()
                .any(|failure| failure.as_str().is_some_and(|text| text.contains(expected)))
        }) {
            return Err("loader refusal lost the actual initial-loader native cause".into());
        }
        super::linux_component_lifecycle::cleanup(&recovery["cleanup"])?;
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
    let product = product.ok_or("current image installed product absent")?;
    if build.is_some()
        || product.key.target != evidence.key.target
        || Some(&product.key.channel) != evidence.key.channel.as_ref()
        || product.source_commit != evidence.source_commit
        || product.source_tree_sha256 != evidence.source_tree_sha256
        || product.version != version
        || evidence.lease_id.as_deref() != Some(product.lifecycle.lease_id.as_str())
    {
        return Err(
            "current image experiment belongs to another selected installed product".into(),
        );
    }
    {
        let provider = if evidence.key.family == "L-IMG-02" {
            crate::validate_json_document(&resolver(&evidence.semantic_observation)?)?["provider"]
                .clone()
        } else {
            crate::validate_json_document(&resolver(
                evidence
                    .raw_result
                    .as_deref()
                    .ok_or("current image result absent")?,
            )?)?["provider"]
                .clone()
        };
        if provider["runtime_manifest_sha256"]
            != crate::sha256(&resolver(&product.runtime_manifest)?)
            || provider["generation"] != format!("{version}:{}", product.source_commit)
        {
            return Err("loader refusal belongs to another measured installed provider".into());
        }
    }
    verify_observed_case(evidence, input, &product.source_commit, resolver)
}
