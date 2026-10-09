//! Independent canonical policy bytes for retained Linux activation receipts.
use crate::VerificationResult;
use serde_json::Value;

fn fields(value: &Value, names: &[&str]) -> VerificationResult<()> {
    let object = value
        .as_object()
        .ok_or("Linux registry member is not an object")?;
    if object.len() != names.len() || names.iter().any(|name| !object.contains_key(*name)) {
        return Err("Linux registry member has unknown/missing fields".into());
    }
    Ok(())
}
fn count(bytes: &mut Vec<u8>, value: usize) -> VerificationResult<()> {
    bytes.extend(
        u16::try_from(value)
            .map_err(|_| "Linux canonical count exceeds bound")?
            .to_be_bytes(),
    );
    Ok(())
}
fn text(bytes: &mut Vec<u8>, value: &Value) -> VerificationResult<()> {
    let value = value
        .as_str()
        .filter(|value| !value.is_empty() && value.len() <= 65535 && !value.contains('\0'))
        .ok_or("Linux canonical text absent/unbounded")?;
    count(bytes, value.len())?;
    bytes.extend(value.as_bytes());
    Ok(())
}
fn digest(bytes: &mut Vec<u8>, value: &Value) -> VerificationResult<()> {
    let value = value.as_str().ok_or("Linux canonical digest absent")?;
    crate::digest(value)?;
    bytes.extend(hex::decode(value).map_err(|error| error.to_string())?);
    Ok(())
}
fn number(bytes: &mut Vec<u8>, value: &Value) -> VerificationResult<()> {
    bytes.extend(
        value
            .as_u64()
            .ok_or("Linux canonical integer absent")?
            .to_be_bytes(),
    );
    Ok(())
}
fn boolean(bytes: &mut Vec<u8>, value: &Value) -> VerificationResult<()> {
    bytes.push(u8::from(
        value.as_bool().ok_or("Linux canonical boolean absent")?,
    ));
    Ok(())
}
fn domain(name: &str) -> Vec<u8> {
    let mut bytes = name.as_bytes().to_vec();
    bytes.extend([0, 0, 1]);
    bytes
}
fn sorted<'a>(value: &'a Value, key: &str, bound: usize) -> VerificationResult<Vec<&'a Value>> {
    let mut values = value
        .as_array()
        .filter(|values| values.len() <= bound)
        .ok_or("Linux registry array exceeds bound")?
        .iter()
        .collect::<Vec<_>>();
    for item in &values {
        if item.pointer(key).and_then(Value::as_str).is_none() {
            return Err("Linux registry sort identity absent".into());
        }
    }
    values.sort_by(|a, b| {
        a.pointer(key)
            .and_then(Value::as_str)
            .cmp(&b.pointer(key).and_then(Value::as_str))
    });
    if values
        .windows(2)
        .any(|pair| pair[0].pointer(key) == pair[1].pointer(key))
    {
        return Err("Linux registry identity duplicated".into());
    }
    Ok(values)
}
fn scalar_sorted<'a>(value: &'a Value, bound: usize) -> VerificationResult<Vec<&'a Value>> {
    let mut values = value
        .as_array()
        .filter(|values| values.len() <= bound)
        .ok_or("Linux registry scalar array exceeds bound")?
        .iter()
        .collect::<Vec<_>>();
    if values
        .iter()
        .any(|value| !value.is_string() && !value.is_u64())
    {
        return Err("Linux registry scalar malformed".into());
    }
    values.sort_by(|a, b| {
        if a.is_string() {
            a.as_str().cmp(&b.as_str())
        } else {
            a.as_u64().cmp(&b.as_u64())
        }
    });
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("Linux registry scalar duplicated".into());
    }
    Ok(values)
}
fn reference(bytes: &mut Vec<u8>, value: &Value, digest_field: &str) -> VerificationResult<()> {
    fields(value, &["id", digest_field])?;
    text(bytes, &value["id"])?;
    digest(bytes, &value[digest_field])
}
fn disposition(bytes: &mut Vec<u8>, value: &Value) -> VerificationResult<()> {
    bytes.push(match value.as_str() {
        Some("drain-existing") => 1,
        Some("revoke-active") => 2,
        _ => return Err("Linux disposition unknown".into()),
    });
    Ok(())
}
fn ceiling(bytes: &mut Vec<u8>, value: &Value) -> VerificationResult<()> {
    let fields_and_tags: [(&str, &[&str]); 5] = [
        (
            "direct_socket_authority",
            &[
                "pinned-legacy-socket-filter-accepted",
                "no-new-inet-sockets",
                "attempt-private-ipv4-stack-all-ports",
                "external-host-policy-accepted",
            ],
        ),
        (
            "unix_authority",
            &[
                "no-named-endpoints-socket-pairs-only",
                "existing-host-unix-authority-accepted",
            ],
        ),
        (
            "external_socket_custody",
            &[
                "no-socket-at-target-entry",
                "existing-stdio-authority-accepted",
            ],
        ),
        (
            "credential_gains",
            &["no-gain", "existing-caller-envelope-accepted"],
        ),
        (
            "mediated_communication",
            &[
                "external-filesystem-and-stdio-policy-accepted",
                "require-no-external-communication",
            ],
        ),
    ];
    fields(
        value,
        &fields_and_tags
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>(),
    )?;
    for (name, tags) in fields_and_tags {
        bytes.push(
            tags.iter()
                .position(|tag| value[name].as_str() == Some(*tag))
                .ok_or("Linux ceiling unknown")? as u8
                + 1,
        );
    }
    Ok(())
}
pub(crate) fn legacy_digest(value: &Value) -> VerificationResult<String> {
    fields(
        value,
        &[
            "format",
            "revision",
            "profiles",
            "execution_identities",
            "grants",
            "active_attempt_disposition",
        ],
    )?;
    if value["format"] != "memcordon.local-private-policy" || value["revision"] != 1 {
        return Err("Linux legacy registry header differs".into());
    }
    let mut bytes = domain("memcordon.local-private-policy/revision1");
    let profiles = sorted(&value["profiles"], "/reference/id", 32)?;
    count(&mut bytes, profiles.len())?;
    for profile in profiles {
        fields(profile, &["profile", "reference", "enabled"])?;
        reference(&mut bytes, &profile["reference"], "semantic_digest")?;
        boolean(&mut bytes, &profile["enabled"])?;
    }
    let identities = sorted(&value["execution_identities"], "/reference/id", 32)?;
    count(&mut bytes, identities.len())?;
    for identity in identities {
        fields(
            identity,
            &[
                "reference",
                "enabled",
                "uid",
                "gid",
                "supplementary_groups",
                "entrypoints",
            ],
        )?;
        reference(&mut bytes, &identity["reference"], "semantic_digest")?;
        boolean(&mut bytes, &identity["enabled"])?;
        number(&mut bytes, &identity["uid"])?;
        number(&mut bytes, &identity["gid"])?;
        let groups = scalar_sorted(&identity["supplementary_groups"], 32)?;
        count(&mut bytes, groups.len())?;
        for group in groups {
            number(&mut bytes, group)?;
        }
        let entries = sorted(&identity["entrypoints"], "/id", 32)?;
        count(&mut bytes, entries.len())?;
        for entry in entries {
            fields(entry, &["id", "absolute_path", "sha256", "size"])?;
            text(&mut bytes, &entry["id"])?;
            text(&mut bytes, &entry["absolute_path"])?;
            number(&mut bytes, &entry["size"])?;
            digest(&mut bytes, &entry["sha256"])?;
        }
    }
    let grants = sorted(&value["grants"], "/id", 128)?;
    count(&mut bytes, grants.len())?;
    for grant in grants {
        fields(
            grant,
            &[
                "id",
                "revision",
                "profile",
                "ceiling",
                "enabled",
                "callers",
                "approved_plans",
                "execution_identity",
            ],
        )?;
        text(&mut bytes, &grant["id"])?;
        number(&mut bytes, &grant["revision"])?;
        reference(&mut bytes, &grant["profile"], "semantic_digest")?;
        ceiling(&mut bytes, &grant["ceiling"])?;
        boolean(&mut bytes, &grant["enabled"])?;
        let mut callers = grant["callers"]
            .as_array()
            .filter(|values| values.len() <= 4)
            .ok_or("Linux legacy callers exceed bound")?
            .iter()
            .collect::<Vec<_>>();
        for caller in &callers {
            fields(caller, &["platform", "uid"])?;
            if caller["platform"] != "linux"
                || caller["uid"]
                    .as_u64()
                    .filter(|uid| *uid <= u64::from(u32::MAX))
                    .is_none()
            {
                return Err("Linux legacy caller differs".into());
            }
        }
        callers.sort_by_key(|caller| caller["uid"].as_u64());
        if callers
            .windows(2)
            .any(|pair| pair[0]["uid"] == pair[1]["uid"])
        {
            return Err("Linux legacy caller duplicated".into());
        }
        count(&mut bytes, callers.len())?;
        for caller in callers {
            bytes.push(1);
            bytes.extend((caller["uid"].as_u64().expect("checked caller") as u32).to_be_bytes());
        }
        let plans = scalar_sorted(&grant["approved_plans"], 16)?;
        count(&mut bytes, plans.len())?;
        for plan in plans {
            digest(&mut bytes, plan)?;
        }
        let identity = &grant["execution_identity"];
        match identity["kind"].as_str() {
            Some("preserve-caller") => {
                fields(identity, &["kind"])?;
                bytes.push(1);
            }
            Some("administrator-profile") => {
                fields(identity, &["kind", "reference"])?;
                bytes.push(2);
                reference(&mut bytes, &identity["reference"], "semantic_digest")?;
            }
            _ => return Err("Linux legacy identity unknown".into()),
        }
    }
    disposition(&mut bytes, &value["active_attempt_disposition"])?;
    Ok(crate::sha256(&bytes))
}

/// Encode all digest-bearing objects and canonical ordering independently of
/// the operational registry parser/compiler. This checks byte association;
/// selected authority and mutation semantics are separate required checks.
pub(crate) fn linux_combined_profile_reference() -> Value {
    let semantics=b"memcordon.profile/linux-tcp4-unix-private-v1\0ipv4-tcp-loopback-only-all-ports;unix-stream-pair-path-abstract;scm-rights-intra-attempt;no-ipv6-udp-raw-packet-netlink;fresh-mount-pid-net-ipc-root;immutable-image-input;declared-generated-exec-work;exclusive-admin-nonroot;no-new-privileges-no-caps;stdio-byte-pipes-three;no-host-proc-or-fd-import;closed-native-abi;clone3-enosys;native-exec-observed;aggregate-empty-before-root-export-retire-account";
    serde_json::json!({"id":"linux-tcp4-unix-private-v1","semantic_digest":crate::sha256(semantics)})
}

pub(crate) fn linux_identity_reference(identity: &Value) -> VerificationResult<Value> {
    fields(
        identity,
        &[
            "identity_id",
            "enabled",
            "uid",
            "gid",
            "supplementary_groups",
            "exclusive_use_policy",
            "reservation_key",
        ],
    )?;
    let mut encoded = domain("memcordon.exclusive-identity/version1");
    text(&mut encoded, &identity["identity_id"])?;
    number(&mut encoded, &identity["uid"])?;
    number(&mut encoded, &identity["gid"])?;
    let groups = scalar_sorted(&identity["supplementary_groups"], 32)?;
    count(&mut encoded, groups.len())?;
    for group in groups {
        number(&mut encoded, group)?;
    }
    reference(&mut encoded, &identity["exclusive_use_policy"], "digest")?;
    text(&mut encoded, &identity["reservation_key"])?;
    Ok(serde_json::json!({"id":identity["identity_id"],"digest":crate::sha256(&encoded)}))
}

pub(crate) fn linux_root_layout_reference(layout: &Value) -> VerificationResult<Value> {
    fields(
        layout,
        &[
            "format",
            "revision",
            "layout_id",
            "runtime_image",
            "input_image",
            "writable_roots",
            "output_files",
        ],
    )?;
    if layout["format"] != "memcordon.root-layout" || layout["revision"] != 1 {
        return Err("Linux root layout header differs".into());
    }
    let mut encoded = domain("memcordon.root-layout/version1");
    text(&mut encoded, &layout["layout_id"])?;
    reference(&mut encoded, &layout["runtime_image"], "digest")?;
    reference(&mut encoded, &layout["input_image"], "digest")?;
    let roots = sorted(&layout["writable_roots"], "/id", 16)?;
    count(&mut encoded, roots.len())?;
    for root in roots {
        fields(root, &["id", "path", "byte_limit", "generated_execution"])?;
        text(&mut encoded, &root["id"])?;
        text(&mut encoded, &root["path"])?;
        number(&mut encoded, &root["byte_limit"])?;
        boolean(&mut encoded, &root["generated_execution"])?;
    }
    let outputs = scalar_sorted(&layout["output_files"], 64)?;
    count(&mut encoded, outputs.len())?;
    for output in outputs {
        text(&mut encoded, output)?;
    }
    Ok(serde_json::json!({"id":layout["layout_id"],"digest":crate::sha256(&encoded)}))
}

pub fn linux_registry_digest(value: &Value, target: &str) -> VerificationResult<String> {
    fields(
        value,
        &[
            "format",
            "revision",
            "legacy",
            "execution_identities",
            "images",
            "root_layouts",
            "grants",
            "active_attempt_disposition",
        ],
    )?;
    if value["format"] != "memcordon.local-private-policy" || value["revision"] != 2 {
        return Err("Linux V3 registry header differs".into());
    }
    let mut bytes = domain("memcordon.local-private-policy/version2");
    digest(&mut bytes, &Value::String(legacy_digest(&value["legacy"])?))?;
    disposition(&mut bytes, &value["active_attempt_disposition"])?;
    let identities = sorted(&value["execution_identities"], "/identity_id", 32)?;
    count(&mut bytes, identities.len())?;
    for identity in identities {
        reference(&mut bytes, &linux_identity_reference(identity)?, "digest")?;
        boolean(&mut bytes, &identity["enabled"])?;
    }
    let images = sorted(&value["images"], "/image_id", 16)?;
    count(&mut bytes, images.len())?;
    for image in images {
        reference(
            &mut bytes,
            &crate::linux_build::linux_image_reference(image, target)?,
            "digest",
        )?;
    }
    let layouts = sorted(&value["root_layouts"], "/layout_id", 16)?;
    count(&mut bytes, layouts.len())?;
    for layout in layouts {
        reference(&mut bytes, &linux_root_layout_reference(layout)?, "digest")?;
    }
    let grants = sorted(&value["grants"], "/id", 128)?;
    count(&mut bytes, grants.len())?;
    for grant in grants {
        fields(
            grant,
            &[
                "id",
                "revision",
                "enabled",
                "callers",
                "approved_plans",
                "profile",
                "execution_identity",
                "runtime_image",
                "input_image",
                "root_layout",
            ],
        )?;
        text(&mut bytes, &grant["id"])?;
        number(&mut bytes, &grant["revision"])?;
        boolean(&mut bytes, &grant["enabled"])?;
        let mut callers = grant["callers"]
            .as_array()
            .filter(|values| values.len() <= 4)
            .ok_or("Linux callers exceed bound")?
            .iter()
            .collect::<Vec<_>>();
        for caller in &callers {
            fields(caller, &["platform", "uid"])?;
            if caller["platform"] != "linux"
                || caller["uid"]
                    .as_u64()
                    .filter(|uid| *uid <= u64::from(u32::MAX))
                    .is_none()
            {
                return Err("Linux caller differs".into());
            }
        }
        callers.sort_by_key(|caller| caller["uid"].as_u64());
        if callers
            .windows(2)
            .any(|pair| pair[0]["uid"] == pair[1]["uid"])
        {
            return Err("Linux caller duplicated".into());
        }
        count(&mut bytes, callers.len())?;
        for caller in callers {
            number(&mut bytes, &caller["uid"])?;
        }
        let plans = scalar_sorted(&grant["approved_plans"], 16)?;
        count(&mut bytes, plans.len())?;
        for plan in plans {
            digest(&mut bytes, plan)?;
        }
        reference(&mut bytes, &grant["profile"], "semantic_digest")?;
        fields(
            &grant["execution_identity"],
            &["identity", "exclusive_use_policy"],
        )?;
        for item in [
            &grant["execution_identity"]["identity"],
            &grant["execution_identity"]["exclusive_use_policy"],
            &grant["runtime_image"],
            &grant["input_image"],
            &grant["root_layout"],
        ] {
            reference(&mut bytes, item, "digest")?;
        }
    }
    if bytes.len() > 16 * 1024 * 1024 {
        return Err("Linux canonical policy exceeds native bound".into());
    }
    Ok(crate::sha256(&bytes))
}
