//! Shared actual no-target account/cgroup/journal census associations.
use crate::*;
use serde_json::Value;

pub(crate) fn validate_linux_refusal_census(
    census: &Value,
    identity: &Value,
    cell: &Value,
    lease_id: &str,
    scenario: &str,
    account: &Value,
    provider: &Value,
    request_sha256: &str,
    result_sha256: &str,
    attempt: &str,
) -> VerificationResult<()> {
    let closed = |value: &Value, fields: &[&str]| -> VerificationResult<()> {
        if value.as_object().is_none_or(|object| {
            object.len() != fields.len()
                || object.keys().any(|field| !fields.contains(&field.as_str()))
        }) {
            return Err("native refusal census raw shape differs".into());
        }
        Ok(())
    };
    closed(
        census,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "lease_id",
            "scenario",
            "attempt_id",
            "provider",
            "account",
            "result_sha256",
            "request_sha256",
            "tasks",
            "cgroup_root",
            "journal_root",
        ],
    )?;
    closed(
        &census["identity"],
        &["run_id", "source_commit", "source_tree_sha256", "version"],
    )?;
    closed(&census["cell"], &["target", "channel"])?;
    closed(
        &census["provider"],
        &["generation", "source_commit", "runtime_manifest_sha256"],
    )?;
    closed(
        &census["account"],
        &[
            "name",
            "uid",
            "gid",
            "intent",
            "native_readback",
            "group_readback",
        ],
    )?;
    digest(request_sha256)?;
    digest(result_sha256)?;
    if census["format"] != "memcordon.linux-policy-native-census"
        || census["revision"] != 1
        || census["identity"] != *identity
        || census["cell"] != *cell
        || census["lease_id"] != lease_id
        || census["scenario"] != scenario
        || census["account"] != *account
        || census["provider"] != *provider
        || census["request_sha256"] != request_sha256
        || census["result_sha256"] != result_sha256
        || census["attempt_id"] != attempt
        || attempt.len() != 32
        || !attempt
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(
            "native refusal census differs from original source/cell/account/request/result".into(),
        );
    }
    let uid = account["uid"]
        .as_u64()
        .filter(|value| *value > 0 && *value <= u32::MAX as u64)
        .ok_or("native refusal account UID absent")?;
    let gid = account["gid"]
        .as_u64()
        .filter(|value| *value > 0 && *value <= u32::MAX as u64)
        .ok_or("native refusal account GID absent")?;
    let tasks = census["tasks"]
        .as_array()
        .ok_or("native refusal task census absent")?;
    if tasks.is_empty() || tasks.len() > 65536 {
        return Err("native refusal task census empty/unbounded".into());
    }
    let mut identities = BTreeSet::new();
    let mut credential_count = 0usize;
    for task in tasks {
        closed(task, &["pid", "tid", "birth", "uids", "gids", "groups"])?;
        if ["pid", "tid", "birth"]
            .iter()
            .any(|field| task[*field].as_u64().is_none_or(|value| value == 0))
            || ["pid", "tid"].iter().any(|field| {
                task[*field]
                    .as_u64()
                    .is_none_or(|value| value > i32::MAX as u64)
            })
            || !identities.insert((task["pid"].as_u64(), task["tid"].as_u64()))
        {
            return Err("native refusal task identity repeated/invalid".into());
        }
        for (field, owned, count) in [
            ("uids", uid, Some(4)),
            ("gids", gid, Some(4)),
            ("groups", gid, None),
        ] {
            let values = task[field]
                .as_array()
                .ok_or("native refusal credential array absent")?;
            credential_count = credential_count
                .checked_add(values.len())
                .ok_or("native refusal credential size overflow")?;
            if count.is_some_and(|count| values.len() != count)
                || credential_count > 262144
                || values.iter().any(|value| {
                    value
                        .as_u64()
                        .is_none_or(|value| value > u32::MAX as u64 || value == owned)
                })
            {
                return Err("native refusal census retains exclusive credentials".into());
            }
        }
    }
    for (field, path) in [
        ("cgroup_root", "/sys/fs/cgroup/memcordon-sealed"),
        ("journal_root", "/var/lib/memcordon/sealed"),
    ] {
        let root = &census[field];
        if field == "cgroup_root" {
            closed(
                root,
                &[
                    "path",
                    "device",
                    "inode",
                    "uid",
                    "mode",
                    "filesystem_type",
                    "attempt_directories",
                    "attempt_absence_errno",
                ],
            )?;
        } else {
            closed(
                root,
                &[
                    "path",
                    "device",
                    "inode",
                    "uid",
                    "mode",
                    "attempt_absence_errno",
                ],
            )?;
        }
        if root["path"] != path
            || root["uid"] != 0
            || root["attempt_absence_errno"] != 2
            || ["device", "inode"]
                .iter()
                .any(|field| root[*field].as_u64().is_none_or(|value| value == 0))
            || root["mode"]
                .as_u64()
                .is_none_or(|mode| mode & 0o170000 != 0o040000 || mode & 0o022 != 0)
        {
            return Err("native refusal held parent/absence association differs".into());
        }
    }
    if census["cgroup_root"]["filesystem_type"] != 0x63677270u64
        || census["cgroup_root"]["attempt_directories"] != serde_json::json!([])
    {
        return Err("native refusal census retains cgroup or wrong filesystem".into());
    }
    Ok(())
}
