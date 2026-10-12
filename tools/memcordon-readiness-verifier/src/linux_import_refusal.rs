//! Finite original native importer refusals for hostile input authority.
use crate::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxIsolationImportEvidence {
    pub format: String,
    pub revision: u32,
    pub key: CaseKey,
    pub run_id: String,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub lease_id: String,
    pub owner: String,
    pub original_lease: String,
    pub acquisition: String,
    pub activation: String,
    pub contract: String,
    pub definition: String,
    pub intent: String,
    pub source: String,
    pub original_inventory: String,
    pub inventory: String,
    pub source_retirement: String,
    pub source_closure: String,
    pub invocation: String,
    pub native_creation: String,
    pub native_process: String,
    pub exit: String,
    pub stdout: String,
    pub stderr: String,
    pub account_intent: String,
    pub account_readback: String,
    pub group_readback: String,
    pub census: String,
    pub challenge: String,
    pub definition_retirement: String,
    pub retirement_creation: String,
    pub retirement_process: String,
    pub retirement_exit: String,
    pub retirement_stdout: String,
    pub retirement_stderr: String,
    pub replaced_original: Option<String>,
}
impl LinuxIsolationImportEvidence {
    pub(crate) fn artifact_paths(&self) -> Vec<&str> {
        let mut paths = vec![
            self.owner.as_str(),
            &self.original_lease,
            &self.acquisition,
            &self.activation,
            &self.contract,
            &self.definition,
            &self.intent,
            &self.source,
            &self.original_inventory,
            &self.inventory,
            &self.source_retirement,
            &self.source_closure,
            &self.invocation,
            &self.native_creation,
            &self.native_process,
            &self.exit,
            &self.stdout,
            &self.stderr,
            &self.account_intent,
            &self.account_readback,
            &self.group_readback,
            &self.census,
            &self.challenge,
            &self.definition_retirement,
            &self.retirement_creation,
            &self.retirement_process,
            &self.retirement_exit,
            &self.retirement_stdout,
            &self.retirement_stderr,
        ];
        if let Some(path) = &self.replaced_original {
            paths.push(path);
        }
        paths
    }
}
fn closed(value: &Value, fields: &[&str]) -> VerificationResult<()> {
    if value.as_object().is_none_or(|object| {
        object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field))
    }) {
        return Err("isolation importer original raw schema differs".into());
    }
    Ok(())
}

fn validate_inventory(
    e: &LinuxIsolationImportEvidence,
    definition: &Value,
    source: &Value,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    let original: Value = crate::wire::json(custody.bytes(&e.original_inventory)?)?;
    let after: Value = crate::wire::json(custody.bytes(&e.inventory)?)?;
    for inventory in [&original, &after] {
        closed(
            inventory,
            &["format", "revision", "source_root", "root", "members"],
        )?;
        closed(
            &inventory["root"],
            &["device", "inode", "uid", "gid", "mode"],
        )?;
        if inventory["format"] != "memcordon.linux-isolation-import-inventory"
            || inventory["revision"] != 1
            || inventory["source_root"] != source["path"]
        {
            return Err("isolation source full inventory crosses original root".into());
        }
    }
    let entries = definition["entries"]
        .as_array()
        .filter(|entries| !entries.is_empty() && entries.len() <= 4096)
        .ok_or("isolation original input population absent")?;
    let before = original["members"]
        .as_array()
        .filter(|members| members.len() == entries.len())
        .ok_or("isolation original input inventory incomplete")?;
    let after_members = after["members"]
        .as_array()
        .filter(|members| {
            members.len() == entries.len() + usize::from(e.key.scenario == "input-socket")
        })
        .ok_or("isolation mutated input inventory population differs")?;
    for (ordinal, entry) in entries.iter().enumerate() {
        closed(entry, &["kind", "path", "sha256", "size", "executable"])?;
        let member = &before[ordinal];
        closed(
            member,
            &[
                "path", "device", "inode", "uid", "gid", "mode", "nlink", "length", "sha256",
            ],
        )?;
        if entry["kind"] != "regular"
            || member["path"] != entry["path"]
            || member["sha256"] != entry["sha256"]
            || member["length"] != entry["size"]
            || member["uid"] != 0
            || member["gid"] != 0
            || member["nlink"] != 1
            || member["mode"].as_u64().is_none_or(|mode| {
                mode != if entry["executable"] == true {
                    0o100555
                } else {
                    0o100444
                }
            })
            || ["device", "inode"]
                .iter()
                .any(|field| member[*field].as_u64().is_none_or(|value| value == 0))
        {
            return Err(
                "isolation original copied input differs from acquired complete definition".into(),
            );
        }
        let modified = &after_members[ordinal];
        closed(
            modified,
            &[
                "path", "device", "inode", "uid", "gid", "mode", "nlink", "length", "sha256",
            ],
        )?;
        if !(e.key.scenario == "imported-socket" && ordinal == 0) && modified != member {
            return Err("isolation hostile source changes unrelated original input member".into());
        }
    }
    let mut expected_root = original["root"].clone();
    if e.key.scenario == "caller-writable-tree" {
        expected_root["uid"] = 65534.into();
        expected_root["gid"] = 65534.into();
        expected_root["mode"] = json!(0o040755);
    }
    if original["root"]["uid"] != 0
        || original["root"]["gid"] != 0
        || original["root"]["mode"] != 0o040700
        || after["root"] != expected_root
        || ["device", "inode", "uid", "gid", "mode"]
            .iter()
            .any(|field| after["root"][*field] != source[*field])
    {
        return Err("isolation actual original source root mutation differs".into());
    }
    if e.key.scenario != "caller-writable-tree" {
        let ordinal = if e.key.scenario == "input-socket" {
            entries.len()
        } else {
            0
        };
        let socket = &after_members[ordinal];
        closed(
            socket,
            &[
                "path", "device", "inode", "uid", "gid", "mode", "nlink", "length", "sha256",
            ],
        )?;
        if !socket["sha256"].is_null()
            || socket["mode"]
                .as_u64()
                .is_none_or(|mode| mode & 0o170000 != 0o140000)
            || socket["uid"] != 0
            || socket["nlink"] != 1
            || ["path", "device", "inode", "uid", "gid", "mode", "nlink"]
                .iter()
                .any(|field| socket[*field] != source["mutation"][*field])
        {
            return Err("isolation original socket type/inventory mutation differs".into());
        }
    }
    Ok(())
}

fn validate_source(
    e: &LinuxIsolationImportEvidence,
    source: &Value,
    definition: &Value,
    intent: &Value,
    retired: &Value,
    closure: &Value,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    closed(
        source,
        &[
            "format", "revision", "scenario", "path", "device", "inode", "uid", "gid", "mode",
            "mutation", "parent",
        ],
    )?;
    closed(
        &source["parent"],
        &["path", "device", "inode", "uid", "mode"],
    )?;
    closed(
        retired,
        &[
            "format",
            "revision",
            "original",
            "held_nlink",
            "native_errno",
            "caller_write_revoked_before_cleanup",
        ],
    )?;
    closed(
        closure,
        &[
            "format",
            "revision",
            "original",
            "parent",
            "root_closed",
            "parent_closed",
            "socket_parent_closed",
            "listener_closed",
            "native_file_closes",
            "native_errno",
        ],
    )?;
    closed(&closure["parent"], &["device", "inode", "uid", "mode"])?;
    let writable = e.key.scenario == "caller-writable-tree";
    let path = std::path::Path::new(
        source["path"]
            .as_str()
            .ok_or("isolation original source path absent")?,
    );
    if path.parent().and_then(std::path::Path::to_str) != source["parent"]["path"].as_str()
        || ["device", "inode"].iter().any(|field| {
            source["parent"][*field]
                .as_u64()
                .is_none_or(|value| value == 0)
        })
    {
        return Err("isolation original source parent native name differs".into());
    }
    if source["format"] != "memcordon.linux-isolation-import-source"
        || source["revision"] != 1
        || source["scenario"] != e.key.scenario
        || source["path"] != intent["source_root"]
        || ["device", "inode"]
            .iter()
            .any(|field| source[*field].as_u64().is_none_or(|value| value == 0))
        || source["parent"]["uid"] != 0
        || source["parent"]["mode"]
            .as_u64()
            .is_none_or(|mode| mode & 0o170000 != 0o040000 || mode & 0o022 != 0)
        || retired["format"] != "memcordon.linux-isolation-import-source-retired"
        || retired["revision"] != 1
        || retired["original"] != *source
        || retired["held_nlink"] != 0
        || retired["native_errno"] != 2
        || retired["caller_write_revoked_before_cleanup"] != writable
        || closure["format"] != "memcordon.linux-isolation-import-source-closed"
        || closure["revision"] != 1
        || closure["original"] != *source
        || closure["root_closed"] != true
        || closure["parent_closed"] != true
        || closure["socket_parent_closed"] != !writable
        || closure["listener_closed"] != !writable
        || !closure["native_errno"].is_null()
    {
        return Err("isolation original source native root/name/checked close differs".into());
    }
    for field in ["device", "inode", "uid", "mode"] {
        if closure["parent"][field] != source["parent"][field] {
            return Err("isolation original source parent changed before checked close".into());
        }
    }
    let mutation = &source["mutation"];
    if writable {
        closed(mutation, &["kind", "caller_uid", "caller_gid"])?;
        if mutation["kind"] != e.key.scenario
            || mutation["caller_uid"] != 65534
            || mutation["caller_gid"] != 65534
            || source["uid"] != 65534
            || source["gid"] != 65534
            || source["mode"] != 0o040755
            || e.replaced_original.is_some()
        {
            return Err("isolation actual caller-writable root differs".into());
        }
    } else {
        closed(
            mutation,
            &[
                "kind",
                "path",
                "device",
                "inode",
                "uid",
                "gid",
                "mode",
                "nlink",
                "baseline_sha256",
                "listener",
            ],
        )?;
        closed(&mutation["listener"], &["device", "inode", "mode"])?;
        if mutation["kind"] != e.key.scenario
            || source["uid"] != 0
            || source["gid"] != 0
            || source["mode"] != 0o040700
            || mutation["mode"]
                .as_u64()
                .is_none_or(|mode| mode & 0o170000 != 0o140000)
            || mutation["listener"]["mode"]
                .as_u64()
                .is_none_or(|mode| mode & 0o170000 != 0o140000)
            || ["device", "inode"].iter().any(|field| {
                mutation["listener"][*field]
                    .as_u64()
                    .is_none_or(|value| value == 0)
            })
            || mutation["uid"] != 0
            || mutation["gid"] != 0
            || mutation["nlink"] != 1
        {
            return Err("isolation original named socket/native listener differs".into());
        }
        if e.key.scenario == "input-socket" {
            if mutation["path"] != "owned-source/input-socket"
                || !mutation["baseline_sha256"].is_null()
                || e.replaced_original.is_some()
                || definition["entries"].as_array().is_none_or(|entries| {
                    entries
                        .iter()
                        .any(|entry| entry["path"] == mutation["path"])
                })
            {
                return Err(
                    "isolation extra input socket replaces approved original authority".into(),
                );
            }
        } else {
            let original = e
                .replaced_original
                .as_deref()
                .ok_or("isolation original socket-replaced bytes absent")?;
            let first = definition["entries"]
                .as_array()
                .and_then(|entries| entries.first())
                .ok_or("isolation original selected input member absent")?;
            if mutation["path"] != first["path"]
                || first["kind"] != "regular"
                || first["sha256"] != custody.hash(original)?
                || first["size"] != custody.bytes(original)?.len()
                || mutation["baseline_sha256"] != first["sha256"]
            {
                return Err(
                    "isolation socket replacement crosses original measured approved member".into(),
                );
            }
        }
    }
    validate_inventory(e, definition, source, custody)?;
    let count = definition["entries"]
        .as_array()
        .ok_or("isolation original member population absent")?
        .len();
    let expected = count
        .checked_mul(4)
        .and_then(|count| {
            if e.key.scenario == "imported-socket" {
                count.checked_sub(1)
            } else if e.key.scenario == "input-socket" {
                count.checked_add(1)
            } else {
                Some(count)
            }
        })
        .ok_or("isolation native descriptor population overflow")?;
    if closure["native_file_closes"]
        .as_u64()
        .is_none_or(|closes| closes < expected as u64 || closes > 65536)
    {
        return Err("isolation original complete member descriptors not closed".into());
    }
    Ok(())
}

pub(crate) fn verify(
    index: &EvidenceIndex,
    record: &CaseRecord,
    e: &LinuxIsolationImportEvidence,
    products: &BTreeMap<ProductKey, &ProductObservation>,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    header(
        &e.format,
        e.revision,
        "memcordon.consumer-readiness.linux-isolation-import-refusal",
    )?;
    let origin = producer_origin(index, &record.key.target, record.key.channel.as_deref())?;
    if e.key != record.key
        || e.run_id != origin.run_id
        || e.source_commit != index.source_commit
        || e.source_tree_sha256 != index.source_tree_sha256
        || e.key.family != "L-ISO-02"
        || !["input-socket", "imported-socket", "caller-writable-tree"]
            .contains(&e.key.scenario.as_str())
        || e.key.evidence_class != EvidenceClass::InstalledProduct
        || !e.key.target.ends_with("linux-gnu")
    {
        return Err("isolation importer crosses original finite installed scope".into());
    }
    let product = products
        .get(&ProductKey {
            target: e.key.target.clone(),
            channel: e
                .key
                .channel
                .clone()
                .ok_or("isolation importer installed channel absent")?,
        })
        .copied()
        .ok_or("isolation importer selected original product absent")?;
    if e.lease_id != product.lifecycle.lease_id {
        return Err("isolation importer crosses original installed lease".into());
    }
    for path in e.artifact_paths() {
        custody.bytes(path)?;
    }
    let decode = |path: &str| crate::wire::json(custody.bytes(path)?);
    let owner = decode(&e.owner)?;
    let lease = decode(&e.original_lease)?;
    let acquired = decode(&e.acquisition)?;
    closed(
        &owner,
        &[
            "format",
            "revision",
            "run_id",
            "source_commit",
            "source_tree_sha256",
            "cell",
            "lease_id",
            "provider",
            "baseline_registry",
            "baseline_epoch",
            "admin_root",
            "admin_root_device",
            "admin_root_inode",
            "privileged_policy_root",
        ],
    )?;
    closed(
        &lease,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "admin_root",
            "device",
            "inode",
            "cleanup_agent",
            "cleanup_agent_sha256",
            "legacy",
            "lease_id",
            "artifact_root",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
        ],
    )?;
    closed(
        &acquired,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "admin_root",
            "device",
            "inode",
            "legacy",
            "images",
            "account",
        ],
    )?;
    let identity = serde_json::json!({"run_id":e.run_id,"source_commit":index.source_commit,"source_tree_sha256":index.source_tree_sha256,"version":index.version});
    let cell = serde_json::to_value(&product.key).map_err(|error| error.to_string())?;
    if owner["format"] != "memcordon.linux-policy-case-owner"
        || owner["revision"] != 1
        || owner["run_id"] != e.run_id
        || owner["source_commit"] != e.source_commit
        || owner["source_tree_sha256"] != e.source_tree_sha256
        || owner["cell"] != cell
        || owner["lease_id"] != e.lease_id
        || lease["format"] != "memcordon.consumer-readiness.linux-lease-owner"
        || lease["revision"] != 1
        || lease["identity"] != identity
        || lease["cell"] != cell
        || lease["lease_id"] != e.lease_id
        || acquired["format"] != "memcordon.owned-readiness-resources"
        || acquired["revision"] != 1
        || acquired["identity"] != identity
        || acquired["cell"] != cell
        || lease["admin_root"] != owner["admin_root"]
        || acquired["admin_root"] != owner["admin_root"]
        || lease["device"] != owner["admin_root_device"]
        || lease["inode"] != owner["admin_root_inode"]
        || acquired["device"] != lease["device"]
        || acquired["inode"] != lease["inode"]
        || lease["legacy"] != acquired["legacy"]
    {
        return Err("isolation importer original lease/acquisition authority differs".into());
    }
    crate::linux_ingress::validate_owned_account(
        &acquired["account"],
        &decode(&e.account_intent)?,
        custody.bytes(&e.account_readback)?,
        custody.bytes(&e.group_readback)?,
        index,
        &e.key,
        &e.run_id,
        &e.acquisition,
        &owner,
        &lease,
    )?;
    let activation = decode(&e.activation)?;
    let contract = decode(&e.contract)?;
    if crate::linux_policy::activation_registry(&activation)? != &owner["baseline_registry"]
        || activation["epoch"] != owner["baseline_epoch"]
        || contract["expected_epoch"] != activation["epoch"]
    {
        return Err("isolation importer replaces original active authority".into());
    }
    crate::wire::v3_request_digest(&contract)?;
    let definition = decode(&e.definition)?;
    let intent = decode(&e.intent)?;
    let source = decode(&e.source)?;
    closed(
        &intent,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "lease_id",
            "scenario",
            "definition",
            "definition_sha256",
            "reference",
            "source_root",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
        ],
    )?;
    let mut baseline = definition.clone();
    baseline["image_id"] = acquired["images"]["input"]["image_id"].clone();
    if baseline != acquired["images"]["input"]
        || intent["format"] != "memcordon.linux-isolation-import-intent"
        || intent["revision"] != 1
        || intent["identity"] != identity
        || intent["cell"] != cell
        || intent["lease_id"] != e.lease_id
        || intent["scenario"] != e.key.scenario
        || intent["definition_sha256"] != custody.hash(&e.definition)?
        || intent["reference"]
            != crate::linux_build::linux_image_reference(&definition, &e.key.target)?
        || intent["work_deadline_unix_millis"] != lease["work_deadline_unix_millis"]
        || intent["cleanup_deadline_unix_millis"] != lease["cleanup_deadline_unix_millis"]
    {
        return Err("isolation importer original input definition/intent/cutoff differs".into());
    }
    let agent = product
        .components
        .iter()
        .find(|component| component.role == "sealed-agent")
        .ok_or("isolation importer selected original agent absent")?;
    let command = decode(&e.invocation)?;
    let status = validate_linux_image_command(
        &command,
        &decode(&e.native_process)?,
        custody.bytes(&e.native_creation)?,
        &decode(&e.exit)?,
        custody.bytes(&e.invocation)?,
        custody.bytes(&e.stdout)?,
        custody.bytes(&e.stderr)?,
        &agent.installed_sha256,
    )?;
    if status == 0
        || command["identity"] != identity
        || command["cell"] != cell
        || command["lease_id"] != e.lease_id
        || command["scenario"] != e.key.scenario
        || command["argv"]
            != serde_json::json!([
                "package",
                "policy",
                "image",
                "install",
                "--definition",
                intent["definition"],
                "--source-root",
                intent["source_root"],
                "--json"
            ])
        || command["definition_sha256"] != intent["definition_sha256"]
        || command["work_deadline_unix_millis"] != intent["work_deadline_unix_millis"]
        || command["cleanup_deadline_unix_millis"] != intent["cleanup_deadline_unix_millis"]
    {
        return Err("isolation importer original command/native refusal differs".into());
    }
    if command["format"] != "memcordon.linux-image-import-command"
        || lease["cleanup_agent_sha256"] != agent.installed_sha256
        || lease["cleanup_agent"] != "/usr/libexec/memcordon-sealed-agent"
        || owner["provider"]["generation"] != format!("{}:{}", index.version, index.source_commit)
        || owner["provider"]["source_commit"] != index.source_commit
        || owner["provider"]["runtime_manifest_sha256"]
            != custody.hash(&product.runtime_manifest)?
    {
        return Err("isolation importer original provider/cleanup executable differs".into());
    }
    let admin = owner["admin_root"]
        .as_str()
        .ok_or("isolation importer original admin root absent")?;
    for field in ["definition", "source_root"] {
        let authority = if field == "definition" {
            admin
        } else {
            lease["artifact_root"]
                .as_str()
                .ok_or("isolation importer original artifact root absent")?
        };
        let path = intent[field]
            .as_str()
            .ok_or("isolation importer native source path absent")?;
        // Retained Linux-native scope is independent of the verifier host OS.
        // Match Unix Path components: repeated separators and interior `.`
        // normalize, while `..` remains an explicit forbidden component.
        let path_parts: Vec<_> = path
            .split('/')
            .filter(|part| !part.is_empty() && *part != ".")
            .collect();
        let authority_parts: Vec<_> = authority
            .split('/')
            .filter(|part| !part.is_empty() && *part != ".")
            .collect();
        if !path.starts_with('/')
            || !authority.starts_with('/')
            || !path_parts.starts_with(&authority_parts)
            || path_parts.len() == authority_parts.len()
            || path_parts.contains(&"..")
        {
            return Err(
                "isolation importer native source escapes original protected authority".into(),
            );
        }
    }
    if definition["image_id"] == acquired["images"]["input"]["image_id"] {
        return Err("isolation importer replaces original approved input image".into());
    }
    let challenge = custody.bytes(&e.challenge)?;
    if challenge.len() != 32 {
        return Err("isolation importer original probe challenge absent".into());
    }
    let nonce = hex::encode(&challenge[..16]);
    let census = decode(&e.census)?;
    closed(
        &census,
        &[
            "format",
            "revision",
            "original_probe_nonce",
            "definition_sha256",
            "stdout_sha256",
            "native_census",
        ],
    )?;
    if census["format"] != "memcordon.linux-isolation-import-census"
        || census["revision"] != 1
        || census["original_probe_nonce"] != nonce
        || census["definition_sha256"] != custody.hash(&e.definition)?
        || census["stdout_sha256"] != custody.hash(&e.stdout)?
    {
        return Err("isolation importer original no-provider probe census differs".into());
    }
    crate::linux_refusal_census::validate_linux_refusal_census(
        &census["native_census"],
        &identity,
        &cell,
        &e.lease_id,
        &e.key.scenario,
        &acquired["account"],
        &owner["provider"],
        custody.hash(&e.definition)?,
        custody.hash(&e.stdout)?,
        &nonce,
    )?;
    let retirement = decode(&e.definition_retirement)?;
    let retirement_native = decode(&e.retirement_process)?;
    let retirement_status = crate::linux_images::validate_linux_image_native_command(
        &retirement,
        &retirement_native,
        custody.bytes(&e.retirement_creation)?,
        &decode(&e.retirement_exit)?,
        custody.bytes(&e.definition_retirement)?,
        custody.bytes(&e.retirement_stdout)?,
        custody.bytes(&e.retirement_stderr)?,
        &agent.installed_sha256,
    )?;
    if retirement_status != 0
        || retirement["format"] != "memcordon.linux-isolation-image-retirement-command"
        || retirement["identity"] != identity
        || retirement["cell"] != cell
        || retirement["lease_id"] != e.lease_id
        || retirement["scenario"] != e.key.scenario
        || retirement["argv"]
            != json!([
                "package",
                "policy",
                "image",
                "retire",
                "--definition",
                intent["definition"],
                "--json"
            ])
        || retirement["definition_sha256"] != intent["definition_sha256"]
        || retirement["work_deadline_unix_millis"] != lease["work_deadline_unix_millis"]
        || retirement["cleanup_deadline_unix_millis"] != lease["cleanup_deadline_unix_millis"]
        || retirement_native["process_id"] == decode(&e.native_process)?["process_id"]
            && retirement_native["birth"] == decode(&e.native_process)?["birth"]
    {
        return Err("isolation importer original definition cleanup native custody differs".into());
    }
    let retired = decode(&e.retirement_stdout)?;
    let fields = if retired["already_absent"] == true {
        vec![
            "format",
            "revision",
            "reference",
            "storage_absent",
            "already_absent",
        ]
    } else {
        vec![
            "format",
            "revision",
            "reference",
            "storage_absent",
            "device",
            "inode",
        ]
    };
    closed(&retired, &fields)?;
    if retired["format"] != "memcordon.runtime-image-retirement"
        || retired["revision"] != 1
        || retired["reference"] != intent["reference"]
        || retired["storage_absent"] != true
        || retired["already_absent"] != true
            && ["device", "inode"]
                .iter()
                .any(|field| retired[*field].as_u64().is_none_or(|value| value == 0))
    {
        return Err("isolation importer original rejected definition storage remains".into());
    }
    validate_source(
        e,
        &source,
        &definition,
        &intent,
        &decode(&e.source_retirement)?,
        &decode(&e.source_closure)?,
        custody,
    )
}
