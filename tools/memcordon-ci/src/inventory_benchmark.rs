//! Explicit, finite inventory comparisons. No cache admission or scope migration.
use crate::{CiError, Result, build_context::BuildInputSnapshot};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const MAX_JSON: u64 = 1024 * 1024;
const MANIFEST_ARTIFACT_BUDGET: u64 = 64 * 1024 * 1024;
struct BudgetWriter<'a> {
    file: &'a mut File,
    remaining: &'a mut u64,
}
impl Write for BudgetWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() as u64 > *self.remaining {
            return Err(std::io::Error::other(
                "inventory manifest artifact budget exhausted",
            ));
        }
        let written = self.file.write(bytes)?;
        *self.remaining -= written as u64;
        Ok(written)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}
fn outside_roots(output: &Path, request: &ScanRequest) -> Result<PathBuf> {
    let output = if output.try_exists()? {
        output.canonicalize()?
    } else {
        let parent = output
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        parent.canonicalize()?.join(
            output.file_name().ok_or_else(|| {
                CiError::Message("inventory output needs a directory name".into())
            })?,
        )
    };
    for root in &request.roots {
        if output.starts_with(root.canonicalize()?) {
            return Err(CiError::Message(
                "inventory report directory must be outside measured roots".into(),
            ));
        }
    }
    Ok(output)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanRequest {
    pub schema: u32,
    pub profile: String,
    /// Provisioning evidence supplied by the experiment, not inferred from labels.
    pub corpus_identity: String,
    pub roots: Vec<PathBuf>,
    pub audits: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Variant {
    pub name: String,
    pub binary: PathBuf,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema: u32,
    pub request: ScanRequest,
    pub variants: Vec<Variant>,
    /// Exact finite order; repeated indices are planned observations, never retries.
    pub order: Vec<usize>,
    pub child_budget_seconds: u64,
    pub instance_provenance: String,
}
pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_JSON + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_JSON {
        return Err(CiError::Message("inventory request exceeds 1 MiB".into()));
    }
    Ok(serde_json::from_slice(&bytes)?)
}
fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = File::create(path)?;
    serde_json::to_writer(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}
pub fn file_sha256(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hex::encode(hash.finalize()))
}
pub fn validate_request(request: &ScanRequest) -> Result<()> {
    if request.schema != 1
        || request.profile.is_empty()
        || request.corpus_identity.is_empty()
        || request.roots.is_empty()
        || request.roots.len() > 128
        || request.audits > 16
        || request.roots.iter().any(|root| !root.is_absolute())
    {
        return Err(CiError::Message(
            "invalid inventory scan request: schema/profile/corpus/absolute roots/audit bounds"
                .into(),
        ));
    }
    Ok(())
}
pub fn scan(request_path: &Path, output: &Path) -> Result<()> {
    let request: ScanRequest = read_json(request_path)?;
    validate_request(&request)?;
    let output = outside_roots(output, &request)?;
    fs::create_dir_all(&output)?;
    crate::inventory_progress::set_report_directory(Some(output.clone()))?;
    let start = Instant::now();
    write_json(
        &output.join("outcome.json"),
        &serde_json::json!({"schema":1,"outcome":"incomplete_unknown_termination","inventory_complete":false,"profile":request.profile,"corpus_identity":request.corpus_identity}),
    )?;
    let result = scan_inner(&request, &output);
    let report = match &result {
        Ok(identities) => {
            serde_json::json!({"schema":1,"outcome":"success","inventory_complete":true,"audit_equal":true,"elapsed_ms":start.elapsed().as_millis(),"profile":request.profile,"corpus_identity":request.corpus_identity,"identities":identities,"cache_eligible":false})
        }
        Err(error) => {
            serde_json::json!({"schema":1,"outcome":"scan_error","inventory_complete":false,"elapsed_ms":start.elapsed().as_millis(),"error":error.to_string(),"cache_eligible":false})
        }
    };
    write_json(&output.join("outcome.json"), &report)?;
    crate::inventory_progress::set_report_directory(None)?;
    result.map(|_| ())
}
fn scan_inner(request: &ScanRequest, output: &Path) -> Result<Vec<String>> {
    let mut manifest_remaining = MANIFEST_ARTIFACT_BUDGET;
    let mut snapshots = Vec::new();
    let mut identities = Vec::new();
    let mut phases = File::create(output.join("phases.jsonl"))?;
    for (index, root) in request.roots.iter().enumerate() {
        let started = Instant::now();
        let snapshot = BuildInputSnapshot::capture_native_tree(root)?;
        let digest = snapshot.digest()?;
        identities.push(digest.clone());
        serde_json::to_writer(
            &mut phases,
            &serde_json::json!({"phase":"initial","root_index":index,"elapsed_ms":started.elapsed().as_millis(),"digest":digest}),
        )?;
        phases.write_all(b"\n")?;
        phases.flush()?;
        // Manifest is correctness output, streamed rather than buffered as a JSON Value.
        let mut manifest = File::create(
            output
                .join(index.to_string())
                .with_extension("manifest.json"),
        )?;
        let mut writer = BudgetWriter {
            file: &mut manifest,
            remaining: &mut manifest_remaining,
        };
        serde_json::to_writer(&mut writer, &snapshot.inputs())?;
        writer.write_all(b"\n")?;
        manifest.sync_all()?;
        snapshots.push(snapshot);
    }
    for ordinal in 0..request.audits {
        for (index, snapshot) in snapshots.iter().enumerate() {
            let started = Instant::now();
            snapshot.audit()?;
            serde_json::to_writer(
                &mut phases,
                &serde_json::json!({"phase":"audit","ordinal":ordinal,"root_index":index,"elapsed_ms":started.elapsed().as_millis(),"equal":true}),
            )?;
            phases.write_all(b"\n")?;
            phases.flush()?;
        }
    }
    Ok(identities)
}
pub fn benchmark(plan_path: &Path, output: &Path) -> Result<()> {
    let plan: Plan = read_json(plan_path)?;
    validate_request(&plan.request)?;
    if plan.schema != 1
        || plan.variants.is_empty()
        || plan.variants.len() > 8
        || plan.order.is_empty()
        || plan.order.len() > 64
        || plan.order.iter().any(|&i| i >= plan.variants.len())
        || !(1..=1800).contains(&plan.child_budget_seconds)
        || plan.instance_provenance.is_empty()
    {
        return Err(CiError::Message(
            "invalid finite inventory benchmark plan".into(),
        ));
    }
    let output = outside_roots(output, &plan.request)?;
    fs::create_dir(&output)?;
    write_json(&output.join("plan.json"), &plan)?;
    let request = output.join("request.json");
    write_json(&request, &plan.request)?;
    for variant in &plan.variants {
        if !variant.binary.is_absolute() || file_sha256(&variant.binary)? != variant.sha256 {
            return Err(CiError::Message(
                "benchmark executable identity mismatch".into(),
            ));
        }
    }
    let mut observations = Vec::new();
    let mut reference = None;
    let mut qualified = true;
    for (ordinal, &variant_index) in plan.order.iter().enumerate() {
        let variant = &plan.variants[variant_index];
        let directory = output.join(ordinal.to_string());
        fs::create_dir(&directory)?;
        if file_sha256(&variant.binary)? != variant.sha256 {
            return Err(CiError::Message(
                "benchmark executable changed before scheduled execution".into(),
            ));
        }
        let mut command = Command::new(&variant.binary);
        command
            .arg("inventory-scan")
            .arg("--request")
            .arg(&request)
            .arg("--report-dir")
            .arg(&directory);
        let start = Instant::now();
        let execution = memcordon_testkit::run_with_deadline_output_limit(
            &mut command,
            Duration::from_secs(plan.child_budget_seconds),
            4 * 1024 * 1024,
        );
        let (success, error) = match execution {
            Ok(result) => {
                fs::write(directory.join("stderr.log"), result.stderr)?;
                (result.status.success(), None)
            }
            Err(error) => (false, Some(error.to_string())),
        };
        let report = read_json::<serde_json::Value>(&directory.join("outcome.json")).ok();
        let identities = report
            .as_ref()
            .filter(|r| r["inventory_complete"] == true && r["outcome"] == "success")
            .and_then(|r| r.get("identities"))
            .cloned();
        let equal = if let Some(ids) = &identities {
            if let Some(expected) = &reference {
                ids == expected
            } else {
                reference = Some(ids.clone());
                true
            }
        } else {
            false
        };
        let binary_unchanged = file_sha256(&variant.binary)? == variant.sha256;
        qualified &= success && equal && binary_unchanged;
        observations.push(serde_json::json!({"ordinal":ordinal,"variant":variant.name,"elapsed_ms":start.elapsed().as_millis(),"child_success":success,"complete_identity_equal":equal,"binary_unchanged":binary_unchanged,"error":error}));
        write_json(
            &output.join("comparison.json"),
            &serde_json::json!({"schema":1,"complete":ordinal+1==plan.order.len(),"qualified":qualified && ordinal+1==plan.order.len(),"cache_equivalence":"not_established","provenance":plan.instance_provenance,"observations":observations}),
        )?;
    }
    if qualified {
        Ok(())
    } else {
        Err(CiError::Message(
            "inventory benchmark qualification failed; all planned observations retained".into(),
        ))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    schema: u32,
    nonce: String,
    sha256: String,
    parent_outcome: String,
    run_id: String,
    run_attempt: String,
    job: String,
}
pub fn require_admission(path: &Path) -> Result<()> {
    let admission: Admission = read_json(&path.with_extension("admission.json"))?;
    if admission.schema != 1
        || admission.nonce.is_empty()
        || admission.parent_outcome != "success"
        || admission.sha256 != file_sha256(path)?
        || admission.run_id != std::env::var("GITHUB_RUN_ID").unwrap_or_default()
        || admission.run_attempt != std::env::var("GITHUB_RUN_ATTEMPT").unwrap_or_default()
        || admission.job != std::env::var("GITHUB_JOB").unwrap_or_default()
    {
        return Err(CiError::Message(
            "build context lacks matching successful parent admission for this job attempt".into(),
        ));
    }
    Ok(())
}
