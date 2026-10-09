use clap::{Parser, Subcommand};
use memcordon_readiness_verifier::{PROFILE, VerificationScope, validate_manifest, verify_scoped};
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version,
    about = "Independently verify the fixed MemCordon consumer readiness evidence"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Verify {
        #[arg(long)]
        manifest: PathBuf,
        /// Evidence directory (evidence-index.json) or an explicit index file.
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        artifact_root: Option<PathBuf>,
        /// Fresh output path; existing verdicts are never overwritten.
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_enum, default_value = "complete-profile")]
        scope: VerificationScope,
    },
    ValidateManifest {
        #[arg(long)]
        manifest: PathBuf,
    },
}

#[derive(Serialize)]
struct InvalidEvidence<'a> {
    format: &'static str,
    revision: u32,
    profile: &'static str,
    scope: VerificationScope,
    profile_ready: bool,
    accepted: bool,
    error: &'a str,
}

fn write_verdict(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    output.write_all(bytes).map_err(|e| e.to_string())?;
    output.write_all(b"\n").map_err(|e| e.to_string())?;
    output.sync_all().map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn execute(cli: Cli) -> Result<bool, String> {
    match cli.command {
        Command::ValidateManifest { manifest } => {
            let metadata = std::fs::symlink_metadata(&manifest).map_err(|e| e.to_string())?;
            if !metadata.is_file() || metadata.len() > 1024 * 1024 {
                return Err("manifest is not a bounded ordinary file".into());
            }
            let cases = validate_manifest(&std::fs::read(&manifest).map_err(|e| e.to_string())?)?;
            println!("{PROFILE}: {} required evidence rows", cases.len());
            Ok(true)
        }
        Command::Verify {
            manifest,
            input,
            artifact_root,
            output,
            scope,
        } => {
            let directory = input.is_dir();
            let index = if directory {
                input.join("evidence-index.json")
            } else {
                input.clone()
            };
            let root = artifact_root.unwrap_or_else(|| {
                if directory {
                    input
                } else {
                    index
                        .parent()
                        .unwrap_or(std::path::Path::new("."))
                        .to_path_buf()
                }
            });
            let result = verify_scoped(&manifest, &index, &root, scope);
            let accepted = result.as_ref().is_ok_and(|verdict| verdict.accepted);
            let bytes = match &result {
                Ok(verdict) => serde_json::to_vec_pretty(verdict).map_err(|e| e.to_string())?,
                Err(error) => serde_json::to_vec_pretty(&InvalidEvidence {
                    format: "memcordon.consumer-readiness.invalid-evidence",
                    revision: 1,
                    profile: PROFILE,
                    scope,
                    profile_ready: false,
                    accepted: false,
                    error,
                })
                .map_err(|e| e.to_string())?,
            };
            write_verdict(&output, &bytes)?;
            if let Err(error) = result {
                eprintln!("readiness evidence rejected: {error}");
            }
            Ok(accepted)
        }
    }
}

fn main() {
    match execute(Cli::parse()) {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(error) => {
            eprintln!("readiness verification failed: {error}");
            std::process::exit(2);
        }
    }
}
