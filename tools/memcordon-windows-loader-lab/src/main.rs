mod controller;
#[cfg(windows)]
mod observer;
mod spawner;
use memcordon_windows_loader_lab::{artifact, scenario, target};

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "memcordon-windows-loader-lab")]
#[command(about = "Out-of-band Windows loader experiment harness")]
struct Cli {
    #[command(subcommand)]
    role: Role,
}

#[derive(Debug, Subcommand)]
enum Role {
    Run {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        production_plan: PathBuf,
        #[arg(long)]
        bootstrap: PathBuf,
    },
    AttachExternal {
        #[arg(long)]
        run_directory: PathBuf,
        #[arg(long)]
        external_trace: Vec<PathBuf>,
        #[arg(long)]
        external_summary: Vec<PathBuf>,
    },
    Spawner {
        #[arg(long)]
        scenario: PathBuf,
        #[arg(long)]
        result: PathBuf,
    },
    ServiceSpawner {
        #[arg(long)]
        service_run_id: String,
        #[arg(long)]
        service_scenario_id: String,
        #[arg(long)]
        scenario: PathBuf,
        #[arg(long)]
        result: PathBuf,
        #[arg(long)]
        source_process_id: u32,
        #[arg(long)]
        source_creation_time: u64,
        #[arg(long)]
        source_token: u64,
    },
    Target {
        #[arg(long)]
        pipe: String,
        #[arg(long)]
        nonce: String,
        #[arg(long)]
        desktop: String,
    },
}

fn main() {
    let result = match Cli::parse().role {
        Role::Run {
            output,
            production_plan,
            bootstrap,
        } => controller::run(&output, &production_plan, &bootstrap),
        Role::AttachExternal {
            run_directory,
            external_trace,
            external_summary,
        } => controller::attach_external(&run_directory, &external_trace, &external_summary),
        Role::Spawner { scenario, result } => spawner::run(&scenario, &result),
        Role::ServiceSpawner {
            service_run_id,
            service_scenario_id,
            scenario,
            result,
            source_process_id,
            source_creation_time,
            source_token,
        } => spawner::run_as_service(
            &spawner::lab_service_name(&service_run_id, &service_scenario_id),
            &scenario,
            &result,
            source_process_id,
            source_creation_time,
            source_token,
        ),
        Role::Target {
            pipe,
            nonce,
            desktop,
        } => target::run(&pipe, &nonce, &desktop),
    };
    if let Err(error) = result {
        eprintln!("memcordon-windows-loader-lab: {error}");
        std::process::exit(2);
    }
}
