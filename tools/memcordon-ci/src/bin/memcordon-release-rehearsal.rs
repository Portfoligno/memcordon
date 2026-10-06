//! Runner-local publication rehearsal helper, distributed separately from publisher/product.
use clap::{Parser, Subcommand};
use std::path::PathBuf;
#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Operation,
}
#[derive(Subcommand)]
enum Operation {
    Run {
        #[arg(long)]
        publisher: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        report_dir: PathBuf,
    },
    #[command(hide = true)]
    Serve {
        #[arg(long)]
        case: String,
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        ready: PathBuf,
    },
    #[command(hide = true)]
    TransportControl {
        #[arg(long)]
        fixture: PathBuf,
    },
    #[command(hide = true)]
    CancellationControl {
        #[arg(long)]
        publisher: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        fixture: PathBuf,
        #[arg(long)]
        result: PathBuf,
        #[arg(long)]
        identity: PathBuf,
    },
}
fn main() -> std::process::ExitCode {
    let result = match Cli::parse().command {
        Operation::Run {
            publisher,
            input,
            report_dir,
        } => std::env::current_exe()
            .map_err(memcordon_ci::CiError::from)
            .and_then(|helper| {
                memcordon_ci::rehearsal_support::coordinator::run(
                    &helper,
                    &publisher,
                    &input,
                    &report_dir,
                )
            }),
        Operation::Serve { case, state, ready } => {
            memcordon_ci::rehearsal_support::server::serve(&case, &state, &ready)
        }
        Operation::TransportControl { fixture } => transport_control(&fixture),
        Operation::CancellationControl {
            publisher,
            input,
            fixture,
            result,
            identity,
        } => memcordon_ci::rehearsal_support::coordinator::cancellation_control(
            &publisher, &input, &fixture, &result, &identity,
        ),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("release rehearsal failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
fn transport_control(fixture: &std::path::Path) -> memcordon_ci::Result<()> {
    use memcordon_ci::rehearsal_support::protocol::GITHUB_TOKEN;
    use memcordon_ci::release::http::Transport;
    let record = serde_json::from_slice(&std::fs::read(fixture)?)?;
    let transport = memcordon_ci::release::rehearsal::LoopbackTransport::new(record)?;
    let logical =
        url::Url::parse("https://api.github.com/repos/fixture/repository").expect("constant URL");
    let response = transport.request(
        "GET",
        &logical,
        &[("Authorization".into(), format!("Bearer {GITHUB_TOKEN}"))],
        &[],
        transport.deadline()?,
        4096,
    )?;
    if response.status != 200 {
        return Err(memcordon_ci::CiError::Message(
            "confined control read failed".into(),
        ));
    }
    let unknown = url::Url::parse("https://example.invalid/").expect("constant URL");
    if transport
        .request("GET", &unknown, &[], &[], transport.deadline()?, 4096)
        .is_ok()
    {
        return Err(memcordon_ci::CiError::Message(
            "unknown origin escaped confinement".into(),
        ));
    }
    Ok(())
}
