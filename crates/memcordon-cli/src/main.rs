mod args;
mod commands;
mod exit_mapping;

use clap::Parser;

fn main() {
    let cli = args::Cli::parse();
    let code = match cli.command {
        args::Command::Run(args) => commands::run_command(args),
        args::Command::Probe { json } => commands::probe_command(json),
        args::Command::Explain(args) => commands::explain_command(args),
        args::Command::Cleanup { dry_run } => commands::cleanup_command(dry_run),
        args::Command::Version { verbose } => commands::version_command(verbose),
        args::Command::Compat(args) => commands::compat_command(args),
        args::Command::Launcher {
            control_fd,
            command,
        } => commands::launcher(control_fd, command),
        args::Command::Guardian {
            control_fd,
            process_group,
        } => commands::guardian(control_fd, process_group),
    };
    std::process::exit(code);
}
