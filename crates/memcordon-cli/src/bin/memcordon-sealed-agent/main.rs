#![cfg_attr(feature = "test-support", allow(dead_code))]

use std::ffi::OsString;

mod admission;
mod inspection_schema;
#[cfg(target_os = "linux")]
mod linux;
mod package;
mod policy_registry;
#[cfg(target_os = "linux")]
mod private_policy_fixture_schema;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod protocol;
#[cfg(target_os = "linux")]
mod rejection;
mod release_cli_cutover;
#[cfg(target_os = "linux")]
mod request;
#[cfg(target_os = "windows")]
mod windows;

include!(concat!(env!("OUT_DIR"), "/source_commit.rs"));

const HELP: &str = "\
MemCordon sealed-provider administration

Usage:
  memcordon-sealed-agent --version
  memcordon-sealed-agent --help
  memcordon-sealed-agent serve
  memcordon-sealed-agent launch-broker
  memcordon-sealed-agent probe
  memcordon-sealed-agent package <install|upgrade|inspect|verify|uninstall> [--json]
  memcordon-sealed-agent package policy apply --file PATH
  memcordon-sealed-agent package policy inspect --json
  memcordon-sealed-agent package policy entrypoint install --definition PATH --source PATH

Package administration inspects and manages installed provider files.
";

fn main() {
    #[cfg(target_os = "windows")]
    let entry_thread_token_transition =
        windows::token::revert_entry_thread_token().unwrap_or_else(|_| std::process::abort());
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let retired = release_cli_cutover::retired_release_command(
        release_cli_cutover::ReleasePlatform::current(),
        &arguments,
    );
    let result = if retired {
        Err("retired release command is unavailable".into())
    } else {
        match arguments.as_slice() {
            [command] if command == "--version" || command == "-V" => {
                println!("memcordon-sealed-agent {}", env!("CARGO_PKG_VERSION"));
                Ok(())
            }
            [command] if command == "--help" || command == "-h" => {
                print!("{HELP}");
                Ok(())
            }
            [command] if command == "serve" => serve(),
            [command] if command == "launch-broker" => launch_broker(),
            #[cfg(all(target_os = "linux", feature = "private-tcp"))]
            [command] if command == "network-launch-broker" => linux::launcher::serve_network(),
            [command] if command == "probe" => probe(),
            #[cfg(target_os = "linux")]
            [command, directory] if command == "__export-unit-files" => {
                package::export_unit_files(std::path::Path::new(directory))
            }
            #[cfg(target_os = "linux")]
            [command] if command == "workload-profile-probe" => {
                linux::qualification::workload_profile_probe()
            }
            #[cfg(target_os = "windows")]
            [command] if command == "windows-control" => windows::control(),
            #[cfg(target_os = "windows")]
            [command] if command == "windows-launcher" => windows::launcher(),
            #[cfg(target_os = "windows")]
            [command, slot] if command == "windows-guardian-service" => {
                windows::guardian_service(slot)
            }
            #[cfg(target_os = "windows")]
            [command, guardian_arguments @ ..] if command == "windows-guardian" => {
                match windows::guardian(guardian_arguments) {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        eprintln!("{error}");
                        std::process::exit(error.exit_code() as i32);
                    }
                }
            }
            #[cfg(target_os = "windows")]
            [command] if command == "windows-certification-hold" => {
                std::thread::sleep(std::time::Duration::from_secs(5 * 60));
                Ok(())
            }
            #[cfg(target_os = "windows")]
            [command] if command == "windows-certification-hold-ready" => {
                use std::io::Write;

                let readiness = {
                    let mut stdout = std::io::stdout().lock();
                    stdout
                        .write_all(b"memcordon-certification-hold-ready\n")
                        .and_then(|()| stdout.flush())
                        .map_err(|error| error.to_string())
                };
                readiness.map(|()| std::thread::sleep(std::time::Duration::from_secs(5 * 60)))
            }
            #[cfg(target_os = "windows")]
            [command] if command == "windows-certification-memory" => {
                let mut allocations = Vec::new();
                loop {
                    let mut allocation = vec![0_u8; 1024 * 1024];
                    for byte in allocation.iter_mut().step_by(4096) {
                        *byte = 1;
                    }
                    allocations.push(allocation);
                    std::hint::black_box(&allocations);
                }
            }
            #[cfg(all(target_os = "windows", feature = "test-support"))]
            [command] if command == "windows-certification-ntstatus" => {
                std::process::exit(0xC000_013A_u32 as i32)
            }
            #[cfg(all(target_os = "windows", feature = "test-support"))]
            [command, code] if command == "windows-certification-exit" => {
                match code.to_string_lossy().parse::<u8>() {
                    Ok(code) => std::process::exit(i32::from(code)),
                    Err(error) => Err(format!("invalid certification exit code: {error}")),
                }
            }
            #[cfg(all(target_os = "windows", feature = "test-support"))]
            [command] if command == "windows-certification-grandchild" => {
                windows::qualification::grandchild_parent_canary()
            }
            #[cfg(all(target_os = "windows", feature = "test-support"))]
            [command, marker] if command == "windows-certification-cleanup-churn" => {
                windows::qualification::cleanup_churn_canary(marker)
            }
            #[cfg(all(target_os = "windows", feature = "test-support"))]
            [command] if command == "windows-certification-orphan" => {
                windows::qualification::orphan_descendant_canary()
            }
            #[cfg(target_os = "windows")]
            [command] if command == "windows-recovery-status" => windows_recovery_status(),
            #[cfg(target_os = "windows")]
            [command] if command == "windows-provider-state-absent" => {
                windows::package::provider_state_absent().map(|absent| println!("{absent}"))
            }
            #[cfg(all(target_os = "windows", feature = "test-support"))]
            [command, canary_handles @ ..] if command == "windows-certification-nested-target" => {
                windows::qualification::certification_nested_target_canary(canary_handles)
            }
            #[cfg(all(target_os = "windows", feature = "test-support"))]
            [
                command,
                receipt,
                attempt_binding,
                stdin,
                stdout,
                stderr,
                session,
            ] if command == "windows-certification-nested-child" => {
                windows::qualification::certification_nested_child(
                    &entry_thread_token_transition,
                    receipt,
                    attempt_binding,
                    [stdin, stdout, stderr],
                    session,
                )
            }
            #[cfg(target_os = "linux")]
            [package, policy, operation, json]
                if package == "package"
                    && policy == "policy"
                    && operation == "inspect"
                    && json == "--json" =>
            {
                policy_registry::inspect()
            }
            #[cfg(all(target_os = "linux", feature = "private-tcp"))]
            [
                package,
                policy,
                entrypoint,
                operation,
                definition,
                path,
                source,
                image,
            ] if package == "package"
                && policy == "policy"
                && entrypoint == "entrypoint"
                && operation == "install"
                && definition == "--definition"
                && source == "--source" =>
            {
                linux::entrypoint_install::install(
                    std::path::Path::new(path),
                    std::path::Path::new(image),
                )
            }
            #[cfg(target_os = "linux")]
            [package, policy, operation, file, path]
                if package == "package"
                    && policy == "policy"
                    && operation == "apply"
                    && file == "--file" =>
            {
                policy_registry::apply(std::path::Path::new(path))
            }
            #[cfg(target_os = "windows")]
            [package, policy, operation, json]
                if package == "package"
                    && policy == "policy"
                    && operation == "inspect"
                    && json == "--json" =>
            {
                windows::policy_registry::inspect()
            }
            #[cfg(target_os = "windows")]
            [package, policy, operation, file, path]
                if package == "package"
                    && policy == "policy"
                    && operation == "apply"
                    && file == "--file" =>
            {
                windows::policy_registry::apply(std::path::Path::new(path))
            }
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            [package, operation] if package == "package" => package::run(operation, false),
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            [package, operation, json] if package == "package" && json == "--json" => {
                package::run(operation, true)
            }
            _ => Err(format!("invalid arguments\n\n{HELP}")),
        }
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(125);
    }
}

#[cfg(target_os = "windows")]
fn windows_recovery_status() -> Result<(), String> {
    println!("{}", windows::qualification::recovery_status()?);
    Ok(())
}

fn probe() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        println!("{}", package::probe_provider()?.render());
        Ok(())
    }
    #[cfg(target_os = "windows")]
    {
        println!(
            "{}",
            serde_json::to_string_pretty(&windows::qualification::probe()?)
                .map_err(|error| error.to_string())?
        );
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    Err("sealed provider probe is unavailable on this platform".to_owned())
}

fn serve() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        linux::service::serve()
    }
    #[cfg(target_os = "windows")]
    {
        windows::control()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    Err("the sealed provider service is not implemented on this platform".to_owned())
}

fn launch_broker() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        linux::launcher::serve()
    }
    #[cfg(target_os = "windows")]
    {
        windows::launcher()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    Err("the sealed launch broker is not implemented on this platform".to_owned())
}
