#![cfg_attr(feature = "test-support", allow(dead_code))]

use std::ffi::OsString;

mod inspection_schema;
#[cfg(target_os = "linux")]
mod linux;
mod package;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod protocol;
#[cfg(target_os = "linux")]
mod rejection;
#[cfg(target_os = "linux")]
mod request;
#[cfg(target_os = "windows")]
mod windows;

include!(concat!(env!("OUT_DIR"), "/source_commit.rs"));

const HELP: &str = "\
MemCordon sealed-provider administration

Usage:
  memcordon-sealed-agent --version
  memcordon-sealed-agent package inspect [--json]
  memcordon-sealed-agent package verify [--json]
  memcordon-sealed-agent package install [--ephemeral-ci]
  memcordon-sealed-agent package upgrade [--ephemeral-ci]
  memcordon-sealed-agent package uninstall [--ephemeral-ci]

Provider installation and mutation require root. Inspection is credential-free.
";

fn main() {
    #[cfg(target_os = "windows")]
    let entry_thread_token_transition =
        windows::token::revert_entry_thread_token().unwrap_or_else(|_| std::process::abort());
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let result = match arguments.as_slice() {
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
        [command] if command == "probe" => probe(),
        [command] if command == "qualify" => qualify(),
        #[cfg(target_os = "windows")]
        [command] if command == "windows-control" => windows::control(),
        #[cfg(target_os = "windows")]
        [command] if command == "windows-launcher" => windows::launcher(),
        #[cfg(target_os = "windows")]
        [command, slot] if command == "windows-guardian-service" => windows::guardian_service(slot),
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
        #[cfg(target_os = "windows")]
        [command] if command == "windows-certification-ntstatus" => {
            std::process::exit(0xC000_013A_u32 as i32)
        }
        #[cfg(target_os = "windows")]
        [command, code] if command == "windows-certification-exit" => {
            match code.to_string_lossy().parse::<u8>() {
                Ok(code) => std::process::exit(i32::from(code)),
                Err(error) => Err(format!("invalid certification exit code: {error}")),
            }
        }
        #[cfg(target_os = "windows")]
        [command] if command == "windows-certification-grandchild" => {
            windows::qualification::grandchild_parent_canary()
        }
        #[cfg(target_os = "windows")]
        [command, marker] if command == "windows-certification-cleanup-churn" => {
            windows::qualification::cleanup_churn_canary(marker)
        }
        #[cfg(target_os = "windows")]
        [command] if command == "windows-certification-orphan" => {
            windows::qualification::orphan_descendant_canary()
        }
        #[cfg(target_os = "windows")]
        [command, release_marker] if command == "windows-certification-frontend" => {
            windows::qualification::frontend_loss_client(release_marker)
        }
        #[cfg(target_os = "windows")]
        [command, fault, marker] if command == "windows-certification-authority-frontend" => {
            windows::qualification::authority_loss_client(fault, marker)
        }
        #[cfg(target_os = "windows")]
        [command] if command == "windows-authority-loss-observations" => {
            windows::qualification::authority_loss_observations()
                .and_then(|value| {
                    serde_json::to_string_pretty(&value).map_err(|error| error.to_string())
                })
                .map(|value| println!("{value}"))
        }
        #[cfg(target_os = "windows")]
        [command] if command == "windows-runtime-mutant-observations" => {
            windows::qualification::runtime_mutant_observations()
                .and_then(|value| {
                    serde_json::to_string_pretty(&value).map_err(|error| error.to_string())
                })
                .map(|value| println!("{value}"))
        }
        #[cfg(target_os = "windows")]
        [command, marker] if command == "windows-certification-recursive-mutant" => {
            windows::qualification::recursive_mutant_target(marker)
        }
        #[cfg(target_os = "windows")]
        [command] if command == "windows-certification-appcontainer" => {
            windows::qualification::appcontainer_rejection_client()
        }
        #[cfg(target_os = "windows")]
        [command, marker] if command == "windows-certification-marker" => {
            std::fs::write(marker, b"released\n").map_err(|error| error.to_string())
        }
        #[cfg(target_os = "windows")]
        [command, marker, tag, kind, handle]
            if command == "windows-certification-marker-hold"
                && tag == "windows-mutant-leaked-handle" =>
        {
            windows::qualification::leaked_handle_mutant_target(marker, kind, handle)
        }
        #[cfg(target_os = "windows")]
        [command, marker] if command == "windows-certification-marker-hold" => (|| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5 * 60);
            let mut heartbeat = 0_u64;
            while std::time::Instant::now() < deadline {
                std::fs::write(marker, format!("{} {heartbeat}\n", std::process::id()))
                    .map_err(|error| error.to_string())?;
                heartbeat = heartbeat.saturating_add(1);
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Ok(())
        })(),
        #[cfg(target_os = "windows")]
        [command] if command == "windows-recovery-status" => windows_recovery_status(),
        #[cfg(target_os = "windows")]
        [command] if command == "windows-certification-observations" => {
            windows_certification_observations()
        }
        #[cfg(target_os = "windows")]
        [command] if command == "windows-token-observations" => windows_token_observations(),
        #[cfg(target_os = "windows")]
        [command] if command == "windows-provider-state-absent" => {
            windows::package::provider_state_absent().map(|absent| println!("{absent}"))
        }
        #[cfg(target_os = "windows")]
        [command, canary_handles @ ..] if command == "windows-certification-target" => {
            windows::qualification::certification_target_canary(canary_handles)
        }
        #[cfg(target_os = "windows")]
        [command, canary_handles @ ..] if command == "windows-certification-nested-target" => {
            windows::qualification::certification_nested_target_canary(canary_handles)
        }
        #[cfg(target_os = "windows")]
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
        [package, operation] if package == "package" => package::run(operation, false, false),
        [package, operation, option] if package == "package" && option == "--json" => {
            package::run(operation, true, false)
        }
        [package, operation, option] if package == "package" && option == "--ephemeral-ci" => {
            package::run(operation, false, true)
        }
        _ => Err(format!("invalid arguments\n\n{HELP}")),
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

#[cfg(target_os = "windows")]
fn windows_certification_observations() -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(&windows::qualification::certification_observations()?)
            .map_err(|error| error.to_string())?
    );
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_token_observations() -> Result<(), String> {
    let observations = windows::qualification::token_observations()?;
    println!(
        "{}",
        serde_json::to_string_pretty(&observations).map_err(|error| error.to_string())?
    );
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

fn qualify() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let _qualification_lease = linux::service::acquire_qualification_lease()?;
        println!("{}", linux::qualification::qualify()?.render());
        Ok(())
    }
    #[cfg(target_os = "windows")]
    {
        let receipt = windows::qualification::qualify_and_store()?;
        println!(
            "{}",
            serde_json::to_string_pretty(&receipt).map_err(|error| error.to_string())?
        );
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    Err("sealed qualification is unavailable on this platform".to_owned())
}
