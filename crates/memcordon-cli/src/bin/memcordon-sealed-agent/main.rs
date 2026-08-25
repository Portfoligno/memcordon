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

fn probe() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        println!("{}", package::probe_provider()?.render());
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    Err("sealed provider probe is unavailable on this platform".to_owned())
}

fn serve() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        linux::service::serve()
    }
    #[cfg(not(target_os = "linux"))]
    Err("the sealed provider service is not implemented on this platform".to_owned())
}

fn launch_broker() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        linux::launcher::serve()
    }
    #[cfg(not(target_os = "linux"))]
    Err("the sealed launch broker is not implemented on this platform".to_owned())
}

fn qualify() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let _qualification_lease = linux::service::acquire_qualification_lease()?;
        println!("{}", linux::qualification::qualify()?.render());
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    Err("sealed qualification is unavailable on this platform".to_owned())
}
