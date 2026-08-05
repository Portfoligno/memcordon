mod commands;

use memcordon::invocation::{
    CLEAN_USAGE, DOCTOR_USAGE, HelpKind, Invocation, PLAN_USAGE, ROOT_USAGE, route,
};

fn main() {
    let argv: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    if let Some(internal) = commands::route_internal(&argv) {
        let code = match internal {
            Ok(internal) => commands::execute_internal(internal),
            Err(message) => {
                eprintln!("error[MCCLI-INTERNAL-PROTOCOL]: {message}");
                2
            }
        };
        std::process::exit(code);
    }
    let code = match route(&argv) {
        Ok(Invocation::Execute(args)) => commands::execute(args),
        Ok(Invocation::Doctor(args)) => commands::doctor(args),
        Ok(Invocation::Plan(args)) => commands::plan(args),
        Ok(Invocation::Clean(args)) => commands::clean(args),
        Ok(Invocation::Version) => {
            println!("memcordon {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Ok(Invocation::Help(kind)) => {
            println!(
                "{}",
                match kind {
                    HelpKind::Root => ROOT_USAGE,
                    HelpKind::Doctor => DOCTOR_USAGE,
                    HelpKind::Plan => PLAN_USAGE,
                    HelpKind::Clean => CLEAN_USAGE,
                }
            );
            0
        }
        Err(error) if error.code == "MCCLI-HELP" => {
            println!("{}", error.message);
            0
        }
        Err(error) => {
            eprintln!("error[{}]: {}", error.code, error.message);
            2
        }
    };
    std::process::exit(code);
}
