mod commands;
mod presentation;

use memcordon::invocation::{
    CLEAN_USAGE, DOCTOR_USAGE, HelpKind, Invocation, PLAN_USAGE, ROOT_USAGE, route,
};
use presentation::Presentation;

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
    let presentation = Presentation::automatic();
    let code = match route(&argv) {
        Ok(Invocation::Execute(args)) => commands::execute(args, &presentation),
        Ok(Invocation::Doctor(args)) => commands::doctor(args, &presentation),
        Ok(Invocation::Plan(args)) => commands::plan(args, &presentation),
        Ok(Invocation::Clean(args)) => commands::clean(args, &presentation),
        Ok(Invocation::Version) => {
            let mut out = presentation.stdout();
            presentation::write_version(&mut out, env!("CARGO_PKG_VERSION"))
                .expect("version output should be writable");
            0
        }
        Ok(Invocation::Help(kind)) => {
            let help = match kind {
                HelpKind::Root => ROOT_USAGE,
                HelpKind::Doctor => DOCTOR_USAGE,
                HelpKind::Plan => PLAN_USAGE,
                HelpKind::Clean => CLEAN_USAGE,
            };
            let mut out = presentation.stdout();
            presentation::write_help(&mut out, help).expect("help output should be writable");
            0
        }
        Err(error) if error.code == "MCCLI-HELP" => {
            let mut out = presentation.stdout();
            presentation::write_help(&mut out, &error.message)
                .expect("topic help output should be writable");
            0
        }
        Err(error) => {
            let mut out = presentation.stderr();
            presentation::write_usage_error(&mut out, error.code, &error.message)
                .expect("usage diagnostic should be writable");
            if let Some(help) = error.help {
                presentation::write_help(&mut out, help).expect("usage help should be writable");
            }
            2
        }
    };
    std::process::exit(code);
}
