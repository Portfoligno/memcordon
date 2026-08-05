use std::ffi::OsString;
use std::fs::File;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

#[cfg(target_os = "linux")]
use memcordon::MemcordonExecutable;
use memcordon::exit_mapping::{error_exit_code, outcome_exit_code};
use memcordon::invocation::LimitToken;
use memcordon::{CommandSpec, Enforcement, Limiter, Policy};

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    #[cfg(target_os = "linux")]
    let memcordon_executable = {
        if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--memcordon")) {
            eprintln!("embedding fixture requires --memcordon ABSOLUTE_PATH on Linux");
            std::process::exit(2);
        }
        let Some(path) = arguments.next() else {
            eprintln!("embedding fixture --memcordon requires a path");
            std::process::exit(2);
        };
        match MemcordonExecutable::new(path) {
            Ok(executable) => executable,
            Err(error) => {
                eprintln!("embedding fixture: {error}");
                std::process::exit(2);
            }
        }
    };
    let Some(limit) = arguments.next() else {
        eprintln!("embedding fixture requires +MEMORY before the target program");
        std::process::exit(2);
    };
    let memory = match LimitToken::parse(limit) {
        Ok(limit) => limit.bytes,
        Err(error) => {
            eprintln!("embedding fixture error[{}]: {}", error.code, error.message);
            std::process::exit(2);
        }
    };
    let Some(program) = arguments.next() else {
        eprintln!("embedding fixture requires a target program");
        std::process::exit(2);
    };
    let target = CommandSpec::new(program).args(arguments.collect::<Vec<OsString>>());
    let mut policy = Policy::new(memory);
    policy.enforcement = Enforcement::Hard;
    let _inherited_descriptor_probe = File::open("/dev/null").ok();
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let host_worker = thread::spawn(move || {
        while !worker_stop.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(10));
        }
    });
    let limiter = Limiter::new(policy).command(target);
    #[cfg(target_os = "linux")]
    let limiter = limiter.memcordon_executable(memcordon_executable);
    let result = limiter.run();
    stop.store(true, Ordering::Release);
    let _ = host_worker.join();
    let code = match result {
        Ok(outcome) => outcome_exit_code(&outcome),
        Err(error) => {
            eprintln!("embedding fixture: {error}");
            error_exit_code(&error)
        }
    };
    std::process::exit(code);
}
