#[cfg(target_os = "linux")]
mod credentials;
#[cfg(target_os = "linux")]
mod namespace;
#[cfg(target_os = "linux")]
mod process;
mod registry;

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() == Some(std::ffi::OsStr::new("--fixture-inventory-json")) {
        if arguments.next().is_some() {
            std::process::exit(2);
        }
        println!(
            "{}",
            serde_json::to_string(registry::COMMANDS).expect("fixture inventory serializes")
        );
        return;
    }
    #[cfg(target_os = "linux")]
    {
        let mode = std::env::args().nth(1).unwrap_or_else(|| "exit".to_owned());
        let command = registry::COMMANDS
            .iter()
            .find(|entry| entry.name == mode)
            .unwrap_or_else(|| std::process::exit(2));
        (command.handler)();
    }
    #[cfg(not(target_os = "linux"))]
    std::process::exit(125);
}
