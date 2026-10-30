//! Standalone real-rustc observer for the shared Cargo jobserver fixture.
mod compiler_pool_protocol;
use compiler_pool_protocol::{Protocol, Role};
use std::{io, process::{Command, ExitStatus}};

fn run() -> io::Result<ExitStatus> {
    let mut arguments = std::env::args_os().skip(1);
    let compiler = arguments.next().expect("actual rustc argv");
    let arguments: Vec<_> = arguments.collect();
    let compilation = arguments
        .iter()
        .any(|arg| arg.to_str().is_some_and(|arg| arg.starts_with("--emit")))
        && !arguments
            .iter()
            .any(|arg| arg.to_str().is_some_and(|arg| arg.starts_with("--print")));
    if !compilation { return Command::new(compiler).args(arguments).status(); }
    let executable = std::env::current_exe()?;
    let role = match executable.file_name().and_then(|name| name.to_str()) {
        Some("product-wrapper") => Role::Product,
        Some("native-wrapper") => Role::Native,
        _ => return Err(io::Error::other("compiler observer role path differs")),
    };
    let protocol = Protocol::open(executable.parent().expect("owned wrapper directory"))?;
    let admission = protocol.admit(role)?;
    let result = protocol.wait_gate(role).and_then(|()| Command::new(compiler).args(arguments).status());
    let settlement = admission.finish();
    match (result, settlement) {
        (Ok(status), Ok(())) => Ok(status),
        (Err(error), Ok(())) => Err(error),
        (original, Err(error)) => Err(io::Error::other(format!("original rustc result={original:?}; observer retirement={error}"))),
    }
}
fn main() {
    let code = match run() { Ok(status) => status.code().unwrap_or(1), Err(error) => { eprintln!("compiler observer: {error}"); 1 } };
    std::process::exit(code);
}
