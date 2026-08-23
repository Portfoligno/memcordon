use std::ffi::OsString;

fn main() {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let result = match arguments.as_slice() {
        [command] if command == "serve" => serve(),
        [command] if command == "qualify" => qualify(),
        [package, operation] if package == "package" => {
            memcordon_sealed_agent::package::run(operation, false)
        }
        [package, operation, option]
            if package == "package" && option == "--ephemeral-ci" =>
        {
            memcordon_sealed_agent::package::run(operation, true)
        }
        _ => Err("usage: memcordon-sealed-agent serve|qualify|package verify|install|upgrade|uninstall [--ephemeral-ci]".to_owned()),
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(125);
    }
}

fn serve() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        return memcordon_sealed_agent::linux::service::serve();
    }
    #[cfg(not(target_os = "linux"))]
    Err("the sealed provider service is not implemented on this platform".to_owned())
}

fn qualify() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        println!(
            "{}",
            memcordon_sealed_agent::linux::qualification::qualify()?.render()
        );
        return Ok(());
    }
    #[cfg(not(target_os = "linux"))]
    Err("sealed qualification is unavailable on this platform".to_owned())
}
