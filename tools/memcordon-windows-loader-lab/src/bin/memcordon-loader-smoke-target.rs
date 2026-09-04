#[cfg(windows)]
fn main() {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let [action, pipe, nonce, desktop] = arguments.as_slice() else {
        std::process::exit(2);
    };
    if action != "loader-control" {
        std::process::exit(2);
    }
    let (Some(pipe), Some(nonce), Some(desktop)) =
        (pipe.to_str(), nonce.to_str(), desktop.to_str())
    else {
        std::process::exit(2);
    };
    if let Err(error) = memcordon_windows_loader_lab::target::run(pipe, nonce, desktop) {
        eprintln!("memcordon-loader-smoke-target: {error}");
        std::process::exit(3);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("memcordon-loader-smoke-target is Windows-only");
    std::process::exit(2);
}
