//! Independent black-box controller. No production or testkit supervision code
//! is linked into this executable.
#[cfg(target_os = "macos")]
mod native;

fn main() {
    #[cfg(target_os = "macos")]
    let result = native::run();
    #[cfg(not(target_os = "macos"))]
    let result: Result<(), Box<dyn std::error::Error>> =
        Err("macOS qualification requires a native macOS host".into());
    if let Err(error) = result {
        eprintln!("deadline oracle: {error}");
        std::process::exit(1);
    }
}
