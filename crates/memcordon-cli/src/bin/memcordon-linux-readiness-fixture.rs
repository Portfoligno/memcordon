#[cfg(target_os = "linux")]
#[path = "consumer_readiness_linux/mod.rs"]
mod fixture;
#[cfg(target_os = "linux")]
#[path = "consumer_readiness_native_export.rs"]
mod native_export;

fn main() {
    #[cfg(target_os = "linux")]
    if let Err(error) = fixture::run() {
        eprintln!("linux readiness fixture: {error}");
        std::process::exit(1);
    }
    #[cfg(not(target_os = "linux"))]
    panic!("Linux native readiness fixture requires Linux");
}
