#[cfg(target_os = "windows")]
#[path = "memcordon-sealed-agent/admission.rs"]
mod admission;
#[cfg(target_os = "windows")]
#[path = "memcordon-sealed-agent/inspection_schema.rs"]
mod inspection_schema;
#[cfg(target_os = "windows")]
#[path = "memcordon-sealed-agent/package.rs"]
mod package;
#[cfg(target_os = "windows")]
#[path = "memcordon-sealed-agent/policy_registry.rs"]
mod policy_registry;
#[cfg(target_os = "windows")]
#[path = "memcordon-sealed-agent/protocol.rs"]
mod protocol;
#[cfg(target_os = "windows")]
#[path = "memcordon-sealed-agent/windows/mod.rs"]
mod windows;

#[cfg(target_os = "windows")]
include!(concat!(env!("OUT_DIR"), "/source_commit.rs"));

fn main() {
    #[cfg(feature = "test-support")]
    if std::env::args_os()
        .skip(1)
        .eq([std::ffi::OsString::from("--provider-contract-fingerprint")])
    {
        println!(
            "{}",
            memcordon_core::sealed_provider::fingerprint::provider_contract_fingerprint()
        );
        return;
    }
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--version")) {
        println!("memcordon-session-broker {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    #[cfg(target_os = "windows")]
    {
        windows::token::revert_entry_thread_token().unwrap_or_else(|_| std::process::abort());
        if let Err(error) = windows::session_broker::run() {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        eprintln!("memcordon-session-broker is Windows-only");
        std::process::exit(1);
    }
}
