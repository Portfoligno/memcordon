#![cfg_attr(feature = "test-support", allow(dead_code))]

#[cfg(all(target_os = "windows", not(target_feature = "crt-static")))]
compile_error!("the target desktop bootstrap requires a statically linked CRT");

use std::ffi::OsString;

#[cfg(target_os = "windows")]
#[path = "memcordon-sealed-agent/inspection_schema.rs"]
mod inspection_schema;
#[cfg(target_os = "windows")]
#[path = "memcordon-sealed-agent/package.rs"]
mod package;
#[cfg(target_os = "windows")]
#[path = "memcordon-sealed-agent/protocol.rs"]
mod protocol;
#[cfg(target_os = "windows")]
#[path = "memcordon-sealed-agent/windows/mod.rs"]
mod windows;

#[cfg(target_os = "windows")]
include!(concat!(env!("OUT_DIR"), "/source_commit.rs"));

fn main() {
    #[cfg(target_os = "windows")]
    {
        windows::token::revert_entry_thread_token().unwrap_or_else(|_| std::process::abort());
        let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
        let result = match arguments.as_slice() {
            [role, pipe_name, nonce] if role == "holder" => {
                windows::target_desktop_holder(pipe_name, nonce)
            }
            [role, pipe_name, nonce, desktop] if role == "loader-control" => {
                windows::target_desktop_loader_control(pipe_name, nonce, desktop)
            }
            [role, pipe_name, nonce, desktop] if role == "probe" => {
                windows::target_desktop_probe(pipe_name, nonce, desktop)
            }
            _ => Err("target desktop bootstrap requires holder <pipe-name> <nonce>, loader-control <pipe-name> <nonce> <station\\desktop>, or probe <pipe-name> <nonce> <station\\desktop>".to_owned()),
        };
        if let Err(error) = result {
            eprintln!("{error}");
            std::process::exit(windows::target_desktop_bootstrap_failure_status());
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = OsString::new();
        eprintln!("target desktop bootstrap is Windows-only");
        std::process::exit(1);
    }
}
