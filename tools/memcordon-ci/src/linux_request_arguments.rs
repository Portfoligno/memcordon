//! Public CLI spelling for the original request lifetime; no shell parsing.
use memcordon_core::Lifetime;
use std::ffi::OsString;

pub fn wait_arguments(lifetime: Lifetime) -> [OsString; 2] {
    [
        "--wait-for".into(),
        match lifetime {
            Lifetime::Command => "command",
            Lifetime::Workload => "workload",
        }
        .into(),
    ]
}
