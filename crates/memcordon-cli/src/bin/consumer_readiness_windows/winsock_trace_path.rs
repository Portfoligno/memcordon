//! Separate root and peer startup observations without overwriting either role.
pub fn startup_trace_leaf(peer: bool) -> &'static str {
    if peer {
        "peer-winsock-startup-trace.json"
    } else {
        "winsock-startup-trace.json"
    }
}
