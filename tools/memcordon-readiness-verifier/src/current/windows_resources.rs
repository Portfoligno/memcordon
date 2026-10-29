//! Independent requested-resource commitment for the special fixture's closed
//! `+4GiB +120s --sealed` invocation. Native wire limits are joined separately.
use serde::Serialize;

pub(super) fn default_resource_digest() -> String {
    crate::sha256(br#"{"boundary":"sealed","memory":null,"deadline":null,"wait_for":"command","signal_grace_ms":2000,"command_exit_grace_ms":0,"limit_grace_ms":0,"restart":{"enabled":false,"enablement_source":null,"configured_conditions":[],"limit":{"kind":"unlimited"},"backoff":null,"circuit_breaker":null}}"#)
}

pub fn special_resource_digest() -> String {
    #[derive(Serialize)]
    struct Kind {
        kind: &'static str,
    }
    #[derive(Serialize)]
    struct Swap {
        kind: &'static str,
        bytes: u64,
    }
    #[derive(Serialize)]
    struct Memory {
        limit_bytes: u64,
        enforcement: &'static str,
        metric: &'static str,
        poll_interval_ms: u64,
        swap: Swap,
    }
    #[derive(Serialize)]
    struct Deadline {
        duration_ms: u64,
        scope: &'static str,
        origin: Option<&'static str>,
        clock: &'static str,
    }
    #[derive(Serialize)]
    struct Restart {
        enabled: bool,
        enablement_source: Option<&'static str>,
        configured_conditions: Vec<&'static str>,
        limit: Kind,
        backoff: Option<()>,
        circuit_breaker: Option<()>,
    }
    #[derive(Serialize)]
    struct Resources {
        boundary: &'static str,
        memory: Memory,
        deadline: Deadline,
        wait_for: &'static str,
        signal_grace_ms: u64,
        command_exit_grace_ms: u64,
        limit_grace_ms: u64,
        restart: Restart,
    }
    let value = Resources {
        boundary: "sealed",
        memory: Memory {
            limit_bytes: 4 * 1024 * 1024 * 1024,
            enforcement: "auto",
            metric: "native",
            poll_interval_ms: 50,
            swap: Swap {
                kind: "bytes",
                bytes: 0,
            },
        },
        deadline: Deadline {
            duration_ms: 120000,
            scope: "attempt",
            origin: None,
            clock: "rust-instant",
        },
        wait_for: "command",
        signal_grace_ms: 2000,
        command_exit_grace_ms: 0,
        limit_grace_ms: 0,
        restart: Restart {
            enabled: false,
            enablement_source: None,
            configured_conditions: Vec::new(),
            limit: Kind { kind: "unlimited" },
            backoff: None,
            circuit_breaker: None,
        },
    };
    crate::sha256(&serde_json::to_vec(&value).expect("finite resource fields serialize"))
}
