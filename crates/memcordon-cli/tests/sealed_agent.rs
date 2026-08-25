#![allow(dead_code)]

#[path = "../src/bin/memcordon-sealed-agent/inspection_schema.rs"]
mod inspection_schema;
#[path = "../src/bin/memcordon-sealed-agent/package.rs"]
mod package;
#[path = "../src/bin/memcordon-sealed-agent/protocol.rs"]
mod protocol;
#[path = "../src/bin/memcordon-sealed-agent/rejection.rs"]
mod rejection;
#[path = "../src/bin/memcordon-sealed-agent/request.rs"]
mod request;
#[path = "../src/bin/memcordon-sealed-agent/state.rs"]
mod state;

#[cfg(target_os = "linux")]
#[path = "../src/bin/memcordon-sealed-agent/linux/mod.rs"]
mod linux;

#[cfg(target_os = "windows")]
#[path = "../src/bin/memcordon-sealed-agent/windows/mod.rs"]
mod windows;

include!(concat!(env!("OUT_DIR"), "/source_commit.rs"));

#[path = "sealed_agent/attempt_record_atomic.rs"]
mod attempt_record_atomic;
#[path = "sealed_agent/cgroup_grace.rs"]
mod cgroup_grace;
#[path = "sealed_agent/exec_status.rs"]
mod exec_status;
#[path = "sealed_agent/guardian_terminal.rs"]
mod guardian_terminal;
#[path = "sealed_agent/launcher_activation.rs"]
mod launcher_activation;
#[path = "sealed_agent/linux_cgroup_readback.rs"]
mod linux_cgroup_readback;
#[path = "sealed_agent/linux_faults.rs"]
mod linux_faults;
#[path = "sealed_agent/linux_package.rs"]
mod linux_package;
#[path = "sealed_agent/linux_provider.rs"]
mod linux_provider;
#[path = "sealed_agent/linux_recovery.rs"]
mod linux_recovery;
#[path = "sealed_agent/linux_recovery_inventory.rs"]
mod linux_recovery_inventory;
#[path = "sealed_agent/linux_sealed.rs"]
mod linux_sealed;
#[path = "sealed_agent/linux_service.rs"]
mod linux_service;
#[path = "sealed_agent/linux_startup.rs"]
mod linux_startup;
#[path = "sealed_agent/namespace_startup.rs"]
mod namespace_startup;
#[path = "sealed_agent/package.rs"]
mod package_tests;
#[path = "sealed_agent/package_verification.rs"]
mod package_verification;
#[path = "sealed_agent/protocol.rs"]
mod protocol_tests;
#[path = "sealed_agent/rejection.rs"]
mod rejection_tests;
#[path = "sealed_agent/request.rs"]
mod request_tests;
