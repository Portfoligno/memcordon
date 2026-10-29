#![allow(dead_code)]

#[cfg(target_os = "linux")]
#[path = "../../../tools/memcordon-ci/tests/caller_observation.rs"]
mod caller_observation_publication;

#[path = "../src/bin/memcordon-sealed-agent/network_readiness.rs"]
mod network_readiness;

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
#[cfg(target_os = "linux")]
#[path = "sealed_agent/linux_resource_publication.rs"]
mod linux_resource_publication;
#[path = "sealed_agent/linux_sealed.rs"]
mod linux_sealed;
#[path = "sealed_agent/linux_service.rs"]
mod linux_service;
#[path = "sealed_agent/linux_startup.rs"]
mod linux_startup;
#[cfg(target_os = "linux")]
#[path = "sealed_agent/linux_transport_deadline.rs"]
mod linux_transport_deadline;
#[path = "sealed_agent/namespace_startup.rs"]
mod namespace_startup;
#[cfg(target_os = "linux")]
#[path = "sealed_agent/native_current_filter.rs"]
mod native_current_filter;
#[cfg(target_os = "linux")]
#[path = "sealed_agent/native_descriptor_custody.rs"]
mod native_descriptor_custody;
#[path = "sealed_agent/native_private_namespace_init.rs"]
mod native_private_namespace_init;
#[path = "sealed_agent/package.rs"]
mod package_tests;
#[path = "sealed_agent/package_verification.rs"]
mod package_verification;
#[cfg(target_os = "linux")]
#[path = "sealed_agent/private_guardian.rs"]
mod private_guardian;
#[path = "sealed_agent/protocol.rs"]
mod protocol_tests;
#[path = "sealed_agent/rejection.rs"]
mod rejection_tests;
#[path = "sealed_agent/request.rs"]
mod request_tests;
#[cfg(target_os = "windows")]
#[path = "sealed_agent/windows_current_install_inventory.rs"]
mod windows_current_install_inventory;
#[cfg(target_os = "windows")]
#[path = "sealed_agent/windows_guardian_startup.rs"]
mod windows_guardian_startup;
#[cfg(target_os = "windows")]
#[path = "sealed_agent/windows_handle_provenance.rs"]
mod windows_handle_provenance;
#[cfg(target_os = "windows")]
#[path = "sealed_agent/windows_install_intent.rs"]
mod windows_install_intent;
#[cfg(target_os = "windows")]
#[path = "sealed_agent/windows_postauthorization_retirement.rs"]
mod windows_postauthorization_retirement;
#[cfg(target_os = "windows")]
#[path = "sealed_agent/windows_qualification.rs"]
mod windows_qualification;
#[cfg(target_os = "windows")]
#[path = "sealed_agent/windows_replay_retention.rs"]
mod windows_replay_retention;
#[cfg(target_os = "windows")]
#[path = "sealed_agent/windows_security.rs"]
mod windows_security;
#[cfg(target_os = "windows")]
#[path = "sealed_agent/windows_service_manager.rs"]
mod windows_service_manager;
#[cfg(target_os = "windows")]
#[path = "sealed_agent/windows_terminal_transport.rs"]
mod windows_terminal_transport;
#[cfg(target_os = "windows")]
#[path = "sealed_agent/windows_token.rs"]
mod windows_token;
#[cfg(target_os = "windows")]
#[path = "sealed_agent/windows_v3_fixture.rs"]
mod windows_v3_fixture;
