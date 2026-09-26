#![allow(dead_code)]

#[path = "../src/bin/memcordon-sealed-agent/admission.rs"]
mod admission;
#[path = "sealed_agent/native_workload_admission.rs"]
mod native_workload_admission;
#[path = "sealed_agent/policy_activation_v2.rs"]
mod policy_activation_v2;
#[path = "../src/bin/memcordon-sealed-agent/policy_registry.rs"]
mod policy_registry;
#[path = "sealed_agent/policy_revocation.rs"]
mod policy_revocation;

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
#[path = "sealed_agent/installed_release_qualification.rs"]
mod installed_release_qualification;
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
#[cfg(target_os = "linux")]
#[path = "sealed_agent/native_descriptor_custody.rs"]
mod native_descriptor_custody;
#[cfg(target_os = "linux")]
#[path = "sealed_agent/native_entrypoint.rs"]
mod native_entrypoint;
#[path = "sealed_agent/native_private_namespace_init.rs"]
mod native_private_namespace_init;
#[cfg(target_os = "linux")]
#[path = "sealed_agent/native_private_tcp.rs"]
mod native_private_tcp;
#[path = "sealed_agent/package.rs"]
mod package_tests;
#[path = "sealed_agent/package_verification.rs"]
mod package_verification;
#[cfg(target_os = "linux")]
#[path = "sealed_agent/private_attempt.rs"]
mod private_attempt;
#[cfg(target_os = "linux")]
#[path = "sealed_agent/private_guardian.rs"]
mod private_guardian;
#[path = "sealed_agent/private_host_prerequisites.rs"]
mod private_host_prerequisites;
#[path = "sealed_agent/private_host_receipt.rs"]
mod private_host_receipt;
#[path = "sealed_agent/private_probe_baseline.rs"]
mod private_probe_baseline;
#[path = "sealed_agent/private_probe_faults.rs"]
mod private_probe_faults;
#[path = "sealed_agent/private_probe_loss.rs"]
mod private_probe_loss;
#[cfg(target_os = "linux")]
#[path = "sealed_agent/private_public_abi_control.rs"]
mod private_public_abi_control;
#[path = "sealed_agent/private_public_abi_filtered.rs"]
mod private_public_abi_filtered;
#[cfg(target_os = "linux")]
#[path = "sealed_agent/private_public_provider.rs"]
mod private_public_provider;
#[cfg(target_os = "linux")]
#[path = "sealed_agent/private_public_release_case.rs"]
mod private_public_release_case;
#[cfg(target_os = "linux")]
#[path = "sealed_agent/private_public_reuse.rs"]
mod private_public_reuse;
#[cfg(target_os = "linux")]
#[path = "sealed_agent/private_qualification.rs"]
mod private_qualification;
#[cfg(target_os = "linux")]
#[path = "sealed_agent/private_release_alt_abi.rs"]
mod private_release_alt_abi;
#[path = "sealed_agent/private_release_alt_abi_raw.rs"]
mod private_release_alt_abi_raw;
#[path = "sealed_agent/private_release_ancestor.rs"]
mod private_release_ancestor;
#[path = "sealed_agent/private_release_attempt.rs"]
mod private_release_attempt;
#[path = "sealed_agent/private_release_caller.rs"]
mod private_release_caller;
#[cfg(target_os = "linux")]
#[path = "sealed_agent/private_release_case.rs"]
mod private_release_case;
#[path = "sealed_agent/private_release_child_gate.rs"]
mod private_release_child_gate;
#[path = "sealed_agent/private_release_child_owner.rs"]
mod private_release_child_owner;
#[path = "sealed_agent/private_release_children.rs"]
mod private_release_children;
#[path = "sealed_agent/private_release_dual_attempt.rs"]
mod private_release_dual_attempt;
#[path = "sealed_agent/private_release_socket_gate.rs"]
mod private_release_socket_gate;
#[path = "sealed_agent/private_release_terminal_join.rs"]
mod private_release_terminal_join;

#[path = "sealed_agent/private_release_denial.rs"]
mod private_release_denial;
#[path = "sealed_agent/private_release_descriptors.rs"]
mod private_release_descriptors;
#[path = "sealed_agent/private_release_exec.rs"]
mod private_release_exec;
#[path = "sealed_agent/private_release_filter.rs"]
mod private_release_filter;
#[path = "sealed_agent/private_release_frontend_loss.rs"]
mod private_release_frontend_loss;
#[path = "sealed_agent/private_release_gate.rs"]
mod private_release_gate;
#[path = "sealed_agent/private_release_guardian_loss.rs"]
mod private_release_guardian_loss;
#[path = "sealed_agent/private_release_host_state.rs"]
mod private_release_host_state;
#[path = "sealed_agent/private_release_identity.rs"]
mod private_release_identity;
#[path = "sealed_agent/private_release_result.rs"]
mod private_release_result;
#[cfg(target_os = "linux")]
#[path = "sealed_agent/private_release_run.rs"]
mod private_release_run;
#[path = "sealed_agent/private_release_topology.rs"]
mod private_release_topology;
#[cfg(target_os = "linux")]
#[path = "sealed_agent/private_release_unix_intent.rs"]
mod private_release_unix_intent;

#[path = "sealed_agent/private_release_raw.rs"]
mod private_release_raw;
#[cfg(target_os = "linux")]
#[path = "sealed_agent/private_v4_failure_matrix.rs"]
mod private_v4_failure_matrix;
#[cfg(target_os = "linux")]
#[path = "sealed_agent/private_v4_relay_terminal.rs"]
mod private_v4_relay_terminal;
#[cfg(target_os = "linux")]
#[path = "sealed_agent/private_version_recovery.rs"]
mod private_version_recovery;
#[path = "sealed_agent/protocol.rs"]
mod protocol_tests;
#[path = "sealed_agent/rejection.rs"]
mod rejection_tests;
#[path = "sealed_agent/request.rs"]
mod request_tests;
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
#[path = "sealed_agent/windows_qualification_artifacts.rs"]
mod windows_qualification_artifacts;
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
#[path = "sealed_agent/windows_token.rs"]
mod windows_token;
