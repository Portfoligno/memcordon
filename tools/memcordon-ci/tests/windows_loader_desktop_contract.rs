const DESKTOP_LOADER_SOURCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/process_impl/desktop_loader.rs"
));
const LAUNCH_CORE_NATIVE_SOURCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/memcordon-windows-launch-core/src/native.rs"
));
const PACKAGE_LOADER_CHANNEL_IMPL_EVIDENCE: &str =
    "impl LoaderReadyChannel<PackageLoaderProcess> for PackageLoaderChannel<'_> {";
const AWAIT_READY_EVIDENCE: &str = "    fn await_ready(";
const ATTEST_CONTAINMENT_EVIDENCE: &str = "    fn attest_containment(";
const AUTHENTICATION_EVIDENCE: &str = "authenticate_target_desktop_bootstrap_client(";
const OBSERVED_BINDING_EVIDENCE: &str = "observed_desktop_binding: Some(observed_desktop_binding),";
const BINDING_VALIDATION_EVIDENCE: &str =
    "validate_loader_control_desktop_evidence(self.exact_desktop, &desktop_evidence)?;";
const RELEASE_EVIDENCE: &str =
    "super::pipe::TargetDesktopBootstrapPipeOperation::LoaderControlReleaseWrite,";

fn source_offset(source: &str, evidence: &str) -> usize {
    source
        .find(evidence)
        .unwrap_or_else(|| panic!("required source evidence is absent: {evidence}"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LoaderControlAwaitReadyOffsets {
    authentication: usize,
    observed_binding: usize,
    binding_validation: usize,
    release: usize,
}

impl LoaderControlAwaitReadyOffsets {
    fn are_ordered(self) -> bool {
        self.authentication < self.observed_binding
            && self.observed_binding < self.binding_validation
            && self.binding_validation < self.release
    }
}

fn loader_control_await_ready_offsets(source: &str) -> LoaderControlAwaitReadyOffsets {
    let normalized_source = source.replace("\r\n", "\n");
    let channel = &normalized_source
        [source_offset(&normalized_source, PACKAGE_LOADER_CHANNEL_IMPL_EVIDENCE)..];
    let await_ready = &channel[source_offset(channel, AWAIT_READY_EVIDENCE)..];
    let await_ready = &await_ready[..source_offset(await_ready, ATTEST_CONTAINMENT_EVIDENCE)];
    LoaderControlAwaitReadyOffsets {
        authentication: source_offset(await_ready, AUTHENTICATION_EVIDENCE),
        observed_binding: source_offset(await_ready, OBSERVED_BINDING_EVIDENCE),
        binding_validation: source_offset(await_ready, BINDING_VALIDATION_EVIDENCE),
        release: source_offset(await_ready, RELEASE_EVIDENCE),
    }
}

fn loader_control_order_fixture(order: [&str; 4]) -> String {
    [
        RELEASE_EVIDENCE,
        BINDING_VALIDATION_EVIDENCE,
        OBSERVED_BINDING_EVIDENCE,
        AUTHENTICATION_EVIDENCE,
        PACKAGE_LOADER_CHANNEL_IMPL_EVIDENCE,
        AWAIT_READY_EVIDENCE,
        order[0],
        order[1],
        order[2],
        order[3],
        ATTEST_CONTAINMENT_EVIDENCE,
    ]
    .join("\n")
}

#[test]
fn suspended_attestation_never_reads_a_remote_thread_desktop() {
    assert!(
        !DESKTOP_LOADER_SOURCE.contains("suspended_thread_desktop_name"),
        "the invalid remote suspended-thread desktop helper must stay removed"
    );
    assert!(
        !DESKTOP_LOADER_SOURCE.contains("GetThreadDesktop(process.native.thread_id())"),
        "the parent must not query the suspended child thread's USER binding"
    );
    assert!(
        DESKTOP_LOADER_SOURCE.contains("GetThreadDesktop(GetCurrentThreadId())"),
        "the running child must observe its own current-thread desktop"
    );
}

#[test]
fn exact_plan_desktop_material_remains_the_native_lpdesktop_input() {
    assert!(
        LAUNCH_CORE_NATIVE_SOURCE.contains("request.desktop.strip_suffix(&[0])"),
        "native validation must strip and require the desktop terminator"
    );
    assert!(
        LAUNCH_CORE_NATIVE_SOURCE.contains("\"concrete-plan-mismatch\""),
        "native validation must retain a typed plan/material mismatch"
    );
    assert!(
        LAUNCH_CORE_NATIVE_SOURCE
            .contains("startup.StartupInfo.lpDesktop = request.desktop.as_mut_ptr();"),
        "the exact validated request buffer must remain the lpDesktop input"
    );
}

#[test]
fn authenticated_child_observation_is_validated_before_release() {
    let offsets = loader_control_await_ready_offsets(DESKTOP_LOADER_SOURCE);
    assert!(
        offsets.are_ordered(),
        "package loader-control must authenticate its pipe peer, accept the child-observed station and desktop pair, validate that binding, and only then release"
    );
}

#[test]
fn loader_control_order_contract_is_line_ending_independent_and_rejects_reordering() {
    let ordered_lf = loader_control_order_fixture([
        AUTHENTICATION_EVIDENCE,
        OBSERVED_BINDING_EVIDENCE,
        BINDING_VALIDATION_EVIDENCE,
        RELEASE_EVIDENCE,
    ]);
    let ordered_crlf = ordered_lf.replace('\n', "\r\n");
    assert_eq!(
        loader_control_await_ready_offsets(&ordered_lf),
        loader_control_await_ready_offsets(&ordered_crlf),
        "LF and CRLF source must resolve the same scoped transition offsets"
    );
    assert!(loader_control_await_ready_offsets(&ordered_lf).are_ordered());

    let reordered_cases = [
        [
            OBSERVED_BINDING_EVIDENCE,
            AUTHENTICATION_EVIDENCE,
            BINDING_VALIDATION_EVIDENCE,
            RELEASE_EVIDENCE,
        ],
        [
            AUTHENTICATION_EVIDENCE,
            BINDING_VALIDATION_EVIDENCE,
            OBSERVED_BINDING_EVIDENCE,
            RELEASE_EVIDENCE,
        ],
        [
            AUTHENTICATION_EVIDENCE,
            OBSERVED_BINDING_EVIDENCE,
            RELEASE_EVIDENCE,
            BINDING_VALIDATION_EVIDENCE,
        ],
    ];
    for reordered in reordered_cases {
        assert!(
            !loader_control_await_ready_offsets(&loader_control_order_fixture(reordered))
                .are_ordered(),
            "every reordered package loader-control transition must be rejected"
        );
    }
}
