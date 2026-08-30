const PRIVILEGED_REASON: &str = "#[ignore = \"requires privileged Linux sealed certification\"]";
const CREDENTIAL_TRANSITION_REASON: &str =
    "#[ignore = \"requires privileged Linux sealed credential-transition certification\"]";

use memcordon_ci::sealed_selector::exact_test_name;

fn normalize_windows_source(source: &str) -> String {
    source.replace("\r\n", "\n").replace('\r', "\n")
}

fn semantic_function_region(source: &str, signature: &str, next_signature: &str) -> Option<String> {
    let mut lines = source.lines();
    loop {
        if lines.next()? == signature {
            break;
        }
    }
    let mut region = Vec::new();
    for line in lines {
        if line == next_signature {
            return Some(region.join("\n"));
        }
        region.push(line);
    }
    None
}

fn validate_windows_sddl_decoder_contract(security: &str) -> Result<(), String> {
    let descriptor = semantic_function_region(
        security,
        "fn descriptor_sddl(descriptor: *mut c_void, information: u32) -> Result<String, String> {",
        "unsafe fn decode_local_alloc_utf16(",
    )
    .ok_or_else(|| "Windows SDDL descriptor conversion boundary is absent".to_owned())?;
    for (needle, label) in [
        (
            "let string = LocalWideString::new(string)?;",
            "exactly-owned LocalAlloc SDDL string",
        ),
        (
            "LocalSize(string.raw().cast())",
            "native LocalAlloc byte-extent proof",
        ),
        (
            "decode_local_alloc_utf16(string.raw(), length, allocated_bytes)",
            "bounded SDDL decoder handoff",
        ),
    ] {
        require_source(&descriptor, needle, label)?;
    }

    let decoder = semantic_function_region(
        security,
        "unsafe fn decode_local_alloc_utf16(",
        "pub(crate) fn sddl_utf16_allocation_window(",
    )
    .ok_or_else(|| "Windows LocalAlloc SDDL decoder boundary is absent".to_owned())?;
    for (needle, label) in [
        (
            "sddl_utf16_allocation_window(reported_length, allocated_bytes)?",
            "allocation-window validation before pointer reads",
        ),
        ("for index in 0..readable_units {", "bounded first-NUL scan"),
        (
            "if unsafe { *string.add(index) } == 0 {",
            "first-NUL terminator selection",
        ),
        ("String::from_utf16(text)", "strict UTF-16 decoding"),
    ] {
        require_source(&decoder, needle, label)?;
    }

    let allocation = semantic_function_region(
        security,
        "pub(crate) fn sddl_utf16_allocation_window(",
        "pub(crate) fn utf16_nul_terminated_with_reported_length(",
    )
    .ok_or_else(|| "Windows SDDL allocation-window boundary is absent".to_owned())?;
    for (needle, label) in [
        (
            "if allocated_bytes % unit_bytes != 0 {",
            "whole-WCHAR allocation validation",
        ),
        (
            "if reported > allocation_units {",
            "reported-count allocation containment",
        ),
        (
            "usize::from(reported < allocation_units)",
            "LocalSize-proven optional terminator unit",
        ),
        (
            ".checked_add(usize::from(reported < allocation_units))",
            "overflow-safe readable window",
        ),
    ] {
        require_source(&allocation, needle, label)?;
    }

    let first_nul = semantic_function_region(
        security,
        "pub(crate) fn utf16_nul_terminated_with_reported_length(",
        "pub(crate) fn utf16_nul_terminated(buffer: &[u16]) -> Result<String, String> {",
    )
    .ok_or_else(|| "Windows pure SDDL decoder boundary is absent".to_owned())?;
    require_source(
        &first_nul,
        ".position(|unit| *unit == 0)",
        "pure first-NUL selection",
    )?;

    let local_wide = security
        .split_once("struct LocalWideString(*mut u16);")
        .and_then(|(_, tail)| tail.split_once("fn read_token_dacl("))
        .map(|(body, _)| body)
        .ok_or_else(|| "LocalAlloc SDDL ownership boundary is absent".to_owned())?;
    require_source(
        local_wide,
        "unsafe { LocalFree(self.0.cast()) };",
        "exactly-once LocalFree owner",
    )?;

    for forbidden in ["wcslen", "lstrlenW", "String::from_utf16_lossy"] {
        if descriptor.contains(forbidden) || decoder.contains(forbidden) {
            return Err(format!(
                "Windows SDDL decoder admits an unbounded or lossy operation: {forbidden}"
            ));
        }
    }
    Ok(())
}

fn validate_windows_live_kernel_access_check_contract(security: &str) -> Result<(), String> {
    let access_check = semantic_function_region(
        security,
        "    pub(crate) fn kernel_object_access_check_for_test(",
        "    pub fn converge_path(&self, applied_dacl: &Self, path: &std::path::Path) -> Result<(), String> {",
    )
    .ok_or_else(|| "live kernel-object AccessCheck boundary is absent".to_owned())?;
    for (needle, label) in [
        (
            "let policy_information = self.1;",
            "independent policy-comparison mask",
        ),
        (
            "let access_check_information = policy_information\n            | OWNER_SECURITY_INFORMATION\n            | GROUP_SECURITY_INFORMATION\n            | DACL_SECURITY_INFORMATION;",
            "AccessCheck owner/group/DACL prerequisites",
        ),
        (
            "GetKernelObjectSecurity(\n                handle,\n                access_check_information,\n                ptr::null_mut(),",
            "paired-mask live descriptor sizing",
        ),
        (
            "GetKernelObjectSecurity(\n                handle,\n                access_check_information,\n                descriptor.as_mut_ptr().cast(),",
            "paired-mask live descriptor fill",
        ),
        (
            "sizing_error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)",
            "exact descriptor sizing protocol",
        ),
        (
            "if needed == 0 || needed > allocated_bytes {",
            "descriptor fill bounds",
        ),
    ] {
        require_source(&access_check, needle, label)?;
    }
    require_source(
        security,
        "MCSEALED-WINDOWS-LIVE-ACCESS-CHECK:",
        "typed live AccessCheck diagnostics",
    )?;
    require_source_order(
        &access_check,
        &[
            (
                "let actual = descriptor.as_mut_ptr().cast();",
                "live descriptor identity",
            ),
            (
                "require_live_access_check_descriptor_shape(\n            actual,\n            policy_information,\n            access_check_information,",
                "live self-relative owner/group/DACL shape proof",
            ),
            (
                "self.verify_descriptor(actual, SecurityObjectKind::File)",
                "live descriptor policy verification",
            ),
            (
                "access_check_descriptor(\n            actual,",
                "AccessCheck on the same live descriptor",
            ),
        ],
    )?;
    for forbidden in [
        "access_check_descriptor(\n            self.0,",
        "MakeAbsoluteSD(",
        "AuthzAccessCheck",
        "CreateFileW(",
    ] {
        if access_check.contains(forbidden) {
            return Err(format!(
                "live kernel-object AccessCheck introduced a surrogate: {forbidden}"
            ));
        }
    }

    let shape = semantic_function_region(
        security,
        "fn require_live_access_check_descriptor_shape(",
        "pub(crate) fn write_restricted_behavior_attested(",
    )
    .ok_or_else(|| "live AccessCheck descriptor-shape boundary is absent".to_owned())?;
    for (needle, label) in [
        (
            "IsValidSecurityDescriptor(descriptor)",
            "whole-descriptor validity",
        ),
        (
            "revision != 1 || control & SE_SELF_RELATIVE == 0",
            "revision-1 self-relative representation",
        ),
        (
            "GetSecurityDescriptorOwner(descriptor,",
            "owner presence readback",
        ),
        (
            "if owner.is_null() || unsafe { IsValidSid(owner) } == 0 {",
            "owner SID validity",
        ),
        (
            "GetSecurityDescriptorGroup(descriptor,",
            "group presence readback",
        ),
        (
            "if group.is_null() || unsafe { IsValidSid(group) } == 0 {",
            "group SID validity",
        ),
        (
            "GetSecurityDescriptorDacl(",
            "decision-bearing DACL readback",
        ),
        (
            "if dacl_present == 0 || dacl.is_null() || unsafe { IsValidAcl(dacl) } == 0 {",
            "DACL validity",
        ),
    ] {
        require_source(&shape, needle, label)?;
    }
    Ok(())
}

#[derive(Clone)]
struct WindowsProductionSources {
    main: String,
    process: String,
    token: String,
    security: String,
    package: String,
    job: String,
    pipe: String,
    session_broker: String,
    service_manager: String,
    record: String,
    launcher: String,
    qualification: String,
    control: String,
    supervisor: String,
    platform: String,
    release_config: String,
    release_evidence: String,
    sealed_windows: String,
}

#[derive(Clone, Copy)]
enum WindowsProductionSource {
    Process,
    Token,
    Pipe,
    Security,
    Job,
    Package,
    SessionBroker,
    ServiceManager,
    Launcher,
    Qualification,
    Control,
    Supervisor,
    Platform,
    ReleaseConfig,
}

impl WindowsProductionSources {
    fn load() -> Self {
        Self {
            main: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/main.rs"
            )),
            process: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/process.rs"
            )),
            token: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/token.rs"
            )),
            security: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/security.rs"
            )),
            package: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/package.rs"
            )),
            job: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/job.rs"
            )),
            pipe: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/pipe.rs"
            )),
            session_broker: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/session_broker.rs"
            )),
            service_manager: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/service_manager.rs"
            )),
            record: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/record.rs"
            )),
            launcher: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/launcher_service.rs"
            )),
            qualification: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/qualification.rs"
            )),
            control: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/control_service.rs"
            )),
            supervisor: normalize_windows_source(include_str!(
                "../../../crates/memcordon-platform/src/supervisor.rs"
            )),
            platform: normalize_windows_source(include_str!(
                "../../../crates/memcordon-platform/src/sealed/windows.rs"
            )),
            release_config: normalize_windows_source(include_str!("../src/config.rs")),
            release_evidence: normalize_windows_source(include_str!("../src/release_evidence.rs")),
            sealed_windows: normalize_windows_source(include_str!("../src/sealed_windows.rs")),
        }
    }

    fn normalize_line_endings(&mut self) {
        self.process = normalize_windows_source(&self.process);
        self.token = normalize_windows_source(&self.token);
        self.security = normalize_windows_source(&self.security);
        self.package = normalize_windows_source(&self.package);
        self.job = normalize_windows_source(&self.job);
        self.pipe = normalize_windows_source(&self.pipe);
        self.session_broker = normalize_windows_source(&self.session_broker);
        self.service_manager = normalize_windows_source(&self.service_manager);
        self.record = normalize_windows_source(&self.record);
        self.launcher = normalize_windows_source(&self.launcher);
        self.qualification = normalize_windows_source(&self.qualification);
        self.control = normalize_windows_source(&self.control);
        self.supervisor = normalize_windows_source(&self.supervisor);
        self.platform = normalize_windows_source(&self.platform);
        self.release_config = normalize_windows_source(&self.release_config);
        self.release_evidence = normalize_windows_source(&self.release_evidence);
        self.sealed_windows = normalize_windows_source(&self.sealed_windows);
    }

    fn convert_line_endings_to_crlf(&mut self) {
        self.process = self.process.replace('\n', "\r\n");
        self.token = self.token.replace('\n', "\r\n");
        self.security = self.security.replace('\n', "\r\n");
        self.package = self.package.replace('\n', "\r\n");
        self.job = self.job.replace('\n', "\r\n");
        self.pipe = self.pipe.replace('\n', "\r\n");
        self.session_broker = self.session_broker.replace('\n', "\r\n");
        self.service_manager = self.service_manager.replace('\n', "\r\n");
        self.record = self.record.replace('\n', "\r\n");
        self.launcher = self.launcher.replace('\n', "\r\n");
        self.qualification = self.qualification.replace('\n', "\r\n");
        self.control = self.control.replace('\n', "\r\n");
        self.supervisor = self.supervisor.replace('\n', "\r\n");
        self.platform = self.platform.replace('\n', "\r\n");
        self.release_config = self.release_config.replace('\n', "\r\n");
        self.release_evidence = self.release_evidence.replace('\n', "\r\n");
        self.sealed_windows = self.sealed_windows.replace('\n', "\r\n");
    }

    fn source(&self, source: WindowsProductionSource) -> &str {
        match source {
            WindowsProductionSource::Process => &self.process,
            WindowsProductionSource::Token => &self.token,
            WindowsProductionSource::Pipe => &self.pipe,
            WindowsProductionSource::Security => &self.security,
            WindowsProductionSource::Job => &self.job,
            WindowsProductionSource::Package => &self.package,
            WindowsProductionSource::SessionBroker => &self.session_broker,
            WindowsProductionSource::ServiceManager => &self.service_manager,
            WindowsProductionSource::Launcher => &self.launcher,
            WindowsProductionSource::Qualification => &self.qualification,
            WindowsProductionSource::Control => &self.control,
            WindowsProductionSource::Supervisor => &self.supervisor,
            WindowsProductionSource::Platform => &self.platform,
            WindowsProductionSource::ReleaseConfig => &self.release_config,
        }
    }

    fn source_mut(&mut self, source: WindowsProductionSource) -> &mut String {
        match source {
            WindowsProductionSource::Process => &mut self.process,
            WindowsProductionSource::Token => &mut self.token,
            WindowsProductionSource::Pipe => &mut self.pipe,
            WindowsProductionSource::Security => &mut self.security,
            WindowsProductionSource::Job => &mut self.job,
            WindowsProductionSource::Package => &mut self.package,
            WindowsProductionSource::SessionBroker => &mut self.session_broker,
            WindowsProductionSource::ServiceManager => &mut self.service_manager,
            WindowsProductionSource::Launcher => &mut self.launcher,
            WindowsProductionSource::Qualification => &mut self.qualification,
            WindowsProductionSource::Control => &mut self.control,
            WindowsProductionSource::Supervisor => &mut self.supervisor,
            WindowsProductionSource::Platform => &mut self.platform,
            WindowsProductionSource::ReleaseConfig => &mut self.release_config,
        }
    }
}

fn windows_mutant_hook(mutant: &str) -> (WindowsProductionSource, &'static str) {
    match mutant {
        "use-create-process-w" => (
            WindowsProductionSource::Process,
            "let created = if matches!(\n            certification_mutant,\n            Some(\n                WindowsSealedMutant::UseCreateProcessW\n                    | WindowsSealedMutant::SkipTargetTokenReadback",
        ),
        "create-under-service-token" => (
            WindowsProductionSource::Process,
            "let service_token =\n            if certification_mutant == Some(WindowsSealedMutant::CreateUnderServiceToken)",
        ),
        "assign-job-after-create" => (
            WindowsProductionSource::Process,
            "if certification_mutant == Some(WindowsSealedMutant::AssignJobAfterCreate)\n            && unsafe { AssignProcessToJobObject",
        ),
        "omit-job-list" => (
            WindowsProductionSource::Process,
            "if !matches!(\n            certification_mutant,\n            Some(\n                WindowsSealedMutant::AssignJobAfterCreate\n                    | WindowsSealedMutant::OmitJobList",
        ),
        "omit-handle-list" => (
            WindowsProductionSource::Process,
            "if certification_mutant != Some(WindowsSealedMutant::OmitHandleList) {",
        ),
        "permit-breakaway" => (
            WindowsProductionSource::Job,
            "if certification_mutant == Some(WindowsSealedMutant::PermitBreakaway) {\n            limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_BREAKAWAY_OK;",
        ),
        "trust-client-token" => (
            WindowsProductionSource::Control,
            "if certification_mutant == Some(WindowsSealedMutant::TrustClientToken) {",
        ),
        "skip-target-token-readback" => (
            WindowsProductionSource::Launcher,
            "let target_token = if request.certification_mutant\n            == Some(memcordon_core::WindowsSealedMutant::SkipTargetTokenReadback)",
        ),
        "skip-job-membership-readback" => (
            WindowsProductionSource::Launcher,
            "request.certification_mutant\n            != Some(memcordon_core::WindowsSealedMutant::SkipJobMembershipReadback)",
        ),
        "resume-before-guardian" => (
            WindowsProductionSource::Launcher,
            "if request.certification_mutant\n        != Some(memcordon_core::WindowsSealedMutant::ResumeBeforeGuardian)\n    {\n        observe_guardian_startup(",
        ),
        "resume-before-relays" => (
            WindowsProductionSource::Launcher,
            "request.certification_mutant != Some(memcordon_core::WindowsSealedMutant::ResumeBeforeRelays)\n    {\n        if let Err(detail) = wait_for_relays_ready(",
        ),
        "leak-job-handle-to-target" => (
            WindowsProductionSource::Process,
            "Some(WindowsSealedMutant::LeakJobHandleToTarget) => Some(\"job\"),",
        ),
        "leak-launcher-pipe" => (
            WindowsProductionSource::Process,
            "Some(WindowsSealedMutant::LeakLauncherPipe) => Some(\"pipe\"),",
        ),
        "accept-recursive-provider" => (
            WindowsProductionSource::Control,
            "&& certification_mutant == Some(WindowsSealedMutant::AcceptRecursiveProvider) => {}",
        ),
        "omit-guardian" => (
            WindowsProductionSource::Launcher,
            "request.certification_mutant\n        == Some(memcordon_core::WindowsSealedMutant::OmitGuardian)",
        ),
        "accept-completion-without-accounting" => (
            WindowsProductionSource::Launcher,
            "request.certification_mutant\n        == Some(memcordon_core::WindowsSealedMutant::AcceptCompletionWithoutAccounting)",
        ),
        "success-before-active-zero" => (
            WindowsProductionSource::Launcher,
            "request.certification_mutant\n        == Some(memcordon_core::WindowsSealedMutant::SuccessBeforeActiveZero)",
        ),
        "skip-relay-ack" => (
            WindowsProductionSource::Launcher,
            "request.certification_mutant == Some(memcordon_core::WindowsSealedMutant::SkipRelayAck)",
        ),
        "close-job-before-evidence" => (
            WindowsProductionSource::Launcher,
            "request.certification_mutant\n        == Some(memcordon_core::WindowsSealedMutant::CloseJobBeforeEvidence)",
        ),
        "fall-back-to-standard" => (
            WindowsProductionSource::Supervisor,
            "mutant == Some(memcordon_core::WindowsSealedMutant::FallBackToStandard)",
        ),
        "omit-agent-from-archive" => (
            WindowsProductionSource::ReleaseConfig,
            "agent.binary != \"memcordon-sealed-agent\"",
        ),
        "advertise-without-certificate" => (
            WindowsProductionSource::Platform,
            "mutant == Some(memcordon_core::WindowsSealedMutant::AdvertiseWithoutCertificate)",
        ),
        other => panic!("unmapped Windows production mutant hook: {other}"),
    }
}

fn require_source(source: &str, fragment: &str, invariant: &str) -> Result<(), String> {
    if source.contains(fragment) {
        Ok(())
    } else {
        Err(format!("Windows production contract omitted {invariant}"))
    }
}

fn require_source_order(source: &str, fragments: &[(&str, &str)]) -> Result<(), String> {
    let mut cursor = 0_usize;
    for (fragment, invariant) in fragments {
        let offset = source[cursor..]
            .find(fragment)
            .ok_or_else(|| format!("Windows production contract omitted {invariant}"))?;
        cursor = cursor
            .checked_add(offset)
            .and_then(|value| value.checked_add(fragment.len()))
            .ok_or_else(|| "Windows production contract source offset overflowed".to_owned())?;
    }
    Ok(())
}

fn validate_windows_fresh_install_contract(package: &str) -> Result<(), String> {
    let filesystem_preflight = semantic_function_region(
        package,
        "fn require_fresh_filesystem_absence() -> Result<(), String> {",
        "pub fn verify_installed() -> Result<(), String> {",
    )
    .ok_or_else(|| "fresh filesystem preflight has no semantic boundary".to_owned())?;
    validate_windows_fresh_filesystem_absence_region(&filesystem_preflight)?;
    let fresh_install = semantic_function_region(
        package,
        "fn install(ephemeral_ci: bool) -> Result<InstallTransition, String> {",
        "enum FreshRollback {",
    )
    .ok_or_else(|| "fresh install must end at its rollback ownership mode".to_owned())?;
    validate_windows_fresh_install_region(&fresh_install)
}

fn validate_windows_fresh_install_region(fresh_install: &str) -> Result<(), String> {
    require_source_order(
        fresh_install,
        &[
            (
                "require_fresh_filesystem_absence()?;",
                "complete no-follow installed filesystem rejection",
            ),
            (
                "if !package_attempts_empty()? {",
                "package-attempt rejection before installation mutation",
            ),
            (
                "require_fresh_service_absence(&manager)?;",
                "service residual preflight before filesystem mutation",
            ),
            (
                "let source = std::env::current_exe()",
                "agent source discovery after residual preflight",
            ),
            (
                "let source_bootstrap = packaged_target_desktop_bootstrap(&source)?;",
                "helper source discovery after residual preflight",
            ),
            (
                "let source_broker = packaged_session_broker(&source)?;",
                "session-broker source discovery after residual preflight",
            ),
            (
                "let result = install_transaction(\n        &source,\n        &source_bootstrap,\n        &source_broker,",
                "install transaction after all residual and source preflights",
            ),
        ],
    )
}

fn validate_windows_fresh_filesystem_absence_region(preflight: &str) -> Result<(), String> {
    require_source_order(
        preflight,
        &[
            (
                "(\"installed-agent\", installed_binary()),",
                "installed agent residual inventory",
            ),
            (
                "\"installed-target-desktop-bootstrap\",\n            installed_target_desktop_bootstrap(),",
                "installed target desktop bootstrap residual inventory",
            ),
            (
                "(\"installed-session-broker\", installed_session_broker()),",
                "installed session broker residual inventory",
            ),
            (
                "(\"installed-state-root\", state_root()),",
                "installed state residual inventory",
            ),
            (
                "reject_reparse_components(&path)?;",
                "fresh residual ancestor-reparse rejection",
            ),
            (
                "path_absent_no_follow(&path, \"fresh-install-filesystem-preflight\")?",
                "fresh residual no-follow absence inspection",
            ),
            (
                "MCSEALED-WINDOWS-ALREADY-INSTALLED: phase=fresh-install-filesystem-preflight role={role}",
                "role-bound already-installed rejection",
            ),
        ],
    )
}

fn validate_windows_artifact_boundary_contract(package: &str, process: &str) -> Result<(), String> {
    let capture = semantic_function_region(
        package,
        "fn capture_package_artifacts(",
        "fn validate_artifact_pair(",
    )
    .ok_or_else(|| "package artifact capture has no semantic boundary".to_owned())?;
    require_source_order(
        &capture,
        &[
            (
                "read_regular_no_follow(agent, \"agent-source\")?",
                "no-follow agent source capture",
            ),
            (
                "read_regular_no_follow(target_desktop_bootstrap, \"target-desktop-bootstrap-source\")?",
                "no-follow helper source capture",
            ),
            (
                "verify_native_target_desktop_bootstrap_pe(&target_desktop_bootstrap_bytes)?",
                "helper native-machine/import-policy verification over captured bytes",
            ),
            (
                "read_regular_no_follow(session_broker, \"session-broker-source\")?",
                "no-follow session-broker source capture",
            ),
            (
                "verify_native_session_broker_pe(&session_broker_bytes)?",
                "session-broker native-machine/import-policy verification over captured bytes",
            ),
            (
                "sha256_bytes(&agent_bytes)",
                "agent digest over captured bytes",
            ),
            (
                "sha256_bytes(\n            &target_desktop_bootstrap_bytes,",
                "helper digest over captured bytes",
            ),
            (
                "session_broker_sha256: crate::package::sha256_bytes(&session_broker_bytes)",
                "session-broker digest over captured bytes",
            ),
        ],
    )?;

    let install = semantic_function_region(
        package,
        "fn install_transaction(",
        "struct ConfiguredServices {",
    )
    .ok_or_else(|| "install transaction has no semantic boundary".to_owned())?;
    require_source_order(
        &install,
        &[
            (
                "let source_artifacts = capture_package_artifacts(source, source_bootstrap, source_broker)?;",
                "source capture before installation mutation",
            ),
            (
                "copy_atomically_bytes(&source_artifacts.agent_bytes, &destination)?;",
                "agent installation from captured bytes",
            ),
            (
                "&source_artifacts.target_desktop_bootstrap_bytes,",
                "helper installation from captured bytes",
            ),
            (
                "&source_artifacts.session_broker_bytes,",
                "session-broker installation from captured bytes",
            ),
            (
                "validate_installed_artifacts(&source_artifacts.digests)?;",
                "installed artifact validation before service configuration",
            ),
            (
                "configure_services(&destination, ServiceConfiguration::Fresh(transition))?",
                "service configuration after artifact validation",
            ),
            (
                "start_services(&services)?;",
                "service start after validation",
            ),
            (
                "verify_live_installed_state()?;",
                "live verification after service start",
            ),
        ],
    )?;

    let reconcile = semantic_function_region(
        package,
        "fn reconcile_services_from_installed() -> Result<(), String> {",
        "fn reconcile_runtime_state_security() -> Result<(), String> {",
    )
    .ok_or_else(|| "service reconciliation has no semantic boundary".to_owned())?;
    require_source_order(
        &reconcile,
        &[
            (
                "validate_existing_installed_artifacts()?",
                "installed pair validation before reconciliation",
            ),
            ("configure_services(", "configuration after pair validation"),
            (
                "start_services(&services)",
                "service start after pair validation",
            ),
        ],
    )?;

    require_source(
        package,
        "validate_artifact_pair(\n        &backup,\n        &bootstrap_backup,\n        &broker_backup,\n        Some(&captured.digests),\n    )?;",
        "digest-bound upgrade backup inventory",
    )?;
    require_source(
        package,
        "Some(&rollback.artifact_digests),",
        "digest-bound upgrade restore preflight",
    )?;

    let holder = semantic_function_region(
        process,
        "impl TargetDesktopLease {",
        "fn launch_target_desktop_probe(",
    )
    .ok_or_else(|| "target desktop holder launch has no semantic boundary".to_owned())?;
    validate_windows_helper_launch_region(&holder, "holder")?;
    let probe = semantic_function_region(
        process,
        "fn launch_target_desktop_probe(",
        "fn read_target_desktop_bootstrap_attestation(",
    )
    .ok_or_else(|| "target desktop probe launch has no semantic boundary".to_owned())?;
    validate_windows_helper_launch_region(&probe, "probe")?;

    let helper_checks = process
        .match_indices("validate_installed_target_desktop_bootstrap()")
        .count();
    if helper_checks < 4 {
        return Err(format!(
            "Windows production contract omitted uniform helper no-follow/import checks: expected at least 4, found {helper_checks}"
        ));
    }
    require_source(
        process,
        "binding.bootstrap_image_sha256\n        != super::package::validate_installed_target_desktop_bootstrap()?",
        "helper digest revalidation during Admission and liveness",
    )?;
    Ok(())
}

fn validate_windows_helper_launch_region(region: &str, role: &str) -> Result<(), String> {
    let image_readback = match role {
        "holder" => "verify_image_path(bootstrap_process.raw(), &executable)?;",
        "probe" => "verify_image_path(probe_process.raw(), &executable)?;",
        _ => return Err(format!("unknown helper launch role {role}")),
    };
    let launch = match role {
        "holder" => (
            "super::session_broker::request_holder(",
            "authenticated fixed-image session-broker launch",
        ),
        "probe" => (
            "CreateProcessAsUserW(",
            "exact-target probe process creation",
        ),
        _ => return Err(format!("unknown helper launch role {role}")),
    };
    require_source_order(
        region,
        &[
            (
                "let executable = super::package::installed_target_desktop_bootstrap();",
                "canonical installed helper selection",
            ),
            (
                "validate_installed_target_desktop_bootstrap()?",
                "pre-launch helper no-follow/import validation",
            ),
            launch,
            (image_readback, "created helper image-path readback"),
            (
                "bootstrap_image_sha256,",
                "helper digest transcript binding",
            ),
        ],
    )
    .map_err(|error| format!("{role} helper launch contract failed: {error}"))
}

fn require_exact_source_occurrences(
    source: &str,
    needle: &str,
    expected: usize,
    label: &str,
) -> Result<(), String> {
    let actual = source.matches(needle).count();
    if actual != expected {
        return Err(format!(
            "{label} occurrence count is mismatched: expected {expected}, found {actual}"
        ));
    }
    Ok(())
}

fn validate_broker_common_bootstrap_contract(session_broker: &str) -> Result<(), String> {
    let bootstrap = semantic_function_region(
        session_broker,
        "fn start_authenticated_broker(",
        "pub(crate) fn request_loader_snaps(",
    )
    .ok_or_else(|| "authenticated broker common bootstrap has no semantic boundary".to_owned())?;
    require_source_order(
        &bootstrap,
        &[
            (
                "BROKER_TRANSACTION_LEASE.try_lock()",
                "process-local one-shot broker serialization",
            ),
            (
                "initial_status.dwCurrentState != SERVICE_STOPPED",
                "stale one-shot broker rejection",
            ),
            (
                "super::service_manager::start_with_arguments(",
                "shared service-name-aware demand start",
            ),
            (
                "connect_session_broker_pipe(",
                "role-correct broker endpoint connection",
            ),
            (
                "authenticate_broker_server(pipe.raw())",
                "exact broker process authentication",
            ),
            (
                "process_token_query_attestation(pinned_broker.handle.raw())",
                "independent broker source query snapshot",
            ),
            (
                "status.dwProcessId != pinned_broker.identity.process_id",
                "SCM-to-pipe-peer process pin",
            ),
            (
                "SessionBrokerFrameV1::Hello(hello) => hello",
                "Hello-first authenticated protocol",
            ),
            (
                "if hello.schema_version != SESSION_BROKER_SCHEMA_VERSION",
                "common Hello schema rejection",
            ),
            (
                "validate_normalized_session_broker_source_snapshot(&hello.broker_source)",
                "common normalized Hello source validation",
            ),
            (
                "session-broker-hello-source-to-authenticated-process",
                "common Hello source-to-process binding",
            ),
            (
                "Ok(AuthenticatedBrokerClient {",
                "typed authenticated client publication",
            ),
        ],
    )
    .map_err(|error| format!("broker common bootstrap contract failed: {error}"))?;
    for (needle, label) in [
        (
            "BROKER_TRANSACTION_LEASE.try_lock()",
            "common transaction lease",
        ),
        ("connect_session_broker_pipe(", "common broker connection"),
        (
            "if hello.schema_version != SESSION_BROKER_SCHEMA_VERSION",
            "common Hello schema rejection",
        ),
        (
            "validate_normalized_session_broker_source_snapshot(&hello.broker_source)",
            "common Hello normalized-source validation",
        ),
        (
            "session-broker-hello-source-to-authenticated-process",
            "common Hello source binding",
        ),
    ] {
        require_exact_source_occurrences(&bootstrap, needle, 1, label)?;
    }
    let broker_start = bootstrap
        .split_once("super::service_manager::start_with_arguments(")
        .and_then(|(_, suffix)| suffix.split_once(").map_err").map(|(body, _)| body))
        .ok_or_else(|| "common broker service-start call has no semantic boundary".to_owned())?;
    for (needle, label) in [
        (
            "WINDOWS_SESSION_BROKER_SERVICE_NAME",
            "broker demand-start service name",
        ),
        (
            "SESSION_BROKER_SCHEMA_VERSION.to_string()",
            "broker demand-start schema argument",
        ),
        ("start_nonce.clone()", "broker demand-start nonce argument"),
    ] {
        require_exact_source_occurrences(broker_start, needle, 1, label)?;
    }
    require_source(
        &bootstrap,
        "SERVICE_START | SERVICE_QUERY_STATUS,",
        "least-rights broker service runtime open",
    )?;
    Ok(())
}

fn validate_holder_broker_protocol_contract(session_broker: &str) -> Result<(), String> {
    let server = semantic_function_region(
        session_broker,
        "unsafe fn broker_service_transaction(",
        "fn validate_loader_snaps_request(",
    )
    .ok_or_else(|| "session-broker holder server has no semantic boundary".to_owned())?;
    let hello_constructor = server
        .split_once("let hello = SessionBrokerHelloV1 {")
        .and_then(|(_, suffix)| suffix.split_once("    };").map(|(body, _)| body))
        .ok_or_else(|| "session-broker Hello construction has no semantic boundary".to_owned())?;
    require_exact_source_occurrences(
        hello_constructor,
        "schema_version: SESSION_BROKER_SCHEMA_VERSION",
        1,
        "server Hello schema construction",
    )?;
    let launched_constructor = server
        .split_once("let mut launched = SessionBrokerLaunchedV1 {")
        .and_then(|(_, suffix)| suffix.split_once("    };").map(|(body, _)| body))
        .ok_or_else(|| {
            "session-broker Launched construction has no semantic boundary".to_owned()
        })?;
    require_exact_source_occurrences(
        launched_constructor,
        "schema_version: SESSION_BROKER_SCHEMA_VERSION",
        1,
        "server Launched schema construction",
    )?;

    let holder = semantic_function_region(
        session_broker,
        "pub(crate) fn request_holder(",
        "fn retire_authenticated_broker(",
    )
    .ok_or_else(|| "holder broker client has no semantic boundary".to_owned())?;
    require_source_order(
        &holder,
        &[
            (
                "start_authenticated_broker(BrokerClientOperation::Holder)",
                "typed common bootstrap delegation",
            ),
            (
                "let request = SessionBrokerRequestV1 {",
                "holder Request construction",
            ),
            (
                "schema_version: SESSION_BROKER_SCHEMA_VERSION,",
                "holder Request schema construction",
            ),
            (
                "SessionBrokerFrameV1::Request(request.clone())",
                "holder Request publication",
            ),
            (
                "SessionBrokerFrameV1::Launched(launched) => launched",
                "holder Launched receipt",
            ),
            (
                "if launched.schema_version != SESSION_BROKER_SCHEMA_VERSION",
                "holder Launched schema rejection",
            ),
        ],
    )
    .map_err(|error| format!("holder broker protocol contract failed: {error}"))?;
    for (needle, label) in [
        (
            "schema_version: SESSION_BROKER_SCHEMA_VERSION,",
            "holder Request schema construction",
        ),
        (
            "if launched.schema_version != SESSION_BROKER_SCHEMA_VERSION",
            "holder Launched schema rejection",
        ),
    ] {
        require_exact_source_occurrences(&holder, needle, 1, label)?;
    }

    let request_validation = semantic_function_region(
        session_broker,
        "fn validate_request(",
        "fn authenticate_launcher_client(",
    )
    .ok_or_else(|| "holder Request validation has no semantic boundary".to_owned())?;
    require_exact_source_occurrences(
        &request_validation,
        "if request.schema_version != SESSION_BROKER_SCHEMA_VERSION",
        1,
        "holder Request schema rejection",
    )?;
    Ok(())
}

fn validate_loader_snaps_broker_protocol_contract(session_broker: &str) -> Result<(), String> {
    let client = semantic_function_region(
        session_broker,
        "pub(crate) fn request_loader_snaps(",
        "#[allow(clippy::too_many_arguments)]",
    )
    .ok_or_else(|| "loader-snaps broker client has no semantic boundary".to_owned())?;
    require_source_order(
        &client,
        &[
            (
                "start_authenticated_broker(BrokerClientOperation::LoaderSnaps)",
                "typed common authenticated bootstrap delegation",
            ),
            (
                "let mut request = LoaderSnapsRequestV2 {",
                "typed loader-snaps Request construction",
            ),
            (
                "schema_version: LOADER_SNAPS_SCHEMA_VERSION,",
                "loader-snaps Request schema construction",
            ),
            (
                "request.binding_sha256 = request.calculated_sha256()",
                "loader-snaps Request digest binding",
            ),
            (
                "SessionBrokerFrameV1::LoaderSnapsRequest(request.clone())",
                "loader-snaps Request publication after binding",
            ),
            (
                "SessionBrokerFrameV1::LoaderSnapsArmed(receipt) => receipt",
                "loader-snaps Armed receipt selection",
            ),
            (
                "armed.validate()",
                "loader-snaps Armed schema/digest validation",
            ),
        ],
    )
    .map_err(|error| format!("loader-snaps broker client contract failed: {error}"))?;
    require_exact_source_occurrences(
        &client,
        "schema_version: LOADER_SNAPS_SCHEMA_VERSION,",
        1,
        "loader-snaps Request schema construction",
    )?;

    let server_validation = semantic_function_region(
        session_broker,
        "fn validate_loader_snaps_request(",
        "fn run_loader_snaps_authority_transaction(",
    )
    .ok_or_else(|| "loader-snaps server validation has no semantic boundary".to_owned())?;
    require_source_order(
        &server_validation,
        &[
            (
                "if request.schema_version != LOADER_SNAPS_SCHEMA_VERSION",
                "loader-snaps Request schema rejection",
            ),
            (
                "request\n            .calculated_sha256()",
                "loader-snaps Request digest rejection",
            ),
            (
                "request.binding.image_sha256 != contract.sha256",
                "loader-snaps image digest binding",
            ),
            (
                "request.binding.native_machine != contract.imports.machine",
                "loader-snaps native-machine binding",
            ),
            (
                "request.binding.matrix_cell.ends_with(\"snaps-on\")",
                "loader-snaps matrix-view binding",
            ),
        ],
    )
    .map_err(|error| format!("loader-snaps server validation contract failed: {error}"))?;
    require_exact_source_occurrences(
        &server_validation,
        "if request.schema_version != LOADER_SNAPS_SCHEMA_VERSION",
        1,
        "loader-snaps Request schema rejection",
    )?;

    let armed_validation = semantic_function_region(
        session_broker,
        "impl LoaderSnapsArmedReceiptV2 {",
        "#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]",
    )
    .ok_or_else(|| "loader-snaps Armed validation has no semantic boundary".to_owned())?;
    require_source_order(
        &armed_validation,
        &[
            (
                "if self.schema_version != LOADER_SNAPS_SCHEMA_VERSION",
                "Armed schema rejection",
            ),
            (
                "self.clone().seal()?.receipt_sha256 != self.receipt_sha256",
                "Armed receipt digest rejection",
            ),
        ],
    )?;
    let restored_validation = semantic_function_region(
        session_broker,
        "impl LoaderSnapsRestoredReceiptV2 {",
        "#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]",
    )
    .ok_or_else(|| "loader-snaps Restored validation has no semantic boundary".to_owned())?;
    require_source_order(
        &restored_validation,
        &[
            (
                "if self.schema_version != LOADER_SNAPS_SCHEMA_VERSION",
                "Restored schema rejection",
            ),
            (
                "self.clone().seal()?.receipt_sha256 != self.receipt_sha256",
                "Restored receipt digest rejection",
            ),
        ],
    )?;
    Ok(())
}

fn validate_broker_retirement_contract(session_broker: &str) -> Result<(), String> {
    let ownership = semantic_function_region(
        session_broker,
        "impl AuthenticatedBrokerClient {",
        "impl LoaderSnapsControlLease {",
    )
    .ok_or_else(|| "authenticated broker ownership transfer has no semantic boundary".to_owned())?;
    require_source_order(
        &ownership,
        &[
            ("fn retire(mut self)", "typed pre-transfer retirement"),
            (
                "drop(self.pipe.take());",
                "endpoint release before retirement",
            ),
            (
                "retire_authenticated_broker(",
                "exact authenticated pre-transfer retirement",
            ),
            (
                "fn into_holder_control(",
                "holder control ownership transfer",
            ),
            (
                "fn into_loader_snaps_control(",
                "loader-snaps control ownership transfer",
            ),
            (
                "impl Drop for AuthenticatedBrokerClient {",
                "fail-safe pre-transfer cleanup owner",
            ),
            (
                "retire_authenticated_broker(service, broker)",
                "fail-safe exact authenticated retirement",
            ),
        ],
    )?;
    let retirement = semantic_function_region(
        session_broker,
        "fn retire_authenticated_broker(",
        "fn validate_request(",
    )
    .ok_or_else(|| "authenticated broker retirement has no semantic boundary".to_owned())?;
    require_source_order(
        &retirement,
        &[
            (
                "wait_stopped(service, WINDOWS_SESSION_BROKER_SERVICE_NAME)?;",
                "SCM stopped convergence",
            ),
            (
                "status.dwCurrentState != SERVICE_STOPPED || status.dwProcessId != 0",
                "SCM stopped PID-zero proof",
            ),
            (
                "wait_service_process_exit(",
                "pinned broker process signal proof",
            ),
            (
                "!super::pipe::endpoint_exists(WINDOWS_SESSION_BROKER_PIPE)?",
                "broker endpoint disappearance proof",
            ),
        ],
    )?;
    Ok(())
}

fn validate_windows_session_broker_contract(
    sources: &WindowsProductionSources,
) -> Result<(), String> {
    validate_broker_common_bootstrap_contract(&sources.session_broker)
        .map_err(|error| format!("broker-common-bootstrap: {error}"))?;
    validate_holder_broker_protocol_contract(&sources.session_broker)
        .map_err(|error| format!("holder-broker-protocol: {error}"))?;
    validate_loader_snaps_broker_protocol_contract(&sources.session_broker)
        .map_err(|error| format!("loader-snaps-broker-protocol: {error}"))?;
    validate_broker_retirement_contract(&sources.session_broker)
        .map_err(|error| format!("broker-retirement: {error}"))?;
    require_source(
        &sources.security,
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00000014;;;{launcher})(A;;0x00020005;;;{broker})",
        "exact SYSTEM-owned broker service policy",
    )?;
    require_source(
        &sources.security,
        "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;0x00101000;;;{launcher})(A;;0x00101000;;;BA)",
        "exact query/synchronize-only broker process policy",
    )?;
    require_source(
        &sources.security,
        "O:SYD:P(A;;GA;;;SY)(A;;GA;;;{launcher})(A;;0x00101040;;;{broker})",
        "exact synchronize/query/duplicate broker access to launcher process",
    )?;
    require_source(
        &sources.security,
        "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;0x00101040;;;{launcher})",
        "exact synchronize/query/duplicate launcher access to holder process",
    )?;
    require_source(
        &sources.security,
        "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;0x00001800;;;{launcher})(A;;0x000000c0;;;{broker})",
        "separate exact launcher-resume and broker-arm holder thread policy",
    )?;
    require_source(
        &sources.security,
        "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;0x00020018;;;SY)(A;;0x00020018;;;{broker})",
        "protected query/source/read-control creation-carrier token policy",
    )?;
    require_source(
        &sources.security,
        "pub fn apply_owner_group_dacl_to_service",
        "explicit owner/group/DACL service mutation API",
    )?;
    let request = sources
        .session_broker
        .split_once("pub(crate) struct SessionBrokerRequestV1 {")
        .and_then(|(_, suffix)| suffix.split_once("}\n\n#[derive").map(|(body, _)| body))
        .ok_or_else(|| "session-broker request schema has no semantic boundary".to_owned())?;
    require_source_order(
        request,
        &[
            ("schema_version: u32,", "broker request schema version"),
            ("start_nonce: String,", "SCM start-nonce binding"),
            ("challenge: String,", "broker challenge response"),
            (
                "launcher_identity: WindowsProcessIdentityV1,",
                "launcher process identity binding",
            ),
            ("target_session_id: u32,", "target session selection"),
            ("holder_pipe_name: String,", "fixed holder channel binding"),
            ("holder_nonce: String,", "fixed holder nonce binding"),
            ("launcher_job_handle: u64,", "launcher-owned Job capability"),
            (
                "holder_image_sha256: String,",
                "fixed holder image digest binding",
            ),
        ],
    )?;
    for forbidden in [
        "token_handle",
        "command_line",
        "target_image",
        "environment",
    ] {
        if request.contains(forbidden) {
            return Err(format!(
                "session-broker request exposes forbidden launch authority: {forbidden}"
            ));
        }
    }
    require_source(
        &sources.session_broker,
        "broker_source: super::token::TokenAttestationSnapshot,",
        "normalized broker source certificate in Hello and Launched evidence",
    )?;
    let launched = sources
        .session_broker
        .split_once("pub(crate) struct SessionBrokerLaunchedV1 {")
        .and_then(|(_, suffix)| suffix.split_once("}\n\n#[derive").map(|(body, _)| body))
        .ok_or_else(|| "session-broker launch schema has no semantic boundary".to_owned())?;
    require_source_order(
        launched,
        &[
            (
                "broker_source: super::token::TokenAttestationSnapshot,",
                "broker source evidence",
            ),
            (
                "holder_effective: super::token::TokenAttestationSnapshot,",
                "holder authority evidence",
            ),
            (
                "holder_query: super::token::TokenQueryAttestationSnapshot,",
                "assigned process-token evidence",
            ),
            (
                "holder_process_handle: u64,",
                "exact holder process capability",
            ),
            (
                "holder_thread_id: u32,",
                "digest-bound holder primary-thread identity",
            ),
            ("binding_sha256: String,", "digest-bound launch result"),
        ],
    )?;
    for forbidden in ["token_handle", "job_handle", "holder_thread_handle"] {
        if launched.contains(forbidden) {
            return Err(format!(
                "session-broker response transfers forbidden reusable capability: {forbidden}"
            ));
        }
    }
    let broker_frames = semantic_function_region(
        &sources.session_broker,
        "enum SessionBrokerFrameV1 {",
        "pub(crate) struct BrokeredHolder {",
    )
    .ok_or_else(|| "session-broker phase frames have no semantic boundary".to_owned())?;
    require_source_order(
        &broker_frames,
        &[
            ("Arm {", "broker arm request"),
            (
                "holder_binding_sha256: String,",
                "holder transcript binding",
            ),
            ("phase: SessionCreationPhaseV1,", "typed creation phase"),
            ("ordinal: u32,", "strict phase ordinal"),
            ("thread_id: u32,", "authenticated creator TID"),
            ("holder_primary:", "pre-arm primary snapshot"),
            ("Armed {", "broker armed evidence"),
            ("carrier:", "attached carrier attestation"),
            ("Consumed {", "post-create consumption evidence"),
            (
                "native_code: Option<i32>,",
                "preserved native create result",
            ),
            ("thread_token_absent: bool,", "holder absence claim"),
            ("Cleared {", "independent broker clearance"),
            ("FinalAck {", "final USER-object acknowledgement"),
            ("completed_phases: u32,", "two-phase completion count"),
            ("Done {", "broker retirement acknowledgement"),
        ],
    )?;
    for forbidden in [
        "token_handle",
        "carrier_handle",
        "creation_token",
        "holder_thread_handle",
    ] {
        if broker_frames.contains(forbidden) {
            return Err(format!(
                "session-broker phase protocol serializes forbidden capability: {forbidden}"
            ));
        }
    }

    let service_start = semantic_function_region(
        &sources.service_manager,
        "pub fn start_with_arguments(",
        "pub(crate) fn service_start_argument_values(",
    )
    .ok_or_else(|| "argument-taking service start has no semantic boundary".to_owned())?;
    require_source_order(
        &service_start,
        &[
            (
                "service_start_argument_values(name, additional_arguments)?",
                "single shared SCM argument builder",
            ),
            (
                "let pointer = if pointers.is_empty()",
                "zero-argument null native vector",
            ),
            ("StartServiceW(", "native demand-start invocation"),
            (
                "u32::try_from(pointers.len())",
                "additional-only native argument count",
            ),
            (
                "ServiceStatePhase::DemandStart",
                "bounded SCM startup-state observation",
            ),
        ],
    )?;
    let service_arguments = semantic_function_region(
        &sources.service_manager,
        "pub(crate) fn service_start_argument_values(",
        "fn service_start_argument(value: &str, role: &str) -> Result<Vec<u16>, String> {",
    )
    .ok_or_else(|| "SCM argument builder has no semantic boundary".to_owned())?;
    require_source_order(
        &service_arguments,
        &[
            (
                "service_start_argument(name, \"service name\")?;",
                "diagnostic service-name validation",
            ),
            (
                "Vec::with_capacity(additional_arguments.len())",
                "additional-only argument capacity",
            ),
            (
                "for (index, argument) in additional_arguments.iter().enumerate()",
                "additional argument encoding",
            ),
        ],
    )?;
    if service_arguments.contains("values.push(service_start_argument(name") {
        return Err(
            "StartServiceW input duplicates the SCM-supplied ServiceMain service name".to_owned(),
        );
    }
    require_source(
        &sources.service_manager,
        "if value.contains('\\0') {",
        "embedded-NUL start-argument rejection",
    )?;
    require_source(
        &sources.service_manager,
        "if name.is_empty() {",
        "empty service-name rejection",
    )?;

    let native_canary = semantic_function_region(
        &sources.qualification,
        "fn native_public_canary(",
        "pub(crate) fn qualification_process_attempt_id(",
    )
    .ok_or_else(|| "native qualification canary has no semantic boundary".to_owned())?;
    require_source_order(
        &native_canary,
        &[
            (
                "qualification_process_attempt_id(&nonce, &request_sha256, &caller_process_identity)",
                "locally derived process-bound attempt identity",
            ),
            (
                "qualification_pretarget_attempt_id(&nonce, &request_sha256)",
                "locally derived pretarget rejection identity",
            ),
            (
                "received != expected_process_attempt_id",
                "StreamsPrepared process-attempt pin",
            ),
            (
                "validate_native_reject(",
                "typed pre-stream rejection validation",
            ),
            (
                "provider_response_variant(&response)",
                "bounded invalid-response discriminant",
            ),
        ],
    )?;
    if native_canary.contains("attempt_id.as_deref() == Some(returned_attempt.as_str())") {
        return Err(
            "native qualification still compares a pre-stream Reject with an unset learned attempt"
                .to_owned(),
        );
    }
    require_source_order(
        &sources.qualification,
        &[
            (
                "identity.extend_from_slice(b\"pretarget-rejection-v1\");",
                "control-domain pretarget attempt derivation",
            ),
            (
                "returned_attempt == expected_process_attempt",
                "process-bound pre-stream Reject acceptance",
            ),
            (
                "returned_attempt == expected_pretarget_attempt",
                "pretarget-bound pre-stream Reject acceptance",
            ),
            ("predicate={predicate}", "named invalid-response predicate"),
        ],
    )?;

    let guardian_service = normalize_windows_source(include_str!(
        "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/guardian_service.rs"
    ));
    let guardian_parser = semantic_function_region(
        &guardian_service,
        "    fn parse(slot: &str, arguments: &[OsString]) -> Result<Self, String> {",
        "    fn guardian_arguments(",
    )
    .ok_or_else(|| "guardian service argument parser has no semantic boundary".to_owned())?;
    require_source_order(
        &guardian_parser,
        &[
            ("service_name,", "guardian service name at argument zero"),
            ("schema,", "guardian binding schema"),
            ("slot_argument,", "guardian dynamic slot binding"),
            ("attempt_id,", "guardian attempt binding"),
            ("nonce,", "guardian nonce binding"),
            ("pipe_name,", "guardian pipe binding"),
            ("launcher_pid,", "guardian launcher PID binding"),
            (
                "launcher_creation_time,",
                "guardian launcher creation-time binding",
            ),
            ("cleanup_deadline,", "guardian cleanup deadline binding"),
            ("readiness_delay,", "guardian readiness delay binding"),
            (
                "if text(service_name)? != slot",
                "guardian SCM name verification",
            ),
        ],
    )?;
    let guardian_start = semantic_function_region(
        &sources.process,
        "pub fn create_guardian(",
        "fn authenticate_guardian_slot_process(",
    )
    .ok_or_else(|| "guardian demand-start path has no semantic boundary".to_owned())?;
    let guardian_payload = guardian_start
        .split_once("let start_arguments = vec![")
        .and_then(|(_, suffix)| suffix.split_once("];\n").map(|(body, _)| body))
        .ok_or_else(|| "guardian additional-argument vector has no semantic boundary".to_owned())?;
    require_source_order(
        guardian_payload,
        &[
            (
                "SERVICE_BINDING_SCHEMA_VERSION.to_string(),",
                "guardian additional argument zero is schema, not a duplicated name",
            ),
            ("slot.name.clone(),", "guardian dynamic slot argument"),
            ("attempt_id.to_owned(),", "guardian attempt argument"),
            ("nonce.clone(),", "guardian nonce argument"),
            ("pipe_name,", "guardian pipe argument"),
            (
                "launcher_identity.process_id.to_string(),",
                "guardian launcher PID argument",
            ),
            (
                "launcher_identity.creation_time_100ns.to_string(),",
                "guardian launcher creation-time argument",
            ),
            (
                "cleanup_deadline_millis.to_string(),",
                "guardian cleanup deadline argument",
            ),
            (
                "readiness_delay_millis.to_string(),",
                "guardian readiness delay argument",
            ),
        ],
    )?;
    require_source(
        &guardian_start,
        "start_with_arguments(&slot.service, &slot.name, &start_arguments)?;",
        "guardian shared SCM argument-vector construction",
    )?;

    let protected_dacl_apply = semantic_function_region(
        &sources.security,
        "    pub fn apply_dacl_to_kernel_object_detailed(",
        "    pub fn apply_to_file_object(",
    )
    .ok_or_else(|| "protected kernel DACL apply has no semantic boundary".to_owned())?;
    require_source_order(
        &protected_dacl_apply,
        &[
            ("self.dacl()", "explicit non-null kernel DACL precondition"),
            (
                "SetKernelObjectSecurity(handle, PROTECTED_KERNEL_DACL_INFORMATION, self.0)",
                "protected DACL-only kernel mutation",
            ),
        ],
    )?;
    for forbidden in [
        "OWNER_SECURITY_INFORMATION",
        "GROUP_SECURITY_INFORMATION",
        "LABEL_SECURITY_INFORMATION",
    ] {
        if protected_dacl_apply.contains(forbidden) {
            return Err(format!(
                "protected kernel DACL apply selected forbidden component {forbidden}"
            ));
        }
    }
    require_source(
        &sources.security,
        "const PROTECTED_KERNEL_DACL_INFORMATION: u32 =\n    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;",
        "exact protected kernel DACL security-information mask",
    )?;

    let broker_protection = semantic_function_region(
        &sources.security,
        "pub fn protect_current_session_broker() -> Result<(), SessionBrokerProtectionError> {",
        "#[derive(Clone, Copy, Debug, Eq, PartialEq)]",
    )
    .ok_or_else(|| "broker protection has no semantic boundary".to_owned())?;
    require_source_order(
        &broker_protection,
        &[
            (
                ".apply_to_kernel_object_detailed(process)",
                "broker process descriptor apply",
            ),
            (
                "verify_kernel_object_detailed(process, SecurityObjectKind::Process)",
                "broker process full descriptor readback",
            ),
            (
                "const BROKER_TOKEN_PROTECTION_ACCESS: u32 =\n        TOKEN_QUERY | READ_CONTROL_ACCESS | WRITE_DAC_ACCESS;",
                "exact broker token startup access",
            ),
            ("OpenProcessToken(", "broker token open"),
            (
                "apply_dacl_to_kernel_object_detailed(token.raw())",
                "broker token protected-DACL-only mutation",
            ),
            (
                "verify_kernel_object_detailed(token.raw(), SecurityObjectKind::Token)",
                "broker token complete descriptor readback",
            ),
        ],
    )?;
    for forbidden in [
        "WRITE_OWNER",
        "TOKEN_ALL_ACCESS",
        "SeTakeOwnershipPrivilege",
    ] {
        if broker_protection.contains(forbidden) {
            return Err(format!(
                "broker protection gained forbidden authority {forbidden}"
            ));
        }
    }
    if broker_protection.contains("token_descriptor.apply_to_kernel_object(")
        || broker_protection.contains("token_descriptor.apply_to_kernel_object_detailed(")
    {
        return Err("broker token retained generic full-descriptor mutation".to_owned());
    }

    let source_normalization = semantic_function_region(
        &sources.token,
        "pub(crate) fn normalize_current_session_broker_source_privileges()",
        "fn derive_exact_session_broker_carrier(",
    )
    .ok_or_else(|| "session-broker source normalization has no semantic boundary".to_owned())?;
    require_source(
        &sources.token,
        "const SESSION_BROKER_RAW_SOURCE_PRIVILEGES: &[(&str, bool)] = &[\n    (\"SeAssignPrimaryTokenPrivilege\", false),\n    (\"SeIncreaseQuotaPrivilege\", false),\n    (\"SeImpersonatePrivilege\", true),\n    (\"SeSecurityPrivilege\", false),\n    (\"SeTcbPrivilege\", true),\n    (\"SeChangeNotifyPrivilege\", true),\n];",
        "exact raw SCM-created LocalSystem privilege state",
    )?;
    require_source(
        &sources.token,
        "const SESSION_BROKER_NORMALIZED_SOURCE_PRIVILEGES: &[(&str, bool)] = &[\n    (\"SeAssignPrimaryTokenPrivilege\", false),\n    (\"SeIncreaseQuotaPrivilege\", false),\n    (\"SeImpersonatePrivilege\", false),\n    (\"SeSecurityPrivilege\", false),\n    (\"SeTcbPrivilege\", false),\n    (\"SeChangeNotifyPrivilege\", true),\n];",
        "exact normalized broker source privilege state",
    )?;
    for field in [
        "SourceUserSid",
        "SourceSessionId",
        "SourceTokenType",
        "SourceRestrictedState",
        "SourceRestrictingSidInventory",
        "SourceBrokerSid",
        "SourceAdministratorsSid",
        "SourcePrivilegeMembership",
        "SourcePrivilegeState",
        "SourceEnabledSensitivePrivilegeCount",
        "SourceHandleAccess",
        "SourceThreadTokenAbsence",
        "SourcePrivilegeTransition",
        "SourceSnapshotTransition",
    ] {
        require_source(
            &sources.token,
            field,
            "typed broker-source diagnostic field",
        )?;
    }
    require_source_order(
        &source_normalization,
        &[
            (
                "require_current_thread_token_absent()",
                "normalization thread-token preflight",
            ),
            (
                "let source_access = TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES;",
                "exact normalization capability",
            ),
            (
                "current_process_token_with_attested_access(source_access, \"broker-source-normalization\")",
                "process-primary source selection and exact-handle readback",
            ),
            (
                "SESSION_BROKER_RAW_SOURCE_PRIVILEGES",
                "raw SCM LocalSystem source certificate",
            ),
            (
                "disable_session_broker_source_privilege(source.raw(), \"SeImpersonatePrivilege\")?;",
                "ambient impersonate disable",
            ),
            (
                "disable_session_broker_source_privilege(source.raw(), \"SeTcbPrivilege\")?;",
                "ambient TCB disable",
            ),
            (
                "exact_disabled_privilege_set_transition(&raw_before, &raw_after, &disabled)",
                "exact raw privilege transition",
            ),
            (
                "SESSION_BROKER_NORMALIZED_SOURCE_PRIVILEGES",
                "normalized idle source certificate",
            ),
            (
                "exact_session_broker_source_snapshot_transition(&before, &after)",
                "full source transition invariance",
            ),
            ("drop(source);", "adjust-capable source handle retirement"),
            (
                "require_current_thread_token_absent()",
                "normalization thread-token postflight",
            ),
        ],
    )?;
    for forbidden in [
        "TOKEN_DUPLICATE",
        "TOKEN_ASSIGN_PRIMARY",
        "TOKEN_IMPERSONATE",
        "TOKEN_ADJUST_DEFAULT",
        "TOKEN_ADJUST_SESSIONID",
        "WRITE_DAC_ACCESS",
        "READ_CONTROL_ACCESS",
        "SE_PRIVILEGE_REMOVED",
    ] {
        if source_normalization.contains(forbidden) {
            return Err(format!(
                "broker source normalizer gained forbidden capability or removal semantic {forbidden}"
            ));
        }
    }
    let source_disable = semantic_function_region(
        &sources.token,
        "fn disable_session_broker_source_privilege(",
        "pub(crate) fn normalize_current_session_broker_source_privileges()",
    )
    .ok_or_else(|| "session-broker source disable helper has no semantic boundary".to_owned())?;
    require_source_order(
        &source_disable,
        &[
            (
                "let before = privilege_entries_snapshot(token)",
                "per-privilege pre-state",
            ),
            ("Attributes: 0,", "disable-not-remove operation"),
            ("AdjustTokenPrivileges(", "native source privilege disable"),
            (
                "GetLastError() } == ERROR_NOT_ALL_ASSIGNED",
                "normalization not-all-assigned rejection",
            ),
            (
                "let after = privilege_entries_snapshot(token)",
                "per-privilege post-state",
            ),
            (
                "exact_disabled_privilege_transition(&before, &after, &luid)",
                "only-enabled-bit transition proof",
            ),
        ],
    )?;
    if source_disable.contains("SE_PRIVILEGE_REMOVED") {
        return Err("broker source normalizer removes a reusable privilege".to_owned());
    }

    let exact_carrier = semantic_function_region(
        &sources.token,
        "fn derive_exact_session_broker_carrier(",
        "fn privilege_inventory_is_security_only_enabled(inventory: &[String]) -> Result<bool, String> {",
    )
    .ok_or_else(|| "exact session-broker carrier helper has no semantic boundary".to_owned())?;
    require_source_order(
        &exact_carrier,
        &[
            (
                "DuplicateTokenEx(",
                "private disposable carrier duplication",
            ),
            (
                "token_privileges_except_keep(carrier.raw(), &allowed_luids)?",
                "forbidden privilege enumeration before enablement",
            ),
            (
                "Attributes: SE_PRIVILEGE_REMOVED,",
                "forbidden carrier privilege deletion",
            ),
            (
                "for (&name, luid) in allowed_privileges.iter().zip(&allowed_luids)",
                "allowed privilege enable phase",
            ),
            (
                "Attributes: SE_PRIVILEGE_ENABLED,",
                "allowed carrier privilege enablement",
            ),
            (
                "let entries = privilege_entries_snapshot(carrier.raw())?;",
                "exact carrier inventory readback before installation",
            ),
            (
                "evidence.behavior.envelope.token_type != TokenImpersonation as u32",
                "impersonation carrier type attestation",
            ),
        ],
    )?;
    if exact_carrier
        .split_once("let entries = privilege_entries_snapshot(carrier.raw())?;")
        .is_some_and(|(before_attestation, _)| before_attestation.contains("return Ok(carrier);"))
    {
        return Err(
            "exact session-broker carrier can return before inventory attestation".to_owned(),
        );
    }

    let carrier_derivation = semantic_function_region(
        &sources.token,
        "fn derive_target_session_security_carrier(",
        "pub(crate) fn derive_session_broker_holder_primary(",
    )
    .ok_or_else(|| "creation-carrier derivation has no semantic boundary".to_owned())?;
    require_source_order(
        &carrier_derivation,
        &[
            ("DuplicateTokenEx(", "private target-session carrier seed"),
            ("TokenPrimary,", "unassigned mutable primary seed"),
            ("NtSetInformationToken(", "target-session mutation"),
            ("TokenSessionId,", "exact carrier session class"),
            (
                "token_privileges_except_keep(mutable.raw(), &[security])?",
                "Security-only keep set",
            ),
            (
                "Attributes: 0x0000_0004,",
                "irreversible non-Security removal",
            ),
            ("Attributes: SE_PRIVILEGE_ENABLED,", "Security enablement"),
            (
                "session_creation_carrier_token_sddl()?",
                "protected narrow carrier DACL",
            ),
            (
                "SESSION_CREATION_CARRIER_ACCESS,",
                "narrow retained carrier rights",
            ),
            ("SecurityImpersonation,", "full impersonation level"),
            ("TokenImpersonation,", "impersonation-token result"),
            (
                "privilege_inventory_is_security_only_enabled",
                "exact one-privilege carrier evidence",
            ),
            (
                "token_has_enabled_group(carrier.raw(), \"S-1-5-32-544\")?",
                "enabled Administrators membership",
            ),
        ],
    )?;
    for forbidden in [
        "SeTcbPrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeIncreaseQuotaPrivilege",
        "SeImpersonatePrivilege",
        "SeCreateGlobalPrivilege",
        "SeRelabelPrivilege",
        "SeChangeNotifyPrivilege",
    ] {
        if carrier_derivation.contains(&format!("&[security, privilege_luid(\"{forbidden}\")")) {
            return Err(format!(
                "creation carrier retained forbidden privilege {forbidden}"
            ));
        }
    }

    let holder_derivation = semantic_function_region(
        &sources.token,
        "pub(crate) fn derive_session_broker_holder_primary(",
        "pub(crate) fn with_session_broker_launch_privileges<T>(",
    )
    .ok_or_else(|| "broker holder-token derivation has no semantic boundary".to_owned())?;
    require_source_order(
        &holder_derivation,
        &[
            (
                "validate_normalized_session_broker_source_snapshot(&broker_source)",
                "shared exact normalized broker source proof",
            ),
            (
                "derive_exact_session_broker_carrier(\n        source.raw(),\n        \"holder-derivation-tcb-only\",\n        &[\"SeTcbPrivilege\"],",
                "exact TCB-only derivation carrier",
            ),
            ("| WRITE_DAC_ACCESS", "holder startup DACL-write authority"),
            (
                "| READ_CONTROL_ACCESS;",
                "holder full descriptor readback authority",
            ),
            (
                "apply_dacl_to_kernel_object_detailed(mutable.raw())",
                "holder token protected-DACL-only mutation",
            ),
            (
                "verify_kernel_object(mutable.raw(), super::security::SecurityObjectKind::Token)",
                "holder token complete descriptor readback",
            ),
            (
                "derive_target_session_security_carrier(\n                source.raw(),\n                target_session_id,\n                mutable_access,\n                \"station\",",
                "independent station carrier derivation",
            ),
            (
                "derive_target_session_security_carrier(\n                source.raw(),\n                target_session_id,\n                mutable_access,\n                \"desktop\",",
                "independent desktop carrier derivation",
            ),
            (
                "station_creation_evidence.instance.token_id\n            == desktop_creation_evidence.instance.token_id",
                "station/desktop TokenId non-reuse proof",
            ),
        ],
    )?;
    for forbidden in [
        "WRITE_OWNER",
        "TOKEN_ALL_ACCESS",
        "SeTakeOwnershipPrivilege",
    ] {
        if holder_derivation.contains(forbidden) {
            return Err(format!(
                "broker holder-token derivation gained forbidden authority {forbidden}"
            ));
        }
    }
    if holder_derivation.contains("object_security.apply_to_kernel_object(")
        || holder_derivation.contains("object_security.apply_to_kernel_object_detailed(")
    {
        return Err("holder token retained generic full-descriptor mutation".to_owned());
    }

    let holder_launch = semantic_function_region(
        &sources.token,
        "pub(crate) fn with_session_broker_launch_privileges<T>(",
        "fn with_session_broker_impersonate_privilege<T>(",
    )
    .ok_or_else(|| "session-broker holder launch scope has no semantic boundary".to_owned())?;
    require_source_order(
        &holder_launch,
        &[
            (
                "require_current_thread_token_absent()?;",
                "holder launch thread-token preflight",
            ),
            (
                "validate_normalized_session_broker_source_snapshot(&source_before)",
                "shared normalized launch source proof",
            ),
            (
                "derive_exact_session_broker_carrier(\n        source.raw(),\n        \"holder-launch-assign-primary-increase-quota\",\n        &[\"SeAssignPrimaryTokenPrivilege\", \"SeIncreaseQuotaPrivilege\"],",
                "exact assign-primary plus increase-quota launch carrier",
            ),
            (
                "ScopedPrivilegeThreadToken::install(carrier.raw())",
                "launch carrier installation after exact attestation",
            ),
            ("let result = (|| {", "early-error result capture"),
            ("operation()", "single holder launch operation"),
            ("scoped.revert()", "explicit launch carrier reversion"),
            (
                "require_current_thread_token_absent()?;",
                "holder launch postflight absence",
            ),
            (
                "token_attestation_snapshot(source.raw())? != source_before",
                "holder launch source invariance",
            ),
        ],
    )?;

    let remote_arm = semantic_function_region(
        &sources.token,
        "fn with_session_broker_impersonate_privilege<T>(",
        "fn token_privileges_except_change_notify(",
    )
    .ok_or_else(|| "remote creation-carrier arming has no semantic boundary".to_owned())?;
    require_source_order(
        &remote_arm,
        &[
            (
                "require_current_thread_token_absent()?;",
                "broker pre-scope absence proof",
            ),
            (
                "validate_normalized_session_broker_source_snapshot(&source_before)",
                "shared exact idle source proof",
            ),
            (
                "derive_exact_session_broker_carrier(\n        source.raw(),\n        \"remote-arm-impersonate-only\",\n        &[\"SeImpersonatePrivilege\"],",
                "exact broker-local impersonate-only carrier",
            ),
            (
                "ScopedPrivilegeThreadToken::install(carrier.raw())",
                "broker-local carrier installation",
            ),
            (
                "let result = (|| {",
                "early-error remote-arm result capture",
            ),
            ("operation()", "single remote attach operation"),
            ("scoped.revert()", "immediate broker reversion"),
            (
                "token_attestation_snapshot(source.raw())? != source_before",
                "broker source invariance",
            ),
            (
                "pub(crate) fn attach_creation_carrier_to_thread(",
                "remote arm API",
            ),
            (
                "require_thread_token_absent(thread)?;",
                "target preexisting-token absence proof",
            ),
            (
                "SetThreadToken(&raw mut thread, carrier)",
                "exact remote attachment",
            ),
            (
                "thread_token_attestation(thread)?",
                "independent attached-token readback",
            ),
            ("observed != requested", "exact attached TokenId equality"),
            (
                "pub(crate) fn revert_creation_carrier_and_attest_absent()",
                "holder immediate reversion API",
            ),
            ("RevertToSelf()", "native holder reversion"),
            (
                "require_current_thread_token_absent()",
                "holder post-revert absence proof",
            ),
        ],
    )?;

    let server = semantic_function_region(
        &sources.session_broker,
        "unsafe fn broker_service_transaction(",
        "fn validate_loader_snaps_request(",
    )
    .ok_or_else(|| "session-broker server transaction has no semantic boundary".to_owned())?;
    require_source_order(
        &server,
        &[
            (
                "normalize_current_session_broker_source_privileges()",
                "exact source normalization before exposure",
            ),
            (
                "protect_current_session_broker()",
                "broker process self-protection",
            ),
            (
                "certify_current_broker()",
                "broker source-token certification",
            ),
            ("PipeListener::new(", "first-instance protected broker pipe"),
            (
                "announce_running()",
                "running publication only after listener preparation",
            ),
            (
                "authenticate_launcher_client(pipe.raw())?",
                "restricted launcher admission",
            ),
            (
                "service_attestation_challenge(\"session-broker\")",
                "fresh broker challenge",
            ),
            (
                "broker_source: normalized_broker_source.clone(),",
                "normalized source certificate in Hello",
            ),
            (
                "validate_request(&request, &hello, &launcher_identity)",
                "challenge-bound request validation",
            ),
            (
                "create_session_broker_holder(",
                "fixed suspended holder creation",
            ),
            (
                "holder.broker_source == normalized_broker_source",
                "holder derivation source invariance from startup",
            ),
            (
                "HOLDER_PROCESS_TRANSFER_ACCESS,",
                "least-rights process transfer",
            ),
            (
                "transfer_rollback.record_process(remote_process);",
                "process duplicate rollback recording",
            ),
            (
                "holder_thread_id: holder.primary_thread_id,",
                "bound primary-thread identity publication",
            ),
            (
                "SessionBrokerFrameV1::Launched(launched.clone())",
                "complete holder capability delivery",
            ),
            (
                "transfer_rollback.disarm_after_launched_delivery();",
                "launcher handle-close ownership after complete delivery",
            ),
            (
                "SessionBrokerFrameV1::Ack { binding_sha256 }",
                "digest-bound acknowledgement",
            ),
            (
                "run_creation_authority_transaction(",
                "authenticated exact-call authority transaction",
            ),
        ],
    )?;
    let creation_transaction = semantic_function_region(
        &sources.session_broker,
        "fn run_creation_authority_transaction(",
        "fn loader_snaps_client_failure(",
    )
    .ok_or_else(|| "broker creation-authority transaction has no semantic boundary".to_owned())?;
    require_source_order(
        &creation_transaction,
        &[
            ("let mut completed = 0_u32;", "strict initial phase state"),
            ("let mut station_tid = None;", "station TID replay state"),
            ("SessionBrokerFrameV1::Arm {", "authenticated arm input"),
            (
                "0 => SessionCreationPhaseV1::WindowStation,",
                "station-first ordering",
            ),
            (
                "1 => SessionCreationPhaseV1::Desktop,",
                "desktop-second ordering",
            ),
            (
                "_ => return Err(\"session broker rejected a third creation arm\".to_owned())",
                "third-arm rejection",
            ),
            (
                "binding_sha256 != launched.binding_sha256",
                "launch-binding pin",
            ),
            ("ordinal != completed + 1", "exact next ordinal"),
            ("phase != expected_phase", "exact next phase"),
            ("thread_id == 0", "zero TID rejection"),
            (
                "holder_primary != holder.query",
                "primary invariant pre-arm",
            ),
            (
                "thread_id != holder.primary_thread_id",
                "station primary-TID equality",
            ),
            (
                "station_tid == Some(thread_id)",
                "desktop TID non-reuse proof",
            ),
            (
                "OpenThread(HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS, 0, thread_id)",
                "noninheritable exact creator-thread open",
            ),
            (
                "verify_exact_handle(\n                    thread.raw(),\n                    HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS,\n                    HOLDER_THREAD_BROKER_ARM_GRANTED_ACCESS,\n                    \"creator-thread\",\n                    \"open\",",
                "exact canonical broker arm rights readback",
            ),
            (
                "GetProcessIdOfThread(thread.raw())",
                "creator TID holder-PID association",
            ),
            (
                "require_thread_token_absent(thread.raw())?;",
                "pre-arm absence proof",
            ),
            (
                "holder.station_creation_carrier.raw()",
                "fresh station carrier selection",
            ),
            (
                "holder.desktop_creation_carrier.raw()",
                "fresh desktop carrier selection",
            ),
            (
                "attach_creation_carrier_to_thread(thread.raw(), carrier)?",
                "broker remote attachment and readback",
            ),
            (
                "&attached != expected_evidence",
                "exact carrier TokenId evidence",
            ),
            ("SessionBrokerFrameV1::Armed {", "armed publication"),
            ("SessionBrokerFrameV1::Consumed {", "consumption readback"),
            (
                "consumed_primary == holder.query",
                "primary invariant post-call",
            ),
            ("&& thread_token_absent", "holder absence evidence"),
            (
                "require_thread_token_absent(thread.raw())?;",
                "independent broker absence proof",
            ),
            ("completed = ordinal;", "phase completion transition"),
            ("SessionBrokerFrameV1::Cleared {", "clearance publication"),
            (
                "SessionBrokerFrameV1::FinalAck {",
                "final attestation acknowledgement",
            ),
            ("completed_phases == completed", "final completion binding"),
            ("(completed == 2 || failed)", "two-clearance success gate"),
            ("holder.disarm();", "late holder termination disarm"),
            ("SessionBrokerFrameV1::Done {", "post-disarm completion"),
        ],
    )?;
    if creation_transaction.contains("DuplicateHandle(")
        || creation_transaction.contains("TOKEN_DUPLICATE")
    {
        return Err(
            "creation-authority state machine introduced a token-transfer surface".to_owned(),
        );
    }
    let broker_control = semantic_function_region(
        &sources.session_broker,
        "impl BrokerControlLease {",
        "impl Drop for BrokerControlLease {",
    )
    .ok_or_else(|| "broker control lease has no semantic boundary".to_owned())?;
    require_source_order(
        &broker_control,
        &[
            (
                "drop(self.pipe.take());",
                "broker endpoint release before retirement",
            ),
            (
                "retire_authenticated_broker(&self.service, &self.broker)",
                "exact authenticated broker retirement",
            ),
        ],
    )?;
    let broker_request = semantic_function_region(
        &sources.session_broker,
        "pub(crate) fn request_holder(",
        "fn retire_authenticated_broker(",
    )
    .ok_or_else(|| "broker demand-start path has no semantic boundary".to_owned())?;
    require_source_order(
        &broker_request,
        &[
            (
                "launched.broker_source != hello.broker_source",
                "Hello/Launched source equality",
            ),
            (
                "validate_normalized_session_broker_source_snapshot(&launched.broker_source)",
                "Launched normalized source validation",
            ),
            (
                "session-broker-launched-source-to-authenticated-process",
                "Launched source-to-process binding",
            ),
        ],
    )?;
    for (contract, role) in [
        (
            "const BROKER_PROCESS_LAUNCHER_ACCESS: u32 = 0x0010_1000;",
            "broker process query/synchronize rights",
        ),
        (
            "const LAUNCHER_PROCESS_BROKER_ACCESS: u32 =\n    SYNCHRONIZE_ACCESS | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE;",
            "launcher process synchronize/query/duplicate rights",
        ),
        (
            "pub(crate) const HOLDER_PROCESS_TRANSFER_ACCESS: u32 = 0x0010_1040;",
            "holder process synchronize/query/duplicate rights",
        ),
        (
            "pub(crate) const HOLDER_THREAD_LAUNCHER_ACCESS: u32 =\n    THREAD_QUERY_LIMITED_INFORMATION | THREAD_RESUME;",
            "holder thread resume-only plus query-limited rights",
        ),
        (
            "pub(crate) const HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS: u32 =\n    THREAD_QUERY_INFORMATION | THREAD_SET_THREAD_TOKEN;",
            "broker thread set-token plus query-information request rights",
        ),
        (
            "pub(crate) const HOLDER_THREAD_BROKER_ARM_GRANTED_ACCESS: u32 =\n    HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS | THREAD_QUERY_LIMITED_INFORMATION;",
            "canonical broker thread granted rights including implied query-limited",
        ),
        (
            "actual_thread_process_id != launched.holder_identity.process_id",
            "holder primary-thread process association",
        ),
        (
            "pub(crate) const HOLDER_JOB_BROKER_ACCESS: u32 = 0x0000_0005;",
            "broker Job assign/query rights",
        ),
    ] {
        require_source(&sources.session_broker, contract, role)?;
    }
    require_source(
        &sources.session_broker,
        "pub(crate) const SESSION_BROKER_SCHEMA_VERSION: u32 = 5;",
        "versioned exact-call creation authority protocol",
    )?;
    require_source(
        &sources.session_broker,
        "memcordon-session-broker-binding-v5",
        "schema-specific launched binding domain",
    )?;
    let launched_binding = semantic_function_region(
        &sources.session_broker,
        "fn launched_binding_sha256(",
        "fn snapshot_has_enabled_group(",
    )
    .ok_or_else(|| "session-broker launch binding has no semantic boundary".to_owned())?;
    require_source_order(
        &launched_binding,
        &[
            (
                "let mut launched = launched.clone();",
                "complete launch clone",
            ),
            (
                "launched.binding_sha256.clear();",
                "only recursive binding field cleared",
            ),
            (
                "serde_json::to_vec(&(request, launched))",
                "complete request and launch serialization",
            ),
            (
                "memcordon-session-broker-binding-v5",
                "versioned launch binding domain",
            ),
        ],
    )?;
    if launched_binding.contains("holder_thread_id") {
        return Err("primary TID was removed or rewritten before launch binding".to_owned());
    }
    require_source_order(
        &broker_request,
        &[
            (
                "if launched.holder_thread_id == 0 {",
                "nonzero digest-bound primary TID",
            ),
            (
                "let thread = OwnedHandle::new(unsafe {",
                "local thread RAII",
            ),
            ("OpenThread(", "launcher-local DACL-authorized thread open"),
            (
                "HOLDER_THREAD_LAUNCHER_ACCESS,",
                "exact launcher thread open authority",
            ),
            ("0,", "noninheritable launcher thread open"),
            (
                "launched.holder_thread_id",
                "bound primary TID used for local open",
            ),
            ("verify_exact_handle(", "exact local handle attestation"),
            (
                "let actual_thread_process_id = unsafe { GetProcessIdOfThread(thread.raw()) };",
                "primary TID to holder PID association",
            ),
            (
                "expected_pid={} actual_pid={} primary_thread_id={}",
                "evidentiary TID/PID mismatch diagnostic",
            ),
            (
                "SessionBrokerFrameV1::Ack {",
                "ack only after local capability attestation",
            ),
        ],
    )?;
    for forbidden in [
        "launched.holder_thread_handle",
        "HOLDER_THREAD_TRANSFER_ACCESS",
        "record_thread(remote_thread)",
        "remote_thread: Option<u64>",
    ] {
        if sources.session_broker.contains(forbidden) {
            return Err(format!(
                "session-broker retained forbidden remote thread transfer surface: {forbidden}"
            ));
        }
    }
    require_source_order(
        &sources.session_broker,
        &[
            ("let inherited =", "explicit handle inheritance observation"),
            (
                "let actual_granted_access =",
                "single granted-access readback",
            ),
            (
                "requested_access={requested_access:#010x}",
                "requested access diagnostic",
            ),
            (
                "expected_granted_access={expected_granted_access:#010x}",
                "expected granted access diagnostic",
            ),
            (
                "actual_granted_access={actual_granted_access:#010x}",
                "actual granted access diagnostic",
            ),
        ],
    )?;
    let holder_arm = semantic_function_region(
        &sources.process,
        "fn request_creator_arm(",
        "fn consume_creator_arm(",
    )
    .ok_or_else(|| "holder creation-arm handshake has no semantic boundary".to_owned())?;
    require_source_order(
        &holder_arm,
        &[
            (
                "require_thread_token_absent(unsafe { GetCurrentThread() })",
                "holder pre-arm absence proof",
            ),
            (
                "holder_primary != &binding.holder_process_snapshot",
                "holder pre-arm primary invariant",
            ),
            (
                "TargetDesktopBootstrapMessageV1::CreationReady {",
                "authenticated creation readiness",
            ),
            (
                "TargetDesktopBootstrapMessageV1::CreationArmed {",
                "authenticated creation arming",
            ),
            (
                "AttachedCreationCarrierGuard::adopt()",
                "exact attached carrier adoption",
            ),
            ("attached != carrier", "Armed carrier evidence equality"),
        ],
    )?;
    if holder_arm
        .split_once("CreationReadyWrite")
        .is_some_and(|(_, uncertain)| !uncertain.contains("fail_stop_uncertain_creation_arm"))
    {
        return Err(
            "holder can return normally after readiness with uncertain authority".to_owned(),
        );
    }
    let desktop_creator = semantic_function_region(
        &sources.process,
        "fn create_target_desktop_on_creator_thread(",
        "fn bounded_target_desktop_bootstrap_detail(mut detail: String) -> String {",
    )
    .ok_or_else(|| "desktop creator worker has no semantic boundary".to_owned())?;
    require_source_order(
        &desktop_creator,
        &[
            (
                "std::thread::Builder::new()",
                "separate desktop creator worker",
            ),
            (
                ".name(\"memcordon-target-desktop-creator\".to_owned())",
                "fixed worker role",
            ),
            ("GetCurrentThreadId()", "worker TID publication"),
            (
                "SessionCreationPhaseV1::Desktop,\n                2,",
                "fresh desktop phase arm",
            ),
            ("CreateDesktopW(", "protected desktop creation"),
            (
                "let create_error =",
                "native result capture before reversion",
            ),
            ("carrier_guard.revert()", "immediate worker reversion"),
            (
                "TerminateProcess(GetCurrentProcess(), TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS)",
                "fail-stop desktop reversion failure",
            ),
            ("std::process::abort();", "desktop reversion abort"),
            (
                "process_token_query_attestation(unsafe { GetCurrentProcess() })",
                "post-call primary invariant snapshot",
            ),
            (
                "consume_creator_arm(",
                "holder absence consumption evidence",
            ),
            (
                "SessionCreationPhaseV1::Desktop,\n                2,",
                "desktop clearance wait",
            ),
            (
                "Ok(OwnedDesktop::new(desktop))",
                "worker exits only after clearance",
            ),
        ],
    )?;
    if desktop_creator.matches("request_creator_arm(").count() != 1
        || desktop_creator.contains("SessionCreationPhaseV1::WindowStation")
        || desktop_creator.contains("station_creation_carrier")
    {
        return Err("desktop worker does not use one independent desktop arm".to_owned());
    }
    let station_creator = semantic_function_region(
        &sources.process,
        "fn run_target_desktop_bootstrap(",
        "fn serve_target_desktop_probe(",
    )
    .ok_or_else(|| "station creator bootstrap has no semantic boundary".to_owned())?;
    require_source_order(
        &station_creator,
        &[
            (
                "SessionCreationPhaseV1::WindowStation,\n        1,",
                "primary-thread station phase arm",
            ),
            ("CreateWindowStationW(", "protected station creation"),
            ("let station_error =", "native station result capture"),
            (
                "station_carrier_guard.revert()",
                "immediate station reversion",
            ),
            (
                "TerminateProcess(GetCurrentProcess(), TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS)",
                "fail-stop station reversion failure",
            ),
            ("std::process::abort();", "station reversion abort"),
            (
                "process_token_query_attestation(unsafe { GetCurrentProcess() })",
                "post-station primary invariant snapshot",
            ),
            ("consume_creator_arm(", "station dual-absence handshake"),
            (
                "SetProcessWindowStation(",
                "ordinary station binding after clearance",
            ),
            (
                "create_target_desktop_on_creator_thread(",
                "independently armed desktop worker",
            ),
        ],
    )?;
    if station_creator.matches("request_creator_arm(").count() != 1 {
        return Err("station creation does not use exactly one primary-thread arm".to_owned());
    }
    let creation_relay = semantic_function_region(
        &sources.process,
        "fn read_target_desktop_bootstrap_attestation(",
        "fn validate_target_desktop_bootstrap_failure(",
    )
    .ok_or_else(|| "launcher creation relay has no semantic boundary".to_owned())?;
    require_source_order(
        &creation_relay,
        &[
            (
                "super::pipe::TargetDesktopBootstrapPipeOperation::StartedRead",
                "bounded AwaitStarted observation",
            ),
            (
                "TargetDesktopBootstrapMessageV1::Failed {",
                "binding-bound pre-Started failure relay",
            ),
            ("\"await-started\"", "pre-Started failure state evidence"),
            (
                "TargetDesktopBootstrapMessageV1::Started {",
                "exact endpoint-admission Started transition",
            ),
            (
                "phase: TargetDesktopBootstrapPhaseV1::EndpointAdmission",
                "exact Started phase",
            ),
            ("binding == *expected_binding", "exact Started binding"),
            ("let mut pending = None;", "strict no-pending initial state"),
            ("let mut completed = 0_u32;", "strict zero completed state"),
            (
                "broker_control.is_some() && completed != 2",
                "Ready requires two cleared phases",
            ),
            (
                "TargetDesktopBootstrapMessageV1::Failed {",
                "binding-bound post-Started failure relay",
            ),
            ("\"after-started\"", "post-Started failure state evidence"),
            (
                "TargetDesktopBootstrapMessageV1::CreationReady {",
                "holder readiness relay",
            ),
            ("pending.is_none()", "no duplicate arm while pending"),
            (
                "target_desktop_creation_transition_is_expected(",
                "exact local phase/ordinal/TID transition",
            ),
            (
                "holder_primary == expected_binding.holder_process_snapshot",
                "exact ready holder-primary evidence",
            ),
            ("control.arm(", "authenticated broker arm forwarding"),
            (
                "TargetDesktopBootstrapMessageV1::CreationArmed {",
                "authenticated Armed response",
            ),
            (
                "TargetDesktopBootstrapMessageV1::CreationConsumed {",
                "holder consumption relay",
            ),
            (
                "pending == Some((phase, ordinal, thread_id))",
                "exact pending tuple equality",
            ),
            (
                "holder_primary == expected_binding.holder_process_snapshot",
                "exact consumed holder-primary evidence",
            ),
            ("control.consumed(", "broker absence-proof forwarding"),
            (
                "TargetDesktopBootstrapMessageV1::CreationCleared {",
                "authenticated Cleared response",
            ),
            ("completed = ordinal;", "relay completion transition"),
        ],
    )?;
    let creation_transition = semantic_function_region(
        &sources.process,
        "fn target_desktop_creation_transition_is_expected(",
        "#[cfg(test)]",
    )
    .ok_or_else(|| "launcher creation transition has no semantic boundary".to_owned())?;
    for (needle, label) in [
        ("thread_id != 0", "nonzero creator TID"),
        (
            "SessionCreationPhaseV1::WindowStation,\n                1",
            "station phase ordinal one",
        ),
        (
            "SessionCreationPhaseV1::Desktop, 2",
            "desktop phase ordinal two",
        ),
    ] {
        require_source(&creation_transition, needle, label)?;
    }
    let failure_validation = semantic_function_region(
        &sources.process,
        "fn validate_target_desktop_bootstrap_failure(",
        "fn target_desktop_bootstrap_client_identity(pipe: HANDLE) -> Result<(u32, u32), String> {",
    )
    .ok_or_else(|| "launcher failure validation has no semantic boundary".to_owned())?;
    require_source_order(
        &failure_validation,
        &[
            (
                "binding == *expected_binding",
                "exact failure binding comparison",
            ),
            ("if !binding_matches", "exact failure binding requirement"),
            ("detail.is_empty()", "nonempty failure detail"),
            (
                "detail.len() > TARGET_DESKTOP_BOOTSTRAP_DETAIL_MAX_BYTES",
                "bounded failure detail",
            ),
            (
                "state={state} phase={}",
                "failure state and phase preservation",
            ),
            ("native_code={native_code:?}", "native failure preservation"),
            ("detail={detail}", "failure detail preservation"),
        ],
    )?;
    let server_authentication = semantic_function_region(
        &sources.process,
        "fn authenticate_target_desktop_bootstrap_server(",
        "fn publish_target_desktop_bootstrap_failure(",
    )
    .ok_or_else(|| "bootstrap server authentication has no semantic boundary".to_owned())?;
    require_source_order(
        &server_authentication,
        &[
            (
                "let target_snapshot =\n        super::token::token_attestation_snapshot(target_token)",
                "full target token source attestation",
            ),
            (
                "let target_binding_matches = match binding.role {",
                "role-specific target authority validation",
            ),
            (
                "TargetDesktopBootstrapRoleV1::Holder => {",
                "holder target authority role",
            ),
            (
                "super::token::require_same_token_instance(",
                "exact holder target capability instance",
            ),
            (
                "\"target-request-to-holder-capability\"",
                "typed holder target capability relation",
            ),
            (
                "TargetDesktopBootstrapRoleV1::Probe => {",
                "probe target authority role",
            ),
            (
                "super::token::require_assigned_token_authority(",
                "full-source probe assignment relation",
            ),
            (
                "\"target-request-to-probe-self\"",
                "typed probe target assignment relation",
            ),
            (
                "target_snapshot.query_evidence() == binding.bootstrap_process_snapshot",
                "probe current-query bootstrap evidence anchor",
            ),
            (
                "target_assignment == binding.bootstrap_assignment",
                "probe sealed assignment evidence equality",
            ),
            (
                "|| !target_binding_matches",
                "role-specific target authority acceptance",
            ),
        ],
    )?;
    if server_authentication.contains("binding.target_request_snapshot != target_snapshot") {
        return Err(
            "bootstrap authentication retained role-blind target instance equality".to_owned(),
        );
    }
    let admitted_bootstrap = semantic_function_region(
        &sources.process,
        "fn run_admitted_target_desktop_bootstrap(",
        "fn authenticate_target_desktop_bootstrap_server(",
    )
    .ok_or_else(|| "admitted target desktop bootstrap has no semantic boundary".to_owned())?;
    require_source_order(
        &admitted_bootstrap,
        &[
            (
                "authenticate_target_desktop_bootstrap_server(",
                "server authentication before Started",
            ),
            (
                "TargetDesktopBootstrapPipeOperation::StartedWrite",
                "complete Started publication",
            ),
            (
                "TargetDesktopBootstrapMessageV1::Started {",
                "binding-bound Started frame",
            ),
            (
                ".after_started_publication_error(bytes_transferred)",
                "Started partial-publication evidence",
            ),
            ("match role {", "role execution only after Started"),
        ],
    )?;
    let bounded_frame_writer = semantic_function_region(
        &sources.pipe,
        "pub fn write_frame_bounded<T: Serialize>(",
        "fn read_exact_bounded(",
    )
    .ok_or_else(|| "bounded bootstrap frame writer has no semantic boundary".to_owned())?;
    require_source_order(
        &bounded_frame_writer,
        &[
            ("let mut offset = 0;", "zero-byte initial publication state"),
            ("while offset < bytes.len() {", "complete-frame write loop"),
            (
                "Err(error) => return Err(error.with_bytes_transferred(offset))",
                "partial native failure byte evidence",
            ),
            (
                ".with_bytes_transferred(offset)",
                "zero-progress failure byte evidence",
            ),
            ("offset += transferred;", "complete transfer accounting"),
        ],
    )?;
    let target_lease_create = semantic_function_region(
        &sources.process,
        "    pub fn create(",
        "    fn attest_live(&self) -> Result<(), String> {",
    )
    .ok_or_else(|| "target desktop lease creation has no semantic boundary".to_owned())?;
    require_source_order(
        &target_lease_create,
        &[
            (
                "let expected_window_station_policy_sha256 =\n            SecurityDescriptor::from_sddl(&expected_window_station_sddl)?\n                .user_object_policy_fingerprint(\n                    super::security::SecurityObjectKind::WindowStation,\n                )?;",
                "launcher canonical station policy fingerprint construction",
            ),
            (
                "let expected_desktop_policy_sha256 = SecurityDescriptor::from_sddl(&expected_desktop_sddl)?\n            .user_object_policy_fingerprint(super::security::SecurityObjectKind::Desktop)?;",
                "launcher canonical desktop policy fingerprint construction",
            ),
            (
                "read_target_desktop_bootstrap_attestation(",
                "Ready and both clearance proofs",
            ),
            (
                "frame.window_station_policy_sha256 != expected_window_station_policy_sha256",
                "station canonical policy evidence",
            ),
            (
                "frame.desktop_policy_sha256 != expected_desktop_policy_sha256",
                "desktop canonical policy evidence",
            ),
            (
                "!frame.window_station_policy_verified",
                "station policy evidence",
            ),
            ("!frame.desktop_policy_verified", "desktop policy evidence"),
            (
                "validate_target_desktop_binding(&frame.window_station_name, &frame.desktop_name)?;",
                "nonce-private USER-object names",
            ),
            (
                "broker_control.finish(&binding.binding_sha256)?;",
                "broker disarm only after final USER-object evidence",
            ),
        ],
    )?;
    require_source(
        &target_lease_create,
        "window_station_live_equality_sha256: frame.window_station_live_equality_sha256,",
        "station final live-equality evidence retained in lease",
    )?;
    require_source(
        &target_lease_create,
        "desktop_live_equality_sha256: frame.desktop_live_equality_sha256,",
        "desktop final live-equality evidence retained in lease",
    )?;
    let holder_lease_drop = semantic_function_region(
        &sources.process,
        "impl Drop for TargetDesktopLease {",
        "#[allow(clippy::too_many_arguments)]",
    )
    .ok_or_else(|| "target desktop lease drop has no semantic boundary".to_owned())?;
    require_source_order(
        &holder_lease_drop,
        &[
            (
                ".bootstrap_job",
                "launcher-owned one-process Job termination authority",
            ),
            (
                ".terminate(TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS)",
                "Job-scoped holder timeout termination",
            ),
            (
                "WaitForSingleObject(self.bootstrap_process.raw(), 5_000)",
                "bounded post-termination convergence",
            ),
        ],
    )?;
    if holder_lease_drop.contains("TerminateProcess(") {
        return Err(
            "target desktop lease retained direct process termination authority".to_owned(),
        );
    }
    for (exit, diagnostic) in [
        ("BROKER_FAILURE_ARGUMENTS", "Some((\"arguments\", None))"),
        (
            "BROKER_FAILURE_SOURCE_PRIVILEGE_NORMALIZATION",
            "{\n            Some((\"source-privilege-normalization\", None))\n        }",
        ),
        (
            "BROKER_FAILURE_PROCESS_PROTECTION",
            "Some((\"process-protection\", None))",
        ),
        (
            "BROKER_FAILURE_PROCESS_DESCRIPTOR",
            "{\n            Some((\"process-protection\", Some(\"process-descriptor\")))\n        }",
        ),
        (
            "BROKER_FAILURE_PROCESS_APPLY",
            "Some((\"process-protection\", Some(\"process-apply\")))",
        ),
        (
            "BROKER_FAILURE_PROCESS_READBACK",
            "Some((\"process-protection\", Some(\"process-readback\")))",
        ),
        (
            "BROKER_FAILURE_TOKEN_OPEN",
            "Some((\"process-protection\", Some(\"token-open\")))",
        ),
        (
            "BROKER_FAILURE_TOKEN_DESCRIPTOR",
            "Some((\"process-protection\", Some(\"token-descriptor\")))",
        ),
        (
            "BROKER_FAILURE_TOKEN_DACL_APPLY",
            "Some((\"process-protection\", Some(\"token-dacl-apply\")))",
        ),
        (
            "BROKER_FAILURE_TOKEN_READBACK",
            "Some((\"process-protection\", Some(\"token-readback\")))",
        ),
        (
            "BROKER_FAILURE_CERTIFICATION",
            "Some((\"certification\", None))",
        ),
        (
            "BROKER_FAILURE_LISTENER_PREPARATION",
            "Some((\"listener-preparation\", None))",
        ),
        (
            "BROKER_FAILURE_RUNNING_PUBLICATION",
            "Some((\"running-publication\", None))",
        ),
        (
            "BROKER_FAILURE_NONCE_VALIDATION",
            "Some((\"nonce-validation\", None))",
        ),
    ] {
        require_source(
            &sources.session_broker,
            &format!("{exit} => {diagnostic}"),
            "bijective broker startup-stage diagnostic",
        )?;
    }
    require_source(
        &sources.service_manager,
        "startup_diagnostic=role=session-broker operation=startup stage={stage} subphase={subphase}",
        "SCM stopped-state broker startup diagnostic",
    )?;
    require_source(
        &sources.pipe,
        "Self::SessionBroker => \"session-broker\"",
        "session-broker endpoint role diagnostic",
    )?;
    require_source(
        &sources.session_broker,
        "usize::try_from(value)",
        "checked protocol-handle native-width conversion",
    )?;
    require_source(
        &sources.process,
        "decode_protocol_handle(launcher_job_handle, \"launcher-job\")?",
        "checked launcher Job capability decoding",
    )?;

    require_source_order(
        &sources.process,
        &[
            (
                "pub(crate) fn create_session_broker_holder(",
                "broker-only fixed holder creator",
            ),
            (
                "HOLDER_JOB_BROKER_ACCESS",
                "least-rights launcher Job adoption",
            ),
            (
                "derive_session_broker_holder_primary(target_session_id)?",
                "broker-local holder token derivation",
            ),
            (
                "validate_installed_target_desktop_bootstrap()?",
                "fixed installed holder validation",
            ),
            (
                "PROC_THREAD_ATTRIBUTE_JOB_LIST as usize",
                "atomic launcher-owned Job assignment",
            ),
            (
                "with_session_broker_launch_privileges(|| {",
                "scoped process-creation privileges",
            ),
            ("CreateProcessAsUserW(", "fixed suspended holder creation"),
            (
                "created.dwProcessId == 0 || created.dwThreadId == 0",
                "nonzero native process and primary-thread identities",
            ),
            (
                "GetProcessIdOfThread(thread.raw())",
                "broker primary-thread association attestation",
            ),
            (
                "identity.process_id != created.dwProcessId",
                "native and queried process identity equality",
            ),
            (
                "process_token_query_attestation(process.raw())?",
                "independent assigned-token readback",
            ),
            (
                "super::session_broker::HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS,",
                "exact broker arm request for local duplicate",
            ),
            (
                "super::session_broker::HOLDER_THREAD_BROKER_ARM_GRANTED_ACCESS,",
                "exact canonical native grant readback for local duplicate",
            ),
            (
                "primary_thread_id: created.dwThreadId,",
                "primary TID preservation for protocol publication",
            ),
        ],
    )?;
    require_source(
        &sources.process,
        "actual_granted_access != expected_granted_access",
        "no arbitrary granted-access superset acceptance",
    )?;
    require_source(
        &sources.session_broker,
        "actual_granted_access != expected_granted_access",
        "no arbitrary creator-thread granted-access superset acceptance",
    )?;
    for diagnostic in [
        "requested_access={requested_access:#010x}",
        "expected_granted_access={expected_granted_access:#010x}",
        "actual_granted_access={actual_granted_access:#010x}",
        "inherited={inherited}",
    ] {
        require_source(
            &sources.process,
            diagnostic,
            "self-describing broker arm duplicate diagnostic",
        )?;
        require_source(
            &sources.session_broker,
            diagnostic,
            "self-describing broker arm open diagnostic",
        )?;
    }
    require_source_order(
        &sources.token,
        &[
            (
                "pub(crate) fn derive_session_broker_holder_primary(",
                "broker-local token derivation",
            ),
            (
                "let broker_source = token_attestation_snapshot(source.raw())?;",
                "immutable broker source baseline",
            ),
            (
                "ScopedPrivilegeThreadToken::install(carrier.raw())",
                "disposable privilege carrier installation",
            ),
            (
                "let mutable_access = TOKEN_QUERY",
                "post-carrier mutable primary access",
            ),
            ("NtSetInformationToken(", "target-session mutation"),
            (
                "token_privileges_except_change_notify(mutable.raw())?",
                "complete privilege deletion inventory",
            ),
            ("Attributes: 0x0000_0004,", "irreversible privilege removal"),
            ("scoped.revert()", "fail-closed carrier reversion"),
            (
                "holder_effective.behavior.token_is_restricted",
                "unrestricted-holder oracle",
            ),
            (
                "!holder_effective.behavior.restricting_sids.is_empty()",
                "empty restricting-SID proof",
            ),
            (
                "privilege_inventory_is_change_notify_only",
                "SeChangeNotify-only final privilege proof",
            ),
            (
                "token_attestation_snapshot(source.raw())? != broker_source",
                "broker source invariance",
            ),
            (
                "HOLDER_LAUNCH_TOKEN_ACCESS",
                "final launch-handle narrowing",
            ),
            ("drop(source);", "source handle retired before transfer"),
            (
                "require_current_thread_token_absent()?;",
                "no thread-token residue",
            ),
        ],
    )?;
    let owner_scope = semantic_function_region(
        &sources.token,
        "pub(crate) fn with_scoped_service_owner_restore_privilege<T>(",
        "pub(crate) fn validate_holder_session_derivation(",
    )
    .ok_or_else(|| "package service-owner privilege scope has no semantic boundary".to_owned())?;
    require_source_order(
        &owner_scope,
        &[
            (
                "require_current_thread_token_absent()",
                "thread-token absence preflight",
            ),
            (
                "let source_access = TOKEN_QUERY | TOKEN_DUPLICATE;",
                "least-rights process-token source",
            ),
            (
                "DuplicateTokenEx(",
                "disposable impersonation-carrier duplication",
            ),
            (
                "wide_null(\"SeRestorePrivilege\")",
                "restore privilege selection",
            ),
            ("AdjustTokenPrivileges(", "restore privilege enablement"),
            (
                "exact_enabled_privilege_transition",
                "exact carrier privilege-transition readback",
            ),
            (
                "ScopedPrivilegeThreadToken::install(carrier.raw())",
                "thread-only privilege carrier installation",
            ),
            (
                "effective_thread_privilege_enabled(\"SeRestorePrivilege\")",
                "effective restore-privilege proof",
            ),
            ("Ok(true) => operation()", "single scoped mutation"),
            ("scoped.revert()", "fail-closed carrier reversion"),
            (
                "privilege_snapshots_equal(&source_after, &source_privileges)",
                "process-token privilege invariance",
            ),
            (
                "require_current_thread_token_absent()",
                "post-scope thread-token residue proof",
            ),
        ],
    )?;
    if owner_scope.contains("SeTakeOwnershipPrivilege")
        || owner_scope.contains("SeSecurityPrivilege")
        || owner_scope.contains("TOKEN_ADJUST_PRIVILEGES | TOKEN_DUPLICATE")
    {
        return Err("package owner scope widens beyond the disposable restore carrier".to_owned());
    }

    let broker_configuration = semantic_function_region(
        &sources.service_manager,
        "fn configure_session_broker_handle(",
        "fn verify_session_broker_handle(",
    )
    .ok_or_else(|| "session-broker configuration has no semantic boundary".to_owned())?;
    require_source_order(
        &broker_configuration,
        &[
            (
                "ServiceSidType::Unrestricted",
                "unrestricted service SID type",
            ),
            (
                "configure_no_failure_actions(service)?;",
                "no broker restart actions",
            ),
            (
                "session_broker_service_sddl()?",
                "exact broker service descriptor",
            ),
            (
                "with_scoped_service_owner_restore_privilege(|| {",
                "package-only owner assignment scope",
            ),
            (
                "descriptor.apply_owner_group_dacl_to_service(service.raw())",
                "owner/group/DACL service application",
            ),
            (
                "verify_session_broker_handle(service, config)",
                "unprivileged broker configuration readback",
            ),
        ],
    )?;

    let package_configuration = semantic_function_region(
        &sources.package,
        "fn configure_services(",
        "fn require_fresh_service_absence(manager: &service_manager::ScHandle) -> Result<(), String> {",
    )
    .ok_or_else(|| "package service configuration has no semantic boundary".to_owned())?;
    require_source_order(
        &package_configuration,
        &[
            (
                "create_session_broker_registration(",
                "fresh broker registration boundary",
            ),
            (
                "transition.session_broker_created = true;",
                "immediate transaction ownership record",
            ),
            (
                "service_manager::configure_created_session_broker(",
                "post-ownership broker configuration",
            ),
        ],
    )?;

    let absence = semantic_function_region(
        &sources.package,
        "pub fn provider_state_absent() -> Result<bool, String> {",
        "fn path_absent_no_follow(path: &Path, phase: &str) -> Result<bool, String> {",
    )
    .ok_or_else(|| "provider absence predicate has no semantic boundary".to_owned())?;
    for (fragment, invariant) in [
        (
            "exists(&manager, WINDOWS_SESSION_BROKER_SERVICE_NAME)",
            "broker service absence",
        ),
        (
            "endpoint_exists(WINDOWS_SESSION_BROKER_PIPE)",
            "broker pipe absence",
        ),
    ] {
        require_source(&absence, fragment, invariant)?;
    }
    require_source_order(
        &sources.package,
        &[
            (
                "pub(crate) const SESSION_BROKER_PRIVILEGES",
                "broker privilege inventory",
            ),
            (
                "\"SeAssignPrimaryTokenPrivilege\",",
                "assign-primary broker privilege",
            ),
            ("\"SeIncreaseQuotaPrivilege\",", "quota broker privilege"),
            ("\"SeImpersonatePrivilege\",", "remote-arm broker privilege"),
            (
                "\"SeSecurityPrivilege\",",
                "protected-SACL broker privilege",
            ),
            ("\"SeTcbPrivilege\",", "TCB broker privilege"),
            (
                "let source_broker = packaged_session_broker(&source)?;",
                "packaged broker discovery",
            ),
            ("session_broker_bytes", "broker artifact capture"),
            ("SessionBrokerConfig {", "broker service configuration"),
            ("reconcile_session_broker", "broker service reconciliation"),
            (
                "remove(&manager, WINDOWS_SESSION_BROKER_SERVICE_NAME)",
                "broker uninstall",
            ),
            (
                "is_running(&manager, WINDOWS_SESSION_BROKER_SERVICE_NAME)?",
                "one-shot stopped-state verification",
            ),
        ],
    )?;
    require_source(
        &sources.package,
        "verify_native_session_broker_pe(&session_broker_bytes)?",
        "broker native-machine/PE/import validation",
    )?;
    require_source_order(
        &sources.package,
        &[
            (
                "if imports.machine != expected {",
                "installed native-machine equality gate",
            ),
            (
                "Ok(memcordon_core::WINDOWS_PE_MACHINE_AMD64)",
                "x64 native PE identity",
            ),
            (
                "Ok(memcordon_core::WINDOWS_PE_MACHINE_ARM64)",
                "arm64 native PE identity",
            ),
        ],
    )?;
    require_source(
        &sources.package,
        "pub(crate) const SESSION_BROKER_PRIVILEGES: &[&str] = &[\n    \"SeAssignPrimaryTokenPrivilege\",\n    \"SeIncreaseQuotaPrivilege\",\n    \"SeImpersonatePrivilege\",\n    \"SeSecurityPrivilege\",\n    \"SeTcbPrivilege\",\n];",
        "exact broker runtime privilege inventory for launch and protected USER-object arming",
    )?;
    Ok(())
}

fn validate_windows_qualification_terminal_ack_contract(
    sources: &WindowsProductionSources,
) -> Result<(), String> {
    let canary = semantic_function_region(
        &sources.qualification,
        "fn native_public_canary(",
        "pub(crate) fn qualification_process_attempt_id(",
    )
    .ok_or_else(|| "native qualification terminal consumer boundary is absent".to_owned())?;
    require_source_order(
        &canary,
        &[
            (
                "WindowsProviderResponseV1::Terminal(terminal)",
                "bound terminal selection",
            ),
            (
                "let semantic_result = (|| {",
                "terminal semantic-result latch",
            ),
            (
                "validate_qualification_terminal(&terminal, target_result_receipt)?.clone()",
                "terminal semantic validation inside the latch",
            ),
            (
                "read_bound_nested_child_receipt(marker, &expected_binding)?",
                "nested receipt validation inside the latch",
            ),
            (
                "let terminal_result = acknowledge_latched_qualification_terminal(",
                "bound terminal acknowledgment resolution",
            ),
            (
                "acknowledge_and_confirm_terminal_retirement(",
                "exact public terminal ACK and retirement confirmation",
            ),
            ("return terminal_result;", "post-ACK semantic propagation"),
        ],
    )?;

    let retirement_confirmation = semantic_function_region(
        &sources.qualification,
        "fn acknowledge_and_confirm_terminal_retirement(",
        "#[cfg(test)]",
    )
    .ok_or_else(|| {
        "qualification terminal-retirement confirmation boundary is absent".to_owned()
    })?;
    require_source_order(
        &retirement_confirmation,
        &[
            (
                "&WindowsProviderRequestV1::TerminalAcknowledged {",
                "exact public terminal ACK",
            ),
            (
                "WindowsProviderResponseV1::TerminalRetired(retired)",
                "launcher-authored terminal retirement confirmation",
            ),
            (
                "retired.is_consistent_for(",
                "exact terminal response digest binding",
            ),
        ],
    )?;

    let resolver = semantic_function_region(
        &sources.qualification,
        "fn acknowledge_latched_qualification_terminal<T>(",
        "#[cfg(test)]",
    )
    .ok_or_else(|| "qualification terminal ACK resolver boundary is absent".to_owned())?;
    require_source_order(
        &resolver,
        &[
            (
                "let acknowledgment_result = acknowledge().map_err(|detail| {",
                "ACK attempt before result resolution",
            ),
            (
                "match (semantic_result, acknowledgment_result) {",
                "latched semantic/ACK resolution",
            ),
            (
                "(Err(primary), Ok(())) => Err(primary),",
                "primary semantic failure after successful ACK",
            ),
            (
                "(Ok(_), Err(acknowledgment)) => Err(acknowledgment.to_string()),",
                "ACK-only failure propagation",
            ),
            (
                "(Err(primary), Err(acknowledgment)) => Err(format!(",
                "primary-plus-secondary failure resolution",
            ),
            (
                "terminal acknowledgment failed after bound receipt was latched",
                "secondary ACK evidence label",
            ),
        ],
    )?;
    require_source(
        &sources.qualification,
        "MCSEALED-WINDOWS-TERMINAL-ACKNOWLEDGMENT: stage={} api={} object_role=bound-terminal-delivery attempt_id={} nonce_sha256={} request_sha256={} detail={}",
        "typed bound-terminal ACK diagnostic",
    )?;

    let control_relay = semantic_function_region(
        &sources.control,
        "fn relay_protocol(",
        "fn advance_relay_phase(",
    )
    .ok_or_else(|| "control terminal relay boundary is absent".to_owned())?;
    require_source_order(
        &control_relay,
        &[
            (
                "match pipe::read_frame::<WindowsProviderRequestV1>(public)? {",
                "frontend terminal ACK read",
            ),
            (
                "WindowsProviderRequestV1::TerminalAcknowledged {",
                "frontend terminal ACK binding",
            ),
            (
                "&WindowsLauncherRequestV1::TerminalAcknowledged {",
                "private terminal ACK forwarding",
            ),
            (
                "WindowsLauncherResponseV1::TerminalRetired(retired)",
                "launcher retirement confirmation read",
            ),
            (
                "&WindowsProviderResponseV1::TerminalRetired(retired)",
                "public retirement confirmation forwarding",
            ),
        ],
    )?;

    let platform_retirement = semantic_function_region(
        &sources.platform,
        "fn acknowledge_terminal_retirement(",
        "fn rejection_error(rejection: memcordon_core::ProviderRejectionEvidence) -> Error {",
    )
    .ok_or_else(|| "platform terminal-retirement helper boundary is absent".to_owned())?;
    require_source_order(
        &platform_retirement,
        &[
            (
                "&WindowsProviderRequestV1::TerminalAcknowledged {",
                "platform public terminal ACK",
            ),
            (
                "attempt_id: attempt_id.to_owned(),",
                "platform terminal ACK attempt binding",
            ),
            (
                "nonce: nonce.to_owned(),",
                "platform terminal ACK nonce binding",
            ),
            (
                "request_sha256: request_sha256.to_owned(),",
                "platform terminal ACK request-digest binding",
            ),
            (
                "terminal_response_sha256: terminal_response_sha256.to_owned(),",
                "platform terminal ACK response-digest binding",
            ),
            (
                "WindowsProviderResponseV1::TerminalRetired(retired)",
                "platform terminal-retirement receipt",
            ),
            (
                "retired.is_consistent_for(",
                "platform response-digest retirement proof",
            ),
            (
                "terminal_response_sha256,",
                "platform exact terminal-response digest binding",
            ),
            (
                "WindowsProviderResponseV1::AttemptRetained(retained)",
                "platform retained-attempt failure",
            ),
            (
                "Err(format!(",
                "platform retained-attempt error propagation",
            ),
            (
                "_ => Err(\"provider did not confirm exact terminal retirement\"",
                "platform invalid-retirement failure",
            ),
        ],
    )?;

    let launch_attempt = semantic_function_region(
        &sources.launcher,
        "fn launch_attempt(",
        "fn build_terminal_receipt(",
    )
    .ok_or_else(|| "launcher attempt retirement boundary is absent".to_owned())?;
    require_source_order(
        &launch_attempt,
        &[
            (
                "record.stage_terminal_response(&response)?;",
                "durable terminal outbox staging",
            ),
            (
                "pipe::write_frame(connection, &response)?;",
                "bound terminal delivery",
            ),
            (
                "wait_for_terminal_acknowledgment(",
                "exact terminal ACK wait",
            ),
            (
                "record.acknowledge_terminal_response()?;",
                "pending terminal outbox retirement",
            ),
            (
                "&WindowsLauncherResponseV1::TerminalRetired(retired)",
                "launcher-authored retirement receipt",
            ),
        ],
    )?;

    let record_ack = semantic_function_region(
        &sources.record,
        "    pub fn acknowledge_terminal_response(&mut self) -> Result<(), String> {",
        "    pub fn mark_released(&mut self) -> Result<(), String> {",
    )
    .ok_or_else(|| "durable terminal outbox acknowledgment boundary is absent".to_owned())?;
    require_source_order(
        &record_ack,
        &[
            (
                "if self.terminal_response_json.is_none() {",
                "pending terminal outbox precondition",
            ),
            (
                "remove_guardian_receipt(&self.attempt_id)?;",
                "terminal guardian receipt retirement",
            ),
            (
                "fs::remove_file(record_path(&self.attempt_id)?)",
                "Empty attempt/outbox retirement",
            ),
        ],
    )?;
    Ok(())
}

fn validate_windows_preauthorization_abort_terminal_contract(
    sources: &WindowsProductionSources,
) -> Result<(), String> {
    let control_serve = semantic_function_region(
        &sources.control,
        "fn serve(listener: PipeListener, first: OwnedHandle) -> Result<(), String> {",
        "fn stable_error_code(error: &str) -> &str {",
    )
    .ok_or_else(|| "control connection-owner boundary is absent".to_owned())?;
    if control_serve.contains("WindowsProviderResponseV1::Reject")
        || control_serve.contains("attempt_id: String::new()")
    {
        return Err("control connection owner can publish an unbound fallback".to_owned());
    }
    let launcher_serve = semantic_function_region(
        &sources.launcher,
        "fn serve(listener: PipeListener, first: OwnedHandle) -> Result<(), String> {",
        "fn handle_control(connection: HANDLE) -> Result<(), String> {",
    )
    .ok_or_else(|| "launcher connection-owner boundary is absent".to_owned())?;
    if launcher_serve.contains("WindowsLauncherResponseV1::Reject")
        || launcher_serve.contains("attempt_id: String::new()")
    {
        return Err("launcher connection owner can publish an unbound fallback".to_owned());
    }
    let launch_failure_owner = sources
        .control
        .split_once("WindowsProviderRequestV1::Launch(launch)")
        .and_then(|(_, region)| {
            region
                .split_once("WindowsProviderRequestV1::CertificationFault")
                .map(|(region, _)| region)
        })
        .ok_or_else(|| "control launch-failure owner boundary is absent".to_owned())?;
    require_source(
        launch_failure_owner,
        "&WindowsProviderResponseV1::AttemptRetained(retained)",
        "bound retained-attempt publication",
    )?;

    for (source, fragment, invariant) in [
        (
            &sources.control,
            "enum LaunchResponseState {\n    None,\n    BoundAttemptActive,\n    TerminalDelivered,\n}",
            "typed control response commitment",
        ),
        (
            &sources.control,
            "match (&failure.progress.binding, failure.progress.response_state)",
            "exhaustive launch-failure owner",
        ),
        (
            &sources.control,
            "_ => Err(failure.diagnostic()),",
            "post-commit fallback prohibition",
        ),
        (
            &sources.control,
            "match replay_terminal(",
            "active attempt durable-terminal replay",
        ),
        (
            &sources.control,
            "&WindowsProviderResponseV1::PackageCleanupResult {",
            "request-typed package-cleanup result",
        ),
        (
            &sources.control,
            "WindowsControlRequestStatusV1::Active",
            "request-typed active cleanup status",
        ),
        (
            &sources.record,
            "pub terminal_disposition: Option<WindowsAttemptTerminalDispositionV1>",
            "durable typed terminal disposition",
        ),
        (
            &sources.record,
            "WindowsAttemptTerminalDispositionV1::PreauthorizationAbort",
            "preauthorization-abort outbox disposition",
        ),
        (
            &sources.record,
            "rejection.terminal_ack_required",
            "abort Reject ACK requirement",
        ),
        (
            &sources.qualification,
            "if rejection.terminal_ack_required {",
            "qualification abort Reject acknowledgment",
        ),
        (
            &sources.launcher,
            "secondary terminal ACK failure",
            "primary-preserving launcher ACK diagnostic",
        ),
        (
            &sources.platform,
            "secondary terminal acknowledgment failure",
            "primary-preserving public ACK diagnostic",
        ),
        (
            &sources.platform,
            "acknowledge_terminal_retirement(",
            "frontend terminal-retirement confirmation",
        ),
        (
            &sources.platform,
            "&WindowsProviderRequestV1::ReplayTerminal {",
            "frontend exact terminal replay request",
        ),
        (
            &sources.qualification,
            "impl Drop for QualificationRelayRetirement {",
            "qualification fail-safe relay retirement",
        ),
        (
            &sources.qualification,
            "qualification_control_peer_identity(pipe.raw())? != control_peer_identity",
            "qualification replay peer identity pin",
        ),
        (
            &sources.control,
            "caller_token_sha256: caller.token_sha256.clone(),",
            "server-derived replay token binding",
        ),
        (
            &sources.launcher,
            "WindowsLauncherResponseV1::ReplayPending(pending)",
            "typed private replay-pending frontier",
        ),
        (
            &sources.platform,
            "WindowsPublicFrameFailureV1::PeerClosed(WindowsPublicFramePhaseV1::Availability)",
            "public availability peer-close classification",
        ),
    ] {
        require_source(source, fragment, invariant)?;
    }

    let replay_terminal = semantic_function_region(
        &sources.control,
        "fn replay_terminal(",
        "pub(super) const CERTIFICATION_FRONTEND_HANDLE_ROLES: [&str;",
    )
    .ok_or_else(|| "control terminal-replay boundary is absent".to_owned())?;
    require_source_order(
        &replay_terminal,
        &[
            (
                "WindowsLauncherRequestV1::ReplayTerminal {",
                "exact private replay request",
            ),
            (
                "pipe::write_frame(public, &public_response)?;",
                "public replay",
            ),
            (
                "WindowsProviderRequestV1::TerminalAcknowledged {",
                "exact public replay ACK",
            ),
            (
                "WindowsLauncherRequestV1::TerminalAcknowledged {",
                "exact private replay ACK",
            ),
            (
                "WindowsLauncherResponseV1::TerminalRetired(retired)",
                "launcher-authored replay retirement receipt",
            ),
            (
                "WindowsProviderResponseV1::TerminalRetired(retired)",
                "forwarded public replay retirement receipt",
            ),
        ],
    )?;

    let private_replay = semantic_function_region(
        &sources.launcher,
        "fn handle_control(connection: HANDLE) -> Result<(), String> {",
        "fn authenticate_control(connection: HANDLE) -> Result<(), ControlAuthenticationError> {",
    )
    .ok_or_else(|| "launcher control-request boundary is absent".to_owned())?;
    require_source_order(
        &private_replay,
        &[
            (
                "super::record::pending_terminal_response(",
                "authenticated create-once outbox lookup",
            ),
            (
                "pipe::write_frame(connection, &response)?;",
                "exact outbox replay",
            ),
            ("wait_for_terminal_acknowledgment(", "exact replay ACK wait"),
            (
                "super::record::acknowledge_terminal_response(&attempt_id, &nonce, &request_sha256)?",
                "ACK-gated outbox retirement",
            ),
            (
                "WindowsLauncherResponseV1::TerminalRetired(retired)",
                "launcher-authored terminal retirement receipt",
            ),
        ],
    )?;

    let terminal_stage = semantic_function_region(
        &sources.record,
        "    pub fn stage_terminal_response(",
        "    pub fn acknowledge_terminal_response(&mut self) -> Result<(), String> {",
    )
    .ok_or_else(|| "durable terminal-staging boundary is absent".to_owned())?;
    require_source(
        &terminal_stage,
        "&& rejection.terminal_ack_required",
        "preauthorization-abort durable ACK requirement",
    )?;

    let launch_attempt = semantic_function_region(
        &sources.launcher,
        "fn launch_attempt(",
        "fn build_terminal_receipt(",
    )
    .ok_or_else(|| "launcher attempt boundary is absent".to_owned())?;
    let abort_completions = launch_attempt
        .match_indices("record.complete_preauthorization_abort()?;")
        .count();
    if abort_completions != 2 || launch_attempt.contains("record.retire()?;") {
        return Err(
            "preauthorization abort must retain both cleaned attempts through terminal ACK"
                .to_owned(),
        );
    }
    Ok(())
}

fn validate_windows_production_contract(sources: &WindowsProductionSources) -> Result<(), String> {
    validate_windows_session_broker_contract(sources)?;
    validate_windows_live_kernel_access_check_contract(&sources.security)?;
    validate_windows_qualification_terminal_ack_contract(sources)?;
    validate_windows_preauthorization_abort_terminal_contract(sources)?;
    require_source(
        &sources.token,
        "OpenThreadToken(thread, TOKEN_QUERY | TOKEN_QUERY_SOURCE, 1, &raw mut token)",
        "thread-token readback through process authorization",
    )?;
    require_source(
        &sources.token,
        "const SE_CHANGE_NOTIFY_PRIVILEGE_LUID: LUID = LUID {\n    LowPart: 23,\n    HighPart: 0,\n};",
        "documented handle-pure SeChangeNotifyPrivilege catalog entry",
    )?;
    let sensitive_privilege_normalization = semantic_function_region(
        &sources.token,
        "fn enabled_sensitive_privilege_count(token: HANDLE) -> Result<u32, String> {",
        "fn privilege_is_enabled_sensitive(entry: &LUID_AND_ATTRIBUTES) -> bool {",
    )
    .ok_or_else(|| "sensitive-privilege normalization boundary is absent".to_owned())?;
    require_source_order(
        &sensitive_privilege_normalization,
        &[
            (
                "let buffer = query(token, TokenPrivileges)?;",
                "handle-only privilege query",
            ),
            (
                "let entries = token_privilege_entries(buffer.as_bytes())?;",
                "local privilege inventory parse",
            ),
            (
                ".filter(|entry| privilege_is_enabled_sensitive(entry))",
                "documented-LUID sensitive privilege classification",
            ),
        ],
    )?;
    if sensitive_privilege_normalization.contains("LookupPrivilegeValueW(") {
        return Err(
            "sensitive-privilege normalization resolves a privilege through ambient LSA access"
                .to_owned(),
        );
    }
    let change_notify_inventory = semantic_function_region(
        &sources.token,
        "fn privilege_inventory_is_change_notify_only(inventory: &[String]) -> Result<bool, String> {",
        "fn current_process_token_with_access(access: u32) -> Result<OwnedHandle, String> {",
    )
    .ok_or_else(|| "change-notify inventory normalization boundary is absent".to_owned())?;
    require_source_order(
        &change_notify_inventory,
        &[
            (
                "SE_CHANGE_NOTIFY_PRIVILEGE_LUID.HighPart as u32",
                "catalog HighPart use",
            ),
            (
                "SE_CHANGE_NOTIFY_PRIVILEGE_LUID.LowPart",
                "catalog LowPart use",
            ),
        ],
    )?;
    if change_notify_inventory.contains("LookupPrivilegeValueW(") {
        return Err(
            "change-notify inventory normalization resolves a privilege through ambient LSA access"
                .to_owned(),
        );
    }
    let effective_thread_identity = semantic_function_region(
        &sources.token,
        "fn effective_thread_token_identity() -> Result<EffectiveThreadTokenIdentity, String> {",
        "fn require_effective_thread_token_identity(",
    )
    .ok_or_else(|| "restricted fixture identity observer is absent".to_owned())?;
    require_source_order(
        &effective_thread_identity,
        &[
            (
                "OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut observed)",
                "query-only process-authorized current-thread observation",
            ),
            (
                "let observed = OwnedHandle::new(observed)",
                "owned observer adoption",
            ),
            (
                "let statistics = token_statistics(observed.raw())",
                "TokenStatistics-only identity query",
            ),
            (
                "token_id: luid_to_u64(&statistics.TokenId)",
                "TokenId evidence",
            ),
            (
                "modified_id: luid_to_u64(&statistics.ModifiedId)",
                "ModifiedId evidence",
            ),
            (
                "token_type: statistics.TokenType as u32",
                "token-type evidence",
            ),
            (
                "impersonation_level: statistics.ImpersonationLevel as u32",
                "impersonation-level evidence",
            ),
            ("drop(observed);", "observer closed before token loan"),
            ("Ok(identity)", "identity-only observer result"),
        ],
    )?;
    for forbidden in [
        "TOKEN_QUERY_SOURCE",
        "token_attestation_snapshot(",
        "token_fixture_snapshot(",
        "current_process_token(",
    ] {
        if effective_thread_identity.contains(forbidden) {
            return Err(format!(
                "restricted fixture identity observer contains forbidden operation {forbidden}"
            ));
        }
    }
    require_source(
        &sources.token,
        "== Some(ERROR_NO_TOKEN)\n    {\n        \"effective-thread-presence\"",
        "explicit missing-current-thread-token rejection stage",
    )?;
    let effective_thread_identity_compare = semantic_function_region(
        &sources.token,
        "fn require_effective_thread_token_identity(",
        "pub(crate) fn effective_thread_token_identity_validation_for_test(",
    )
    .ok_or_else(|| "restricted fixture identity comparator is absent".to_owned())?;
    require_source_order(
        &effective_thread_identity_compare,
        &[
            (
                "if expected.token_id == 0 {",
                "nonzero cached TokenId requirement",
            ),
            (
                "if observed.token_id == 0 {",
                "nonzero observed TokenId requirement",
            ),
            (
                "if expected.token_id != observed.token_id {",
                "exact TokenId equality",
            ),
            (
                "if expected.modified_id != observed.modified_id {",
                "exact ModifiedId equality",
            ),
            (
                "expected.token_type != TokenImpersonation as u32",
                "impersonation-token type requirement",
            ),
            (
                "expected.impersonation_level != SecurityImpersonation as u32",
                "SecurityImpersonation level requirement",
            ),
        ],
    )?;
    let retained_effective_token = semantic_function_region(
        &sources.token,
        "    pub(crate) fn with_effective_token_for_test(",
        "    pub fn revert(mut self) -> Result<(), String> {",
    )
    .ok_or_else(|| "restricted fixture retained-token diagnostic is absent".to_owned())?;
    require_source_order(
        &retained_effective_token,
        &[
            ("if !self.active {", "active impersonation guard check"),
            (
                "token_id: self.attestation_snapshot.instance.token_id",
                "cached pre-install TokenId",
            ),
            (
                "modified_id: self.attestation_snapshot.instance.modified_id",
                "cached pre-install ModifiedId",
            ),
            (
                "let observed = effective_thread_token_identity()?;",
                "independent current-thread observation",
            ),
            (
                "require_effective_thread_token_identity(expected, observed)?;",
                "exact identity and version comparison",
            ),
            (
                "operation(self.token.raw())",
                "scoped guard-owned token loan",
            ),
        ],
    )?;
    for forbidden in [
        "token_attestation_snapshot(",
        "token_fixture_snapshot(",
        "current_process_token(",
        "OpenProcessToken(",
        "operation(observed",
    ] {
        if retained_effective_token.contains(forbidden) {
            return Err(format!(
                "restricted fixture scoped loan contains forbidden operation {forbidden}"
            ));
        }
    }
    let entry_thread_reversion = semantic_function_region(
        &sources.token,
        "pub fn revert_entry_thread_token() -> Result<EntryThreadTokenTransition, String> {",
        "fn open_thread_token(thread: HANDLE) -> Result<Option<OwnedHandle>, String> {",
    )
    .ok_or_else(|| "entry thread-token reversion boundary is absent".to_owned())?;
    require_source_order(
        &entry_thread_reversion,
        &[
            (
                "let Some(token) = open_thread_token(unsafe { GetCurrentThread() })? else {",
                "process-authorized entry thread-token observation",
            ),
            (
                "if unsafe { RevertToSelf() } == 0 {",
                "checked entry reversion",
            ),
            (
                "let initial_token = token_attestation_snapshot(token.raw())?;",
                "retained initial-token attestation",
            ),
            (
                "if thread_token_envelope(unsafe { GetCurrentThread() })?.is_some() {",
                "post-revert thread-token absence check",
            ),
        ],
    )?;
    if entry_thread_reversion.contains("OpenThreadToken(")
        || entry_thread_reversion.contains("OpenProcessToken(")
    {
        return Err(
            "entry thread-token reversion bypasses the process-authorized observation helper"
                .to_owned(),
        );
    }
    let bootstrap_receiver = semantic_function_region(
        &sources.process,
        "pub(super) fn target_desktop_bootstrap(",
        "fn validate_target_desktop_bootstrap_nonce(nonce: &str) -> Result<(), String> {",
    )
    .ok_or_else(|| "target desktop bootstrap receiver has no semantic boundary".to_owned())?;
    require_source_order(
        &bootstrap_receiver,
        &[
            (
                "let process_token = match role {",
                "role-selected local bootstrap token capability",
            ),
            (
                "TargetDesktopBootstrapRoleV1::Holder => {",
                "holder local token role",
            ),
            (
                "super::token::current_process_token_for_access_check()",
                "query-and-duplicate holder capability",
            ),
            (
                "TargetDesktopBootstrapRoleV1::LoaderControl => {",
                "loader-control local token role",
            ),
            (
                "super::token::current_process_token_for_attestation_and_access_check()",
                "query-source-and-duplicate loader-control capability",
            ),
            (
                "TargetDesktopBootstrapRoleV1::Probe => {",
                "probe local token role",
            ),
            (
                "super::token::current_process_token_for_attestation_and_access_check()",
                "query-source-and-duplicate probe capability",
            ),
            (
                "super::pipe::connect_target_desktop_bootstrap_pipe(pipe_name, deadline)?;",
                "bootstrap pipe connection after capability selection",
            ),
            (
                "let process_envelope = super::token::envelope(process_token.raw())?;",
                "selected local token envelope",
            ),
            (
                "let process_snapshot = super::token::token_query_attestation_snapshot(process_token.raw())?;",
                "selected local token query evidence",
            ),
            (
                "let target_token_handle = match (role, target_token_handle) {",
                "role-bound target capability shape",
            ),
            (
                "(TargetDesktopBootstrapRoleV1::Holder, Some(handle)) => Some(handle)",
                "holder receives exact target capability",
            ),
            (
                "(TargetDesktopBootstrapRoleV1::Probe, None) => None",
                "probe receives no target capability",
            ),
            (
                "target desktop bootstrap admission capability shape is invalid",
                "invalid role-capability shape rejection",
            ),
        ],
    )?;
    let started_publication_gate = semantic_function_region(
        &sources.process,
        "fn started_failure_frame_publication_is_safe(bytes_transferred: usize) -> bool {",
        "#[cfg(test)]",
    )
    .ok_or_else(|| "Started failure-publication gate has no semantic boundary".to_owned())?;
    require_source(
        &started_publication_gate,
        "bytes_transferred == 0",
        "failure frame only before any Started bytes",
    )?;
    require_source_order(
        &bootstrap_receiver,
        &[
            (
                "run_admitted_target_desktop_bootstrap(",
                "admitted bootstrap execution",
            ),
            (
                "started_failure_frame_publication_is_safe(",
                "partial Started publication fail-stop gate",
            ),
            (
                "publish_target_desktop_bootstrap_failure(",
                "failure publication only on an unused frame channel",
            ),
        ],
    )?;
    let bootstrap = normalize_windows_source(include_str!(
        "../../../crates/memcordon-cli/src/bin/memcordon-target-desktop-bootstrap.rs"
    ));
    let user_api = normalize_windows_source(include_str!(
        "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/user_api.rs"
    ));
    let pe_imports = normalize_windows_source(include_str!(
        "../../../crates/memcordon-core/src/windows_pe.rs"
    ));
    require_source(
        &bootstrap,
        "[role, pipe_name, nonce] if role == \"holder\"",
        "launcher-token namespace-holder entry",
    )?;
    require_source(
        &bootstrap,
        "[role, pipe_name, nonce, desktop] if role == \"probe\"",
        "exact-target explicit-desktop probe entry",
    )?;
    for (needle, label) in [
        ("GetSystemDirectoryW", "trusted System32 discovery"),
        (".join(\"user32.dll\")", "absolute USER module path"),
        ("LoadLibraryExW", "post-admission USER module load"),
        ("GetProcAddress", "narrow USER export resolution"),
    ] {
        require_source(&user_api, needle, label)?;
    }
    for denied in ["USER32.DLL", "GDI32.DLL", "SHELL32.DLL"] {
        require_source(&pe_imports, denied, "PE loader import denylist")?;
    }
    require_source_order(
        &sources.pipe,
        &[
            (
                "pub fn finish_server_response(handle: HANDLE) -> Result<(), String> {",
                "centralized server response completion",
            ),
            (
                "FlushFileBuffers(handle)",
                "client-consumption response drain",
            ),
            ("disconnect(handle);", "disconnect after response drain"),
        ],
    )?;
    require_source(
        &sources.pipe,
        "pub fn read_frame_detailed<T: DeserializeOwned>(handle: HANDLE) -> Result<T, FrameReadError>",
        "typed frame length, payload, decode, and peer-close diagnostics",
    )?;
    require_source(
        &sources.launcher,
        "pipe::finish_server_response(connection.raw())",
        "launcher normal response drain",
    )?;
    require_source(
        &sources.control,
        "pipe::finish_server_response(connection.raw())",
        "control normal response drain",
    )?;
    require_source_order(
        &sources.control,
        &[
            (
                "fn probe_authenticated_launcher_detailed() -> Result<(), LauncherAuthenticationError> {",
                "typed launcher probe boundary",
            ),
            (
                "pipe::read_frame_detailed::<WindowsLauncherResponseV1>(launcher.raw())",
                "typed launcher probe response read",
            ),
            (
                "peer_process_id={}",
                "authenticated launcher identity diagnostic",
            ),
        ],
    )?;
    require_source_order(
        &sources.launcher,
        &[
            (
                "WindowsSealedFault::LauncherWorkerKilledAfterAuthorization) =>\n        {\n            cleanup_guard.abandon_to_guardian();",
                "launcher abrupt authority-loss path",
            ),
            (
                "pipe::disconnect(connection);",
                "launcher abrupt disconnect",
            ),
        ],
    )?;
    let target_create = semantic_function_region(
        &sources.process,
        "    fn create_with_object_security(",
        "fn validate_target_handle_list(handles: &[HANDLE]) -> Result<(), String> {",
    )
    .ok_or_else(|| "suspended target creation region is missing".to_owned())?;
    require_source_order(
        &target_create,
        &[
            (
                "let requested_process_snapshot =\n            super::token::token_attestation_snapshot(token).map_err(TargetCreateError::from)?;",
                "requested target identity captured before creation",
            ),
            (
                "let process_handle = OwnedHandle::new(process.hProcess).map_err(TargetCreateError::from)?;",
                "suspended target process ownership",
            ),
            (
                "super::token::process_token_query_attestation(process_handle.raw())",
                "exact suspended target token readback",
            ),
            (
                "super::token::require_assigned_process_authority(\n                    \"target-request-to-real-process\",",
                "typed target assignment authority comparison",
            ),
        ],
    )?;
    if target_create
        .matches("lease\n                .attest_live()")
        .count()
        != 1
        || target_create
            .matches("TargetDesktopLease::attest_live")
            .count()
            != 1
    {
        return Err(
            "holder lease is not re-attested exactly once before and after target creation"
                .to_owned(),
        );
    }
    require_source_order(
        &sources.control,
        &[
            (
                "Some(WindowsSealedFault::ControlWorkerKilledAfterAuthorization)\n                && matches!(",
                "control abrupt authority-loss path",
            ),
            (
                "pipe::disconnect(launcher);",
                "launcher-side abrupt disconnect",
            ),
            ("pipe::disconnect(public);", "public-side abrupt disconnect"),
        ],
    )?;
    require_source(
        &sources.process,
        "} else {\n            unsafe {\n                CreateProcessAsUserW(\n                    service_token.as_ref().map_or(token, OwnedHandle::raw),",
        "caller-token CreateProcessAsUserW",
    )?;
    require_source(
        &sources.process,
        "process_attributes_manifest.push(Attribute::new(\n                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,",
        "creation-time Job list",
    )?;
    require_source(
        &sources.process,
        "process_attributes_manifest.push(Attribute::new(\n                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,",
        "creation-time handle list",
    )?;
    require_source(
        &sources.process,
        "let mut handles = streams.target_handles().to_vec();",
        "exact three-stream handle manifest",
    )?;
    require_source(
        &sources.process,
        "validate_target_handle_list(&handles)?;",
        "ordinary exact handle-list validation",
    )?;
    require_source(
        &sources.job,
        "limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;",
        "kill-on-close-only Job policy",
    )?;
    require_source(
        &sources.job,
        "flags & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK) != 0",
        "breakaway readback rejection",
    )?;
    require_source(
        &sources.control,
        "let (primary_token, mut caller_token_envelope, frontend, before) =\n        super::token::authenticate_pipe_client(public, client_pid, None)?;",
        "kernel-authenticated caller token capture",
    )?;
    require_source(
        &sources.control,
        "inside_active_job: true,",
        "recursive-provider membership rejection",
    )?;
    require_source(
        &sources.control,
        "MCSEALED-WINDOWS-RECURSIVE-PROVIDER",
        "typed recursive-provider rejection",
    )?;
    require_source(
        &sources.launcher,
        "super::process::create_guardian(",
        "per-attempt guardian creation",
    )?;
    require_source(
        &sources.launcher,
        "if request.certification_mutant\n                    == Some(memcordon_core::WindowsSealedMutant::ResumeBeforeGuardian)\n                {\n                    2_000",
        "resume-before-guardian two-second readiness delay",
    )?;
    require_source_order(
        &sources.launcher,
        &[
            (
                "super::process::create_guardian(",
                "guardian creation before durable boundary state",
            ),
            (
                "record.guardian_identity = Some(guardian_identity.clone());",
                "guardian identity before durable boundary state",
            ),
            (
                "record.store()?;",
                "durable BoundaryCreated state before readiness observation",
            ),
            (
                "        observe_guardian_startup(",
                "typed guardian ready-and-live observation",
            ),
            (
                ".transition(super::record::WindowsAttemptStateV1::GuardianReady)?;",
                "GuardianReady transition after readiness observation",
            ),
            (
                "cleanup_guard.record.store()?;",
                "durable GuardianReady state after transition",
            ),
        ],
    )?;
    require_source(
        &sources.launcher,
        "super::token::process_token(target.handle())?",
        "target-token readback equality",
    )?;
    require_source_order(
        &sources.launcher,
        &[
            (
                "primary_token.raw(),\n        guardian.raw(),",
                "authenticated caller token passed to process inventory",
            ),
            (
                "process_identity_for_pid_as_authenticated_caller(",
                "caller-scoped descendant process open",
            ),
        ],
    )?;
    let process_identity_region = semantic_function_region(
        &sources.process,
        "pub(crate) fn process_identity_for_pid_as_authenticated_caller(",
        "pub fn verify_image_path(process: HANDLE, expected: &Path) -> Result<(), String> {",
    )
    .ok_or_else(|| "missing authenticated process-identity helper region".to_owned())?;
    require_source_order(
        &process_identity_region,
        &[
            (
                "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id)",
                "service-context descendant process open",
            ),
            (
                "service_code != Some(windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED)",
                "access-denied-only caller retry",
            ),
            (
                "ThreadImpersonationGuard::install(impersonation.raw())",
                "authenticated caller impersonation",
            ),
            (
                "raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };",
                "caller-context process-open retry",
            ),
            (
                "impersonation_guard.revert()",
                "immediate service-context restoration",
            ),
            (
                "process_identity(process.raw()).map_err",
                "identity readback after reversion",
            ),
            (
                "job.contains(process.raw())",
                "post-open Job-membership recheck",
            ),
        ],
    )?;
    require_source(
        &sources.process,
        "TerminateProcess(GetCurrentProcess(), IMPERSONATION_REVERT_FAILURE_STATUS)",
        "fail-closed impersonation-revert guard",
    )?;
    require_source(
        &sources.launcher,
        "phase: Some(memcordon_core::BoundarySetupPhase::Monitoring)",
        "process-inventory monitoring phase",
    )?;
    require_source_order(
        &sources.token,
        &[
            (
                "CALLER_PRIMARY_LAUNCH_ACCESS | READ_CONTROL_ACCESS | WRITE_DAC_ACCESS",
                "transient caller-token descriptor authority",
            ),
            (
                "converge_token_peer_query(primary.raw(), &launcher_sid)",
                "exact launcher token-query convergence",
            ),
            (
                "if prepared_envelope != primary_envelope",
                "post-convergence caller-envelope equality",
            ),
            (
                "CALLER_PRIMARY_LAUNCH_ACCESS,\n        \"MCSEALED-WINDOWS-CALLER-TOKEN-NARROW\"",
                "final launch-rights-only token handle",
            ),
            ("drop(primary);", "transient descriptor-authority closure"),
        ],
    )?;
    require_source(
        &sources.security,
        "pub fn certification_marker_state_sddl() -> Result<String, String>",
        "marker-specific security policy",
    )?;
    require_source(
        &sources.security,
        "pub(crate) const CERTIFICATION_ADMIN_DIRECTORY_ACCESS: u32 = FILE_ALL_ACCESS & !FILE_DELETE_CHILD;",
        "certification-workspace administrator directory grant without delete-child",
    )?;
    require_source(
        &sources.security,
        "(A;OICI;0x{CERTIFICATION_ADMIN_DIRECTORY_ACCESS:08x};;;BA)",
        "narrowed certification-workspace administrator directory grant",
    )?;
    require_source(
        &sources.security,
        "(A;;GX;;;{launcher})(A;OICIIO;GRGWGX;;;{launcher})(A;;0x00000024;;;AU)(A;OICIIO;GRGWGX;;;AU)(A;;0x00000024;;;RC)(A;OICIIO;GRGWGX;;;RC)(A;;0x00000024;;;WR)(A;OICIIO;GRGWGX;;;WR)S:(ML;OICI;NW;;;LW)",
        "certification-workspace producer creation without inherited reopenable delete authority",
    )?;
    require_source(
        &sources.security,
        "pre_destructive_authority_hardening_certification_marker_state_sddl",
        "exact destructive-authority predecessor policy",
    )?;
    require_source(
        &sources.package,
        "(A;OICI;GRGX;;;BU)(A;;GX;;;RC)(A;OIIO;GRGX;;;RC)(A;OICI;GRGX;;;AC)",
        "installed-image read/execute authority for Restricted Code",
    )?;
    require_source_order(
        &sources.package,
        &[
            (
                "const DELETE_ACCESS: u32 = 0x0001_0000;",
                "retained directory delete authority",
            ),
            (
                "const READ_CONTROL_ACCESS: u32 = 0x0002_0000;",
                "retained directory readback authority",
            ),
            (
                "const WRITE_DAC_ACCESS: u32 = 0x0004_0000;",
                "retained directory DACL authority",
            ),
            (
                "const WRITE_OWNER_ACCESS: u32 = 0x0008_0000;",
                "retained marker mandatory-label authority",
            ),
            (
                "const DACL_TRANSITION_ACCESS: u32 = DELETE_ACCESS | READ_CONTROL_ACCESS | WRITE_DAC_ACCESS;",
                "ordinary retained directory least authority",
            ),
            (
                "security_transition == DirectorySecurityTransition::DaclAndMandatoryLabel",
                "marker-only mandatory-label selection",
            ),
            (
                "FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT",
                "no-follow retained directory handle",
            ),
        ],
    )?;
    require_source(
        &sources.package,
        "byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)",
        "lowercase hexadecimal attempt workspace validation",
    )?;
    require_source(
        &sources.package,
        "metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0\n                        && metadata.is_file()",
        "regular non-reparse stale leaf selection",
    )?;
    require_source(
        &sources.package,
        "Ok(_) => {}",
        "unknown stale leaf preservation",
    )?;
    require_source_order(
        &sources.package,
        &[
            (
                "remove_retired_certification_workspaces(&package.join(\"certification-markers\"), context)?;",
                "allowlisted stale workspace cleanup",
            ),
            (
                "remove_directory_if_present(\n            &package.join(\"certification-markers\"),",
                "exact marker-root removal after stale cleanup",
            ),
            (
                "let Some(digest) = name.strip_prefix(\"attempt-\") else {",
                "attempt workspace prefix validation",
            ),
            (
                "digest.len() != digest_length",
                "attempt workspace digest-length validation",
            ),
            (
                "std::fs::symlink_metadata(&path)",
                "no-follow stale workspace inspection",
            ),
            (
                "FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_dir()",
                "reparse and non-directory preservation",
            ),
            (
                "for child in retired_certification_workspace_paths(&path)",
                "shared complete cleanup-protocol inventory",
            ),
            (
                "std::fs::remove_dir(&path)",
                "unknown-residue fail-closed workspace removal",
            ),
        ],
    )?;
    require_source(
        &sources.package,
        "\"nested-child.json\"",
        "allowlisted nested marker removal",
    )?;
    require_source(
        &sources.package,
        "\"nested-child.json.new\"",
        "allowlisted staged nested receipt removal",
    )?;
    require_source_order(
        &sources.sealed_windows,
        &[
            (
                "seed_retired_certification_workspace(root, &agent)?;",
                "low-integrity stale workspace before upgrade",
            ),
            (
                ".args([\"package\", \"upgrade\", \"--ephemeral-ci\"])",
                "upgrade cleanup exercise",
            ),
            (
                "seed_retired_certification_workspace(root, &agent)?;",
                "low-integrity stale workspace before uninstall",
            ),
            (
                ".args([\"package\", \"uninstall\", \"--ephemeral-ci\"])",
                "uninstall cleanup exercise",
            ),
            (
                "let stale_workspace_cleanup_verified = provider_state_absent(root, &agent)?;",
                "post-uninstall provider absence proof",
            ),
        ],
    )?;
    require_source(
        &sources.sealed_windows,
        "\"stale_low_integrity_workspace_upgrade_and_uninstall_cleanup\"",
        "stale workspace lifecycle evidence name",
    )?;
    require_source(
        &sources.release_evidence,
        "\"stale_low_integrity_workspace_upgrade_and_uninstall_cleanup\"",
        "release consumer stale workspace lifecycle evidence",
    )?;
    require_source_order(
        &sources.package,
        &[
            (
                "let certification_markers = package_path.join(\"certification-markers\");",
                "fixed marker transition path",
            ),
            (
                "transition.retain_with_security_transition(",
                "explicit marker security transition",
            ),
            (
                "DirectorySecurityTransition::DaclAndMandatoryLabel,",
                "marker-only mandatory-label authority",
            ),
        ],
    )?;
    require_source(
        &sources.package,
        ".apply_to_file_object(handle)",
        "file-object security application through retained handles",
    )?;
    require_source(
        &sources.package,
        ".verify_file_object(handle)",
        "file-object security readback through retained handles",
    )?;
    require_source(
        &sources.package,
        ".apply_to_file_object(directory.handle.raw())",
        "file-object bootstrap restoration through retained handles",
    )?;
    require_source(
        &sources.package,
        ".verify_file_object(directory.handle.raw())",
        "file-object bootstrap rollback readback",
    )?;
    require_source(
        &sources.package,
        "if directory.mandatory_label_applied.get()",
        "explicit rollback mandatory-label attestation",
    )?;
    require_source(
        &sources.security,
        "SetSecurityInfo(\n                handle,\n                SE_FILE_OBJECT,",
        "filesystem-correct retained-handle security application",
    )?;
    require_source(
        &sources.security,
        "GetSecurityInfo(\n                handle,\n                SE_FILE_OBJECT,",
        "filesystem-correct retained-handle security readback",
    )?;
    require_source(
        &sources.security,
        "if status == ERROR_SUCCESS",
        "direct file-object security status handling",
    )?;
    require_source_order(
        &sources.package,
        &[
            (
                "let services = configure_services(&installed_binary(), ServiceConfiguration::Reconcile)?;",
                "installed service configuration",
            ),
            (
                "reconcile_runtime_state_security()?;",
                "filesystem policy migration before service exposure",
            ),
            (
                "start_services(&services)",
                "service exposure after filesystem reconciliation",
            ),
        ],
    )?;
    require_source_order(
        &sources.launcher,
        &[
            (
                "process_identity_for_pid_as_authenticated_caller(",
                "live process-object identity observation",
            ),
            (
                "record_job_process_identity(&mut job_process_identities, identity)",
                "full-identity inventory insertion",
            ),
            (
                "if inventory.contains(&identity)",
                "full process-identity deduplication",
            ),
            (
                "if inventory.len() == memcordon_core::WINDOWS_MAX_JOB_PROCESS_IDENTITIES",
                "capacity check after successful identity observation",
            ),
        ],
    )?;
    require_source_order(
        &sources.package,
        &[
            (
                "fn seed_retired_certification_workspace() -> Result<(), String> {",
                "stale workspace lifecycle fixture",
            ),
            (
                "impersonate_low_integrity_current_thread()?;",
                "low-integrity stale workspace creation",
            ),
            (
                "retired_certification_workspace_paths(&workspace)",
                "complete stale cleanup protocol fixture",
            ),
        ],
    )?;
    require_source_order(
        &sources.package,
        &[
            (
                "pre_destructive_authority_hardening_certification_marker_state_sddl()?",
                "recognized destructive-authority predecessor policy",
            ),
            (
                "pre_destructive_authority.verify_path(path)",
                "destructive-authority predecessor attestation",
            ),
            (
                "pre_write_restricted_certification_marker_state_sddl()?",
                "recognized pre-WR marker policy",
            ),
            (
                "pre_write_restricted.verify_path(path)",
                "pre-WR marker policy attestation",
            ),
            (
                "SecurityDescriptor::from_sddl(&package_state_sddl()?)?",
                "recognized older package policy",
            ),
            (
                "package_legacy.verify_path(path)",
                "older package policy attestation",
            ),
            ("expected.apply_to_path(path)?;", "one-way policy migration"),
            ("expected.verify_path(path)", "post-migration readback"),
        ],
    )?;
    require_source(
        &sources.package,
        "fn remove_retired_certification_workspaces(",
        "service-owned stale certification workspace retirement",
    )?;
    require_source(
        &sources.package,
        "SetFileSecurityW does not rewrite inherited ACEs on existing children.",
        "explicit non-retroactive descendant migration boundary",
    )?;
    require_source_order(
        &sources.launcher,
        &[
            (
                "super::record::digest(nonce.as_bytes())",
                "nonce-bound certification workspace",
            ),
            (
                ".join(\"cleanup.marker\")",
                "fixed certification marker leaf",
            ),
            ("if marker != expected", "marker path equality verification"),
        ],
    )?;
    if sources
        .package
        .matches("certification_marker_state_sddl()?")
        .count()
        < 3
    {
        return Err(
            "Windows production contract does not apply and verify marker-specific security"
                .to_owned(),
        );
    }
    require_source(
        &sources.launcher,
        ".is_some_and(|target_envelope| target_envelope != &request.caller_token_envelope)",
        "target-token readback comparison",
    )?;
    require_source(
        &sources.launcher,
        "&& !job.contains(target.handle())?",
        "target Job-membership readback",
    )?;
    require_source(
        &sources.launcher,
        "job.active_processes()? == 0",
        "authoritative active-process accounting query",
    )?;
    require_source(
        &sources.launcher,
        "let empty = job.wait_empty(Instant::now() + Duration::from_secs(30))?;",
        "zero-active-process terminal gate",
    )?;
    require_source_order(
        &sources.launcher,
        &[
            (
                "        if let Err(detail) = wait_for_relays_ready(\n            connection,",
                "relay readiness before target creation",
            ),
            (
                "    let target_result = SuspendedTarget::create(",
                "target creation after relay readiness",
            ),
            (
                "super::process::compare_remote_handle_object(target.handle(), raw, raw)",
                "suspended target excluded-handle object-identity attestation",
            ),
            (
                "    if let Err(detail) = require_guardian_live(guardian.raw()) {",
                "guardian liveness before authorization",
            ),
            (
                "    if let Err(detail) = cleanup_guard.record.authorize() {",
                "durable authorization record",
            ),
            (
                "    if let Err(detail) = require_guardian_live(guardian.raw()) {",
                "guardian liveness immediately before resume",
            ),
            (
                "    if let Err(detail) = target.resume(None) {",
                "single target resume",
            ),
        ],
    )?;
    require_source(
        &sources.process,
        "CompareObjectHandles(snapshot.raw(), expected_local)",
        "kernel-object identity comparison for excluded target handles",
    )?;
    require_source(
        &sources.process,
        "error.raw_os_error() == Some(ERROR_INVALID_HANDLE as i32)",
        "absent remote handle classification",
    )?;
    if sources
        .qualification
        .contains("fn reject_inherited_canary_handles(")
        || sources
            .qualification
            .contains("unrelated frontend handle was inherited by the target")
    {
        return Err("target retained cross-process raw handle-value inference".to_owned());
    }
    if sources
        .launcher
        .contains(".extend(frontend_canaries.iter().map")
    {
        return Err(
            "launcher serialized process-relative canary values into target argv".to_owned(),
        );
    }
    let normal_retirement = sources
        .launcher
        .find(
            "    cleanup_guard\n        .record\n        .transition(super::record::WindowsAttemptStateV1::Terminating)?;",
        )
        .map(|start| &sources.launcher[start..])
        .ok_or_else(|| "Windows production contract omitted normal retirement".to_owned())?;
    let monitor =
        semantic_function_region(&sources.launcher, "fn monitor(", "fn build_outcome(")
            .ok_or_else(|| "Windows production contract omitted terminal observation".to_owned())?;
    if monitor.contains("job.terminate(")
        || monitor.contains("force_attempted")
        || monitor.contains("workload_empty")
    {
        return Err(
            "Windows terminal observation performs or claims destructive retirement".to_owned(),
        );
    }
    require_source_order(
        normal_retirement,
        &[
            (
                ".transition(super::record::WindowsAttemptStateV1::Terminating)?;",
                "durable Terminating transition",
            ),
            (
                "cleanup_guard.record.store()?;",
                "durable Terminating record store",
            ),
            (
                ".is_none_or(|receipt| cleanup_process_creation_expected(receipt.phase))",
                "typed cleanup-certification applicability gate",
            ),
            (
                "match certify_cleanup_process_creation(",
                "post-transition cleanup process-creation certification",
            ),
            (
                "&[WindowsSealedFault::TerminateJob]",
                "authoritative termination fault injection",
            ),
            (
                "WindowsSealedMutant::SuccessBeforeActiveZero",
                "pre-termination active-process mutant hook",
            ),
            (
                "job.terminate(reason.termination_status())?;",
                "single checked reason-specific Job termination",
            ),
            (
                "target.wait(Duration::from_secs(30))?",
                "direct-target reap after Job termination",
            ),
            (
                "let empty = job.wait_empty(Instant::now() + Duration::from_secs(30))?;",
                "authoritative zero-active-process proof",
            ),
            (
                "target_cleanup_barrier.finish();",
                "desktop lease release barrier disarm after zero proof",
            ),
            (
                "observation.final_active_processes_zero = true;",
                "cleanup process-creation final-zero evidence",
            ),
            (
                "let outcome = build_outcome(",
                "terminal outcome construction after completed cleanup",
            ),
        ],
    )?;
    require_source_order(
        normal_retirement,
        &[
            (
                "let job_terminated = JobTerminated;",
                "typed Job termination fact",
            ),
            (
                "let direct_target_reaped = DirectTargetReaped;",
                "typed direct-target reap fact",
            ),
            (
                "let active_processes_zero = ActiveProcessesZero;",
                "typed active-zero fact",
            ),
            (
                "let relays_retired = RelaysRetired;",
                "typed relay-retirement fact",
            ),
            (
                "let guardian_reaped = GuardianReaped;",
                "typed guardian-reap fact",
            ),
            (
                "let final_handles_closed = FinalHandlesClosed;",
                "typed final-handle closure fact",
            ),
            (
                "let record_retired = RecordRetired;",
                "typed record-retirement fact",
            ),
            (
                "let completed = CompletedRetirement {",
                "non-default complete retirement value",
            ),
            (
                "let receipt = build_terminal_receipt(",
                "terminal receipt from complete retirement",
            ),
        ],
    )?;
    require_source_order(
        &sources.qualification,
        &[
            (
                "pub(super) const TARGET_RESULT_SCHEMA_VERSION: u32 = 1;",
                "versioned target result",
            ),
            (
                "pub(super) struct TargetResultReceiptV1 {",
                "typed target-result receipt",
            ),
            ("attempt_binding: String,", "target-result attempt binding"),
            ("phase: TargetResultPhaseV1,", "target-result failure phase"),
            ("success: bool,", "target-result success fact"),
            ("detail: String,", "target-result bounded detail"),
            (
                "fn read_bound_target_result(",
                "target-result bound consumer",
            ),
            (
                "fn validate_qualification_terminal<'a>(",
                "field-diagnostic terminal validator",
            ),
            ("fn publish_target_result(", "target-result producer"),
            (
                "QualificationPublicationProducerV1::TargetResult,",
                "typed target-result publication producer",
            ),
            (
                ".map_err(|error| error.to_string())",
                "typed target-result publication diagnostic propagation",
            ),
        ],
    )?;
    let qualification_publisher = semantic_function_region(
        &sources.qualification,
        "fn publish_qualification_receipt<T: serde::Serialize + ?Sized>(",
        "pub(crate) enum QualificationPublicationProducerForTest {",
    )
    .ok_or_else(|| "qualification receipt publisher region is missing".to_owned())?;
    require_source(
        &sources.qualification,
        "api: error.stage().api(),\n            path_role,\n            path: path.to_owned(),\n            requested_access,\n            io_error_kind: Some(error.kind()),\n            native_code: error.raw_os_error(),",
        "typed qualification native publication substage and error evidence",
    )?;
    require_source_order(
        &qualification_publisher,
        &[
            (
                "let staged = staged_receipt_path(destination);",
                "bound qualification staging path",
            ),
            (
                "serde_json::to_vec_pretty(receipt)",
                "qualification receipt serialization",
            ),
            (
                "CreateOnceStagingFile::create(&staged)",
                "qualification CREATE_NEW retained staging capability",
            ),
            (
                "Some(QualificationPublicationFailure::CREATE_ONCE_STAGING_ACCESS)",
                "qualification staging DELETE access evidence",
            ),
            (
                "write_all(file.file_mut(), &bytes)",
                "qualification write through retained staging handle",
            ),
            (
                "file.sync_all()",
                "qualification sync through retained staging handle",
            ),
            (
                "publish_create_once_atomically(file, destination)",
                "qualification handle-based no-replace rename",
            ),
            (
                "QualificationPublicationStageV1::ReceiptPublishRename",
                "typed qualification rename stage diagnostic",
            ),
        ],
    )?;
    for forbidden in [
        "std::fs::OpenOptions",
        "drop(file)",
        "replace_atomically(",
        "MoveFileExW(",
    ] {
        if qualification_publisher.contains(forbidden) {
            return Err(format!(
                "qualification publisher retained forbidden path-reopen primitive {forbidden}"
            ));
        }
    }
    for (start, end, role, label) in [
        (
            "fn publish_target_result(",
            "fn split_stream_identity(",
            "QualificationPublicationProducerV1::TargetResult,",
            "target-result",
        ),
        (
            "pub fn certification_nested_child(",
            "fn nested_child_staged_receipt(receipt: &std::path::Path) -> std::path::PathBuf {",
            "QualificationPublicationProducerV1::NestedChild,",
            "nested-child",
        ),
    ] {
        let publisher = semantic_function_region(&sources.qualification, start, end)
            .ok_or_else(|| format!("{label} publisher region is missing"))?;
        require_source(
            &publisher,
            "publish_qualification_receipt(",
            &format!("{label} shared retained-handle publisher"),
        )?;
        require_source(&publisher, role, &format!("{label} typed publication role"))?;
        for forbidden in ["std::fs::OpenOptions", "drop(file)", "replace_atomically("] {
            if publisher.contains(forbidden) {
                return Err(format!(
                    "{label} publisher retained forbidden path-reopen primitive {forbidden}"
                ));
            }
        }
    }
    for (fragment, invariant) in [
        (
            "enum QualificationPublicationStageV1 {",
            "typed qualification publication stages",
        ),
        (
            "Self::ReceiptPublishRename => \"SetFileInformationByHandle(FileRenameInfo)\"",
            "exact qualification rename API diagnostic",
        ),
        (
            "io_error_kind: Some(error.kind()),\n            native_code: error.raw_os_error(),",
            "qualification native failure evidence",
        ),
        (
            "requested_access: Option<u32>,",
            "qualification requested-access evidence",
        ),
    ] {
        require_source(&sources.qualification, fragment, invariant)?;
    }
    require_source(
        &sources.token,
        "restricted_primary_for_source(\n        source,\n        DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED,\n        \"S-1-5-33\",\n    )",
        "least-authority write-restricted alternate primary",
    )?;
    require_source(
        &sources.security,
        "pub fn nested_canary_job_sddl() -> Result<String, String>",
        "role-specific nested Job policy",
    )?;
    require_source(
        &sources.security,
        "Ok(format!(\"O:{creator}D:P(A;;GA;;;{creator})(A;;GA;;;WR)\"))",
        "creator and Write Restricted Code nested Job policy",
    )?;
    require_source(
        &sources.security,
        "\"O:{creator}D:P(A;;GA;;;SY)(A;;GA;;;{creator})(A;;GA;;;WR)\"",
        "SYSTEM, creator, and Write Restricted Code nested process policy",
    )?;
    require_source(
        &sources.security,
        "pub fn nested_canary_thread_sddl() -> Result<String, String> {\n    nested_canary_process_sddl()\n}",
        "nested thread policy matching the process role",
    )?;
    require_source(
        &sources.job,
        "JobObjectSecurity::NestedCanaryCreator => super::security::nested_canary_job_sddl()?",
        "nested Job policy applied only to the Job",
    )?;
    require_source(
        &sources.process,
        "super::security::nested_canary_process_sddl()?",
        "nested process policy applied to the process",
    )?;
    require_source(
        &sources.process,
        "super::security::nested_canary_thread_sddl()?",
        "nested thread policy applied to the primary thread",
    )?;
    for (needle, label) in [
        (
            "let executable = super::package::installed_target_desktop_bootstrap();",
            "dedicated namespace holder and target probe image",
        ),
        (
            "let mut empty_desktop = [0_u16];",
            "explicit empty unrestricted holder USER binding",
        ),
        (
            "startup.StartupInfo.lpDesktop = empty_desktop.as_mut_ptr();",
            "broker-created holder uses Windows-selected target-session desktop",
        ),
        (
            "startup.StartupInfo.lpDesktop = startup_desktop.as_mut_ptr();",
            "restricted probe starts on pre-created private desktop",
        ),
        (
            "launch_target_desktop_probe(",
            "runtime exact-target desktop startup proof",
        ),
        (
            "super::token::with_session_broker_launch_privileges(|| {",
            "holder creation under scoped broker launch privileges",
        ),
        (
            "CreateProcessAsUserW(\n                holder_token.launch_token.raw(),",
            "fixed holder creation from broker-owned narrowed token",
        ),
        (
            "let jobs = [local_job.raw()];",
            "launcher-owned Job-only holder manifest",
        ),
        (
            "PROC_THREAD_ATTRIBUTE_JOB_LIST as usize",
            "atomic bootstrap Job assignment",
        ),
        ("CreateDesktopW(", "target-session private desktop creation"),
        (
            "SecurityDescriptor::user_object_security_equality_fingerprint(",
            "station-class-neutral shared USER container non-mutation proof",
        ),
        (
            "frame.target_envelope != target_envelope",
            "bootstrap target-token envelope binding",
        ),
        (
            "verify_image_path(bootstrap_process.raw(), &executable)?;",
            "bootstrap installed-image binding",
        ),
        (
            "connection_lease: Option<OwnedHandle>",
            "bootstrap-held named-pipe lifetime channel",
        ),
        (
            "super::pipe::prepare_target_desktop_bootstrap_pipe(&pipe_name, &pipe_security)?;",
            "launcher-owned target bootstrap pipe",
        ),
        (
            "enum TargetDesktopBootstrapMessageV1",
            "typed bootstrap result protocol",
        ),
        (
            "const TARGET_DESKTOP_BOOTSTRAP_DETAIL_MAX_BYTES: usize = 1_024;",
            "bounded bootstrap failure detail",
        ),
        (
            "#[serde(deny_unknown_fields, tag = \"kind\", rename_all = \"kebab-case\")]",
            "deny-unknown-fields bootstrap outcome",
        ),
        (
            "    Started {\n        binding: TargetDesktopBootstrapBindingV3,",
            "bootstrap endpoint-admission frame",
        ),
        (
            "    Failed {\n        binding: TargetDesktopBootstrapBindingV3,",
            "bounded bootstrap failure frame",
        ),
        (
            "phase: TargetDesktopBootstrapPhaseV1,",
            "typed bootstrap failure phase",
        ),
        ("native_code: Option<i32>,", "bootstrap native failure code"),
        (
            "native_code: failure.native_code,",
            "bootstrap native-code publication",
        ),
        (
            "TargetCreateError::loader_context_with_os(error.detail, error.os_code)",
            "bootstrap native code propagated to target-create evidence",
        ),
        (
            "super::pipe::TargetDesktopBootstrapPipeOperation::StartedRead",
            "bounded overlapped bootstrap observation",
        ),
        (
            "launcher_process_query_handle: u64,\n        launcher_token_query_handle: u64,",
            "separate bootstrap launcher process/token capabilities",
        ),
        (
            "target_token_capability_handle: Option<u64>,",
            "role-minimal target-token holder capability",
        ),
        (
            "duplicate_remote_token_query(launcher_token.raw(), bootstrap_process.raw())?",
            "least-privilege launcher token capability transfer",
        ),
        (
            "const TARGET_TOKEN_CAPABILITY_ACCESS: u32 = TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE;",
            "least-privilege target token capability transfer",
        ),
        (
            "DuplicateTokenEx(\n            token,\n            TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_IMPERSONATE,",
            "target capability duplicates a separately impersonable token",
        ),
        (
            "verify_not_inheritable(launcher_token.raw())?;",
            "bootstrap launcher token capability noninheritability proof",
        ),
        (
            "verify_not_inheritable(target_token.raw())?;",
            "bootstrap target token capability noninheritability proof",
        ),
        (
            "launcher_process_handle == launcher_token_handle",
            "bootstrap launcher capability role separation",
        ),
        (
            "target_token_handle == launcher_process_handle\n                || target_token_handle == launcher_token_handle",
            "bootstrap three-way capability role separation",
        ),
        (
            "launcher_envelope: WindowsCallerTokenEnvelopeV1,",
            "launcher token envelope binding",
        ),
        (
            "target_desktop_bootstrap_pipe_is_quiet(connection.raw())?",
            "post-Ready channel silence proof",
        ),
        (
            "const TARGET_STATION_ATTEST_ACCESS: u32 = READ_CONTROL_ACCESS | WINSTA_READATTRIBUTES_ACCESS;",
            "exact station attestation access mask",
        ),
        (
            "const TARGET_DESKTOP_ATTEST_ACCESS: u32 = READ_CONTROL_ACCESS | DESKTOP_READOBJECTS_ACCESS;",
            "exact desktop attestation access mask",
        ),
        (
            "OwnedUserObjectDuplicate::duplicate(window_station, TARGET_STATION_ATTEST_ACCESS)",
            "exact assigned station duplication",
        ),
        (
            "OwnedUserObjectDuplicate::duplicate(desktop, TARGET_DESKTOP_ATTEST_ACCESS)",
            "exact assigned desktop duplication",
        ),
        (
            "desired_access,\n                0,\n                0,",
            "reduced non-inheritable USER-handle duplication",
        ),
        (
            "source,\n                ptr::null_mut(),\n                ptr::null_mut(),\n                0,\n                0,\n                DUPLICATE_CLOSE_SOURCE,",
            "generic duplicated USER-handle closure",
        ),
        (
            "std::mem::replace(&mut self.0, ptr::null_mut())",
            "checked USER-handle close ownership transfer",
        ),
        (
            "station_duplicate\n        .close()",
            "checked station duplicate close evidence",
        ),
        (
            "desktop_duplicate\n        .close()",
            "checked desktop duplicate close evidence",
        ),
        (
            "unsafe impl Send for OwnedDesktop {}",
            "process-scoped private-desktop handle ownership transfer",
        ),
        (
            "read_handles: TargetUserBindingReadHandles,",
            "nested target USER readback handles",
        ),
        (
            "self.read_handles.window_station.raw()",
            "nested station fingerprint through read-only handle",
        ),
        (
            "startup.StartupInfo.lpDesktop = desktop_lease.as_mut()",
            "explicit target desktop binding",
        ),
        (
            "_desktop_lease: desktop_lease",
            "target-bound USER handle lifetime",
        ),
        (
            "security.private_window_station_access_check(token)?",
            "pre-resume restricted-token private WindowStation AccessCheck",
        ),
        (
            "security.private_desktop_access_check(token)?",
            "pre-resume restricted-token private Desktop AccessCheck",
        ),
        (
            "GetUserObjectInformationW(\n            handle,\n            UOI_FLAGS,",
            "USER-object inheritance flag readback",
        ),
    ] {
        require_source(&sources.process, needle, label)?;
    }
    if sources.process.matches("binding.verify_digest()").count() != 2 {
        return Err(
            "binding digest is not recomputed by both launcher-authenticated peers".to_owned(),
        );
    }
    require_source_order(
        &sources.process,
        &[
            (
                "SetProcessWindowStation(private_window_station.raw())",
                "bootstrap primary-process private station assignment",
            ),
            (
                "let mut desktop = create_target_desktop_on_creator_thread(",
                "quarantined private desktop creation",
            ),
            (
                "verify_private_desktop_containment(private_window_station.raw(), &desktop_wide)",
                "direct private desktop containment enumeration",
            ),
        ],
    )?;
    for (needle, label) in [
        (
            "PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED",
            "first-instance overlapped bootstrap server",
        ),
        (
            "PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,\n            1,\n            64 * 1024,",
            "local-only single-machine bootstrap pipe",
        ),
        (
            "CancelIoEx(handle, overlapped);",
            "cancelled bounded pipe operation",
        ),
        (
            "wait_for_target_desktop_bootstrap_release(",
            "bounded peer-close-only lifetime protocol",
        ),
    ] {
        require_source(&sources.pipe, needle, label)?;
    }
    for (needle, label) in [
        (
            "pub fn target_desktop_bootstrap_pipe_sddl(",
            "role-specific bootstrap pipe policy",
        ),
        ("\"O:SYG:SYD:P\"", "SYSTEM-owned protected bootstrap pipe"),
        ("(A;;0x0012019b;;;{trustee})", "exact bootstrap client mask"),
        (
            "pub const TARGET_PRIVATE_WINDOW_STATION_ACCESS: u32 = NONINTERACTIVE_WINDOW_STATION_ALL_ACCESS;",
            "full nonce-private window-station connection mask",
        ),
        (
            "pub const TARGET_PRIVATE_DESKTOP_ACCESS: u32 = DESKTOP_ALL_ACCESS;",
            "full nonce-private desktop connection mask",
        ),
        (
            "sddl.push_str(&format!(\"(A;;0x{access:08x};;;{trustee})\"));",
            "single-source object-specific USER ACE construction",
        ),
        ("\"S-1-5-18\".to_owned(),", "holder ordinary SYSTEM trustee"),
        (
            "self.holder_restricting_sid.clone(),",
            "holder restricting service-SID trustee",
        ),
        (
            "self.target_logon_sid.clone(),",
            "logon-exact target ordinary trustee",
        ),
        (
            "trustees.extend(restricting_sids.iter().cloned());",
            "exact target restricting trustees",
        ),
        (
            "TargetRestrictionSemantics::Unrestricted => {}",
            "typed unrestricted target policy",
        ),
        (
            "token_is_restricted != !restricting_sids.is_empty()",
            "IsTokenRestricted and restricting-SID inventory agreement",
        ),
        (
            "write_restricted != has_write_restricted_sid",
            "write-restricted oracle and SID inventory agreement",
        ),
        (
            "snapshot_before.behavior.restricting_sids != restricting.evidence",
            "snapshot-bound restricting-SID evidence",
        ),
        (
            "write_restricted_behavior_attested(token)",
            "behavioral write-restricted classification",
        ),
        (
            "S:P(ML;;NW;;;{})",
            "target-matched protected mandatory integrity policy",
        ),
    ] {
        require_source(&sources.security, needle, label)?;
    }
    let bootstrap_create = semantic_function_region(
        &sources.process,
        "    fn create(",
        "    fn attest_live(&self) -> Result<(), String> {",
    )
    .ok_or_else(|| "target desktop bootstrap create region is missing".to_owned())?;
    for forbidden in [
        "CreatePipe(",
        "PROC_THREAD_ATTRIBUTE_HANDLE_LIST",
        "result_writer",
        "lifetime_reader",
    ] {
        if bootstrap_create.contains(forbidden) {
            return Err(format!(
                "target desktop bootstrap retained forbidden inherited transport: {forbidden}"
            ));
        }
    }
    require_source_order(
        &bootstrap_create,
        &[
            (
                "let target_envelope = super::token::envelope(token)?;",
                "authenticated target session capture",
            ),
            (
                "let bootstrap_job = Job::create_session_holder()?;",
                "launcher-owned one-process holder Job",
            ),
            (
                "let bootstrap_image_sha256 = super::package::validate_installed_target_desktop_bootstrap()?;",
                "fixed helper validation before broker request",
            ),
            (
                "let mut brokered = super::session_broker::request_holder(",
                "authenticated one-shot broker request",
            ),
            (
                "let observed_holder_snapshot = brokered.query;",
                "independent suspended holder process-token readback",
            ),
            (
                "super::token::require_assigned_process_authority(\n            \"session-broker-holder-to-process\",",
                "typed holder assignment authority comparison",
            ),
        ],
    )?;
    require_source(
        &bootstrap_create,
        "launch_target_desktop_probe(\n            token,",
        "exact-target probe completes before lease publication",
    )?;
    require_source(
        &bootstrap_create,
        "target_user_object_policy_role: policy_role,",
        "target USER-object policy role is sealed into the holder binding",
    )?;
    let guardian_desktop_policy = semantic_function_region(
        &sources.process,
        "pub(crate) fn validate_guardian_desktop_binding(",
        "struct GuardianStandardHandles {",
    )
    .ok_or_else(|| "guardian desktop policy region is missing".to_owned())?;
    require_source(
        &guardian_desktop_policy,
        "window_station.eq_ignore_ascii_case(\"WinSta0\") || receives_input",
        "guardian-only interactive desktop rejection",
    )?;
    let target_bootstrap = semantic_function_region(
        &sources.process,
        "fn run_target_desktop_bootstrap(",
        "impl CapturedTargetDesktop {",
    )
    .ok_or_else(|| "target desktop bootstrap function region is missing".to_owned())?;
    let private_station_create = target_bootstrap
        .find("CreateWindowStationW(")
        .ok_or_else(|| "target bootstrap private station creation is missing".to_owned())?;
    let pre_private_station = &target_bootstrap[..private_station_create];
    for forbidden in [
        "GetProcessWindowStation(",
        "GetThreadDesktop(",
        "GetUserObjectInformation",
        "GetUserObjectSecurity",
        "SetUserObjectSecurity",
        "SetUserObjectInformation",
        "user_object_security_equality_fingerprint",
        "validate_target_desktop_source_binding(",
        "desktop_receives_input(",
        "WinSta0",
        "source_station",
        "source_desktop",
        "OpenWindowStationW(",
        "OpenDesktopW(",
    ] {
        if pre_private_station.contains(forbidden) {
            return Err(format!(
                "target bootstrap observes an ambient USER binding before nonce-private station creation: {forbidden}"
            ));
        }
    }
    require_source_order(
        &target_bootstrap,
        &[
            (
                "let holder_token = super::token::current_process_token_for_access_check()",
                "purpose-specific launcher-holder token capture",
            ),
            (
                "let target_user_object_policy = super::security::target_user_object_policy(",
                "target USER-object policy capture",
            ),
            (
                "let window_station_security =\n        SecurityDescriptor::from_sddl(&window_station_sddl)",
                "window-station policy construction",
            ),
            (
                ".absolute_for_user_object_creation()",
                "absolute window-station policy preparation",
            ),
            (
                "super::user_api::load()",
                "authenticated trusted USER module resolution",
            ),
            (
                "CreateWindowStationW(",
                "nonce private window-station creation in target-token bootstrap",
            ),
            (
                "SetProcessWindowStation(private_window_station.raw())",
                "dedicated bootstrap private station binding",
            ),
            (
                "private_window_station.mark_assigned();",
                "assigned station lifetime retained until bootstrap exit",
            ),
            (
                "let current_private_window_station = unsafe { GetProcessWindowStation() };",
                "private station binding readback after explicit assignment",
            ),
            (
                "SecurityObjectKind::WindowStation,",
                "private window-station attestation",
            ),
            (
                "let mut desktop = create_target_desktop_on_creator_thread(",
                "quarantined creator/open-handle retention",
            ),
            (
                "attest_target_user_object(\n        desktop.raw(),",
                "private desktop attestation after duplicable token capture",
            ),
            (
                "verify_private_desktop_containment(private_window_station.raw(), &desktop_wide)",
                "enumerated private station containment proof",
            ),
            (
                "&TargetDesktopBootstrapMessageV1::Ready {",
                "authenticated private desktop readiness publication",
            ),
            (
                "serve_holder_target_association_preflight(",
                "target association preflight served after readiness publication",
            ),
            (
                "wait_for_target_desktop_bootstrap_release(",
                "complete private USER-pair lifetime hold",
            ),
            ("drop(desktop);", "desktop retained until lease release"),
            (
                "drop(private_window_station);",
                "assigned station retained until lease release",
            ),
        ],
    )?;
    require_source(
        &target_bootstrap,
        "source_objects_unmodified,\n        private_station_assigned,\n        private_desktop_assigned,\n        desktop_containment_verified: true,\n        window_station_policy_verified: true,",
        "positive private station policy evidence",
    )?;
    for evidence in [
        "source_objects_unmodified,",
        "private_station_assigned,",
        "desktop_containment_verified: true,",
    ] {
        require_source(
            &target_bootstrap,
            evidence,
            "private USER namespace ownership evidence",
        )?;
    }
    let desktop_creator = semantic_function_region(
        &sources.process,
        "fn create_target_desktop_on_creator_thread(",
        "struct TargetDesktopLease {",
    )
    .ok_or_else(|| "private desktop creator helper region is missing".to_owned())?;
    require_source_order(
        &desktop_creator,
        &[
            ("std::thread::Builder", "isolated private desktop creator"),
            ("CreateDesktopW(", "private desktop creation"),
            (
                "Ok(OwnedDesktop::new(desktop))",
                "process-scoped created desktop owner",
            ),
            (".join()", "creator termination before handle transfer"),
        ],
    )?;
    for forbidden in ["GetThreadDesktop(", "SetThreadDesktop("] {
        if desktop_creator.contains(forbidden) {
            return Err(format!(
                "private desktop creator inferred or changed thread binding: {forbidden}"
            ));
        }
    }
    let (_, post_create_bootstrap) = target_bootstrap
        .split_once("let mut desktop = create_target_desktop_on_creator_thread(")
        .ok_or_else(|| "private desktop creator call is missing".to_owned())?;
    require_source_order(
        post_create_bootstrap,
        &[
            ("SetThreadDesktop(desktop.raw())", "private desktop binding"),
            (
                "GetThreadDesktop(GetCurrentThreadId())",
                "private desktop binding readback",
            ),
            (
                "private_desktop_assigned,",
                "private desktop binding evidence",
            ),
        ],
    )?;
    if target_bootstrap.contains("desktop.close()") {
        return Err("assigned private desktop was closed before helper exit".to_owned());
    }
    let station_drop = semantic_function_region(
        &sources.process,
        "impl Drop for BootstrapWindowStation {",
        "impl Drop for OwnedDesktop {",
    )
    .ok_or_else(|| "bootstrap window-station drop region is missing".to_owned())?;
    require_source(
        &station_drop,
        "if !self.assigned && !self.closed {",
        "assigned window-station handle is not falsely closed",
    )?;
    let station_owner = semantic_function_region(
        &sources.process,
        "impl BootstrapWindowStation {",
        "impl Drop for BootstrapWindowStation {",
    )
    .ok_or_else(|| "bootstrap window-station owner region is missing".to_owned())?;
    require_source_order(
        &station_owner,
        &[
            (
                "SetProcessWindowStation(source)",
                "source process-station restoration",
            ),
            (
                "user_object_name(restored)",
                "restored process-station name verification",
            ),
            (
                "CloseWindowStation(self.handle)",
                "private station close after restoration",
            ),
        ],
    )?;
    let desktop_drop = semantic_function_region(
        &sources.process,
        "impl Drop for OwnedDesktop {",
        "struct DesktopEnumerationState {",
    )
    .ok_or_else(|| "owned desktop drop region is missing".to_owned())?;
    require_source(
        &desktop_drop,
        "if !self.assigned && !self.handle.is_null()",
        "desktop owner closes only handles that were never thread-assigned",
    )?;
    require_source(
        &desktop_drop,
        "process exit tears down the complete",
        "assigned desktop lifetime is explicitly process-owned",
    )?;
    require_source(
        &target_bootstrap,
        "desktop.mark_assigned();",
        "assigned private desktop is retained through process exit",
    )?;
    require_source(
        &target_bootstrap,
        "SecurityObjectKind::WindowStation,\n        holder_token.raw(),",
        "holder restricted-token station AccessCheck",
    )?;
    require_source(
        &target_bootstrap,
        "attest_target_user_object(\n        desktop.raw(),\n        &desktop_name,\n        &desktop_security,\n        super::security::SecurityObjectKind::Desktop,\n        target_token,",
        "exact target restricted-token desktop AccessCheck",
    )?;
    require_source(
        &sources.process,
        "let launcher_executable = super::package::installed_binary();",
        "bootstrap authenticates the distinct launcher image rather than its own helper image",
    )?;
    require_source(
        &sources.process,
        "private_desktop_assigned: bool,",
        "authenticated private desktop assignment evidence",
    )?;
    require_source(
        &sources.process,
        "const TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION: u32 = 18;",
        "desktop lifetime protocol schema",
    )?;
    for (fragment, label) in [
        (
            "const TARGET_ASSOCIATION_PREFLIGHT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);",
            "association preflight resettable idle deadline",
        ),
        (
            "const TARGET_ASSOCIATION_PREFLIGHT_OVERALL_TIMEOUT: Duration = Duration::from_secs(180);",
            "association preflight fixed overall deadline",
        ),
        (
            "const TARGET_ASSOCIATION_PREFLIGHT_MAX_PROGRESS_FRAMES: u32 = 4_096;",
            "association preflight progress-frame bound",
        ),
        (
            "sequence > TARGET_ASSOCIATION_PREFLIGHT_MAX_PROGRESS_FRAMES",
            "association preflight progress bound enforcement",
        ),
        (
            "(Instant::now() + TARGET_ASSOCIATION_PREFLIGHT_IDLE_TIMEOUT).min(overall_deadline)",
            "idle deadline capped by fixed overall deadline",
        ),
        (
            "struct AssociationPreflightProgressCursor {",
            "stateful association preflight progress cursor",
        ),
        (
            "cursor.sequence.checked_add(1) != Some(sequence)",
            "checked exact progress sequence successor",
        ),
        (
            "last_stage.successor() != Some(stage)",
            "explicit exact stage successor",
        ),
        (
            "cursor.total == Some(cursor.completed)",
            "closed stage rejects further progress",
        ),
        (
            "cursor.total.is_some() && total.is_none()",
            "known progress total cannot disappear",
        ),
        (
            "cursor.total.is_some() && cursor.total != total",
            "known progress total is immutable",
        ),
        (
            "cursor.total.is_none() && total == Some(completed)",
            "canonical unknown-total stage closure",
        ),
        (
            "cursor.total != Some(cursor.completed)",
            "stage transition requires exact prior completion",
        ),
        (
            "} else if completed != 0 {\n            Some(\"new stage has a nonzero completed count\")",
            "new stage counter reset enforcement",
        ),
    ] {
        require_source(&sources.process, fragment, label)?;
    }
    let target_association_evidence = semantic_function_region(
        &sources.process,
        "struct TargetUserObjectOpenPreflightV1 {",
        "enum TargetDesktopBootstrapMessageV1 {",
    )
    .ok_or_else(|| "target association preflight evidence region is missing".to_owned())?;
    require_source(
        &sources.process,
        "#[derive(Debug, Deserialize, Serialize)]\n#[serde(deny_unknown_fields)]\nstruct TargetUserObjectOpenPreflightV1 {",
        "deny-unknown-fields target association evidence",
    )?;
    require_source_order(
        &target_association_evidence,
        &[
            (
                "window_station_granted_access: u32,",
                "station granted-access evidence",
            ),
            (
                "desktop_granted_access: u32,",
                "desktop granted-access evidence",
            ),
            ("desktop_heap_kb: u32,", "read-only desktop heap evidence"),
            (
                "window_station_policy_sha256: String,",
                "station canonical policy evidence",
            ),
            (
                "desktop_policy_sha256: String,",
                "desktop canonical policy evidence",
            ),
            (
                "window_station_live_equality_sha256: String,",
                "station live equality evidence",
            ),
            (
                "desktop_live_equality_sha256: String,",
                "desktop live equality evidence",
            ),
            (
                "window_station_policy_verified_after_open: bool,",
                "station post-open semantic policy evidence",
            ),
            (
                "desktop_policy_verified_after_open: bool,",
                "desktop post-open semantic policy evidence",
            ),
            (
                "creator_live_baselines_unchanged: bool,",
                "creator-handle live baseline evidence",
            ),
            (
                "target_snapshot_before: super::token::TokenAttestationSnapshot,",
                "preflight target identity before impersonation",
            ),
            (
                "target_snapshot_after: super::token::TokenAttestationSnapshot,",
                "preflight target identity after impersonation",
            ),
            (
                "thread_token_absent: bool,",
                "post-preflight thread-token absence evidence",
            ),
            (
                "native_loader_access: super::loader_access::NativeLoaderAccessEvidenceV2,",
                "exact-token native loader access evidence",
            ),
        ],
    )?;
    let target_bootstrap_messages = semantic_function_region(
        &sources.process,
        "enum TargetDesktopBootstrapMessageV1 {",
        "impl TargetDesktopLease {",
    )
    .ok_or_else(|| "target desktop bootstrap message region is missing".to_owned())?;
    require_source_order(
        &target_bootstrap_messages,
        &[
            (
                "AssociationPreflight {\n        binding: TargetDesktopBootstrapBindingV3,",
                "binding-bound association preflight request",
            ),
            (
                "AssociationPreflightProgress {\n        binding: TargetDesktopBootstrapBindingV3,\n        sequence: u32,\n        stage: TargetAssociationPreflightStageV1,\n        completed: u32,\n        total: Option<u32>,",
                "binding-bound typed association progress",
            ),
            (
                "AssociationPreflightReady {\n        binding: TargetDesktopBootstrapBindingV3,\n        evidence: Box<TargetUserObjectOpenPreflightV1>,",
                "binding-bound typed association preflight response",
            ),
        ],
    )?;
    let target_bootstrap_phases = semantic_function_region(
        &sources.process,
        "enum TargetDesktopBootstrapPhaseV1 {",
        "pub(super) enum TargetDesktopBootstrapRoleV1 {",
    )
    .ok_or_else(|| "target desktop bootstrap phase region is missing".to_owned())?;
    require_source(
        &target_bootstrap_phases,
        "TargetAssociationPreflight,",
        "typed target association preflight failure phase",
    )?;
    let bootstrap_pipe_operations = semantic_function_region(
        &sources.pipe,
        "pub enum TargetDesktopBootstrapPipeOperation {",
        "impl TargetDesktopBootstrapPipeOperation {",
    )
    .ok_or_else(|| "target desktop bootstrap pipe operation region is missing".to_owned())?;
    require_source_order(
        &bootstrap_pipe_operations,
        &[
            (
                "AssociationPreflightRead,",
                "association preflight request read operation",
            ),
            (
                "AssociationPreflightWrite,",
                "association preflight request write operation",
            ),
            (
                "AssociationPreflightProgressWrite,",
                "association preflight progress write operation",
            ),
            (
                "AssociationPreflightReadyRead,",
                "association preflight response read operation",
            ),
            (
                "AssociationPreflightReadyWrite,",
                "association preflight response write operation",
            ),
        ],
    )?;
    let bootstrap_pipe_operation_names = semantic_function_region(
        &sources.pipe,
        "impl TargetDesktopBootstrapPipeOperation {",
        "pub struct TargetDesktopBootstrapPipeError {",
    )
    .ok_or_else(|| "target desktop bootstrap pipe diagnostic region is missing".to_owned())?;
    require_source_order(
        &bootstrap_pipe_operation_names,
        &[
            (
                "Self::AssociationPreflightRead => \"association-preflight-read\"",
                "association preflight request read diagnostic",
            ),
            (
                "Self::AssociationPreflightWrite => \"association-preflight-write\"",
                "association preflight request write diagnostic",
            ),
            (
                "Self::AssociationPreflightProgressWrite => \"association-preflight-progress-write\"",
                "association preflight progress write diagnostic",
            ),
            (
                "Self::AssociationPreflightReadyRead => \"association-preflight-ready-read\"",
                "association preflight response read diagnostic",
            ),
            (
                "Self::AssociationPreflightReadyWrite => \"association-preflight-ready-write\"",
                "association preflight response write diagnostic",
            ),
        ],
    )?;
    for (needle, label) in [
        (
            "struct TargetDesktopBootstrapBindingV3 {",
            "typed desktop bootstrap binding",
        ),
        (
            "binding_sha256: String,",
            "canonical binding transcript digest",
        ),
        (
            "b\"memcordon-target-desktop-binding-v8\\0\"",
            "domain-separated binding digest",
        ),
        (
            "target_user_object_policy_role: super::security::TargetUserObjectPolicyRoleV1,",
            "sealed target USER-object policy role",
        ),
        (
            "launcher_process_snapshot: super::token::TokenAttestationSnapshot,",
            "exact launcher process-token evidence",
        ),
        (
            "holder_launch_snapshot: super::token::TokenAttestationSnapshot,",
            "independent holder launch-token evidence",
        ),
        (
            "holder_process_snapshot: super::token::TokenQueryAttestationSnapshot,",
            "independent holder process-token evidence",
        ),
        (
            "bootstrap_process_snapshot: super::token::TokenQueryAttestationSnapshot,",
            "role-specific bootstrap process-token evidence",
        ),
        (
            "target_request_snapshot: super::token::TokenAttestationSnapshot,",
            "independent target request-token evidence",
        ),
        (
            "bootstrap_process_snapshot: observed_holder_snapshot.clone(),",
            "holder binding stores native holder-process evidence",
        ),
        (
            "bootstrap_process_snapshot: observed_probe_snapshot.clone(),",
            "probe binding stores native probe-process evidence",
        ),
        (
            "observed_snapshot == observed_holder_snapshot",
            "holder LoaderReady uses the observed process baseline",
        ),
        (
            "process_snapshot == observed_probe_snapshot",
            "probe LoaderReady uses the observed process baseline",
        ),
        (
            "\"real-target-process-before-resume\"",
            "real-target same-instance pre-resume re-attestation",
        ),
        (
            "process_snapshot: process_snapshot.clone(),",
            "LoaderReady retains the immutable bootstrap snapshot for Admission comparison",
        ),
        ("binding.verify_digest()", "binding digest recomputation"),
    ] {
        require_source(&sources.process, needle, label)?;
    }
    for (needle, label) in [
        (
            "pub(crate) fn derive_launcher_holder_primary(",
            "launcher holder derivation primitive",
        ),
        (
            "TOKEN_ADJUST_SESSIONID",
            "session-specific mutable token right",
        ),
        (
            "TOKEN_ADJUST_DEFAULT",
            "native-compatible mutable token default-adjust right",
        ),
        ("TOKEN_ADJUST_PRIVILEGES", "scoped privilege carrier right"),
        ("SeTcbPrivilege", "TCB privilege lookup"),
        ("AdjustTokenPrivileges(", "scoped TCB enablement"),
        (
            "adjust_error != ERROR_SUCCESS",
            "exact privilege enablement result",
        ),
        (
            "NtSetInformationToken(",
            "raw-status duplicate-only session mutation",
        ),
        ("NtQueryObject(", "kernel granted-access readback"),
        ("PrivilegeCheck(", "effective thread privilege proof"),
        ("TokenSessionId", "target session mutation class"),
        ("scoped.revert()", "thread privilege restoration"),
        (
            "validate_holder_session_derivation(",
            "session-only derivation proof",
        ),
        (
            "const HOLDER_MUTABLE_TOKEN_ACCESS: u32 = TOKEN_QUERY\n    | TOKEN_QUERY_SOURCE\n    | TOKEN_DUPLICATE\n    | TOKEN_ASSIGN_PRIMARY\n    | TOKEN_ADJUST_DEFAULT\n    | TOKEN_ADJUST_SESSIONID;",
            "exact holder mutation capability",
        ),
        (
            "const HOLDER_LAUNCH_TOKEN_ACCESS: u32 =\n    TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY;",
            "narrow holder launch capability",
        ),
        (
            "AdjustTokenPrivileges(\n            privilege_carrier,",
            "privilege change confined to disposable carrier",
        ),
        (
            "NtSetInformationToken(\n                mutable_primary.raw(),\n                TokenSessionId,",
            "session change confined to unassigned duplicate",
        ),
    ] {
        require_source(&sources.token, needle, label)?;
    }
    let holder_derivation = semantic_function_region(
        &sources.token,
        "pub(crate) fn derive_launcher_holder_primary(",
        "pub(crate) fn derive_session_broker_holder_primary(",
    )
    .ok_or_else(|| "launcher holder derivation has no semantic boundary".to_owned())?;
    require_source_order(
        &holder_derivation,
        &[
            (
                "require_current_thread_token_absent()",
                "clean worker-thread token preflight",
            ),
            (
                "let source_access = TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE;",
                "least-rights launcher source open",
            ),
            (
                "TokenImpersonation,",
                "disposable impersonation carrier duplication",
            ),
            ("\"SeTcbPrivilege\"", "TCB grant privilege enablement"),
            (
                "\"SeAssignPrimaryTokenPrivilege\"",
                "assign-primary grant privilege enablement",
            ),
            (
                "ScopedPrivilegeThreadToken::install(privilege_carrier.raw())",
                "privilege carrier installation before mutable grant",
            ),
            (
                "let mutable_access = HOLDER_MUTABLE_TOKEN_ACCESS;",
                "mutable primary exact access declaration",
            ),
            (
                "let launch_access = HOLDER_LAUNCH_TOKEN_ACCESS;",
                "narrow holder launch access declaration",
            ),
            (
                "effective_thread_privilege_enabled(privilege_name)",
                "effective installed-carrier privilege proof",
            ),
            (
                "DuplicateTokenEx(\n                source.raw(),\n                mutable_access,",
                "mutable primary duplication under effective grant privileges",
            ),
            (
                "handle_granted_access(mutable_primary.raw())",
                "mutable handle kernel granted-access readback",
            ),
            (
                "if mutable_granted_access != mutable_access",
                "exact mutable granted-access proof",
            ),
            (
                "let session_set_status = unsafe {\n            NtSetInformationToken(",
                "direct native session mutation under the same privilege scope",
            ),
            (
                ".with_nt_status(session_set_status)",
                "raw native session-set status evidence",
            ),
            (
                "handle_granted_access(launch_token.raw())",
                "narrowed handle kernel granted-access readback",
            ),
            (
                "if launch_granted_access != launch_access",
                "exact narrowed granted-access proof",
            ),
            (
                "let narrowed_session_status = unsafe {\n            NtSetInformationToken(",
                "negative native session-adjust proof on narrowed launch handle",
            ),
            (
                "narrowed_session_status != STATUS_ACCESS_DENIED",
                "exact raw narrowed-handle access-denied result",
            ),
            (
                "scoped.revert()",
                "fail-closed privilege-carrier reversion after narrowing proof",
            ),
        ],
    )?;
    require_source(
        &holder_derivation,
        "carrier_access,\n            ptr::null(),\n            SecurityImpersonation,\n            TokenImpersonation,",
        "SecurityImpersonation disposable privilege carrier",
    )?;
    require_source(
        &holder_derivation,
        "if token_attestation_snapshot(source.raw()).map_err(|detail| {",
        "post-derivation launcher source invariance readback",
    )?;
    if holder_derivation
        .split_once("let launch_access = HOLDER_LAUNCH_TOKEN_ACCESS;")
        .is_some_and(|(_, narrowed)| {
            narrowed.contains("let launch_access")
                || narrowed.contains("launch_access =")
                || narrowed.contains("launch_access |")
        })
    {
        return Err("narrowed holder launch capability is reassigned after declaration".to_owned());
    }
    require_source(
        &sources.token,
        "Ok(basic.GrantedAccess)",
        "ObjectBasicInformation GrantedAccess evidence",
    )?;
    require_source(
        &holder_derivation,
        ".with_granted_access(mutable_granted_access)",
        "typed mutable granted-access diagnostics",
    )?;
    require_source(
        &holder_derivation,
        ".with_granted_access(launch_granted_access)",
        "typed narrowed granted-access diagnostics",
    )?;
    require_source(
        &sources.token,
        "adjusted == 0 || adjust_error != ERROR_SUCCESS",
        "strict privilege adjustment and ERROR_NOT_ALL_ASSIGNED rejection",
    )?;
    require_source(
        &sources.process,
        "impl From<super::token::LauncherHolderTokenDerivationError> for TargetDesktopLeaseCreateError",
        "typed holder derivation error mapping",
    )?;
    require_source_order(
        &sources.process,
        &[
            (
                "os_code: error.native_code,",
                "holder derivation native code preservation",
            ),
            (
                "detail: error.to_string(),",
                "holder derivation structured detail preservation",
            ),
        ],
    )?;
    require_source(
        &sources.package,
        "pub(crate) const LAUNCHER_PRIVILEGES: &[&str] = &[\n    \"SeAssignPrimaryTokenPrivilege\",\n    \"SeIncreaseQuotaPrivilege\",\n    \"SeTcbPrivilege\",\n];",
        "launcher required TCB privilege",
    )?;
    require_source_order(
        &sources.launcher,
        &[
            (
                "let target_result = SuspendedTarget::create(",
                "typed target creation transcript",
            ),
            (
                "super::token::token_query_attestation_snapshot(target_token.raw())?;",
                "live real-target process-token readback",
            ),
            (
                "target.attest_process_token_snapshot(&observed_target_snapshot)?;",
                "same-instance real-target liveness comparison",
            ),
        ],
    )?;
    if target_bootstrap.contains("process_token(launcher_process)") {
        return Err(
            "target bootstrap reopened the hardened launcher token instead of using its transferred capability"
                .to_owned(),
        );
    }
    for (needle, label) in [
        (
            "GetExitCodeProcess(peer_process, &raw mut exit_code)",
            "bootstrap peer exit-code capture",
        ),
        (
            "Self::StartedRead => \"started-read\"",
            "bootstrap Started read operation diagnostic",
        ),
        (
            "GetOverlappedResult(handle, overlapped, &raw mut transferred, 0)",
            "bootstrap completion-before-exit drain",
        ),
    ] {
        require_source(&sources.pipe, needle, label)?;
    }
    let access_check_token = semantic_function_region(
        &sources.token,
        "pub(crate) fn current_process_token_for_access_check() -> Result<OwnedHandle, String> {",
        "/// Opens the token owned by this process with the exact rights needed for a",
    )
    .ok_or_else(|| "AccessCheck token helper region is missing".to_owned())?;
    if access_check_token.trim_end()
        != "    current_process_token_with_attested_access(TOKEN_QUERY | TOKEN_DUPLICATE, \"access-check\")\n}"
    {
        return Err(
            "AccessCheck token helper is not the exact ordinary-query-and-duplicate capability"
                .to_owned(),
        );
    }
    let attestation_access_check_token = semantic_function_region(
        &sources.token,
        "pub(crate) fn current_process_token_for_attestation_and_access_check() -> Result<OwnedHandle, String>",
        "fn current_process_token_with_attested_access(",
    )
    .ok_or_else(|| "source-attestation-and-AccessCheck token helper region is missing".to_owned())?;
    if attestation_access_check_token.trim_end()
        != "{\n    current_process_token_with_attested_access(\n        TOKEN_ATTESTATION_ACCESS | TOKEN_DUPLICATE,\n        \"source-attestation-and-access-check\",\n    )\n}"
    {
        return Err(
            "source-attestation-and-AccessCheck token helper is not the exact query-source-and-duplicate capability"
                .to_owned(),
        );
    }
    require_source(
        &sources.token,
        "if granted != access {",
        "exact local token capability granted-access equality",
    )?;
    if target_bootstrap.contains("process_token(unsafe { GetCurrentProcess() })") {
        return Err("target desktop bootstrap retained query-only token capture".to_owned());
    }
    let process_token_readback = semantic_function_region(
        &sources.token,
        "pub fn process_token_detailed(process: HANDLE) -> Result<OwnedHandle, TokenOpenError> {",
        "pub fn process_user_sid(process: HANDLE) -> Result<String, String> {",
    )
    .ok_or_else(|| "general process-token readback helper region is missing".to_owned())?;
    require_source(
        &process_token_readback,
        "OpenProcessToken(process, PROCESS_TOKEN_QUERY_ACCESS, &raw mut token)",
        "least-rights process-token query readback",
    )?;
    for (needle, label) in [
        (
            "const PROCESS_TOKEN_QUERY_ACCESS: u32 = TOKEN_QUERY;",
            "exact foreign process-token query capability",
        ),
        (
            "const TOKEN_ATTESTATION_ACCESS: u32 = TOKEN_QUERY | TOKEN_QUERY_SOURCE;",
            "exact owner token-source attestation capability",
        ),
        (
            "pub(crate) struct TokenQueryAttestationSnapshot {",
            "purpose-typed ordinary query evidence",
        ),
        (
            "let query = token_query_attestation_snapshot(token)?;",
            "full snapshot composes ordinary query evidence",
        ),
        (
            "let source = scalar_struct::<TOKEN_SOURCE>(token, TokenSource)?;",
            "TokenSource is isolated to the full snapshot path",
        ),
        (
            "pub(crate) fn process_token_query_attestation(",
            "bracketed foreign process-token query attestation",
        ),
        (
            "require_same_process_token_query(",
            "typed query-only same-instance comparison",
        ),
    ] {
        require_source(&sources.token, needle, label)?;
    }
    if process_token_readback.contains("TOKEN_DUPLICATE") {
        return Err("general process-token readback gained duplicate authority".to_owned());
    }
    let nested_child = semantic_function_region(
        &sources.qualification,
        "pub fn certification_nested_child(",
        "fn nested_child_staged_receipt(receipt: &std::path::Path) -> std::path::PathBuf {",
    )
    .ok_or_else(|| "nested child certification region is missing".to_owned())?;
    require_source_order(
        &nested_child,
        &[
            (
                "entry_thread_token_transition.initial_token_reverted",
                "nested child initial-token reversion",
            ),
            (
                "entry_thread_token_transition.thread_token_absent_after_revert",
                "nested child post-revert thread-token absence",
            ),
            (
                "super::token::current_process_token_for_attestation_and_access_check()?",
                "purpose-specific post-revert snapshot-and-AccessCheck capability",
            ),
            (
                "super::token::token_attestation_snapshot(process_token.raw())",
                "post-revert process-token snapshot",
            ),
            (
                "super::security::write_restricted_behavior_attested(process_token.raw())",
                "post-revert write-restricted AccessCheck attestation",
            ),
        ],
    )?;
    if nested_child.contains("super::token::process_token(unsafe {") {
        return Err("nested child retained query-only process-token capture".to_owned());
    }
    require_source(
        &target_bootstrap,
        "super::user_api::load().map_err(|error|",
        "authenticated post-Started USER module resolution",
    )?;
    require_source(
        &target_bootstrap,
        "attest_target_user_object(\n        desktop.raw(),",
        "returned private desktop handle policy attestation",
    )?;
    require_source(
        &target_bootstrap,
        "validate_target_desktop_input_state(desktop_receives_input(desktop.raw())",
        "live private target desktop UOI_IO rejection",
    )?;
    require_source_order(
        &target_bootstrap,
        &[
            (
                "attest_target_user_object(\n        desktop.raw(),\n        &desktop_name,\n        &desktop_security,\n        super::security::SecurityObjectKind::Desktop,\n        target_token,",
                "target desktop semantic attestation before namespace finalization",
            ),
            (
                "validate_target_desktop_input_state(desktop_receives_input(desktop.raw())",
                "desktop non-input validation before namespace finalization",
            ),
            (
                "verify_private_desktop_containment(private_window_station.raw(), &desktop_wide)",
                "desktop containment before namespace finalization",
            ),
            (
                "let window_station_policy_sha256 = window_station_security",
                "canonical station policy fingerprint after semantic lifecycle",
            ),
            (
                "let desktop_policy_sha256 = desktop_security",
                "canonical desktop policy fingerprint after semantic lifecycle",
            ),
            (
                "let window_station_live_equality_sha256 =",
                "final station live equality baseline",
            ),
            (
                "let desktop_live_equality_sha256 =",
                "final desktop live equality baseline",
            ),
            (
                "let frame = TargetDesktopBootstrapFrameV1 {",
                "Ready evidence only after namespace baseline finalization",
            ),
            (
                "TargetDesktopBootstrapPipeOperation::ReadyWrite,",
                "Ready publication after final namespace baseline capture",
            ),
            (
                "serve_holder_target_association_preflight(",
                "association preflight after final baseline publication",
            ),
        ],
    )?;
    if target_bootstrap.contains("validate_guardian_desktop_binding(") {
        return Err("target bootstrap reused guardian desktop policy".to_owned());
    }
    let captured_target = semantic_function_region(
        &sources.process,
        "impl CapturedTargetDesktop {",
        "fn attest_target_user_object(",
    )
    .ok_or_else(|| "captured target desktop policy region is missing".to_owned())?;
    if captured_target
        .matches("validate_target_desktop_input_state(")
        .count()
        != 2
    {
        return Err(
            "nested target desktop does not recheck non-input state at capture and attestation"
                .to_owned(),
        );
    }
    if captured_target.contains("validate_guardian_desktop_binding(") {
        return Err("nested target capture reused guardian desktop policy".to_owned());
    }
    for forbidden in [
        "GetProcessWindowStation() } != self.window_station",
        "GetThreadDesktop(GetCurrentThreadId()) } != self.desktop",
    ] {
        if captured_target.contains(forbidden) {
            return Err(format!(
                "nested target binding retained raw USER-handle identity inference: {forbidden}"
            ));
        }
    }
    require_source_order(
        &captured_target,
        &[
            (
                "self.read_handles.window_station.raw(),",
                "nested alternate-token station readback handle",
            ),
            (
                "&self.window_station_security,",
                "nested alternate-token station policy preflight",
            ),
            (
                "self.read_handles.desktop.raw(),",
                "nested alternate-token desktop readback handle",
            ),
            (
                "&self.desktop_security,",
                "nested alternate-token desktop policy preflight",
            ),
            (
                "attest_target_user_object_opens_as_token(\n            token,\n            &self.window_station_name,\n            &self.desktop_name,\n            self.read_handles.window_station.raw(),\n            self.read_handles.desktop.raw(),\n            &self.window_station_security,\n            &self.desktop_security,\n            &self.window_station_security_sha256,\n            &self.desktop_security_sha256,\n            Instant::now() + TARGET_ASSOCIATION_PREFLIGHT_OVERALL_TIMEOUT,\n            &mut progress,\n        )",
                "fingerprint-bound nested alternate-token native USER-object open preflight",
            ),
        ],
    )?;
    let association_request = semantic_function_region(
        &sources.process,
        "fn request_holder_target_association_preflight(",
        "#[allow(clippy::too_many_arguments)]",
    )
    .ok_or_else(|| "target association preflight request region is missing".to_owned())?;
    require_source_order(
        &association_request,
        &[
            (
                "super::pipe::write_frame_bounded(",
                "bounded association preflight request publication",
            ),
            (
                "Some(holder_lease.bootstrap_process.raw()),",
                "association request bound to the live holder process",
            ),
            (
                "TargetDesktopBootstrapPipeOperation::AssociationPreflightWrite,",
                "typed association request write",
            ),
            (
                "TargetDesktopBootstrapMessageV1::AssociationPreflight {\n                binding: holder_lease.holder_binding.clone(),",
                "binding-bound association request frame",
            ),
            (
                "super::pipe::read_frame_bounded(",
                "bounded association preflight response read",
            ),
            (
                "Some(holder_lease.bootstrap_process.raw()),",
                "association response bound to the live holder process",
            ),
            (
                "TargetDesktopBootstrapPipeOperation::AssociationPreflightReadyRead,",
                "typed association response read",
            ),
            (
                "TargetDesktopBootstrapMessageV1::AssociationPreflightProgress {\n                    binding,\n                    sequence,\n                    stage,\n                    completed,\n                    total,\n                } if binding == holder_lease.holder_binding",
                "binding-authenticated association progress",
            ),
            (
                "progress\n                        .advance(sequence, stage, completed, total)",
                "monotonic bounded association progress validation",
            ),
            (
                "TargetDesktopBootstrapMessageV1::AssociationPreflightReady {\n                    binding,\n                    evidence,\n                } if binding == holder_lease.holder_binding",
                "exact holder binding on association response",
            ),
            (
                "if !progress.is_terminal()",
                "Ready requires terminal progress",
            ),
            (
                "validate_target_association_preflight_grants(\n                        evidence.window_station_granted_access,\n                        evidence.desktop_granted_access,\n                        evidence.thread_token_absent,",
                "association response granted-mask and thread-token validation",
            ),
            (
                "if evidence.window_station_policy_sha256 != expected_station_policy_sha256\n                        || evidence.desktop_policy_sha256 != expected_desktop_policy_sha256",
                "association response canonical policy binding",
            ),
            (
                "evidence.window_station_live_equality_sha256\n                            != holder_lease.window_station_live_equality_sha256",
                "association response station live-baseline binding",
            ),
            (
                "evidence.desktop_live_equality_sha256\n                            != holder_lease.desktop_live_equality_sha256",
                "association response desktop live-baseline binding",
            ),
            (
                "!evidence.window_station_policy_verified_after_open\n                        || !evidence.desktop_policy_verified_after_open\n                        || !evidence.creator_live_baselines_unchanged",
                "association response post-open semantic and lifecycle decisions",
            ),
            (
                "\"holder-association-preflight-before\",\n                        expected_target_snapshot,\n                        &evidence.target_snapshot_before,",
                "association before-snapshot target binding",
            ),
            (
                "\"holder-association-preflight-after\",\n                        expected_target_snapshot,\n                        &evidence.target_snapshot_after,",
                "association after-snapshot target binding",
            ),
            (
                "TargetDesktopBootstrapMessageV1::Failed {",
                "typed association failure response",
            ),
            (
                "validate_target_desktop_bootstrap_failure(\n                        \"association-preflight\",\n                        binding,\n                        &holder_lease.holder_binding,",
                "binding-aware association failure validation",
            ),
            (
                "target desktop holder association-preflight frame is invalid or out of order",
                "out-of-order association response rejection",
            ),
            (
                "terminate_and_drain_failed_association_preflight(holder_lease)",
                "failed association holder Job termination and drain",
            ),
        ],
    )?;
    let probe_launch = semantic_function_region(
        &sources.process,
        "fn launch_target_desktop_probe(",
        "fn read_target_desktop_bootstrap_attestation(",
    )
    .ok_or_else(|| "target desktop probe launch region is missing".to_owned())?;
    require_source_order(
        &probe_launch,
        &[
            (
                "holder_lease\n        .attest_live()",
                "holder liveness before target association preflight",
            ),
            (
                "request_holder_target_association_preflight(\n        holder_lease,\n        target_snapshot,\n        expected_station_policy_sha256,\n        expected_desktop_policy_sha256,\n    )?;",
                "target association proof before probe execution",
            ),
            (
                "holder_lease\n        .attest_live()",
                "holder liveness after target association preflight",
            ),
            (
                "launch_target_desktop_loader_control(",
                "same-image private-desktop control after association proof",
            ),
            (
                "holder_lease\n        .attest_live()",
                "holder liveness after loader control",
            ),
            (
                "let target_pre_resume = super::token::token_attestation_snapshot(target_token)?;",
                "target identity snapshot before probe resume",
            ),
            (
                "\"probe-target-request-pre-resume\",\n        target_snapshot,\n        &target_pre_resume,",
                "target identity comparison before probe resume",
            ),
            (
                "ResumeThread(probe_thread.raw())",
                "probe resume after holder association proof",
            ),
        ],
    )?;
    let association_server = semantic_function_region(
        &sources.process,
        "fn serve_holder_target_association_preflight(",
        "fn attest_target_user_object_opens_as_token(",
    )
    .ok_or_else(|| "holder target association preflight server region is missing".to_owned())?;
    require_source_order(
        &association_server,
        &[
            (
                "super::pipe::read_frame_bounded(",
                "bounded holder association request read",
            ),
            (
                "TargetDesktopBootstrapPipeOperation::AssociationPreflightRead,",
                "typed holder association request read",
            ),
            (
                "TargetDesktopBootstrapMessageV1::AssociationPreflight {\n            binding: observed_binding,\n        } if observed_binding == *binding",
                "exact holder association request binding",
            ),
            (
                "TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,\n                \"holder association-preflight request is invalid or out of order\",",
                "typed invalid association request failure",
            ),
            (
                "let overall_deadline = Instant::now() + TARGET_ASSOCIATION_PREFLIGHT_OVERALL_TIMEOUT;",
                "holder fixed association preflight deadline",
            ),
            (
                "let mut progress = AssociationPreflightProgressPublisher {",
                "holder authenticated association progress publisher",
            ),
            (
                "attest_target_user_object_opens_as_token(\n        target_token,\n        window_station_name,\n        desktop_name,\n        retained_window_station,\n        retained_desktop,\n        window_station_security,\n        desktop_security,\n        expected_window_station_live_equality_sha256,\n        expected_desktop_live_equality_sha256,\n        overall_deadline,\n        &mut progress,\n    )?;",
                "policy-and-live-baseline-bound exact-target native open proof",
            ),
            (
                "super::pipe::write_frame_bounded(",
                "bounded holder association response write",
            ),
            (
                "TargetDesktopBootstrapPipeOperation::AssociationPreflightReadyWrite,",
                "typed holder association response write",
            ),
            (
                "TargetDesktopBootstrapMessageV1::AssociationPreflightReady {\n            binding: binding.clone(),\n            evidence: Box::new(evidence),",
                "binding-bound typed association evidence response",
            ),
            (
                "TargetDesktopBootstrapFailure::from_pipe(\n            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,",
                "typed association response failure mapping",
            ),
        ],
    )?;
    let progress_publisher = semantic_function_region(
        &sources.process,
        "impl AssociationPreflightProgressSink for AssociationPreflightProgressPublisher<'_> {",
        "fn association_stage_from_native_loader(",
    )
    .ok_or_else(|| "association progress publisher region is missing".to_owned())?;
    require_source_order(
        &progress_publisher,
        &[
            (
                ".validate_next(sequence, stage, completed, total)",
                "publisher previews meaningful progress",
            ),
            (
                "TargetDesktopBootstrapPipeOperation::AssociationPreflightProgressWrite,",
                "publisher writes validated progress",
            ),
            (
                "self.cursor.commit(sequence, stage, completed, total);",
                "publisher commits only after successful write",
            ),
        ],
    )?;
    require_source(
        &sources.process,
        "const MAXIMUM_ALLOWED_ACCESS: u32 = 0x0200_0000;",
        "exact maximum-allowed USER-object open mode",
    )?;
    let target_association_preflight = semantic_function_region(
        &sources.process,
        "fn attest_target_user_object_opens_as_token(",
        "fn duplicate_explicit_impersonation_token(token: HANDLE) -> Result<OwnedHandle, String> {",
    )
    .ok_or_else(|| "target association native preflight region is missing".to_owned())?;
    require_source_order(
        &target_association_preflight,
        &[
            (
                "user_object_name(unsafe { GetProcessWindowStation() })",
                "current process station name observation",
            ),
            (
                ")? != window_station_name",
                "current process station exact-name binding",
            ),
            (
                "attest_retained_target_user_object_namespace(",
                "pre-open retained-handle equality and semantic attestation",
            ),
            (
                "super::token::require_thread_token_absent(unsafe { GetCurrentThread() })",
                "clean pre-impersonation thread-token state",
            ),
            (
                "resolve_native_loader_resources(",
                "holder-primary source identity and mutation pins",
            ),
            (
                "let target_snapshot_before =\n        super::token::token_attestation_snapshot(token)",
                "target identity before impersonation",
            ),
            (
                "duplicate_explicit_impersonation_token(token)",
                "explicit target impersonation duplicate",
            ),
            (
                "ThreadImpersonationGuard::install(impersonation.raw())",
                "scoped target impersonation installation",
            ),
            (
                "OpenWindowStationW(window_station_wide.as_ptr(), 0, MAXIMUM_ALLOWED_ACCESS)",
                "maximum-allowed station open",
            ),
            (
                "super::token::granted_handle_access(window_station.raw())",
                "station kernel granted-mask readback",
            ),
            (
                "if window_station_granted_access & super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS\n            != super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS",
                "complete required station grant validation",
            ),
            (
                "user_object_name(window_station.raw())",
                "opened station name observation",
            ),
            (
                ")? != window_station_name",
                "opened station exact-name binding",
            ),
            (
                "SecurityDescriptor::user_object_security_equality_fingerprint(window_station.raw())",
                "opened station live-equality readback",
            ),
            (
                "if window_station_live_equality_sha256 != expected_window_station_live_equality_sha256",
                "opened station live-baseline binding",
            ),
            (
                ".user_object_resultant_fingerprint(\n                window_station.raw(),\n                super::security::SecurityObjectKind::WindowStation,",
                "opened station canonical full-policy readback",
            ),
            (
                "if window_station_policy_sha256 != expected_window_station_policy_sha256",
                "opened station canonical policy binding",
            ),
            (
                "window_station.mark_assigned();",
                "assigned explicit-open station retained until holder exit",
            ),
            (
                "OpenDesktopW(desktop_wide.as_ptr(), 0, 0, MAXIMUM_ALLOWED_ACCESS)",
                "maximum-allowed desktop open",
            ),
            (
                "super::token::granted_handle_access(desktop.raw())",
                "desktop kernel granted-mask readback",
            ),
            (
                "if desktop_granted_access & super::security::TARGET_PRIVATE_DESKTOP_ACCESS\n            != super::security::TARGET_PRIVATE_DESKTOP_ACCESS",
                "complete required desktop grant validation",
            ),
            (
                "user_object_name(desktop.raw())",
                "opened desktop name observation",
            ),
            (")? != desktop_name", "opened desktop exact-name binding"),
            (
                "SecurityDescriptor::user_object_security_equality_fingerprint(desktop.raw())",
                "opened desktop live-equality readback",
            ),
            (
                "if desktop_live_equality_sha256 != expected_desktop_live_equality_sha256",
                "opened desktop live-baseline binding",
            ),
            (
                ".user_object_resultant_fingerprint(\n                desktop.raw(),\n                super::security::SecurityObjectKind::Desktop,",
                "opened desktop canonical resultant-policy readback",
            ),
            (
                "if desktop_policy_sha256 != expected_desktop_policy_sha256",
                "opened desktop canonical policy binding",
            ),
            (
                "desktop.mark_assigned();",
                "assigned explicit-open desktop retained until holder exit",
            ),
            (
                "guard.revert()",
                "explicit-binding preflight identity restoration",
            ),
            (
                "super::token::require_thread_token_absent(unsafe { GetCurrentThread() })",
                "post-revert thread-token absence",
            ),
            (
                "let target_snapshot_after =\n        super::token::token_attestation_snapshot(token)",
                "target identity after impersonation",
            ),
            (
                "\"holder-target-association-preflight\",\n        &target_snapshot_before,\n        &target_snapshot_after,",
                "same target-token instance across impersonation",
            ),
            (
                "attest_retained_target_user_object_namespace(",
                "post-open retained-handle equality and semantic reattestation",
            ),
            (
                "Ok((\n        TargetUserObjectOpenPreflightV1 {\n            window_station_granted_access,\n            desktop_granted_access,\n            desktop_heap_kb,\n            window_station_policy_sha256,\n            desktop_policy_sha256,\n            window_station_live_equality_sha256,\n            desktop_live_equality_sha256,\n            window_station_policy_verified_after_open: true,\n            desktop_policy_verified_after_open: true,\n            creator_live_baselines_unchanged: true,\n            target_snapshot_before,\n            target_snapshot_after,\n            thread_token_absent: true,\n            native_loader_access,\n        },\n        native_loader_access_lease,\n    ))",
                "complete target association evidence and retained lease construction",
            ),
        ],
    )?;
    if target_association_preflight
        .matches("attest_retained_target_user_object_namespace(")
        .count()
        != 3
    {
        return Err(
            "association preflight must invoke retained namespace attestation before and after the open, then define its helper"
                .to_owned(),
        );
    }
    let retained_namespace_attestation = semantic_function_region(
        &sources.process,
        "fn attest_retained_target_user_object_namespace(",
        "fn duplicate_explicit_impersonation_token(token: HANDLE) -> Result<OwnedHandle, String> {",
    )
    .ok_or_else(|| "retained namespace attestation region is missing".to_owned())?;
    require_source_order(
        &retained_namespace_attestation,
        &[
            (
                "SecurityDescriptor::user_object_security_equality_fingerprint(retained_window_station)",
                "retained station live baseline readback",
            ),
            (
                "SecurityDescriptor::user_object_security_equality_fingerprint(retained_desktop)",
                "retained desktop live baseline readback",
            ),
            (
                "if window_station_live_equality_sha256 != expected_window_station_live_equality_sha256\n        || desktop_live_equality_sha256 != expected_desktop_live_equality_sha256",
                "paired retained namespace equality comparison",
            ),
            (
                "attest_target_user_object(\n        retained_window_station,",
                "retained station semantic policy reattestation",
            ),
            (
                "attest_target_user_object(\n        retained_desktop,",
                "retained desktop semantic policy reattestation",
            ),
        ],
    )?;
    require_source(
        &sources.security,
        "const NONINTERACTIVE_WINDOW_STATION_ALL_ACCESS: u32 = 0x000f_016f;",
        "noninteractive station normalization contract",
    )?;
    require_source(
        &sources.security,
        "pub const TARGET_PRIVATE_WINDOW_STATION_ACCESS: u32 = NONINTERACTIVE_WINDOW_STATION_ALL_ACCESS;",
        "exact private window-station connection mask",
    )?;
    require_source(
        &sources.security,
        "pub const TARGET_PRIVATE_DESKTOP_ACCESS: u32 = DESKTOP_ALL_ACCESS;",
        "exact private desktop connection mask",
    )?;
    require_source(
        &sources.security,
        "pub fn target_window_station_sddl(",
        "private window-station descriptor policy",
    )?;
    require_source(
        &sources.security,
        "target_user_object_sddl(token, TARGET_PRIVATE_WINDOW_STATION_ACCESS)",
        "station-specific USER-object access mask selection",
    )?;
    require_source(
        &sources.security,
        "pub fn target_desktop_sddl(",
        "private desktop descriptor policy",
    )?;
    require_source(
        &sources.security,
        "target_user_object_sddl(token, TARGET_PRIVATE_DESKTOP_ACCESS)",
        "desktop-specific USER-object access mask selection",
    )?;
    require_source(
        &sources.security,
        "pub fn private_window_station_access_check(",
        "window-station-specific target policy AccessCheck",
    )?;
    require_source(
        &sources.security,
        "pub fn private_desktop_access_check(",
        "desktop-specific target policy AccessCheck",
    )?;
    if sources
        .security
        .contains("pub fn user_object_access_check(")
    {
        return Err(
            "private desktop policy retained a generic station-capable AccessCheck API".to_owned(),
        );
    }
    if !target_bootstrap.contains("CreateWindowStationW(")
        || sources.process.matches("CreateWindowStationW(").count() != 1
    {
        return Err(
            "private USER namespace creation escaped its target-token bootstrap scope".to_owned(),
        );
    }
    if !target_bootstrap.contains("SetProcessWindowStation(private_window_station.raw())")
        || !station_owner.contains("SetProcessWindowStation(source)")
        || sources.process.matches("SetProcessWindowStation(").count() != 2
    {
        return Err(
            "private USER namespace station transitions escaped their owned lifecycle".to_owned(),
        );
    }
    for forbidden in [
        "startup.StartupInfo.lpDesktop = ptr::null_mut();",
        "WINSTA_READSCREEN",
        "WINSTA_WRITEATTRIBUTES",
    ] {
        if sources.process.contains(forbidden) {
            return Err(format!(
                "production retained forbidden USER namespace authority: {forbidden}"
            ));
        }
    }
    for (needle, label) in [
        (
            "let mut sddl = \"O:SYG:SYD:P\".to_owned();",
            "authenticated holder USER-object owner and primary group",
        ),
        (
            "trustees.insert(\"S-1-5-33\".to_owned());",
            "explicit nested write-restricted delegation",
        ),
        (
            "trustees.extend(restricting_sids.iter().cloned());",
            "private USER-pair exact restricting-SID participants",
        ),
        (
            "snapshot_before.behavior.restricting_sids != restricting.evidence",
            "snapshot-bound exact restricting inventory",
        ),
        (
            "classify_target_restriction(",
            "typed restriction-semantics classification",
        ),
        (
            "GROUP_SECURITY_INFORMATION",
            "primary-group readback selection",
        ),
        ("MakeAbsoluteSD(", "owned absolute USER creation descriptor"),
        (
            "source_control & SE_SELF_RELATIVE == 0",
            "self-relative source requirement",
        ),
        (
            "absolute_control & SE_SELF_RELATIVE != 0",
            "absolute creation-view requirement",
        ),
        (
            "sddl.contains(\"(ML;\")",
            "SACL-control-independent mandatory-label selection",
        ),
        (
            "source_control & SE_SACL_PRESENT_CONTROL != 0",
            "mandatory-label creator SACL presence proof",
        ),
        (
            "source_control & SE_SACL_PROTECTED_CONTROL != 0",
            "mandatory-label creator SACL protection proof",
        ),
        (
            "source_control & SE_SACL_AUTO_INHERIT_REQ_CONTROL != 0",
            "mandatory-label creator SACL auto-inherit-request rejection",
        ),
        (
            "source_control & SE_SACL_AUTO_INHERITED_CONTROL != 0",
            "mandatory-label creator SACL auto-inherited rejection",
        ),
        (
            "absolute_control & SE_SACL_PRESENT_CONTROL != 0",
            "absolute mandatory-label SACL presence proof",
        ),
        (
            "absolute_control & SE_SACL_PROTECTED_CONTROL != 0",
            "absolute mandatory-label SACL protection proof",
        ),
        (
            "absolute_control & SE_SACL_AUTO_INHERIT_REQ_CONTROL != 0",
            "absolute mandatory-label SACL auto-inherit-request rejection",
        ),
        (
            "absolute_control & SE_SACL_AUTO_INHERITED_CONTROL != 0",
            "absolute mandatory-label SACL auto-inherited rejection",
        ),
        (
            "GenericAll: NONINTERACTIVE_WINDOW_STATION_ALL_ACCESS",
            "exact noninteractive station generic-all mapping",
        ),
        (
            "pre_write_restricted_certification_marker_state_sddl",
            "exact pre-WR marker policy",
        ),
    ] {
        require_source(&sources.security, needle, label)?;
    }
    let target_desktop_policy = sources
        .security
        .split_once("pub(crate) enum TargetUserObjectPolicyRoleV1")
        .and_then(|(_, tail)| tail.split_once("\npub fn target_desktop_bootstrap_pipe_sddl("))
        .map(|(body, _)| body)
        .ok_or_else(|| "target desktop policy function boundary is absent".to_owned())?;
    require_source(
        target_desktop_policy,
        "sddl.push_str(&format!(\"S:P(ML;;NW;;;{})\", self.target_integrity_sid));",
        "target-matched protected private USER-object integrity label",
    )?;
    let normalized_descriptor = semantic_function_region(
        &sources.security,
        "pub(crate) fn normalized_descriptor_sddl(",
        "fn normalized_resultant_user_object_sddl(",
    )
    .ok_or_else(|| "normalized descriptor function boundary is absent".to_owned())?;
    for forbidden in [
        "SE_SACL_AUTO_INHERITED_CONTROL",
        "SetSecurityDescriptorControl(",
        "S:AI",
    ] {
        if normalized_descriptor.contains(forbidden) {
            return Err(format!(
                "USER-object descriptor normalization masks SACL control state: {forbidden}"
            ));
        }
    }
    let resultant_user_object = semantic_function_region(
        &sources.security,
        "fn normalized_resultant_user_object_sddl(",
        "fn normalized_descriptor_copy(",
    )
    .ok_or_else(|| "resultant USER-object function boundary is absent".to_owned())?;
    for (needle, label) in [
        (
            "if kind != SecurityObjectKind::Desktop {",
            "desktop-only resultant USER-object exception",
        ),
        (
            "expected_control & SE_SACL_PRESENT_CONTROL != 0",
            "expected resultant-comparison SACL presence",
        ),
        (
            "expected_control & SE_SACL_PROTECTED_CONTROL != 0",
            "expected resultant-comparison SACL protection",
        ),
        (
            "expected_control & SE_SACL_AUTO_INHERIT_REQ_CONTROL != 0",
            "expected resultant-comparison auto-inherit request rejection",
        ),
        (
            "expected_control & SE_SACL_AUTO_INHERITED_CONTROL != 0",
            "expected resultant-comparison auto-inherited rejection",
        ),
        (
            "if actual_control == expected_control {",
            "exact resultant desktop control fast path",
        ),
        (
            "actual_control & SE_SACL_PRESENT_CONTROL != 0",
            "actual resultant desktop SACL presence",
        ),
        (
            "actual_control & SE_SACL_PROTECTED_CONTROL != 0",
            "actual resultant desktop SACL protection",
        ),
        (
            "actual_control & SE_SACL_AUTO_INHERIT_REQ_CONTROL != 0",
            "actual resultant desktop auto-inherit request rejection",
        ),
        (
            "(expected_control ^ actual_control) == SE_SACL_AUTO_INHERITED_CONTROL",
            "single resultant desktop SACL control-bit exception",
        ),
        (
            "normalized_descriptor_copy(actual, kind)?",
            "resultant desktop descriptor copy",
        ),
        (
            "SetSecurityDescriptorControl(\n            normalized.as_mut_ptr().cast(),\n            SE_SACL_AUTO_INHERITED_CONTROL,\n            0,\n        )",
            "copied resultant desktop SACL control normalization",
        ),
    ] {
        require_source(&resultant_user_object, needle, label)?;
    }
    require_source(
        &sources.security,
        "let actual = if kind == SecurityObjectKind::Desktop {",
        "desktop-gated resultant descriptor comparison",
    )?;
    require_source(
        &sources.security,
        "if actual == expected {",
        "exact normalized owner/group/DACL/mandatory-label comparison",
    )?;
    for (needle, label) in [
        (
            "pub fn user_object_policy_fingerprint(",
            "canonical target USER-object policy fingerprint API",
        ),
        (
            "require_target_user_object_policy_selection(self.1, kind)?;",
            "policy fingerprint O/G/D/LABEL selection enforcement",
        ),
        (
            "normalized_descriptor_sddl(self.0, self.1, kind)?",
            "canonical parsed policy projection",
        ),
        (
            "pub fn user_object_resultant_fingerprint(",
            "canonical target USER-object resultant fingerprint API",
        ),
        (
            "let mut descriptor = read_user_object_security(handle, self.1)?;",
            "live resultant uses matching policy component selection",
        ),
        (
            "let canonical = if kind == SecurityObjectKind::Desktop {\n            normalized_resultant_user_object_sddl(self.0, actual, self.1, kind)?",
            "desktop-only resultant fingerprint normalization",
        ),
        (
            "let required = OWNER_SECURITY_INFORMATION\n        | GROUP_SECURITY_INFORMATION\n        | DACL_SECURITY_INFORMATION\n        | LABEL_SECURITY_INFORMATION;",
            "mandatory-label selection without whole-SACL authority",
        ),
    ] {
        require_source(&sources.security, needle, label)?;
    }
    require_source(
        &sources.sealed_windows,
        "windows_security::desktop_resultant_sacl_auto_inherited_is_the_only_user_object_exception",
        "native x64 and arm64 resultant desktop SACL regression",
    )?;
    require_source(
        &sources.sealed_windows,
        "windows_security::target_user_object_policy_fingerprint_is_canonical_and_label_bound",
        "native canonical O/G/D/LABEL policy fingerprint regression",
    )?;
    require_source(
        &sources.sealed_windows,
        "windows_security::target_user_object_resultant_fingerprint_keeps_the_desktop_exception_narrow",
        "native resultant fingerprint normalization regression",
    )?;
    for source in [&sources.security, &sources.process] {
        if source.contains("SetUserObjectSecurity") {
            return Err(
                "production bootstrap mutates live USER-object security after creation".to_owned(),
            );
        }
    }
    for forbidden in [
        "\"S-1-1-0\"",
        "\"S-1-5-11\"",
        "\"S-1-5-32-544\"",
        "\"S-1-5-4\"",
        "token_user_sid(",
        "envelope.user_sid",
    ] {
        if target_desktop_policy.contains(forbidden) {
            return Err(format!(
                "private target desktop policy grants a forbidden broad/service trustee: {forbidden}"
            ));
        }
    }
    for forbidden in ["WINSTA_READSCREEN", "WINSTA_WRITEATTRIBUTES", "0x000f_037f"] {
        if sources.security.contains(forbidden) {
            return Err(format!(
                "noninteractive station contract retained interactive-only authority: {forbidden}"
            ));
        }
    }
    if sources
        .process
        .matches("target_user_object_policy_role: policy_role,")
        .count()
        != 2
        || sources
            .process
            .matches("binding.target_user_object_policy_role")
            .count()
            != 2
    {
        return Err(
            "target USER-object policy role is not bound through both holder and probe protocols"
                .to_owned(),
        );
    }
    for (needle, label) in [
        (
            "let window_station_attributes = window_station_creation_security.attributes(false);",
            "absolute descriptor used at private station creation",
        ),
        (
            "let attributes = creation_security.attributes(false);",
            "absolute descriptor used at private desktop creation",
        ),
    ] {
        require_source(&sources.process, needle, label)?;
    }
    if sources
        .process
        .contains("let attributes = security.attributes(false);")
    {
        return Err(
            "target USER-object creation still exposes the self-relative descriptor".to_owned(),
        );
    }
    for (needle, label) in [
        (
            "window_station_policy_sha256: String,",
            "separate private station canonical policy evidence",
        ),
        (
            "desktop_policy_sha256: String,",
            "separate private desktop canonical policy evidence",
        ),
        (
            "window_station_live_equality_sha256: String,",
            "separate private station live equality evidence",
        ),
        (
            "desktop_live_equality_sha256: String,",
            "separate private desktop live equality evidence",
        ),
        (
            "window_station_policy_verified: bool,",
            "private station policy decision evidence",
        ),
        (
            "desktop_policy_verified: bool,",
            "private desktop policy decision evidence",
        ),
    ] {
        require_source(&sources.process, needle, label)?;
    }
    for (needle, label) in [
        (
            "write_restricted_code_present: bool,",
            "nested receipt WR identity evidence",
        ),
        (
            "restricted_code_absent: bool,",
            "nested receipt RC exclusion evidence",
        ),
        (
            "write_restricted: bool,",
            "nested receipt write-mode evidence",
        ),
        (
            "window_station_name: String,",
            "nested receipt station binding",
        ),
        ("desktop_name: String,", "nested receipt desktop binding"),
        (
            "desktop_policy_verified: bool,",
            "nested receipt USER policy attestation",
        ),
        (
            "private_desktop_binding_verified: bool,",
            "nested receipt private binding attestation",
        ),
        (
            "initial_thread_token_envelope: memcordon_core::WindowsCallerTokenEnvelopeV1,",
            "nested initial-thread token evidence",
        ),
        (
            "initial_thread_token_id: u64,",
            "nested initial-thread token object evidence",
        ),
        (
            "process_token_id: u64,",
            "nested permanent process-token object evidence",
        ),
        (
            "thread_token_absent_after_revert: bool,",
            "nested entry-token removal evidence",
        ),
    ] {
        require_source(&sources.qualification, needle, label)?;
    }
    for (source, needle, label) in [
        (
            &sources.token,
            "pub(crate) struct TokenInstanceEvidence {",
            "separate nested token-instance evidence",
        ),
        (
            &sources.token,
            "pub(crate) struct TokenLineageEvidence {",
            "separate nested token-lineage evidence",
        ),
        (
            &sources.token,
            "pub originating_logon_session: u64,",
            "TokenOrigin lineage evidence",
        ),
        (
            &sources.token,
            "pub source_name: [u8; 8],",
            "exact TokenSource name evidence",
        ),
        (
            &sources.token,
            "pub source_identifier: u64,",
            "exact TokenSource identifier evidence",
        ),
        (
            &sources.token,
            "pub(crate) struct TokenBehaviorEvidence {",
            "separate nested token-behavior evidence",
        ),
        (
            &sources.token,
            "pub default_dacl_sha256: Option<String>,",
            "default-DACL authority evidence",
        ),
        (
            &sources.token,
            "pub(crate) fn require_assigned_process_authority(",
            "typed source-to-process authority comparator",
        ),
        (
            &sources.token,
            "pub(crate) fn require_assigned_token_authority(",
            "typed full-source assigned-token authority comparator",
        ),
        (
            &sources.token,
            "let differences = token_attestation_difference_fields(source, assigned, false);",
            "full-source assignment ignores only token identity",
        ),
        (
            &sources.token,
            "pub(crate) fn require_same_token_instance(",
            "typed same-object comparator",
        ),
        (
            &sources.token,
            "if source.instance.modified_id != process.instance.modified_id {",
            "pure-copy ModifiedId preservation",
        ),
        (
            &sources.token,
            "if source.lineage.authentication_id != process.lineage.authentication_id {",
            "AuthenticationId assignment lineage",
        ),
        (
            &sources.token,
            "if source.lineage.originating_logon_session != process.lineage.originating_logon_session",
            "TokenOrigin assignment lineage",
        ),
        (
            &sources.token,
            "if source.lineage.source_name != process.lineage.source_name {",
            "TokenSource name assignment lineage",
        ),
        (
            &sources.token,
            "if source.lineage.source_identifier != process.lineage.source_identifier {",
            "TokenSource identifier assignment lineage",
        ),
        (
            &sources.token,
            "if source.lineage.user_sid != process.lineage.user_sid {",
            "assigned-token user identity",
        ),
        (
            &sources.token,
            "if source.lineage.session_id != process.lineage.session_id {",
            "assigned-token session identity",
        ),
        (
            &sources.token,
            "if source.behavior.groups != process.behavior.groups {",
            "assigned-token group inventory",
        ),
        (
            &sources.token,
            "if source.behavior.privileges != process.behavior.privileges {",
            "assigned-token privilege inventory",
        ),
        (
            &sources.token,
            "if source.behavior.restricting_sids != process.behavior.restricting_sids {",
            "assigned-token restricting SID inventory",
        ),
        (
            &sources.token,
            "if source.behavior.token_is_restricted != process.behavior.token_is_restricted {",
            "assigned-token restriction state",
        ),
        (
            &sources.token,
            "let source = scalar_struct::<TOKEN_SOURCE>(token, TokenSource)?;",
            "TokenSource remains full-capability provenance",
        ),
        (
            &sources.token,
            "if source.behavior.default_dacl_sha256 != process.behavior.default_dacl_sha256 {",
            "default-DACL assignment authority",
        ),
        (
            &sources.token,
            "if granted != PROCESS_TOKEN_QUERY_ACCESS {",
            "exact process-token query handle rights",
        ),
        (
            &sources.token,
            "TOKEN_QUERY | TOKEN_QUERY_SOURCE,",
            "process-context foreign-thread token readback",
        ),
        (
            &sources.token,
            "if behavior.envelope.impersonation_level != SecurityImpersonation as u32 {",
            "exact nested loader impersonation level",
        ),
        (
            &sources.token,
            "if !behavior.token_is_restricted",
            "restricted nested loader token invariant",
        ),
        (
            &sources.token,
            "failures.push(\"restricting_sids_empty\")",
            "nonempty nested loader restriction invariant",
        ),
        (
            &sources.token,
            "actual_restricting_sids != expected_restricting_sids",
            "exact canonical nested loader restriction inventory",
        ),
        (
            &sources.process,
            "requested_before_install.instance != installed.observed_thread.instance",
            "exact installed token-instance continuity",
        ),
        (
            &sources.process,
            "requested_before_install.behavior != installed.observed_thread.behavior",
            "fail-closed installed token-behavior continuity",
        ),
        (
            &sources.process,
            "observed_transition_fields.join(\", \")",
            "field-level nested token transition diagnostics",
        ),
        (
            &sources.qualification,
            "receipt.initial_thread_token_id != expected_initial_thread_token_id",
            "parent/child initial token-instance continuity",
        ),
        (
            &sources.qualification,
            "receipt.process_token_id != suspended_process_token_id",
            "parent/child permanent token-instance continuity",
        ),
    ] {
        require_source(source, needle, label)?;
    }
    require_source_order(
        &sources.token,
        &[
            (
                "primary_without_restricting_sid_from_source(source, DISABLE_MAX_PRIVILEGE | LUA_TOKEN)?",
                "post-LUA nested initial primary",
            ),
            (
                "canonical_same_access_restricting_sids(initial_primary.raw())?",
                "canonical nested initial restriction inventory",
            ),
            (
                "restricted_same_access_primary(initial_primary.raw())?",
                "restricted-same-access nested initial primary",
            ),
            (
                "DuplicateTokenEx(\n            same_access_primary.raw(),",
                "restricted-same-access impersonation duplication",
            ),
        ],
    )?;
    require_source(
        &sources.package,
        "pub(crate) const INSTALL_SDDL: &str = \"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)(A;;GX;;;RC)(A;OIIO;GRGX;;;RC)(A;OICI;GRGX;;;AC)\";",
        "package install policy with Restricted Code read/execute",
    )?;
    require_source_order(
        &sources.qualification,
        &[
            (
                "super::token::nested_target_tokens()",
                "common-source nested token factory",
            ),
            (
                "\"windows-certification-nested-child\"",
                "dedicated nested child probe command",
            ),
            (
                "NestedChildOutputCollectors::start(&mut streams)",
                "bounded local output relay",
            ),
            (
                "read_bound_nested_child_receipt(marker, &attempt_binding)",
                "child-owned bound receipt validation",
            ),
        ],
    )?;
    for (source, fragment, invariant) in [
        (
            &sources.control,
            "relay_phase: WindowsRelayPhaseV1,",
            "typed control relay phase outcome",
        ),
        (
            &sources.qualification,
            "let mut relay_phase = WindowsRelayPhaseV1::AwaitStreams;",
            "qualification relay phase machine",
        ),
        (
            &sources.launcher,
            "pipe::read_frame_detailed::<WindowsLauncherRequestV1>(connection)",
            "typed relay-retirement frame diagnostics",
        ),
        (
            &sources.launcher,
            "fallback_cleanup_failures={}",
            "fallback cleanup failure preservation",
        ),
    ] {
        require_source(source, fragment, invariant)?;
    }
    let terminal_validation = semantic_function_region(
        &sources.qualification,
        "fn validate_qualification_terminal<'a>(",
        "fn validate_cleanup_process_creation_evidence(",
    )
    .ok_or_else(|| "qualification terminal validation region is missing".to_owned())?;
    require_source_order(
        &terminal_validation,
        &[
            (
                "if !evidence.active_processes_zero",
                "retirement evidence before target failure",
            ),
            (
                "if !target_result.success",
                "primary target failure preservation",
            ),
            (
                "terminal.cleanup_process_creation.as_ref().ok_or_else",
                "successful-target cleanup evidence requirement",
            ),
        ],
    )?;
    require_source_order(
        &sources.main,
        &[
            (
                "windows::token::revert_entry_thread_token()",
                "entry-thread token reversion",
            ),
            (
                "let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();",
                "argument parsing after entry-token reversion",
            ),
            (
                "&entry_thread_token_transition,",
                "entry-token transition receipt handoff",
            ),
        ],
    )?;
    if normal_retirement
        .split("fn build_terminal_receipt(")
        .next()
        .expect("normal retirement prefix exists")
        .contains("let _ = job.terminate(")
    {
        return Err("Windows normal retirement ignores Job termination failure".to_owned());
    }
    require_source_order(
        &sources.launcher,
        &[
            (
                "Self::Direct(_) | Self::Interrupted(_) => CANCEL_STATUS",
                "direct and interrupted cancellation status",
            ),
            (
                "Self::Deadline => DEADLINE_STATUS",
                "deadline termination status",
            ),
            (
                "Self::Memory(_) => LIMIT_STATUS",
                "memory termination status",
            ),
        ],
    )?;
    require_source_order(
        &sources.qualification,
        &[
            (
                "pub(super) const CLEANUP_PROCESS_CREATION_RESULT_SCHEMA_VERSION: u32 = 1;",
                "versioned cleanup process-creation marker result",
            ),
            (
                "#[serde(deny_unknown_fields, rename_all = \"kebab-case\")]",
                "fail-closed typed cleanup process-creation outcome",
            ),
            (
                "pub(super) struct CleanupProcessCreationResultV1 {",
                "typed cleanup process-creation result receipt",
            ),
            ("    StartSignal,", "typed cleanup start-marker path role"),
            (
                "while !cleanup_process_creation_start_observed(",
                "cleanup start-marker observation",
            ),
            (
                "completed_phases.push(CleanupProcessCreationProducerPhaseV1::SpawnEntered);",
                "positive pre-spawn observation fact",
            ),
            (
                "CleanupProcessCreationOutcomeV1::Failed {",
                "typed child-spawn failure receipt",
            ),
            (
                "publish_cleanup_process_creation_terminal(",
                "self-contained typed terminal publication",
            ),
            (
                "super::record::publish_create_once_atomically(file, &destination).map_err(|error| {\n        CleanupProducerFailure::publication(\n            completed_phases.last().copied(),\n            Some(CleanupProcessCreationProducerPhaseV1::ResultPublished),",
                "retained-handle create-once atomic terminal publication",
            ),
        ],
    )?;
    for (fragment, invariant) in [
        (
            "pub(crate) struct CreateOnceStagingFile {",
            "owned create-once staging capability",
        ),
        (
            ".access_mode(GENERIC_WRITE_ACCESS | DELETE_ACCESS)",
            "DELETE requested only on the CREATE_NEW staging handle",
        ),
        (
            "SetFileInformationByHandle(",
            "handle-based create-once publication",
        ),
        ("FileRenameInfo,", "rename-information publication class"),
        (
            "(*rename).Anonymous.ReplaceIfExists = false;",
            "kernel-enforced no-replace publication",
        ),
        (
            "(*rename).RootDirectory = ptr::null_mut();",
            "documented absolute create-once destination form",
        ),
        (
            "(*rename).FileNameLength = destination_name_bytes;",
            "non-NUL UTF-16 byte-count rename contract",
        ),
        (
            "*filename.add(destination.len()) = 0;",
            "explicit in-buffer UTF-16 terminator",
        ),
        (
            "bytes.max(std::mem::size_of::<FILE_RENAME_INFO>())",
            "complete declared rename-information storage",
        ),
        (
            "words: vec![0_usize; aligned_words]",
            "fully zeroed aligned rename-information storage",
        ),
        (
            "rename.cast(),\n            information.backing_bytes,",
            "complete aligned rename-information API bound",
        ),
        (
            "const NAME_QUERY_FLAGS: u32 = FILE_NAME_NORMALIZED | VOLUME_NAME_NT;",
            "single canonical NT name representation",
        ),
        (
            "create_once_normalized_nt_path(source.file.as_raw_handle() as _)",
            "authoritative retained-handle name readback",
        ),
        (
            "std::mem::zeroed::<FILE_ID_INFO>()",
            "128-bit retained file identity evidence",
        ),
        (
            "if source_location.leaf_units != expected_source_leaf {",
            "exact staging-leaf precondition",
        ),
        (
            "if identity_before.volume_serial != identity_after.volume_serial {",
            "retained volume identity comparison",
        ),
        (
            "if identity_before.file_id != identity_after.file_id {",
            "128-bit retained file identity comparison",
        ),
        (
            "GetFileInformationByHandleEx(\n            handle,\n            FileStandardInfo,",
            "retained-handle hard-link-count evidence",
        ),
        (
            "if source_link_count != 1 {",
            "single-link staging-object precondition",
        ),
        (
            "if final_link_count != 1 {",
            "single-link published-object postcondition",
        ),
        (
            "if source_location.parent_units != final_location.parent_units {",
            "same canonical kernel parent postcondition",
        ),
        (
            "if final_location.leaf_units != expected_final_leaf {",
            "exact requested UTF-16 final component postcondition",
        ),
        (
            "let final_sync = source.file.sync_all();",
            "unconditional post-commit retained-handle durability flush",
        ),
        (
            "return Err(failure.with_secondary(CreateOncePublicationStage::FinalSync, error));",
            "semantic-primary sync-secondary failure preservation",
        ),
    ] {
        require_source(&sources.record, fragment, invariant)?;
    }
    let create_once_publisher = semantic_function_region(
        &sources.record,
        "pub(crate) fn publish_create_once_atomically(",
        "fn provider_generation() -> String {",
    )
    .ok_or_else(|| "create-once publisher boundary is absent".to_owned())?;
    if create_once_publisher.contains("MoveFileExW(") {
        return Err("create-once publisher reopens its staging path for rename".to_owned());
    }
    for (forbidden, invariant) in [
        (
            "GetLongPathNameW(",
            "caller-path long-name canonicalization",
        ),
        ("same_normalized_windows_path(", "ad-hoc path normalization"),
        ("to_ascii_lowercase(", "ASCII-only path case folding"),
        ("OpenOptions::new().open(destination)", "destination reopen"),
        ("File::open(destination)", "destination reopen"),
        ("canonicalize(destination)", "destination reopen"),
    ] {
        if create_once_publisher.contains(forbidden) {
            return Err(format!(
                "create-once publisher restored forbidden {invariant}: {forbidden}"
            ));
        }
    }
    require_source_order(
        &create_once_publisher,
        &[
            (
                "let source_path =\n        create_once_normalized_nt_path(source.file.as_raw_handle() as _)",
                "pre-rename retained-handle canonical name",
            ),
            ("let identity_before =", "pre-rename 128-bit file identity"),
            (
                "let source_link_count =",
                "pre-rename retained-handle link count",
            ),
            (
                "SetFileInformationByHandle(",
                "retained-handle no-replace rename",
            ),
            (
                "let final_path_result = create_once_normalized_nt_path(source.file.as_raw_handle() as _)",
                "post-rename retained-handle final-name readback",
            ),
            (
                "let identity_after_result = create_once_file_identity(source.file.as_raw_handle() as _)",
                "post-rename 128-bit file identity",
            ),
            (
                "let final_link_count_result = create_once_link_count(source.file.as_raw_handle() as _)",
                "post-rename retained-handle link count",
            ),
            (
                "let verification = verify_create_once_postcondition(",
                "complete semantic transition proof",
            ),
            (
                "let final_sync = source.file.sync_all();",
                "unconditional post-commit durability flush",
            ),
        ],
    )?;
    require_source_order(
        &sources.qualification,
        &[
            (
                "CreateOnceStagingFile::create(&staged)",
                "CREATE_NEW staging capability",
            ),
            (
                "write_all(file.file_mut(),",
                "write through retained handle",
            ),
            ("file.sync_all()", "flush through retained handle"),
            (
                "publish_create_once_atomically(file,",
                "consume retained handle for no-replace rename",
            ),
        ],
    )?;
    require_source(
        &sources.qualification,
        "#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]\n#[serde(deny_unknown_fields)]\npub(super) struct CleanupProcessCreationResultV1 {",
        "unknown-field rejection for cleanup process-creation results",
    )?;
    for (fragment, invariant) in [
        (
            "let mut file = match std::fs::File::open(path)",
            "pinned cleanup terminal open",
        ),
        (
            "fn read_cleanup_process_creation_terminal(\n    path: &std::path::Path,",
            "dedicated pinned terminal reader",
        ),
        (
            "metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0",
            "cleanup result reparse-point rejection",
        ),
        (
            "cleanup producer terminal is malformed: {error}",
            "typed cleanup result decoding",
        ),
    ] {
        require_source(&sources.launcher, fragment, invariant)?;
    }
    require_source_order(
        &sources.launcher,
        &[
            (
                "receipt.schema_version\n        != super::qualification::CLEANUP_PROCESS_CREATION_RESULT_SCHEMA_VERSION",
                "cleanup result schema-version equality",
            ),
            (
                "receipt.attempt_binding != attempt_binding",
                "nonce-derived result binding",
            ),
            (
                "|| receipt.producer_identity != pinned_identity",
                "terminal producer identity binding",
            ),
            (
                "|| receipt.completed_phases",
                "required terminal phase transcript",
            ),
            (
                "CleanupProcessCreationOutcomeV1::Failed {",
                "explicit child-spawn failure rejection",
            ),
            (
                "job.process_ids()?.contains(&child_pid)",
                "created-child Job membership proof",
            ),
            (
                "total_processes_after <= total_processes_before",
                "created-child cumulative accounting proof",
            ),
        ],
    )?;
    for (fragment, invariant) in [
        (
            "cleanup-time process creation result timed out: phase={:?} pid={}",
            "missing-result timeout diagnostic",
        ),
        (
            "cleanup producer terminal is malformed: {error}",
            "malformed-result rejection",
        ),
        (
            "cleanup-time process creation result reported a zero child PID",
            "partial created-result rejection",
        ),
        (
            "LaunchAttemptError::cleanup_marker(\n                \"terminal-open\",",
            "typed terminal-open filesystem failure",
        ),
    ] {
        require_source(&sources.launcher, fragment, invariant)?;
    }
    for (source, fragment, invariant) in [
        (
            &sources.qualification,
            "pub(super) struct CleanupProcessCreationStateV1 {",
            "typed cleanup producer state",
        ),
        (
            &sources.qualification,
            "pub(super) struct CleanupProcessCreationProducerFailureV1 {",
            "typed cleanup producer failure receipt",
        ),
        (
            &sources.qualification,
            "Self::SpawnEntered => \"state.02-spawn-entered.json\"",
            "immutable spawn-entry phase destination",
        ),
        (
            &sources.qualification,
            "Self::ResultPublished => \"state.06-result-published.json\"",
            "immutable result-publication phase destination",
        ),
        (
            &sources.qualification,
            "pub(super) attempted_phase: Option<CleanupProcessCreationProducerPhaseV1>",
            "typed attempted producer phase",
        ),
        (
            &sources.qualification,
            "io_error_kind: Some(format!(\"{:?}\", error.kind())),\n                os_code: error.raw_os_error()",
            "native producer publication error",
        ),
        (
            &sources.qualification,
            "CleanupProcessCreationPathRoleV1::FailureReceipt",
            "independent create-once producer failure receipt",
        ),
        (
            &sources.qualification,
            "pub(super) enum CleanupProcessCreationOperationV1 {",
            "typed producer publication operation",
        ),
        (
            &sources.qualification,
            ".stderr(Stdio::from(stderr))",
            "bounded producer fallback stderr sink",
        ),
        (
            &sources.qualification,
            "CleanupProcessCreationProducerPhaseV1::SpawnEntered,\n            None,",
            "cleanup producer pre-spawn phase",
        ),
        (
            &sources.launcher,
            "PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE_ACCESS",
            "pinned cleanup producer process",
        ),
        (
            &sources.launcher,
            "secondary cleanup certification failure",
            "non-masking cleanup failure diagnostic",
        ),
        (
            &sources.launcher,
            "failure.last_completed_phase != completed_phases.last().copied()",
            "producer failure transcript binding",
        ),
        (
            &sources.qualification,
            "fn cleanup_producer_fallback_diagnostic(",
            "shared bounded producer fallback",
        ),
        (
            &sources.launcher,
            "cleanup_failure.terminal_candidate = Some(Box::new(receipt));",
            "truthful completed-retirement receipt on cleanup failure",
        ),
        (
            &sources.record,
            "pub(crate) fn publish_create_once_atomically(",
            "immutable create-once receipt publisher",
        ),
        (
            &sources.record,
            "pub terminal_response_json: Option<String>",
            "durable exact terminal outbox",
        ),
        (
            &sources.launcher,
            "fn wait_for_terminal_acknowledgment(",
            "terminal outbox retained through control acknowledgment",
        ),
        (
            &sources.control,
            "WindowsLauncherRequestV1::TerminalAcknowledged {",
            "control acknowledgment after public terminal publication",
        ),
        (
            &sources.control,
            "WindowsProviderRequestV1::TerminalAcknowledged {",
            "frontend terminal acknowledgment validation",
        ),
        (
            &sources.platform,
            "if terminal_ack_required {\n                        if let Err(acknowledgment) = acknowledge_terminal_retirement(",
            "public posttarget failure acknowledgment and retirement confirmation",
        ),
        (
            &sources.launcher,
            "TargetResultPhaseV1::StandardStreams\n            | super::qualification::TargetResultPhaseV1::ProcessTree",
            "pre-process-tree cleanup certification exclusion",
        ),
        (
            &sources.process,
            "super::token::install_thread_token(target.thread.raw(), initial_thread_token)",
            "suspended nested initial-thread token installation",
        ),
        (
            &sources.token,
            "pub fn revert_entry_thread_token()",
            "earliest controlled entry-token reversion",
        ),
        (
            &sources.token,
            "pub(super) fn nested_target_tokens()",
            "common-source bounded nested token construction",
        ),
    ] {
        require_source(source, fragment, invariant)?;
    }
    require_source_order(
        &sources.qualification,
        &[
            (
                ".stderr(Stdio::from(stderr))",
                "producer fallback stderr binding",
            ),
            (
                "cleanup producer exited before ready publication: status={status} failure_receipt={} staged_failure={} fallback_stderr={}",
                "pre-ready exit diagnostic",
            ),
            (
                "cleanup_producer_fallback_diagnostic(&failure)",
                "published failure diagnostic probe",
            ),
            (
                "cleanup_producer_fallback_diagnostic(&staged_failure)",
                "staged failure diagnostic probe",
            ),
            (
                "cleanup_producer_fallback_diagnostic(&stderr_path)",
                "producer stderr diagnostic probe",
            ),
        ],
    )?;
    let zero_proof = normal_retirement
        .find("let empty = job.wait_empty(Instant::now() + Duration::from_secs(30))?;")
        .ok_or_else(|| {
            "Windows production contract omitted zero-active-process proof".to_owned()
        })?;
    let first_job_close = normal_retirement
        .find("drop(job);")
        .ok_or_else(|| "Windows production contract omitted final Job-handle closure".to_owned())?;
    if first_job_close < zero_proof {
        return Err(
            "Windows production contract closes a final Job handle before zero proof".to_owned(),
        );
    }
    require_source_order(
        normal_retirement,
        &[
            (
                "let empty = job.wait_empty(Instant::now() + Duration::from_secs(30))?;",
                "zero-active-process proof before retirement",
            ),
            (
                "wait_for_relay_retirement_proof(",
                "relay retirement acknowledgment",
            ),
            ("drop(job);", "final Job-handle closure"),
            (
                "record.complete_retirement()?;",
                "durable completed retirement",
            ),
            (
                "let receipt = build_terminal_receipt(",
                "terminal native evidence after final-handle closure",
            ),
            (
                "record.stage_terminal_response(&response)?;",
                "durable terminal outbox after retirement",
            ),
            (
                "record.acknowledge_terminal_response()?;",
                "terminal outbox retirement after publication",
            ),
        ],
    )?;
    require_source(
        &sources.supervisor,
        "return attempt_execution(crate::sealed::windows::run(",
        "sealed Windows routing without standard fallback",
    )?;
    require_source(
        &sources.platform,
        "qualification_is_advertisable(&qualification, None)",
        "native qualification before sealed advertisement",
    )?;
    require_source(
        &sources.release_config,
        "agent.binary != \"memcordon-sealed-agent\"",
        "sealed agent in Windows archive inventory",
    )?;
    for (mutant, _) in memcordon_core::WINDOWS_RELEASE_MUTANTS {
        let (source, hook) = windows_mutant_hook(mutant);
        require_source(
            sources.source(source),
            hook,
            &format!("typed production hook for {mutant}"),
        )?;
    }
    for (_, mapped_test) in memcordon_core::WINDOWS_RELEASE_MUTANTS {
        require_source(
            &sources.release_evidence,
            &format!("\"{mapped_test}\""),
            &format!("native mutant evidence mapping for {mapped_test}"),
        )?;
    }
    Ok(())
}

fn replace_windows_source_once(source: &mut String, exact: &str, replacement: &str, mutant: &str) {
    assert_eq!(
        source.matches(exact).count(),
        1,
        "{mutant} production mutation must select one exact source fragment"
    );
    *source = source.replacen(exact, replacement, 1);
}

fn replace_windows_source_once_in_region(
    source: &mut String,
    start_signature: &str,
    next_signature: &str,
    exact: &str,
    replacement: &str,
    mutant: &str,
) {
    assert_eq!(
        source
            .lines()
            .filter(|line| *line == start_signature)
            .count(),
        1,
        "{mutant} production mutation must select one exact region start"
    );
    let start_marker = format!("{start_signature}\n");
    let (prefix, after_start) = source
        .split_once(&start_marker)
        .unwrap_or_else(|| panic!("{mutant} production mutation region start is absent"));
    assert_eq!(
        after_start
            .lines()
            .filter(|line| *line == next_signature)
            .count(),
        1,
        "{mutant} production mutation must select one exact region end"
    );
    let end_marker = format!("\n{next_signature}");
    let (region, suffix) = after_start
        .split_once(&end_marker)
        .unwrap_or_else(|| panic!("{mutant} production mutation region end is absent"));
    assert_eq!(
        region.matches(exact).count(),
        1,
        "{mutant} production mutation must select one exact source fragment inside its region"
    );
    let mutated_region = region.replacen(exact, replacement, 1);
    let rebuilt = format!("{prefix}{start_marker}{mutated_region}{end_marker}{suffix}");
    assert!(
        rebuilt.starts_with(prefix) && rebuilt.ends_with(suffix),
        "{mutant} production mutation changed text outside its declared region"
    );
    *source = rebuilt;
}

type WindowsContractValidator = fn(&WindowsProductionSources) -> Result<(), String>;

#[derive(Clone, Copy)]
struct SourceRegion {
    start: &'static str,
    end: &'static str,
}

#[derive(Clone, Copy)]
struct SourceMutation {
    exact: &'static str,
    mutant: &'static str,
}

struct ControlRegionMutationHarness<'a> {
    production: &'a WindowsProductionSources,
    selected: SourceRegion,
    complementary: SourceRegion,
    validator: WindowsContractValidator,
}

impl<'a> ControlRegionMutationHarness<'a> {
    fn verified(
        production: &'a WindowsProductionSources,
        selected: SourceRegion,
        complementary: SourceRegion,
        validator: WindowsContractValidator,
    ) -> Self {
        validator(production).unwrap_or_else(|error| {
            panic!(
                "unmutated control-region contract failed for {}..{}: {error}",
                selected.start, selected.end
            )
        });
        Self {
            production,
            selected,
            complementary,
            validator,
        }
    }

    fn assert_rejected(&self, mutation: SourceMutation) {
        let complementary_before = semantic_function_region(
            &self.production.control,
            self.complementary.start,
            self.complementary.end,
        )
        .unwrap_or_else(|| {
            panic!(
                "{} complementary region is absent before mutation",
                mutation.mutant
            )
        });
        let mut mutated = self.production.clone();
        replace_windows_source_once_in_region(
            &mut mutated.control,
            self.selected.start,
            self.selected.end,
            mutation.exact,
            "/* scoped terminal protocol mutant removed */",
            mutation.mutant,
        );
        let selected_after =
            semantic_function_region(&mutated.control, self.selected.start, self.selected.end)
                .unwrap_or_else(|| {
                    panic!(
                        "{} selected region is absent after mutation",
                        mutation.mutant
                    )
                });
        assert_eq!(
            selected_after.matches(mutation.exact).count(),
            0,
            "{} did not erase its exact selected-region target",
            mutation.mutant
        );
        let complementary_after = semantic_function_region(
            &mutated.control,
            self.complementary.start,
            self.complementary.end,
        )
        .unwrap_or_else(|| {
            panic!(
                "{} complementary region is absent after mutation",
                mutation.mutant
            )
        });
        assert_eq!(
            complementary_after, complementary_before,
            "{} changed the complementary terminal protocol region",
            mutation.mutant
        );
        assert!(
            (self.validator)(&mutated).is_err(),
            "{} survived its semantic contract validator",
            mutation.mutant
        );
    }
}

#[test]
fn semantic_region_mutation_is_exact_and_preserves_identical_text_outside() {
    let source =
        "fn outside_before(\nTARGET\nfn shared_bootstrap(\nTARGET\nfn next_operation(\nTARGET\n";
    let mut mutated = source.to_owned();
    replace_windows_source_once_in_region(
        &mut mutated,
        "fn shared_bootstrap(",
        "fn next_operation(",
        "TARGET",
        "MUTATED",
        "semantic-region-exact-target",
    );
    assert_eq!(
        mutated,
        "fn outside_before(\nTARGET\nfn shared_bootstrap(\nMUTATED\nfn next_operation(\nTARGET\n"
    );

    for (region, mutant) in [
        ("", "semantic-region-zero-target"),
        ("TARGET\nTARGET\n", "semantic-region-multiple-targets"),
    ] {
        let mut invalid = format!(
            "fn outside_before(\nTARGET\nfn shared_bootstrap(\n{region}fn next_operation(\nTARGET\n"
        );
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                replace_windows_source_once_in_region(
                    &mut invalid,
                    "fn shared_bootstrap(",
                    "fn next_operation(",
                    "TARGET",
                    "MUTATED",
                    mutant,
                );
            }))
            .is_err(),
            "{mutant} must reject a non-unique target inside the declared region"
        );
    }

    let paired_lf =
        "fn replay_terminal(\nACK\nfn after_replay(\nfn relay_protocol(\nACK\nfn after_relay(\n";
    for crlf in [false, true] {
        let checkout = if crlf {
            paired_lf.replace('\n', "\r\n")
        } else {
            paired_lf.to_owned()
        };
        let normalized = normalize_windows_source(&checkout);
        for (selected_start, selected_end, other_start, other_end, mutant) in [
            (
                "fn replay_terminal(",
                "fn after_replay(",
                "fn relay_protocol(",
                "fn after_relay(",
                "semantic-region-replay-selection",
            ),
            (
                "fn relay_protocol(",
                "fn after_relay(",
                "fn replay_terminal(",
                "fn after_replay(",
                "semantic-region-live-selection",
            ),
        ] {
            let other_before = semantic_function_region(&normalized, other_start, other_end)
                .expect("paired complementary semantic region");
            let mut selected = normalized.clone();
            replace_windows_source_once_in_region(
                &mut selected,
                selected_start,
                selected_end,
                "ACK",
                "MUTATED",
                mutant,
            );
            assert_eq!(
                semantic_function_region(&selected, other_start, other_end).as_deref(),
                Some(other_before.as_str()),
                "{mutant} changed its complementary region (crlf={crlf})"
            );
        }
    }

    for (invalid, mutant) in [
        (
            "fn shared_bootstrap(\nTARGET\nfn shared_bootstrap(\nTARGET\nfn next_operation(\n",
            "semantic-region-duplicate-start",
        ),
        (
            "fn outside_before(\nTARGET\nfn next_operation(\n",
            "semantic-region-absent-start",
        ),
        (
            "fn shared_bootstrap(\nTARGET\nfn unrelated_operation(\n",
            "semantic-region-absent-end",
        ),
        (
            "fn shared_bootstrap(\nTARGET\nfn next_operation(\nfn next_operation(\n",
            "semantic-region-duplicate-end",
        ),
    ] {
        let mut invalid = invalid.to_owned();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                replace_windows_source_once_in_region(
                    &mut invalid,
                    "fn shared_bootstrap(",
                    "fn next_operation(",
                    "TARGET",
                    "MUTATED",
                    mutant,
                );
            }))
            .is_err(),
            "{mutant} must fail closed"
        );
    }
}

fn apply_windows_production_mutant(sources: &mut WindowsProductionSources, mutant: &str) {
    let (source, hook) = windows_mutant_hook(mutant);
    replace_windows_source_once(
        sources.source_mut(source),
        hook,
        "/* production mutant hook removed */",
        mutant,
    );
}

#[test]
fn windows_sddl_decoder_mutations_are_rejected() {
    let production = WindowsProductionSources::load();
    validate_windows_sddl_decoder_contract(&production.security).unwrap();

    for (exact, replacement, mutant) in [
        (
            "LocalSize(string.raw().cast())",
            "length as usize * std::mem::size_of::<u16>()",
            "sddl-local-size-proof-removed",
        ),
        (
            "unsafe { LocalFree(self.0.cast()) };\n        }\n    }\n}\n\nfn read_token_dacl(",
            "let _ = self.0;\n        }\n    }\n}\n\nfn read_token_dacl(",
            "sddl-local-free-owner-removed",
        ),
        (
            "if allocated_bytes % unit_bytes != 0 {",
            "if false {",
            "sddl-partial-wchar-allocation-admitted",
        ),
        (
            "if reported > allocation_units {",
            "if false {",
            "sddl-reported-count-allocation-check-removed",
        ),
        (
            ".checked_add(usize::from(reported < allocation_units))",
            ".checked_add(1)",
            "sddl-extra-terminator-read-unconditionally-admitted",
        ),
        (
            "for index in 0..readable_units {",
            "for index in reported.saturating_sub(1)..readable_units {",
            "sddl-first-nul-scan-replaced-by-boundary-scan",
        ),
        (
            "String::from_utf16(text)",
            "Ok(String::from_utf16_lossy(text))",
            "sddl-invalid-utf16-lossily-admitted",
        ),
    ] {
        let mut mutated = production.clone();
        replace_windows_source_once(&mut mutated.security, exact, replacement, mutant);
        assert!(
            validate_windows_sddl_decoder_contract(&mutated.security).is_err(),
            "{mutant} survived the Windows SDDL decoder contract"
        );
    }
}

#[test]
fn windows_live_kernel_access_check_mutations_are_rejected() {
    let production = WindowsProductionSources::load();
    validate_windows_live_kernel_access_check_contract(&production.security).unwrap();

    for (exact, replacement, mutant) in [
        (
            "let access_check_information = policy_information\n            | OWNER_SECURITY_INFORMATION\n            | GROUP_SECURITY_INFORMATION\n            | DACL_SECURITY_INFORMATION;",
            "let access_check_information = policy_information\n            | OWNER_SECURITY_INFORMATION\n            | DACL_SECURITY_INFORMATION;",
            "live-access-check-group-prerequisite-removed",
        ),
        (
            "let access_check_information = policy_information\n            | OWNER_SECURITY_INFORMATION\n            | GROUP_SECURITY_INFORMATION\n            | DACL_SECURITY_INFORMATION;",
            "let access_check_information = policy_information\n            | GROUP_SECURITY_INFORMATION\n            | DACL_SECURITY_INFORMATION;",
            "live-access-check-owner-prerequisite-removed",
        ),
        (
            "let access_check_information = policy_information\n            | OWNER_SECURITY_INFORMATION\n            | GROUP_SECURITY_INFORMATION\n            | DACL_SECURITY_INFORMATION;",
            "let access_check_information = policy_information\n            | OWNER_SECURITY_INFORMATION\n            | GROUP_SECURITY_INFORMATION;",
            "live-access-check-dacl-prerequisite-removed",
        ),
        (
            "GetKernelObjectSecurity(\n                handle,\n                access_check_information,\n                ptr::null_mut(),",
            "GetKernelObjectSecurity(\n                handle,\n                self.1,\n                ptr::null_mut(),",
            "live-access-check-sizing-mask-narrowed",
        ),
        (
            "GetKernelObjectSecurity(\n                handle,\n                access_check_information,\n                descriptor.as_mut_ptr().cast(),",
            "GetKernelObjectSecurity(\n                handle,\n                self.1,\n                descriptor.as_mut_ptr().cast(),",
            "live-access-check-fill-mask-narrowed",
        ),
        (
            "sizing_error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)",
            "false",
            "live-access-check-sizing-protocol-removed",
        ),
        (
            "if needed == 0 || needed > allocated_bytes {",
            "if false {",
            "live-access-check-fill-bound-removed",
        ),
        (
            "access_check_descriptor(\n            actual,",
            "access_check_descriptor(\n            self.0,",
            "expected-descriptor-access-check-surrogate-restored",
        ),
        (
            "require_live_access_check_descriptor_shape(\n            actual,\n            policy_information,\n            access_check_information,\n        )",
            "Ok(())",
            "live-descriptor-shape-proof-removed",
        ),
        (
            "self.verify_descriptor(actual, SecurityObjectKind::File)",
            "Ok(())",
            "live-descriptor-verification-removed",
        ),
        (
            "if unsafe { IsValidSecurityDescriptor(descriptor) } == 0 {",
            "if false {",
            "live-descriptor-validity-proof-removed",
        ),
        (
            "if revision != 1 || control & SE_SELF_RELATIVE == 0 {",
            "if false {",
            "live-self-relative-control-proof-removed",
        ),
        (
            "if owner.is_null() || unsafe { IsValidSid(owner) } == 0 {",
            "if false {",
            "live-owner-shape-proof-removed",
        ),
        (
            "if group.is_null() || unsafe { IsValidSid(group) } == 0 {",
            "if false {",
            "live-group-shape-proof-removed",
        ),
        (
            "if dacl_present == 0 || dacl.is_null() || unsafe { IsValidAcl(dacl) } == 0 {",
            "if false {",
            "live-dacl-shape-proof-removed",
        ),
    ] {
        let mut mutated = production.security.clone();
        replace_windows_source_once(&mut mutated, exact, replacement, mutant);
        assert!(
            validate_windows_live_kernel_access_check_contract(&mutated).is_err(),
            "live kernel-object AccessCheck mutant {mutant} survived"
        );
    }
}

#[test]
fn session_broker_source_normalization_mutations_are_rejected_for_lf_and_crlf() {
    for normalize_crlf in [false, true] {
        for (source, exact, replacement, mutant) in [
            (
                WindowsProductionSource::Token,
                "(\"SeImpersonatePrivilege\", true),\n    (\"SeSecurityPrivilege\", false),\n    (\"SeTcbPrivilege\", true),",
                "(\"SeImpersonatePrivilege\", false),\n    (\"SeSecurityPrivilege\", false),\n    (\"SeTcbPrivilege\", true),",
                "raw-source-impersonate-default-disabled",
            ),
            (
                WindowsProductionSource::Token,
                "(\"SeSecurityPrivilege\", false),\n    (\"SeTcbPrivilege\", true),\n    (\"SeChangeNotifyPrivilege\", true),\n];\nconst SESSION_BROKER_NORMALIZED_SOURCE_PRIVILEGES",
                "(\"SeSecurityPrivilege\", false),\n    (\"SeTcbPrivilege\", false),\n    (\"SeChangeNotifyPrivilege\", true),\n];\nconst SESSION_BROKER_NORMALIZED_SOURCE_PRIVILEGES",
                "raw-source-tcb-default-disabled",
            ),
            (
                WindowsProductionSource::Token,
                "const SESSION_BROKER_NORMALIZED_SOURCE_PRIVILEGES: &[(&str, bool)] = &[\n    (\"SeAssignPrimaryTokenPrivilege\", false),\n    (\"SeIncreaseQuotaPrivilege\", false),\n    (\"SeImpersonatePrivilege\", false),",
                "const SESSION_BROKER_NORMALIZED_SOURCE_PRIVILEGES: &[(&str, bool)] = &[\n    (\"SeAssignPrimaryTokenPrivilege\", false),\n    (\"SeIncreaseQuotaPrivilege\", false),\n    (\"SeImpersonatePrivilege\", true),",
                "normalized-source-impersonate-enabled",
            ),
            (
                WindowsProductionSource::Token,
                "(\"SeSecurityPrivilege\", false),\n    (\"SeTcbPrivilege\", false),\n    (\"SeChangeNotifyPrivilege\", true),\n];\n\nstruct RevertGuard;",
                "(\"SeSecurityPrivilege\", false),\n    (\"SeTcbPrivilege\", true),\n    (\"SeChangeNotifyPrivilege\", true),\n];\n\nstruct RevertGuard;",
                "normalized-source-tcb-enabled",
            ),
            (
                WindowsProductionSource::Token,
                "(\"SeTcbPrivilege\", false),\n    (\"SeChangeNotifyPrivilege\", true),\n];\n\nstruct RevertGuard;",
                "(\"SeTcbPrivilege\", false),\n    (\"SeChangeNotifyPrivilege\", false),\n];\n\nstruct RevertGuard;",
                "normalized-source-change-notify-disabled",
            ),
            (
                WindowsProductionSource::Token,
                "let source_access = TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES;",
                "let source_access = TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES | TOKEN_DUPLICATE;",
                "normalizer-source-handle-overgranted",
            ),
            (
                WindowsProductionSource::Token,
                "disable_session_broker_source_privilege(source.raw(), \"SeImpersonatePrivilege\")?;",
                "let _ = source.raw();",
                "normalizer-impersonate-disable-omitted",
            ),
            (
                WindowsProductionSource::Token,
                "disable_session_broker_source_privilege(source.raw(), \"SeTcbPrivilege\")?;",
                "let _ = source.raw();",
                "normalizer-tcb-disable-omitted",
            ),
            (
                WindowsProductionSource::Token,
                "let adjustment = TOKEN_PRIVILEGES {\n        PrivilegeCount: 1,\n        Privileges: [LUID_AND_ATTRIBUTES {\n            Luid: luid,\n            Attributes: 0,\n        }],\n    };",
                "let adjustment = TOKEN_PRIVILEGES {\n        PrivilegeCount: 1,\n        Privileges: [LUID_AND_ATTRIBUTES {\n            Luid: luid,\n            Attributes: SE_PRIVILEGE_REMOVED,\n        }],\n    };",
                "normalizer-removes-reusable-privilege",
            ),
            (
                WindowsProductionSource::Token,
                "if unsafe { GetLastError() } == ERROR_NOT_ALL_ASSIGNED {",
                "if false {",
                "normalizer-not-all-assigned-check-omitted",
            ),
            (
                WindowsProductionSource::Token,
                "if !exact_disabled_privilege_set_transition(&raw_before, &raw_after, &disabled) {",
                "if false {",
                "normalizer-aggregate-transition-proof-omitted",
            ),
            (
                WindowsProductionSource::Token,
                "if !exact_session_broker_source_snapshot_transition(&before, &after) {",
                "if false {",
                "normalizer-full-snapshot-invariance-omitted",
            ),
            (
                WindowsProductionSource::Token,
                "\"holder-derivation-tcb-only\",\n        &[\"SeTcbPrivilege\"],",
                "\"holder-derivation-tcb-only\",\n        &[\"SeTcbPrivilege\", \"SeImpersonatePrivilege\"],",
                "holder-derivation-carrier-retains-impersonate",
            ),
            (
                WindowsProductionSource::Token,
                "\"holder-launch-assign-primary-increase-quota\",\n        &[\"SeAssignPrimaryTokenPrivilege\", \"SeIncreaseQuotaPrivilege\"],",
                "\"holder-launch-assign-primary-increase-quota\",\n        &[\"SeAssignPrimaryTokenPrivilege\"],",
                "holder-launch-carrier-omits-quota",
            ),
            (
                WindowsProductionSource::Token,
                "\"remote-arm-impersonate-only\",\n        &[\"SeImpersonatePrivilege\"],",
                "\"remote-arm-impersonate-only\",\n        &[\"SeImpersonatePrivilege\", \"SeTcbPrivilege\"],",
                "remote-arm-carrier-retains-tcb",
            ),
            (
                WindowsProductionSource::Token,
                "for privilege in token_privileges_except_keep(carrier.raw(), &allowed_luids)? {",
                "for privilege in Vec::<LUID_AND_ATTRIBUTES>::new() {",
                "exact-carrier-forbidden-removal-omitted",
            ),
            (
                WindowsProductionSource::Token,
                "let entries = privilege_entries_snapshot(carrier.raw())?;",
                "return Ok(carrier);\n    let entries = privilege_entries_snapshot(carrier.raw())?;",
                "exact-carrier-returns-before-attestation",
            ),
            (
                WindowsProductionSource::Token,
                "validate_normalized_session_broker_source_snapshot(&broker_source)\n        .map_err(|error| error.to_string())?;",
                "let _ = &broker_source;",
                "holder-normalized-source-proof-omitted",
            ),
            (
                WindowsProductionSource::SessionBroker,
                "super::token::normalize_current_session_broker_source_privileges()",
                "super::token::current_service_self_attestation()",
                "startup-normalization-omitted",
            ),
            (
                WindowsProductionSource::SessionBroker,
                "validate_normalized_session_broker_source_snapshot(&hello.broker_source)",
                "validate_normalized_session_broker_source_snapshot(&launched.broker_source)",
                "launcher-hello-source-validation-omitted",
            ),
            (
                WindowsProductionSource::SessionBroker,
                "BROKER_FAILURE_SOURCE_PRIVILEGE_NORMALIZATION => {\n            Some((\"source-privilege-normalization\", None))\n        }",
                "BROKER_FAILURE_SOURCE_PRIVILEGE_NORMALIZATION => None",
                "normalization-startup-diagnostic-omitted",
            ),
        ] {
            let mut production = WindowsProductionSources::load();
            if normalize_crlf {
                production.convert_line_endings_to_crlf();
                production.normalize_line_endings();
            }
            if mutant == "launcher-hello-source-validation-omitted" {
                replace_windows_source_once_in_region(
                    production.source_mut(source),
                    "fn start_authenticated_broker(",
                    "pub(crate) fn request_loader_snaps(",
                    exact,
                    replacement,
                    mutant,
                );
            } else {
                replace_windows_source_once(
                    production.source_mut(source),
                    exact,
                    replacement,
                    mutant,
                );
            }
            assert!(
                validate_windows_session_broker_contract(&production).is_err(),
                "session-broker normalization mutant {mutant} survived (crlf={normalize_crlf})"
            );
        }

        let startup_prefix = "    let normalized_broker_source =\n        super::token::normalize_current_session_broker_source_privileges().map_err(|error| {\n            SessionBrokerServiceError::startup(\n                SessionBrokerStartupStage::SourcePrivilegeNormalization,\n                error.to_string(),\n            )\n        })?;\n";
        let protection = "    super::security::protect_current_session_broker()\n        .map_err(SessionBrokerServiceError::process_protection)?;\n";
        let mut after_protection = WindowsProductionSources::load();
        if normalize_crlf {
            after_protection.convert_line_endings_to_crlf();
            after_protection.normalize_line_endings();
        }
        replace_windows_source_once(
            &mut after_protection.session_broker,
            &format!("{startup_prefix}{protection}"),
            &format!("{protection}{startup_prefix}"),
            "normalization-after-process-protection",
        );
        assert!(
            validate_windows_session_broker_contract(&after_protection).is_err(),
            "normalization after process protection survived (crlf={normalize_crlf})"
        );

        let running = "    super::service::announce_running().map_err(|error| {\n        SessionBrokerServiceError::startup(SessionBrokerStartupStage::RunningPublication, error)\n    })?;\n";
        let mut after_running = WindowsProductionSources::load();
        if normalize_crlf {
            after_running.convert_line_endings_to_crlf();
            after_running.normalize_line_endings();
        }
        replace_windows_source_once(
            &mut after_running.session_broker,
            startup_prefix,
            "",
            "normalization-removed-before-publication",
        );
        replace_windows_source_once(
            &mut after_running.session_broker,
            running,
            &format!("{running}{startup_prefix}"),
            "normalization-moved-after-running",
        );
        assert!(
            validate_windows_session_broker_contract(&after_running).is_err(),
            "normalization after running publication survived (crlf={normalize_crlf})"
        );
    }
}

#[test]
fn windows_production_source_mutants_are_killed_by_native_contract() {
    const REQUIRED_MUTANTS: [&str; 22] = [
        "use-create-process-w",
        "create-under-service-token",
        "assign-job-after-create",
        "omit-job-list",
        "omit-handle-list",
        "permit-breakaway",
        "trust-client-token",
        "skip-target-token-readback",
        "skip-job-membership-readback",
        "resume-before-guardian",
        "resume-before-relays",
        "leak-job-handle-to-target",
        "leak-launcher-pipe",
        "accept-recursive-provider",
        "omit-guardian",
        "accept-completion-without-accounting",
        "success-before-active-zero",
        "skip-relay-ack",
        "close-job-before-evidence",
        "fall-back-to-standard",
        "omit-agent-from-archive",
        "advertise-without-certificate",
    ];

    let inventory = memcordon_core::WINDOWS_RELEASE_MUTANTS
        .iter()
        .map(|(mutant, _)| *mutant)
        .collect::<Vec<_>>();
    assert_eq!(
        inventory, REQUIRED_MUTANTS,
        "the source mutation gate must cover the exact design inventory"
    );
    let production = WindowsProductionSources::load();
    validate_windows_production_contract(&production)
        .expect("unmutated Windows production sources must satisfy the native contract");
    for mutant in REQUIRED_MUTANTS {
        let mut mutated = production.clone();
        apply_windows_production_mutant(&mut mutated, mutant);
        assert!(
            validate_windows_production_contract(&mutated).is_err(),
            "production source mutant {mutant} survived the native contract validator"
        );
    }
}

#[test]
fn windows_preauthorization_abort_terminal_mutations_are_rejected() {
    let production = WindowsProductionSources::load();
    validate_windows_preauthorization_abort_terminal_contract(&production)
        .expect("unmutated preauthorization abort contract must be complete");

    for (source, fragment, mutant) in [
        (
            "control",
            "BoundAttemptActive,",
            "active-response-commitment-erased",
        ),
        (
            "control",
            "_ => Err(failure.diagnostic()),",
            "post-commit-fallback-reenabled",
        ),
        (
            "control",
            "match replay_terminal(",
            "active-terminal-replay-erased",
        ),
        (
            "control",
            "&WindowsProviderResponseV1::AttemptRetained(retained),\n                            )",
            "active-retained-outcome-erased",
        ),
        (
            "control",
            "&WindowsProviderResponseV1::PackageCleanupResult {",
            "package-cleanup-result-erased",
        ),
        (
            "record",
            "pub terminal_disposition: Option<WindowsAttemptTerminalDispositionV1>",
            "abort-terminal-disposition-erased",
        ),
        (
            "qualification",
            "if rejection.terminal_ack_required {",
            "abort-terminal-ack-erased",
        ),
        (
            "launcher",
            "secondary terminal ACK failure",
            "launcher-primary-error-masked-by-ack",
        ),
        (
            "launcher",
            "super::record::pending_terminal_response(",
            "durable-terminal-replay-erased",
        ),
        (
            "platform",
            "secondary terminal acknowledgment failure",
            "platform-primary-error-masked-by-ack",
        ),
        (
            "platform",
            "&WindowsProviderRequestV1::ReplayTerminal {",
            "frontend-terminal-replay-erased",
        ),
        (
            "qualification",
            "impl Drop for QualificationRelayRetirement {",
            "qualification-relay-drop-retirement-erased",
        ),
        (
            "qualification",
            "qualification_control_peer_identity(pipe.raw())? != control_peer_identity",
            "qualification-replay-peer-pin-erased",
        ),
        (
            "control",
            "caller_token_sha256: caller.token_sha256.clone(),",
            "replay-token-envelope-binding-erased",
        ),
        (
            "launcher",
            "WindowsLauncherResponseV1::ReplayPending(pending)",
            "typed-replay-pending-erased",
        ),
        (
            "platform",
            "WindowsPublicFrameFailureV1::PeerClosed(WindowsPublicFramePhaseV1::Availability)",
            "availability-peer-close-classification-erased",
        ),
    ] {
        let mut mutated = production.clone();
        let selected = match source {
            "control" => &mut mutated.control,
            "record" => &mut mutated.record,
            "launcher" => &mut mutated.launcher,
            "qualification" => &mut mutated.qualification,
            "platform" => &mut mutated.platform,
            _ => unreachable!(),
        };
        replace_windows_source_once(
            selected,
            fragment,
            "/* preauthorization abort mutant removed */",
            mutant,
        );
        assert!(
            validate_windows_preauthorization_abort_terminal_contract(&mutated).is_err(),
            "preauthorization abort mutant {mutant} survived"
        );
    }

    let mut missing_abort_ack = production.clone();
    replace_windows_source_once_in_region(
        &mut missing_abort_ack.record,
        "    pub fn stage_terminal_response(",
        "    pub fn acknowledge_terminal_response(&mut self) -> Result<(), String> {",
        "                    && rejection.terminal_ack_required",
        "                    /* preauthorization abort ACK mutant removed */",
        "abort-terminal-ack-staging-erased",
    );
    assert!(
        validate_windows_preauthorization_abort_terminal_contract(&missing_abort_ack).is_err(),
        "preauthorization abort ACK staging mutant survived"
    );

    let mut premature_retirement = production.clone();
    premature_retirement.launcher = premature_retirement.launcher.replacen(
        "record.complete_preauthorization_abort()?;",
        "record.retire()?;",
        1,
    );
    assert!(
        validate_windows_preauthorization_abort_terminal_contract(&premature_retirement).is_err(),
        "premature abort-attempt retirement survived"
    );

    for source in ["control", "launcher"] {
        let mut mutated = production.clone();
        let selected = if source == "control" {
            &mut mutated.control
        } else {
            &mut mutated.launcher
        };
        let insertion = selected
            .find("let response_written =")
            .expect("connection worker response owner");
        selected.insert_str(
            insertion,
            "let _fallback = attempt_id: String::new();\n            ",
        );
        assert!(
            validate_windows_preauthorization_abort_terminal_contract(&mutated).is_err(),
            "{source} unbound worker fallback survived"
        );
    }
}

#[test]
fn windows_restricted_fixture_retained_token_mutations_are_rejected() {
    let production = WindowsProductionSources::load();
    validate_windows_production_contract(&production)
        .expect("unmutated restricted fixture must scope its retained token handle");

    for (exact, replacement, mutant) in [
        (
            "LowPart: 23,\n    HighPart: 0,",
            "LowPart: 24,\n    HighPart: 0,",
            "change-notify-luid-changed",
        ),
        (
            "let buffer = query(token, TokenPrivileges)?;\n    let entries = token_privilege_entries(buffer.as_bytes())?;",
            "let _ = LookupPrivilegeValueW(ptr::null(), ptr::null(), ptr::null_mut());\n    let buffer = query(token, TokenPrivileges)?;\n    let entries = token_privilege_entries(buffer.as_bytes())?;",
            "ambient-privilege-lookup-restored",
        ),
        (
            "fn privilege_inventory_is_change_notify_only(inventory: &[String]) -> Result<bool, String> {\n    let prefix = format!(",
            "fn privilege_inventory_is_change_notify_only(inventory: &[String]) -> Result<bool, String> {\n    let _ = LookupPrivilegeValueW(ptr::null(), ptr::null(), ptr::null_mut());\n    let prefix = format!(",
            "ambient-inventory-privilege-lookup-restored",
        ),
        (
            "        operation: impl FnOnce(HANDLE) -> Result<(), String>,\n    ) -> Result<(), String> {\n        if !self.active {",
            "        operation: impl FnOnce(HANDLE) -> Result<(), String>,\n    ) -> Result<(), String> {\n        if false {",
            "inactive-guard-check-removed",
        ),
        (
            "OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut observed)",
            "OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &raw mut observed)",
            "effective-token-open-as-self-false",
        ),
        (
            "OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut observed)",
            "OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_QUERY_SOURCE, 1, &raw mut observed)",
            "effective-token-source-query-added",
        ),
        (
            "drop(observed);\n    Ok(identity)",
            "Ok(identity)",
            "effective-token-observer-close-removed",
        ),
        (
            "== Some(ERROR_NO_TOKEN)\n    {\n        \"effective-thread-presence\"",
            "== Some(ERROR_NO_TOKEN)\n    {\n        \"effective-thread-open\"",
            "missing-thread-token-not-partitioned",
        ),
        (
            "if expected.token_id == 0 {",
            "if false {",
            "expected-token-id-check-removed",
        ),
        (
            "if observed.token_id == 0 {",
            "if false {",
            "observed-token-id-check-removed",
        ),
        (
            "if expected.token_id != observed.token_id {",
            "if false {",
            "token-id-equality-removed",
        ),
        (
            "if expected.modified_id != observed.modified_id {",
            "if false {",
            "modified-id-equality-removed",
        ),
        (
            "if expected.token_type != TokenImpersonation as u32",
            "if false",
            "token-type-check-removed",
        ),
        (
            "if expected.impersonation_level != SecurityImpersonation as u32",
            "if false",
            "impersonation-level-check-removed",
        ),
        (
            "let observed = effective_thread_token_identity()?;",
            "let observed = expected;",
            "cached-identity-substituted-for-observation",
        ),
        (
            "let observed = effective_thread_token_identity()?;",
            "let _ = token_attestation_snapshot(self.token.raw())?;\n        let observed = effective_thread_token_identity()?;",
            "post-install-full-attestation-restored",
        ),
        (
            "let observed = effective_thread_token_identity()?;",
            "let _ = token_fixture_snapshot(self.token.raw())?;\n        let observed = effective_thread_token_identity()?;",
            "post-install-fixture-reconstruction-restored",
        ),
        (
            "operation(self.token.raw())",
            "operation(current_process_token()?.raw())",
            "process-token-substituted-for-retained-token",
        ),
    ] {
        let mut mutated = production.clone();
        replace_windows_source_once(&mut mutated.token, exact, replacement, mutant);
        assert!(
            validate_windows_production_contract(&mutated).is_err(),
            "restricted fixture mutant {mutant} survived the native contract"
        );
    }
}

#[test]
fn windows_entry_thread_reversion_open_as_self_mutations_are_rejected() {
    let production = WindowsProductionSources::load();
    validate_windows_production_contract(&production)
        .expect("unmutated entry thread reversion must use process-authorized observation");

    for (exact, replacement, mutant) in [
        (
            "let Some(token) = open_thread_token(unsafe { GetCurrentThread() })? else {",
            "let mut raw = std::ptr::null_mut();\n    let _ = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_QUERY_SOURCE, 0, &raw mut raw);\n    let Some(token) = open_thread_token(unsafe { GetCurrentThread() })? else {",
            "entry-token-open-as-self-false-restored",
        ),
        (
            "// inspecting the retained token minimizes the controlled entry window.\n    if unsafe { RevertToSelf() } == 0 {",
            "// inspecting the retained token minimizes the controlled entry window.\n    if false {",
            "entry-token-revert-check-removed",
        ),
        (
            "let initial_token = token_attestation_snapshot(token.raw())?;",
            "let initial_token = token_attestation_snapshot(current_process_token()?.raw())?;",
            "entry-token-process-fallback-added",
        ),
        (
            "if thread_token_envelope(unsafe { GetCurrentThread() })?.is_some() {",
            "if false {",
            "entry-token-post-revert-absence-check-removed",
        ),
    ] {
        let mut mutated = production.clone();
        replace_windows_source_once(&mut mutated.token, exact, replacement, mutant);
        assert!(
            validate_windows_production_contract(&mutated).is_err(),
            "entry thread-token mutant {mutant} survived the native contract"
        );
    }

    let mut false_open_as_self = production.clone();
    replace_windows_source_once(
        &mut false_open_as_self.token,
        "OpenThreadToken(thread, TOKEN_QUERY | TOKEN_QUERY_SOURCE, 1, &raw mut token)",
        "OpenThreadToken(thread, TOKEN_QUERY | TOKEN_QUERY_SOURCE, 0, &raw mut token)",
        "thread-token-helper-open-as-self-false",
    );
    assert!(
        validate_windows_production_contract(&false_open_as_self).is_err(),
        "OpenAsSelf=FALSE survived the entry thread-token contract"
    );
}

#[test]
fn windows_session_broker_authority_mutations_are_rejected() {
    let production = WindowsProductionSources::load();
    validate_windows_session_broker_contract(&production)
        .expect("unmutated session-broker authority contract must be complete");
    for (source, exact, replacement, mutant) in [
        (
            WindowsProductionSource::ServiceManager,
            "service_start_argument(name, \"service name\")?;",
            "let _ = name;",
            "service-start-diagnostic-name-validation-deleted",
        ),
        (
            WindowsProductionSource::ServiceManager,
            "ServiceStatePhase::DemandStart,\n    )",
            "ServiceStatePhase::Start,\n    )",
            "argument-service-start-convergence-deleted",
        ),
        (
            WindowsProductionSource::Qualification,
            "received != expected_process_attempt_id",
            "false",
            "qualification-stream-attempt-pin-deleted",
        ),
        (
            WindowsProductionSource::Qualification,
            "returned_attempt == expected_pretarget_attempt",
            "false",
            "qualification-pretarget-reject-binding-deleted",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "BROKER_TRANSACTION_LEASE.try_lock()",
            "BROKER_TRANSACTION_LEASE.lock()",
            "broker-one-shot-serialization-deleted",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "status.dwCurrentState != SERVICE_STOPPED || status.dwProcessId != 0",
            "status.dwCurrentState != SERVICE_STOPPED",
            "broker-retirement-pid-zero-proof-deleted",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "wait_service_process_exit(",
            "wait_stopped(",
            "broker-exact-process-wait-deleted",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "!super::pipe::endpoint_exists(WINDOWS_SESSION_BROKER_PIPE)?",
            "true",
            "broker-endpoint-disappearance-proof-deleted",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "pub(crate) const BROKER_PROCESS_LAUNCHER_ACCESS: u32 = 0x0010_1000;",
            "pub(crate) const BROKER_PROCESS_LAUNCHER_ACCESS: u32 = 0x0000_1000;",
            "broker-process-synchronize-right-deleted",
        ),
        (
            WindowsProductionSource::Security,
            "SetKernelObjectSecurity(handle, PROTECTED_KERNEL_DACL_INFORMATION, self.0)",
            "SetKernelObjectSecurity(handle, self.1 | PROTECTED_DACL_SECURITY_INFORMATION, self.0)",
            "protected-kernel-dacl-selection-broadened",
        ),
        (
            WindowsProductionSource::Security,
            ".apply_dacl_to_kernel_object_detailed(token.raw())",
            ".apply_to_kernel_object_detailed(token.raw())",
            "broker-token-full-descriptor-mutation-restored",
        ),
        (
            WindowsProductionSource::Security,
            "const BROKER_TOKEN_PROTECTION_ACCESS: u32 =\n        TOKEN_QUERY | READ_CONTROL_ACCESS | WRITE_DAC_ACCESS;",
            "const BROKER_TOKEN_PROTECTION_ACCESS: u32 =\n        TOKEN_QUERY | READ_CONTROL_ACCESS | WRITE_DAC_ACCESS | WRITE_OWNER_ACCESS;",
            "broker-token-write-owner-added",
        ),
        (
            WindowsProductionSource::Token,
            ".apply_dacl_to_kernel_object_detailed(mutable.raw())",
            ".apply_to_kernel_object_detailed(mutable.raw())",
            "holder-token-full-descriptor-mutation-restored",
        ),
        (
            WindowsProductionSource::Token,
            "| WRITE_DAC_ACCESS\n        | READ_CONTROL_ACCESS;",
            "| WRITE_DAC_ACCESS\n        | READ_CONTROL_ACCESS\n        | WRITE_OWNER_ACCESS;",
            "holder-token-write-owner-added",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "const LAUNCHER_PROCESS_BROKER_ACCESS: u32 =\n    SYNCHRONIZE_ACCESS | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE;",
            "const LAUNCHER_PROCESS_BROKER_ACCESS: u32 =\n    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE;",
            "launcher-process-synchronize-right-deleted",
        ),
        (
            WindowsProductionSource::Security,
            "O:SYD:P(A;;GA;;;SY)(A;;GA;;;{launcher})(A;;0x00101040;;;{broker})",
            "O:SYD:P(A;;GA;;;SY)(A;;GA;;;{launcher})(A;;0x00001040;;;{broker})",
            "launcher-process-broker-synchronize-ace-deleted",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "pub(crate) const HOLDER_PROCESS_TRANSFER_ACCESS: u32 = 0x0010_1040;",
            "pub(crate) const HOLDER_PROCESS_TRANSFER_ACCESS: u32 = 0x0010_1041;",
            "holder-process-terminate-right-restored",
        ),
        (
            WindowsProductionSource::Security,
            "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;0x00101040;;;{launcher})",
            "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;0x00101041;;;{launcher})",
            "holder-process-terminate-ace-restored",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "pub(crate) const HOLDER_JOB_BROKER_ACCESS: u32 = 0x0000_0005;",
            "pub(crate) const HOLDER_JOB_BROKER_ACCESS: u32 = 0x0010_000d;",
            "broker-job-capability-overgranted",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "THREAD_QUERY_INFORMATION | THREAD_SET_THREAD_TOKEN;",
            "THREAD_QUERY_LIMITED_INFORMATION | THREAD_SET_THREAD_TOKEN;",
            "broker-arm-query-information-replaced-by-query-limited",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "THREAD_QUERY_INFORMATION | THREAD_SET_THREAD_TOKEN;",
            "THREAD_QUERY_INFORMATION | THREAD_SET_THREAD_TOKEN | THREAD_RESUME;",
            "broker-arm-request-resume-right-added",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS | THREAD_QUERY_LIMITED_INFORMATION;",
            "HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS;",
            "broker-arm-implied-query-limited-grant-omitted",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS | THREAD_QUERY_LIMITED_INFORMATION;",
            "HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS | THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE_ACCESS;",
            "broker-arm-canonical-grant-widened",
        ),
        (
            WindowsProductionSource::Process,
            "actual_granted_access != expected_granted_access",
            "actual_granted_access & expected_granted_access != expected_granted_access",
            "broker-arm-duplicate-exact-equality-weakened",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "actual_granted_access != expected_granted_access",
            "actual_granted_access & expected_granted_access != expected_granted_access",
            "broker-arm-open-exact-equality-weakened",
        ),
        (
            WindowsProductionSource::Process,
            "super::session_broker::HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS,\n        super::session_broker::HOLDER_THREAD_BROKER_ARM_GRANTED_ACCESS,",
            "super::session_broker::HOLDER_THREAD_BROKER_ARM_GRANTED_ACCESS,\n        super::session_broker::HOLDER_THREAD_BROKER_ARM_GRANTED_ACCESS,",
            "broker-arm-duplicate-request-uses-canonical-grant",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "OpenThread(HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS, 0, thread_id)",
            "OpenThread(HOLDER_THREAD_BROKER_ARM_GRANTED_ACCESS, 0, thread_id)",
            "broker-arm-open-requests-canonical-grant",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "THREAD_QUERY_LIMITED_INFORMATION | THREAD_RESUME;",
            "THREAD_QUERY_LIMITED_INFORMATION | THREAD_RESUME | 0x0000_0002;",
            "holder-thread-suspend-authority-restored",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "THREAD_QUERY_LIMITED_INFORMATION | THREAD_RESUME;",
            "THREAD_RESUME;",
            "holder-thread-pid-query-authority-deleted",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "THREAD_QUERY_LIMITED_INFORMATION | THREAD_RESUME;",
            "THREAD_QUERY_LIMITED_INFORMATION;",
            "holder-thread-resume-authority-deleted",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "THREAD_QUERY_LIMITED_INFORMATION | THREAD_RESUME;",
            "THREAD_QUERY_LIMITED_INFORMATION | THREAD_RESUME | SYNCHRONIZE_ACCESS;",
            "holder-thread-wait-authority-added",
        ),
        (
            WindowsProductionSource::Security,
            "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;0x00001800;;;{launcher})",
            "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;0x00001802;;;{launcher})",
            "holder-thread-suspend-ace-restored",
        ),
        (
            WindowsProductionSource::Security,
            "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;0x00001800;;;{launcher})",
            "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;0x00000802;;;{launcher})",
            "holder-thread-legacy-ace-restored",
        ),
        (
            WindowsProductionSource::Security,
            "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;0x00001800;;;{launcher})",
            "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;0x00001000;;;{launcher})",
            "holder-thread-query-ace-deleted",
        ),
        (
            WindowsProductionSource::Security,
            "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;0x00001800;;;{launcher})",
            "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;0x00000800;;;{launcher})",
            "holder-thread-resume-ace-deleted",
        ),
        (
            WindowsProductionSource::Security,
            "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;0x00001800;;;{launcher})",
            "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;0x00101800;;;{launcher})",
            "holder-thread-wait-ace-added",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "actual_thread_process_id != launched.holder_identity.process_id",
            "false",
            "holder-thread-process-association-deleted",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "connect_session_broker_pipe(",
            "connect_target_desktop_bootstrap_pipe(",
            "broker-endpoint-role-confused",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "BROKER_FAILURE_ARGUMENTS => Some((\"arguments\", None)),",
            "BROKER_FAILURE_ARGUMENTS => None,",
            "broker-argument-stage-diagnostic-deleted",
        ),
        (
            WindowsProductionSource::Pipe,
            "Self::SessionBroker => \"session-broker\"",
            "Self::SessionBroker => \"target-desktop-bootstrap\"",
            "broker-pipe-diagnostic-role-confused",
        ),
        (
            WindowsProductionSource::Process,
            "decode_protocol_handle(launcher_job_handle, \"launcher-job\")?",
            "launcher_job_handle as usize as HANDLE",
            "broker-job-handle-width-check-deleted",
        ),
        (
            WindowsProductionSource::Package,
            "if imports.machine != expected {",
            "if false {",
            "native-pe-machine-equality-deleted",
        ),
        (
            WindowsProductionSource::Process,
            "readiness_delay_millis.to_string(),",
            "String::new(),",
            "guardian-additional-argument-deleted",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "launcher_job_handle: u64,",
            "launcher_token_handle: u64,",
            "broker-request-token-transfer",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "holder_process_handle: u64,",
            "holder_token_handle: u64,",
            "broker-response-token-transfer",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "holder_thread_id: u32,",
            "holder_thread_handle: u64,",
            "broker-response-thread-handle-restored",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "pub(crate) const SESSION_BROKER_SCHEMA_VERSION: u32 = 5;",
            "pub(crate) const SESSION_BROKER_SCHEMA_VERSION: u32 = 4;",
            "broker-thread-protocol-version-not-bumped",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "if hello.schema_version != SESSION_BROKER_SCHEMA_VERSION",
            "if false",
            "broker-hello-version-rejection-deleted",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "if launched.schema_version != SESSION_BROKER_SCHEMA_VERSION",
            "if false",
            "broker-launched-version-rejection-deleted",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "if request.schema_version != SESSION_BROKER_SCHEMA_VERSION",
            "if false",
            "broker-request-version-rejection-deleted",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "launched.binding_sha256.clear();",
            "launched.binding_sha256.clear();\n    launched.holder_thread_id = 0;",
            "broker-thread-id-removed-from-launch-binding",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "holder_thread_id: holder.primary_thread_id,",
            "holder_thread_id: 1,",
            "broker-thread-id-binding-deleted",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "if launched.holder_thread_id == 0 {",
            "if false {",
            "broker-zero-thread-id-rejection-deleted",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "OpenThread(HOLDER_THREAD_LAUNCHER_ACCESS, 0, launched.holder_thread_id)",
            "OpenThread(HOLDER_THREAD_LAUNCHER_ACCESS, 1, launched.holder_thread_id)",
            "broker-local-thread-handle-made-inheritable",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "let thread = OwnedHandle::new(unsafe {\n            OpenThread(HOLDER_THREAD_LAUNCHER_ACCESS, 0, launched.holder_thread_id)\n        })?;",
            "let thread = unsafe { OpenThread(HOLDER_THREAD_LAUNCHER_ACCESS, 0, launched.holder_thread_id) };",
            "broker-local-thread-raii-deleted",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "holder.disarm();",
            "holder.terminate();",
            "broker-ownership-transfer-before-ack",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "transfer_rollback.record_process(remote_process);",
            "let _ = remote_process;",
            "broker-process-rollback-record-deleted",
        ),
        (
            WindowsProductionSource::SessionBroker,
            "transfer_rollback.disarm_after_launched_delivery();",
            "let _ = &transfer_rollback;",
            "broker-delivery-close-owner-transition-deleted",
        ),
        (
            WindowsProductionSource::Process,
            ".terminate(TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS)",
            ".contains(self.bootstrap_process.raw())",
            "holder-job-termination-replaced-with-observation",
        ),
        (
            WindowsProductionSource::Process,
            "super::token::with_session_broker_launch_privileges(|| {",
            "(|| {",
            "broker-holder-launch-privilege-scope-deleted",
        ),
        (
            WindowsProductionSource::Token,
            "|| holder_effective.behavior.token_is_restricted",
            "|| false",
            "restricted-holder-oracle-deleted",
        ),
        (
            WindowsProductionSource::ServiceManager,
            "configure_sid_type(service, ServiceSidType::Unrestricted)?;",
            "configure_sid_type(service, ServiceSidType::Restricted)?;",
            "broker-service-restricted-sid",
        ),
        (
            WindowsProductionSource::Package,
            "pub(crate) const SESSION_BROKER_PRIVILEGES: &[&str] = &[\n    \"SeAssignPrimaryTokenPrivilege\",\n    \"SeIncreaseQuotaPrivilege\",\n    \"SeImpersonatePrivilege\",\n    \"SeSecurityPrivilege\",\n    \"SeTcbPrivilege\",\n];",
            "pub(crate) const SESSION_BROKER_PRIVILEGES: &[&str] = &[\n    \"SeAssignPrimaryTokenPrivilege\",\n    \"SeIncreaseQuotaPrivilege\",\n    \"SeImpersonatePrivilege\",\n    \"SeTcbPrivilege\",\n];",
            "broker-service-security-privilege-removed",
        ),
        (
            WindowsProductionSource::Security,
            "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00000014;;;{launcher})(A;;0x00020005;;;{broker})",
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00000014;;;{launcher})(A;;0x00020005;;;{broker})",
            "broker-service-owner-group-deleted",
        ),
        (
            WindowsProductionSource::Token,
            "wide_null(\"SeRestorePrivilege\")",
            "wide_null(\"SeTakeOwnershipPrivilege\")",
            "broker-owner-restore-privilege-substituted",
        ),
        (
            WindowsProductionSource::ServiceManager,
            "super::token::with_scoped_service_owner_restore_privilege(|| {",
            "(|| {",
            "broker-owner-privilege-scope-deleted",
        ),
        (
            WindowsProductionSource::ServiceManager,
            "descriptor.apply_owner_group_dacl_to_service(service.raw())",
            "descriptor.apply_dacl_to_service(service.raw())",
            "broker-owner-group-application-deleted",
        ),
        (
            WindowsProductionSource::Package,
            "transition.session_broker_created = true;",
            "transition.session_broker_created = false;",
            "broker-registration-ownership-record-deleted",
        ),
        (
            WindowsProductionSource::Package,
            "&& !service_manager::exists(&manager, WINDOWS_SESSION_BROKER_SERVICE_NAME)?;",
            "&& true;",
            "broker-service-absence-predicate-deleted",
        ),
        (
            WindowsProductionSource::Package,
            "&& !super::pipe::endpoint_exists(WINDOWS_SESSION_BROKER_PIPE)?;",
            "&& true;",
            "broker-pipe-absence-predicate-deleted",
        ),
        (
            WindowsProductionSource::Package,
            "verify_native_session_broker_pe(&session_broker_bytes)?;",
            "let _ = &session_broker_bytes;",
            "broker-package-pe-validation-deleted",
        ),
    ] {
        let mut mutated = production.clone();
        let region = match mutant {
            "broker-one-shot-serialization-deleted"
            | "broker-endpoint-role-confused"
            | "broker-hello-version-rejection-deleted" => Some((
                "fn start_authenticated_broker(",
                "pub(crate) fn request_loader_snaps(",
            )),
            "broker-launched-version-rejection-deleted" => Some((
                "pub(crate) fn request_holder(",
                "fn retire_authenticated_broker(",
            )),
            "broker-request-version-rejection-deleted" => {
                Some(("fn validate_request(", "fn authenticate_launcher_client("))
            }
            _ => None,
        };
        if let Some((start, end)) = region {
            replace_windows_source_once_in_region(
                mutated.source_mut(source),
                start,
                end,
                exact,
                replacement,
                mutant,
            );
        } else {
            replace_windows_source_once(mutated.source_mut(source), exact, replacement, mutant);
        }
        assert!(
            validate_windows_session_broker_contract(&mutated).is_err(),
            "session-broker authority mutant {mutant} survived the source contract"
        );
    }
}

#[test]
fn shared_broker_bootstrap_and_operation_protocol_mutations_are_rejected() {
    let production = WindowsProductionSources::load();
    validate_broker_common_bootstrap_contract(&production.session_broker)
        .expect("unmutated common broker bootstrap must be complete");
    validate_holder_broker_protocol_contract(&production.session_broker)
        .expect("unmutated holder broker protocol must be complete");
    validate_loader_snaps_broker_protocol_contract(&production.session_broker)
        .expect("unmutated loader-snaps broker protocol must be complete");

    for (start, end, exact, replacement, component, mutant) in [
        (
            "fn start_authenticated_broker(",
            "pub(crate) fn request_loader_snaps(",
            "if hello.schema_version != SESSION_BROKER_SCHEMA_VERSION",
            "if false",
            "common",
            "common-hello-schema-rejection-deleted",
        ),
        (
            "fn start_authenticated_broker(",
            "pub(crate) fn request_loader_snaps(",
            "validate_normalized_session_broker_source_snapshot(&hello.broker_source)",
            "validate_normalized_session_broker_source_snapshot(&broker_source_query)",
            "common",
            "common-hello-source-validation-redirected",
        ),
        (
            "fn start_authenticated_broker(",
            "pub(crate) fn request_loader_snaps(",
            "session-broker-hello-source-to-authenticated-process",
            "unbound-broker-source",
            "common",
            "common-hello-source-binding-deleted",
        ),
        (
            "fn start_authenticated_broker(",
            "pub(crate) fn request_loader_snaps(",
            "SessionBrokerFrameV1::Hello(hello) => hello",
            "SessionBrokerFrameV1::Request(_) => return Err(operation.startup_failure(BrokerClientStartupStage::HelloRead, \"wrong-frame\"))",
            "common",
            "common-hello-first-ordering-deleted",
        ),
        (
            "pub(crate) fn request_holder(",
            "fn retire_authenticated_broker(",
            "start_authenticated_broker(BrokerClientOperation::Holder)",
            "start_authenticated_broker(BrokerClientOperation::LoaderSnaps)",
            "holder",
            "holder-common-bootstrap-delegation-deleted",
        ),
        (
            "pub(crate) fn request_loader_snaps(",
            "pub(crate) fn request_holder(",
            "start_authenticated_broker(BrokerClientOperation::LoaderSnaps)",
            "start_authenticated_broker(BrokerClientOperation::Holder)",
            "loader",
            "loader-snaps-common-bootstrap-delegation-deleted",
        ),
        (
            "unsafe fn broker_service_transaction(",
            "fn validate_loader_snaps_request(",
            "let hello = SessionBrokerHelloV1 {\n        schema_version: SESSION_BROKER_SCHEMA_VERSION,",
            "let hello = SessionBrokerHelloV1 {\n        schema_version: LOADER_SNAPS_SCHEMA_VERSION,",
            "holder",
            "server-hello-schema-construction-replaced",
        ),
        (
            "unsafe fn broker_service_transaction(",
            "fn validate_loader_snaps_request(",
            "let mut launched = SessionBrokerLaunchedV1 {\n        schema_version: SESSION_BROKER_SCHEMA_VERSION,",
            "let mut launched = SessionBrokerLaunchedV1 {\n        schema_version: LOADER_SNAPS_SCHEMA_VERSION,",
            "holder",
            "server-launched-schema-construction-replaced",
        ),
        (
            "pub(crate) fn request_holder(",
            "fn retire_authenticated_broker(",
            "let request = SessionBrokerRequestV1 {\n            schema_version: SESSION_BROKER_SCHEMA_VERSION,",
            "let request = SessionBrokerRequestV1 {\n            schema_version: LOADER_SNAPS_SCHEMA_VERSION,",
            "holder",
            "holder-request-schema-construction-replaced",
        ),
        (
            "pub(crate) fn request_loader_snaps(",
            "pub(crate) fn request_holder(",
            "schema_version: LOADER_SNAPS_SCHEMA_VERSION,",
            "schema_version: SESSION_BROKER_SCHEMA_VERSION,",
            "loader",
            "loader-snaps-request-schema-construction-replaced",
        ),
        (
            "pub(crate) fn request_loader_snaps(",
            "pub(crate) fn request_holder(",
            "request.binding_sha256 = request.calculated_sha256()",
            "request.binding_sha256.clear()",
            "loader",
            "loader-snaps-request-binding-calculation-deleted",
        ),
        (
            "fn validate_loader_snaps_request(",
            "fn run_loader_snaps_authority_transaction(",
            "if request.schema_version != LOADER_SNAPS_SCHEMA_VERSION",
            "if false",
            "loader",
            "loader-snaps-request-schema-rejection-deleted",
        ),
        (
            "impl LoaderSnapsArmedReceiptV2 {",
            "struct LoaderSnapsRestoreRequestV2 {",
            "if self.schema_version != LOADER_SNAPS_SCHEMA_VERSION",
            "if false",
            "loader",
            "loader-snaps-armed-schema-rejection-deleted",
        ),
        (
            "impl LoaderSnapsArmedReceiptV2 {",
            "struct LoaderSnapsRestoreRequestV2 {",
            "self.clone().seal()?.receipt_sha256 != self.receipt_sha256",
            "false",
            "loader",
            "loader-snaps-armed-digest-rejection-deleted",
        ),
        (
            "impl LoaderSnapsRestoredReceiptV2 {",
            "pub(crate) struct SessionBrokerLaunchedV1 {",
            "if self.schema_version != LOADER_SNAPS_SCHEMA_VERSION",
            "if false",
            "loader",
            "loader-snaps-restored-schema-rejection-deleted",
        ),
        (
            "impl LoaderSnapsRestoredReceiptV2 {",
            "pub(crate) struct SessionBrokerLaunchedV1 {",
            "self.clone().seal()?.receipt_sha256 != self.receipt_sha256",
            "false",
            "loader",
            "loader-snaps-restored-digest-rejection-deleted",
        ),
    ] {
        let mut mutated = production.session_broker.clone();
        replace_windows_source_once_in_region(&mut mutated, start, end, exact, replacement, mutant);
        let result = match component {
            "common" => validate_broker_common_bootstrap_contract(&mutated),
            "holder" => validate_holder_broker_protocol_contract(&mutated),
            "loader" => validate_loader_snaps_broker_protocol_contract(&mutated),
            _ => panic!("unknown broker contract component {component}"),
        };
        assert!(
            result.is_err(),
            "broker protocol mutant {mutant} survived its {component} semantic contract"
        );
    }
}

#[test]
fn protected_user_object_creation_authority_mutations_are_rejected_for_lf_and_crlf() {
    for normalize_crlf in [false, true] {
        for (source, exact, replacement, mutant) in [
            (
                WindowsProductionSource::Package,
                "pub(crate) const SESSION_BROKER_PRIVILEGES: &[&str] = &[\n    \"SeAssignPrimaryTokenPrivilege\",\n    \"SeIncreaseQuotaPrivilege\",\n    \"SeImpersonatePrivilege\",\n    \"SeSecurityPrivilege\",\n    \"SeTcbPrivilege\",\n];",
                "pub(crate) const SESSION_BROKER_PRIVILEGES: &[&str] = &[\n    \"SeAssignPrimaryTokenPrivilege\",\n    \"SeIncreaseQuotaPrivilege\",\n    \"SeSecurityPrivilege\",\n    \"SeTcbPrivilege\",\n];",
                "broker-impersonate-privilege-omitted",
            ),
            (
                WindowsProductionSource::Security,
                "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;0x00020018;;;SY)(A;;0x00020018;;;{broker})",
                "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;0x0002001a;;;SY)(A;;0x0002001a;;;{broker})",
                "creation-carrier-duplicate-right-added",
            ),
            (
                WindowsProductionSource::Security,
                "(A;;0x00001800;;;{launcher})(A;;0x000000c0;;;{broker})",
                "(A;;0x00001800;;;{launcher})(A;;0x000000c2;;;{broker})",
                "broker-arm-thread-rights-widened",
            ),
            (
                WindowsProductionSource::Token,
                "token_privileges_except_keep(mutable.raw(), &[security])?",
                "token_privileges_except_keep(mutable.raw(), &[security, privilege_luid(\"SeTcbPrivilege\")?])?",
                "creation-carrier-retains-tcb",
            ),
            (
                WindowsProductionSource::Token,
                "token_privileges_except_change_notify(mutable.raw())?",
                "token_privileges_except_keep(mutable.raw(), &[privilege_luid(\"SeSecurityPrivilege\")?])?",
                "holder-primary-retains-security",
            ),
            (
                WindowsProductionSource::Token,
                "if station_creation_evidence.instance.token_id\n            == desktop_creation_evidence.instance.token_id",
                "if false",
                "creation-carrier-token-id-reuse-check-deleted",
            ),
            (
                WindowsProductionSource::Token,
                "validate_normalized_session_broker_source_snapshot(&broker_source)\n        .map_err(|error| error.to_string())?;",
                "let _ = &broker_source;",
                "broker-normalized-source-proof-deleted",
            ),
            (
                WindowsProductionSource::Token,
                "if unsafe { SetThreadToken(&raw mut thread, carrier) } == 0 {",
                "if false {",
                "remote-set-thread-token-deleted",
            ),
            (
                WindowsProductionSource::Token,
                "if unsafe { RevertToSelf() } == 0 {\n        return Err(format!(\n            \"creator RevertToSelf failed: {}\"",
                "if false {\n        return Err(format!(\n            \"creator RevertToSelf failed: {}\"",
                "holder-creator-reversion-deleted",
            ),
            (
                WindowsProductionSource::SessionBroker,
                "super::token::require_thread_token_absent(thread.raw())?;\n                let (carrier, expected_evidence)",
                "let (carrier, expected_evidence)",
                "broker-pre-arm-absence-proof-deleted",
            ),
            (
                WindowsProductionSource::SessionBroker,
                "if &attached != expected_evidence {",
                "if false {",
                "attached-carrier-token-id-readback-deleted",
            ),
            (
                WindowsProductionSource::SessionBroker,
                "super::token::require_thread_token_absent(thread.raw())?;\n                completed = ordinal;",
                "completed = ordinal;",
                "broker-post-revert-absence-proof-deleted",
            ),
            (
                WindowsProductionSource::SessionBroker,
                "&& (completed == 2 || failed) =>",
                "&& (completed >= 1 || failed) =>",
                "broker-disarms-before-two-clearances",
            ),
            (
                WindowsProductionSource::SessionBroker,
                "carrier: super::token::TokenAttestationSnapshot,",
                "carrier_handle: u64,",
                "creation-token-handle-serialized",
            ),
            (
                WindowsProductionSource::Process,
                "let station_carrier_guard = request_creator_arm(",
                "let station_carrier_guard = consume_creator_arm(",
                "station-create-moved-outside-armed-region",
            ),
            (
                WindowsProductionSource::Process,
                "let carrier_guard = request_creator_arm(",
                "let carrier_guard = consume_creator_arm(",
                "desktop-create-moved-outside-armed-region",
            ),
            (
                WindowsProductionSource::Process,
                "station_carrier_guard.revert()",
                "drop(station_carrier_guard)",
                "station-immediate-reversion-deleted",
            ),
            (
                WindowsProductionSource::Process,
                "if let Err(error) = carrier_guard.revert() {",
                "if let Err(error) = drop(carrier_guard) {",
                "desktop-immediate-reversion-deleted",
            ),
            (
                WindowsProductionSource::Process,
                "pending == Some((phase, ordinal, thread_id))",
                "true",
                "launcher-phase-replay-tuple-check-deleted",
            ),
        ] {
            let mut production = WindowsProductionSources::load();
            if normalize_crlf {
                production.convert_line_endings_to_crlf();
                production.normalize_line_endings();
            }
            replace_windows_source_once(production.source_mut(source), exact, replacement, mutant);
            assert!(
                validate_windows_production_contract(&production).is_err(),
                "protected USER-object authority mutant {mutant} survived (crlf={normalize_crlf})"
            );
        }
    }
}

#[test]
fn nested_native_object_policy_mutations_are_rejected() {
    let production = WindowsProductionSources::load();
    validate_windows_production_contract(&production)
        .expect("unmutated nested native-object policies must satisfy the contract");

    for (source, exact, mutant) in [
        (
            "main",
            "windows::token::revert_entry_thread_token()",
            "nested entry token not reverted",
        ),
        (
            "token",
            "pub(super) fn nested_target_tokens()",
            "nested token factory omitted",
        ),
        (
            "process",
            "super::token::install_thread_token(target.thread.raw(), initial_thread_token)",
            "nested initial token not installed while suspended",
        ),
        (
            "qualification",
            "super::token::nested_target_tokens()",
            "nested token siblings not constructed",
        ),
        (
            "token",
            "OpenThreadToken(thread, TOKEN_QUERY | TOKEN_QUERY_SOURCE, 1, &raw mut token)",
            "nested token readback does not use process authorization",
        ),
        (
            "process",
            "requested_before_install.instance != installed.observed_thread.instance",
            "nested installed token identity not compared",
        ),
        (
            "process",
            "requested_before_install.behavior != installed.observed_thread.behavior",
            "nested installed token behavior not compared fail closed",
        ),
        (
            "token",
            "if behavior.envelope.impersonation_level != SecurityImpersonation as u32 {",
            "nested identification-level token accepted",
        ),
        (
            "token",
            "if !behavior.token_is_restricted",
            "nested unrestricted token accepted",
        ),
        (
            "token",
            "failures.push(\"restricting_sids_empty\")",
            "nested empty restriction inventory accepted",
        ),
        (
            "token",
            "actual_restricting_sids != expected_restricting_sids",
            "nested canonical restriction inventory not validated",
        ),
        (
            "qualification",
            "receipt.initial_thread_token_id != expected_initial_thread_token_id",
            "nested child initial token identity not compared",
        ),
        (
            "qualification",
            "receipt.process_token_id != suspended_process_token_id",
            "nested child permanent token identity not compared",
        ),
        (
            "launcher",
            "super::process::compare_remote_handle_object(target.handle(), raw, raw)",
            "suspended target excluded-handle identity not compared",
        ),
    ] {
        let mut mutated = production.clone();
        let selected = match source {
            "main" => &mut mutated.main,
            "token" => &mut mutated.token,
            "process" => &mut mutated.process,
            "qualification" => &mut mutated.qualification,
            "launcher" => &mut mutated.launcher,
            _ => unreachable!(),
        };
        replace_windows_source_once(selected, exact, "/* nested token mutant removed */", mutant);
        assert!(
            validate_windows_production_contract(&mutated).is_err(),
            "{mutant} survived the native contract validator"
        );
    }

    let mut unrestricted_initial = production.clone();
    replace_windows_source_once(
        &mut unrestricted_initial.token,
        "let same_access_primary = restricted_same_access_primary(initial_primary.raw())?;",
        "let same_access_primary = initial_primary;",
        "old unrestricted nested initial token restored",
    );
    assert!(
        validate_windows_production_contract(&unrestricted_initial).is_err(),
        "old unrestricted nested initial token survived the native contract validator"
    );

    const PROCESS_POLICY: &str = "O:{creator}D:P(A;;GA;;;SY)(A;;GA;;;{creator})(A;;GA;;;WR)";
    for (replacement, mutant) in [
        (
            "O:{creator}D:P(A;;GA;;;{creator})(A;;GA;;;WR)",
            "nested process policy without SYSTEM",
        ),
        (
            "O:{creator}D:P(A;;GA;;;SY)(A;;GA;;;WR)",
            "nested process policy without creator",
        ),
        (
            "O:{creator}D:P(A;;GA;;;SY)(A;;GA;;;{creator})",
            "nested process policy without Write Restricted Code",
        ),
        (
            "O:{creator}D:P(A;;GA;;;SY)(A;;GA;;;{creator})(A;;GA;;;LS)",
            "nested process policy with launcher authority",
        ),
        (
            "O:{creator}D:P(A;;GA;;;SY)(A;;GA;;;{creator})(A;;GA;;;RC)",
            "nested process policy with stale Restricted Code",
        ),
    ] {
        let mut mutated = production.clone();
        replace_windows_source_once(&mut mutated.security, PROCESS_POLICY, replacement, mutant);
        assert!(
            validate_windows_production_contract(&mutated).is_err(),
            "{mutant} survived the native contract validator"
        );
    }

    for (exact, mutant) in [
        (
            "super::security::nested_canary_process_sddl()?",
            "nested Job policy reused for process",
        ),
        (
            "super::security::nested_canary_thread_sddl()?",
            "nested Job policy reused for thread",
        ),
    ] {
        let mut mutated = production.clone();
        replace_windows_source_once(
            &mut mutated.process,
            exact,
            "super::security::nested_canary_job_sddl()?",
            mutant,
        );
        assert!(
            validate_windows_production_contract(&mutated).is_err(),
            "{mutant} survived the native contract validator"
        );
    }
}

#[test]
fn target_desktop_bootstrap_authority_mutations_are_rejected() {
    let production = WindowsProductionSources::load();
    validate_windows_production_contract(&production)
        .expect("unmutated target desktop bootstrap must satisfy the native contract");

    let mut widened_foreign_query = production.clone();
    replace_windows_source_once(
        &mut widened_foreign_query.token,
        "const PROCESS_TOKEN_QUERY_ACCESS: u32 = TOKEN_QUERY;",
        "const PROCESS_TOKEN_QUERY_ACCESS: u32 = TOKEN_QUERY | TOKEN_QUERY_SOURCE;",
        "foreign-process-query-widened-to-token-source",
    );
    assert!(
        validate_windows_production_contract(&widened_foreign_query).is_err(),
        "source-capable foreign process-token open survived the native contract"
    );

    let mut collapsed_query_evidence = production.clone();
    replace_windows_source_once(
        &mut collapsed_query_evidence.token,
        "pub(crate) struct TokenQueryAttestationSnapshot {",
        "pub(crate) struct TokenAttestationSnapshotCollapsed {",
        "query-and-source-evidence-types-collapsed",
    );
    assert!(
        validate_windows_production_contract(&collapsed_query_evidence).is_err(),
        "collapsed query/source evidence types survived the native contract"
    );

    for (exact, replacement, mutant) in [
        (
            "            \"await-started\",\n            binding,",
            "            \"after-started\",\n            binding,",
            "pre-started-failure-state-masked",
        ),
        (
            "        binding == *expected_binding,",
            "        true,",
            "bootstrap-failure-binding-check-removed",
        ),
        (
            "state={state} phase={} native_code={native_code:?} detail={detail}",
            "phase={} detail={detail}",
            "bootstrap-failure-state-and-native-evidence-dropped",
        ),
    ] {
        let mut mutated = production.clone();
        replace_windows_source_once(&mut mutated.process, exact, replacement, mutant);
        assert!(
            validate_windows_production_contract(&mutated).is_err(),
            "{mutant} survived the target desktop relay contract"
        );
    }

    for (source, exact, replacement, mutant) in [
        (
            WindowsProductionSource::Process,
            "        TargetDesktopBootstrapRoleV1::LoaderControl => {\n            super::token::current_process_token_for_attestation_and_access_check()\n        }",
            "        TargetDesktopBootstrapRoleV1::LoaderControl => {\n            super::token::current_process_token_for_access_check()\n        }",
            "loader-control-local-source-attestation-capability-removed",
        ),
        (
            WindowsProductionSource::Process,
            "        TargetDesktopBootstrapRoleV1::Probe => {\n            super::token::current_process_token_for_attestation_and_access_check()\n        }",
            "        TargetDesktopBootstrapRoleV1::Probe => {\n            super::token::current_process_token_for_access_check()\n        }",
            "probe-local-source-attestation-capability-removed",
        ),
        (
            WindowsProductionSource::Process,
            "        TargetDesktopBootstrapRoleV1::Holder => {\n            super::token::current_process_token_for_access_check()\n        }",
            "        TargetDesktopBootstrapRoleV1::Holder => {\n            super::token::current_process_token_for_attestation_and_access_check()\n        }",
            "holder-local-capability-unnecessarily-widened",
        ),
        (
            WindowsProductionSource::Process,
            "(TargetDesktopBootstrapRoleV1::Holder, Some(handle)) => Some(handle)",
            "(TargetDesktopBootstrapRoleV1::Holder, None) => None",
            "holder-target-capability-omitted",
        ),
        (
            WindowsProductionSource::Process,
            "(TargetDesktopBootstrapRoleV1::Probe, None) => None",
            "(TargetDesktopBootstrapRoleV1::Probe, Some(handle)) => Some(handle)",
            "probe-target-capability-injected",
        ),
        (
            WindowsProductionSource::Token,
            "TOKEN_ATTESTATION_ACCESS | TOKEN_DUPLICATE,\n        \"source-attestation-and-access-check\",",
            "TOKEN_QUERY | TOKEN_DUPLICATE,\n        \"source-attestation-and-access-check\",",
            "combined-local-capability-query-source-removed",
        ),
        (
            WindowsProductionSource::Token,
            "TOKEN_ATTESTATION_ACCESS | TOKEN_DUPLICATE,\n        \"source-attestation-and-access-check\",",
            "TOKEN_ATTESTATION_ACCESS,\n        \"source-attestation-and-access-check\",",
            "combined-local-capability-duplicate-removed",
        ),
        (
            WindowsProductionSource::Token,
            "if granted != access {",
            "if granted & access != access {",
            "local-capability-subset-granted-access-accepted",
        ),
        (
            WindowsProductionSource::Process,
            "    bytes_transferred == 0",
            "    true",
            "partial-started-publication-appends-failure-frame",
        ),
        (
            WindowsProductionSource::Pipe,
            "Err(error) => return Err(error.with_bytes_transferred(offset))",
            "Err(error) => return Err(error)",
            "partial-frame-byte-accounting-removed",
        ),
        (
            WindowsProductionSource::Process,
            "    thread_id != 0\n        && matches!(",
            "    matches!(",
            "zero-creator-tid-admitted",
        ),
    ] {
        let mut mutated = production.clone();
        replace_windows_source_once(mutated.source_mut(source), exact, replacement, mutant);
        assert!(
            validate_windows_production_contract(&mutated).is_err(),
            "{mutant} survived the target desktop role-capability contract"
        );
    }

    for (source, exact, replacement, mutant) in [
        (
            WindowsProductionSource::Process,
            "super::token::require_same_token_instance(\n                \"target-request-to-holder-capability\",",
            "super::token::require_assigned_token_authority(\n                \"target-request-to-holder-capability\",",
            "holder-request-capability-instance-check-weakened",
        ),
        (
            WindowsProductionSource::Process,
            "super::token::require_assigned_token_authority(\n                \"target-request-to-probe-self\",",
            "super::token::require_assigned_process_authority(\n                \"target-request-to-probe-self\",",
            "probe-full-source-assignment-replaced-with-query-relation",
        ),
        (
            WindowsProductionSource::Process,
            "target_snapshot.query_evidence() == binding.bootstrap_process_snapshot",
            "binding.target_request_snapshot == target_snapshot",
            "probe-request-process-instance-equality-restored",
        ),
        (
            WindowsProductionSource::Process,
            "target_snapshot.query_evidence() == binding.bootstrap_process_snapshot",
            "binding.target_envelope == target_snapshot.behavior.envelope",
            "probe-target-envelope-only-accepted",
        ),
        (
            WindowsProductionSource::Process,
            "target_snapshot.query_evidence() == binding.bootstrap_process_snapshot",
            "true",
            "probe-role-local-bootstrap-anchor-removed",
        ),
        (
            WindowsProductionSource::Process,
            "target_assignment == binding.bootstrap_assignment",
            "true",
            "bootstrap-assignment-sealed-evidence-check-removed",
        ),
        (
            WindowsProductionSource::Process,
            "let target_binding_matches = match binding.role {",
            "let target_binding_matches = match TargetDesktopBootstrapRoleV1::Holder {",
            "holder-probe-token-role-arms-collapsed",
        ),
        (
            WindowsProductionSource::Process,
            "        || !target_binding_matches",
            "        || binding.target_request_snapshot != target_snapshot",
            "role-specific-target-validation-collapsed",
        ),
        (
            WindowsProductionSource::Token,
            "let differences = token_attestation_difference_fields(source, assigned, false);",
            "let differences = token_attestation_difference_fields(source, assigned, true);",
            "full-source-assignment-requires-same-token-id",
        ),
    ] {
        let mut mutated = production.clone();
        replace_windows_source_once(mutated.source_mut(source), exact, replacement, mutant);
        assert!(
            validate_windows_production_contract(&mutated).is_err(),
            "{mutant} survived the target desktop role-binding contract"
        );
    }

    const PRIVATE_STATION_CREATE: &str =
        "    let private_window_station = unsafe {\n        CreateWindowStationW(";
    for (injected, mutant) in [
        (
            "    let _ = unsafe { GetProcessWindowStation() };\n",
            "ambient-process-station-observation-before-private-create",
        ),
        (
            "    let _ = unsafe { GetThreadDesktop(GetCurrentThreadId()) };\n",
            "ambient-thread-desktop-observation-before-private-create",
        ),
        (
            "    if source_station_name.eq_ignore_ascii_case(\"WinSta0\") {\n        return Err(TargetDesktopBootstrapFailure::contract(\n            TargetDesktopBootstrapPhaseV1::UserBindingAttestation,\n            \"target-session holder source station is interactive\",\n        ));\n    }\n",
            "transient-interactive-source-rejection-restored",
        ),
        (
            "    let _ = desktop_receives_input(source_desktop);\n",
            "transient-source-input-state-rejection-restored",
        ),
    ] {
        let mut mutated = production.clone();
        let replacement = format!("{injected}{PRIVATE_STATION_CREATE}");
        replace_windows_source_once(
            &mut mutated.process,
            PRIVATE_STATION_CREATE,
            &replacement,
            mutant,
        );
        assert!(
            validate_windows_production_contract(&mutated).is_err(),
            "{mutant} survived the target desktop bootstrap contract"
        );
    }

    for (source, exact, replacement, mutant) in [
        (
            WindowsProductionSource::Process,
            "launch_target_desktop_probe(\n            token,",
            "Ok::<(), TargetDesktopLeaseCreateError>(())?;\n        let _ = (token,",
            "restricted-runtime-probe-omitted",
        ),
        (
            WindowsProductionSource::Security,
            "            \"S-1-5-18\".to_owned(),\n            self.holder_restricting_sid.clone(),\n            self.target_logon_sid.clone(),",
            "            self.holder_restricting_sid.clone(),\n            self.target_logon_sid.clone(),",
            "holder-ordinary-trustee-omitted",
        ),
        (
            WindowsProductionSource::Security,
            "            \"S-1-5-18\".to_owned(),\n            self.holder_restricting_sid.clone(),\n            self.target_logon_sid.clone(),",
            "            \"S-1-5-18\".to_owned(),\n            self.target_logon_sid.clone(),",
            "holder-restricting-trustee-omitted",
        ),
        (
            WindowsProductionSource::Security,
            "            \"S-1-5-18\".to_owned(),\n            self.holder_restricting_sid.clone(),\n            self.target_logon_sid.clone(),",
            "            \"S-1-5-18\".to_owned(),\n            self.holder_restricting_sid.clone(),",
            "target-ordinary-trustee-omitted",
        ),
        (
            WindowsProductionSource::Security,
            "trustees.extend(restricting_sids.iter().cloned());",
            "let _ = restricting_sids;",
            "target-restricting-trustees-omitted",
        ),
        (
            WindowsProductionSource::Security,
            "if token_is_restricted != !restricting_sids.is_empty() {",
            "if false {",
            "target-is-restricted-inventory-contradiction-accepted",
        ),
        (
            WindowsProductionSource::Security,
            "if write_restricted != has_write_restricted_sid {",
            "if false {",
            "target-write-restricted-oracle-contradiction-accepted",
        ),
        (
            WindowsProductionSource::Security,
            "|| snapshot_before.behavior.restricting_sids != restricting.evidence",
            "|| false",
            "target-restricting-inventory-not-snapshot-bound",
        ),
        (
            WindowsProductionSource::Security,
            "sddl.push_str(&format!(\"S:P(ML;;NW;;;{})\", self.target_integrity_sid));",
            "let _ = &self.target_integrity_sid;",
            "target-integrity-label-omitted",
        ),
        (
            WindowsProductionSource::Security,
            "sddl.push_str(&format!(\"S:P(ML;;NW;;;{})\", self.target_integrity_sid));",
            "sddl.push_str(&format!(\"S:(ML;;NW;;;{})\", self.target_integrity_sid));",
            "target-integrity-sacl-protection-omitted",
        ),
        (
            WindowsProductionSource::Security,
            "sddl.push_str(&format!(\"S:P(ML;;NW;;;{})\", self.target_integrity_sid));",
            "sddl.push_str(&format!(\"S:P(ML;;NR;;;{})\", self.target_integrity_sid));",
            "target-integrity-no-write-up-policy-changed",
        ),
        (
            WindowsProductionSource::Security,
            "sddl.push_str(&format!(\"S:P(ML;;NW;;;{})\", self.target_integrity_sid));",
            "sddl.push_str(\"S:P(ML;;NW;;;HI)\");",
            "target-integrity-sid-not-token-bound",
        ),
        (
            WindowsProductionSource::Security,
            "sddl.push_str(&format!(\"S:P(ML;;NW;;;{})\", self.target_integrity_sid));",
            "sddl.push_str(&format!(\"S:P(ML;OI;NW;;;{})\", self.target_integrity_sid));",
            "target-integrity-label-made-inheritable",
        ),
        (
            WindowsProductionSource::Security,
            "sddl.contains(\"(ML;\")",
            "sddl.contains(\"S:(ML\")",
            "protected-mandatory-label-selection-omitted",
        ),
        (
            WindowsProductionSource::Security,
            "source_control & SE_SACL_PRESENT_CONTROL != 0",
            "false",
            "creator-mandatory-label-sacl-presence-ignored",
        ),
        (
            WindowsProductionSource::Security,
            "source_control & SE_SACL_PROTECTED_CONTROL != 0",
            "false",
            "creator-mandatory-label-sacl-protection-ignored",
        ),
        (
            WindowsProductionSource::Security,
            "source_control & SE_SACL_AUTO_INHERIT_REQ_CONTROL != 0",
            "false",
            "creator-mandatory-label-sacl-auto-inherit-request-accepted",
        ),
        (
            WindowsProductionSource::Security,
            "source_control & SE_SACL_AUTO_INHERITED_CONTROL != 0",
            "false",
            "creator-mandatory-label-sacl-auto-inherited-accepted",
        ),
        (
            WindowsProductionSource::Security,
            "absolute_control & SE_SACL_PRESENT_CONTROL != 0",
            "false",
            "absolute-mandatory-label-sacl-presence-ignored",
        ),
        (
            WindowsProductionSource::Security,
            "absolute_control & SE_SACL_PROTECTED_CONTROL != 0",
            "false",
            "absolute-mandatory-label-sacl-protection-ignored",
        ),
        (
            WindowsProductionSource::Security,
            "absolute_control & SE_SACL_AUTO_INHERIT_REQ_CONTROL != 0",
            "false",
            "absolute-mandatory-label-sacl-auto-inherit-request-accepted",
        ),
        (
            WindowsProductionSource::Security,
            "absolute_control & SE_SACL_AUTO_INHERITED_CONTROL != 0",
            "false",
            "absolute-mandatory-label-sacl-auto-inherited-accepted",
        ),
        (
            WindowsProductionSource::Security,
            "if kind != SecurityObjectKind::Desktop {",
            "if false {",
            "resultant-sacl-ai-accepted-for-every-object-kind",
        ),
        (
            WindowsProductionSource::Security,
            "expected_control & SE_SACL_PROTECTED_CONTROL != 0",
            "true",
            "resultant-sacl-ai-accepts-unprotected-expected-policy",
        ),
        (
            WindowsProductionSource::Security,
            "expected_control & SE_SACL_AUTO_INHERIT_REQ_CONTROL != 0",
            "false",
            "resultant-sacl-ai-accepts-expected-auto-inherit-request",
        ),
        (
            WindowsProductionSource::Security,
            "expected_control & SE_SACL_AUTO_INHERITED_CONTROL != 0",
            "false",
            "resultant-sacl-ai-accepts-auto-inherited-creator-policy",
        ),
        (
            WindowsProductionSource::Security,
            "actual_control & SE_SACL_PROTECTED_CONTROL != 0",
            "true",
            "resultant-sacl-ai-accepts-unprotected-readback",
        ),
        (
            WindowsProductionSource::Security,
            "actual_control & SE_SACL_AUTO_INHERIT_REQ_CONTROL != 0",
            "false",
            "resultant-sacl-ai-accepts-auto-inherit-request",
        ),
        (
            WindowsProductionSource::Security,
            "(expected_control ^ actual_control) == SE_SACL_AUTO_INHERITED_CONTROL",
            "(expected_control ^ actual_control) & SE_SACL_AUTO_INHERITED_CONTROL != 0",
            "resultant-sacl-ai-accepts-additional-control-drift",
        ),
        (
            WindowsProductionSource::Security,
            "let actual = if kind == SecurityObjectKind::Desktop {",
            "let actual = if matches!(kind, SecurityObjectKind::WindowStation | SecurityObjectKind::Desktop) {",
            "window-station-gains-desktop-sacl-ai-exception",
        ),
        (
            WindowsProductionSource::Security,
            "if actual == expected {",
            "if true {",
            "resultant-desktop-policy-content-comparison-skipped",
        ),
        (
            WindowsProductionSource::Security,
            "SetSecurityDescriptorControl(\n            normalized.as_mut_ptr().cast(),\n            SE_SACL_AUTO_INHERITED_CONTROL,\n            0,\n        )",
            "SetSecurityDescriptorControl(\n            normalized.as_mut_ptr().cast(),\n            u16::MAX,\n            0,\n        )",
            "resultant-desktop-normalizes-broad-control-state",
        ),
        (
            WindowsProductionSource::Token,
            "if source.instance.modified_id != process.instance.modified_id {",
            "if false {",
            "assigned-process-modified-id-change-accepted",
        ),
        (
            WindowsProductionSource::Token,
            "if source.lineage.authentication_id != process.lineage.authentication_id {",
            "if false {",
            "assigned-process-authentication-id-change-accepted",
        ),
        (
            WindowsProductionSource::Token,
            "if source.lineage.originating_logon_session != process.lineage.originating_logon_session",
            "if false",
            "assigned-process-token-origin-change-accepted",
        ),
        (
            WindowsProductionSource::Token,
            "if source.lineage.source_name != process.lineage.source_name {",
            "if false {",
            "assigned-token-source-name-change-accepted",
        ),
        (
            WindowsProductionSource::Token,
            "if source.lineage.source_identifier != process.lineage.source_identifier {",
            "if false {",
            "assigned-token-source-identifier-change-accepted",
        ),
        (
            WindowsProductionSource::Token,
            "if source.lineage.session_id != process.lineage.session_id {",
            "if false {",
            "assigned-token-session-change-accepted",
        ),
        (
            WindowsProductionSource::Token,
            "if source.behavior.groups != process.behavior.groups {",
            "if false {",
            "assigned-token-group-inventory-change-accepted",
        ),
        (
            WindowsProductionSource::Token,
            "if source.behavior.privileges != process.behavior.privileges {",
            "if false {",
            "assigned-token-privilege-inventory-change-accepted",
        ),
        (
            WindowsProductionSource::Token,
            "if source.behavior.restricting_sids != process.behavior.restricting_sids {",
            "if false {",
            "assigned-token-restricting-sid-change-accepted",
        ),
        (
            WindowsProductionSource::Token,
            "if source.behavior.token_is_restricted != process.behavior.token_is_restricted {",
            "if false {",
            "assigned-token-restriction-state-change-accepted",
        ),
        (
            WindowsProductionSource::Token,
            "if source.behavior.default_dacl_sha256 != process.behavior.default_dacl_sha256 {",
            "if false {",
            "assigned-process-default-dacl-change-accepted",
        ),
        (
            WindowsProductionSource::Token,
            "if granted != PROCESS_TOKEN_QUERY_ACCESS {",
            "if false {",
            "process-token-granted-access-proof-bypassed",
        ),
        (
            WindowsProductionSource::Process,
            "bootstrap_process_snapshot: observed_holder_snapshot.clone(),",
            "bootstrap_process_snapshot: holder_launch_snapshot.clone(),",
            "holder-binding-copies-launch-snapshot",
        ),
        (
            WindowsProductionSource::Process,
            "bootstrap_process_snapshot: observed_probe_snapshot.clone(),",
            "bootstrap_process_snapshot: target_snapshot.clone(),",
            "probe-binding-copies-request-snapshot",
        ),
        (
            WindowsProductionSource::Process,
            "role: TargetDesktopBootstrapRoleV1::Holder,\n            target_user_object_policy_role: policy_role,",
            "role: TargetDesktopBootstrapRoleV1::Holder,\n            target_user_object_policy_role: super::security::TargetUserObjectPolicyRoleV1::DirectTarget,",
            "holder-user-object-policy-role-not-bound",
        ),
        (
            WindowsProductionSource::Process,
            "startup.StartupInfo.lpDesktop = empty_desktop.as_mut_ptr();",
            "startup.StartupInfo.lpDesktop = ptr::null_mut();",
            "holder-lacks-target-session-default-desktop-selection",
        ),
        (
            WindowsProductionSource::Process,
            "startup.StartupInfo.lpDesktop = startup_desktop.as_mut_ptr();",
            "startup.StartupInfo.lpDesktop = ptr::null_mut();",
            "restricted-probe-lacks-explicit-private-desktop",
        ),
        (
            WindowsProductionSource::Process,
            "super::token::process_token_query_attestation(process_handle.raw())",
            "super::token::token_attestation_snapshot(token)",
            "immediate-real-target-process-readback-replaced-with-request-reread",
        ),
        (
            WindowsProductionSource::Process,
            "let jobs = [local_job.raw()];",
            "let result_writer = holder_token.launch_token.raw();\n    let handles = [local_job.raw()];",
            "bootstrap-inherits-target-token-handle",
        ),
        (
            WindowsProductionSource::Process,
            "frame.target_envelope != target_envelope",
            "false",
            "bootstrap-token-envelope-not-bound",
        ),
        (
            WindowsProductionSource::Process,
            "process_snapshot: process_snapshot.clone(),",
            "process_snapshot,",
            "loader-ready-bootstrap-snapshot-moved-before-admission-check",
        ),
        (
            WindowsProductionSource::Process,
            "verify_image_path(bootstrap_process.raw(), &executable)?;",
            "let _ = &executable;",
            "bootstrap-image-not-read-back",
        ),
        (
            WindowsProductionSource::Process,
            "connection_lease: Option<OwnedHandle>",
            "connection_lease: Option<u64>",
            "desktop-lifetime-handle-not-owned",
        ),
        (
            WindowsProductionSource::Process,
            "CreateDesktopW(",
            "OpenDesktopW(",
            "private-desktop-not-created",
        ),
        (
            WindowsProductionSource::Process,
            "SetProcessWindowStation(private_window_station.raw())",
            "SetProcessWindowStation(source_window_station)",
            "private-station-binding-removed",
        ),
        (
            WindowsProductionSource::Process,
            "private_window_station.mark_assigned();",
            "let _ = private_window_station.raw();",
            "private-station-lifetime-not-retained",
        ),
        (
            WindowsProductionSource::Process,
            "source_objects_unmodified,\n        private_station_assigned,\n        private_desktop_assigned,\n        desktop_containment_verified: true,\n        window_station_policy_verified: true,",
            "source_objects_unmodified,\n        private_station_assigned,\n        private_desktop_assigned,\n        desktop_containment_verified: true,\n        window_station_policy_verified: false,",
            "private-station-policy-evidence-removed",
        ),
        (
            WindowsProductionSource::Process,
            "SecurityObjectKind::WindowStation,\n        holder_token.raw(),",
            "SecurityObjectKind::Desktop,\n        holder_token.raw(),",
            "holder-station-access-check-kind-confused",
        ),
        (
            WindowsProductionSource::Process,
            "super::token::derive_session_broker_holder_primary(target_session_id)?;",
            "super::token::derive_session_broker_holder_primary(0)?;",
            "session-rebinding-target-session-removed",
        ),
        (
            WindowsProductionSource::Process,
            "    Failed {\n        binding: TargetDesktopBootstrapBindingV3,",
            "    UntypedFailure {\n        binding: TargetDesktopBootstrapBindingV3,",
            "typed-bootstrap-failure-removed",
        ),
        (
            WindowsProductionSource::Process,
            "const TARGET_DESKTOP_BOOTSTRAP_DETAIL_MAX_BYTES: usize = 1_024;",
            "const TARGET_DESKTOP_BOOTSTRAP_DETAIL_MAX_BYTES: usize = usize::MAX;",
            "bootstrap-failure-detail-unbounded",
        ),
        (
            WindowsProductionSource::Process,
            "native_code: failure.native_code,",
            "native_code: None,",
            "bootstrap-native-code-discarded",
        ),
        (
            WindowsProductionSource::Process,
            "TargetCreateError::loader_context_with_os(error.detail, error.os_code)",
            "TargetCreateError::loader_context_with_os(error.detail, None)",
            "bootstrap-native-code-dropped-at-target-create",
        ),
        (
            WindowsProductionSource::Process,
            "launcher_token_query_handle: u64,",
            "launcher_token_query_value: u64,",
            "bootstrap-token-capability-role-removed",
        ),
        (
            WindowsProductionSource::Process,
            "duplicate_remote_token_query(launcher_token.raw(), bootstrap_process.raw())?",
            "duplicate_remote_process_query(unsafe { GetCurrentProcess() }, bootstrap_process.raw())?",
            "bootstrap-token-capability-replaced-with-process-handle",
        ),
        (
            WindowsProductionSource::Process,
            "const TARGET_TOKEN_CAPABILITY_ACCESS: u32 = TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE;",
            "const TARGET_TOKEN_CAPABILITY_ACCESS: u32 = TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE | TOKEN_IMPERSONATE;",
            "bootstrap-target-token-capability-overgranted",
        ),
        (
            WindowsProductionSource::Process,
            "verify_not_inheritable(target_token.raw())?;",
            "let _ = target_token.raw();",
            "bootstrap-target-token-inheritability-unverified",
        ),
        (
            WindowsProductionSource::Process,
            "launcher_process_handle == launcher_token_handle",
            "false",
            "bootstrap-capability-role-collision-accepted",
        ),
        (
            WindowsProductionSource::Process,
            "target_token_handle == launcher_process_handle\n                || target_token_handle == launcher_token_handle",
            "false",
            "bootstrap-target-capability-role-collision-accepted",
        ),
        (
            WindowsProductionSource::Pipe,
            "GetExitCodeProcess(peer_process, &raw mut exit_code)",
            "GetProcessId(peer_process)",
            "bootstrap-peer-exit-code-discarded",
        ),
        (
            WindowsProductionSource::Process,
            "target_desktop_bootstrap_pipe_is_quiet(connection.raw())?",
            "true",
            "post-ready-bytes-not-rejected",
        ),
        (
            WindowsProductionSource::Process,
            "const TARGET_STATION_ATTEST_ACCESS: u32 = READ_CONTROL_ACCESS | WINSTA_READATTRIBUTES_ACCESS;",
            "const TARGET_STATION_ATTEST_ACCESS: u32 = READ_CONTROL_ACCESS;",
            "station-attestation-readattributes-removed",
        ),
        (
            WindowsProductionSource::Process,
            "const TARGET_STATION_ATTEST_ACCESS: u32 = READ_CONTROL_ACCESS | WINSTA_READATTRIBUTES_ACCESS;",
            "const TARGET_STATION_ATTEST_ACCESS: u32 = READ_CONTROL_ACCESS | WINSTA_READATTRIBUTES_ACCESS | 0x0000_0200;",
            "station-attestation-readscreen-added",
        ),
        (
            WindowsProductionSource::Process,
            "const TARGET_DESKTOP_ATTEST_ACCESS: u32 = READ_CONTROL_ACCESS | DESKTOP_READOBJECTS_ACCESS;",
            "const TARGET_DESKTOP_ATTEST_ACCESS: u32 = READ_CONTROL_ACCESS;",
            "desktop-attestation-readobjects-removed",
        ),
        (
            WindowsProductionSource::Process,
            "const TARGET_DESKTOP_ATTEST_ACCESS: u32 = READ_CONTROL_ACCESS | DESKTOP_READOBJECTS_ACCESS;",
            "const TARGET_DESKTOP_ATTEST_ACCESS: u32 = READ_CONTROL_ACCESS | DESKTOP_READOBJECTS_ACCESS | 0x0000_0080;",
            "desktop-attestation-writeobjects-added",
        ),
        (
            WindowsProductionSource::Process,
            "const TARGET_DESKTOP_ATTEST_ACCESS: u32 = READ_CONTROL_ACCESS | DESKTOP_READOBJECTS_ACCESS;",
            "const TARGET_DESKTOP_ATTEST_ACCESS: u32 = 0x000f_01ff;",
            "desktop-attestation-all-access-added",
        ),
        (
            WindowsProductionSource::Process,
            "                desired_access,\n                0,\n                0,\n            )\n        } == 0",
            "                desired_access,\n                0,\n                DUPLICATE_SAME_ACCESS,\n            )\n        } == 0",
            "user-object-duplicate-same-access-added",
        ),
        (
            WindowsProductionSource::Process,
            "let mut desktop = create_target_desktop_on_creator_thread(\n        desktop_wide.clone(),\n        desktop_creation_security,\n        connection.raw(),\n        launcher_process.raw(),\n        binding.clone(),\n    )?;",
            "let desktop_attributes = desktop_creation_security.attributes(false);\n    let desktop = OwnedDesktop::new(unsafe {\n        CreateDesktopW(\n            desktop_wide.as_ptr(),\n            ptr::null(),\n            ptr::null(),\n            0,\n            super::security::TARGET_PRIVATE_DESKTOP_ACCESS,\n            &raw const desktop_attributes,\n        )\n    });",
            "private-desktop-creator-thread-removed",
        ),
        (
            WindowsProductionSource::Process,
            "    desktop.mark_assigned();\n    attest_target_user_object(\n        desktop.raw(),\n        &desktop_name,\n        &desktop_security,\n        super::security::SecurityObjectKind::Desktop,\n        holder_token.raw(),",
            "    let _ = desktop.raw();\n    attest_target_user_object(\n        desktop.raw(),\n        &desktop_name,\n        &desktop_security,\n        super::security::SecurityObjectKind::Desktop,\n        holder_token.raw(),",
            "assigned-private-desktop-closed-before-process-exit",
        ),
        (
            WindowsProductionSource::Process,
            "let launcher_executable = super::package::installed_binary();",
            "let launcher_executable = std::env::current_exe()?;",
            "bootstrap-launcher-image-confused-with-helper",
        ),
        (
            WindowsProductionSource::Process,
            ".join()",
            ".map(|handle| handle)",
            "private-desktop-creator-join-removed",
        ),
        (
            WindowsProductionSource::Process,
            "Ok(OwnedDesktop::new(desktop))",
            "let _ = unsafe { GetThreadDesktop(GetCurrentThreadId()) };\n            Ok(OwnedDesktop::new(desktop))",
            "private-desktop-creator-binding-inference-added",
        ),
        (
            WindowsProductionSource::Process,
            "Ok(OwnedDesktop::new(desktop))",
            "let _ = unsafe { SetThreadDesktop(desktop) };\n            Ok(OwnedDesktop::new(desktop))",
            "private-desktop-creator-explicit-binding-added",
        ),
        (
            WindowsProductionSource::Process,
            "attest_target_user_object(\n        desktop.raw(),\n        &desktop_name,\n        &desktop_security,\n        super::security::SecurityObjectKind::Desktop,\n        target_token,",
            "attest_target_user_object(\n        default_desktop,\n        &desktop_name,\n        &desktop_security,\n        super::security::SecurityObjectKind::Desktop,\n        target_token,",
            "private-desktop-returned-handle-attestation-removed",
        ),
        (
            WindowsProductionSource::Process,
            "verify_private_desktop_containment(private_window_station.raw(), &desktop_wide)",
            "Ok::<(), String>(())",
            "private-desktop-containment-proof-removed",
        ),
        (
            WindowsProductionSource::Process,
            "attest_target_user_object_opens_as_token(\n            token,\n            &self.window_station_name,\n            &self.desktop_name,\n            self.read_handles.window_station.raw(),\n            self.read_handles.desktop.raw(),\n            &self.window_station_security,\n            &self.desktop_security,\n            &self.window_station_security_sha256,\n            &self.desktop_security_sha256,\n            Instant::now() + TARGET_ASSOCIATION_PREFLIGHT_OVERALL_TIMEOUT,\n            &mut progress,\n        )",
            "Ok::<(), String>(())",
            "nested-explicit-binding-open-preflight-removed",
        ),
        (
            WindowsProductionSource::Process,
            "read_handles: TargetUserBindingReadHandles,",
            "read_handles: (),",
            "nested-readback-handles-removed",
        ),
        (
            WindowsProductionSource::Process,
            "self.read_handles.desktop.raw(),\n            &self.window_station_security,\n            &self.desktop_security,",
            "self.read_handles.desktop.raw(),\n            &self.desktop_security,\n            &self.desktop_security,",
            "nested-station-preflight-policy-confused",
        ),
        (
            WindowsProductionSource::Process,
            "SecurityDescriptor::from_sddl(&expected_window_station_sddl)?\n                .user_object_policy_fingerprint(\n                    super::security::SecurityObjectKind::WindowStation,\n                )?;",
            "super::record::digest(expected_window_station_sddl.as_bytes());",
            "target-station-policy-raw-sddl-digest-restored",
        ),
        (
            WindowsProductionSource::Security,
            "        | DACL_SECURITY_INFORMATION\n        | LABEL_SECURITY_INFORMATION;",
            "        | DACL_SECURITY_INFORMATION;",
            "target-policy-fingerprint-label-dropped",
        ),
        (
            WindowsProductionSource::Security,
            "let canonical = if kind == SecurityObjectKind::Desktop {\n            normalized_resultant_user_object_sddl(self.0, actual, self.1, kind)?",
            "let canonical = if kind == SecurityObjectKind::Desktop {\n            normalized_descriptor_sddl(actual, self.1, kind)?",
            "desktop-resultant-policy-normalization-bypassed",
        ),
        (
            WindowsProductionSource::Process,
            "    attest_retained_target_user_object_namespace(\n        token,\n        window_station_name,\n        desktop_name,\n        retained_window_station,\n        retained_desktop,\n        window_station_security,\n        desktop_security,\n        expected_window_station_live_equality_sha256,\n        expected_desktop_live_equality_sha256,\n    )?;\n    progress.publish(\n        TargetAssociationPreflightStageV1::RetainedNamespaceBefore,\n        1,\n        Some(1),\n    )?;\n    super::token::require_thread_token_absent",
            "    progress.publish(\n        TargetAssociationPreflightStageV1::RetainedNamespaceBefore,\n        1,\n        Some(1),\n    )?;\n    super::token::require_thread_token_absent",
            "association-preflight-retained-pre-open-attestation-removed",
        ),
        (
            WindowsProductionSource::Process,
            "    attest_retained_target_user_object_namespace(\n        token,\n        window_station_name,\n        desktop_name,\n        retained_window_station,\n        retained_desktop,\n        window_station_security,\n        desktop_security,\n        expected_window_station_live_equality_sha256,\n        expected_desktop_live_equality_sha256,\n    )?;\n    let native_loader_access_lease = native_loader_access_lease",
            "    let native_loader_access_lease = native_loader_access_lease",
            "association-preflight-retained-post-open-attestation-removed",
        ),
        (
            WindowsProductionSource::Process,
            "attest_target_user_object(\n        retained_desktop,\n        desktop_name,\n        desktop_security,\n        super::security::SecurityObjectKind::Desktop,\n        token,\n    )",
            "Ok::<(), String>(())",
            "association-preflight-post-open-desktop-policy-reattest-removed",
        ),
        (
            WindowsProductionSource::Process,
            "OpenWindowStationW(window_station_wide.as_ptr(), 0, MAXIMUM_ALLOWED_ACCESS)",
            "OpenWindowStationW(\n                window_station_wide.as_ptr(),\n                0,\n                super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS,\n            )",
            "explicit-binding-station-maximum-allowed-weakened",
        ),
        (
            WindowsProductionSource::Process,
            "        window_station.mark_assigned();",
            "        let _ = window_station.raw();",
            "assigned-explicit-open-station-closed",
        ),
        (
            WindowsProductionSource::Process,
            "OpenDesktopW(desktop_wide.as_ptr(), 0, 0, MAXIMUM_ALLOWED_ACCESS)",
            "OpenDesktopW(\n            desktop_wide.as_ptr(),\n            0,\n            0,\n            super::security::TARGET_PRIVATE_DESKTOP_ACCESS,\n        )",
            "explicit-binding-desktop-maximum-allowed-weakened",
        ),
        (
            WindowsProductionSource::Process,
            "        desktop.mark_assigned();",
            "        let _ = desktop.raw();",
            "assigned-explicit-open-desktop-closed",
        ),
        (
            WindowsProductionSource::Process,
            "const MAXIMUM_ALLOWED_ACCESS: u32 = 0x0200_0000;",
            "const MAXIMUM_ALLOWED_ACCESS: u32 = 0x000f_ffff;",
            "association-preflight-maximum-allowed-mode-changed",
        ),
        (
            WindowsProductionSource::Process,
            "holder_lease\n        .attest_live()\n        .map_err(TargetDesktopLeaseCreateError::from)?;\n    let association_preflight = request_holder_target_association_preflight(",
            "let association_preflight = request_holder_target_association_preflight(",
            "holder-liveness-preflight-check-removed",
        ),
        (
            WindowsProductionSource::Process,
            "    holder_lease\n        .attest_live()\n        .map_err(TargetDesktopLeaseCreateError::from)?;\n    launch_target_desktop_loader_control(",
            "    launch_target_desktop_loader_control(",
            "holder-liveness-postflight-check-removed",
        ),
        (
            WindowsProductionSource::Process,
            "let association_preflight = request_holder_target_association_preflight(\n        holder_lease,\n        target_snapshot,\n        expected_station_policy_sha256,\n        expected_desktop_policy_sha256,\n    )?;",
            "let _ = holder_lease;",
            "holder-association-preflight-request-removed",
        ),
        (
            WindowsProductionSource::Process,
            "                    total,\n                } if binding == holder_lease.holder_binding => {\n                    progress",
            "                    total,\n                } if true => {\n                    progress",
            "association-preflight-progress-binding-check-removed",
        ),
        (
            WindowsProductionSource::Process,
            "!progress.is_terminal()",
            "false",
            "association-preflight-ready-before-terminal-progress",
        ),
        (
            WindowsProductionSource::Process,
            "cursor.total.is_none() && total == Some(completed)",
            "cursor.total.is_none() && total.is_some()",
            "association-progress-noncanonical-unknown-total-closure",
        ),
        (
            WindowsProductionSource::Process,
            "cursor.total.is_some() && total.is_none()",
            "false",
            "association-progress-known-total-disappears",
        ),
        (
            WindowsProductionSource::Process,
            "cursor.total.is_some() && cursor.total != total",
            "false",
            "association-progress-known-total-mutates",
        ),
        (
            WindowsProductionSource::Process,
            "last_stage.successor() != Some(stage)",
            "stage == last_stage",
            "association-progress-stage-skip-accepted",
        ),
        (
            WindowsProductionSource::Process,
            "} else if completed != 0 {\n            Some(\"new stage has a nonzero completed count\")",
            "} else if false {\n            Some(\"new stage has a nonzero completed count\")",
            "association-progress-new-stage-counter-not-reset",
        ),
        (
            WindowsProductionSource::Process,
            "serve_holder_target_association_preflight(\n        connection,\n        launcher_process,\n        binding,\n        target_token,\n        &frame.window_station_name,\n        &frame.desktop_name,\n        private_window_station.raw(),\n        desktop.raw(),\n        &window_station_security,\n        &desktop_security,\n        &frame.window_station_live_equality_sha256,\n        &frame.desktop_live_equality_sha256,\n    )?;",
            "let _ = (connection, launcher_process, binding, target_token);",
            "holder-association-preflight-server-removed",
        ),
        (
            WindowsProductionSource::Process,
            "        } if observed_binding == *binding => {}",
            "        } if true => {}",
            "holder-association-request-binding-check-removed",
        ),
        (
            WindowsProductionSource::Process,
            "                    evidence,\n                } if binding == holder_lease.holder_binding =>",
            "                    evidence,\n                } if true =>",
            "holder-association-response-binding-check-removed",
        ),
        (
            WindowsProductionSource::Process,
            "super::pipe::TargetDesktopBootstrapPipeOperation::AssociationPreflightWrite,",
            "super::pipe::TargetDesktopBootstrapPipeOperation::ReadyWrite,",
            "association-preflight-request-operation-confused",
        ),
        (
            WindowsProductionSource::Process,
            "super::pipe::TargetDesktopBootstrapPipeOperation::AssociationPreflightReadyRead,",
            "super::pipe::TargetDesktopBootstrapPipeOperation::ReadyWrite,",
            "association-preflight-response-operation-confused",
        ),
        (
            WindowsProductionSource::Process,
            "super::pipe::TargetDesktopBootstrapPipeOperation::AssociationPreflightRead,",
            "super::pipe::TargetDesktopBootstrapPipeOperation::ReadyWrite,",
            "association-preflight-server-read-operation-confused",
        ),
        (
            WindowsProductionSource::Process,
            "super::pipe::TargetDesktopBootstrapPipeOperation::AssociationPreflightReadyWrite,",
            "super::pipe::TargetDesktopBootstrapPipeOperation::ReadyWrite,",
            "association-preflight-server-write-operation-confused",
        ),
        (
            WindowsProductionSource::Process,
            "    TargetAssociationPreflight,\n    TargetNativeLoaderAccessPreflight,\n    LoaderControl,\n}",
            "    UntypedAssociationPreflight,\n    TargetNativeLoaderAccessPreflight,\n    LoaderControl,\n}",
            "association-preflight-typed-phase-removed",
        ),
        (
            WindowsProductionSource::Process,
            "    target_snapshot_after: super::token::TokenAttestationSnapshot,\n    thread_token_absent: bool,",
            "    target_snapshot_after: (),\n    thread_token_absent: bool,",
            "association-preflight-after-evidence-field-removed",
        ),
        (
            WindowsProductionSource::Process,
            "if evidence.window_station_policy_sha256 != expected_station_policy_sha256\n                        || evidence.desktop_policy_sha256 != expected_desktop_policy_sha256",
            "if false",
            "association-preflight-response-descriptor-binding-removed",
        ),
        (
            WindowsProductionSource::Process,
            "\"holder-association-preflight-before\",",
            "\"holder-association-preflight-before-unbound\",",
            "association-preflight-before-evidence-unbound",
        ),
        (
            WindowsProductionSource::Process,
            "\"holder-association-preflight-after\",",
            "\"holder-association-preflight-after-unbound\",",
            "association-preflight-after-evidence-unbound",
        ),
        (
            WindowsProductionSource::Process,
            "        expected_window_station_live_equality_sha256,\n        expected_desktop_live_equality_sha256,\n        overall_deadline,\n        &mut progress,\n    )?;\n    super::pipe::write_frame_bounded(",
            "        expected_desktop_live_equality_sha256,\n        expected_desktop_live_equality_sha256,\n        overall_deadline,\n        &mut progress,\n    )?;\n    super::pipe::write_frame_bounded(",
            "association-preflight-server-live-baseline-binding-confused",
        ),
        (
            WindowsProductionSource::Process,
            "super::token::granted_handle_access(window_station.raw())",
            "Ok(super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS)",
            "station-maximum-allowed-grant-not-attested",
        ),
        (
            WindowsProductionSource::Process,
            "super::token::granted_handle_access(desktop.raw())",
            "Ok(super::security::TARGET_PRIVATE_DESKTOP_ACCESS)",
            "desktop-maximum-allowed-grant-not-attested",
        ),
        (
            WindowsProductionSource::Process,
            "if window_station_granted_access & super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS\n            != super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS",
            "if false",
            "station-maximum-allowed-required-mask-check-removed",
        ),
        (
            WindowsProductionSource::Process,
            "if desktop_granted_access & super::security::TARGET_PRIVATE_DESKTOP_ACCESS\n            != super::security::TARGET_PRIVATE_DESKTOP_ACCESS",
            "if false",
            "desktop-maximum-allowed-required-mask-check-removed",
        ),
        (
            WindowsProductionSource::Process,
            "if user_object_name(window_station.raw())",
            "if Ok(window_station_name.to_owned())",
            "association-preflight-station-name-unbound",
        ),
        (
            WindowsProductionSource::Process,
            "if user_object_name(desktop.raw())",
            "if Ok(desktop_name.to_owned())",
            "association-preflight-desktop-name-unbound",
        ),
        (
            WindowsProductionSource::Process,
            "SecurityDescriptor::user_object_security_equality_fingerprint(window_station.raw())",
            "Ok(expected_window_station_live_equality_sha256.to_owned())",
            "association-preflight-station-live-readback-removed",
        ),
        (
            WindowsProductionSource::Process,
            "        let desktop_live_equality_sha256 =\n            SecurityDescriptor::user_object_security_equality_fingerprint(desktop.raw())",
            "        let desktop_live_equality_sha256 =\n            Ok(expected_desktop_live_equality_sha256.to_owned())",
            "association-preflight-desktop-live-readback-removed",
        ),
        (
            WindowsProductionSource::Process,
            "if window_station_live_equality_sha256 != expected_window_station_live_equality_sha256 {",
            "if false {",
            "association-preflight-station-descriptor-comparison-removed",
        ),
        (
            WindowsProductionSource::Process,
            "if window_station_live_equality_sha256 != expected_window_station_live_equality_sha256 {",
            "if window_station_live_equality_sha256 != expected_window_station_policy_sha256 {",
            "association-preflight-policy-substituted-for-live-baseline",
        ),
        (
            WindowsProductionSource::Process,
            "if desktop_live_equality_sha256 != expected_desktop_live_equality_sha256 {",
            "if false {",
            "association-preflight-desktop-descriptor-comparison-removed",
        ),
        (
            WindowsProductionSource::Process,
            "super::token::require_thread_token_absent(unsafe { GetCurrentThread() }).map_err(|error| {\n        TargetDesktopBootstrapFailure::contract(\n            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,\n            error,\n        )\n    })?;\n    // Resolve paths, PE imports, API-set hosts, and source identity/mutation",
            "// Resolve paths, PE imports, API-set hosts, and source identity/mutation",
            "association-preflight-preexisting-thread-token-accepted",
        ),
        (
            WindowsProductionSource::Process,
            "guard.revert().map_err(|error| {",
            "Ok::<(), io::Error>(()).map_err(|error| {",
            "association-preflight-impersonation-not-reverted",
        ),
        (
            WindowsProductionSource::Process,
            "super::token::require_thread_token_absent(unsafe { GetCurrentThread() }).map_err(|error| {\n        TargetDesktopBootstrapFailure::contract(\n            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,\n            error,\n        )\n    })?;\n    let (",
            "let (",
            "association-preflight-post-revert-thread-token-check-removed",
        ),
        (
            WindowsProductionSource::Process,
            "\"holder-target-association-preflight\",",
            "\"holder-target-association-unbound\",",
            "association-preflight-target-token-substitution-accepted",
        ),
        (
            WindowsProductionSource::Process,
            "            target_snapshot_after,\n            thread_token_absent: true,",
            "            target_snapshot_after,\n            thread_token_absent: false,",
            "association-preflight-thread-token-residue-accepted",
        ),
        (
            WindowsProductionSource::Pipe,
            "    AssociationPreflightRead,\n    AssociationPreflightWrite,\n    AssociationPreflightProgressWrite,\n    AssociationPreflightReadyRead,\n    AssociationPreflightReadyWrite,",
            "    AssociationPreflightRead,\n    ReadyWrite,\n    AssociationPreflightProgressWrite,\n    AssociationPreflightReadyRead,\n    AssociationPreflightReadyWrite,",
            "association-preflight-operation-type-removed",
        ),
        (
            WindowsProductionSource::Pipe,
            "PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED",
            "PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED",
            "bootstrap-first-instance-removed",
        ),
        (
            WindowsProductionSource::Pipe,
            "PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,\n            1,\n            64 * 1024,",
            "PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,\n            1,\n            64 * 1024,",
            "bootstrap-remote-clients-admitted",
        ),
        (
            WindowsProductionSource::Pipe,
            "CancelIoEx(handle, overlapped);",
            "let _ = (handle, overlapped);",
            "bootstrap-pending-io-not-cancelled",
        ),
        (
            WindowsProductionSource::Security,
            "(A;;0x0012019b;;;{trustee})",
            "(A;;GA;;;{trustee})",
            "bootstrap-client-mask-broadened",
        ),
        (
            WindowsProductionSource::Security,
            "target_user_object_sddl(token, TARGET_PRIVATE_WINDOW_STATION_ACCESS)",
            "target_user_object_sddl(token, TARGET_PRIVATE_DESKTOP_ACCESS)",
            "private-window-station-mask-confused",
        ),
        (
            WindowsProductionSource::Security,
            "target_user_object_sddl(token, TARGET_PRIVATE_DESKTOP_ACCESS)",
            "target_user_object_sddl(token, TARGET_PRIVATE_WINDOW_STATION_ACCESS)",
            "private-desktop-mask-broadened",
        ),
    ] {
        let mut mutated = production.clone();
        replace_windows_source_once(mutated.source_mut(source), exact, replacement, mutant);
        assert!(
            validate_windows_production_contract(&mutated).is_err(),
            "{mutant} survived the target desktop bootstrap contract"
        );
    }

    let mut preflight_after_probe_resume = production.clone();
    let association_request = "let association_preflight = request_holder_target_association_preflight(\n        holder_lease,\n        target_snapshot,\n        expected_station_policy_sha256,\n        expected_desktop_policy_sha256,\n    )?;";
    replace_windows_source_once(
        &mut preflight_after_probe_resume.process,
        association_request,
        "let _association_preflight_moved_after_resume = ();",
        "holder-association-preflight-after-probe-resume",
    );
    replace_windows_source_once(
        &mut preflight_after_probe_resume.process,
        "ResumeThread(probe_thread.raw())",
        &format!("ResumeThread(probe_thread.raw());\n    {association_request}"),
        "holder-association-preflight-after-probe-resume",
    );
    assert!(
        validate_windows_production_contract(&preflight_after_probe_resume).is_err(),
        "holder association preflight after probe resume survived the target desktop bootstrap contract"
    );

    for (exact, replacement, mutant) in [
        (
            "adjust_error != ERROR_SUCCESS",
            "adjust_error == ERROR_NOT_ALL_ASSIGNED",
            "tcb-adjust-result-not-exact",
        ),
        (
            "if let Err(error) = scoped.revert() {\n        let error = LauncherHolderTokenDerivationError::new(",
            "if false {\n        let error = LauncherHolderTokenDerivationError::new(",
            "tcb-thread-token-reversion-removed",
        ),
        (
            "NtSetInformationToken(\n                mutable_primary.raw(),\n                TokenSessionId,",
            "NtSetInformationToken(\n                source.raw(),\n                TokenSessionId,",
            "live-launcher-session-mutated",
        ),
        (
            "const HOLDER_MUTABLE_TOKEN_ACCESS: u32 = TOKEN_QUERY\n    | TOKEN_QUERY_SOURCE\n    | TOKEN_DUPLICATE\n    | TOKEN_ASSIGN_PRIMARY\n    | TOKEN_ADJUST_DEFAULT\n    | TOKEN_ADJUST_SESSIONID;",
            "const HOLDER_MUTABLE_TOKEN_ACCESS: u32 =\n    TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID;",
            "holder-mutable-default-adjust-authority-omitted",
        ),
        (
            "effective_thread_privilege_enabled(privilege_name)",
            "Ok(true)",
            "effective-thread-privilege-proof-bypassed",
        ),
        (
            "if mutable_granted_access != mutable_access {",
            "if false {",
            "holder-mutable-granted-access-proof-bypassed",
        ),
        (
            "if launch_granted_access != launch_access {",
            "if false {",
            "holder-launch-granted-access-proof-bypassed",
        ),
        (
            "privilege_carrier.raw(),\n        \"SeAssignPrimaryTokenPrivilege\",",
            "privilege_carrier.raw(),\n        \"SeTcbPrivilege\",",
            "assign-primary-grant-privilege-omitted",
        ),
        (
            "carrier_access,\n            ptr::null(),\n            SecurityImpersonation,\n            TokenImpersonation,\n            &raw mut privilege_carrier,",
            "carrier_access,\n            ptr::null(),\n            SecurityDelegation,\n            TokenImpersonation,\n            &raw mut privilege_carrier,",
            "carrier-impersonation-level-broadened",
        ),
        (
            "const HOLDER_LAUNCH_TOKEN_ACCESS: u32 =\n    TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY;",
            "const HOLDER_LAUNCH_TOKEN_ACCESS: u32 = TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;",
            "holder-launch-mutation-authority-retained",
        ),
        (
            "narrowed_session_status != STATUS_ACCESS_DENIED",
            "narrowed_session_status >= 0",
            "holder-launch-raw-native-authority-result-not-exact",
        ),
        (
            ".with_nt_status(session_set_status)",
            ".with_nt_status(0)",
            "holder-session-raw-ntstatus-evidence-discarded",
        ),
        (
            "if token_attestation_snapshot(source.raw()).map_err(|detail| {",
            "if Ok(launcher_original.clone()).map_err(|detail: String| {",
            "launcher-source-invariance-check-removed",
        ),
    ] {
        let mut mutated = production.clone();
        replace_windows_source_once(&mut mutated.token, exact, replacement, mutant);
        assert!(
            validate_windows_production_contract(&mutated).is_err(),
            "{mutant} survived the target desktop bootstrap contract"
        );
    }

    let mut early_mutable_duplicate = production.clone();
    let carrier_install = "ScopedPrivilegeThreadToken::install(privilege_carrier.raw())";
    let carrier_install_sentinel = "__MOVED_PRIVILEGE_CARRIER_INSTALL__";
    replace_windows_source_once(
        &mut early_mutable_duplicate.token,
        carrier_install,
        carrier_install_sentinel,
        "mutable-primary-duplicated-before-carrier-install",
    );
    let mutable_adoption =
        "let mutable_primary = OwnedHandle::new(mutable_primary).map_err(|detail| {";
    let reordered_mutable_adoption =
        format!("let _moved_carrier_install = {carrier_install};\n        {mutable_adoption}");
    replace_windows_source_once(
        &mut early_mutable_duplicate.token,
        mutable_adoption,
        &reordered_mutable_adoption,
        "mutable-primary-duplicated-before-carrier-install",
    );
    replace_windows_source_once(
        &mut early_mutable_duplicate.token,
        carrier_install_sentinel,
        "",
        "mutable-primary-duplicated-before-carrier-install",
    );
    assert!(
        validate_windows_production_contract(&early_mutable_duplicate).is_err(),
        "mutable primary duplication before carrier installation survived the target desktop bootstrap contract"
    );

    let mut missing_tcb = production.clone();
    replace_windows_source_once(
        &mut missing_tcb.package,
        "pub(crate) const LAUNCHER_PRIVILEGES: &[&str] = &[\n    \"SeAssignPrimaryTokenPrivilege\",\n    \"SeIncreaseQuotaPrivilege\",\n    \"SeTcbPrivilege\",\n];",
        "pub(crate) const LAUNCHER_PRIVILEGES: &[&str] = &[\n    \"SeAssignPrimaryTokenPrivilege\",\n    \"SeIncreaseQuotaPrivilege\",\n];",
        "launcher-tcb-required-privilege-omitted",
    );
    assert!(
        validate_windows_production_contract(&missing_tcb).is_err(),
        "missing launcher TCB privilege survived the target desktop bootstrap contract"
    );

    let mut stale_schema = production.clone();
    replace_windows_source_once(
        &mut stale_schema.process,
        "const TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION: u32 = 18;",
        "const TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION: u32 = 12;",
        "stale-bootstrap-schema",
    );
    assert!(
        validate_windows_production_contract(&stale_schema).is_err(),
        "stale bootstrap schema survived the target desktop bootstrap contract"
    );

    let mut digest_not_verified = production.clone();
    replace_windows_source_once(
        &mut digest_not_verified.process,
        "    binding.verify_digest()?;",
        "    let _ = &binding.binding_sha256;",
        "binding-digest-not-verified-before-capability-use",
    );
    assert!(
        validate_windows_production_contract(&digest_not_verified).is_err(),
        "unverified binding digest survived the target desktop bootstrap contract"
    );

    let mut real_target_assignment_regressed = production.clone();
    replace_windows_source_once(
        &mut real_target_assignment_regressed.process,
        "super::token::require_assigned_process_authority(\n                    \"target-request-to-real-process\",",
        "super::token::require_same_token_instance(\n                    \"target-request-to-real-process\",",
        "real-target-assignment-replaced-with-instance-equality",
    );
    assert!(
        validate_windows_production_contract(&real_target_assignment_regressed).is_err(),
        "whole-snapshot real-target assignment comparison survived the target desktop bootstrap contract"
    );

    let mut query_only_token = production.clone();
    replace_windows_source_once(
        &mut query_only_token.token,
        "pub(crate) fn current_process_token_for_access_check() -> Result<OwnedHandle, String> {\n    current_process_token_with_attested_access(TOKEN_QUERY | TOKEN_DUPLICATE, \"access-check\")\n}",
        "pub(crate) fn current_process_token_for_access_check() -> Result<OwnedHandle, String> {\n    current_process_token_with_attested_access(TOKEN_QUERY, \"access-check\")\n}",
        "private-desktop-access-check-token-not-duplicable",
    );
    assert!(
        validate_windows_production_contract(&query_only_token).is_err(),
        "query-only private desktop AccessCheck token survived the target desktop bootstrap contract"
    );

    let mut general_process_token = production.clone();
    replace_windows_source_once(
        &mut general_process_token.process,
        "let holder_token = super::token::current_process_token_for_access_check().map_err(|error| {",
        "let holder_token = super::token::process_token(unsafe { GetCurrentProcess() }).map_err(|error| {",
        "private-desktop-access-check-reuses-general-process-token",
    );
    assert!(
        validate_windows_production_contract(&general_process_token).is_err(),
        "general query-only process token survived the target desktop bootstrap contract"
    );

    for (exact, replacement, mutant) in [
        (
            "const NONINTERACTIVE_WINDOW_STATION_ALL_ACCESS: u32 = 0x000f_016f;",
            "const NONINTERACTIVE_WINDOW_STATION_ALL_ACCESS: u32 = 0x000f_037f;",
            "interactive-station-generic-all",
        ),
        (
            "            \"S-1-5-18\".to_owned(),\n            self.holder_restricting_sid.clone(),\n            self.target_logon_sid.clone(),",
            "            self.holder_restricting_sid.clone(),\n            self.target_logon_sid.clone(),",
            "private-desktop-system-trustee-removed",
        ),
        (
            "self.target_logon_sid.clone()",
            "self.holder_restricting_sid.clone()",
            "private-logon-trustee-removed",
        ),
        (
            "self.target_logon_sid.clone()",
            "\"S-1-5-11\".to_owned()",
            "private-logon-trustee-broadened",
        ),
        (
            "trustees.insert(\"S-1-5-33\".to_owned());",
            "let _ = &trustees;",
            "private-write-restricted-trustee-removed",
        ),
    ] {
        let mut mutated = production.clone();
        replace_windows_source_once(&mut mutated.security, exact, replacement, mutant);
        assert!(
            validate_windows_production_contract(&mutated).is_err(),
            "{mutant} survived the target desktop bootstrap contract"
        );
    }
}

#[derive(Clone)]
struct WindowsLoaderControlContractSources {
    process: String,
    pipe: String,
    loader_access: String,
    loader_debug: String,
    session_broker: String,
    cargo: String,
    bootstrap: String,
    package_schema: String,
    pe: String,
    cargo_config: String,
    sealed_windows: String,
    release: String,
}

#[derive(Clone, Copy)]
enum WindowsLoaderControlContractSource {
    Process,
    Pipe,
    LoaderAccess,
    LoaderDebug,
    SessionBroker,
    Bootstrap,
    PackageSchema,
    Pe,
    CargoConfig,
}

impl WindowsLoaderControlContractSources {
    fn load() -> Self {
        Self {
            process: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/process.rs"
            )),
            pipe: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/pipe.rs"
            )),
            loader_access: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/loader_access.rs"
            )),
            loader_debug: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/loader_debug.rs"
            )),
            session_broker: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/session_broker.rs"
            )),
            cargo: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/Cargo.toml"
            )),
            bootstrap: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-target-desktop-bootstrap.rs"
            )),
            package_schema: normalize_windows_source(include_str!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/inspection_schema.rs"
            )),
            pe: normalize_windows_source(include_str!(
                "../../../crates/memcordon-core/src/windows_pe.rs"
            )),
            cargo_config: normalize_windows_source(include_str!("../../../.cargo/config.toml")),
            sealed_windows: normalize_windows_source(include_str!("../src/sealed_windows.rs")),
            release: normalize_windows_source(include_str!("../src/release.rs")),
        }
    }

    fn source_mut(&mut self, source: WindowsLoaderControlContractSource) -> &mut String {
        match source {
            WindowsLoaderControlContractSource::Process => &mut self.process,
            WindowsLoaderControlContractSource::Pipe => &mut self.pipe,
            WindowsLoaderControlContractSource::LoaderAccess => &mut self.loader_access,
            WindowsLoaderControlContractSource::LoaderDebug => &mut self.loader_debug,
            WindowsLoaderControlContractSource::SessionBroker => &mut self.session_broker,
            WindowsLoaderControlContractSource::Bootstrap => &mut self.bootstrap,
            WindowsLoaderControlContractSource::PackageSchema => &mut self.package_schema,
            WindowsLoaderControlContractSource::Pe => &mut self.pe,
            WindowsLoaderControlContractSource::CargoConfig => &mut self.cargo_config,
        }
    }
}

fn validate_windows_loader_control_contract(
    sources: &WindowsLoaderControlContractSources,
) -> Result<(), String> {
    require_source(
        &sources.bootstrap,
        "#[cfg(all(target_os = \"windows\", not(target_feature = \"crt-static\")))]\ncompile_error!(\"the target desktop bootstrap requires a statically linked CRT\");",
        "helper-local static CRT assertion",
    )?;
    require_source(
        &sources.bootstrap,
        "[role, pipe_name, nonce, desktop] if role == \"loader-control\"",
        "fixed loader-control CLI arity",
    )?;
    let probe = semantic_function_region(
        &sources.process,
        "fn launch_target_desktop_probe(",
        "fn read_target_desktop_bootstrap_attestation(",
    )
    .ok_or_else(|| "explicit Probe launch has no semantic boundary".to_owned())?;
    require_source_order(
        &probe,
        &[
            (
                "let association_preflight = request_holder_target_association_preflight(",
                "retained exact-target association evidence",
            ),
            (
                "holder_lease\n        .attest_live()",
                "holder liveness after association preflight",
            ),
            (
                "launch_target_desktop_loader_control(",
                "loader control before explicit Probe",
            ),
            (
                "exact_desktop,\n        launch_context,",
                "canonical private desktop passed into loader control",
            ),
            (
                "holder_lease\n        .attest_live()",
                "holder liveness after loader control",
            ),
            (
                "let nonce = target_desktop_nonce()?;",
                "Probe endpoint creation after loader control",
            ),
        ],
    )?;
    let control = semantic_function_region(
        &sources.process,
        "fn launch_target_desktop_loader_control(",
        "#[allow(clippy::too_many_arguments)]",
    )
    .ok_or_else(|| "loader-control launch has no semantic boundary".to_owned())?;
    require_source_order(
        &control,
        &[
            (
                "let control_job = Job::create(None, None, None)?;",
                "separate atomic loader-control Job",
            ),
            (
                "PROC_THREAD_ATTRIBUTE_JOB_LIST",
                "atomic loader-control Job assignment",
            ),
            (
                "\"loader-control\".encode_utf16().collect(),",
                "same-image loader-control role",
            ),
            (
                "exact_desktop.encode_utf16().collect(),",
                "canonical desktop CLI argument",
            ),
            (
                "let mut loader_control_desktop = exact_desktop.encode_utf16().collect::<Vec<_>>();",
                "live canonical desktop selection",
            ),
            (
                "loader_control_desktop.push(0);",
                "canonical desktop NUL termination",
            ),
            (
                "startup.StartupInfo.lpDesktop = loader_control_desktop.as_mut_ptr();",
                "explicit canonical private lpDesktop",
            ),
            (
                "CreateProcessAsUserW(",
                "exact-token loader-control creation",
            ),
            (
                "require_assigned_process_authority(\n            \"target-request-to-loader-control-process\"",
                "exact target assignment attestation",
            ),
            (
                "ResumeThread(control_thread.raw())",
                "single loader-control resume",
            ),
            (
                "TargetDesktopBootstrapMessageV1::LoaderReady {",
                "validated loader-ready evidence",
            ),
            (
                "observed_desktop.as_deref() == Some(exact_desktop)",
                "loader-ready canonical desktop binding",
            ),
            (
                "TargetDesktopBootstrapPipeOperation::LoaderControlReleaseWrite",
                "typed loader-control release",
            ),
            (
                "WaitForSingleObject(control_process.raw(), 30_000)",
                "bounded loader-control exit",
            ),
            ("control_job.wait_empty(", "empty loader-control Job proof"),
        ],
    )?;
    if control.contains("let mut loader_control_desktop = [0_u16];")
        || control.contains("startup.StartupInfo.lpDesktop = ptr::null_mut();")
    {
        return Err("loader-control admits an automatic desktop selection".to_owned());
    }
    require_source(
        &sources.cargo,
        "\"Win32_System_Diagnostics_Debug\",",
        "Windows debug-event API feature",
    )?;
    require_source(
        &sources.cargo,
        "\"Win32_System_ProcessStatus\",",
        "Windows mapped-module-name API feature",
    )?;
    require_source_order(
        &control,
        &[
            (
                "super::loader_debug::enabled(TargetDesktopBootstrapRoleV1::LoaderControl)",
                "loader-control-only protected trace gate",
            ),
            (
                "PROC_THREAD_ATTRIBUTE_JOB_LIST",
                "atomic Job assignment retained under tracing",
            ),
            (
                "let creation_flags = if loader_debug_trace {",
                "trace-gated creation flags",
            ),
            (
                "| DEBUG_ONLY_THIS_PROCESS",
                "exact-child-only debug relation",
            ),
            (
                "CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT",
                "unchanged production creation flags",
            ),
            (
                "PendingTargetDesktopBootstrapAccept::start(prepared_pipe)",
                "debug/pipe interleaving",
            ),
            (
                "session.drain_until_exit(",
                "exit debug-event drain before process wait",
            ),
            (
                "WaitForSingleObject(control_process.raw(), 30_000)",
                "unchanged production process wait",
            ),
        ],
    )?;
    if control.contains("DEBUG_PROCESS") {
        return Err("loader-control trace includes descendants through DEBUG_PROCESS".to_owned());
    }
    for (source, fragment, invariant) in [
        (
            &sources.process,
            "const CERTIFICATION: [Self; 6] = [",
            "frozen six-cell debugger-relation/loader-snaps certification matrix",
        ),
        (
            &sources.process,
            "explicit-empty-full-observer-snaps-on",
            "explicit-empty full-observer loader-snaps control cell",
        ),
        (
            &sources.process,
            "CreateEnvironmentBlock(&raw mut raw, ptr::null_mut(), 0)",
            "system-only canonical environment source",
        ),
        (
            &sources.process,
            "const LOADER_REQUIRED_ENVIRONMENT_KEYS: [&str; 3] = [\"SystemDrive\", \"SystemRoot\", \"windir\"];",
            "explicit required native startup environment variables",
        ),
        (
            &sources.process,
            "GetProcessMitigationPolicy(",
            "suspended-child mitigation readback",
        ),
        (
            &sources.process,
            "source_token_sha256: loader_snapshot_digest(",
            "source token binding in V4 launch evidence",
        ),
        (
            &sources.process,
            "child_token_sha256: loader_snapshot_digest(",
            "exact child token binding in V4 launch evidence",
        ),
        (
            &sources.process,
            "session.bind_launch_evidence(launch_evidence.clone());",
            "pre-resume V4 launch evidence bound to debug trace",
        ),
        (
            &sources.session_broker,
            "recover_loader_snaps_journal().map_err(|error|",
            "broker-owned incomplete loader-snaps transaction recovery",
        ),
        (
            &sources.process,
            "secondary_loader_snaps_restoration_failure={}",
            "primary loader failure preserved across restoration failure",
        ),
        (
            &sources.process,
            "error.detail.contains(\"loader_trace=v4\")",
            "child V4 trace retained as the matrix's detailed primary evidence",
        ),
        (
            &sources.session_broker,
            "!= Some(&self.journal.applied_value)",
            "loader-snaps compare-before-restore",
        ),
        (
            &sources.session_broker,
            "!= self.journal.prior_value",
            "loader-snaps exact prior-value restoration attestation",
        ),
        (
            &sources.session_broker,
            "if self.applied_value != expected",
            "loader-snaps journal binds the applied bit to its exact prior value",
        ),
        (
            &sources.session_broker,
            "const LOADER_SNAPS_FLAG: u32 = 0x0000_0002;",
            "per-image loader-snaps bit only",
        ),
        (
            &sources.session_broker,
            "CreateOnceStagingFile::create(&staged)",
            "broker-owned retained-handle create-once journal staging",
        ),
        (
            &sources.session_broker,
            "publish_create_once_atomically(file, &path)",
            "broker-owned no-replace retained-handle journal publication",
        ),
        (
            &sources.session_broker,
            "KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY",
            "explicit shared 64-bit IFEO registry view",
        ),
        (
            &sources.loader_debug,
            "minimal-pump-no-remote-read",
            "minimal mandatory debugger pump performs no remote string read",
        ),
        (
            &sources.loader_debug,
            "minimal-pump-no-observation",
            "minimal mandatory debugger pump performs no path observation",
        ),
        (
            &sources.loader_debug,
            "super::package::ephemeral_ci_enabled()\n        && role == super::process::TargetDesktopBootstrapRoleV1::LoaderControl",
            "protected ephemeral-CI loader-control trace gate",
        ),
        (
            &sources.loader_debug,
            "DebugSetProcessKillOnExit(1)",
            "debugger kill-on-exit assertion",
        ),
        (
            &sources.loader_debug,
            "if unsafe { GetCurrentThreadId() } != self.creator_thread_id",
            "same-thread debug-event ownership",
        ),
        (
            &sources.loader_debug,
            "WaitForDebugEventEx(&raw mut event, timeout_millis)",
            "bounded debug-event wait",
        ),
        (
            &sources.loader_debug,
            "ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continuation)",
            "exactly-once debug-event continuation",
        ),
        (
            &sources.loader_debug,
            "code == EXCEPTION_BREAKPOINT as u32 && !self.trace.initial_breakpoint",
            "initial-breakpoint-only continuation",
        ),
        (
            &sources.loader_debug,
            "                } else {\n                    DBG_EXCEPTION_NOT_HANDLED\n                }",
            "non-breakpoint exception propagation",
        ),
        (
            &sources.loader_debug,
            "info.lpBaseOfImage as usize,\n                        true,\n                        info.hFile,\n                        info.lpImageName,\n                        info.fUnicode,",
            "CREATE_PROCESS image-file handle closure",
        ),
        (
            &sources.loader_debug,
            "info.lpBaseOfDll as usize,\n                        false,\n                        info.hFile,\n                        info.lpImageName,\n                        info.fUnicode,",
            "LOAD_DLL image-file handle ownership",
        ),
        (
            &sources.loader_debug,
            "let _ = OwnedHandle::new(file);",
            "minimal mandatory pump closes transferred debug image handles",
        ),
        (
            &sources.loader_debug,
            "K32GetMappedFileNameW(\n            process,\n            base as *const c_void,",
            "mapped-module name resolution by exact base",
        ),
        (
            &sources.loader_debug,
            "ReadProcessMemory(\n            process,\n            remote_image_name.cast_const(),",
            "bounded remote debug image-name pointer fallback",
        ),
        (
            &sources.loader_debug,
            "ReadProcessMemory(\n                    process,\n                    remote.cast(),",
            "loader-snaps debuggee payload capture",
        ),
        (
            &sources.loader_debug,
            "const LOADER_SNAP_EVENT_MAX_BYTES: usize = 1_024;",
            "bounded per-event loader-snaps capture",
        ),
        (
            &sources.loader_debug,
            "const LOADER_SNAP_TOTAL_MAX_BYTES: usize = 8_192;",
            "bounded aggregate loader-snaps capture",
        ),
        (
            &sources.loader_debug,
            "self.trace.record_unload(info.lpBaseOfDll as usize);",
            "unload-to-load accounting",
        ),
        (
            &sources.loader_debug,
            "self.trace.record_unknown_event(other);",
            "unknown debug-event accounting",
        ),
        (
            &sources.loader_debug,
            "canonical.update(b\"memcordon-loader-debug-trace-v4\\0\");",
            "loader trace v4 canonical domain",
        ),
        (
            &sources.loader_debug,
            "LoaderDebugTraceV4::from_loader_evidence(native_loader_access)",
            "admitted graph inventory reuse",
        ),
        (
            &sources.loader_debug,
            "let missing_direct_roots = self",
            "direct loader-root frontier classification",
        ),
        (
            &sources.loader_debug,
            "let blocked_descendants = blocked_hosts",
            "blocked descendant classification",
        ),
        (
            &sources.loader_debug,
            "self.active_modules.remove(&base);",
            "active-at-exit unload accounting",
        ),
        (
            &sources.loader_debug,
            "holder_resources=identity-access-attestation-and-mutation-pin child_inherited_resources=false child_loader_consumption=unproven",
            "holder attestation is not mislabeled as a child loader capability",
        ),
        (
            &sources.loader_debug,
            "const MODULE_TAIL_CAPACITY: usize = 8;",
            "bounded module tail",
        ),
        (
            &sources.loader_debug,
            "const EXCEPTION_TAIL_CAPACITY: usize = 4;",
            "bounded exception tail",
        ),
        (
            &sources.loader_debug,
            "const UNLOAD_TAIL_CAPACITY: usize = 4;",
            "bounded unload tail",
        ),
        (
            &sources.loader_debug,
            "const UNKNOWN_EVENT_TAIL_CAPACITY: usize = 4;",
            "bounded unknown-event tail",
        ),
        (
            &sources.loader_debug,
            "const OBSERVED_HOST_CAPACITY: usize = 32;",
            "bounded observed-host correlation",
        ),
        (
            &sources.loader_debug,
            "const REMOTE_IMAGE_NAME_MAX_UNITS: usize = 512;",
            "bounded untrusted remote image name",
        ),
        (
            &sources.loader_debug,
            "const LOADER_TRACE_DIAGNOSTIC_MAX_BYTES: usize = 8_192;",
            "bounded rendered trace",
        ),
        (
            &sources.pipe,
            "overlapped: Box<OVERLAPPED>,",
            "heap-stable pending accept storage",
        ),
        (
            &sources.pipe,
            "pub(crate) fn cancel_and_drain(&mut self)",
            "explicit pending accept cancellation and drain",
        ),
    ] {
        require_source(source, fragment, invariant)?;
    }
    require_source_order(
        &sources.process,
        &[
            (
                "require_thread_token_absent(unsafe { GetCurrentThread() })",
                "entry thread-token absence",
            ),
            (
                "resolve_native_loader_resources(",
                "holder-primary native loader resolution and source pinning",
            ),
            (
                "require_primary_to_impersonation_authority(",
                "exact duplicate impersonation authority",
            ),
            (
                "ThreadImpersonationGuard::install(impersonation.raw())",
                "exact target impersonation install",
            ),
            (
                "probe_native_loader_access_as_effective_thread(",
                "effective-target native opens",
            ),
            ("guard.revert()", "explicit impersonation reversion"),
            (
                "require_same_token_instance(\n        \"holder-target-association-preflight\"",
                "source target token invariance",
            ),
            (
                ".mark_reverted_and_seal()",
                "post-revert loader evidence sealing",
            ),
        ],
    )?;
    let holder_bootstrap = semantic_function_region(
        &sources.process,
        "fn run_target_desktop_bootstrap(",
        "fn serve_target_desktop_probe(",
    )
    .ok_or_else(|| "target desktop holder has no semantic boundary".to_owned())?;
    require_source_order(
        &holder_bootstrap,
        &[
            (
                "let native_loader_access_lease = serve_holder_target_association_preflight(",
                "holder receives the non-serializable loader lease",
            ),
            (
                "wait_for_target_desktop_bootstrap_release(",
                "launcher child-qualification release boundary",
            ),
            (
                "drop(native_loader_access_lease);",
                "loader lease retained through release",
            ),
        ],
    )?;
    let loader_probe = semantic_function_region(
        &sources.loader_access,
        "pub(crate) fn probe_native_loader_access_as_effective_thread(",
        "fn capture_source_ancestor(",
    )
    .ok_or_else(|| "native loader target probe has no semantic boundary".to_owned())?;
    require_source_order(
        &loader_probe,
        &[
            (
                "let bootstrap_target_identity = probe_final_file_path_retained(",
                "exact-target bootstrap proof before module routing",
            ),
            (
                ") = probe_known_dlls(&resources, budget)?;",
                "KnownDll routing before System32 fallback",
            ),
            (
                "for (module_index, module) in resources.modules.iter().enumerate() {",
                "module evidence after KnownDll classification",
            ),
            (
                ".get(module.concrete_host.as_str())",
                "physical-host disposition lookup",
            ),
            (
                "KnownDllDispositionV1::Section { .. } => {",
                "section-backed route",
            ),
            (
                "KnownDllDispositionV1::FileBacked { not_found_status }",
                "file-backed fallback route",
            ),
        ],
    )?;
    let loader_graph = semantic_function_region(
        &sources.loader_access,
        "fn resolve_loader_graph(",
        "fn admit_source_known_dlls(",
    )
    .ok_or_else(|| "native loader graph has no semantic boundary".to_owned())?;
    require_source_order(
        &loader_graph,
        &[
            (
                "let request = resolve_loader_request(",
                "parent-aware logical/API-set request resolution",
            ),
            (
                "api_set_selections.insert(selection_key, request.concrete_host.clone())",
                "API-set collision confirmation before physical coalescing",
            ),
            (
                "admitted_physical_loader_index(module_indices, &request.concrete_host)",
                "concrete-host lookup before physical admission",
            ),
            (
                "let candidate = admit_physical_loader_module(request, native_machine)?;",
                "one-time physical module admission",
            ),
            (
                "identities.insert(identity, candidate.concrete_host.clone())",
                "new physical identity alias collision check",
            ),
        ],
    )?;
    let section_route = loader_probe
        .split_once("KnownDllDispositionV1::Section { .. } => {")
        .and_then(|(_, suffix)| {
            suffix
                .split_once("KnownDllDispositionV1::FileBacked { not_found_status }")
                .map(|(region, _)| region.to_owned())
        })
        .ok_or_else(|| "section-backed loader route has no semantic boundary".to_owned())?;
    for (fragment, invariant) in [
        (
            "module.source_identity.evidence.clone()",
            "section-backed holder provenance",
        ),
        (
            "module.source_pe_machine",
            "section-backed holder machine proof",
        ),
    ] {
        require_source(&section_route, fragment, invariant)?;
    }
    for forbidden in [
        "probe_final_file_path_retained",
        "CreateFileW",
        "AccessCheck(",
        "Authz",
    ] {
        if section_route.contains(forbidden) {
            return Err(format!(
                "section-backed route performs a surrogate or target file probe: {forbidden}"
            ));
        }
    }
    let file_route = loader_probe
        .split_once("KnownDllDispositionV1::FileBacked { not_found_status }")
        .and_then(|(_, suffix)| {
            suffix
                .split_once("KnownDllDispositionV1::FileBacked { .. } => {")
                .map(|(region, _)| region.to_owned())
        })
        .ok_or_else(|| "file-backed loader route has no semantic boundary".to_owned())?;
    require_source_order(
        &file_route,
        &[
            (
                "not_found_status == STATUS_OBJECT_NAME_NOT_FOUND",
                "exact section-name absence guard",
            ),
            (
                "probe_final_file_path_retained(&module.path, LoaderPathRoleV1::SystemModule)?;",
                "exact-target file-backed module open",
            ),
            (
                "require_same_final_identity(",
                "file-backed final identity relation",
            ),
            (
                "if target_sha256 != module.source_sha256 {",
                "file-backed source digest relation",
            ),
            (
                "target_pe_machine != module.source_pe_machine",
                "file-backed source machine relation",
            ),
            (
                "target_files.push(handle);",
                "file-backed target handle retention",
            ),
        ],
    )?;
    for (fragment, invariant) in [
        (
            "pub(crate) const LOADER_ANCESTOR_IDENTITY_ACCESS: u32 = 0;",
            "zero-access loader ancestor identity mask",
        ),
        (
            "pub(crate) const LOADER_FILE_ACCESS: u32 = 0x0010_00a1;",
            "exact loader file mask",
        ),
        (
            "pub(crate) const KNOWN_DLL_DIRECTORY_ACCESS: u32 = 0x0000_0003;",
            "exact KnownDll directory mask",
        ),
        (
            "pub(crate) const KNOWN_DLL_SECTION_ACCESS: u32 = 0x0000_000d;",
            "exact KnownDll section mask",
        ),
        ("GetSystemDirectoryW", "native System32 discovery"),
        ("RtlGetCurrentPeb", "pinned native API-set schema discovery"),
        (
            "api_set_u32(&bytes, 0)? != 6",
            "exact native API-set schema version",
        ),
        (
            "fn parse_api_set_schema_v6(bytes: &[u8]) -> Result<ApiSetSchemaV6, String>",
            "pure bounded native API-set parser",
        ),
        (
            "api_set_table_end(hash_offset, count, 8, bytes.len(), \"hash table\")?;",
            "bounded native API-set hash table",
        ),
        (
            "if contract_index >= count {",
            "native API-set hash contract-index bound",
        ),
        (
            "if hashed_length == 0 || hashed_length % 2 != 0 || hashed_length > name_length {",
            "native API-set hashed-prefix bound",
        ),
        (
            "fn normalize_api_set_namespace_identifier(",
            "native API-set structural namespace validation",
        ),
        (
            "fn normalize_api_set_hash_prefix(",
            "native API-set exact hash-prefix validation",
        ),
        (
            "let hash_span = if hashed_length == name_length {",
            "native API-set explicit structural hash span",
        ),
        (
            ".rsplit_once('-')\n        .expect(\"validated API-set contract contains its revision separator\")",
            "native API-set final-revision key boundary",
        ),
        (
            "let raw_hash_key = api_set_utf16(bytes, name_offset, hashed_length)?;",
            "native API-set HashedLength key decoding",
        ),
        (
            "let hash_key = normalize_api_set_hash_prefix(",
            "native API-set hash prefix is not reparsed as a whole namespace name",
        ),
        (
            "hash_span == ApiSetHashSpanV6::ProperPrefix && hash_key == request.revision_key",
            "native API-set public revision-prefix classification",
        ),
        (
            "{\n            ApiSetNamespaceKindV6::SchemaComposition\n        } else {",
            "native API-set nonselectable schema composition family",
        ),
        (
            "is_schema_extension_namespace_name(&namespace_name)",
            "native SchemaExt composition family grammar",
        ),
        (
            "hash_keys.insert(hash_key.clone(), namespace_name.clone())",
            "native API-set duplicate lookup-key rejection",
        ),
        (
            "let hash_factor = api_set_u32(bytes, 24)?;",
            "native API-set header hash factor",
        ),
        (
            "hash.wrapping_mul(hash_factor).wrapping_add(u32::from(unit))",
            "native API-set wrapping hash",
        ),
        (
            "if namespace_indices[contract_index] {",
            "native API-set hash namespace permutation",
        ),
        (
            "if hashes[hash_index - 1].hash >= hashes[hash_index].hash {",
            "native API-set strictly sorted hash table",
        ),
        (
            "if hash_entry.hash != expected {",
            "native API-set hash value validation",
        ),
        (
            ".binary_search_by_key(&lookup_hash, |entry| entry.hash)",
            "native API-set hash-table binary lookup",
        ),
        (
            "if contract.hash_key != key {",
            "native API-set post-hash exact-key guard",
        ),
        (
            "contract.namespace_kind != ApiSetNamespaceKindV6::PublicContract",
            "native API-set lookup-time public-family guard",
        ),
        (
            "probe_api_set_contract(schema, &request.revision_key)",
            "native API-set single exact revision-prefix probe",
        ),
        (
            "let alias = api_set_utf16(bytes, api_set_u32(bytes, value + 4)?, alias_length)?;",
            "native API-set value Name field is parent alias",
        ),
        (
            "let host = api_set_utf16(bytes, api_set_u32(bytes, value + 12)?, host_length)?;\n                let host = normalize_api_set_host(&host)",
            "native API-set value Value field is physical host",
        ),
        (
            "fn is_api_set_name(name: &str) -> bool {\n    parse_api_set_request(name).is_ok()\n}",
            "strict public API-set request classification for graph and host routing",
        ),
        (
            "ApiSetHostV6::Unhosted",
            "explicit native API-set unhosted state",
        ),
        (
            "let host = if host_length == 0 {\n                api_set_utf16(bytes, api_set_u32(bytes, value + 12)?, host_length)?;\n                ApiSetHostV6::Unhosted",
            "zero API-set value length preserved as unhosted",
        ),
        (
            "let mapping = if values.is_empty() {\n            ApiSetMappingV6::Unhosted",
            "zero API-set value count preserved as unhosted",
        ),
        (
            ".enumerate()\n        .skip(1)\n        .find(|(_, value)| value.parent_alias.as_deref() == Some(parent_key))",
            "ordinal parent override search after default",
        ),
        (
            "match &selection.value.host {\n        ApiSetHostV6::Hosted(host) => Ok(ApiSetResolvedHostV6 {",
            "reached selected API-set unhosted rejection",
        ),
        (
            "ApiSetHostV6::Unhosted => Err(format!(\n            \"API-set requested_contract",
            "selected API-set unhosted value rejection",
        ),
        (
            "value.parent_alias.as_deref() == Some(parent_key)",
            "parent-aware API-set host selection",
        ),
        (
            "api_set_schema.sha256.clone(),\n                parent_key,\n                selection.hash_key.clone(),",
            "schema-parent-selected-key API-set cache identity",
        ),
        ("NtOpenDirectoryObject", "KnownDll directory open"),
        ("NtOpenSection", "KnownDll section open"),
        ("NtQuerySection", "KnownDll SEC_IMAGE query"),
        (
            "CompareObjectHandles",
            "source/target KnownDll object binding",
        ),
        (
            "CompareObjectHandles(source_handle.raw(), target_handle.raw())",
            "holder/target section kernel-object identity",
        ),
        ("const SEC_IMAGE: u32 = 0x0100_0000;", "exact SEC_IMAGE bit"),
        (
            "information.allocation_attributes & SEC_IMAGE == 0",
            "section SEC_IMAGE enforcement",
        ),
        (
            "const SECTION_IMAGE_INFORMATION_CLASS: u32 = 1;",
            "section image-information class",
        ),
        (
            "information.machine != native_machine",
            "native section machine enforcement",
        ),
        (
            "target_image_information.machine != source.image_machine",
            "source/target section image metadata relation",
        ),
        (
            "STATUS_OBJECT_NAME_NOT_FOUND",
            "file-backed KnownDll absence classification",
        ),
        (
            "if status == STATUS_OBJECT_NAME_NOT_FOUND {\n        return Ok((status, None));",
            "exact sole KnownDll file-fallback status",
        ),
        (
            "repair_scope: \"external-never-repair\"",
            "external resources are never repaired",
        ),
        (
            "install_ancestors.push(capture_source_ancestor(path, *role)?);",
            "holder-primary install-ancestor identity pin",
        ),
        (
            "system_ancestors.push(capture_source_ancestor(path, *role)?);",
            "holder-primary system-ancestor identity pin",
        ),
        (
            "let bootstrap_target_identity = probe_final_file_path_retained(",
            "exact-target bootstrap full-path access probe",
        ),
        (
            "probe_final_file_path_retained(&module.path, LoaderPathRoleV1::SystemModule)?;",
            "exact-target file-backed native module full-path access probe",
        ),
        (
            "if evidence.requested_access != LOADER_ANCESTOR_IDENTITY_ACCESS {",
            "exact zero ancestor requested-access validation",
        ),
        (
            "validate_file_access_evidence(&self.bootstrap_file, LOADER_FILE_ACCESS)?;",
            "bootstrap leaf access evidence validation",
        ),
        (
            "validate_file_access_evidence(&module.file, LOADER_FILE_ACCESS)?;",
            "native module leaf access evidence validation",
        ),
        (
            "const LOADER_PIN_SHARE_MODE: u32 = FILE_SHARE_READ;",
            "source and target mutation-resistant share mode",
        ),
        (
            "probe_path_retained(path, role, LOADER_FILE_ACCESS, false)",
            "final-file access handle contract",
        ),
        (
            "let observed_bootstrap_sha256 = sha256_bytes(&bootstrap_target_bytes);",
            "target-handle bootstrap identity hash",
        ),
        (
            ") = probe_known_dlls(&resources, budget)?;",
            "retained KnownDll directory and section probes",
        ),
        (
            "retained_sections.push(target_handle);",
            "successful exact-target KnownDll section retention",
        ),
        (
            "target_files.push(handle);",
            "file-backed exact-target handle retention",
        ),
        (
            "if target_sha256 != module.source_sha256 {",
            "holder-source to target-final content binding",
        ),
        (
            "target_pe_machine != module.source_pe_machine",
            "holder-source to target-final machine binding",
        ),
        (
            "while let Some((phase, parent_host)) = queue.pop_front() {\n        if Instant::now() >= overall_deadline",
            "depth-independent recursive loader-graph closure",
        ),
        (
            "for symbol in &descriptor.symbols {\n                let origin_symbol = LoaderSymbolKey::from_import(symbol).evidence();",
            "reachable imported-symbol-only walk",
        ),
        (
            "let memcordon_core::WindowsPeExportTarget::Forwarder(value) = current_export",
            "reachable export-forwarder walk",
        ),
        (
            "let mut active = BTreeMap::<ForwarderNodeKey, usize>::new();",
            "per-chain pinned physical-host and exact-symbol cycle set",
        ),
        (
            "BTreeMap::<ForwarderNodeKey, Vec<ForwarderEdgeTemplate>>::new();",
            "completed exact forwarder-state memo",
        ),
        (
            "completed_forwarders.get(&current_key).cloned()",
            "completed forwarder suffix reuse",
        ),
        (
            "\"export-forwarder-cycle\"",
            "true forwarder-cycle diagnostic",
        ),
        (
            "\"export-forwarder-hop-bound\"",
            "separate forwarder-hop-bound diagnostic",
        ),
        ("export_name == name", "case-sensitive named-export lookup"),
        (
            "if edges.contains_key(&identity)",
            "logical edge coalescing before accounting",
        ),
        (
            "let shortest_depths = loader_graph_shortest_depths(&self.loader_roots, &self.loader_edges);",
            "phase-local shortest physical-host depth validation",
        ),
        (
            "canonicalize_loader_edge_depths(&roots, &mut edges, system_directory)?",
            "post-closure canonical edge depths",
        ),
        (
            "const MAX_LOADER_GRAPH_DEPTH: usize = 16;",
            "loader graph depth bound",
        ),
        (
            "const MAX_LOADER_FORWARDER_HOPS: usize = 16;",
            "independent forwarder hop bound",
        ),
        (
            "const MAX_LOADER_MODULES: usize = 128;",
            "loader graph node bound",
        ),
        (
            "NativeLoaderProgressStage::SourceLoaderGraph,\n            modules.len(),\n            None,",
            "dynamic loader graph admissions retain unknown exact total",
        ),
        (
            "NativeLoaderProgressStage::SourceLoaderGraph,\n        modules.len(),\n        Some(modules.len()),",
            "dynamic loader graph emits one exact closure",
        ),
        (
            "budget.check_deadline(\n            NativeLoaderProgressStage::SourceKnownDlls,",
            "source KnownDll pre-unit deadline check does not publish a no-op",
        ),
        (
            "budget.check_deadline(\n            NativeLoaderProgressStage::TargetKnownDlls,",
            "target KnownDll pre-unit deadline check does not publish a no-op",
        ),
        (
            "completed progress is not representable as u32",
            "progress completed conversion fails closed",
        ),
        (
            "total progress is not representable as u32",
            "progress total conversion fails closed",
        ),
        (
            "const MAX_LOADER_GRAPH_EDGES: usize = 1_024;",
            "loader graph edge bound",
        ),
        (
            "parse_windows_pe_mapped_loader_contract(bytes)",
            "KnownDll graph parsed from mapped section",
        ),
        (
            "mapped_loader_contract_sha256 != source_contract.source_loader_contract_sha256",
            "mapped section contract bound to pinned System32 bytes",
        ),
        (
            "source.mapped_loader_contract_sha256.as_deref()",
            "source and exact-target mapped section contract relation",
        ),
        (
            "fn attest_executable_section_map(",
            "separate executable KnownDll mapping stage",
        ),
        (
            "MapViewOfFile(section, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, 0, size)",
            "explicit read-plus-execute map access",
        ),
        (
            "validate_exact_target_import_tier_canary(&known_dll_sections)?;",
            "exact-target core-versus-ADVAPI access/map canary",
        ),
        (
            "[\"NTDLL.DLL\", \"KERNEL32.DLL\", \"ADVAPI32.DLL\"]",
            "core and first non-core direct-root canary inventory",
        ),
        (
            "loader_graph_digests(&self.loader_roots, &self.loader_edges, &self.system_modules)",
            "loader graph evidence digest",
        ),
        (
            "canonical.extend_from_slice(loader_symbol_name(symbol).as_bytes());",
            "thunk identity included in loader contract digest",
        ),
        (
            "they are non-inheritable and are not child loader capabilities",
            "retained holder resources have attestation-only child semantics",
        ),
    ] {
        require_source(&sources.loader_access, fragment, invariant)?;
    }
    for (fragment, invariant) in [
        (
            "pub struct WindowsPeImportDescriptor",
            "ordered PE import descriptor model",
        ),
        (
            "pub enum WindowsPeImportSymbol",
            "named and ordinal PE thunk model",
        ),
        (
            "WindowsPeExportTarget::Forwarder",
            "PE export forwarder classification",
        ),
        (
            "descriptors.push(WindowsPeImportDescriptor",
            "descriptor order preservation",
        ),
        (
            "let mut descriptors = Vec::new();",
            "ordered descriptor accumulator",
        ),
        (
            "pub fn parse_windows_pe_mapped_loader_contract(",
            "mapped-image PE contract parser",
        ),
    ] {
        require_source(&sources.pe, fragment, invariant)?;
    }
    for (fragment, invariant) in [
        (
            "LoaderDebugTraceV4::from_loader_evidence(native_loader_access)",
            "trace closure sourced from loader graph evidence",
        ),
        (
            "closure-hosts-all-observed:initialization-unresolved",
            "complete closure does not claim initializer success",
        ),
        (
            "let frontier_edges = self",
            "graph-aware bounded frontier classification",
        ),
        (
            "missing_direct_roots=[{}] edge_frontier=[{}] blocked_descendants=[{}]",
            "V4 root and downstream frontier schema",
        ),
        (
            "ever_mapped=[{}] active_at_exit=[{}]",
            "V4 historical and terminal module-state split",
        ),
        (
            "exact_token_import_tier_canary=core-ntdll-kernel32:read-execute-map-attested,advapi32:read-execute-map-attested",
            "V4 exact-token tier-canary schema",
        ),
    ] {
        require_source(&sources.loader_debug, fragment, invariant)?;
    }
    let graph_edge_canonical = semantic_function_region(
        &sources.loader_access,
        "fn graph_edge_canonical(edge: &LoaderImportEdgeEvidenceV2) -> Vec<u8> {",
        "fn graph_edge_identity_canonical(edge: &LoaderImportEdgeEvidenceV2) -> Vec<u8> {",
    )
    .ok_or_else(|| "loader graph edge canonicalization has no semantic boundary".to_owned())?;
    for (fragment, invariant) in [
        (
            "edge.parent_host.to_ascii_uppercase()",
            "edge parent identity",
        ),
        (
            "edge.descriptor_ordinal.unwrap_or(u32::MAX)",
            "descriptor ordinal identity",
        ),
        (
            "edge.requested_symbol.as_deref().unwrap_or(\"\")",
            "requested thunk identity",
        ),
        (
            "edge.concrete_host.to_ascii_uppercase()",
            "concrete host identity",
        ),
        (
            "edge.resolved_target_symbol.as_deref().unwrap_or(\"\")",
            "forwarder target identity",
        ),
    ] {
        require_source(&graph_edge_canonical, fragment, invariant)?;
    }
    for forbidden in [
        "SetNamedSecurityInfo",
        "SetFileSecurity",
        "SetSecurityInfo",
        "AccessCheck(",
        "AuthzAccessCheck",
    ] {
        if sources.loader_access.contains(forbidden) {
            return Err(format!(
                "native loader preflight mutates ACLs through {forbidden}"
            ));
        }
    }
    let bootstrap_entry = semantic_function_region(
        &sources.process,
        "pub(super) fn target_desktop_bootstrap(",
        "fn started_failure_frame_publication_is_safe(bytes_transferred: usize) -> bool {",
    )
    .ok_or_else(|| "target desktop bootstrap entry has no semantic boundary".to_owned())?;
    require_source_order(
        &bootstrap_entry,
        &[
            (
                "TargetDesktopBootstrapRoleV1::LoaderControl | TargetDesktopBootstrapRoleV1::Probe",
                "desktop-bearing bootstrap roles",
            ),
            (
                "validate_target_desktop_binding(window_station, desktop)?;",
                "canonical desktop argument validation",
            ),
            (
                "TargetDesktopBootstrapPipeOperation::LoaderReadyWrite",
                "LoaderReady before role-specific work",
            ),
            (
                "if role == TargetDesktopBootstrapRoleV1::LoaderControl",
                "loader-control release boundary after LoaderReady",
            ),
            (
                "TargetDesktopBootstrapPipeOperation::LoaderControlReleaseRead",
                "typed loader-control release read",
            ),
            (
                "Some(observed_desktop.as_str()) == expected_desktop_name.as_deref()",
                "release canonical desktop binding",
            ),
        ],
    )?;
    let pre_loader_ready = bootstrap_entry
        .split_once("TargetDesktopBootstrapPipeOperation::LoaderReadyWrite")
        .map(|(prefix, _)| prefix)
        .ok_or_else(|| "LoaderReady publication is absent".to_owned())?;
    for forbidden in [
        "super::user_api::load()",
        "GetProcessWindowStation(",
        "GetThreadDesktop(",
        "OpenWindowStationW(",
        "OpenDesktopW(",
        "SetProcessWindowStation(",
        "SetThreadDesktop(",
    ] {
        if pre_loader_ready.contains(forbidden) {
            return Err(format!(
                "loader-control performs explicit USER/GDI work before LoaderReady: {forbidden}"
            ));
        }
    }
    for (source, fragment, label) in [
        (
            &sources.process,
            "LoaderReady {\n        schema_version: u32,\n        nonce: String,\n        expected_desktop: Option<String>,",
            "desktop-bound LoaderReady schema",
        ),
        (
            &sources.process,
            "LoaderControlRelease {\n        schema_version: u32,\n        nonce: String,\n        expected_desktop: String,",
            "bounded nonce-and-desktop-bound loader-control release schema",
        ),
        (
            &sources.process,
            "desktop_heap_kb: u32,",
            "desktop heap preflight evidence",
        ),
        (
            &sources.process,
            "GetUserObjectInformationW(\n            desktop,\n            UOI_HEAPSIZE_CLASS,",
            "read-only UOI_HEAPSIZE query",
        ),
        (
            &sources.process,
            "loader_control=loader-ready loader_control_desktop_sha256={}",
            "Probe diagnostic binds successful control",
        ),
        (
            &sources.process,
            "pre-bootstrap-connect-exit:{:#010x}",
            "precise pre-bootstrap-connect exit diagnostic",
        ),
        (
            &sources.pipe,
            "LoaderControlReleaseRead,",
            "typed loader-control release read operation",
        ),
        (
            &sources.pipe,
            "LoaderControlReleaseWrite,",
            "typed loader-control release write operation",
        ),
        (
            &sources.package_schema,
            "target_desktop_bootstrap_crt_static: bool,",
            "package static CRT evidence",
        ),
        (
            &sources.package_schema,
            "target_desktop_bootstrap_normal_imports: Vec<String>,",
            "package normal import inventory",
        ),
        (
            &sources.package_schema,
            "target_desktop_bootstrap_delayed_imports: Vec<String>,",
            "package delayed import inventory",
        ),
        (
            &sources.package_schema,
            "target_desktop_bootstrap_loader_contract_sha256: String,",
            "package loader-contract digest",
        ),
        (
            &sources.pe,
            "name.starts_with(\"VCRUNTIME\")",
            "dynamic MSVC CRT rejection",
        ),
        (
            &sources.pe,
            "name.starts_with(\"API-MS-WIN-CRT-\")",
            "dynamic UCRT API-set rejection",
        ),
        (
            &sources.pe,
            "name.as_str() == \"MSVCRT.DLL\"",
            "dynamic legacy CRT rejection",
        ),
    ] {
        require_source(source, fragment, label)?;
    }
    for target in ["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"] {
        require_source(
            &sources.cargo_config,
            &format!("[target.{target}]\nrustflags = [\"-C\", \"target-feature=+crt-static\"]"),
            "repository Windows static CRT target",
        )?;
        require_source(
            &sources.sealed_windows,
            target,
            "packaged-source Windows static CRT target",
        )?;
        require_source(
            &sources.release,
            target,
            "release smoke Windows static CRT target",
        )?;
    }
    for source in [
        &sources.cargo_config,
        &sources.sealed_windows,
        &sources.release,
    ] {
        require_source(
            source,
            "target-feature=+crt-static",
            "Windows static CRT compiler selection",
        )?;
    }
    Ok(())
}

#[test]
fn windows_loader_control_and_static_crt_mutations_are_rejected() {
    let sources = WindowsLoaderControlContractSources::load();
    validate_windows_loader_control_contract(&sources)
        .expect("unmutated loader-control/static-CRT contract must be complete");

    for (source, exact, replacement, mutant) in [
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "budget.check(\n            NativeLoaderProgressStage::SourceLoaderGraph,\n            modules.len(),\n            None,\n        )?;",
            "budget.check(\n            NativeLoaderProgressStage::SourceLoaderGraph,\n            modules.len(),\n            Some(MAX_LOADER_MODULES),\n        )?;",
            "loader-graph-cap-mislabeled-as-progress-total",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "budget.check_deadline(\n            NativeLoaderProgressStage::SourceKnownDlls,",
            "budget.check(\n            NativeLoaderProgressStage::SourceKnownDlls,",
            "source-known-dll-no-op-progress-restored",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "budget.check_deadline(\n            NativeLoaderProgressStage::TargetKnownDlls,",
            "budget.check(\n            NativeLoaderProgressStage::TargetKnownDlls,",
            "target-known-dll-no-op-progress-restored",
        ),
        (
            WindowsLoaderControlContractSource::Process,
            "    launch_target_desktop_loader_control(\n        target_token,",
            "    loader_control_removed(\n        target_token,",
            "loader-control-call-removed",
        ),
        (
            WindowsLoaderControlContractSource::Process,
            "startup.StartupInfo.lpDesktop = loader_control_desktop.as_mut_ptr();",
            "startup.StartupInfo.lpDesktop = ptr::null_mut();",
            "loader-control-private-desktop-null",
        ),
        (
            WindowsLoaderControlContractSource::Process,
            "let mut loader_control_desktop = exact_desktop.encode_utf16().collect::<Vec<_>>();",
            "let mut loader_control_desktop = [0_u16];",
            "loader-control-private-desktop-emptied",
        ),
        (
            WindowsLoaderControlContractSource::Process,
            "        \"loader-control\".encode_utf16().collect(),\n        pipe_name.encode_utf16().collect(),\n        nonce.encode_utf16().collect(),\n        exact_desktop.encode_utf16().collect(),",
            "        \"loader-control\".encode_utf16().collect(),\n        pipe_name.encode_utf16().collect(),\n        nonce.encode_utf16().collect(),",
            "loader-control-canonical-cli-argument-removed",
        ),
        (
            WindowsLoaderControlContractSource::Process,
            "        target_snapshot,\n        exact_desktop,\n        launch_context,\n        &association_preflight,",
            "        target_snapshot,\n        \"\",\n        launch_context,\n        &association_preflight,",
            "loader-control-canonical-call-binding-removed",
        ),
        (
            WindowsLoaderControlContractSource::Process,
            "                && observed_desktop.as_deref() == Some(exact_desktop)\n                && bootstrap_identity == control_identity",
            "                && bootstrap_identity == control_identity",
            "loader-ready-canonical-desktop-binding-removed",
        ),
        (
            WindowsLoaderControlContractSource::Process,
            "LoaderReady {\n        schema_version: u32,\n        nonce: String,\n        expected_desktop: Option<String>,",
            "LoaderReady {\n        schema_version: u32,\n        nonce: String,",
            "loader-ready-desktop-schema-binding-removed",
        ),
        (
            WindowsLoaderControlContractSource::Process,
            "            validate_target_desktop_binding(window_station, desktop)?;",
            "            let _ = (window_station, desktop);",
            "loader-control-canonical-desktop-validation-removed",
        ),
        (
            WindowsLoaderControlContractSource::Process,
            "                && Some(observed_desktop.as_str()) == expected_desktop_name.as_deref()",
            "                && !observed_desktop.is_empty()",
            "loader-release-canonical-desktop-binding-removed",
        ),
        (
            WindowsLoaderControlContractSource::Process,
            "TargetDesktopBootstrapPipeOperation::LoaderReadyWrite",
            "TargetDesktopBootstrapPipeOperation::AdmissionWrite",
            "loader-ready-conflated-with-admission",
        ),
        (
            WindowsLoaderControlContractSource::Process,
            "    launch_target_desktop_loader_control(\n        target_token,\n        target_envelope,\n        target_snapshot,\n        exact_desktop,\n        launch_context,\n        &association_preflight,\n        &holder_lease.bootstrap_identity,\n    )?;\n    holder_lease\n        .attest_live()\n        .map_err(TargetDesktopLeaseCreateError::from)?;",
            "    holder_lease\n        .attest_live()\n        .map_err(TargetDesktopLeaseCreateError::from)?;\n    launch_target_desktop_loader_control(\n        target_token,\n        target_envelope,\n        target_snapshot,\n        exact_desktop,\n        launch_context,\n        &association_preflight,\n        &holder_lease.bootstrap_identity,\n    )?;",
            "holder-liveness-reordered-before-loader-control",
        ),
        (
            WindowsLoaderControlContractSource::Process,
            "TargetDesktopBootstrapPipeOperation::LoaderControlReleaseWrite",
            "TargetDesktopBootstrapPipeOperation::AdmissionWrite",
            "loader-control-release-confused",
        ),
        (
            WindowsLoaderControlContractSource::Process,
            "control_job.wait_empty(",
            "control_job_mutant.wait_empty(",
            "loader-control-job-empty-proof-removed",
        ),
        (
            WindowsLoaderControlContractSource::Process,
            "UOI_HEAPSIZE_CLASS,",
            "UOI_IO,",
            "desktop-heap-evidence-removed",
        ),
        (
            WindowsLoaderControlContractSource::Process,
            "let creation_flags = if loader_debug_trace {",
            "let creation_flags = if true {",
            "loader-debug-made-unconditional",
        ),
        (
            WindowsLoaderControlContractSource::Process,
            "const CERTIFICATION: [Self; 6] = [",
            "const CERTIFICATION: [Self; 5] = [",
            "loader-control-six-cell-matrix-truncated",
        ),
        (
            WindowsLoaderControlContractSource::Process,
            "CreateEnvironmentBlock(&raw mut raw, ptr::null_mut(), 0)",
            "CreateEnvironmentBlock(&raw mut raw, target_token, 1)",
            "loader-environment-inherits-privileged-context",
        ),
        (
            WindowsLoaderControlContractSource::SessionBroker,
            "recover_loader_snaps_journal().map_err(|error| {",
            "Ok::<(), LoaderSnapsFailureV2>(()).map_err(|error| {",
            "loader-snaps-broker-startup-recovery-removed",
        ),
        (
            WindowsLoaderControlContractSource::SessionBroker,
            "!= Some(&self.journal.applied_value)",
            "false",
            "loader-snaps-compare-before-restore-removed",
        ),
        (
            WindowsLoaderControlContractSource::SessionBroker,
            "!= self.journal.prior_value",
            "if false",
            "loader-snaps-restoration-readback-removed",
        ),
        (
            WindowsLoaderControlContractSource::SessionBroker,
            "if self.applied_value != expected",
            "if false",
            "loader-snaps-journal-applied-relation-removed",
        ),
        (
            WindowsLoaderControlContractSource::SessionBroker,
            "const LOADER_SNAPS_FLAG: u32 = 0x0000_0002;",
            "const LOADER_SNAPS_FLAG: u32 = u32::MAX;",
            "loader-snaps-global-flag-widened",
        ),
        (
            WindowsLoaderControlContractSource::SessionBroker,
            "publish_create_once_atomically(file, &path)",
            "replace_atomically(&staged, &path)",
            "loader-snaps-journal-path-reopen-restored",
        ),
        (
            WindowsLoaderControlContractSource::SessionBroker,
            "KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY",
            "KEY_QUERY_VALUE | KEY_SET_VALUE",
            "loader-snaps-explicit-registry-view-removed",
        ),
        (
            WindowsLoaderControlContractSource::Process,
            "error.detail.contains(\"loader_trace=v4\")",
            "false",
            "loader-matrix-child-trace-selection-removed",
        ),
        (
            WindowsLoaderControlContractSource::Process,
            "            | DEBUG_ONLY_THIS_PROCESS",
            "            | DEBUG_PROCESS",
            "loader-debug-descendants-included",
        ),
        (
            WindowsLoaderControlContractSource::LoaderDebug,
            "super::package::ephemeral_ci_enabled()",
            "true",
            "loader-debug-protected-gate-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderDebug,
            "        if unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continuation) } == 0",
            "        if continuation == 0",
            "loader-debug-continuation-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderDebug,
            "                } else {\n                    DBG_EXCEPTION_NOT_HANDLED\n                }",
            "                } else {\n                    DBG_CONTINUE\n                }",
            "loader-debug-arbitrary-exception-swallowed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderDebug,
            "                        info.lpBaseOfImage as usize,\n                        true,\n                        info.hFile,\n                        info.lpImageName,\n                        info.fUnicode,",
            "                        info.lpBaseOfImage as usize,\n                        true,\n                        std::ptr::null_mut(),\n                        info.lpImageName,\n                        info.fUnicode,",
            "loader-debug-create-file-handle-leaked",
        ),
        (
            WindowsLoaderControlContractSource::LoaderDebug,
            "let _ = OwnedHandle::new(file);",
            "let _minimal_pump_file_handle_leak = file;",
            "loader-minimal-pump-file-handle-leaked",
        ),
        (
            WindowsLoaderControlContractSource::LoaderDebug,
            "K32GetMappedFileNameW(\n            process,\n            base as *const c_void,",
            "K32GetMappedFileNameW(\n            process,\n            std::ptr::null(),",
            "loader-debug-mapped-base-correlation-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderDebug,
            "self.trace.record_unload(info.lpBaseOfDll as usize);",
            "self.trace\n                    .canonical_field(UNLOAD_DLL_DEBUG_EVENT, &[]);",
            "loader-debug-unload-accounting-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderDebug,
            "self.trace.record_unknown_event(other);",
            "self.trace.canonical_field(other, &[]);",
            "loader-debug-unknown-event-accounting-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderDebug,
            "remote.cast(),",
            "std::ptr::null(),",
            "loader-snaps-payload-capture-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderDebug,
            "const LOADER_SNAP_EVENT_MAX_BYTES: usize = 1_024;",
            "const LOADER_SNAP_EVENT_MAX_BYTES: usize = usize::MAX;",
            "loader-snaps-event-bound-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderDebug,
            "const LOADER_SNAP_TOTAL_MAX_BYTES: usize = 8_192;",
            "const LOADER_SNAP_TOTAL_MAX_BYTES: usize = usize::MAX;",
            "loader-snaps-total-bound-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderDebug,
            "canonical.update(b\"memcordon-loader-debug-trace-v4\\0\");",
            "canonical.update(b\"memcordon-loader-debug-trace-v2\\0\");",
            "loader-debug-v4-domain-rolled-back",
        ),
        (
            WindowsLoaderControlContractSource::LoaderDebug,
            "const REMOTE_IMAGE_NAME_MAX_UNITS: usize = 512;",
            "const REMOTE_IMAGE_NAME_MAX_UNITS: usize = usize::MAX;",
            "loader-debug-remote-image-name-unbounded",
        ),
        (
            WindowsLoaderControlContractSource::Pipe,
            "overlapped: Box<OVERLAPPED>,",
            "overlapped: OVERLAPPED,",
            "loader-debug-overlapped-storage-movable",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "pub(crate) const LOADER_ANCESTOR_IDENTITY_ACCESS: u32 = 0;",
            "pub(crate) const LOADER_ANCESTOR_IDENTITY_ACCESS: u32 = 0x0010_00a0;",
            "native-loader-ancestor-final-object-access-reintroduced",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "admitted_physical_loader_index(module_indices, &request.concrete_host)",
            "module_indices.get(&request.concrete_host).copied()",
            "native-loader-physical-admission-dedup-bypassed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "install_ancestors.push(capture_source_ancestor(path, *role)?);",
            "install_ancestors.push(probe_final_file_path_retained(path, *role)?);",
            "native-loader-install-ancestor-moved-to-target-final probe",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "system_ancestors.push(capture_source_ancestor(path, *role)?);",
            "system_ancestors.push(probe_final_file_path_retained(path, *role)?);",
            "native-loader-system-ancestor-moved-to-target-final probe",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "const LOADER_PIN_SHARE_MODE: u32 = FILE_SHARE_READ;",
            "const LOADER_PIN_SHARE_MODE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;",
            "native-loader-mutation-pin-sharing-weakened",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "pub(crate) const LOADER_FILE_ACCESS: u32 = 0x0010_00a1;",
            "pub(crate) const LOADER_FILE_ACCESS: u32 = 0x0010_00a0;",
            "native-loader-file-execute-bit-removed",
        ),
        (
            WindowsLoaderControlContractSource::Process,
            "super::loader_access::probe_native_loader_access_as_effective_thread(",
            "native_loader_probe_removed(",
            "native-loader-effective-token-probe-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "let bootstrap_target_identity = probe_final_file_path_retained(",
            "let bootstrap_target_identity = capture_source_final_file(",
            "native-loader-bootstrap-full-path-probe-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "probe_final_file_path_retained(&module.path, LoaderPathRoleV1::SystemModule)?;",
            "module.source_identity.evidence.clone();",
            "file-fallback-target-probe-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "module.source_identity.evidence.clone()",
            "probe_final_file_path_retained(&module.path, LoaderPathRoleV1::SystemModule)?.evidence",
            "section-backed-file-probe-added",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            ") = probe_known_dlls(&resources, budget)?;",
            ") = probe_known_dlls_after_module_loop(&resources)?;",
            "known-dll-probe-moved-below-module-loop",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            ".get(module.concrete_host.as_str())",
            ".get(module.import_contract.as_str())",
            "api-set-virtual-name-used-for-known-dll",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "if status == STATUS_OBJECT_NAME_NOT_FOUND {\n        return Ok((status, None));",
            "if status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_ACCESS_DENIED {\n        return Ok((status, None));",
            "known-dll-denial-treated-as-absence",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "require_same_final_identity(\n                    &module.path,\n                    &module.source_identity,\n                    &target_identity,\n                )?;",
            "let _ = (&module.source_identity, &target_identity);",
            "native-loader-final-identity-binding-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "if target_sha256 != module.source_sha256 {",
            "if false {",
            "native-loader-target-hash-binding-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "target_pe_machine != module.source_pe_machine",
            "target_pe_machine == module.source_pe_machine",
            "native-loader-target-machine-binding-inverted",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "retained_sections.push(target_handle);",
            "drop(target_handle);",
            "known-dll-section-handle-retention-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "CompareObjectHandles(source_handle.raw(), target_handle.raw())",
            "1",
            "known-dll-section-object-comparison-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "information.allocation_attributes & SEC_IMAGE == 0",
            "false",
            "known-dll-section-sec-image-check-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "information.machine != native_machine",
            "false",
            "known-dll-section-machine-check-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "target_image_information.machine != source.image_machine",
            "false",
            "known-dll-section-source-target-metadata-check-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "MapViewOfFile(section, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, 0, size)",
            "MapViewOfFile(section, FILE_MAP_READ, 0, 0, size)",
            "known-dll-execute-map-stage-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "validate_exact_target_import_tier_canary(&known_dll_sections)?;",
            "let _ = &known_dll_sections;",
            "exact-target-import-tier-canary-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "[\"NTDLL.DLL\", \"KERNEL32.DLL\", \"ADVAPI32.DLL\"]",
            "[\"NTDLL.DLL\", \"KERNEL32.DLL\", \"KERNELBASE.DLL\"]",
            "advapi-import-tier-canary-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "target_files.push(handle);",
            "drop(handle);",
            "file-backed-target-handle-retention-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "while let Some((phase, parent_host)) = queue.pop_front() {\n        if Instant::now() >= overall_deadline",
            "if let Some((phase, parent_host)) = queue.pop_front() {\n        if !expanded.insert",
            "loader-graph-recursion-stopped-after-one-node",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "let memcordon_core::WindowsPeExportTarget::Forwarder(value) = current_export",
            "let memcordon_core::WindowsPeExportTarget::DirectRva(value) = current_export",
            "reachable-forwarder-traversal-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "for symbol in &descriptor.symbols {\n                let origin_symbol = LoaderSymbolKey::from_import(symbol).evidence();",
            "for symbol in std::iter::empty() {\n                let origin_symbol = LoaderSymbolKey::from_import(symbol).evidence();",
            "reachable-imported-symbol-walk-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "let mut active = BTreeMap::<ForwarderNodeKey, usize>::new();",
            "let mut active = BTreeSet::<String>::new();",
            "forwarder-cycle-symbol-identity-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "completed_forwarders.get(&current_key).cloned()",
            "None::<Vec<ForwarderEdgeTemplate>>",
            "forwarder-completed-memo-reuse-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "const MAX_LOADER_FORWARDER_HOPS: usize = 16;",
            "const MAX_LOADER_FORWARDER_HOPS: usize = usize::MAX;",
            "forwarder-hop-bound-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "export_name == name",
            "export_name.eq_ignore_ascii_case(name)",
            "named-export-case-folded",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "value.parent_alias.as_deref() == Some(parent_key)",
            "value.parent_alias.is_none()",
            "api-set-parent-alias-ignored",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "api_set_u32(&bytes, 0)? != 6",
            "api_set_u32(&bytes, 0)? != 5",
            "api-set-schema-version-weakened",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "api_set_table_end(hash_offset, count, 8, bytes.len(), \"hash table\")?;",
            "let _ = hash_offset;",
            "api-set-hash-table-bound-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "if contract_index >= count {",
            "if false {",
            "api-set-hash-index-bound-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "if hashed_length == 0 || hashed_length % 2 != 0 || hashed_length > name_length {",
            "if false {",
            "api-set-hashed-prefix-bound-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "if hashed_length == 0 || hashed_length % 2 != 0 || hashed_length > name_length {",
            "if hashed_length == 0 || hashed_length % 2 != 0 || hashed_length >= name_length {",
            "api-set-equal-hashed-prefix-rejected",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            ".rsplit_once('-')",
            ".split_once('-')",
            "api-set-final-revision-key-boundary-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "api_set_utf16(bytes, name_offset, hashed_length)?",
            "api_set_utf16(bytes, name_offset, name_length)?",
            "api-set-hashed-length-key-decoding-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "let hash_key = normalize_api_set_hash_prefix(",
            "let hash_key = normalize_api_set_namespace_identifier(",
            "api-set-hash-prefix-reparsed-as-whole-namespace-name",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "hash_span == ApiSetHashSpanV6::ProperPrefix && hash_key == request.revision_key",
            "hash_span == ApiSetHashSpanV6::ProperPrefix",
            "api-set-public-declared-revision-key-relation-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "hash_keys.insert(hash_key.clone(), namespace_name.clone())",
            "hash_keys.get(&hash_key).cloned()",
            "api-set-duplicate-lookup-key-rejection-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "{\n            ApiSetNamespaceKindV6::SchemaComposition\n        } else {",
            "{\n            ApiSetNamespaceKindV6::Opaque\n        } else {",
            "api-set-schema-composition-classification-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "is_schema_extension_namespace_name(&namespace_name)",
            "false",
            "api-set-schema-composition-family-grammar-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "contract.namespace_kind != ApiSetNamespaceKindV6::PublicContract",
            "false",
            "api-set-public-family-lookup-guard-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "let hash_factor = api_set_u32(bytes, 24)?;",
            "let hash_factor = 31;",
            "api-set-header-hash-factor-ignored",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "hash.wrapping_mul(hash_factor)",
            "hash.wrapping_add(hash_factor)",
            "api-set-wrapping-hash-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "if namespace_indices[contract_index] {",
            "if false {",
            "api-set-hash-namespace-permutation-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "if hashes[hash_index - 1].hash >= hashes[hash_index].hash {",
            "if false {",
            "api-set-hash-order-validation-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "if hash_entry.hash != expected {",
            "if false {",
            "api-set-hash-value-validation-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            ".binary_search_by_key(&lookup_hash, |entry| entry.hash)",
            ".binary_search_by_key(&lookup_hash, |_| lookup_hash)",
            "api-set-native-hash-lookup-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "if contract.hash_key != key {",
            "if false {",
            "api-set-hash-exact-key-guard-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "probe_api_set_contract(schema, &request.revision_key)",
            "probe_api_set_contract(schema, &request.full_name)",
            "api-set-revision-prefix-probe-replaced-with-full-name",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "api_set_utf16(bytes, api_set_u32(bytes, value + 4)?, alias_length)?",
            "api_set_utf16(bytes, api_set_u32(bytes, value + 12)?, alias_length)?",
            "api-set-parent-alias-name-field-swapped",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "let host = api_set_utf16(bytes, api_set_u32(bytes, value + 12)?, host_length)?;\n                let host = normalize_api_set_host(&host)",
            "let host = api_set_utf16(bytes, api_set_u32(bytes, value + 4)?, host_length)?;\n                let host = normalize_api_set_host(&host)",
            "api-set-host-value-field-swapped",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "parse_api_set_request(name).is_ok()",
            "name.to_ascii_lowercase().starts_with(\"api-\")",
            "api-set-request-classification-weakened-to-family-prefix",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "let host = if host_length == 0 {\n                api_set_utf16(bytes, api_set_u32(bytes, value + 12)?, host_length)?;\n                ApiSetHostV6::Unhosted",
            "let host = if host_length == 0 {\n                ApiSetHostV6::Hosted(\".DLL\".to_owned())",
            "api-set-empty-value-invented-host",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "let mapping = if values.is_empty() {\n            ApiSetMappingV6::Unhosted",
            "let mapping = if values.is_empty() {\n            ApiSetMappingV6::Mapped(Vec::new())",
            "api-set-zero-value-count-invented-mapping",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            ".enumerate()\n        .skip(1)\n        .find(|(_, value)| value.parent_alias.as_deref() == Some(parent_key))",
            ".enumerate()\n        .skip(0)\n        .find(|(_, value)| value.parent_alias.as_deref() == Some(parent_key))",
            "api-set-default-admitted-as-parent-override",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "ApiSetHostV6::Unhosted => Err(format!(\n            \"API-set requested_contract",
            "ApiSetHostV6::Unhosted => Ok(ApiSetResolvedHostV6 {\n            /* API-set requested_contract",
            "api-set-selected-unhosted-rejection-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "parent_key,\n                selection.hash_key.clone(),",
            "String::new(),\n                selection.hash_key.clone(),",
            "api-set-cache-parent-identity-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "selection.hash_key.clone(),",
            "import_contract.to_ascii_uppercase(),",
            "api-set-cache-selected-key-identity-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "if edges.contains_key(&identity) {",
            "if false {",
            "logical-edge-coalescing-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "let shortest_depths = loader_graph_shortest_depths(&self.loader_roots, &self.loader_edges);",
            "let shortest_depths = BTreeMap::new();",
            "sealed-shortest-depth-validation-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "parse_windows_pe_mapped_loader_contract(bytes)",
            "parse_windows_pe_loader_contract(bytes)",
            "known-dll-graph-read-from-file-layout",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "mapped_loader_contract_sha256 != source_contract.source_loader_contract_sha256",
            "false",
            "mapped-section-pinned-contract-comparison-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "const MAX_LOADER_GRAPH_DEPTH: usize = 16;",
            "const MAX_LOADER_GRAPH_DEPTH: usize = usize::MAX;",
            "loader-graph-depth-bound-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "const MAX_LOADER_GRAPH_EDGES: usize = 1_024;",
            "const MAX_LOADER_GRAPH_EDGES: usize = usize::MAX;",
            "loader-graph-edge-bound-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "canonical.extend_from_slice(loader_symbol_name(symbol).as_bytes());",
            "canonical.extend_from_slice(b\"thunk-omitted\");",
            "loader-graph-thunk-identity-omitted",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "edge.depth,\n        edge.parent_host.to_ascii_uppercase(),\n        edge.descriptor_ordinal",
            "edge.depth,\n        \"parent-omitted\",\n        edge.descriptor_ordinal",
            "loader-graph-edge-parent-omitted",
        ),
        (
            WindowsLoaderControlContractSource::Pe,
            "let mut descriptors = Vec::new();",
            "let mut descriptors = BTreeSet::new();",
            "loader-descriptor-order-collapsed-to-set",
        ),
        (
            WindowsLoaderControlContractSource::LoaderDebug,
            "LoaderDebugTraceV4::from_loader_evidence(native_loader_access)",
            "LoaderDebugTraceV4::new(std::iter::empty())",
            "loader-debug-closure-reverted-to-root-set",
        ),
        (
            WindowsLoaderControlContractSource::LoaderDebug,
            "closure-hosts-all-observed:initialization-unresolved",
            "loader-access-success",
            "complete-closure-misreported-as-loader-success",
        ),
        (
            WindowsLoaderControlContractSource::Process,
            "drop(native_loader_access_lease);",
            "let _ = &native_loader_access_lease;",
            "native-loader-lease-release-removed",
        ),
        (
            WindowsLoaderControlContractSource::LoaderAccess,
            "repair_scope: \"external-never-repair\",",
            "repair_scope: \"memcordon-owned\",",
            "native-loader-external-repair-boundary-weakened",
        ),
        (
            WindowsLoaderControlContractSource::LoaderDebug,
            "const MODULE_TAIL_CAPACITY: usize = 8;",
            "const MODULE_TAIL_CAPACITY: usize = usize::MAX;",
            "loader-debug-module-tail-unbounded",
        ),
        (
            WindowsLoaderControlContractSource::Bootstrap,
            "[role, pipe_name, nonce, desktop] if role == \"loader-control\"",
            "[role, pipe_name, nonce] if role == \"loader-control\"",
            "loader-control-cli-arity-widened",
        ),
        (
            WindowsLoaderControlContractSource::Bootstrap,
            "compile_error!(\"the target desktop bootstrap requires a statically linked CRT\");",
            "const _: () = ();",
            "helper-static-crt-assertion-removed",
        ),
        (
            WindowsLoaderControlContractSource::PackageSchema,
            "target_desktop_bootstrap_crt_static: bool,",
            "target_desktop_bootstrap_crt_dynamic: bool,",
            "package-static-crt-evidence-removed",
        ),
        (
            WindowsLoaderControlContractSource::Pe,
            "name.starts_with(\"VCRUNTIME\")",
            "false",
            "dynamic-msvc-crt-admitted",
        ),
        (
            WindowsLoaderControlContractSource::Pe,
            "name.as_str() == \"MSVCRT.DLL\"",
            "false",
            "dynamic-legacy-crt-admitted",
        ),
        (
            WindowsLoaderControlContractSource::CargoConfig,
            "[target.x86_64-pc-windows-msvc]\nrustflags = [\"-C\", \"target-feature=+crt-static\"]",
            "[target.x86_64-pc-windows-msvc]\nrustflags = [\"-C\", \"target-feature=-crt-static\"]",
            "repository-static-crt-disabled",
        ),
    ] {
        let mut mutated = sources.clone();
        replace_windows_source_once(mutated.source_mut(source), exact, replacement, mutant);
        assert!(
            validate_windows_loader_control_contract(&mutated).is_err(),
            "{mutant} survived the loader-control/static-CRT contract",
        );
    }

    for (forbidden, mutant) in [
        ("SetNamedSecurityInfo", "loader-file-dacl-repair-added"),
        ("SetFileSecurity", "loader-file-security-repair-added"),
        ("SetSecurityInfo", "loader-object-security-repair-added"),
        ("AccessCheck(", "loader-surrogate-access-check-added"),
        ("AuthzAccessCheck", "loader-authz-surrogate-added"),
    ] {
        let mut mutated = sources.clone();
        mutated.loader_access.push_str(forbidden);
        assert!(
            validate_windows_loader_control_contract(&mutated).is_err(),
            "{mutant} survived: {forbidden}",
        );
    }
}

#[test]
fn windows_cleanup_retirement_and_typed_marker_mutants_are_rejected() {
    let production = WindowsProductionSources::load();
    validate_windows_production_contract(&production)
        .expect("unmutated Windows cleanup retirement must satisfy the native contract");

    for (source, exact, mutant) in [
        (
            "launcher",
            "PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE_ACCESS",
            "cleanup producer process not pinned",
        ),
        (
            "qualification",
            "CleanupProcessCreationProducerPhaseV1::SpawnEntered,\n            None,",
            "cleanup producer spawn-entry phase omitted",
        ),
        (
            "launcher",
            "let active_processes_zero = ActiveProcessesZero;\n    target_cleanup_barrier.finish();",
            "desktop lease barrier omitted",
        ),
        (
            "launcher",
            ".is_none_or(|receipt| cleanup_process_creation_expected(receipt.phase))",
            "typed cleanup applicability gate omitted",
        ),
    ] {
        let mut mutated = production.clone();
        let selected = match source {
            "launcher" => &mut mutated.launcher,
            "qualification" => &mut mutated.qualification,
            _ => unreachable!(),
        };
        replace_windows_source_once(selected, exact, "/* cleanup mutant removed */", mutant);
        assert!(
            validate_windows_production_contract(&mutated).is_err(),
            "{mutant} survived the cleanup retirement contract"
        );
    }

    let mut monitor_terminates = production.clone();
    replace_windows_source_once(
        &mut monitor_terminates.launcher,
        "    let mut direct_status = None;",
        "    job.terminate(CANCEL_STATUS)?;\n    let mut direct_status = None;",
        "monitor-terminates-job",
    );
    assert!(
        validate_windows_production_contract(&monitor_terminates).is_err(),
        "a destructive monitor survived the Windows cleanup retirement contract"
    );

    let mut ignored_termination = production.clone();
    replace_windows_source_once(
        &mut ignored_termination.launcher,
        "    job.terminate(reason.termination_status())?;",
        "    let _ = job.terminate(reason.termination_status());",
        "ignored-normal-job-termination",
    );
    assert!(
        validate_windows_production_contract(&ignored_termination).is_err(),
        "an ignored normal Job termination survived the Windows cleanup contract"
    );

    for (fragment, mutant) in [
        (
            "fn read_cleanup_process_creation_terminal(\n    path: &std::path::Path,",
            "followed-or-untyped-result-node",
        ),
        (
            "cleanup-time process creation result timed out: phase={:?} pid={}",
            "missing-result-accepted",
        ),
        (
            "cleanup producer terminal is malformed: {error}",
            "malformed-result-accepted",
        ),
        (
            "receipt.schema_version\n        != super::qualification::CLEANUP_PROCESS_CREATION_RESULT_SCHEMA_VERSION",
            "mismatched-result-schema-accepted",
        ),
        (
            "receipt.attempt_binding != attempt_binding",
            "mismatched-result-binding-accepted",
        ),
        (
            "|| receipt.producer_identity != pinned_identity",
            "mismatched-terminal-producer-accepted",
        ),
        (
            "|| receipt.completed_phases",
            "missing-phase-transcript-accepted",
        ),
        (
            "CleanupProcessCreationOutcomeV1::Failed {",
            "explicit-spawn-failure-accepted",
        ),
        (
            "cleanup-time process creation result reported a zero child PID",
            "partial-success-result-accepted",
        ),
        (
            "job.process_ids()?.contains(&child_pid)",
            "uncontained-result-pid-accepted",
        ),
        (
            "total_processes_after <= total_processes_before",
            "unaccounted-result-pid-accepted",
        ),
    ] {
        let mut mutated = production.clone();
        replace_windows_source_once(
            &mut mutated.launcher,
            fragment,
            "/* cleanup marker mutant removed */",
            mutant,
        );
        assert!(
            validate_windows_production_contract(&mutated).is_err(),
            "cleanup marker mutant {mutant} survived the native contract"
        );
    }

    let mut result_probe_failure = production.clone();
    result_probe_failure.launcher = result_probe_failure.launcher.replace(
        "LaunchAttemptError::cleanup_marker(\n                \"terminal-open\",",
        "LaunchAttemptError::from(",
    );
    assert!(
        validate_windows_production_contract(&result_probe_failure).is_err(),
        "an untyped cleanup result-probe failure survived the native contract"
    );

    for (fragment, mutant) in [
        (
            "#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]\n#[serde(deny_unknown_fields)]\npub(super) struct CleanupProcessCreationResultV1 {",
            "unknown-result-fields-accepted",
        ),
        (
            "CleanupProcessCreationOutcomeV1::Failed {",
            "spawn-failure-result-not-published",
        ),
        (
            "completed_phases.push(CleanupProcessCreationProducerPhaseV1::SpawnEntered);",
            "spawn-entry-transcript-not-published",
        ),
        (
            "super::record::publish_create_once_atomically(file, &destination).map_err(|error| {\n        CleanupProducerFailure::publication(\n            completed_phases.last().copied(),\n            Some(CleanupProcessCreationProducerPhaseV1::ResultPublished),",
            "terminal-not-create-once-published",
        ),
    ] {
        let mut mutated = production.clone();
        replace_windows_source_once(
            &mut mutated.qualification,
            fragment,
            "/* cleanup marker producer mutant removed */",
            mutant,
        );
        assert!(
            validate_windows_production_contract(&mutated).is_err(),
            "cleanup marker producer mutant {mutant} survived the native contract"
        );
    }

    for (source, fragment, mutant) in [
        (
            "qualification",
            "pub(super) struct CleanupProcessCreationProducerFailureV1 {",
            "typed-producer-failure-removed",
        ),
        (
            "qualification",
            "pub(super) enum CleanupProcessCreationOperationV1 {",
            "typed-producer-operation-removed",
        ),
        (
            "qualification",
            "Self::SpawnEntered => \"state.02-spawn-entered.json\"",
            "immutable-spawn-phase-removed",
        ),
        (
            "qualification",
            "Self::ResultPublished => \"state.06-result-published.json\"",
            "immutable-result-publication-phase-removed",
        ),
        (
            "qualification",
            "pub(super) attempted_phase: Option<CleanupProcessCreationProducerPhaseV1>",
            "attempted-producer-phase-erased",
        ),
        (
            "qualification",
            "io_error_kind: Some(format!(\"{:?}\", error.kind())),\n                os_code: error.raw_os_error()",
            "producer-native-code-erased",
        ),
        (
            "qualification",
            ".stderr(Stdio::from(stderr))",
            "producer-stderr-fallback-erased",
        ),
        (
            "launcher",
            "cleanup_failure.terminal_candidate = Some(Box::new(receipt));",
            "posttarget-terminal-receipt-erased",
        ),
        (
            "qualification",
            "fn cleanup_producer_fallback_diagnostic(",
            "shared-stderr-fallback-erased",
        ),
        (
            "record",
            "pub(crate) fn publish_create_once_atomically(",
            "create-once-publisher-removed",
        ),
        (
            "record",
            "pub terminal_response_json: Option<String>",
            "durable-terminal-outbox-erased",
        ),
        (
            "launcher",
            "fn wait_for_terminal_acknowledgment(",
            "terminal-ack-wait-erased",
        ),
    ] {
        let mut mutated = production.clone();
        let selected = match source {
            "qualification" => &mut mutated.qualification,
            "launcher" => &mut mutated.launcher,
            "record" => &mut mutated.record,
            "control" => &mut mutated.control,
            "platform" => &mut mutated.platform,
            _ => unreachable!(),
        };
        replace_windows_source_once(
            selected,
            fragment,
            "/* cleanup protocol mutant removed */",
            mutant,
        );
        assert!(
            validate_windows_production_contract(&mutated).is_err(),
            "cleanup protocol mutant {mutant} survived the native contract"
        );
    }

    const LIVE_CONTROL_REGION: SourceRegion = SourceRegion {
        start: "fn relay_protocol(",
        end: "fn advance_relay_phase(",
    };
    const REPLAY_CONTROL_REGION: SourceRegion = SourceRegion {
        start: "fn replay_terminal(",
        end: "pub(super) const CERTIFICATION_FRONTEND_HANDLE_ROLES: [&str;",
    };
    let live_mutations = ControlRegionMutationHarness::verified(
        &production,
        LIVE_CONTROL_REGION,
        REPLAY_CONTROL_REGION,
        validate_windows_qualification_terminal_ack_contract,
    );
    for mutation in [
        SourceMutation {
            exact: "WindowsProviderRequestV1::TerminalAcknowledged {",
            mutant: "live-relay-frontend-terminal-ack-validation-erased",
        },
        SourceMutation {
            exact: "&WindowsLauncherRequestV1::TerminalAcknowledged {",
            mutant: "live-relay-private-terminal-ack-forwarding-erased",
        },
        SourceMutation {
            exact: "WindowsLauncherResponseV1::TerminalRetired(retired)",
            mutant: "live-relay-launcher-terminal-retired-validation-erased",
        },
        SourceMutation {
            exact: "WindowsProviderResponseV1::TerminalRetired(retired)",
            mutant: "live-relay-public-terminal-retired-forwarding-erased",
        },
    ] {
        live_mutations.assert_rejected(mutation);
    }
    let replay_mutations = ControlRegionMutationHarness::verified(
        &production,
        REPLAY_CONTROL_REGION,
        LIVE_CONTROL_REGION,
        validate_windows_preauthorization_abort_terminal_contract,
    );
    for mutation in [
        SourceMutation {
            exact: "WindowsProviderRequestV1::TerminalAcknowledged {",
            mutant: "replay-frontend-terminal-ack-validation-erased",
        },
        SourceMutation {
            exact: "&WindowsLauncherRequestV1::TerminalAcknowledged {",
            mutant: "replay-private-terminal-ack-forwarding-erased",
        },
        SourceMutation {
            exact: "WindowsLauncherResponseV1::TerminalRetired(retired)",
            mutant: "replay-launcher-terminal-retired-validation-erased",
        },
        SourceMutation {
            exact: "WindowsProviderResponseV1::TerminalRetired(retired)",
            mutant: "replay-public-terminal-retired-forwarding-erased",
        },
    ] {
        replay_mutations.assert_rejected(mutation);
    }

    const PLATFORM_RETIREMENT_REGION: SourceRegion = SourceRegion {
        start: "fn acknowledge_terminal_retirement(",
        end: "fn rejection_error(rejection: memcordon_core::ProviderRejectionEvidence) -> Error {",
    };
    validate_windows_qualification_terminal_ack_contract(&production)
        .expect("unmutated platform terminal-retirement contract");
    for mutation in [
        SourceMutation {
            exact: "&WindowsProviderRequestV1::TerminalAcknowledged {",
            mutant: "public-terminal-ack-erased",
        },
        SourceMutation {
            exact: "WindowsProviderResponseV1::TerminalRetired(retired)",
            mutant: "public-terminal-retired-response-erased",
        },
        SourceMutation {
            exact: "retired.is_consistent_for(",
            mutant: "public-terminal-retired-response-digest-proof-erased",
        },
    ] {
        let mut mutated = production.clone();
        replace_windows_source_once_in_region(
            &mut mutated.platform,
            PLATFORM_RETIREMENT_REGION.start,
            PLATFORM_RETIREMENT_REGION.end,
            mutation.exact,
            "/* scoped platform terminal protocol mutant removed */",
            mutation.mutant,
        );
        let region_after = semantic_function_region(
            &mutated.platform,
            PLATFORM_RETIREMENT_REGION.start,
            PLATFORM_RETIREMENT_REGION.end,
        )
        .unwrap_or_else(|| {
            panic!(
                "{} platform retirement region is absent after mutation",
                mutation.mutant
            )
        });
        assert_eq!(
            region_after.matches(mutation.exact).count(),
            0,
            "{} did not erase its exact platform helper target",
            mutation.mutant
        );
        assert!(
            validate_windows_qualification_terminal_ack_contract(&mutated).is_err(),
            "platform terminal protocol mutant {} survived its semantic contract",
            mutation.mutant
        );
    }

    for (source, exact, replacement, mutant) in [
        (
            "security",
            "FILE_ALL_ACCESS & !FILE_DELETE_CHILD",
            "FILE_ALL_ACCESS",
            "administrator-delete-child-restored",
        ),
        (
            "security",
            "(A;OICIIO;GRGWGX;;;WR)",
            "(A;OICIIO;GRGWGXSD;;;WR)",
            "write-restricted-leaf-delete-restored",
        ),
        (
            "record",
            ".access_mode(GENERIC_WRITE_ACCESS | DELETE_ACCESS)",
            ".access_mode(GENERIC_WRITE_ACCESS)",
            "staging-handle-delete-capability-removed",
        ),
        (
            "record",
            "(*rename).Anonymous.ReplaceIfExists = false;",
            "(*rename).Anonymous.ReplaceIfExists = true;",
            "create-once-replacement-enabled",
        ),
        (
            "record",
            "SetFileInformationByHandle(\n            source.file.as_raw_handle() as _,",
            "MoveFileExW(\n            source.file.as_raw_handle() as _,",
            "create-once-path-rename-restored",
        ),
        (
            "record",
            "(*rename).RootDirectory = ptr::null_mut();",
            "(*rename).RootDirectory = source.file.as_raw_handle() as _;",
            "create-once-absolute-name-contract-erased",
        ),
        (
            "record",
            "(*rename).FileNameLength = destination_name_bytes;",
            "(*rename).FileNameLength = backing_bytes;",
            "create-once-filename-byte-bound-erased",
        ),
        (
            "record",
            "*filename.add(destination.len()) = 0;",
            "/* explicit terminator erased */",
            "create-once-explicit-terminator-erased",
        ),
        (
            "record",
            "bytes.max(std::mem::size_of::<FILE_RENAME_INFO>())",
            "bytes",
            "create-once-declared-structure-bound-erased",
        ),
        (
            "record",
            "words: vec![0_usize; aligned_words]",
            "words: Vec::with_capacity(aligned_words)",
            "create-once-zero-initialization-erased",
        ),
        (
            "record",
            "rename.cast(),\n            information.backing_bytes,",
            "rename.cast(),\n            information.information_bytes,",
            "create-once-aligned-buffer-bound-erased",
        ),
        (
            "record",
            "const NAME_QUERY_FLAGS: u32 = FILE_NAME_NORMALIZED | VOLUME_NAME_NT;",
            "const NAME_QUERY_FLAGS: u32 = 0;",
            "create-once-canonical-name-flags-erased",
        ),
        (
            "record",
            "let source_path =\n        create_once_normalized_nt_path(source.file.as_raw_handle() as _)",
            "let source_path =\n        Ok(source.path.clone())",
            "create-once-pre-rename-handle-name-anchor-erased",
        ),
        (
            "record",
            "let final_path_result = create_once_normalized_nt_path(source.file.as_raw_handle() as _);",
            "let final_path_result = std::fs::canonicalize(destination);",
            "create-once-post-rename-destination-reopen-restored",
        ),
        (
            "record",
            "if source_location.leaf_units != expected_source_leaf {",
            "if false {",
            "create-once-source-leaf-proof-erased",
        ),
        (
            "record",
            "if identity_before.volume_serial != identity_after.volume_serial {",
            "if false {",
            "create-once-volume-identity-comparison-erased",
        ),
        (
            "record",
            "std::mem::zeroed::<FILE_ID_INFO>()",
            "std::mem::zeroed::<FILE_STANDARD_INFO>()",
            "create-once-128-bit-file-identity-erased",
        ),
        (
            "record",
            "if identity_before.file_id != identity_after.file_id {",
            "if false {",
            "create-once-file-identity-comparison-erased",
        ),
        (
            "record",
            "if source_location.parent_units != final_location.parent_units {",
            "if false {",
            "create-once-canonical-parent-comparison-erased",
        ),
        (
            "record",
            "if final_location.leaf_units != expected_final_leaf {",
            "if false {",
            "create-once-exact-final-leaf-comparison-erased",
        ),
        (
            "record",
            "if source_link_count != 1 {",
            "if false {",
            "create-once-source-single-link-proof-erased",
        ),
        (
            "record",
            "if final_link_count != 1 {",
            "if false {",
            "create-once-final-single-link-proof-erased",
        ),
        (
            "record",
            "let final_sync = source.file.sync_all();",
            "let final_sync: Result<(), std::io::Error> = Ok(());",
            "create-once-post-rename-sync-erased",
        ),
        (
            "record",
            "return Err(failure.with_secondary(CreateOncePublicationStage::FinalSync, error));",
            "return Err(CreateOncePublicationFailure::io(CreateOncePublicationStage::FinalSync, &source.path, destination, Some(&information), &evidence, error));",
            "create-once-semantic-primary-erased-by-sync",
        ),
    ] {
        let mut mutated = production.clone();
        let selected = match source {
            "security" => &mut mutated.security,
            "record" => &mut mutated.record,
            _ => unreachable!(),
        };
        replace_windows_source_once(selected, exact, replacement, mutant);
        assert!(
            validate_windows_production_contract(&mutated).is_err(),
            "destructive-authority mutant {mutant} survived the native contract"
        );
    }
}

#[test]
fn windows_qualification_create_once_publication_mutants_are_rejected() {
    let production = WindowsProductionSources::load();
    validate_windows_production_contract(&production)
        .expect("unmutated qualification publishers must retain create-once handles");

    for (exact, replacement, mutant) in [
        (
            "publish_qualification_receipt(\n        path,\n        QualificationPublicationProducerV1::TargetResult,\n        &receipt,\n    )",
            "super::record::replace_atomically(&path.with_extension(\"result.new\"), path)",
            "target-result-path-reopen-restored",
        ),
        (
            "publish_qualification_receipt(\n        receipt,\n        QualificationPublicationProducerV1::NestedChild,\n        &receipt_value,\n    )",
            "super::record::replace_atomically(&nested_child_staged_receipt(receipt), receipt)",
            "nested-child-path-reopen-restored",
        ),
        (
            "super::record::publish_create_once_atomically(file, destination)",
            "drop(file);\n    super::record::replace_atomically(&staged, destination).map_err(std::io::Error::other)",
            "qualification-retained-handle-dropped-before-rename",
        ),
        (
            "api: error.stage().api(),\n            path_role,\n            path: path.to_owned(),\n            requested_access,\n            io_error_kind: Some(error.kind()),\n            native_code: error.raw_os_error(),",
            "api: stage.api(),\n            path_role,\n            path: path.to_owned(),\n            requested_access,\n            io_error_kind: None,\n            native_code: None,",
            "qualification-native-publication-evidence-erased",
        ),
        (
            "Self::ReceiptPublishRename => \"SetFileInformationByHandle(FileRenameInfo)\"",
            "Self::ReceiptPublishRename => \"MoveFileExW\"",
            "qualification-rename-api-mislabeled",
        ),
    ] {
        let mut mutated = production.clone();
        replace_windows_source_once(&mut mutated.qualification, exact, replacement, mutant);
        assert!(
            validate_windows_production_contract(&mutated).is_err(),
            "qualification publication mutant {mutant} survived the native contract"
        );
    }
}

#[test]
fn windows_failed_terminal_ack_order_and_outbox_retirement_mutants_are_rejected() {
    let production = WindowsProductionSources::load();
    validate_windows_qualification_terminal_ack_contract(&production)
        .expect("unmutated failed terminals must ACK before semantic propagation");

    for (source, exact, replacement, mutant) in [
        (
            "qualification",
            "let semantic_result = (|| {",
            "let semantic_result = Err(\"semantic validation bypassed\".to_owned()).and_then(|_| (|| {",
            "terminal-semantic-latch-bypassed",
        ),
        (
            "qualification",
            "let acknowledgment_result = acknowledge().map_err(|detail| {",
            "let acknowledgment_result = semantic_result.as_ref().map(|_| ()).map_err(|detail| {",
            "terminal-ack-attempt-bypassed",
        ),
        (
            "qualification",
            "(Err(primary), Ok(())) => Err(primary),",
            "(Err(_), Ok(())) => Err(\"terminal ACK masked the semantic failure\".to_owned()),",
            "terminal-primary-failure-masked",
        ),
        (
            "qualification",
            "terminal acknowledgment failed after bound receipt was latched",
            "terminal acknowledgment replaced the primary semantic failure",
            "terminal-secondary-evidence-erased",
        ),
        (
            "launcher",
            "record.acknowledge_terminal_response()?;",
            "return Err(LaunchAttemptError::from(\"terminal outbox retained\"));",
            "terminal-outbox-retirement-deleted",
        ),
    ] {
        let mut mutated = production.clone();
        let selected = match source {
            "qualification" => &mut mutated.qualification,
            "control" => &mut mutated.control,
            "launcher" => &mut mutated.launcher,
            _ => unreachable!(),
        };
        replace_windows_source_once(selected, exact, replacement, mutant);
        assert!(
            validate_windows_qualification_terminal_ack_contract(&mutated).is_err(),
            "failed-terminal ACK mutant {mutant} survived the contract"
        );
    }

    let mut missing_private_ack = production.clone();
    replace_windows_source_once_in_region(
        &mut missing_private_ack.control,
        "fn relay_protocol(",
        "fn advance_relay_phase(",
        "                        &WindowsLauncherRequestV1::TerminalAcknowledged {",
        "                        &WindowsLauncherRequestV1::Cancel {",
        "terminal-ack-not-forwarded",
    );
    assert!(
        validate_windows_qualification_terminal_ack_contract(&missing_private_ack).is_err(),
        "terminal ACK forwarding mutant survived the contract"
    );
}

#[test]
fn windows_token_envelope_canonicalizes_only_primary_impersonation_level() {
    let token = include_str!(
        "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/token.rs"
    );
    let envelope = token
        .split_once("pub fn envelope(token: HANDLE)")
        .expect("Windows token envelope constructor must exist")
        .1
        .split_once("pub(super) fn envelope_mismatch_fields")
        .expect("Windows token envelope mismatch diagnostics must exist")
        .0;
    for required in [
        "let token_type = statistics.TokenType;",
        "if token_type == TokenPrimary {",
        "SecurityAnonymous as u32",
        "else if token_type == TokenImpersonation {",
        "let level = scalar_i32(token, TokenImpersonationLevel)?;",
        "if level < SecurityAnonymous || level > SecurityDelegation {",
        "return Err(\"token impersonation level is invalid\".to_owned());",
        "return Err(\"token type is invalid\".to_owned());",
    ] {
        assert!(
            envelope.contains(required),
            "Windows token envelope omitted {required}"
        );
    }
    assert!(
        !envelope.contains("unwrap_or(statistics.ImpersonationLevel)"),
        "primary-token envelopes must not use the undefined TOKEN_STATISTICS impersonation level"
    );
    for required in [
        "let source_envelope = envelope(impersonation.raw())?;",
        "source_envelope.token_type != TokenImpersonation as u32",
        "source_envelope.impersonation_level < SecurityImpersonation as u32",
        "source_envelope.impersonation_level > SecurityDelegation as u32",
        "MCSEALED-WINDOWS-CALLER-AUTH: caller impersonation level is unsupported",
        "primary_envelope.token_type != TokenPrimary as u32",
        "primary_envelope.impersonation_level != SecurityAnonymous as u32",
        "MCSEALED-WINDOWS-CALLER-AUTH: duplicated caller token is not canonical primary",
        "let mut expected_primary_envelope = source_envelope;",
        "expected_primary_envelope.token_type = TokenPrimary as u32;",
        "expected_primary_envelope.impersonation_level = SecurityAnonymous as u32;",
        "if primary_envelope != expected_primary_envelope {",
        "duplicated primary differs from effective caller (fields: {})",
    ] {
        assert!(
            token.contains(required),
            "Windows caller-token admission omitted {required}"
        );
    }

    let mismatch_fields = token
        .split_once("pub(super) fn envelope_mismatch_fields")
        .expect("Windows token envelope mismatch diagnostics must exist")
        .1
        .split_once("struct QueryBuffer")
        .expect("Windows token envelope mismatch diagnostics must precede QueryBuffer")
        .0;
    for field in [
        "user_sid",
        "owner_sid",
        "primary_group_sid",
        "groups_sha256",
        "privileges_sha256",
        "restricted_sids_sha256",
        "integrity_level",
        "mandatory_policy",
        "session_id",
        "elevation_type",
        "elevated",
        "virtualization_allowed",
        "virtualization_enabled",
        "ui_access",
        "appcontainer",
        "authentication_id",
        "token_type",
        "impersonation_level",
    ] {
        assert!(
            mismatch_fields.contains(&format!("fields.push(\"{field}\")")),
            "Windows token mismatch diagnostics omitted {field}"
        );
    }

    let launcher = include_str!(
        "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/launcher_service.rs"
    );
    assert_eq!(
        launcher.matches("mismatch_fields.join(\", \")").count(),
        2,
        "both authenticated-token readback failures must report field names only"
    );
}

#[test]
fn semantic_function_region_accepts_lf_and_crlf_without_broad_matching() {
    let lf = "fn selected() {\n    structured_call();\n}\n\nfn following() {\n}\n";
    let crlf = lf.replace('\n', "\r\n");
    let expected = "    structured_call();\n}\n";

    for source in [lf, crlf.as_str()] {
        assert_eq!(
            semantic_function_region(source, "fn selected() {", "fn following() {").as_deref(),
            Some(expected),
        );
        assert!(semantic_function_region(source, "fn selected", "fn following() {").is_none());
        assert!(semantic_function_region(source, "fn selected() {", "fn following").is_none());
    }
}

#[test]
fn windows_production_contract_is_identical_after_crlf_checkout_normalization() {
    let lf = WindowsProductionSources::load();
    validate_windows_production_contract(&lf).expect("LF production contract must be complete");

    let mut crlf = lf.clone();
    crlf.convert_line_endings_to_crlf();
    crlf.normalize_line_endings();
    validate_windows_production_contract(&crlf)
        .expect("CRLF production contract must normalize to the complete LF contract");
}

#[test]
fn windows_package_starts_the_exact_configured_service_handles() {
    let package = include_str!(
        "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/package.rs"
    );
    let install = semantic_function_region(
        package,
        "fn install_transaction(",
        "struct ConfiguredServices {",
    )
    .expect("install transaction must end at the configured service handle owner");
    assert_eq!(install.matches("configure_services(").count(), 1);
    require_source_order(
        &install,
        &[
            (
                "let services = configure_services(&destination, ServiceConfiguration::Fresh(transition))?;",
                "one fresh service configuration pass",
            ),
            (
                "harden_runtime_state_security(transition)?;",
                "runtime ACL sealing before service startup",
            ),
            (
                "start_services(&services)?;",
                "startup through the retained configured handles",
            ),
        ],
    )
    .expect("fresh installation must configure, seal, and start in order");

    validate_windows_fresh_install_contract(package)
        .expect("fresh install must reject every residual before beginning its transaction");

    let dispatch = semantic_function_region(
        package,
        "pub fn mutate(operation: &OsStr, ephemeral_ci: bool) -> Result<(), String> {",
        "pub(super) struct PackageLease {",
    )
    .expect("package mutation dispatch must end before the lease owner");
    let (fresh_dispatch, _) = dispatch
        .split_once("} else if operation == \"upgrade\" {")
        .expect("fresh and upgrade dispatch must have an exact boundary");
    assert!(!fresh_dispatch.contains("reconcile_services_from_installed()"));

    let configure = semantic_function_region(
        package,
        "fn configure_services(",
        "fn require_fresh_service_absence(manager: &service_manager::ScHandle) -> Result<(), String> {",
    )
    .expect("service configuration must have a semantic boundary before residual preflight");
    assert!(configure.contains("require_fresh_service_absence(&manager)?;"));
    require_source_order(
        &configure,
        &[
            (
                "super::security::set_scm_launcher_connect(manager.raw(), true)?;",
                "SCM authority mutation",
            ),
            (
                "transition.scm_connect_ace_created = true;",
                "immediate SCM authority ownership recording",
            ),
            (
                "if let Err(marker_error) = std::fs::write(",
                "durable SCM ownership marker persistence",
            ),
            (
                "let slot = service_manager::create_guardian_slot_registration(&manager, &config)?;",
                "fresh guardian registration creation",
            ),
            (
                "transition.guardian_slots_created.push(name.clone());",
                "immediate guardian registration ownership recording",
            ),
            (
                "service_manager::configure_created_guardian_slot(&slot, &config)?;",
                "guardian post-registration hardening",
            ),
            (
                "let launcher = service_manager::create_registration(&manager, &launcher_config)?;",
                "fresh launcher creation",
            ),
            (
                "transition.launcher_created = true;",
                "immediate launcher ownership recording",
            ),
            (
                "service_manager::configure_created(&launcher, &launcher_config)?;",
                "launcher post-registration hardening",
            ),
            (
                "let control = service_manager::create_registration(&manager, &control_config)?;",
                "fresh control creation",
            ),
            (
                "transition.control_created = true;",
                "immediate control ownership recording",
            ),
            (
                "service_manager::configure_created(&control, &control_config)?;",
                "control post-registration hardening",
            ),
        ],
    )
    .expect("fresh configuration must record ownership immediately after each create");
    assert!(configure.contains("_guardian_slots: guardian_slots"));
    assert!(configure.contains("create_guardian_slot_registration(&manager, &config)?"));
    assert!(configure.contains("configure_created_guardian_slot(&slot, &config)?"));
    assert!(!configure.contains("service_manager::start("));

    let preflight = semantic_function_region(
        package,
        "fn require_fresh_service_absence(manager: &service_manager::ScHandle) -> Result<(), String> {",
        "fn start_services(services: &ConfiguredServices) -> Result<(), String> {",
    )
    .expect("fresh service residual preflight must end before startup");
    assert!(preflight.contains("MCSEALED-WINDOWS-SERVICE-PREFLIGHT-RESIDUAL"));
    assert!(preflight.contains("MCSEALED-WINDOWS-SERVICE-PREFLIGHT:"));
    assert!(preflight.contains("service_manager::exists(manager, name)"));

    let start = semantic_function_region(
        package,
        "fn start_services(services: &ConfiguredServices) -> Result<(), String> {",
        "fn harden_runtime_state_security(transition: &InstallTransition) -> Result<(), String> {",
    )
    .expect("service startup must have a semantic boundary before ACL hardening");
    assert_eq!(start.matches("service_manager::start(").count(), 2);
    assert!(!start.contains("configure_services("));
    assert!(!start.contains("service_manager::create("));
    assert!(!start.contains("service_manager::reconcile("));

    let reconcile = semantic_function_region(
        package,
        "fn reconcile_services_from_installed() -> Result<(), String> {",
        "fn reconcile_runtime_state_security() -> Result<(), String> {",
    )
    .expect("service reconciliation must have a semantic boundary before security readback");
    assert_eq!(reconcile.matches("configure_services(").count(), 1);
    require_source_order(
        &reconcile,
        &[
            (
                "let services = configure_services(&installed_binary(), ServiceConfiguration::Reconcile)?;",
                "one installed service reconciliation pass",
            ),
            (
                "reconcile_runtime_state_security()?;",
                "filesystem policy reconciliation before service exposure",
            ),
            ("start_services(&services)", "reconciled handle startup"),
        ],
    )
    .expect("reconciliation must migrate policy before starting returned handles");

    let rollback = semantic_function_region(
        package,
        "fn rollback_fresh_install(rollback: FreshRollback) -> Result<(), String> {",
        "fn service_owned_cleanup_barrier() -> Result<(), String> {",
    )
    .expect("fresh rollback must end at the transition ownership model");
    require_source_order(
        &rollback,
        &[
            (
                "service_owned_cleanup_barrier()",
                "authenticated service-owned cleanup barrier",
            ),
            (
                "drop(transition);",
                "release retained directory handles only after cleanup",
            ),
            (
                "uninstall_transaction_services(&service_ownership)",
                "transaction-owned service teardown",
            ),
            (
                "ScmAceDisposition::Revoked",
                "transaction-owned SCM authority revocation",
            ),
            (
                "remove_provider_files(ProviderRemovalContext { scm_ace })",
                "package-owned filesystem removal",
            ),
        ],
    )
    .expect("fresh rollback must cross the cleanup barrier before destructive teardown");
    assert!(rollback.contains("MCSEALED-WINDOWS-INSTALL-ROLLBACK-AUTHORITY-RETAINED"));
    assert!(rollback.contains("services=reconciled scm=retained"));
    assert!(rollback.contains("transition.restore_bootstrap().err()"));
    assert!(rollback.contains("uninstall_transaction_services(&service_ownership)"));
    assert!(!rollback.contains("uninstall_services()"));
    assert!(package.contains("rollback_fresh_install(FreshRollback::Transition(transition))"));

    let cleanup_barrier = semantic_function_region(
        package,
        "fn service_owned_cleanup_barrier() -> Result<(), String> {",
        "#[derive(Default)]",
    )
    .expect("service-owned cleanup barrier must end at the transition ownership model");
    assert!(cleanup_barrier.contains("super::qualification::prepare_package_cleanup()"));
    assert!(cleanup_barrier.contains("super::qualification::recovery_status()?"));
    assert!(cleanup_barrier.contains("MCSEALED-WINDOWS-PACKAGE-ACTIVE:"));
    assert!(cleanup_barrier.contains("MCSEALED-WINDOWS-PACKAGE-CLEANUP-TIMEOUT:"));

    let qualification = semantic_function_region(
        package,
        "fn qualify_outside_package_lease(",
        "fn restore_upgrade(",
    )
    .expect("qualification transaction must end before upgrade restoration");
    assert!(qualification.contains("QualificationRollback::Fresh(transition)"));
    assert!(qualification.contains("drop(transition);"));
    assert!(qualification.contains("FreshRollback::Transition(transition)"));

    let transaction_cleanup = semantic_function_region(
        package,
        "fn uninstall_transaction_services(ownership: &ServiceOwnership) -> Result<(), String> {",
        "fn reconcile_services_from_installed() -> Result<(), String> {",
    )
    .expect("transaction-owned cleanup must end before installed reconciliation");
    require_source_order(
        &transaction_cleanup,
        &[
            (
                "(ownership.control_created, WINDOWS_CONTROL_SERVICE_NAME)",
                "transaction-owned control cleanup first",
            ),
            (
                "(ownership.launcher_created, WINDOWS_LAUNCHER_SERVICE_NAME)",
                "transaction-owned launcher cleanup second",
            ),
        ],
    )
    .expect("transaction rollback must remove only owned services in reverse dependency order");
    assert!(transaction_cleanup.contains("MCSEALED-WINDOWS-SERVICE-ROLLBACK-RESIDUAL"));

    let service_manager = include_str!(
        "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/service_manager.rs"
    );
    let remove = semantic_function_region(
        service_manager,
        "pub fn remove(manager: &ScHandle, name: &str) -> Result<(), String> {",
        "fn capture_service_process(",
    )
    .expect("service removal must end at the process-capture helper");
    require_source_order(
        &remove,
        &[
            (
                "let process = capture_service_process(&service, name, Duration::from_secs(2))?;",
                "exact process capture before stop",
            ),
            ("stop(&service, name)?;", "SCM stopped observation"),
            (
                "wait_service_process_exit(&process, name, SERVICE_PROCESS_WAIT)?;",
                "exact process termination barrier",
            ),
            (
                "DeleteService(service.raw())",
                "service registration deletion",
            ),
            (
                "open_for_remove(manager, name, 0)",
                "service registration absence proof",
            ),
        ],
    )
    .expect("service removal must pin, stop, reap, delete, and prove absence in order");

    let capture = semantic_function_region(
        service_manager,
        "fn capture_service_process(",
        "pub(crate) fn wait_service_process_exit(",
    )
    .expect("process capture must end at the exact-process wait helper");
    assert!(capture.contains("PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE_ACCESS"));
    assert!(capture.contains("super::process::process_identity(handle.raw())"));
    assert!(capture.contains("after.dwCurrentState == SERVICE_STOPPED"));
    assert!(capture.contains("after.dwProcessId == 0"));

    let remove_files = semantic_function_region(
        package,
        "fn remove_provider_files(context: ProviderRemovalContext) -> Result<(), String> {",
        "fn require_removed_service_identities() -> Result<(), String> {",
    )
    .expect("provider-file removal must end at its service-absence proof");
    require_source_order(
        &remove_files,
        &[
            (
                "require_removed_service_identities()?;",
                "both service registrations absent before filesystem mutation",
            ),
            ("remove_provider_state(context)?;", "provider state removal"),
            (
                "remove_installed_binary_with_convergence(",
                "bounded installed-image deletion convergence",
            ),
            ("std::fs::remove_dir(&install)", "install-root removal"),
        ],
    )
    .expect("provider cleanup must prove service absence and image deletion before root removal");
    let image_delete = semantic_function_region(
        package,
        "pub(crate) fn remove_installed_binary_with_convergence(",
        "#[derive(Clone, Copy, Debug)]",
    )
    .expect("image convergence must end before provider-state cleanup");
    assert!(image_delete.contains("Some(ERROR_ACCESS_DENIED) | Some(ERROR_SHARING_VIOLATION)"));
    assert!(image_delete.contains("phase=delete-image path="));
    assert!(image_delete.contains("attempts={attempts} elapsed_ms="));

    let provider_state_cleanup = semantic_function_region(
        package,
        "fn remove_provider_state(context: ProviderRemovalContext) -> Result<(), String> {",
        "fn remove_file_if_present(",
    )
    .expect("provider state cleanup must end at the typed file remover");
    require_source_order(
        &provider_state_cleanup,
        &[
            (
                "PackageArtifact::ScmLauncherConnectOwnership",
                "SCM ownership marker cleanup after authority disposition",
            ),
            (
                "StateDirectory::CertificationMarkers",
                "empty certification marker inventory",
            ),
            ("StateDirectory::Package", "empty package root removal"),
            (
                "(\"guardian-slots\", StateDirectory::GuardianSlots)",
                "guardian slot fallback cleanup for partial installation",
            ),
            (
                "remove_state_root_with_kernel_empty_proof(&state, context)?;",
                "kernel-proven sealed state root removal",
            ),
        ],
    )
    .expect("known SCM and guardian-slot state must be removed before their parent roots");
    assert!(!provider_state_cleanup.contains("remove_dir_all"));
    assert!(package.contains("const RESIDUAL_LIMIT: usize = 16;"));
    assert!(package.contains("artifact={artifact}"));

    let record = include_str!(
        "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/record.rs"
    );
    let authenticated_cleanup = semantic_function_region(
        record,
        "pub fn remove_empty_attempt_state() -> Result<(), String> {",
        "fn remove_empty_guardian_slot_state() -> Result<(), String> {",
    )
    .expect("authenticated package cleanup must end at guardian-slot retirement");
    assert!(authenticated_cleanup.contains("remove_empty_guardian_slot_state()?;"));
    assert!(record.contains("phase=retire-guardian-slots"));
    assert!(!record.contains("remove_dir_all"));

    let absence_attestation = semantic_function_region(
        package,
        "pub fn provider_state_absent() -> Result<bool, String> {",
        "fn path_absent_no_follow(path: &Path, phase: &str) -> Result<bool, String> {",
    )
    .expect("provider absence must end at its no-follow inventory helper");
    assert!(absence_attestation.contains("SCM_CONNECT_ACE_MARKER"));
    assert!(absence_attestation.contains("state.join(\"guardian-slots\")"));
    assert!(absence_attestation.contains("path_absent_no_follow"));

    let qualification = semantic_function_region(
        package,
        "fn qualify_outside_package_lease(",
        "fn restore_upgrade(",
    )
    .expect("qualification handoff must end before upgrade restoration");
    assert!(qualification.contains("QUALIFICATION_ROLLBACK_FAULT"));
    assert!(
        qualification.contains(
            "MCSEALED-WINDOWS-CERTIFICATION-FAULT: injected fresh qualification rollback"
        )
    );
    assert!(package.contains("operation == \"install-rollback-certification\""));
    assert!(package.contains("remove qualification rollback fault"));

    let native = include_str!("../src/sealed_windows.rs");
    let rollback_stress = semantic_function_region(
        native,
        "fn certify_fresh_install_rollback(root: &Path, agent: &Path) -> Result<bool> {",
        "fn collect_mutant_kill_evidence(root: &Path, agent: &Path) -> Result<WindowsMutantKillEvidenceV1> {",
    )
    .expect("native rollback stress must end before mutant evidence collection");
    assert!(rollback_stress.contains("const STRESS_ITERATIONS: u32 = 20;"));
    assert!(rollback_stress.contains("install-rollback-certification"));
    assert!(rollback_stress.contains("provider_state_absent(root, agent)?"));
    assert!(rollback_stress.contains("MCSEALED-WINDOWS-INSTALL-ROLLBACK-FAILED"));
}

#[test]
fn windows_fresh_install_filesystem_contract_mutations_are_rejected() {
    let package = normalize_windows_source(include_str!(
        "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/package.rs"
    ));
    validate_windows_fresh_install_contract(&package)
        .expect("unmodified fresh install filesystem contract must be complete");
    let fresh_install = semantic_function_region(
        &package,
        "fn install(ephemeral_ci: bool) -> Result<InstallTransition, String> {",
        "enum FreshRollback {",
    )
    .expect("fresh install must end at its rollback ownership mode");
    let filesystem_preflight = semantic_function_region(
        &package,
        "fn require_fresh_filesystem_absence() -> Result<(), String> {",
        "pub fn verify_installed() -> Result<(), String> {",
    )
    .expect("fresh filesystem preflight has no semantic boundary");

    for (exact, replacement, mutant) in [
        (
            "(\"installed-agent\", installed_binary()),",
            "(\"installed-agent\", state_root()),",
            "installed-agent-residual-predicate-deleted",
        ),
        (
            "\"installed-target-desktop-bootstrap\",\n            installed_target_desktop_bootstrap(),",
            "\"installed-target-desktop-bootstrap\",\n            state_root(),",
            "installed-helper-residual-predicate-deleted",
        ),
        (
            "(\"installed-session-broker\", installed_session_broker()),",
            "(\"installed-session-broker\", state_root()),",
            "installed-broker-residual-predicate-deleted",
        ),
        (
            "(\"installed-state-root\", state_root()),",
            "(\"installed-state-root\", installed_binary()),",
            "installed-state-residual-predicate-deleted",
        ),
        (
            "MCSEALED-WINDOWS-ALREADY-INSTALLED: phase=fresh-install-filesystem-preflight role={role}",
            "MCSEALED-WINDOWS-INSTALL-CONTINUED",
            "already-installed-rejection-deleted",
        ),
        (
            "reject_reparse_components(&path)?;",
            "let _ = &path;",
            "fresh-residual-reparse-preflight-deleted",
        ),
        (
            "path_absent_no_follow(&path, \"fresh-install-filesystem-preflight\")?",
            "path.exists()",
            "fresh-residual-no-follow-preflight-deleted",
        ),
    ] {
        let mut mutated = filesystem_preflight.clone();
        replace_windows_source_once(&mut mutated, exact, replacement, mutant);
        assert!(
            validate_windows_fresh_filesystem_absence_region(&mutated).is_err(),
            "{mutant} survived the fresh install filesystem absence contract"
        );
    }

    for (exact, replacement, mutant) in [
        (
            "if !package_attempts_empty()? {",
            "if false {",
            "package-attempt-preflight-deleted",
        ),
        (
            "require_fresh_service_absence(&manager)?;",
            "let _ = &manager;",
            "service-residual-preflight-deleted",
        ),
        (
            "let source_bootstrap = packaged_target_desktop_bootstrap(&source)?;",
            "let source_bootstrap = source.clone();",
            "helper-source-discovery-deleted",
        ),
        (
            "let source_broker = packaged_session_broker(&source)?;",
            "let source_broker = source.clone();",
            "broker-source-discovery-deleted",
        ),
        (
            "let result = install_transaction(\n        &source,\n        &source_bootstrap,\n        &source_broker,\n        ephemeral_ci,\n        &mut transition,\n    );",
            "let result = Ok(());",
            "install-transaction-boundary-deleted",
        ),
    ] {
        let mut mutated = fresh_install.clone();
        replace_windows_source_once(&mut mutated, exact, replacement, mutant);
        assert!(
            validate_windows_fresh_install_region(&mutated).is_err(),
            "{mutant} survived the fresh install filesystem contract"
        );
    }
}

#[test]
fn windows_artifact_boundary_mutations_are_rejected() {
    let package = normalize_windows_source(include_str!(
        "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/package.rs"
    ));
    let process = normalize_windows_source(include_str!(
        "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/process.rs"
    ));
    validate_windows_artifact_boundary_contract(&package, &process)
        .expect("unmodified Windows artifact boundary must be complete");

    for (exact, replacement, mutant) in [
        (
            "read_regular_no_follow(agent, \"agent-source\")?",
            "std::fs::read(agent)?",
            "agent-no-follow-capture-deleted",
        ),
        (
            "verify_native_target_desktop_bootstrap_pe(&target_desktop_bootstrap_bytes)?",
            "let _ = &target_desktop_bootstrap_bytes;",
            "captured-helper-import-check-deleted",
        ),
        (
            "read_regular_no_follow(session_broker, \"session-broker-source\")?",
            "Vec::new()",
            "broker-no-follow-capture-deleted",
        ),
        (
            "verify_native_session_broker_pe(&session_broker_bytes)?",
            "let _ = &session_broker_bytes;",
            "broker-import-check-deleted",
        ),
        (
            "validate_installed_artifacts(&source_artifacts.digests)?;",
            "let _ = &source_artifacts.digests;",
            "pre-service-installed-pair-check-deleted",
        ),
        (
            "let _installed_artifacts = validate_existing_installed_artifacts()?;",
            "let _installed_artifacts = ();",
            "reconcile-installed-pair-check-deleted",
        ),
        (
            "validate_artifact_pair(\n        &backup,\n        &bootstrap_backup,\n        &broker_backup,\n        Some(&captured.digests),\n    )?;",
            "let _ = (&backup, &bootstrap_backup, &broker_backup);",
            "upgrade-backup-digest-check-deleted",
        ),
        (
            "Some(&rollback.artifact_digests),",
            "None,",
            "upgrade-restore-digest-check-deleted",
        ),
    ] {
        let mut mutated = package.clone();
        replace_windows_source_once(&mut mutated, exact, replacement, mutant);
        assert!(
            validate_windows_artifact_boundary_contract(&mutated, &process).is_err(),
            "{mutant} survived the Windows artifact boundary contract"
        );
    }

    let holder = semantic_function_region(
        &process,
        "impl TargetDesktopLease {",
        "fn launch_target_desktop_probe(",
    )
    .expect("holder launch must have a semantic boundary");
    let probe = semantic_function_region(
        &process,
        "fn launch_target_desktop_probe(",
        "fn read_target_desktop_bootstrap_attestation(",
    )
    .expect("probe launch must have a semantic boundary");
    for (region, role, image_readback) in [
        (
            holder,
            "holder",
            "verify_image_path(bootstrap_process.raw(), &executable)?;",
        ),
        (
            probe,
            "probe",
            "verify_image_path(probe_process.raw(), &executable)?;",
        ),
    ] {
        for (exact, replacement, mutant) in [
            (
                "validate_installed_target_desktop_bootstrap()?",
                "String::new()",
                "pre-launch-helper-validation-deleted",
            ),
            (
                image_readback,
                "let _ = &executable;",
                "post-launch-image-readback-deleted",
            ),
        ] {
            let mut mutated = region.clone();
            replace_windows_source_once(&mut mutated, exact, replacement, mutant);
            assert!(
                validate_windows_helper_launch_region(&mutated, role).is_err(),
                "{role} {mutant} survived the Windows artifact boundary contract"
            );
        }
    }

    let mut process_mutant = process.clone();
    replace_windows_source_once(
        &mut process_mutant,
        "binding.bootstrap_image_sha256\n        != super::package::validate_installed_target_desktop_bootstrap()?",
        "binding.bootstrap_image_sha256 != String::new()",
        "helper-admission-validation-deleted",
    );
    assert!(
        validate_windows_artifact_boundary_contract(&package, &process_mutant).is_err(),
        "helper Admission validation deletion survived the Windows artifact boundary contract"
    );
}

#[test]
fn windows_qualification_and_package_teardown_are_phase_bound() {
    let qualification = include_str!(
        "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/qualification.rs"
    );
    let canary = semantic_function_region(
        qualification,
        "fn native_public_canary(",
        "pub fn certification_target_canary(canary_handles: &[std::ffi::OsString]) -> Result<(), String> {",
    )
    .expect("native public canary must end at its certification target");
    require_source_order(
        &canary,
        &[
            (
                "WindowsProviderResponseV1::StreamsPrepared {",
                "bound stream preparation",
            ),
            (
                "WindowsProviderResponseV1::TargetAuthorized {",
                "bound target authorization",
            ),
            (
                "WindowsProviderResponseV1::TargetRetired {",
                "bound target retirement",
            ),
            (
                "WindowsProviderResponseV1::Terminal(terminal)",
                "terminal evidence",
            ),
        ],
    )
    .expect("qualification must consume public frames in lifecycle order");
    for binding in [
        "schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION",
        "attempt_id.as_deref() == Some(received.as_str())",
        "returned_nonce == nonce",
        "returned_digest == request_sha256",
        "!target_authorized",
        "!target_retired",
        "child_pid != 0",
    ] {
        assert!(
            canary.contains(binding),
            "missing authorization binding {binding}"
        );
    }
    assert!(canary.contains("if !target_authorized || target_retired"));
    assert!(canary.contains("&& target_authorized\n                    && target_retired"));

    let package = include_str!(
        "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/package.rs"
    );
    assert_eq!(
        package
            .matches("super::qualification::prepare_package_cleanup()")
            .count(),
        1,
        "all destructive package paths must use the shared bounded barrier"
    );
    let upgrade = semantic_function_region(
        package,
        "fn upgrade(ephemeral_ci: bool) -> Result<UpgradeInstallation, String> {",
        "enum QualificationRollback {",
    )
    .expect("upgrade must end at qualification rollback ownership");
    assert!(upgrade.contains("service_owned_cleanup_barrier()"));
    assert!(upgrade.contains("transition,"));
    let restore = semantic_function_region(
        package,
        "fn restore_upgrade(",
        "fn cleanup_upgrade_rollback(rollback: &UpgradeRollback) {",
    )
    .expect("upgrade restoration must end before rollback artifact cleanup");
    assert!(restore.contains("service_owned_cleanup_barrier()"));
    assert!(restore.contains("transition.phase.service_cleanup_required()"));
    let uninstall = semantic_function_region(
        package,
        "fn uninstall(ephemeral_ci: bool) -> Result<(), String> {",
        "fn scm_ownership_marker_present() -> Result<bool, String> {",
    )
    .expect("uninstall must end before SCM marker inspection");
    require_source_order(
        &uninstall,
        &[
            (
                "service_owned_cleanup_barrier()?;",
                "authenticated service-owned cleanup barrier",
            ),
            ("uninstall_services()", "service teardown"),
            (
                "super::security::set_scm_launcher_connect(manager.raw(), false)?;",
                "owned SCM authority revocation",
            ),
            (
                "remove_provider_files(ProviderRemovalContext { scm_ace })",
                "package-owned filesystem teardown",
            ),
        ],
    )
    .expect("uninstall must prove cleanup before destroying service and SCM authority");
}

#[test]
fn post_guardian_errors_use_one_finalizer_and_deadline_proves_no_residue() {
    let launch = include_str!(
        "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/launch.rs"
    );
    let execute =
        semantic_function_region(launch, "fn execute_inner(", "fn wait_command_exit_grace(")
            .expect("execute_inner must have a semantic boundary before its next helper");
    let channels = execute
        .find("cleanup_guard.set_guardian_channels(guardian_write, guardian_terminal_read);")
        .expect("guardian channels must enter the cleanup owner");
    let outcome = execute
        .find("let outcome = (|| -> Result<TerminalFacts, String> {")
        .expect("post-guardian work must enter one result funnel");
    let finalizer = execute
        .find("Err(error) => match cleanup_guard.finalize_failure()")
        .expect("every post-guardian error must use the explicit finalizer");
    assert!(channels < outcome && outcome < finalizer);
    assert!(execute.contains("MCSEALED-BOUNDARY-NOT-RETIRED: primary={error}; cleanup={cleanup}"));

    let scenarios =
        include_str!("../../../crates/memcordon-cli/tests/sealed_agent/linux_sealed.rs");
    let deadline = semantic_function_region(
        scenarios,
        "fn sealed_expired_deadline_never_authorizes_and_retires() {",
        "fn sealed_staged_fixture_is_isolated_and_removed_after_retirement() {",
    )
    .expect("expired-deadline selector must have a semantic test boundary");
    for required in [
        "let transaction_path = record_path.with_extension(\"new\");",
        "!record_path.exists()",
        "!transaction_path.exists()",
        "!cgroup_path.exists()",
        "crate::linux::recovery::recover()",
        "ambiguity.is_empty()",
    ] {
        assert!(
            deadline.contains(required),
            "expired-deadline retirement proof omitted {required}"
        );
    }
}

#[test]
fn generic_workspace_tests_ignore_every_privileged_linux_sealed_selector() {
    const STABLE_LEASE_SELECTOR: &str =
        "sealed_package_stable_lease_survives_legacy_inode_replacement";
    let privileged_tests = [
        include_str!("../../../crates/memcordon-cli/tests/sealed_agent/linux_sealed.rs"),
        include_str!("../../../crates/memcordon-cli/tests/sealed_agent/linux_faults.rs"),
        include_str!("../../../crates/memcordon-cli/tests/sealed_agent/linux_recovery.rs"),
        include_str!("../../../crates/memcordon-cli/tests/sealed_agent/linux_package.rs"),
    ];
    let ignored = privileged_tests
        .iter()
        .map(|source| {
            source.matches(PRIVILEGED_REASON).count()
                + source.matches(CREDENTIAL_TRANSITION_REASON).count()
        })
        .sum::<usize>();
    assert_eq!(ignored, 46, "all root-required selectors must be ignored");
    assert_eq!(
        privileged_tests[3].matches(STABLE_LEASE_SELECTOR).count(),
        1
    );
    assert_eq!(
        include_str!("../src/sealed_linux.rs")
            .matches(STABLE_LEASE_SELECTOR)
            .count(),
        1,
        "the stable lease selector must remain in the certified scenario registry"
    );
    assert_eq!(
        include_str!("../src/release_evidence.rs")
            .matches(STABLE_LEASE_SELECTOR)
            .count(),
        1,
        "the stable lease selector must remain in release evidence"
    );

    let provider =
        include_str!("../../../crates/memcordon-cli/tests/sealed_agent/linux_provider.rs");
    assert!(!provider.contains(PRIVILEGED_REASON));
    assert_eq!(provider.matches("#[test]").count(), 3);
}

#[test]
fn dedicated_certification_explicitly_selects_ignored_tests() {
    let runner = include_str!("../src/sealed_linux.rs");
    assert!(runner.contains("if scenario.privileged()"));
    assert!(runner.contains("test_arguments.push(\"--ignored\")"));
    assert!(runner.contains("let exact_name = scenario.exact_name();"));
    assert!(runner.contains("exact_name.as_str(),"));
    assert!(runner.contains("\"--test-threads=1\""));
    assert!(runner.contains("sealed-scenario-progress.json"));
    for state in ["Pending", "Running", "Passed", "Failed"] {
        assert!(
            runner.contains(state),
            "typed scenario progress omitted {state}"
        );
    }
    assert!(runner.contains("bounded_diagnostic_text(&message)"));
    assert!(runner.contains("progress[index].diagnostic = Some(diagnostic)"));
    assert!(runner.contains("observe_scenario_process"));
    assert!(runner.contains("evidence-status={evidence_status:?}"));
    assert!(runner.contains("failed to persist typed scenario evidence"));
    assert!(runner.contains("MCSEALED-CONCURRENCY-EVIDENCE:"));
    assert!(runner.contains("sealed-concurrency-report.json"));
    assert!(runner.contains("typed concurrency evidence did not prove live disjoint overlap"));
    assert!(runner.contains("MCSEALED-FAULT-EVIDENCE:"));
    assert!(runner.contains("parse_fault_evidence"));
    assert!(runner.contains("FaultInjectionReport"));
    assert!(runner.contains("schema_version: 2"));
    assert!(runner.contains("remove_file(report_dir.join(\"sealed-scenario-progress.json\"))"));
}

#[test]
fn consolidated_linux_tests_use_module_qualified_exact_names() {
    for (test_module, test_name, expected) in [
        (
            "linux_provider",
            "qualification_fails_closed_without_root_provider",
            "linux_provider::qualification_fails_closed_without_root_provider",
        ),
        (
            "linux_sealed",
            "sealed_direct_exit_retires_fresh_boundary",
            "linux_sealed::sealed_direct_exit_retires_fresh_boundary",
        ),
        (
            "linux_recovery",
            "sealed_recovery_removes_authenticated_stale_record_without_cgroup",
            "linux_recovery::sealed_recovery_removes_authenticated_stale_record_without_cgroup",
        ),
        (
            "linux_package",
            "sealed_package_identity_rejects_tampered_provider",
            "linux_package::sealed_package_identity_rejects_tampered_provider",
        ),
    ] {
        assert_eq!(exact_test_name(test_module, test_name), expected);
    }
}

#[test]
fn fault_producer_emits_truthful_observation_before_contract_assertions() {
    let producer =
        include_str!("../../../crates/memcordon-cli/tests/sealed_agent/support/sealed_faults.rs");
    let assertion = producer
        .find("assert_eq!(rejection.code, code)")
        .expect("fault producer must assert the exact rejection code");
    let emission = producer
        .find("emit_fault_evidence(selector, captured);")
        .expect("fault producer must emit typed evidence");
    assert!(
        emission < assertion,
        "truthful typed outcome must be emitted before selector contract assertions"
    );
}

#[test]
fn release_inventory_promotes_and_binds_public_provider_evidence() {
    let evidence = include_str!("../src/release_evidence.rs");
    assert!(evidence.contains("validate_linux_fault_evidence"));
    assert!(evidence.contains("LINUX_FAULT_EVIDENCE_TESTS"));
    let specification = include_str!("../../../spec/sealed-linux-v2.md");
    for name in [
        "provider-package-verification.json",
        "provider-qualification-v2.json",
        "setid-transition.json",
        "sudo-transition.json",
        "file-capability-transition.json",
        "caller-envelope.json",
        "mount-context.json",
        "fault-injection.json",
        "cleanup-leak-check.json",
    ] {
        assert!(evidence.contains(name), "release inventory omitted {name}");
        assert!(
            specification.contains(name),
            "sealed specification omitted {name}"
        );
    }
    for required in [
        "LinuxProviderPackageVerification",
        "validate_linux_provider_package",
        "validate_linux_public_launch",
        "linux_provider_binding",
        "linux_qualification_complete",
        "BoundaryMechanismEvidence::LinuxPidNamespaceCgroupV2",
        "CredentialTransitionDisposition::PreserveCallerEnvelope",
        "SupervisionTerminal::AttemptOutcome",
    ] {
        assert!(
            evidence.contains(required),
            "release validation omitted {required}"
        );
    }
}

#[test]
fn credential_redesign_fuzz_targets_bind_real_parser_surfaces() {
    let manifest = include_str!("../../../fuzz/Cargo.toml");
    let suite = include_str!("../src/suites.rs");
    let targets = [
        (
            "caller-envelope-status",
            include_str!("../../../fuzz/fuzz_targets/caller_envelope_status.rs"),
            "parse_proc_status",
        ),
        (
            "capability-mask",
            include_str!("../../../fuzz/fuzz_targets/capability_mask.rs"),
            "parse_capability_mask",
        ),
        (
            "namespace-identity",
            include_str!("../../../fuzz/fuzz_targets/namespace_identity.rs"),
            "parse_namespace_identity",
        ),
        (
            "broker-protocol-v2",
            include_str!("../../../fuzz/fuzz_targets/broker_protocol_v2.rs"),
            "decode_launch_broker_request",
        ),
        (
            "qualification-receipt-v2",
            include_str!("../../../fuzz/fuzz_targets/qualification_receipt_v2.rs"),
            "sealed_qualification_v2_is_valid",
        ),
        (
            "terminal-receipt-v2",
            include_str!("../../../fuzz/fuzz_targets/terminal_receipt_v2.rs"),
            "sealed_terminal_v2_is_valid",
        ),
        (
            "linux-evidence-v2",
            include_str!("../../../fuzz/fuzz_targets/linux_evidence_v2.rs"),
            "BoundaryMechanismEvidence",
        ),
        (
            "service-unit-policy",
            include_str!("../../../fuzz/fuzz_targets/service_unit_policy.rs"),
            "fuzz_linux_service_unit_policy",
        ),
        (
            "provider-recursion-proof",
            include_str!("../../../fuzz/fuzz_targets/provider_recursion_proof.rs"),
            "cgroup_membership::is_sealed",
        ),
        (
            "mount-context-manifest",
            include_str!("../../../fuzz/fuzz_targets/mount_context_manifest.rs"),
            "fuzz_linux_mount_context_manifest",
        ),
        (
            "runtime-manifest",
            include_str!("../../../fuzz/fuzz_targets/runtime_manifest.rs"),
            "fuzz_runtime_manifest",
        ),
        (
            "release-asset-components",
            include_str!("../../../fuzz/fuzz_targets/release_asset_components.rs"),
            "config::Release",
        ),
        (
            "agent-package-inspection",
            include_str!("../../../fuzz/fuzz_targets/agent_package_inspection.rs"),
            "AgentPackageInspectionV3",
        ),
        (
            "installed-provider-inspection",
            include_str!("../../../fuzz/fuzz_targets/installed_provider_inspection.rs"),
            "InstalledProviderInspectionV3",
        ),
        (
            "cargo-bin-inventory",
            include_str!("../../../fuzz/fuzz_targets/cargo_bin_inventory.rs"),
            "toml::Value",
        ),
        (
            "channel-pairing",
            include_str!("../../../fuzz/fuzz_targets/channel_pairing.rs"),
            "source_commit",
        ),
        (
            "windows-public-provider-protocol",
            include_str!("../../../fuzz/fuzz_targets/windows_public_provider_protocol.rs"),
            "WindowsProviderRequestV1",
        ),
        (
            "windows-private-launcher-protocol",
            include_str!("../../../fuzz/fuzz_targets/windows_private_launcher_protocol.rs"),
            "WindowsLauncherRequestV1",
        ),
        (
            "windows-token-envelope",
            include_str!("../../../fuzz/fuzz_targets/windows_token_envelope.rs"),
            "WindowsCallerTokenEnvelopeV1",
        ),
        (
            "windows-security-descriptor",
            include_str!("../../../fuzz/fuzz_targets/windows_security_descriptor.rs"),
            "validate_windows_security_descriptor_text",
        ),
        (
            "windows-handle-manifest",
            include_str!("../../../fuzz/fuzz_targets/windows_handle_manifest.rs"),
            "WindowsRemoteStreamV1",
        ),
        (
            "windows-environment-block",
            include_str!("../../../fuzz/fuzz_targets/windows_environment_block.rs"),
            "WindowsEnvironmentEntryV1",
        ),
        (
            "windows-argv",
            include_str!("../../../fuzz/fuzz_targets/windows_argv.rs"),
            "encode_windows_command_line",
        ),
        (
            "windows-qualification",
            include_str!("../../../fuzz/fuzz_targets/windows_qualification.rs"),
            "is_consistent",
        ),
        (
            "windows-terminal-receipt",
            include_str!("../../../fuzz/fuzz_targets/windows_terminal_receipt.rs"),
            "WindowsTerminalReceiptV1",
        ),
        (
            "windows-attempt-record",
            include_str!("../../../fuzz/fuzz_targets/windows_attempt_record.rs"),
            "windows_certification_transition_allowed",
        ),
        (
            "windows-package-inspection",
            include_str!("../../../fuzz/fuzz_targets/windows_package_inspection.rs"),
            "AgentPackageInspectionV3",
        ),
    ];

    for (target, source, parser) in targets {
        assert!(
            manifest.contains(&format!("name = \"{target}\"")),
            "fuzz manifest omitted {target}"
        );
        assert!(
            suite.contains(&format!("\"{target}\"")),
            "fuzz suite omitted {target}"
        );
        assert!(
            source.contains(parser),
            "{target} does not exercise {parser}"
        );
    }
}

#[test]
fn sealed_fixtures_are_isolated_and_status_assertions_are_mandatory() {
    let support = include_str!("../../../crates/memcordon-cli/tests/sealed_agent/support/mod.rs");
    let scenarios =
        include_str!("../../../crates/memcordon-cli/tests/sealed_agent/linux_sealed.rs");
    let fixture =
        include_str!("../../../crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture.rs");

    for required in [
        ".tempdir_in(\"/tmp\")",
        ".create_new(true)",
        "directory_metadata.uid() != 0",
        "program_metadata.uid() != 0",
        "Permissions::from_mode(0o755)",
        "Permissions::from_mode(0o555)",
    ] {
        assert!(support.contains(required), "fixture omitted {required}");
    }
    assert!(!support.contains("set_permissions(Path::new(fixture())"));
    assert!(scenarios.contains("fixture mode {mode} did not complete successfully"));
    assert!(scenarios.contains("sealed_native_nonzero_exit_preserves_provenance"));
    assert!(scenarios.contains("assert_eq!(captured.facts.child_status, 17)"));
    assert!(scenarios.contains("retired attempt leaked its isolated fixture"));
    assert!(scenarios.contains("expired attempt leaked its isolated fixture"));
    assert!(fixture.contains("\"retained-stream\""));
    assert!(fixture.contains("Duration::from_millis(500)"));
    assert!(fixture.contains("if descendant == -1"));
    assert!(fixture.contains("retained-stdout-release"));
    assert!(fixture.contains("retained-stderr-release"));
    assert!(fixture.contains("\"fault-ready\""));
    assert!(scenarios.contains("prepare_fault_target"));
    assert!(!scenarios.contains("run(\"child\", Lifetime::Workload)"));
    for required in [
        ".request(\"retained-stream\", Lifetime::Workload)",
        "captured.execution_millis >= 400",
        "captured.execution_millis < 10_000",
        "captured.facts.exec_status, TargetExecStatus::Succeeded",
        "captured.facts.spawn_error_reported",
        "!captured.facts.deadline_exceeded",
        "!captured.facts.memory_limit_exceeded",
        "retained-stream attempt leaked its isolated fixture",
    ] {
        assert!(
            scenarios.contains(required),
            "retained-stream scenario omitted {required}"
        );
    }
}

#[test]
fn package_scenarios_tamper_and_recover_real_installed_state() {
    let package =
        include_str!("../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/package.rs");
    let scenarios =
        include_str!("../../../crates/memcordon-cli/tests/sealed_agent/linux_package.rs");
    let runner = include_str!("../src/sealed_linux.rs");

    for required in [
        "MCSEALED-PACKAGE-VERIFY: installed package is incomplete",
        "ArtifactAccess::MetadataOnly => libc::O_PATH",
        "ArtifactAccess::Readable => 0",
        "custom_flags(access_flag | libc::O_CLOEXEC | libc::O_NOFOLLOW)",
        "let metadata = file",
        ".metadata()",
        "metadata.uid() != expected_uid || metadata.gid() != expected_gid",
        "metadata.mode() & 0o7777 != expected_mode",
        "actual != expected_bytes",
        "verify_metadata_artifact(",
        "std::path::Path::new(crate::linux::service::PACKAGE_LEASE)",
        "verify_readable_artifact(",
    ] {
        assert!(
            package.contains(required),
            "installed package verification omitted {required}"
        );
    }
    let verify_path = semantic_function_region(
        package,
        "pub(crate) fn verify() -> Result<(), String> {",
        "fn render_inspection(inspection: &AgentPackageInspectionV3, json: bool) -> Result<(), String> {",
    )
    .expect("explicit package verification must end before inspection rendering");
    assert_eq!(
        verify_path.matches("verify_installed_package()?;").count(),
        1,
        "explicit Linux package verification must verify installed state exactly once"
    );

    let invoked_verification = semantic_function_region(
        package,
        "fn verify_installed_package() -> Result<(), String> {",
        "fn verify_installed_package_against(packaged_executable_sha256: &str) -> Result<(), String> {",
    )
    .expect("invoked-package verification must delegate to the digest-bound verifier");
    require_source_order(
        &invoked_verification,
        &[
            (
                "let packaged_executable = inspect()?;",
                "invoked package inspection",
            ),
            (
                "verify_installed_package_against(&packaged_executable.executable_sha256)",
                "installed package verification bound to the invoked digest",
            ),
        ],
    )
    .expect("explicit package verification must use the invoked executable digest");

    let mutation = semantic_function_region(
        package,
        "fn linux_mutation(operation: &OsStr, ephemeral_ci: bool) -> Result<(), String> {",
        "fn remove_uninstalled_file(path: &str) -> Result<(), String> {",
    )
    .expect("Linux mutation must end before uninstall cleanup helpers");
    require_source_order(
        &mutation,
        &[
            (
                "let source_bytes = fs::read(&source).map_err(|error| error.to_string())?;",
                "source capture before replacement",
            ),
            (
                "let source_digest = sha256_bytes(&source_bytes);",
                "digest capture before replacement",
            ),
            (
                "(Path::new(BINARY), source_bytes, 0o755),",
                "installation of the captured executable bytes",
            ),
            (
                "fs::rename(temporary, path).map_err(|error| error.to_string())?;",
                "atomic artifact replacement",
            ),
            (
                "verify_installed_package_against(&source_digest)?;",
                "post-write verification against the captured source identity",
            ),
            (
                "systemctl([\"daemon-reload\"])?;",
                "daemon reload only after verification",
            ),
            (
                "systemctl([\"start\", \"memcordon-sealed-launcher.socket\"])?;",
                "ephemeral advertisement only after verification",
            ),
        ],
    )
    .expect("install and upgrade must verify captured bytes before advertisement");
    assert_eq!(
        mutation
            .matches("verify_installed_package_against(&source_digest)?;")
            .count(),
        1,
        "Linux package mutation must verify the installed package exactly once"
    );
    assert!(
        !mutation.contains("verify_installed_package()?;"),
        "Linux package mutation must not reopen the replaced executable through the zero-argument verifier"
    );
    let install = runner
        .find("privileged_agent(root, [\"package\", \"install\", \"--ephemeral-ci\"])")
        .expect("certification must install the provider");
    let verify = runner
        .find("agent(root, [\"package\", \"verify\"])")
        .expect("certification must verify the installed provider");
    let upgrade = runner
        .find("privileged_agent(root, [\"package\", \"upgrade\", \"--ephemeral-ci\"])")
        .expect("certification must upgrade the provider");
    assert!(install < verify && verify < upgrade);
    for required in [
        "\"schema_version\": 3",
        "\"/usr/libexec/memcordon-sealed-agent\"",
        "\"/run/memcordon-sealed-package.lock\"",
    ] {
        assert!(
            runner.contains(required),
            "package evidence omitted {required}"
        );
    }
    for required in [
        "tampered.set_mode(0o775)",
        "assert_eq!(rejected.status.code(), Some(125))",
        "rejection.starts_with(\"MCSEALED-PACKAGE-VERIFY:\")",
        "AttemptRecord::create(",
        "libc::pid_t::MAX",
        "record.transition(\"boundary-created\")",
        "record-only stale recovery fixture must not stage an attempt cgroup",
        "upgrade advertised before retiring the authenticated stale record",
        "stale_record.disarm()",
        "assert_active_capability_caller_rejected(&execution)",
        "MCSEALED-CALLER-ENVELOPE-CAPTURE",
        "MCSEALED-CREDENTIAL-TRANSITION-POLICY: callers with active capability sets are unsupported",
        "BoundarySetupPhase::RequestValidation",
        "assert!(!rejection.target_created)",
        "assert!(!rejection.target_released)",
        "assert!(!rejection.cleanup_attempted)",
        "libc::kill(frontend_pid, 0)",
        ".args([\"package\", \"uninstall\", \"--ephemeral-ci\"])",
        "refusing to uninstall while sealed recovery is ambiguous",
        "assert_eq!(std::fs::read(&record_path).unwrap(), authenticated_before)",
        "refused uninstall damaged the installed provider",
        "live_record.record.take().unwrap().retire().unwrap()",
        "assert!(!record_path.exists())",
    ] {
        assert!(
            scenarios.contains(required),
            "privileged package scenario omitted {required}"
        );
    }
}

#[test]
fn package_stop_suppresses_success_noise_and_bounds_failure_diagnostics() {
    let package =
        include_str!("../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/package.rs");
    let stop = semantic_function_region(
        package,
        "fn stop_unit(unit: &str) -> Result<(), String> {",
        "fn systemctl_output_diagnostic(output: &std::process::Output) -> serde_json::Value {",
    )
    .expect("stop_unit must precede its structured diagnostic helper");
    for required in [
        ".args([\"stop\", unit])",
        ".output()",
        "if output.status.success()",
        "return Ok(())",
        "systemctl_output_diagnostic(&output)",
        "MCSEALED-PACKAGE-STOP: unit={unit}",
        "load-state={state}",
        "load-state-error={error}",
    ] {
        assert!(
            stop.contains(required),
            "package stop path omitted {required}"
        );
    }
    assert!(
        !stop.contains(".status()"),
        "successful systemctl output must not escape through inherited streams"
    );
    for required in [
        "MAXIMUM_BYTES: usize = 4 * 1024",
        "\"encoding\": \"utf-8\"",
        "\"encoding\": \"hex\"",
        "\"original_bytes\": bytes.len()",
        "\"truncated\": truncated",
    ] {
        assert!(
            package.contains(required),
            "bounded systemctl diagnostic omitted {required}"
        );
    }
}

#[test]
fn certification_uses_a_nonroot_frontend_with_the_provider_access_group() {
    let runner = include_str!("../src/sealed_linux.rs");
    let identity = include_str!("../src/sealed_identity.rs");
    assert!(runner.contains("authorized_nonroot_memcordon"));
    assert!(runner.contains("Path::new(\"/usr/bin/cat\")"));
    assert!(runner.contains("[\"/proc/self/status\"]"));
    assert!(runner.contains("parse_credential_readback"));
    assert!(identity.contains("pub const SETPRIV_PATH: &str = \"/usr/bin/setpriv\""));
    assert!(identity.contains("OsString::from(\"--clear-groups\")"));
    assert!(identity.contains("OsString::from(\"--inh-caps=-all\")"));
    assert!(identity.contains("OsString::from(\"--ambient-caps=-all\")"));
    assert!(identity.contains("OsString::from(\"--no-new-privs\")"));
    assert!(!runner.contains("OsString::from(\"--user\")"));
    assert!(!runner.contains("OsString::from(\"--group\")"));
    assert!(
        runner.contains("const PRE_SCENARIO_PUBLIC_REPORT: &str = \".sealed-public-launch.json\"")
    );
    assert!(runner.contains(
        "const POST_UPGRADE_PUBLIC_REPORT: &str = \".sealed-post-scenario-public-launch.json\""
    ));
    assert!(runner.contains("OsString::from(\"--sealed\")"));
    assert!(runner.contains("OsString::from(\"--report\")"));
    assert!(runner.contains("public_report.as_os_str().to_os_string()"));
    assert!(runner.contains("OsString::from(\"/usr/bin/true\")"));
    assert_eq!(runner.matches("validate_public_launch(").count(), 3);
    let certification_start = runner
        .find("fn certification_body(")
        .expect("certification body must exist");
    let certification_end = runner[certification_start..]
        .find("pub fn certify(")
        .expect("certification wrapper must follow its body")
        + certification_start;
    let certification = &runner[certification_start..certification_end];
    let upgrade = certification
        .find("if scenario.name == \"sealed_package_upgrade_recovers_before_advertising\"")
        .expect("upgrade must own the clean nonroot public proof");
    let post_upgrade_proof = certification
        .find("validate_post_upgrade_public_proof(root, &identity, report_dir, &receipt)")
        .expect("upgrade must run the clean nonroot public proof");
    let passed = certification
        .find("progress[index].state = ScenarioProgressState::Passed")
        .expect("certification must record scenario success");
    assert!(upgrade < post_upgrade_proof && post_upgrade_proof < passed);
    assert!(
        certification.contains("ScenarioRunFailure::setup(\"post-upgrade-public-proof\", error)")
    );
    let proof_start = runner
        .find("fn validate_post_upgrade_public_proof(")
        .expect("post-upgrade public proof must have one explicit implementation");
    let proof_end = runner[proof_start..]
        .find("fn validate_public_execution_report(")
        .expect("public report validation must follow the post-upgrade proof")
        + proof_start;
    let proof = &runner[proof_start..proof_end];
    assert!(proof.contains("verify_frontend_credentials(root, identity)?"));
    assert_eq!(
        proof.matches("authorized_nonroot(root, identity").count(),
        1
    );
    assert!(proof.contains("[\"probe\"]"));
    assert_eq!(proof.matches("validate_public_launch(").count(), 1);
    let after_post_upgrade_dispatch = &certification[post_upgrade_proof..];
    assert!(!after_post_upgrade_dispatch.contains("verify_frontend_credentials("));
    assert!(!after_post_upgrade_dispatch.contains("authorized_nonroot("));
    assert!(!after_post_upgrade_dispatch.contains("validate_public_launch("));
    let post_loop_start = certification
        .find("let post_upgrade_public_path = report_dir.join(POST_UPGRADE_PUBLIC_REPORT)")
        .expect("evidence assembly must consume the post-upgrade public proof");
    let post_loop = &certification[post_loop_start..];
    assert!(post_loop.contains("let public_path = post_upgrade_public_path;"));
    assert!(runner.contains("if post_upgrade_report.is_file()"));
}

#[test]
fn package_refusal_preflight_preserves_live_service_state() {
    let package =
        include_str!("../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/package.rs");
    let package_tests =
        include_str!("../../../crates/memcordon-cli/tests/sealed_agent/linux_package.rs");
    let runner = include_str!("../src/sealed_linux.rs");

    let mutation_start = package
        .find("fn linux_mutation(")
        .expect("Linux package mutation must exist");
    let mutation_end = package[mutation_start..]
        .find("fn ensure_recovery_idle(")
        .expect("package recovery-idle proof must follow mutation")
        + mutation_start;
    let mutation = &package[mutation_start..mutation_end];
    let recovery_idle_start = mutation_end;
    let recovery_idle_end = package[recovery_idle_start..]
        .find("fn verify_client_access(")
        .expect("client access verification must follow recovery-idle proof")
        + recovery_idle_start;
    let recovery_idle = &package[recovery_idle_start..recovery_idle_end];
    assert!(recovery_idle.contains("crate::linux::recovery::recover()?"));
    assert!(recovery_idle.contains("live_attempt_exists()?"));
    let uninstall = mutation
        .find("if operation == \"uninstall\"")
        .expect("uninstall branch must exist");
    let uninstall_preflight = mutation[uninstall..]
        .find("ensure_recovery_idle(\"uninstall\")")
        .expect("uninstall must preflight authenticated state")
        + uninstall;
    let first_stop = mutation[uninstall..]
        .find("stop_unit(\"memcordon-sealed-agent.service\")")
        .expect("uninstall must stop the provider after preflight")
        + uninstall;
    let uninstall_post_stop = mutation[first_stop..]
        .find("ensure_recovery_idle(\"uninstall\")")
        .expect("uninstall must recover again after all units stop")
        + first_stop;
    assert!(uninstall_preflight < first_stop && first_stop < uninstall_post_stop);

    let upgrade = mutation
        .find("if operation == \"upgrade\"")
        .expect("upgrade branch must exist");
    let upgrade_preflight = mutation[upgrade..]
        .find("ensure_recovery_idle(\"upgrade\")")
        .expect("upgrade must preflight authenticated state")
        + upgrade;
    let upgrade_first_stop = mutation[upgrade..]
        .find("stop_unit(\"memcordon-sealed-agent.service\")")
        .expect("upgrade must stop the provider after preflight")
        + upgrade;
    let upgrade_post_stop = mutation[upgrade_first_stop..]
        .find("ensure_recovery_idle(\"upgrade\")")
        .expect("upgrade must recover again after all units stop")
        + upgrade_first_stop;
    assert!(upgrade_preflight < upgrade_first_stop && upgrade_first_stop < upgrade_post_stop);

    for lifecycle_call in [
        "stop_unit(\"memcordon-sealed-agent.service\")",
        "stop_unit(\"memcordon-sealed-launcher.service\")",
        "stop_unit(\"memcordon-sealed-agent.socket\")",
        "stop_unit(\"memcordon-sealed-launcher.socket\")",
        "ensure_unit_inactive(\"memcordon-sealed-agent.service\")",
        "ensure_unit_inactive(\"memcordon-sealed-launcher.service\")",
        "ensure_unit_inactive(\"memcordon-sealed-agent.socket\")",
        "ensure_unit_inactive(\"memcordon-sealed-launcher.socket\")",
    ] {
        assert_eq!(mutation.matches(lifecycle_call).count(), 2);
        let uninstall_lifecycle = mutation[uninstall..]
            .find(lifecycle_call)
            .expect("uninstall must retain every lifecycle boundary")
            + uninstall;
        let upgrade_lifecycle = mutation[upgrade..]
            .find(lifecycle_call)
            .expect("upgrade must retain every lifecycle boundary")
            + upgrade;
        assert!(
            uninstall_preflight < uninstall_lifecycle && uninstall_lifecycle < uninstall_post_stop
        );
        assert!(upgrade_preflight < upgrade_lifecycle && upgrade_lifecycle < upgrade_post_stop);
    }

    let refusal_start = package_tests
        .find("fn sealed_package_uninstall_refuses_live_authenticated_attempt()")
        .expect("uninstall-refusal scenario must exist");
    let refusal = &package_tests[refusal_start..];
    assert_eq!(refusal.matches("active_provider_unit_states()").count(), 2);
    assert_eq!(refusal.matches("installed_package_bytes()").count(), 2);
    assert!(
        refusal.contains("assert_eq!(std::fs::read(&record_path).unwrap(), authenticated_before)")
    );
    assert!(refusal.contains("let probe = Command::new(AGENT).arg(\"probe\")"));

    let inventory_start = runner
        .find("const SCENARIOS: &[Scenario] = &[")
        .expect("scenario inventory must exist");
    let inventory_end = runner[inventory_start..]
        .find("struct QualificationReceipt")
        .expect("qualification receipt must follow the scenario inventory")
        + inventory_start;
    let inventory = &runner[inventory_start..inventory_end];
    let upgrade_scenario = inventory
        .find("name: \"sealed_package_upgrade_recovers_before_advertising\"")
        .expect("upgrade scenario must remain certified");
    let uninstall_scenario = inventory
        .find("name: \"sealed_package_uninstall_refuses_live_authenticated_attempt\"")
        .expect("uninstall refusal scenario must remain certified");
    assert!(upgrade_scenario < uninstall_scenario);
    assert_eq!(
        inventory[upgrade_scenario..uninstall_scenario]
            .matches("name: ")
            .count(),
        1,
        "uninstall refusal must immediately follow the upgrade scenario"
    );
    assert_eq!(
        inventory[uninstall_scenario..].matches("name: ").count(),
        1,
        "uninstall refusal must remain the final scenario"
    );
}
