#![cfg(windows)]

use std::ptr::null_mut;

use memcordon_windows_launch_core::{
    DesktopBindingV1, ExactHandleListV1, LoaderReadyEndpointV1, NativeSecurityDescriptorV1,
    PreparedCurrentDirectoryV1, PreparedLoaderCommandV1, PreparedLoaderEnvironmentV1,
    ProductionLoaderPlanInputV1, ProductionNativeCreateRequestV1, TargetTokenIdentityV1,
    build_package_loader_plan, create_suspended_in_job,
};

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SECURITY_SDDL: &str = "D:P(A;;GA;;;SY)";

struct NativeMaterialFixture {
    plan: memcordon_windows_launch_core::ProductionLoaderPlanV1,
    application: Vec<u16>,
    command: PreparedLoaderCommandV1,
    environment: PreparedLoaderEnvironmentV1,
    current_directory: PreparedCurrentDirectoryV1,
    process_security: NativeSecurityDescriptorV1,
    thread_security: NativeSecurityDescriptorV1,
    exact_desktop: Vec<u16>,
}

impl NativeMaterialFixture {
    fn new() -> Self {
        let executable = r"C:\Program Files\MemCordon\bootstrap.exe"
            .encode_utf16()
            .collect::<Vec<_>>();
        let exact_desktop_name = format!("MemCordonTarget-{}\\Restricted", "ab".repeat(32));
        let exact_desktop_units = exact_desktop_name.encode_utf16().collect::<Vec<_>>();
        let endpoint = LoaderReadyEndpointV1::new("cd".repeat(32))
            .expect("fixture nonce should construct a loader-ready endpoint");
        let command =
            PreparedLoaderCommandV1::loader_control(&executable, &endpoint, &exact_desktop_units)
                .expect("fixture command should be canonical");
        let environment = PreparedLoaderEnvironmentV1::new(vec![0, 0])
            .expect("fixture environment should be double-NUL terminated");
        let current_directory = PreparedCurrentDirectoryV1::new(
            r"C:\Program Files\MemCordon"
                .encode_utf16()
                .collect::<Vec<_>>(),
        )
        .expect("fixture current directory should be canonical");
        let plan = build_package_loader_plan(ProductionLoaderPlanInputV1 {
            executable_path_utf16: executable.clone(),
            executable_sha256: String::from(DIGEST),
            command_line_sha256: command.semantic_sha256().to_owned(),
            environment: environment.identity().clone(),
            current_directory_sha256: current_directory.sha256().to_owned(),
            desktop: DesktopBindingV1 {
                exact_name: exact_desktop_name,
                security_descriptor_sha256: String::from(DIGEST),
                window_station_security_descriptor_sddl: String::from(SECURITY_SDDL),
                desktop_security_descriptor_sddl: String::from(SECURITY_SDDL),
            },
            process_security_descriptor_sddl: String::from(SECURITY_SDDL),
            thread_security_descriptor_sddl: String::from(SECURITY_SDDL),
            job_security_descriptor_sddl: String::from(SECURITY_SDDL),
            loader_ready_pipe_security_descriptor_sddl: String::from(SECURITY_SDDL),
            target_token: TargetTokenIdentityV1 {
                envelope_sha256: String::from(DIGEST),
                authentication_id: 7,
                session_id: 0,
            },
            inherited_handles: ExactHandleListV1::none(),
            job_at_creation: true,
        })
        .expect("fixture plan should be valid");
        let process_security = NativeSecurityDescriptorV1::from_sddl(SECURITY_SDDL)
            .expect("fixture process descriptor should parse");
        let thread_security = NativeSecurityDescriptorV1::from_sddl(SECURITY_SDDL)
            .expect("fixture thread descriptor should parse");
        let mut application = executable;
        application.push(0);
        let mut exact_desktop = exact_desktop_units;
        exact_desktop.push(0);
        Self {
            plan,
            application,
            command,
            environment,
            current_directory,
            process_security,
            thread_security,
            exact_desktop,
        }
    }

    fn create_with_desktop(
        &mut self,
        desktop: &mut [u16],
    ) -> memcordon_windows_launch_core::NativeCreateErrorV1 {
        let result = create_suspended_in_job(ProductionNativeCreateRequestV1 {
            plan: &self.plan,
            target_token: null_mut(),
            job: null_mut(),
            application: &self.application,
            command: &mut self.command,
            environment: &mut self.environment,
            current_directory: &self.current_directory,
            desktop,
            process_security: Some(&self.process_security),
            thread_security: Some(&self.thread_security),
        });
        match result {
            Ok(_) => panic!("invalid authority handles must prevent native process creation"),
            Err(error) => error,
        }
    }
}

#[test]
fn pre_resume_desktop_material_is_exact_nul_terminated_and_plan_bound() {
    let mut fixture = NativeMaterialFixture::new();

    let mut mismatched = format!("MemCordonTarget-{}\\Other", "ab".repeat(32))
        .encode_utf16()
        .collect::<Vec<_>>();
    mismatched.push(0);
    let mismatch = fixture.create_with_desktop(&mut mismatched);
    assert_eq!(mismatch.stable_code, "concrete-plan-mismatch");
    assert!(mismatch.win32_error.is_none());

    let mut unterminated = fixture
        .exact_desktop
        .strip_suffix(&[0])
        .expect("fixture desktop should have a trailing NUL")
        .to_vec();
    let unterminated_error = fixture.create_with_desktop(&mut unterminated);
    assert_eq!(unterminated_error.stable_code, "unterminated-native-buffer");
    assert!(unterminated_error.win32_error.is_none());

    let mut exact = fixture.exact_desktop.clone();
    let accepted_material = fixture.create_with_desktop(&mut exact);
    assert_eq!(accepted_material.stable_code, "invalid-authority-handle");
    assert!(accepted_material.win32_error.is_none());
}
