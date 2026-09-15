use super::{
    ValidatedBuildContext, enroll_miri_sysroot, enrollment_identity_output, native,
    require_same_inputs,
};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::ffi::OsStr;

fn fixture() -> (tempfile::TempDir, ValidatedBuildContext) {
    let temporary = tempfile::tempdir().unwrap();
    let parent = temporary.path().canonicalize().unwrap();
    let root = parent.join("workspace");
    let home = parent.join("cargo-home");
    let compiler = parent.join("compiler");
    let support = parent.join("helper-support");
    let sdk = parent.join("sdk");
    for path in [&root, &home, &compiler, &support, &sdk] {
        std::fs::create_dir(path).unwrap();
    }
    for path in [&root, &compiler, &support, &sdk] {
        std::fs::write(path.join("input"), b"abc").unwrap();
    }
    let mut selected = ValidatedBuildContext {
        schema_version: 3,
        root,
        environment: vec![(native(OsStr::new("CARGO_HOME")), native(home.as_os_str()))],
        toolchains: BTreeMap::from([("reviewed".to_owned(), compiler.join("input"))]),
        input_roots: vec![compiler, support],
        discovery_roots: vec![sdk],
        inputs: Vec::new(),
        worker: BTreeMap::new(),
    };
    selected.inputs = selected.measure_inputs().unwrap();
    (temporary, selected)
}

fn copy(context: &ValidatedBuildContext) -> ValidatedBuildContext {
    serde_json::from_slice(&serde_json::to_vec(context).unwrap()).unwrap()
}

#[test]
fn independent_enrollment_rejects_self_consistent_root_and_record_omissions() {
    let (_temporary, selected) = fixture();
    selected
        .audit_with_discovery(|| Ok(copy(&selected)))
        .unwrap();
    for index in 0..selected.input_roots.len() {
        let mut omitted = copy(&selected);
        omitted.input_roots.remove(index);
        // Reproduce the old acceptance condition: the omitted root and all its
        // records disappear together, leaving a self-consistent measured set.
        omitted.inputs = omitted.measure_inputs().unwrap();
        require_same_inputs(&omitted.measure_inputs().unwrap(), &omitted.inputs).unwrap();
        assert!(
            omitted
                .audit_with_discovery(|| Ok(copy(&selected)))
                .unwrap_err()
                .to_string()
                .contains("input_roots")
        );
    }
    for index in 0..selected.discovery_roots.len() {
        let mut omitted = copy(&selected);
        omitted.discovery_roots.remove(index);
        omitted.inputs = omitted.measure_inputs().unwrap();
        require_same_inputs(&omitted.measure_inputs().unwrap(), &omitted.inputs).unwrap();
        assert!(
            omitted
                .audit_with_discovery(|| Ok(copy(&selected)))
                .unwrap_err()
                .to_string()
                .contains("discovery_roots")
        );
    }
}

#[test]
fn enrollment_binds_workspace_environment_and_selected_toolchain() {
    let (temporary, selected) = fixture();
    let mut changed = copy(&selected);
    changed.root = temporary
        .path()
        .canonicalize()
        .unwrap()
        .join("other-workspace");
    std::fs::create_dir(&changed.root).unwrap();
    changed.inputs = changed.measure_inputs().unwrap();
    require_same_inputs(&changed.measure_inputs().unwrap(), &changed.inputs).unwrap();
    assert!(
        changed
            .audit_with_discovery(|| Ok(copy(&selected)))
            .unwrap_err()
            .to_string()
            .contains("for root")
    );

    let mut changed = copy(&selected);
    changed.environment.push((
        native(OsStr::new("SDKROOT")),
        native(temporary.path().as_os_str()),
    ));
    assert!(
        changed
            .audit_with_discovery(|| Ok(copy(&selected)))
            .unwrap_err()
            .to_string()
            .contains("environment")
    );

    let mut changed = copy(&selected);
    changed
        .toolchains
        .insert("reviewed".to_owned(), selected.root.join("input"));
    assert!(
        changed
            .audit_with_discovery(|| Ok(copy(&selected)))
            .unwrap_err()
            .to_string()
            .contains("toolchains")
    );
}

#[test]
fn correct_enrollment_still_requires_every_record_and_current_content() {
    let (_temporary, selected) = fixture();
    for index in 0..selected.inputs.len() {
        let mut omitted = copy(&selected);
        omitted.inputs.remove(index);
        assert!(
            omitted
                .audit_with_discovery(|| Ok(copy(&selected)))
                .unwrap_err()
                .to_string()
                .contains("inputs changed")
        );
    }
    std::fs::write(selected.input_roots[0].join("input"), b"changed compiler").unwrap();
    assert!(
        selected
            .audit_with_discovery(|| Ok(copy(&selected)))
            .unwrap_err()
            .to_string()
            .contains("inputs changed")
    );
}

#[test]
fn changed_inputs_are_rejected_before_discovery_can_execute_or_repair_them() {
    let (_temporary, selected) = fixture();
    let compiler = selected.input_roots[0].join("input");
    std::fs::write(&compiler, b"changed compiler").unwrap();
    let called = Cell::new(false);
    let error = selected
        .audit_with_discovery(|| {
            called.set(true);
            std::fs::write(&compiler, b"abc").unwrap();
            Ok(copy(&selected))
        })
        .unwrap_err();
    assert!(error.to_string().contains("inputs changed"));
    assert!(
        !called.get(),
        "discovery must not repair recorded drift before comparison"
    );
    assert_eq!(std::fs::read(compiler).unwrap(), b"changed compiler");
}

#[test]
fn omitted_selector_is_rejected_before_the_discovery_command_runs() {
    let (_temporary, selected) = fixture();
    let selector = selected.input_roots[0].join("input");
    selected.require_recorded_selector(&selector).unwrap();
    let mut omitted = copy(&selected);
    omitted.input_roots.remove(0);
    omitted.inputs = omitted.measure_inputs().unwrap();
    require_same_inputs(&omitted.measure_inputs().unwrap(), &omitted.inputs).unwrap();
    let error =
        enrollment_identity_output(Some(&omitted), &mut std::process::Command::new(&selector))
            .unwrap_err();
    assert!(
        error.to_string().contains("discovery selector is absent"),
        "must reject coverage before trying the non-executable fixture: {error}"
    );
}

#[test]
fn windows_discovery_rejects_omitted_or_changed_vswhere_before_execution() {
    let (_temporary, mut selected) = fixture();
    let program_files = selected.input_roots[0].clone();
    let query = program_files.join("Microsoft Visual Studio/Installer/vswhere.exe");
    std::fs::create_dir_all(query.parent().unwrap()).unwrap();
    std::fs::write(&query, b"non-executable selector fixture\n").unwrap();
    selected.inputs = selected.measure_inputs().unwrap();
    selected.require_recorded_selector(&query).unwrap();
    let mut omitted = copy(&selected);
    omitted.input_roots.remove(0);
    omitted.inputs = omitted.measure_inputs().unwrap();
    require_same_inputs(&omitted.measure_inputs().unwrap(), &omitted.inputs).unwrap();
    for (changed, recorded) in [(false, &omitted), (true, &selected)] {
        if changed {
            std::fs::write(&query, b"changed selector fixture\n").unwrap();
        }
        let mut env = BTreeMap::from([(
            "ProgramFiles(x86)".into(),
            program_files.as_os_str().to_owned(),
        )]);
        let original = env.clone();
        let error = super::enroll_windows_compiler(
            &selected.root,
            &mut env,
            &BTreeMap::new(),
            super::environment::msvc::Architecture::Arm64,
            Some(recorded),
        )
        .err()
        .expect("unrecorded or changed discovery must fail before spawning");
        assert!(
            error
                .to_string()
                .contains("discovery selector is absent from or differs from recorded inputs"),
            "must reject the measured selector before native spawning: {error}"
        );
        assert_eq!(
            env, original,
            "failed discovery must not partially configure compilation"
        );
    }
}

#[test]
fn miri_sysroot_is_independently_selected_forwarded_and_never_repaired_by_audit() {
    let (_temporary, mut selected) = fixture();
    let expected = selected.root.join("target/ci/miri-sysroot");
    let expected_command_path = super::environment::command_path(&selected.root)
        .unwrap()
        .join("target/ci/miri-sysroot");
    let mut env = selected.environment().unwrap();
    env.insert(
        "PATH".into(),
        std::env::join_paths([&selected.input_roots[0]]).unwrap(),
    );
    let prepared = enroll_miri_sysroot(&selected.root, &mut env, None, |env| {
        assert_eq!(
            env.get(OsStr::new("MIRI_SYSROOT")),
            Some(&expected_command_path.clone().into_os_string())
        );
        std::fs::create_dir_all(&expected).unwrap();
        std::fs::write(expected.join("input"), b"abc").unwrap();
        Ok(expected_command_path.to_str().unwrap().as_bytes().to_vec())
    })
    .unwrap();
    assert_eq!(prepared, expected);
    selected.environment = env
        .iter()
        .map(|(key, value)| (native(key), native(value)))
        .collect();
    selected.input_roots.push(prepared.clone());
    selected.inputs = selected.measure_inputs().unwrap();
    assert!(
        selected
            .inputs
            .iter()
            .any(|input| input.path == native(expected.join("input").as_os_str())),
        "explicit sysroot input must survive target output exclusions"
    );
    selected
        .audit_with_discovery(|| Ok(copy(&selected)))
        .unwrap();

    let command = selected
        .cargo_command("reviewed", &["miri".into(), "test".into()], &selected.root)
        .unwrap();
    assert_eq!(
        command
            .get_envs()
            .find(|(key, _)| *key == OsStr::new("MIRI_SYSROOT"))
            .unwrap()
            .1,
        Some(expected_command_path.as_os_str())
    );
    let audited = enroll_miri_sysroot(&selected.root, &mut env, Some(&selected), |_| {
        panic!("audit must never run setup")
    })
    .unwrap();
    assert_eq!(audited, prepared);

    let mut omitted = copy(&selected);
    omitted.input_roots.retain(|path| path != &expected);
    omitted.inputs = omitted.measure_inputs().unwrap();
    assert!(
        enroll_miri_sysroot(&selected.root, &mut env, Some(&omitted), |_| panic!(
            "omitted root must not be repaired"
        ))
        .unwrap_err()
        .to_string()
        .contains("missing from the recorded input closure")
    );

    let (_missing_temporary, missing) = fixture();
    assert!(
        enroll_miri_sysroot(&missing.root, &mut env, Some(&missing), |_| panic!(
            "missing root must not be created"
        ))
        .is_err()
    );
    assert!(!missing.root.join("target").exists());
}
