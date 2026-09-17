use std::fs;
use std::path::{Path, PathBuf};

use memcordon_ci::native_profile::QualificationStage;
use memcordon_ci::native_profile::{self, Architecture, Selection};
use serde_json::{Value, json};

const CONTRACT: &str = "windows-staged-native-qualification-v1";

struct Fixture {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    selection: Selection,
    policy: PathBuf,
    selected: PathBuf,
    destination: PathBuf,
}

fn write(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn read(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

impl Fixture {
    fn new(architecture: Architecture) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let selection = Selection {
            architecture,
            installation: root.join("installed-vs"),
            toolset_version: "14.44.35207".into(),
            sdk: root.join("sdk"),
            sdk_version: "10.0.26100.0".into(),
            git: root.join("git"),
            llvm: root.join("llvm"),
            rustup_bin: root.join("rustup"),
            system_root: root.join("windows"),
            additional_support: vec![],
        };
        let (host, target) = match architecture {
            Architecture::X64 => ("Hostx64", "x64"),
            Architecture::Arm64 => ("Hostarm64", "arm64"),
        };
        let toolset = selection
            .installation
            .join("VC")
            .join("Tools")
            .join("MSVC")
            .join(&selection.toolset_version);
        for name in ["cl.exe", "link.exe", "lib.exe", "mspdbsrv.exe", "c1.dll"] {
            write(
                &toolset.join("bin").join(host).join(target).join(name),
                name.as_bytes(),
            );
        }
        write(&toolset.join("include").join("example.h"), b"header");
        write(
            &toolset.join("lib").join(target).join("libcmt.lib"),
            b"static runtime",
        );
        // Complete toolset means even unselected architecture support is kept.
        write(
            &toolset.join("bin").join("other-host").join("helper.dll"),
            b"other",
        );
        write(
            &selection
                .installation
                .join("VC")
                .join("Auxiliary")
                .join("Build")
                .join("Microsoft.VCToolsVersion.default.txt"),
            selection.toolset_version.as_bytes(),
        );
        write(
            &selection
                .installation
                .join("VC")
                .join("Redist")
                .join("runtime.dll"),
            b"runtime",
        );
        write(
            &selection.installation.join("IDE").join("not-selected.txt"),
            b"unrelated workload",
        );
        for part in ["ucrt", "um", "shared"] {
            write(
                &selection
                    .sdk
                    .join("Include")
                    .join(&selection.sdk_version)
                    .join(part)
                    .join("sdk.h"),
                b"sdk header",
            );
        }
        for (part, name) in [("um", "kernel32.lib"), ("ucrt", "ucrt.lib")] {
            write(
                &selection
                    .sdk
                    .join("Lib")
                    .join(&selection.sdk_version)
                    .join(part)
                    .join(target)
                    .join(name),
                b"sdk lib",
            );
        }
        for name in ["rc.exe", "mt.exe"] {
            write(
                &selection
                    .sdk
                    .join("bin")
                    .join(&selection.sdk_version)
                    .join(target)
                    .join(name),
                name.as_bytes(),
            );
        }
        write(
            &selection
                .sdk
                .join("unversioned-resource")
                .join("resource.bin"),
            b"resource",
        );
        write(
            &selection
                .sdk
                .join("Lib")
                .join("another-version")
                .join("support.lib"),
            b"retained",
        );
        write(&selection.git.join("cmd").join("git.exe"), b"git");
        write(
            &selection
                .git
                .join("mingw64")
                .join("libexec")
                .join("git-core")
                .join("helper"),
            b"helper",
        );
        write(&selection.llvm.join("bin").join("clang.exe"), b"clang");
        write(
            &selection.llvm.join("lib").join("clang").join("resource.h"),
            b"clang resource",
        );
        write(&selection.rustup_bin.join("rustup.exe"), b"rustup");
        for name in [
            "kernel32.dll",
            "ntdll.dll",
            "ucrtbase.dll",
            "msvcp_win.dll",
            "cmd.exe",
            "ping.exe",
        ] {
            write(
                &selection.system_root.join("System32").join(name),
                name.as_bytes(),
            );
        }
        let policy = root.join("policy.json");
        let checked_in = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../ci/native-profiles/windows-staged-v1.json");
        fs::copy(checked_in, &policy).unwrap();
        let selected = root.join("selection.json");
        write(&selected, &serde_json::to_vec(&selection).unwrap());
        let destination = root.join("qualification");
        fs::create_dir(&destination).unwrap();
        Self {
            _temporary: temporary,
            root,
            selection,
            policy,
            selected,
            destination,
        }
    }

    fn qualify(&self) -> memcordon_ci::Result<()> {
        native_profile::qualify(&self.policy, &self.selected, &self.destination)
    }

    fn scope(&self) -> PathBuf {
        self.destination
            .join(CONTRACT)
            .join(match self.selection.architecture {
                Architecture::X64 => "x64",
                Architecture::Arm64 => "arm64",
            })
    }

    fn specification(&self) -> PathBuf {
        self.scope().join("control").join("specification.json")
    }
    fn evidence(&self) -> PathBuf {
        self.scope().join("control").join("evidence.json")
    }
    fn active(&self) -> PathBuf {
        memcordon_ci::build_context::environment::command_path(
            &self.scope().join("active").join("tree"),
        )
        .unwrap()
    }
}

#[test]
fn qualification_copies_complete_support_and_sdk_on_both_architectures() {
    for architecture in [Architecture::X64, Architecture::Arm64] {
        let fixture = Fixture::new(architecture);
        fixture.qualify().unwrap();
        native_profile::audit(&fixture.specification()).unwrap();
        assert!(
            fixture
                .active()
                .join("sdk/unversioned-resource/resource.bin")
                .is_file()
        );
        assert!(
            fixture
                .active()
                .join("sdk/Lib/another-version/support.lib")
                .is_file()
        );
        assert!(fixture.active().join("vs/VC/Redist/runtime.dll").is_file());
        assert!(!fixture.active().join("vs/IDE").exists());
        let specification = read(&fixture.specification());
        let env = specification["native_environment"].as_object().unwrap();
        assert_eq!(
            env["VSINSTALLDIR"],
            fixture.active().join("vs").to_str().unwrap()
        );
        assert_eq!(
            env["WindowsSdkDir"],
            fixture.active().join("sdk").to_str().unwrap()
        );
        assert!(!env.contains_key("ProgramFiles"));
        #[cfg(windows)]
        for variable in ["VSINSTALLDIR", "WindowsSdkDir", "SystemRoot"] {
            assert!(!env[variable].as_str().unwrap().starts_with(r"\\?\"));
        }
        for variable in ["INCLUDE", "LIB"] {
            for path in std::env::split_paths(env[variable].as_str().unwrap()) {
                assert!(path.starts_with(fixture.active()));
            }
        }
        let evidence = read(&fixture.evidence());
        assert_eq!(evidence["outcome"], "copy-verified-closure-unqualified");
        assert!(specification.get("inventories").is_none());
        assert!(specification.get("complete").is_none());
        assert!(
            memcordon_ci::build_context::ValidatedBuildContext::read(&fixture.evidence()).is_err()
        );
    }
}

#[test]
fn persistent_content_changes_in_staged_and_external_inputs_fail_audit() {
    for relative in [
        "sdk/unversioned-resource/resource.bin",
        "llvm/lib/clang/resource.h",
        "vs/VC/Redist/runtime.dll",
        "git/mingw64/libexec/git-core/helper",
    ] {
        let fixture = Fixture::new(Architecture::X64);
        fixture.qualify().unwrap();
        let path = fixture.active().join(relative);
        let original = fs::read(&path).unwrap();
        fs::write(&path, vec![b'!'; original.len()]).unwrap();
        assert!(native_profile::audit(&fixture.specification()).is_err());
    }
    let fixture = Fixture::new(Architecture::X64);
    fixture.qualify().unwrap();
    fs::write(
        fixture.selection.system_root.join("System32/cmd.exe"),
        b"changed",
    )
    .unwrap();
    assert!(native_profile::audit(&fixture.specification()).is_err());
}

#[test]
fn staged_ancestor_additions_and_deletions_fail_audit() {
    let fixture = Fixture::new(Architecture::X64);
    fixture.qualify().unwrap();
    write(&fixture.active().join("vs/new-support/input"), b"new");
    assert!(native_profile::audit(&fixture.specification()).is_err());
    let fixture = Fixture::new(Architecture::Arm64);
    fixture.qualify().unwrap();
    fs::remove_file(
        fixture
            .active()
            .join("sdk/unversioned-resource/resource.bin"),
    )
    .unwrap();
    assert!(native_profile::audit(&fixture.specification()).is_err());
}

#[test]
fn original_unreferenced_installation_drift_is_not_staged_runtime_drift() {
    let fixture = Fixture::new(Architecture::X64);
    fixture.qualify().unwrap();
    fs::write(
        fixture
            .selection
            .sdk
            .join("unversioned-resource/resource.bin"),
        b"new original",
    )
    .unwrap();
    native_profile::audit(&fixture.specification()).unwrap();
}

#[test]
fn occupied_candidate_and_stale_lease_are_never_overwritten() {
    let fixture = Fixture::new(Architecture::X64);
    fixture.qualify().unwrap();
    let spec = fs::read(fixture.specification()).unwrap();
    let evidence = fs::read(fixture.evidence()).unwrap();
    assert!(fixture.qualify().is_err());
    assert_eq!(spec, fs::read(fixture.specification()).unwrap());
    assert_eq!(evidence, fs::read(fixture.evidence()).unwrap());
    let fixture = Fixture::new(Architecture::X64);
    fs::create_dir_all(fixture.scope().join("active")).unwrap();
    write(&fixture.scope().join("active/sentinel"), b"preserve");
    assert!(fixture.qualify().is_err());
    assert_eq!(
        fs::read(fixture.scope().join("active/sentinel")).unwrap(),
        b"preserve"
    );
    assert!(!fixture.evidence().exists());
}

#[test]
fn production_claims_and_partial_recipe_policies_fail_before_publication() {
    for change in [
        json!({"qualification_only": false}),
        json!({"recipes": ["controller"]}),
        json!({"inventories": []}),
    ] {
        let fixture = Fixture::new(Architecture::X64);
        let mut policy = read(&fixture.policy);
        policy
            .as_object_mut()
            .unwrap()
            .extend(change.as_object().unwrap().clone());
        fs::write(&fixture.policy, serde_json::to_vec(&policy).unwrap()).unwrap();
        assert!(fixture.qualify().is_err());
        assert!(!fixture.scope().exists());
    }
}

#[test]
fn malformed_selection_and_missing_helper_cannot_emit_complete_evidence() {
    let fixture = Fixture::new(Architecture::X64);
    let mut selected = read(&fixture.selected);
    selected["toolset_version"] = json!("../../escape");
    fs::write(&fixture.selected, serde_json::to_vec(&selected).unwrap()).unwrap();
    assert!(fixture.qualify().is_err());
    assert!(!fixture.evidence().exists());
    let fixture = Fixture::new(Architecture::X64);
    fs::remove_file(fixture.selection.llvm.join("bin/clang.exe")).unwrap();
    assert!(fixture.qualify().is_err());
    assert!(!fixture.evidence().exists());
    assert!(fixture.qualify().is_err());
}

#[test]
fn evidence_cannot_omit_roots_or_change_frozen_specification() {
    let fixture = Fixture::new(Architecture::X64);
    fixture.qualify().unwrap();
    let original = fs::read(fixture.specification()).unwrap();
    let mut evidence = read(&fixture.evidence());
    evidence["inventories"].as_array_mut().unwrap().pop();
    fs::write(fixture.evidence(), serde_json::to_vec(&evidence).unwrap()).unwrap();
    assert!(native_profile::audit(&fixture.specification()).is_err());
    assert_eq!(fs::read(fixture.specification()).unwrap(), original);
    let fixture = Fixture::new(Architecture::X64);
    fixture.qualify().unwrap();
    let mut spec = read(&fixture.specification());
    spec["complete"] = json!(true);
    fs::write(fixture.specification(), serde_json::to_vec(&spec).unwrap()).unwrap();
    assert!(native_profile::audit(&fixture.specification()).is_err());
}

#[test]
fn incoming_generations_do_not_change_final_runtime_identities() {
    let fixture = Fixture::new(Architecture::X64);
    fixture.qualify().unwrap();
    let before_spec = fs::read(fixture.specification()).unwrap();
    let before = read(&fixture.evidence());
    // Test-owned temporary fixture only; production never adopts or clears a
    // prior candidate. Recreate this fixture at the identical absolute root.
    fs::remove_dir_all(&fixture.destination).unwrap();
    fs::create_dir(&fixture.destination).unwrap();
    fixture.qualify().unwrap();
    let after = read(&fixture.evidence());
    assert_eq!(before_spec, fs::read(fixture.specification()).unwrap());
    assert_eq!(before["inventories"], after["inventories"]);
    assert_eq!(
        before["specification_sha256"],
        after["specification_sha256"]
    );
    assert!(
        !String::from_utf8(before_spec)
            .unwrap()
            .contains("incoming-")
    );
    let other = fixture.root.join("other-qualification");
    fs::create_dir(&other).unwrap();
    native_profile::qualify(&fixture.policy, &fixture.selected, &other).unwrap();
    let other = read(&other.join(CONTRACT).join("x64/control/evidence.json"));
    assert_ne!(before["inventories"], other["inventories"]);
}

#[cfg(unix)]
#[test]
fn escaping_links_and_reserved_names_are_rejected_not_pruned() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new(Architecture::X64);
    symlink(&fixture.root, fixture.selection.sdk.join("escape")).unwrap();
    assert!(fixture.qualify().is_err());
    assert!(!fixture.evidence().exists());
    let fixture = Fixture::new(Architecture::X64);
    // This filesystem may be case-insensitive; reserved names are portable.
    write(
        &fixture.selection.sdk.join("NUL.txt"),
        b"invalid native name",
    );
    assert!(fixture.qualify().is_err());
    assert!(!fixture.evidence().exists());
}

#[test]
fn phase_cancellation_never_publishes_complete_evidence() {
    for phase in [
        QualificationStage::SourceCaptured,
        QualificationStage::Copied,
        QualificationStage::Published,
        QualificationStage::SourceVerified,
        QualificationStage::DestinationMeasured,
        QualificationStage::SourceRechecked,
    ] {
        let fixture = Fixture::new(Architecture::X64);
        let result = native_profile::qualify_with_observer(
            &fixture.policy,
            &fixture.selected,
            &fixture.destination,
            |observed| {
                if observed == phase {
                    Err(memcordon_ci::CiError::Message(
                        "qualification cancelled".into(),
                    ))
                } else {
                    Ok(())
                }
            },
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("qualification cancelled")
        );
        assert!(!fixture.evidence().exists());
        assert!(native_profile::audit(&fixture.specification()).is_err());
        assert!(
            fixture.qualify().is_err(),
            "cancelled generation was adopted"
        );
    }
}

#[test]
fn acquisition_boundary_mutation_is_rejected_before_evidence() {
    for phase in [
        QualificationStage::SourceCaptured,
        QualificationStage::DestinationMeasured,
    ] {
        let fixture = Fixture::new(Architecture::X64);
        let result = native_profile::qualify_with_observer(
            &fixture.policy,
            &fixture.selected,
            &fixture.destination,
            |observed| {
                if observed == phase {
                    fs::write(
                        fixture
                            .selection
                            .sdk
                            .join("unversioned-resource/resource.bin"),
                        b"changed",
                    )?;
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!fixture.evidence().exists());
    }
    let fixture = Fixture::new(Architecture::X64);
    let result = native_profile::qualify_with_observer(
        &fixture.policy,
        &fixture.selected,
        &fixture.destination,
        |phase| {
            if phase == QualificationStage::SourceRechecked {
                fs::write(
                    fixture
                        .active()
                        .join("sdk/unversioned-resource/resource.bin"),
                    b"changed",
                )?;
            }
            Ok(())
        },
    );
    assert!(result.is_err());
    assert!(!fixture.evidence().exists());
}

#[test]
fn optional_support_appearance_and_external_metadata_overlap_are_rejected() {
    let fixture = Fixture::new(Architecture::X64);
    fs::remove_dir_all(fixture.selection.installation.join("VC/Redist")).unwrap();
    let result = native_profile::qualify_with_observer(
        &fixture.policy,
        &fixture.selected,
        &fixture.destination,
        |phase| {
            if phase == QualificationStage::DestinationMeasured {
                fs::create_dir(fixture.selection.installation.join("VC/Redist"))?;
            }
            Ok(())
        },
    );
    assert!(result.is_err());
    assert!(!fixture.evidence().exists());
    let fixture = Fixture::new(Architecture::X64);
    let mut selection = fixture.selection.clone();
    selection.rustup_bin = fixture.root.clone();
    fs::write(&fixture.selected, serde_json::to_vec(&selection).unwrap()).unwrap();
    assert!(
        fixture
            .qualify()
            .unwrap_err()
            .to_string()
            .contains("overlap")
    );
}
