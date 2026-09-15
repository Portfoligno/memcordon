use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use memcordon_ci::build_context::{BuildInputSnapshot, ValidatedBuildContext};
use serde_json::Value;

const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

fn native(path: &OsStr) -> String {
    hex::encode(path.as_encoded_bytes())
}

fn mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

struct Fixture {
    temporary: tempfile::TempDir,
    root: PathBuf,
    wire: Value,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let parent = temporary.path().canonicalize().unwrap();
        let root = parent.join("checkout");
        let home = parent.join("cargo-home");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&home).unwrap();
        mode(&root, 0o755);
        for name in ["cargo", "source"] {
            std::fs::write(root.join(name), b"abc").unwrap();
            mode(&root.join(name), 0o644);
        }
        let substitutions = BTreeMap::from([
            ("$root", root.to_str().unwrap().to_owned()),
            ("$cargo", root.join("cargo").to_str().unwrap().to_owned()),
            ("$root_hex", native(root.as_os_str())),
            ("$cargo_hex", native(root.join("cargo").as_os_str())),
            ("$source_hex", native(root.join("source").as_os_str())),
            ("$cargo_home_hex", native(home.as_os_str())),
        ]);
        let mut wire: Value =
            serde_json::from_str(include_str!("../../../spec/vectors/build-context-v3.json"))
                .unwrap();
        fn expand(value: &mut Value, substitutions: &BTreeMap<&str, String>) {
            match value {
                Value::String(text) => {
                    if let Some(replacement) = substitutions.get(text.as_str()) {
                        *text = replacement.clone();
                    }
                }
                Value::Array(values) => {
                    for value in values {
                        expand(value, substitutions);
                    }
                }
                Value::Object(values) => {
                    for value in values.values_mut() {
                        expand(value, substitutions);
                    }
                }
                _ => {}
            }
        }
        expand(&mut wire, &substitutions);
        // V3 records native Unix modes; Windows records the readonly bit.
        if cfg!(windows) {
            for input in wire["inputs"].as_array_mut().unwrap() {
                input["mode"] = 0.into();
            }
        }
        Self {
            temporary,
            root,
            wire,
        }
    }

    fn read(&self, wire: &Value) -> memcordon_ci::Result<ValidatedBuildContext> {
        let path = self.temporary.path().join("context.json");
        std::fs::write(&path, serde_json::to_vec(wire).unwrap()).unwrap();
        ValidatedBuildContext::read(&path)
    }

    fn assert_native_records_required(&self, root: &Path, records: &[Value]) {
        let mut wire = self.wire.clone();
        wire["discovery_roots"] = serde_json::json!([root]);
        let inputs = wire["inputs"].as_array_mut().unwrap();
        inputs.extend_from_slice(records);
        inputs.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
        self.read(&wire).unwrap().audit().unwrap();
        for record in records {
            let mut omitted = wire.clone();
            omitted["inputs"]
                .as_array_mut()
                .unwrap()
                .retain(|input| input["path"] != record["path"]);
            assert!(
                self.read(&omitted).unwrap().audit().is_err(),
                "omitted native record {record}"
            );
        }
    }
}

#[test]
fn reviewed_v3_records_match_real_capture_and_roundtrip() {
    let fixture = Fixture::new();
    let capture = BuildInputSnapshot::capture(&fixture.root).unwrap();
    let records: Value = serde_json::from_slice(&capture.serialized_inputs().unwrap()).unwrap();
    assert_eq!(records, fixture.wire["inputs"]);
    let context = fixture.read(&fixture.wire).unwrap();
    context.audit().unwrap();
    let written = fixture.temporary.path().join("written.json");
    context.write(&written).unwrap();
    let bytes = std::fs::read(written).unwrap();
    assert!(bytes.ends_with(b"\n"));
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap(),
        fixture.wire
    );
}

#[test]
fn every_omitted_v3_input_is_rejected_by_actual_audit() {
    let fixture = Fixture::new();
    fixture.read(&fixture.wire).unwrap().audit().unwrap();
    for index in 0..fixture.wire["inputs"].as_array().unwrap().len() {
        let mut omitted = fixture.wire.clone();
        let missing = omitted["inputs"].as_array_mut().unwrap().remove(index);
        assert!(
            fixture.read(&omitted).unwrap().audit().is_err(),
            "omitted {missing}"
        );
    }
}

#[test]
fn v3_required_fields_and_unknown_fields_remain_strict() {
    let fixture = Fixture::new();
    for key in fixture.wire.as_object().unwrap().keys() {
        let mut missing = fixture.wire.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(fixture.read(&missing).is_err(), "missing {key}");
    }
    for pointer in ["", "/inputs/0", "/inputs/1"] {
        let mut extended = fixture.wire.clone();
        extended.pointer_mut(pointer).unwrap()["unreviewed_authority"] = true.into();
        assert!(
            fixture.read(&extended).is_err(),
            "unknown field at {pointer}"
        );
    }
    let mut future = fixture.wire.clone();
    future["schema_version"] = 4.into();
    assert!(fixture.read(&future).is_err());
}

#[test]
fn native_file_batches_preserve_the_same_records_as_serial_capture() {
    let fixture = Fixture::new();
    for name in [
        "batch-a", "batch-b", "batch-c", "batch-d", "batch-e", "batch-f", "batch-g", "batch-h",
    ] {
        std::fs::write(fixture.root.join(name), b"abc").unwrap();
        mode(&fixture.root.join(name), 0o644);
    }
    let serial = BuildInputSnapshot::capture(&fixture.root).unwrap();
    let native = BuildInputSnapshot::capture_native_tree(&fixture.root).unwrap();
    assert_eq!(
        serial.serialized_inputs().unwrap(),
        native.serialized_inputs().unwrap()
    );
    let records: Vec<Value> = serde_json::from_slice(&native.serialized_inputs().unwrap()).unwrap();
    assert_eq!(
        records
            .iter()
            .filter(|record| record["kind"] == "file")
            .count(),
        10
    );
    assert!(
        records
            .iter()
            .filter(|record| record["kind"] == "file")
            .all(|record| record["digest"] == ABC_SHA256)
    );
    native.audit().unwrap();
    let mut wire = fixture.wire.clone();
    wire["inputs"] = serde_json::to_value(&records).unwrap();
    fixture.read(&wire).unwrap().audit().unwrap();
    for index in 0..records.len() {
        let mut omitted = wire.clone();
        let missing = omitted["inputs"].as_array_mut().unwrap().remove(index);
        assert!(
            fixture.read(&omitted).unwrap().audit().is_err(),
            "omitted batch record {missing}"
        );
    }
}

#[cfg(unix)]
#[test]
fn native_symlink_records_bind_raw_and_resolved_targets() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let parent = fixture.root.parent().unwrap();
    let tree = parent.join("native-tree");
    std::fs::create_dir(&tree).unwrap();
    let external = parent.join("external");
    std::fs::write(&external, b"abc").unwrap();
    let link = tree.join("alias");
    symlink("../external", &link).unwrap();
    let dangling = tree.join("dangling");
    symlink("missing", &dangling).unwrap();
    let capture = BuildInputSnapshot::capture_native_tree(&tree).unwrap();
    let records: Vec<Value> =
        serde_json::from_slice(&capture.serialized_inputs().unwrap()).unwrap();
    let record = |path: &Path| {
        records
            .iter()
            .find(|record| record["path"] == native(path.as_os_str()))
            .unwrap()
    };
    assert_eq!(record(&external)["kind"], "file");
    assert_eq!(record(&external)["digest"], ABC_SHA256);
    assert_eq!(record(&link)["kind"], "symlink");
    assert_eq!(
        record(&link)["digest"],
        serde_json::to_string(&[
            native(OsStr::new("../external")),
            native(external.as_os_str())
        ])
        .unwrap()
    );
    assert_eq!(record(&dangling)["kind"], "dangling-symlink");
    assert_eq!(record(&dangling)["digest"], native(OsStr::new("missing")));
    capture.audit().unwrap();
    fixture.assert_native_records_required(&tree, &records);
    std::fs::write(tree.join("missing"), b"abc").unwrap();
    assert!(
        capture.audit().is_err(),
        "appearing target must invalidate the dangling record"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn native_null_device_is_recorded_without_reading_its_contents() {
    use std::os::unix::fs::{MetadataExt, symlink};

    let fixture = Fixture::new();
    let tree = fixture.root.parent().unwrap().join("native-tree");
    std::fs::create_dir(&tree).unwrap();
    let device = Path::new("/dev/null").canonicalize().unwrap();
    let metadata = std::fs::metadata(&device).unwrap();
    symlink(&device, tree.join("null")).unwrap();
    let capture = BuildInputSnapshot::capture_native_tree(&tree).unwrap();
    let records: Vec<Value> =
        serde_json::from_slice(&capture.serialized_inputs().unwrap()).unwrap();
    let record = records
        .iter()
        .find(|record| record["path"] == native(device.as_os_str()))
        .unwrap();
    assert_eq!(record["kind"], "linux-null-device");
    assert_eq!(record["mode"], metadata.mode());
    assert_eq!(
        record["digest"],
        serde_json::to_string(&(metadata.rdev(), metadata.uid(), metadata.gid())).unwrap()
    );
    capture.audit().unwrap();
    fixture.assert_native_records_required(&tree, &records);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct RestoreSearch(PathBuf);

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for RestoreSearch {
    fn drop(&mut self) {
        mode(&self.0, 0o700);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn unreadable_descendant_records_do_not_authorize_unreadable_roots() {
    let fixture = Fixture::new();
    let tree = fixture.root.parent().unwrap().join("native-tree");
    std::fs::create_dir(&tree).unwrap();
    let private = tree.join("private");
    std::fs::create_dir(&private).unwrap();
    std::fs::write(private.join("input"), b"abc").unwrap();
    let restore = RestoreSearch(private.clone());
    mode(&private, 0);
    assert_eq!(
        std::fs::read_dir(&private).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    let capture = BuildInputSnapshot::capture_native_tree(&tree).unwrap();
    let records: Vec<Value> =
        serde_json::from_slice(&capture.serialized_inputs().unwrap()).unwrap();
    let record = records
        .iter()
        .find(|record| record["path"] == native(private.as_os_str()))
        .unwrap();
    let metadata = std::fs::metadata(&private).unwrap();
    let identity = memcordon_native_inspect::unsearchable_directory(&private, &metadata)
        .unwrap()
        .unwrap();
    assert_eq!(record["kind"], "inaccessible-directory");
    assert_eq!(record["mode"], 0o40000);
    assert_eq!(
        record["digest"],
        serde_json::to_string(&(
            identity.owner_uid,
            identity.owner_gid,
            (identity.effective_uid, identity.effective_gid),
            identity.supplementary_groups
        ))
        .unwrap()
    );
    fixture.assert_native_records_required(&tree, &records);
    assert!(
        BuildInputSnapshot::capture_native_tree(&private).is_err(),
        "a required native root cannot use descendant denial evidence"
    );
    drop(restore);
    assert!(
        capture.audit().is_err(),
        "restored search must invalidate denial evidence"
    );
}

#[cfg(windows)]
#[test]
fn windows_case_aliases_capture_one_canonical_native_identity() {
    let fixture = Fixture::new();
    let parent = fixture.root.parent().unwrap();
    let tree = parent.join("NativeCaseTree");
    std::fs::create_dir(&tree).unwrap();
    std::fs::write(tree.join("MixedCaseInput"), b"abc").unwrap();
    let alias = parent.join("nativecasetree");
    assert!(
        alias.is_dir(),
        "Windows case-alias fixture requires a case-insensitive directory"
    );
    let original = BuildInputSnapshot::capture_native_tree(&tree).unwrap();
    let aliased = BuildInputSnapshot::capture_native_tree(&alias).unwrap();
    assert_eq!(
        original.serialized_inputs().unwrap(),
        aliased.serialized_inputs().unwrap()
    );
    let records: Vec<Value> =
        serde_json::from_slice(&original.serialized_inputs().unwrap()).unwrap();
    assert_eq!(
        records
            .iter()
            .filter(|record| record["kind"] == "file")
            .count(),
        1
    );
    fixture.assert_native_records_required(&alias, &records);
}
