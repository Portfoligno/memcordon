//! Independent joins for the original compiler and its retained native children.
use crate::*;
use serde_json::Value;

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    process_id: u32,
    creation_time_100ns: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Created {
    format: String,
    revision: u32,
    role: String,
    challenge: Vec<u8>,
    parent: Identity,
    child: Identity,
    program_utf16: Vec<u16>,
    argv_utf16: Vec<Vec<u16>>,
    image_sha256: String,
    held_from_process_creation: bool,
    held_live_before_wait: bool,
    native_parent_edge_observed: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Retired {
    format: String,
    revision: u32,
    role: String,
    challenge: Vec<u8>,
    parent: Identity,
    child: Identity,
    image_sha256: String,
    held_from_process_creation: bool,
    held_live_before_wait: bool,
    native_parent_edge_observed: bool,
    native_wait_completed: bool,
    native_status: Option<i32>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selected {
    path: String,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Library {
    original_path: String,
    artifact: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Descendant {
    format: String,
    revision: u32,
    ordinal: u32,
    root_pid: u32,
    pid: u32,
    birth: u64,
    parent_pid: u32,
    parent_birth: u64,
    image_sha256: String,
    native_parent_edge_observed: bool,
    parent_and_child_held_live: bool,
}

pub(crate) fn validate(
    descriptor: &Value,
    native: &NativeObservation,
    input: &FixtureInput,
    challenge: &[u8],
    peers: &BTreeMap<&str, &str>,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    let tc = &descriptor["toolchain"];
    let fields = [
        "rustc",
        "native_linker",
        "native_library_directories",
        "library_source",
        "test_source",
        "child_source",
        "dll_source",
        "loader_source",
        "target",
    ];
    if tc.as_object().is_none_or(|object| {
        object.len() != fields.len() || object.keys().any(|field| !fields.contains(&field.as_str()))
    }) || tc["target"] != native.target
    {
        return Err("original Windows selected toolchain schema/target differs".into());
    }
    let text = |field: &str| -> VerificationResult<String> {
        let value = tc[field].as_str().ok_or("selected toolchain path absent")?;
        if value.len() < 3
            || value.as_bytes()[1] != b':'
            || !matches!(value.as_bytes()[2], b'\\' | b'/')
            || value.contains('\0')
        {
            return Err("selected toolchain path is not an absolute native path".into());
        }
        Ok(value.into())
    };
    let raw = |role: &str| -> VerificationResult<&[u8]> {
        custody.bytes(
            peers
                .get(role)
                .copied()
                .ok_or("original measured toolchain artifact absent")?,
        )
    };
    let manifest = raw("toolchain-inputs")?;
    if input.toolchain_identity.as_deref() != Some(sha256(manifest).as_str()) {
        return Err("original immutable toolchain manifest digest differs".into());
    }
    let selected: Vec<Selected> = wire::decode(manifest)?;
    if selected.is_empty() || selected.len() > 65536 {
        return Err("original selected toolchain population exceeds bound".into());
    }
    let mut measured = BTreeMap::new();
    for item in selected {
        if item.path.contains('\0')
            || item.sha256.len() != 64
            || hex::decode(&item.sha256).is_err()
            || measured.insert(item.path, item.sha256).is_some()
        {
            return Err("original selected toolchain manifest malformed or duplicated".into());
        }
    }
    for field in [
        "rustc",
        "native_linker",
        "library_source",
        "test_source",
        "child_source",
        "dll_source",
        "loader_source",
    ] {
        let path = text(field)?;
        if measured.get(&path) != Some(&sha256(raw(&format!("selected-{field}"))?)) {
            return Err(
                "selected compiler/linker/source is outside original measured immutable inputs"
                    .into(),
            );
        }
    }
    for (field, file) in [
        ("library_source", "library.rs"),
        ("test_source", "tests.rs"),
        ("child_source", "child.rs"),
        ("dll_source", "dll.rs"),
        ("loader_source", "loader.rs"),
    ] {
        if raw(&format!("selected-{field}"))? != raw(&format!("compiler-source-{file}"))? {
            return Err(
                "actual compiler source differs from original measured copied input".into(),
            );
        }
    }
    let libraries: Vec<String> = serde_json::from_value(tc["native_library_directories"].clone())
        .map_err(|error| error.to_string())?;
    if libraries.len() != 3
        || libraries.iter().any(|path| {
            path.len() < 3
                || path.as_bytes()[1] != b':'
                || !matches!(path.as_bytes()[2], b'\\' | b'/')
                || path.contains('\0')
        })
        || libraries.iter().collect::<BTreeSet<_>>().len() != 3
    {
        return Err("native library directory vector malformed".into());
    }
    let expected_libraries = measured
        .iter()
        .filter(|(path, _)| {
            libraries.iter().any(|directory| {
                path.starts_with(&format!("{}\\", directory.trim_end_matches(['\\', '/'])))
            })
        })
        .map(|(path, digest)| (path.clone(), digest.clone()))
        .collect::<BTreeMap<_, _>>();
    if libraries.iter().any(|directory| {
        !expected_libraries
            .keys()
            .any(|path| path.starts_with(&format!("{}\\", directory.trim_end_matches(['\\', '/']))))
    }) {
        return Err("original immutable native library directory lacks measured members".into());
    }
    let captured: Vec<Library> = wire::decode(raw("selected-native-library-inputs")?)?;
    let mut library_paths = BTreeSet::new();
    let parent = std::path::Path::new(peers["selected-rustc"])
        .parent()
        .ok_or("selected compiler custody parent absent")?;
    for (ordinal, library) in captured.iter().enumerate() {
        let expected = parent.join(format!("selected-native-library-{ordinal}.bin"));
        if !library_paths.insert(library.original_path.as_str())
            || std::path::Path::new(&library.artifact) != expected
            || expected_libraries.get(&library.original_path)
                != Some(&sha256(custody.bytes(&library.artifact)?))
        {
            return Err("original measured native library artifact closure differs".into());
        }
    }
    if library_paths != expected_libraries.keys().map(String::as_str).collect() {
        return Err("original measured native SDK library population omitted or added".into());
    }
    let output = descriptor["output_root"]
        .as_str()
        .ok_or("original generated output root absent")?;
    let root = format!("{}\\compiled", output.trim_end_matches(['\\', '/']));
    let utf16 = |value: &str| value.encode_utf16().collect::<Vec<_>>();
    let compiler_sha = sha256(raw("selected-rustc")?);
    let linker_sha = sha256(raw("selected-native_linker")?);
    let mut live_images = BTreeSet::new();
    let mut ordinals = BTreeSet::new();
    for (role, path) in peers
        .iter()
        .filter(|(role, _)| role.starts_with("native-toolchain-descendant-"))
    {
        let descendant: Descendant = wire::decode(custody.bytes(path)?)?;
        let child = native
            .held_processes
            .iter()
            .find(|identity| identity.pid == descendant.pid && identity.birth == descendant.birth)
            .ok_or("actual compiler descendant absent from original held retirement family")?;
        let parent = native
            .held_processes
            .iter()
            .find(|identity| {
                identity.pid == descendant.parent_pid && identity.birth == descendant.parent_birth
            })
            .ok_or("actual compiler ancestor was not retained")?;
        if descendant.format != "memcordon.windows-native-toolchain-descendant"
            || descendant.revision != 1
            || descendant.ordinal >= 4096
            || *role != format!("native-toolchain-descendant-{}", descendant.ordinal)
            || !ordinals.insert(descendant.ordinal)
            || Some(descendant.root_pid) != native.root_pid
            || !child.retirement_observed
            || !parent.retirement_observed
            || child.parent_pid != Some(parent.pid)
            || child.parent_birth != Some(parent.birth)
            || parent.birth > child.birth
            || !descendant.native_parent_edge_observed
            || !descendant.parent_and_child_held_live
            || descendant.image_sha256.len() != 64
            || hex::decode(&descendant.image_sha256).is_err()
        {
            return Err("actual held compiler/linker descendant image/ancestry differs".into());
        }
        live_images.insert(descendant.image_sha256);
    }
    if !live_images.contains(&compiler_sha) || !live_images.contains(&linker_sha) {
        return Err("actual independently held compiler and linker kernel images absent".into());
    }
    let mut children = BTreeSet::new();
    for (role, source, flags) in [
        ("readiness.rlib", "library.rs", vec!["--crate-type=rlib"]),
        ("child.exe", "child.rs", vec![]),
        ("tests.exe", "tests.rs", vec!["--test"]),
        ("readiness.dll", "dll.rs", vec!["--crate-type=cdylib"]),
        ("loader.exe", "loader.rs", vec![]),
        ("run-tests", "", vec![]),
        ("run-child", "", vec![]),
        ("run-loader", "", vec![]),
    ] {
        let created: Created = wire::decode(raw(&format!("native-child-{role}-created"))?)?;
        let retired: Retired = wire::decode(raw(&format!("native-child-{role}-retired"))?)?;
        if created.format != "memcordon.windows-fixture-owned-child-created"
            || retired.format != "memcordon.windows-fixture-owned-child-retired"
            || created.revision != 1
            || retired.revision != 1
            || created.role != role
            || retired.role != role
            || created.challenge != challenge
            || retired.challenge != challenge
            || created.parent != retired.parent
            || created.child != retired.child
            || Some(created.parent.process_id) != native.root_pid
            || Some(created.parent.creation_time_100ns) != native.root_birth
            || created.child.process_id == 0
            || created.child.process_id == created.parent.process_id
            || created.child.creation_time_100ns < created.parent.creation_time_100ns
            || !children.insert((created.child.process_id, created.child.creation_time_100ns))
            || !created.held_from_process_creation
            || !retired.held_from_process_creation
            || !created.native_parent_edge_observed
            || !retired.native_parent_edge_observed
            || created.held_live_before_wait != retired.held_live_before_wait
            || !retired.native_wait_completed
            || retired.native_status != Some(0)
            || created.image_sha256 != retired.image_sha256
        {
            return Err(
                "original retained toolchain child identity/wait/owner closure differs".into(),
            );
        }
        let (program, args, image) = if !source.is_empty() {
            let mut args = vec![format!("{root}\\{source}")];
            args.extend(flags.into_iter().map(String::from));
            args.extend([
                "--edition=2021".into(),
                "--target".into(),
                native.target.clone(),
                "-C".into(),
                format!("linker={}", text("native_linker")?),
                "-o".into(),
                format!("{root}\\{role}"),
            ]);
            for directory in &libraries {
                args.extend(["-L".into(), format!("native={directory}")]);
            }
            (text("rustc")?, args, compiler_sha.clone())
        } else {
            let artifact = match role {
                "run-tests" => "tests.exe",
                "run-child" => "child.exe",
                _ => "loader.exe",
            };
            let args = match role {
                "run-tests" => vec!["--test-threads=1".into()],
                "run-child" => vec![
                    format!("{root}\\challenge-input.bin"),
                    format!("{root}\\child-output.bin"),
                ],
                _ => vec![format!("{root}\\readiness.dll"), root.clone()],
            };
            (
                format!("{root}\\{artifact}"),
                args,
                sha256(raw(&format!("generated-{artifact}"))?),
            )
        };
        if created.program_utf16 != utf16(&program)
            || created.argv_utf16 != args.iter().map(|arg| utf16(arg)).collect::<Vec<_>>()
            || created.image_sha256 != image
        {
            return Err("native toolchain child program/arguments/kernel image differs from measured compiler or generated image".into());
        }
    }
    Ok(())
}
