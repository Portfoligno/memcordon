//! Resolve every image ELF dependency against the same held immutable inventory.
use super::workload_snapshot::HeldSnapshot;
use memcordon_core::workload_files::ImageEntryV1;
use memcordon_core::workload_files::RootRelativePath;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::unix::fs::FileExt;

pub(crate) fn validate_initial_environment(
    launch: &crate::request::LaunchRequestV2,
) -> Result<(), String> {
    if launch.environment.iter().any(|(name, _)| {
        name.starts_with(b"LD_") || matches!(name.as_slice(), b"GLIBC_TUNABLES" | b"GCONV_PATH")
    }) {
        return Err("initial loader environment cannot select writable or external code".into());
    }
    Ok(())
}
pub(crate) fn initial_launch(
    launch: &crate::request::LaunchRequestV2,
    library_path: Option<String>,
) -> Result<crate::request::LaunchRequestV2, String> {
    validate_initial_environment(launch)?;
    let mut trusted = launch.clone();
    if let Some(path) = library_path {
        trusted
            .environment
            .push((b"LD_LIBRARY_PATH".to_vec(), path.into_bytes()));
    }
    Ok(trusted)
}

fn resolved_members<'a>(
    images: &[&'a HeldSnapshot],
    cutoff: std::time::Instant,
) -> Result<BTreeMap<RootRelativePath, (&'a HeldSnapshot, &'a ImageEntryV1)>, String> {
    let mut entries = BTreeMap::new();
    let mut resolved = BTreeMap::new();
    for image in images {
        for entry in image.definition().entries.as_slice() {
            if std::time::Instant::now() >= cutoff {
                return Err("original ELF closure cutoff expired".into());
            }
            if entries
                .insert(entry.path().clone(), (*image, entry))
                .is_some()
            {
                return Err("ELF immutable member is ambiguous".into());
            }
            if matches!(entry, ImageEntryV1::Regular { .. }) {
                resolved.insert(entry.path().clone(), (*image, entry));
            }
        }
    }
    for start in entries.keys() {
        let mut current = start.clone();
        let mut chain = Vec::new();
        let mut seen = BTreeSet::new();
        while !resolved.contains_key(&current) {
            if std::time::Instant::now() >= cutoff {
                return Err("original ELF closure cutoff expired".into());
            }
            if !seen.insert(current.clone()) {
                return Err("ELF immutable link cycle".into());
            }
            chain.push(current.clone());
            match entries.get(&current).map(|(_, entry)| *entry) {
                Some(ImageEntryV1::Symlink { target, .. }) => current = target.clone(),
                _ => return Err("ELF immutable link target absent".into()),
            }
        }
        let target = resolved
            .get(&current)
            .copied()
            .ok_or("ELF resolved target absent")?;
        for member in chain {
            resolved.insert(member, target);
        }
    }
    Ok(resolved)
}

pub(super) fn validate(
    runtime: &HeldSnapshot,
    input: &HeldSnapshot,
    layout: &memcordon_core::workload_request::PrivateRootLayoutV1,
    cutoff: std::time::Instant,
) -> Result<Option<String>, String> {
    memcordon_core::workload_bundle::validate_layout(
        runtime.definition(),
        input.definition(),
        layout,
    )?;
    runtime.revalidate()?;
    input.revalidate()?;
    if runtime.definition().target != input.definition().target {
        return Err("ELF image native targets differ".into());
    }
    let images = [runtime, input];
    let members = resolved_members(&images, cutoff)?;
    let mut directories = Vec::new();
    for image in images {
        for directory in image.definition().library_directories.as_slice() {
            if !directories.contains(directory) {
                directories.push(directory.clone());
            }
        }
    }
    for image in images {
        for entry in image.definition().entries.as_slice() {
            if std::time::Instant::now() >= cutoff {
                return Err("original ELF closure cutoff expired".into());
            }
            let name = entry.path().as_str();
            if matches!(
                name,
                "etc/ld.so.preload" | "etc/ld.so.cache" | "etc/ld.so.conf"
            ) || name == "etc/ld.so.conf.d"
                || name.starts_with("etc/ld.so.conf.d/")
            {
                return Err(
                    "ELF loader configuration is outside the declared immutable library catalogue"
                        .into(),
                );
            }
            let ImageEntryV1::Regular { path, size, .. } = entry else {
                continue;
            };
            let held = File::from(
                image
                    .object(path)?
                    .try_clone_to_owned()
                    .map_err(|error| error.to_string())?,
            );
            let dependency = memcordon_core::elf_closure::inspect(
                |offset, buffer| {
                    super::workload_snapshot::check_validation_cutoff(cutoff)?;
                    held.read_exact_at(buffer, offset)
                        .map_err(|error| error.to_string())
                },
                *size,
                &image.definition().target,
            )?;
            let Some(dependency) = dependency else {
                continue;
            };
            if let Some(interpreter) = dependency.interpreter {
                let interpreter = RootRelativePath::new(
                    interpreter
                        .strip_prefix('/')
                        .ok_or("ELF interpreter not absolute")?
                        .to_owned(),
                )?;
                let (image, entry) = members
                    .get(&interpreter)
                    .copied()
                    .ok_or("ELF interpreter absent from immutable inventory")?;
                if !matches!(
                    entry,
                    ImageEntryV1::Regular {
                        executable: true,
                        ..
                    }
                ) {
                    return Err("ELF interpreter is not a declared executable image member".into());
                }
                image.object(entry.path())?;
            }
            for search in dependency.search_paths {
                let parent = path.as_str().rsplit_once('/').map_or("", |pair| pair.0);
                let expanded = search
                    .replace("${ORIGIN}", &format!("/{parent}"))
                    .replace("$ORIGIN", &format!("/{parent}"));
                if expanded.contains('$') || !expanded.starts_with('/') {
                    return Err(
                        "ELF loader search contains unsupported or relative authority".into(),
                    );
                }
                let mut components = Vec::new();
                for component in expanded.split('/') {
                    match component {
                        "" | "." => (),
                        ".." => {
                            if components.pop().is_none() {
                                return Err("ELF loader search escapes target root".into());
                            }
                        }
                        value => components.push(value),
                    }
                }
                let directory = RootRelativePath::new(components.join("/"))?;
                if !directories.contains(&directory) {
                    return Err("ELF loader search directory is outside the declared immutable search catalogue".into());
                }
            }
            for name in dependency.needed {
                if name.contains('/') || name.contains('$') {
                    return Err(
                        "ELF needed dependency must be an immutable library basename".into(),
                    );
                }
                let candidates = directories
                    .iter()
                    .filter_map(|directory| {
                        RootRelativePath::new(format!("{}/{name}", directory.as_str())).ok()
                    })
                    .filter(|path| members.contains_key(path))
                    .collect::<Vec<_>>();
                if candidates.is_empty() {
                    return Err(format!(
                        "ELF library dependency absent from immutable search catalogue: {name}"
                    ));
                }
                // Ordered provider-derived LD_LIBRARY_PATH is the actual search
                // authority; aliases remain confined to held image members.
                let (image, selected) = members
                    .get(&candidates[0])
                    .copied()
                    .ok_or("ELF dependency absent from immutable inventory")?;
                image.object(selected.path())?;
            }
        }
    }
    runtime.revalidate()?;
    input.revalidate()?;
    Ok((!directories.is_empty()).then(|| {
        directories
            .iter()
            .map(|path| format!("/{}", path.as_str()))
            .collect::<Vec<_>>()
            .join(":")
    }))
}
