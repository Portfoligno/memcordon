//! Resolve every image ELF dependency against the same held immutable inventory.
use super::runtime_image::InstalledRuntimeImage;
use memcordon_core::workload_contract_v3::RootRelativePath;
use memcordon_core::workload_registry_v3::ImageEntryV1;
use std::collections::BTreeSet;
use std::fs::File;
use std::os::unix::fs::FileExt;

fn regular<'a>(
    images: &[&'a InstalledRuntimeImage],
    path: &RootRelativePath,
) -> Result<(&'a InstalledRuntimeImage, RootRelativePath), String> {
    let mut selected = path.clone();
    let mut seen = BTreeSet::new();
    loop {
        if !seen.insert(selected.clone()) || seen.len() > 64 {
            return Err("ELF immutable dependency link cycle/excessive depth".into());
        }
        let matches = images
            .iter()
            .flat_map(|image| {
                image
                    .definition()
                    .entries
                    .as_slice()
                    .iter()
                    .filter(|entry| entry.path() == &selected)
                    .map(move |entry| (*image, entry))
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(format!(
                "ELF dependency is absent/ambiguous in held images: {}",
                selected.as_str()
            ));
        }
        match matches[0] {
            (image, ImageEntryV1::Regular { .. }) => return Ok((image, selected)),
            (_, ImageEntryV1::Symlink { target, .. }) => selected = target.clone(),
        }
    }
}

pub(super) fn validate(
    runtime: &InstalledRuntimeImage,
    input: &InstalledRuntimeImage,
) -> Result<Option<String>, String> {
    runtime.revalidate()?;
    input.revalidate()?;
    if runtime.definition().target != input.definition().target {
        return Err("ELF image native targets differ".into());
    }
    let images = [runtime, input];
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
            let name = entry.path().as_str();
            if matches!(
                name,
                "etc/ld.so.preload" | "etc/ld.so.cache" | "etc/ld.so.conf"
            ) || name == "etc/ld.so.conf.d"
                || name.starts_with("etc/ld.so.conf.d/")
            {
                return Err(
                    "ELF loader configuration is outside the approved immutable library catalogue"
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
                let (image, path) = regular(&images, &interpreter)?;
                let entry = image
                    .definition()
                    .entries
                    .as_slice()
                    .iter()
                    .find(|entry| entry.path() == &path)
                    .expect("resolved regular dependency");
                if !matches!(
                    entry,
                    ImageEntryV1::Regular {
                        executable: true,
                        ..
                    }
                ) {
                    return Err("ELF interpreter is not approved executable image member".into());
                }
                image.object(&path)?;
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
                    return Err("ELF loader search directory is outside approved immutable search catalogue".into());
                }
            }
            for name in dependency.needed {
                let candidates = directories
                    .iter()
                    .filter_map(|directory| {
                        RootRelativePath::new(format!("{}/{name}", directory.as_str())).ok()
                    })
                    .filter(|path| {
                        images.iter().any(|image| {
                            image
                                .definition()
                                .entries
                                .as_slice()
                                .iter()
                                .any(|entry| entry.path() == path)
                        })
                    })
                    .collect::<Vec<_>>();
                if candidates.is_empty() {
                    return Err(format!(
                        "ELF library dependency absent from immutable search catalogue: {name}"
                    ));
                }
                // Ordered provider-derived LD_LIBRARY_PATH is the actual search
                // authority; aliases remain confined to held image members.
                let (image, selected) = regular(&images, &candidates[0])?;
                image.object(&selected)?;
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
