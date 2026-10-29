//! Caller-side packaging. The provider never receives these host source paths.
use memcordon_core::workload_bundle::{
    MANIFEST_BYTES, SnapshotManifestV1, stream_member, write_bundle_headers,
};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSource {
    pub manifest: PathBuf,
    pub root: PathBuf,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSpec {
    pub runtime: PackSource,
    pub input: PackSource,
}

fn read_document(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|error| error.to_string())?;
    if !file
        .metadata()
        .map_err(|error| error.to_string())?
        .is_file()
    {
        return Err("pack document must be a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > limit {
        return Err("pack document exceeds byte bound".into());
    }
    Ok(bytes)
}

pub fn pack(spec_path: &Path, output_path: &Path) -> Result<(), String> {
    let bytes = read_document(spec_path, memcordon_core::workload_limits::REQUEST_BYTES)?;
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)?;
    let spec: PackSpec = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let runtime =
        SnapshotManifestV1::parse(&read_document(&spec.runtime.manifest, MANIFEST_BYTES)?)?;
    let input = SnapshotManifestV1::parse(&read_document(&spec.input.manifest, MANIFEST_BYTES)?)?;
    let parent = output_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut output = tempfile::NamedTempFile::new_in(parent).map_err(|error| error.to_string())?;
    write_bundle_headers(output.as_file_mut(), &runtime, &input)?;
    for (source, manifest) in [(&spec.runtime, &runtime), (&spec.input, &input)] {
        for member in manifest.regular_members() {
            let path = source.root.join(member.path().as_str());
            let mut options = std::fs::OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NONBLOCK);
            }
            let mut file = options.open(path).map_err(|error| error.to_string())?;
            let metadata = file.metadata().map_err(|error| error.to_string())?;
            let memcordon_core::workload_bundle::ImageEntryV1::Regular { size, .. } = member else {
                unreachable!("regular member inventory contains only regular members");
            };
            if !metadata.is_file() || metadata.len() != *size {
                return Err("source member type or declared size differs".into());
            }
            stream_member(&mut file, output.as_file_mut(), member)?;
            let mut extra = [0; 1];
            if file.read(&mut extra).map_err(|error| error.to_string())? != 0 {
                return Err("source member grew during packaging".into());
            }
        }
    }
    output
        .as_file_mut()
        .flush()
        .map_err(|error| error.to_string())?;
    output
        .as_file()
        .sync_all()
        .map_err(|error| error.to_string())?;
    output
        .persist_noclobber(output_path)
        .map_err(|error| error.to_string())?;
    Ok(())
}

pub fn run(arguments: &[std::ffi::OsString]) -> Result<(), String> {
    match arguments {
        [spec, path, output, destination] if spec == "--spec" && output == "--output" => {
            pack(Path::new(path), Path::new(destination))
        }
        _ => Err("usage: memcordon workload pack --spec PATH --output PATH".into()),
    }
}
