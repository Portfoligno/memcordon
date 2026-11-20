//! Fresh file access checks on case-owned evidence only.
use super::descriptor::gate_precondition::{
    COMPILER_AUTHORITY_PROBE_BYTES, CompilerAuthorityFileIdentity,
    CompilerAuthorityOrdinaryControl, CompilerAuthorityProbes, REDUCED_COMPILER_OUTPUT,
    REDUCED_COMPILER_SENTINEL, TokenObservation, sha256,
};
use super::{Descriptor, Transcript, native};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, Write},
    os::windows::fs::OpenOptionsExt,
    path::Path,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA,
};

fn target(descriptor: &Descriptor) -> io::Result<&Path> {
    descriptor
        .reduced_compiler_sentinel()
        .filter(|path| {
            path.is_absolute()
                && path
                    .file_name()
                    .is_some_and(|name| name == REDUCED_COMPILER_SENTINEL)
                && !path.starts_with(&descriptor.output_root)
        })
        .ok_or_else(|| io::Error::other("reduced compiler sentinel declaration differs"))
}

fn at<T>(stage: &'static str, result: io::Result<T>) -> io::Result<T> {
    result.map_err(|error| {
        super::operation_context::with_secondary(
            error,
            format!("reduced-compiler-probe-stage={stage}"),
        )
    })
}

fn observe(reader: &mut File, expected: &[u8]) -> io::Result<CompilerAuthorityFileIdentity> {
    let metadata = memcordon_platform::test_support::windows_held_file_metadata(reader)?;
    if metadata.attributes
        & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_REPARSE_POINT)
        != 0
        || metadata.links != 1
        || metadata.length != expected.len() as u64
    {
        return Err(io::Error::other(
            "reduced compiler probe file custody differs",
        ));
    }
    reader.rewind()?;
    let mut bytes = Vec::new();
    reader
        .take((expected.len() + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes != expected {
        return Err(io::Error::other(
            "reduced compiler probe file content differs",
        ));
    }
    Ok(CompilerAuthorityFileIdentity {
        volume_serial: metadata.volume_serial,
        file_index: metadata.file_index,
    })
}

fn sentinel_read(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

fn sentinel_write(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(FILE_WRITE_DATA)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

pub(super) fn ordinary_control(
    descriptor: &Descriptor,
) -> io::Result<CompilerAuthorityOrdinaryControl> {
    let bytes = native::effective_token_observation()?;
    let token: TokenObservation = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let authority = super::compiler_authority::effective()?;
    authority.validate_source().map_err(io::Error::other)?;
    if token != authority.token {
        return Err(io::Error::other(
            "sentinel positive control requires the ordinary caller",
        ));
    }
    let path = target(descriptor)?;
    let mut reader = at("ordinary-sentinel-read-open", sentinel_read(path))?;
    let original = at("ordinary-empty-sentinel", observe(&mut reader, &[]))?;
    let mut writer = at("ordinary-sentinel-write-open", sentinel_write(path))?;
    at(
        "ordinary-sentinel-write",
        writer.write_all(&descriptor.challenge),
    )?;
    drop(writer);
    let protected = at(
        "ordinary-sentinel-readback",
        observe(&mut reader, &descriptor.challenge),
    )?;
    if protected != original {
        return Err(io::Error::other(
            "ordinary sentinel write targeted a different file",
        ));
    }
    Ok(CompilerAuthorityOrdinaryControl {
        challenge_sha256: sha256(&descriptor.challenge),
        effective_token_sha256: sha256(&bytes),
        protected,
        protected_write_verified: true,
        token,
        authority,
    })
}

fn verify_sentinel(descriptor: &Descriptor) -> io::Result<CompilerAuthorityFileIdentity> {
    let path = target(descriptor)?;
    // The read handle permits FILE_WRITE_DATA sharing, but pins the original
    // identity against deletion or replacement while a fresh write is tested.
    let mut sentinel = at("restricted-sentinel-read-open", sentinel_read(path))?;
    let protected = at(
        "restricted-sentinel-readback",
        observe(&mut sentinel, &descriptor.challenge),
    )?;
    match sentinel_write(path) {
        Err(error) if error.raw_os_error() == Some(5) => {}
        Err(error) => return at("restricted-sentinel-write-open", Err(error)),
        Ok(_) => {
            return Err(io::Error::other(
                "protected sentinel write unexpectedly succeeded",
            ));
        }
    };
    if observe(&mut sentinel, &descriptor.challenge)? != protected {
        return Err(io::Error::other("protected sentinel identity changed"));
    }
    Ok(protected)
}

pub(super) fn run(
    descriptor: &Descriptor,
    transcript: &mut Transcript,
    token_bytes: &[u8],
) -> io::Result<()> {
    let authority = super::compiler_authority::effective()?;
    authority.validate_reduced().map_err(io::Error::other)?;
    if serde_json::from_slice::<TokenObservation>(token_bytes).map_err(io::Error::other)?
        != authority.token
    {
        return Err(io::Error::other(
            "reduced compiler effective token differs from process token",
        ));
    }
    let protected = verify_sentinel(descriptor)?;
    let mut product = at(
        "owned-output-create",
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(descriptor.output_root.join(REDUCED_COMPILER_OUTPUT)),
    )?;
    at(
        "owned-output-write",
        product.write_all(&descriptor.challenge),
    )?;
    at("owned-output-flush", product.sync_all())?;
    at(
        "owned-output-readback",
        observe(&mut product, &descriptor.challenge),
    )?;
    let evidence = CompilerAuthorityProbes {
        challenge_sha256: sha256(&descriptor.challenge),
        effective_token_sha256: sha256(token_bytes),
        protected,
        protected_write_win32: 5,
        output_write_verified: true,
        authority,
    };
    let bytes = serde_json::to_vec(&evidence).map_err(io::Error::other)?;
    if bytes.len() > COMPILER_AUTHORITY_PROBE_BYTES {
        return Err(io::Error::other(
            "reduced compiler probe evidence exceeds bound",
        ));
    }
    transcript.event("reduced-compiler-probes", None, &bytes)
}
