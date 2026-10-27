//! Original native owners for the closed compiler cwd and selected bundled linker.
use memcordon_platform::test_support::windows_held_file_metadata;
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{self, Read},
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
};

pub struct Qualified {
    directories: BTreeMap<PathBuf, File>,
    linker: File,
    linker_sha256: String,
}

fn identity(file: &File, directory: bool) -> io::Result<(u32, u64)> {
    let value = windows_held_file_metadata(file)?;
    if value.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (value.attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || (!directory && value.links != 1)
    {
        return Err(io::Error::other(
            "qualified compiler input type/link/reparse identity differs",
        ));
    }
    Ok((value.volume_serial, value.file_index))
}
fn open(path: &Path, directory: bool) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .share_mode(if directory {
            FILE_SHARE_READ | FILE_SHARE_WRITE
        } else {
            FILE_SHARE_READ
        })
        .custom_flags(
            FILE_FLAG_OPEN_REPARSE_POINT
                | if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    0
                },
        )
        .open(path)
}
fn live(input: &super::super::descriptor::Toolchain) -> io::Result<()> {
    super::super::toolchain_debug::validate_clock(
        input.native_work_cutoff_ticks,
        input.native_work_frequency,
    )
}
impl Qualified {
    pub fn new(input: &super::super::descriptor::Toolchain, command: &Command) -> io::Result<Self> {
        input.validate_selected_images().map_err(io::Error::other)?;
        if command.get_current_dir() != Some(input.input_root.as_path())
            || command.get_program() != input.rustc.as_os_str()
        {
            return Err(io::Error::other(
                "compiler command cwd/program differs from qualified input layout",
            ));
        }
        let mut directories = BTreeMap::new();
        for path in std::iter::once(input.input_root.as_path())
            .chain(
                input
                    .native_library_directories
                    .iter()
                    .map(PathBuf::as_path),
            )
            .chain(input.native_linker.parent())
        {
            for ancestor in path
                .ancestors()
                .filter(|path| !path.as_os_str().is_empty())
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
            {
                live(input)?;
                if directories.contains_key(ancestor) {
                    continue;
                }
                if directories.len() >= 64 {
                    return Err(io::Error::other(
                        "compiler input ancestor owner bound exceeded",
                    ));
                }
                let file = open(ancestor, true)?;
                identity(&file, true)?;
                directories.insert(ancestor.to_owned(), file);
                live(input)?;
            }
        }
        let linker = open(&input.native_linker, false)?;
        identity(&linker, false)?;
        let metadata = windows_held_file_metadata(&linker)?;
        if metadata.length > 512 * 1024 * 1024 {
            return Err(io::Error::other(
                "selected bundled linker exceeds original code bound",
            ));
        }
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        let mut reader = &linker;
        let mut buffer = [0u8; 64 * 1024];
        let mut length = 0u64;
        loop {
            live(input)?;
            let count = reader.read(&mut buffer)?;
            live(input)?;
            if count == 0 {
                break;
            }
            length = length
                .checked_add(count as u64)
                .ok_or_else(|| io::Error::other("selected linker byte count overflow"))?;
            if length > metadata.length {
                return Err(io::Error::other(
                    "selected linker grew during qualification",
                ));
            }
            digest.update(&buffer[..count]);
        }
        let linker_sha256 = String::from(memcordon_core::DiagnosticSha256::from_bytes(
            digest.finalize().into(),
        ));
        if length != metadata.length
            || !input.admits_created_image(&input.native_linker, &linker_sha256)
        {
            return Err(io::Error::other(
                "original held bundled linker differs from frozen selected image",
            ));
        }
        let qualified = Self {
            directories,
            linker,
            linker_sha256,
        };
        qualified.verify(input, command)?;
        Ok(qualified)
    }
    pub fn verify(
        &self,
        input: &super::super::descriptor::Toolchain,
        command: &Command,
    ) -> io::Result<()> {
        live(input)?;
        if command.get_current_dir() != Some(input.input_root.as_path()) {
            return Err(io::Error::other("compiler cwd changed after qualification"));
        }
        for (path, file) in &self.directories {
            live(input)?;
            if identity(file, true)? != identity(&open(path, true)?, true)? {
                return Err(io::Error::other(
                    "compiler named input ancestry differs from original owners",
                ));
            }
            live(input)?;
        }
        let named = open(&input.native_linker, false)?;
        if identity(&self.linker, false)? != identity(&named, false)?
            || windows_held_file_metadata(&self.linker)?.length
                != windows_held_file_metadata(&named)?.length
        {
            return Err(io::Error::other(
                "selected linker named identity differs from original owner",
            ));
        }
        live(input)
    }
    pub fn receipt(
        &self,
        input: &super::super::descriptor::Toolchain,
    ) -> io::Result<serde_json::Value> {
        let cwd = self
            .directories
            .get(&input.input_root)
            .ok_or_else(|| io::Error::other("original compiler cwd owner absent"))?;
        Ok(
            serde_json::json!({"cwd_utf16":input.input_root.as_os_str().encode_wide().collect::<Vec<_>>(),
            "selected_linker_utf16":input.native_linker.as_os_str().encode_wide().collect::<Vec<_>>(),
            "cwd_native_identity":identity(cwd,true)?,"selected_linker_native_identity":identity(&self.linker,false)?,
            "selected_linker_sha256":self.linker_sha256,"linker_mode":input.linker_mode,
            "retained_ancestor_count":self.directories.len(),"binding":"original held directory passed as Command.current_dir; original selected linker held through debug settlement"}),
        )
    }
}
