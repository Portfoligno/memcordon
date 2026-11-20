//! Original native owners for the closed compiler cwd and selected bundled linker.
use super::super::descriptor::{Toolchain, ToolchainInputRoot};
use super::super::operation_context::{
    CompilerDirectoryRole as Role, CompilerOperation as Op, compiler_context as context,
};
use memcordon_platform::test_support::{WindowsHeldFileMetadata, windows_held_file_metadata};
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
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
};

pub struct Qualified<'a> {
    root: Option<&'a HeldRoot>,
    directories: BTreeMap<PathBuf, File>,
    linker: File,
    linker_sha256: String,
}

pub(super) struct HeldRoot {
    file: File,
    pub(super) identity: ToolchainInputRoot,
}

impl HeldRoot {
    pub(super) fn acquire(input: &Toolchain, expected: ToolchainInputRoot) -> io::Result<Self> {
        live(input)?;
        context(
            Op::QualifySelection,
            input.validate_selected_images().map_err(io::Error::other),
        )?;
        let file = context(
            Op::DirectoryOpen(Role::InputRoot),
            open_directory(&input.input_root),
        )?;
        let observed = context(
            Op::DirectoryMetadata(Role::InputRoot),
            metadata(&file, true),
        )?;
        let identity = ToolchainInputRoot {
            volume_serial: observed.volume_serial,
            file_index: observed.file_index,
        };
        if identity != expected {
            return context(
                Op::DirectoryNamedIdentity(Role::InputRoot),
                Err(io::Error::other(
                    "held compiler input root differs from controller identity",
                )),
            );
        }
        let held = Self { file, identity };
        held.verify(input)?;
        Ok(held)
    }

    pub(super) fn verify(&self, input: &Toolchain) -> io::Result<()> {
        live(input)?;
        let held = context(
            Op::DirectoryRetainedMetadata(Role::InputRoot),
            metadata(&self.file, true),
        )?;
        let named = context(
            Op::DirectoryNamedOpen(Role::InputRoot),
            open_directory(&input.input_root),
        )?;
        let named = context(
            Op::DirectoryNamedMetadata(Role::InputRoot),
            metadata(&named, true),
        )?;
        let expected = (self.identity.volume_serial, self.identity.file_index);
        if identity(&held) != expected || identity(&named) != expected {
            return context(
                Op::DirectoryNamedIdentity(Role::InputRoot),
                Err(io::Error::other(
                    "named compiler input root differs from original controller and fixture owners",
                )),
            );
        }
        live(input)
    }
}

fn metadata(file: &File, directory: bool) -> io::Result<WindowsHeldFileMetadata> {
    let value = windows_held_file_metadata(file)?;
    if value.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (value.attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || (!directory && value.links != 1)
    {
        return Err(io::Error::other(
            "qualified compiler input type/link/reparse identity differs",
        ));
    }
    Ok(value)
}
fn identity(value: &WindowsHeldFileMetadata) -> (u32, u64) {
    (value.volume_serial, value.file_index)
}

fn open_directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

fn open_linker(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

fn directory_role(input: &Toolchain, path: &Path) -> Role {
    if path == input.input_root {
        Role::InputRoot
    } else if input
        .native_library_directories
        .iter()
        .any(|library| library == path)
    {
        Role::NativeLibraryDirectory
    } else if input.native_linker.parent() == Some(path) {
        Role::LinkerDirectory
    } else if path.starts_with(&input.input_root) {
        Role::InputAncestor
    } else {
        Role::OutsideInputRoot
    }
}

fn live(input: &Toolchain) -> io::Result<()> {
    context(
        Op::QualifyClock,
        super::super::toolchain_debug::validate_clock(
            input.native_work_cutoff_ticks,
            input.native_work_frequency,
        ),
    )
}
impl<'a> Qualified<'a> {
    pub fn new(
        input: &Toolchain,
        command: &Command,
        root: Option<&'a HeldRoot>,
    ) -> io::Result<Self> {
        context(
            Op::QualifySelection,
            input.validate_selected_images().map_err(io::Error::other),
        )?;
        if command.get_current_dir() != Some(input.input_root.as_path())
            || command.get_program() != input.rustc.as_os_str()
            || input.controller_input_root != root.map(|held| held.identity)
        {
            return context(
                Op::QualifyCommand,
                Err(io::Error::other(
                    "compiler command cwd/program differs from qualified input layout",
                )),
            );
        }
        if let Some(root) = root {
            root.verify(input)?;
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
            .chain(root.and_then(|_| input.rustc.parent()))
        {
            for ancestor in path
                .ancestors()
                .take_while(|path| root.is_none() || path.starts_with(&input.input_root))
                .filter(|path| !path.as_os_str().is_empty())
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
            {
                live(input)?;
                if directories.contains_key(ancestor)
                    || (root.is_some() && ancestor == input.input_root)
                {
                    continue;
                }
                if directories.len() >= 64 {
                    return context(
                        Op::DirectoryOwnerBound,
                        Err(io::Error::other(
                            "compiler input ancestor owner bound exceeded",
                        )),
                    );
                }
                let role = directory_role(input, ancestor);
                let file = context(Op::DirectoryOpen(role), open_directory(ancestor))?;
                context(Op::DirectoryMetadata(role), metadata(&file, true))?;
                directories.insert(ancestor.to_owned(), file);
                live(input)?;
            }
        }
        let linker = context(Op::LinkerOpen, open_linker(&input.native_linker))?;
        let metadata = context(Op::LinkerMetadata, metadata(&linker, false))?;
        if metadata.length > 512 * 1024 * 1024 {
            return context(
                Op::LinkerMeasure,
                Err(io::Error::other(
                    "selected bundled linker exceeds original code bound",
                )),
            );
        }
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        let mut reader = &linker;
        let mut buffer = [0u8; 64 * 1024];
        let mut length = 0u64;
        loop {
            live(input)?;
            let count = context(Op::LinkerRead, reader.read(&mut buffer))?;
            live(input)?;
            if count == 0 {
                break;
            }
            length = context(
                Op::LinkerMeasure,
                length
                    .checked_add(count as u64)
                    .ok_or_else(|| io::Error::other("selected linker byte count overflow")),
            )?;
            if length > metadata.length {
                return context(
                    Op::LinkerMeasure,
                    Err(io::Error::other(
                        "selected linker grew during qualification",
                    )),
                );
            }
            digest.update(&buffer[..count]);
        }
        let linker_sha256 = String::from(memcordon_core::DiagnosticSha256::from_bytes(
            digest.finalize().into(),
        ));
        if length != metadata.length
            || !input.admits_created_image(&input.native_linker, &linker_sha256)
        {
            return context(
                Op::LinkerMeasure,
                Err(io::Error::other(
                    "original held bundled linker differs from frozen selected image",
                )),
            );
        }
        let qualified = Self {
            root,
            directories,
            linker,
            linker_sha256,
        };
        qualified.verify(input, command)?;
        Ok(qualified)
    }
    pub fn verify(&self, input: &Toolchain, command: &Command) -> io::Result<()> {
        live(input)?;
        if command.get_current_dir() != Some(input.input_root.as_path()) {
            return context(
                Op::QualifyCommand,
                Err(io::Error::other("compiler cwd changed after qualification")),
            );
        }
        if let Some(root) = self.root {
            root.verify(input)?;
        }
        for (path, file) in &self.directories {
            live(input)?;
            let role = directory_role(input, path);
            let held = context(Op::DirectoryRetainedMetadata(role), metadata(file, true))?;
            let named = context(Op::DirectoryNamedOpen(role), open_directory(path))?;
            let named = context(Op::DirectoryNamedMetadata(role), metadata(&named, true))?;
            if identity(&held) != identity(&named) {
                return context(
                    Op::DirectoryNamedIdentity(role),
                    Err(io::Error::other(
                        "compiler named input ancestry differs from original owners",
                    )),
                );
            }
            live(input)?;
        }
        let named = context(Op::LinkerNamedOpen, open_linker(&input.native_linker))?;
        let held = context(Op::LinkerRetainedMetadata, metadata(&self.linker, false))?;
        let named = context(Op::LinkerNamedMetadata, metadata(&named, false))?;
        if identity(&held) != identity(&named) || held.length != named.length {
            return context(
                Op::LinkerNamedIdentity,
                Err(io::Error::other(
                    "selected linker named identity differs from original owner",
                )),
            );
        }
        live(input)
    }
    pub fn receipt(&self, input: &Toolchain) -> io::Result<serde_json::Value> {
        let cwd = context(
            Op::QualifyCommand,
            self.root
                .map(|root| &root.file)
                .or_else(|| self.directories.get(&input.input_root))
                .ok_or_else(|| io::Error::other("original compiler cwd owner absent")),
        )?;
        let cwd = context(
            Op::DirectoryRetainedMetadata(Role::InputRoot),
            metadata(cwd, true),
        )?;
        let linker = context(Op::LinkerRetainedMetadata, metadata(&self.linker, false))?;
        Ok(
            serde_json::json!({"cwd_utf16":input.input_root.as_os_str().encode_wide().collect::<Vec<_>>(),
            "selected_linker_utf16":input.native_linker.as_os_str().encode_wide().collect::<Vec<_>>(),
            "cwd_native_identity":identity(&cwd),"selected_linker_native_identity":identity(&linker),
            "selected_linker_sha256":self.linker_sha256,"linker_mode":input.linker_mode,
            "retained_ancestor_count":self.directories.len() + usize::from(self.root.is_some()),"binding":"original held directory passed as Command.current_dir; original selected linker held through debug settlement"}),
        )
    }
}
