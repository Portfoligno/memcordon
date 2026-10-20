//! Bind the original filesystem socket through a short, held-directory alias.
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixListener;
use std::path::{Component, Path};

pub fn bind_via_held_alias(parent: &File, alias: &Path, leaf: &OsStr) -> io::Result<UnixListener> {
    let mut components = Path::new(leaf).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket leaf is not one native name",
        ));
    }
    // The production alias is /proc/self/fd/<held parent descriptor>. Follow
    // that deliberate kernel alias, then compare it with the actual held inode.
    let named = std::fs::metadata(alias)?;
    let held = parent.metadata()?;
    if !named.is_dir()
        || !held.is_dir()
        || held.nlink() == 0
        || (named.dev(), named.ino()) != (held.dev(), held.ino())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "socket alias differs from held parent",
        ));
    }
    UnixListener::bind(alias.join(leaf))
}
