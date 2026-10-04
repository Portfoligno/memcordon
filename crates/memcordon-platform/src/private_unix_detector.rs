//! A positive Unix-inventory detector control confined to a fresh thread's
//! private network and mount namespaces. No product/host endpoint is planted.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{SocketAddr, UnixListener};

fn read(path: &str) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err(io::Error::other("Unix detector source bound differs"));
    }
    Ok(bytes)
}

pub(super) fn sample(challenge: [u8; 32]) -> io::Result<BTreeMap<String, Vec<u8>>> {
    // SAFETY: geteuid has no pointer operands or state effects.
    if unsafe { libc::geteuid() } != 0 || challenge == [0; 32] {
        return Err(io::Error::other(
            "Unix detector requires root and fresh challenge",
        ));
    }
    let mut challenge_hex = String::new();
    use std::fmt::Write;
    for byte in challenge {
        write!(&mut challenge_hex, "{byte:02x}").map_err(io::Error::other)?;
    }
    let pathname = format!("/tmp/memcordon-private-unix-{challenge_hex}-path");
    let abstract_name = format!("memcordon-private-unix-{challenge_hex}-abstract");
    let original_net = std::fs::metadata("/proc/thread-self/ns/net")?.ino();
    let original_mount = std::fs::metadata("/proc/thread-self/ns/mnt")?.ino();
    std::thread::spawn(move || -> io::Result<BTreeMap<String, Vec<u8>>> {
        // SAFETY: only this newly spawned thread detaches its filesystem state
        // and namespaces. On every return its private namespaces are destroyed.
        if unsafe { libc::unshare(libc::CLONE_FS | libc::CLONE_NEWNS | libc::CLONE_NEWNET) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let slash = CString::new("/").map_err(io::Error::other)?;
        // SAFETY: the NUL-terminated target is valid; propagation changes are
        // confined to this thread's newly unshared mount namespace.
        if unsafe {
            libc::mount(
                std::ptr::null(),
                slash.as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let tmp = CString::new("/tmp").map_err(io::Error::other)?;
        let tmpfs = CString::new("tmpfs").map_err(io::Error::other)?;
        let options = CString::new("size=1048576,mode=0700").map_err(io::Error::other)?;
        // SAFETY: all C strings live through mount; the private tmpfs contains
        // only this bounded detector control and cannot alter the host /tmp.
        if unsafe {
            libc::mount(
                tmpfs.as_ptr(),
                tmp.as_ptr(),
                tmpfs.as_ptr(),
                libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC,
                options.as_ptr().cast(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let net = std::fs::metadata("/proc/thread-self/ns/net")?.ino();
        let mount = std::fs::metadata("/proc/thread-self/ns/mnt")?.ino();
        if net == original_net || mount == original_mount || net == 0 || mount == 0 {
            return Err(io::Error::other(
                "Unix detector namespaces were not isolated",
            ));
        }
        let begin = crate::test_support::private_observer_monotonic_ns()?;
        let before = read("/proc/thread-self/net/unix")?;
        let path_listener = UnixListener::bind(&pathname)?;
        let abstract_listener =
            UnixListener::bind_addr(&SocketAddr::from_abstract_name(abstract_name.as_bytes())?)?;
        let path_fd = path_listener.as_raw_fd();
        let abstract_fd = abstract_listener.as_raw_fd();
        let path_object = std::fs::metadata(format!("/proc/thread-self/fd/{path_fd}"))?;
        let abstract_object = std::fs::metadata(format!("/proc/thread-self/fd/{abstract_fd}"))?;
        let mut leaves = BTreeMap::new();
        leaves.insert("stat-before.raw".into(), read("/proc/thread-self/stat")?);
        leaves.insert("status.raw".into(), read("/proc/thread-self/status")?);
        leaves.insert("unix-before.raw".into(), before);
        leaves.insert("unix-held.raw".into(), read("/proc/thread-self/net/unix")?);
        leaves.insert(
            "pathname-fdinfo.raw".into(),
            read(&format!("/proc/thread-self/fdinfo/{path_fd}"))?,
        );
        leaves.insert(
            "abstract-fdinfo.raw".into(),
            read(&format!("/proc/thread-self/fdinfo/{abstract_fd}"))?,
        );
        let held_ns = crate::test_support::private_observer_monotonic_ns()?;
        let metadata = std::fs::symlink_metadata(&pathname)?;
        leaves.insert(
            "identity.json".into(),
            serde_json::to_vec(&serde_json::json!({
                "schema_version":1,"protocol":"private-unix-planted-detector-v1",
                "pathname":pathname,"abstract_name":abstract_name,
                "reader_netns_inode":original_net,"reader_mountns_inode":original_mount,
                "control_netns_inode":net,"control_mountns_inode":mount,
                "pathname_fd":path_fd,"pathname_socket_inode":path_object.ino(),
                "abstract_fd":abstract_fd,"abstract_socket_inode":abstract_object.ino(),
                "pathname_device":metadata.dev(),"pathname_inode":metadata.ino(),
                "pathname_mode":metadata.mode(),"pathname_uid":metadata.uid(),
                "begin_monotonic_ns":begin,"held_monotonic_ns":held_ns
            }))
            .map_err(io::Error::other)?,
        );
        drop(path_listener);
        drop(abstract_listener);
        std::fs::remove_file(&pathname)?;
        leaves.insert("unix-after.raw".into(), read("/proc/thread-self/net/unix")?);
        leaves.insert("stat-after.raw".into(), read("/proc/thread-self/stat")?);
        leaves.insert(
            "end-monotonic.raw".into(),
            crate::test_support::private_observer_monotonic_ns()?
                .to_le_bytes()
                .to_vec(),
        );
        if std::fs::metadata("/proc/thread-self/ns/net")?.ino() != net
            || std::fs::metadata("/proc/thread-self/ns/mnt")?.ino() != mount
        {
            return Err(io::Error::other(
                "Unix detector cleanup or namespace changed",
            ));
        }
        match std::fs::symlink_metadata(&pathname) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => return Err(io::Error::other("Unix detector pathname survived cleanup")),
        }
        Ok(leaves)
    })
    .join()
    .map_err(|_| io::Error::other("Unix detector thread panicked"))?
}
