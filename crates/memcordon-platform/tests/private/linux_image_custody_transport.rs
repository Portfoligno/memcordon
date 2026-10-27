use super::*;
use std::io::Read;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::time::Duration;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

fn fixture() -> (tempfile::TempDir, std::path::PathBuf, File) {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let path = root.path().join("original");
    std::fs::write(&path, b"original capability bytes").unwrap();
    let file = File::open(&path).unwrap();
    (root, path, file)
}

fn count_original(file: &File) -> usize {
    let expected = file.metadata().unwrap();
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| std::fs::metadata(entry.path()).ok())
        .filter(|actual| (actual.dev(), actual.ino()) == (expected.dev(), expected.ino()))
        .count()
}

fn raw_packet(socket: &ImageCustodySocket, bytes: &[u8], files: &[&File]) {
    let mut vector = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: fixed initialized message and bounded aligned ancillary storage.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    // SAFETY: finite fixture descriptor count, only computes a length.
    let space =
        unsafe { libc::CMSG_SPACE((files.len() * size_of::<libc::c_int>()) as u32) } as usize;
    let mut control = vec![0usize; space.div_ceil(size_of::<usize>())];
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = space;
    // SAFETY: allocated control storage admits the full native header.
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    // SAFETY: write only the admitted count of borrowed fixture descriptors.
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len =
            libc::CMSG_LEN((files.len() * size_of::<libc::c_int>()) as u32) as usize;
        let target = libc::CMSG_DATA(header).cast::<libc::c_int>();
        for (ordinal, file) in files.iter().enumerate() {
            target.add(ordinal).write_unaligned(file.as_raw_fd());
        }
    }
    // SAFETY: fixture packet/control buffers remain live throughout native send.
    assert_eq!(
        unsafe {
            libc::sendmsg(
                socket.socket.as_raw_fd(),
                &message,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        },
        bytes.len() as isize
    );
}

#[test]
fn capability_transfer_retains_original_inode_and_positional_reads() {
    let (_root, path, file) = fixture();
    let (sender, receiver) = ImageCustodySocket::pair().unwrap();
    let cutoff = deadline();
    let peer = image_custody_current_peer().unwrap();
    sender.send(b"admit-original", Some(&file), cutoff).unwrap();
    let received = receiver.receive(peer, cutoff).unwrap();
    assert_eq!(received.bytes, b"admit-original");
    let retained = received.descriptor.unwrap();
    assert_eq!(
        (
            retained.metadata().unwrap().dev(),
            retained.metadata().unwrap().ino()
        ),
        (
            file.metadata().unwrap().dev(),
            file.metadata().unwrap().ino()
        )
    );
    receiver.send(b"acknowledged", None, cutoff).unwrap();
    assert_eq!(sender.receive(peer, cutoff).unwrap().bytes, b"acknowledged");
    let replacement = path.with_extension("replacement");
    std::fs::write(&replacement, b"different path bytes").unwrap();
    std::fs::rename(replacement, &path).unwrap();
    drop(file);
    let mut first = [0u8; 8];
    let mut second = [0u8; 8];
    retained.read_at(&mut first, 0).unwrap();
    retained.read_at(&mut second, 0).unwrap();
    assert_eq!(&first, b"original");
    assert_eq!(first, second);
    assert_ne!(
        retained.metadata().unwrap().ino(),
        std::fs::metadata(path).unwrap().ino()
    );
}

#[test]
fn malformed_truncated_or_wrong_peer_packets_close_every_delivered_descriptor() {
    let (_root, _path, file) = fixture();
    let peer = ImageCustodyPeer::current();
    for count in [2, REJECT_DESCRIPTOR_BOUND + 1] {
        let (sender, receiver) = ImageCustodySocket::pair().unwrap();
        let before = count_original(&file);
        raw_packet(&sender, b"too-many", &vec![&file; count]);
        assert!(receiver.receive(peer, deadline()).is_err());
        assert_eq!(count_original(&file), before);
    }
    let (sender, receiver) = ImageCustodySocket::pair().unwrap();
    let before = count_original(&file);
    raw_packet(&sender, &vec![0; IMAGE_CUSTODY_PACKET_BOUND + 1], &[&file]);
    assert!(receiver.receive(peer, deadline()).is_err());
    assert_eq!(count_original(&file), before);
    for wrong in [
        ImageCustodyPeer {
            pid: peer.pid.checked_add(1).unwrap(),
            ..peer
        },
        ImageCustodyPeer {
            uid: peer.uid.checked_add(1).unwrap(),
            ..peer
        },
        ImageCustodyPeer {
            gid: peer.gid.checked_add(1).unwrap(),
            ..peer
        },
    ] {
        sender.send(b"wrong-peer", Some(&file), deadline()).unwrap();
        assert!(receiver.receive(wrong, deadline()).is_err());
        assert_eq!(count_original(&file), before);
    }
}

#[test]
fn original_cutoff_prevents_io_and_clock_bridge_never_extends_it() {
    let (_root, _path, file) = fixture();
    let (sender, receiver) = ImageCustodySocket::pair().unwrap();
    let expired = Instant::now();
    assert_eq!(
        sender
            .send(b"expired", Some(&file), expired)
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    let cutoff = deadline();
    sender.send(b"retained-packet", None, cutoff).unwrap();
    assert!(
        receiver
            .receive(ImageCustodyPeer::current(), expired)
            .is_err()
    );
    assert_eq!(
        receiver
            .receive(ImageCustodyPeer::current(), cutoff)
            .unwrap()
            .bytes,
        b"retained-packet"
    );
    let transferred = image_custody_cutoff_nanos(cutoff).unwrap();
    assert!(image_custody_deadline(transferred).unwrap() <= cutoff);
    assert!(image_custody_deadline(0).is_err());
    let budget = image_custody_fd_budget().unwrap();
    assert!(budget.soft_limit > 0 && budget.open_descriptors > 0);
    assert!(image_custody_parent_pid().unwrap() > 0);

    // A complete local send and even receipt of the same capability do not
    // acknowledge an ownership handoff. The receiver deliberately sends no ACK.
    let original = file.metadata().unwrap();
    sender.send(b"unacknowledged", Some(&file), cutoff).unwrap();
    let unacknowledged = receiver
        .receive(ImageCustodyPeer::current(), cutoff)
        .unwrap();
    assert_eq!(unacknowledged.bytes, b"unacknowledged");
    let received = unacknowledged.descriptor.unwrap();
    let received_identity = received.metadata().unwrap();
    assert_eq!(
        (received_identity.dev(), received_identity.ino()),
        (original.dev(), original.ino())
    );
    drop(received);
    drop(receiver);

    // The kernel may accept a local packet after peer closure. Neither result
    // supplies the missing authenticated ACK or permits releasing this owner.
    let local_send = sender.send(b"lost-ack", Some(&file), cutoff);
    eprintln!("closed-peer local packet accepted={}", local_send.is_ok());
    assert!(sender.receive(ImageCustodyPeer::current(), cutoff).is_err());
    let retained = file.metadata().unwrap();
    assert!(retained.is_file());
    assert_eq!(
        (retained.dev(), retained.ino()),
        (original.dev(), original.ino())
    );
    assert_eq!(
        (retained.len(), retained.mode(), retained.nlink()),
        (original.len(), original.mode(), original.nlink())
    );
    let expected = b"original capability bytes";
    let mut actual = vec![0; expected.len()];
    assert_eq!(file.read_at(&mut actual, 0).unwrap(), expected.len());
    assert_eq!(actual, expected);
    assert_eq!(count_original(&file), 1);
}

struct ChildOwner(std::process::Child, Instant);

impl Drop for ChildOwner {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        loop {
            match self.0.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < self.1 => std::thread::sleep(Duration::from_millis(1)),
                Ok(None) | Err(_) => {
                    eprintln!(
                        "native transport test child retirement unobserved at original cutoff"
                    );
                    break;
                }
            }
        }
    }
}

#[test]
fn actual_child_messages_bind_kernel_pid_and_return_same_original() {
    let (_root, _path, file) = fixture();
    let (parent, child) = ImageCustodySocket::pair().unwrap();
    let cutoff = deadline();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    let selector = match module_path!().split("::").nth(1) {
        Some("transport") => "transport::native_tests::inherited_child",
        Some("test_support") => {
            "test_support::linux_image_custody_transport::native_tests::inherited_child"
        }
        _ => panic!("unexpected native transport test module"),
    };
    command
        .args(["--exact", selector, "--ignored", "--nocapture"])
        .stdin(child.into_stdio())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = ChildOwner(command.spawn().unwrap(), cutoff);
    drop(command);
    let peer = ImageCustodyPeer {
        pid: child.0.id(),
        ..ImageCustodyPeer::current()
    };
    parent
        .send(
            &image_custody_cutoff_nanos(cutoff).unwrap().to_le_bytes(),
            Some(&file),
            cutoff,
        )
        .unwrap();
    let ack = parent.receive(peer, cutoff).unwrap();
    assert_eq!(ack.bytes, b"stored-original");
    drop(file);
    parent.send(b"duplicate", None, cutoff).unwrap();
    let lease = parent.receive(peer, cutoff).unwrap().descriptor.unwrap();
    let mut bytes = Vec::new();
    (&lease).read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"original capability bytes");
    parent.send(b"finish", None, cutoff).unwrap();
    assert_eq!(
        parent.receive(peer, cutoff).unwrap().bytes,
        b"retired-original"
    );
    loop {
        cutoff_check(cutoff);
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn cutoff_check(cutoff: Instant) {
    assert!(Instant::now() < cutoff);
}

#[test]
#[ignore = "invoked only by the owned parent transport test"]
fn inherited_child() {
    let socket = ImageCustodySocket::take_stdin().unwrap();
    let peer = ImageCustodyPeer {
        pid: image_custody_parent_pid().unwrap(),
        ..ImageCustodyPeer::current()
    };
    let packet = socket.receive(peer, deadline()).unwrap();
    let inherited: [u8; size_of::<u64>()] = packet.bytes.try_into().unwrap();
    let cutoff = image_custody_deadline(u64::from_le_bytes(inherited)).unwrap();
    let original = packet.descriptor.unwrap();
    socket.send(b"stored-original", None, cutoff).unwrap();
    assert_eq!(socket.receive(peer, cutoff).unwrap().bytes, b"duplicate");
    socket.send(b"duplicate", Some(&original), cutoff).unwrap();
    assert_eq!(socket.receive(peer, cutoff).unwrap().bytes, b"finish");
    drop(original);
    socket.send(b"retired-original", None, cutoff).unwrap();
}
