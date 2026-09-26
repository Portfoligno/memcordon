//! Disposable helper-local valid-context controls. Only an independently
//! admitted root wrapper may call this primitive; it creates no target grant.
use super::network_filter::{NativeAbi, install_gated_private_filter};
use memcordon_core::DiagnosticSha256;
use memcordon_core::private_facility_source_v1::*;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

const MAX_FRAME: usize = 64 * 1024;
#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Message {
    Held {
        phase: FacilityPhaseV1,
        helper: FacilityProcessV1,
        objects: Vec<FacilityObjectV1>,
        status: Vec<u8>,
    },
    Report {
        report: FacilitySourceReportV1,
    },
    Failure {
        message: String,
    },
}
struct ChildOwner(i32);
impl ChildOwner {
    fn wait(&mut self) -> Result<i32, String> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let mut status = 0;
            let ret = unsafe { libc::waitpid(self.0, &mut status, libc::WNOHANG) };
            if ret == self.0 {
                self.0 = 0;
                return Ok(status);
            }
            if ret < 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            if Instant::now() >= deadline {
                return Err("facility child wait deadline".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for ChildOwner {
    fn drop(&mut self) {
        if self.0 > 0 {
            unsafe {
                libc::kill(self.0, libc::SIGKILL);
                libc::waitpid(self.0, std::ptr::null_mut(), 0);
            }
        }
    }
}
fn pipe() -> Result<[OwnedFd; 2], String> {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(unsafe { [OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])] })
}
fn process(pid: i32) -> Result<FacilityProcessV1, String> {
    Ok(FacilityProcessV1 {
        pid: u32::try_from(pid).map_err(|e| e.to_string())?,
        start_time_ticks: super::envelope::process_start_time(pid)?,
    })
}
fn namespace() -> Result<u64, String> {
    let inode = std::fs::metadata("/proc/self/ns/net")
        .map_err(|e| e.to_string())?
        .ino();
    if inode == 0 {
        Err("facility namespace inode absent".into())
    } else {
        Ok(inode)
    }
}
fn object(fd: i32, role: &str) -> Result<FacilityObjectV1, String> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let stat = unsafe { stat.assume_init() };
    let path = std::path::Path::new("/proc/self/fdinfo").join(fd.to_string());
    let file = File::open(path).map_err(|e| e.to_string())?;
    let mut fdinfo = Vec::new();
    file.take(8193)
        .read_to_end(&mut fdinfo)
        .map_err(|e| e.to_string())?;
    if stat.st_ino == 0 || fdinfo.len() > 8192 {
        return Err("facility object identity/bound differs".into());
    }
    Ok(FacilityObjectV1 {
        role: role.into(),
        fd,
        device: stat.st_dev,
        inode: stat.st_ino,
        fdinfo,
    })
}
fn close_owned(fd: OwnedFd, role: &str, closes: &mut Vec<FacilityCloseV1>) -> Result<(), String> {
    let object = object(fd.as_raw_fd(), role)?;
    let before = super::clock::monotonic_nanos()?;
    let result = unsafe { libc::close(fd.into_raw_fd()) };
    let after = super::clock::monotonic_nanos()?;
    closes.push(FacilityCloseV1 {
        object,
        before_monotonic_ns: before,
        after_monotonic_ns: after,
        result,
    });
    if result != 0 {
        return Err("facility actual close failed".into());
    }
    Ok(())
}
fn write_message(file: &mut File, message: &Message) -> Result<(), String> {
    let bytes = serde_json::to_vec(message).map_err(|e| e.to_string())?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err("facility frame exceeds bound".into());
    }
    file.write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|()| file.write_all(&bytes))
        .and_then(|()| file.flush())
        .map_err(|e| e.to_string())
}
fn read_exact_bounded(file: &mut File, bytes: &mut [u8], deadline: Instant) -> Result<(), String> {
    let mut offset = 0;
    while offset < bytes.len() {
        if Instant::now() >= deadline {
            return Err("facility frame deadline".into());
        }
        let mut poll = libc::pollfd {
            fd: file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut poll, 1, 100) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        if ret == 0 {
            continue;
        }
        let count = file.read(&mut bytes[offset..]).map_err(|e| e.to_string())?;
        if count == 0 {
            return Err("facility frame closed early".into());
        }
        offset += count;
    }
    Ok(())
}
fn read_message(file: &mut File, deadline: Instant) -> Result<Message, String> {
    let mut length = [0; 4];
    read_exact_bounded(file, &mut length, deadline)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err("facility frame bound differs".into());
    }
    let mut bytes = vec![0; length];
    read_exact_bounded(file, &mut bytes, deadline)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}
fn install_outer() -> Result<DiagnosticSha256, String> {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let instruction = libc::sock_filter {
        code: 6,
        jt: 0,
        jf: 0,
        k: 0x7fff0000,
    };
    let program = libc::sock_fprog {
        len: 1,
        filter: (&instruction as *const libc::sock_filter).cast_mut(),
    };
    if unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0,
            &program,
        )
    } != 0
    {
        return Err("facility helper noop install failed".into());
    }
    Ok(memcordon_core::workload_codec::hash_bytes(
        &outer_allow_program_v1(),
    ))
}

struct Context {
    source: Option<File>,
    source_process: Option<FacilityProcessV1>,
    source_child: Option<ChildOwner>,
    source_go: Option<OwnedFd>,
    pidfd: Option<OwnedFd>,
    namespace: Option<File>,
    pair: Option<[OwnedFd; 2]>,
    parameters: Box<[u64; 15]>,
    slots: Box<[i32; 2]>,
    payload: Box<[u8; 1]>,
    iov: Box<libc::iovec>,
    control: Vec<usize>,
    message: Box<libc::msghdr>,
    created: Vec<(OwnedFd, String)>,
}
impl Context {
    fn prepare(operations: &[FacilityOperationV1]) -> Result<Self, String> {
        let mut ctx = Self {
            source: None,
            source_process: None,
            source_child: None,
            source_go: None,
            pidfd: None,
            namespace: None,
            pair: None,
            parameters: Box::new([0; 15]),
            slots: Box::new([-1; 2]),
            payload: Box::new([0x51]),
            iov: Box::new(unsafe { std::mem::zeroed() }),
            control: Vec::new(),
            message: Box::new(unsafe { std::mem::zeroed() }),
            created: Vec::new(),
        };
        if operations.contains(&FacilityOperationV1::PidfdGetfd)
            || operations.contains(&FacilityOperationV1::Sendmsg)
        {
            ctx.source = Some(File::open("/dev/null").map_err(|e| e.to_string())?);
        }
        if operations.contains(&FacilityOperationV1::PidfdGetfd) {
            let [read, write] = pipe()?;
            let child = unsafe { libc::fork() };
            if child < 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            if child == 0 {
                drop(write);
                let mut byte = [0];
                let result =
                    unsafe { libc::read(read.as_raw_fd(), byte.as_mut_ptr().cast(), byte.len()) };
                unsafe {
                    libc::_exit(if result == 1 && byte == [0x5a] {
                        0
                    } else {
                        125
                    })
                };
            }
            drop(read);
            ctx.source_child = Some(ChildOwner(child));
            ctx.source_process = Some(process(child)?);
            ctx.source_go = Some(write);
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child, 0) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            ctx.pidfd = Some(unsafe { OwnedFd::from_raw_fd(fd as i32) });
        }
        if operations.contains(&FacilityOperationV1::Setns) {
            ctx.namespace = Some(File::open("/proc/self/ns/net").map_err(|e| e.to_string())?);
        }
        if operations.contains(&FacilityOperationV1::Sendmsg) {
            let mut pair = [-1; 2];
            if unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    pair.as_mut_ptr(),
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
            ctx.pair =
                Some(unsafe { [OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])] });
            let length = unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) } as usize;
            ctx.control = vec![0; length.div_ceil(std::mem::size_of::<usize>())];
            ctx.iov.iov_base = ctx.payload.as_mut_ptr().cast();
            ctx.iov.iov_len = ctx.payload.len();
            ctx.message.msg_iov = &mut *ctx.iov;
            ctx.message.msg_iovlen = 1;
            ctx.message.msg_control = ctx.control.as_mut_ptr().cast();
            ctx.message.msg_controllen = length;
            unsafe {
                let header = libc::CMSG_FIRSTHDR(&*ctx.message);
                if header.is_null() {
                    return Err("facility cmsg absent".into());
                }
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as usize;
                *libc::CMSG_DATA(header).cast::<i32>() = ctx
                    .source
                    .as_ref()
                    .expect("SCM source prepared")
                    .as_raw_fd();
            }
        }
        Ok(ctx)
    }
    fn objects(&self) -> Result<Vec<FacilityObjectV1>, String> {
        let mut objects = Vec::new();
        if let Some(source) = &self.source {
            objects.push(object(source.as_raw_fd(), "source")?);
        }
        if let Some(pidfd) = &self.pidfd {
            objects.push(object(pidfd.as_raw_fd(), "pidfd")?);
        }
        if let Some(namespace) = &self.namespace {
            objects.push(object(namespace.as_raw_fd(), "namespace")?);
        }
        if let Some(pair) = &self.pair {
            for (index, fd) in pair.iter().enumerate() {
                objects.push(object(
                    fd.as_raw_fd(),
                    if index == 0 {
                        "scm-send"
                    } else {
                        "scm-receive"
                    },
                )?);
            }
        }
        for (fd, role) in &self.created {
            objects.push(object(fd.as_raw_fd(), role)?);
        }
        Ok(objects)
    }
    fn call(
        &mut self,
        operation: FacilityOperationV1,
        phase: FacilityPhaseV1,
        arch: u32,
    ) -> Result<FacilityCallV1, String> {
        use FacilityOperationV1::*;
        self.parameters.fill(0);
        self.slots.fill(-1);
        let mut transferred = None;
        let (nr, args, mut operand) = match operation {
            Socket => (
                libc::SYS_socket,
                [
                    libc::AF_UNIX as u64,
                    (libc::SOCK_STREAM | libc::SOCK_CLOEXEC) as u64,
                    0,
                    0,
                    0,
                    0,
                ],
                FacilityOperandV1::Scalars,
            ),
            Socketpair => {
                let address = self.slots.as_mut_ptr() as u64;
                (
                    libc::SYS_socketpair,
                    [
                        libc::AF_UNIX as u64,
                        (libc::SOCK_STREAM | libc::SOCK_CLOEXEC) as u64,
                        0,
                        address,
                        0,
                        0,
                    ],
                    FacilityOperandV1::Socketpair {
                        output_address: address,
                        slots_before: *self.slots,
                        slots_after: *self.slots,
                    },
                )
            }
            IoUringSetup => {
                let address = self.parameters.as_mut_ptr() as u64;
                (
                    libc::SYS_io_uring_setup,
                    [1, address, 0, 0, 0, 0],
                    FacilityOperandV1::IoUring {
                        parameter_address: address,
                        parameters_before: *self.parameters,
                        parameters_after: *self.parameters,
                    },
                )
            }
            PidfdGetfd => {
                let pidfd = object(
                    self.pidfd.as_ref().expect("pidfd prepared").as_raw_fd(),
                    "pidfd",
                )?;
                let source = object(
                    self.source.as_ref().expect("source prepared").as_raw_fd(),
                    "source",
                )?;
                (
                    libc::SYS_pidfd_getfd,
                    [pidfd.fd as u64, source.fd as u64, 0, 0, 0, 0],
                    FacilityOperandV1::Descriptor {
                        object: pidfd,
                        source: Some(source),
                        source_process: self.source_process.clone(),
                    },
                )
            }
            Setns => {
                let namespace = object(
                    self.namespace
                        .as_ref()
                        .expect("namespace prepared")
                        .as_raw_fd(),
                    "namespace",
                )?;
                (
                    libc::SYS_setns,
                    [namespace.fd as u64, libc::CLONE_NEWNET as u64, 0, 0, 0, 0],
                    FacilityOperandV1::Descriptor {
                        object: namespace,
                        source: None,
                        source_process: None,
                    },
                )
            }
            Unshare => (
                libc::SYS_unshare,
                [libc::CLONE_NEWNET as u64, 0, 0, 0, 0, 0],
                FacilityOperandV1::Scalars,
            ),
            Sendmsg => {
                let socket = object(
                    self.pair.as_ref().expect("SCM pair prepared")[0].as_raw_fd(),
                    "scm-send",
                )?;
                let source = object(
                    self.source
                        .as_ref()
                        .expect("SCM source prepared")
                        .as_raw_fd(),
                    "source",
                )?;
                let message_address = (&*self.message as *const libc::msghdr) as u64;
                let control_bytes = unsafe {
                    std::slice::from_raw_parts(
                        self.message.msg_control.cast::<u8>(),
                        self.message.msg_controllen,
                    )
                }
                .to_vec();
                (
                    libc::SYS_sendmsg,
                    [
                        socket.fd as u64,
                        message_address,
                        libc::MSG_NOSIGNAL as u64,
                        0,
                        0,
                        0,
                    ],
                    FacilityOperandV1::ScmRights {
                        socket,
                        source,
                        message_address,
                        iov_address: self.message.msg_iov as u64,
                        payload_address: self.iov.iov_base as u64,
                        control_address: self.message.msg_control as u64,
                        payload: self.payload.to_vec(),
                        control_bytes,
                        transferred_device: None,
                        transferred_inode: None,
                    },
                )
            }
        };
        let namespace_before = namespace()?;
        let before = super::clock::monotonic_nanos()?;
        let result =
            unsafe { libc::syscall(nr, args[0], args[1], args[2], args[3], args[4], args[5]) };
        let errno = if result < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32
        } else {
            0
        };
        let after = super::clock::monotonic_nanos()?;
        let namespace_after = namespace()?;
        if operation == Sendmsg && result == 1 && phase == FacilityPhaseV1::Outer {
            let receive = self.pair.as_ref().expect("SCM pair prepared")[1].as_raw_fd();
            let mut payload = [0];
            let mut iov = libc::iovec {
                iov_base: payload.as_mut_ptr().cast(),
                iov_len: payload.len(),
            };
            let length = unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) } as usize;
            let mut control = vec![0usize; length.div_ceil(std::mem::size_of::<usize>())];
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = length;
            if unsafe {
                libc::recvmsg(
                    receive,
                    &mut msg,
                    libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT,
                )
            } != 1
                || payload != [0x51]
                || msg.msg_flags != 0
            {
                return Err("facility outer SCM receive differs".into());
            }
            let header = unsafe { libc::CMSG_FIRSTHDR(&msg) };
            if header.is_null()
                || unsafe {
                    (*header).cmsg_level != libc::SOL_SOCKET
                        || (*header).cmsg_type != libc::SCM_RIGHTS
                        || (*header).cmsg_len
                            != libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as usize
                }
            {
                return Err("facility outer SCM cmsg differs".into());
            }
            let fd = unsafe { OwnedFd::from_raw_fd(*libc::CMSG_DATA(header).cast::<i32>()) };
            let copied = object(fd.as_raw_fd(), "transferred-source")?;
            let source = object(
                self.source
                    .as_ref()
                    .expect("SCM source prepared")
                    .as_raw_fd(),
                "source",
            )?;
            if (copied.device, copied.inode) != (source.device, source.inode) {
                return Err("facility outer SCM source differs".into());
            }
            transferred = Some((copied.device, copied.inode));
            self.created.push((fd, "transferred-source".into()));
        }
        match &mut operand {
            FacilityOperandV1::Socketpair { slots_after, .. } => *slots_after = *self.slots,
            FacilityOperandV1::IoUring {
                parameters_after, ..
            } => *parameters_after = *self.parameters,
            FacilityOperandV1::ScmRights {
                transferred_device,
                transferred_inode,
                ..
            } => {
                *transferred_device = transferred.map(|v| v.0);
                *transferred_inode = transferred.map(|v| v.1);
            }
            _ => {}
        }
        if result >= 0 {
            if matches!(operation, Socket | IoUringSetup | PidfdGetfd) {
                let fd = unsafe { OwnedFd::from_raw_fd(result as i32) };
                if operation == PidfdGetfd {
                    let copied = object(fd.as_raw_fd(), "imported-source")?;
                    let source = object(
                        self.source
                            .as_ref()
                            .expect("import source prepared")
                            .as_raw_fd(),
                        "source",
                    )?;
                    if (copied.device, copied.inode) != (source.device, source.inode) {
                        return Err("facility imported object differs".into());
                    }
                }
                self.created.push((fd, "operation-result".into()));
            } else if operation == Socketpair && result == 0 {
                for fd in *self.slots {
                    if fd < 0 {
                        return Err("facility successful socketpair slots differ".into());
                    }
                    self.created.push((
                        unsafe { OwnedFd::from_raw_fd(fd) },
                        "socketpair-result".into(),
                    ));
                }
            }
        }
        Ok(FacilityCallV1 {
            operation,
            phase,
            audit_arch: arch,
            syscall_nr: nr,
            args,
            before_monotonic_ns: before,
            after_monotonic_ns: after,
            result,
            errno,
            namespace_before,
            namespace_after,
            operand,
        })
    }
    fn close(mut self) -> Result<(Vec<FacilityCloseV1>, Option<i32>), String> {
        let mut closes = Vec::new();
        let mut source_status = None;
        if let Some(go) = self.source_go.take() {
            File::from(go)
                .write_all(&[0x5a])
                .map_err(|e| e.to_string())?;
        }
        if let Some(mut child) = self.source_child.take() {
            source_status = Some(child.wait()?);
        }
        for (fd, role) in self.created.drain(..) {
            close_owned(fd, &role, &mut closes)?;
        }
        if let Some(pair) = self.pair.take() {
            for (index, fd) in pair.into_iter().enumerate() {
                close_owned(
                    fd,
                    if index == 0 {
                        "scm-send"
                    } else {
                        "scm-receive"
                    },
                    &mut closes,
                )?;
            }
        }
        if let Some(pidfd) = self.pidfd.take() {
            close_owned(pidfd, "pidfd", &mut closes)?;
        }
        if let Some(file) = self.source.take() {
            close_owned(file.into(), "source", &mut closes)?;
        }
        if let Some(file) = self.namespace.take() {
            close_owned(file.into(), "namespace", &mut closes)?;
        }
        Ok((closes, source_status))
    }
}

fn phase(
    report: &mut File,
    go: &mut File,
    phase: FacilityPhaseV1,
    helper: &FacilityProcessV1,
    ctx: &Context,
) -> Result<Vec<u8>, String> {
    let file = File::open("/proc/self/status").map_err(|e| e.to_string())?;
    let mut status = Vec::new();
    file.take(8193)
        .read_to_end(&mut status)
        .map_err(|e| e.to_string())?;
    if status.len() > 8192 {
        return Err("facility helper status exceeds bound".into());
    }
    write_message(
        report,
        &Message::Held {
            phase,
            helper: helper.clone(),
            objects: ctx.objects()?,
            status: status.clone(),
        },
    )?;
    let mut byte = [0];
    read_exact_bounded(go, &mut byte, Instant::now() + Duration::from_secs(45))?;
    if byte != [0xa5] {
        return Err("facility root held ACK differs".into());
    }
    Ok(status)
}
fn child_run(
    selector: &str,
    key: &DiagnosticSha256,
    abi: NativeAbi,
    private_filter: &DiagnosticSha256,
    report: &mut File,
    go: &mut File,
) -> Result<FacilitySourceReportV1, String> {
    let operations = facility_operations_v1(selector).map_err(str::to_owned)?;
    let mut ctx = Context::prepare(operations)?;
    let helper = process(unsafe { libc::getpid() })?;
    let source_process = ctx.source_process.clone();
    let outer_filter = install_outer()?;
    let status_after_outer_install = phase(report, go, FacilityPhaseV1::Outer, &helper, &ctx)?;
    let arch = match abi {
        NativeAbi::X86_64 => 0xc000003e,
        NativeAbi::Aarch64 => 0xc00000b7,
    };
    let mut calls = Vec::new();
    for operation in operations {
        let call = ctx.call(*operation, FacilityPhaseV1::Outer, arch)?;
        if call.result < 0 || (*operation == FacilityOperationV1::Sendmsg && call.result != 1) {
            return Err(format!(
                "valid outer facility prerequisite failed: {operation:?} errno {}",
                call.errno
            ));
        }
        calls.push(call);
    }
    install_gated_private_filter(abi, *private_filter.bytes())?;
    let status_after_private_install = phase(report, go, FacilityPhaseV1::Private, &helper, &ctx)?;
    for operation in operations {
        let call = ctx.call(*operation, FacilityPhaseV1::Private, arch)?;
        let errno = if *operation == FacilityOperationV1::Socket {
            libc::EAFNOSUPPORT
        } else {
            libc::EPERM
        };
        if call.result != -1 || call.errno != errno as u32 {
            return Err("facility private exact denial differs".into());
        }
        calls.push(call);
    }
    let (closes, source_wait_status) = ctx.close()?;
    Ok(FacilitySourceReportV1 {
        schema_version: 1,
        source_revision_sha256: facility_source_revision_sha256(),
        selector: selector.into(),
        parent_result_key: key.clone(),
        helper,
        source_process,
        private_filter_sha256: private_filter.clone(),
        outer_filter_sha256: outer_filter,
        status_after_outer_install,
        status_after_private_install,
        calls,
        closes,
        source_wait_status,
        helper_wait_status: 0,
    })
}

pub(crate) fn run_owned(
    selector: &str,
    parent_result_key: &DiagnosticSha256,
    abi: NativeAbi,
    private_filter: &DiagnosticSha256,
    mut held: impl FnMut(
        FacilityPhaseV1,
        &FacilityProcessV1,
        &[FacilityObjectV1],
        &[u8],
    ) -> Result<(), String>,
) -> Result<FacilitySourceReportV1, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("facility primitive requires admitted root wrapper".into());
    }
    facility_operations_v1(selector).map_err(str::to_owned)?;
    let [read, write] = pipe()?;
    let [go_read, go_write] = pipe()?;
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if child == 0 {
        drop(read);
        drop(go_write);
        let mut report = File::from(write);
        let mut go = File::from(go_read);
        let result = child_run(
            selector,
            parent_result_key,
            abi,
            private_filter,
            &mut report,
            &mut go,
        );
        let good = result.is_ok();
        let message = match result {
            Ok(report) => Message::Report { report },
            Err(message) => Message::Failure { message },
        };
        let written = write_message(&mut report, &message).is_ok();
        unsafe { libc::_exit(if good && written { 0 } else { 125 }) };
    }
    drop(write);
    drop(go_read);
    let mut owner = ChildOwner(child);
    let identity = process(child)?;
    let mut input = File::from(read);
    let mut go = File::from(go_write);
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut next = Some(FacilityPhaseV1::Outer);
    loop {
        match read_message(&mut input, deadline)? {
            Message::Held {
                phase,
                helper,
                objects,
                status,
            } => {
                if helper != identity || Some(phase) != next {
                    return Err("facility actual held helper/phase differs".into());
                }
                held(phase, &helper, &objects, &status)?;
                go.write_all(&[0xa5]).map_err(|e| e.to_string())?;
                next = if phase == FacilityPhaseV1::Outer {
                    Some(FacilityPhaseV1::Private)
                } else {
                    None
                };
            }
            Message::Report { mut report } => {
                if next.is_some()
                    || report.helper != identity
                    || report.selector != selector
                    || report.parent_result_key != *parent_result_key
                {
                    return Err("facility final helper subject differs".into());
                }
                report.helper_wait_status = owner.wait()?;
                if report.helper_wait_status != 0
                    || report.source_wait_status.is_some_and(|s| s != 0)
                {
                    return Err("facility actual helper/source wait differs".into());
                }
                validate_facility_source_shape(&report).map_err(str::to_owned)?;
                return Ok(report);
            }
            Message::Failure { message } => {
                let status = owner.wait()?;
                return Err(format!(
                    "facility prerequisite/source failed ({status}): {message}"
                ));
            }
        }
    }
}
