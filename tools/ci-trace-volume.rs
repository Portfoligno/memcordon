//! A newly created bounded VHD, used entirely inside the contained recording helper.
use std::ffi::{OsStr, OsString, c_void};
use std::fs;
use std::io::{self, Read, Write};
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

type Handle = *mut c_void;
const CAPACITY: u64 = 256 * 1024 * 1024;
const OFFSET: i64 = 1024 * 1024;
const LENGTH: i64 = CAPACITY as i64 - 2 * OFFSET;
const INVALID: Handle = -1_isize as Handle;
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Guid {
    a: u32,
    b: u16,
    c: u16,
    d: [u8; 8],
}
#[repr(C)]
struct Storage {
    device: u32,
    vendor: Guid,
}
#[repr(C)]
struct CreateParameters {
    version: u32,
    parameters: CreateVersionOne,
}
#[repr(C)]
struct CreateVersionOne {
    id: Guid,
    maximum: u64,
    block: u32,
    sector: u32,
    parent: *const u16,
    source: *const u16,
}
#[repr(C)]
struct AttachParameters {
    version: u32,
    // The modern SDK's versioned union has 64-bit alignment and two u64s.
    parameters: [u64; 2],
}
#[repr(C)]
struct CreateDisk {
    style: u32,
    id: Guid,
    partitions: u32,
}
#[repr(C)]
struct Layout {
    style: u32,
    count: u32,
    id: Guid,
    start: i64,
    length: i64,
    max: u32,
    partition: Partition,
}
#[repr(C)]
struct Partition {
    style: u32,
    start: i64,
    length: i64,
    number: u32,
    rewrite: bool,
    service: bool,
    kind: Guid,
    id: Guid,
    attributes: u64,
    name: [u16; 36],
}
#[repr(C)]
#[derive(Default)]
struct DeviceNumber {
    kind: u32,
    number: u32,
    partition: u32,
}
#[repr(C)]
#[derive(Default)]
struct Extents {
    count: u32,
    disk: DiskExtent,
}
#[repr(C)]
#[derive(Default)]
struct DiskExtent {
    number: u32,
    start: i64,
    length: i64,
}
#[repr(C)]
#[derive(Default)]
struct Privilege {
    count: u32,
    luid: [u32; 2],
    attributes: u32,
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    fn LookupPrivilegeValueW(system: *const u16, name: *const u16, luid: *mut [u32; 2]) -> i32;
    fn AdjustTokenPrivileges(
        token: Handle,
        disable: i32,
        state: *const Privilege,
        length: u32,
        previous: *mut c_void,
        returned: *mut u32,
    ) -> i32;
}
#[link(name = "virtdisk")]
unsafe extern "system" {
    fn CreateVirtualDisk(
        storage: *const Storage,
        path: *const u16,
        access: u32,
        security: *const c_void,
        flags: u32,
        provider: u32,
        parameters: *const CreateParameters,
        overlapped: *const c_void,
        handle: *mut Handle,
    ) -> u32;
    fn AttachVirtualDisk(
        handle: Handle,
        security: *const c_void,
        flags: u32,
        provider: u32,
        parameters: *const AttachParameters,
        overlapped: *const c_void,
    ) -> u32;
    fn DetachVirtualDisk(handle: Handle, flags: u32, provider: u32) -> u32;
    fn GetVirtualDiskPhysicalPath(handle: Handle, bytes: *mut u32, path: *mut u16) -> u32;
}
#[link(name = "rpcrt4")]
unsafe extern "system" {
    fn UuidCreate(id: *mut Guid) -> u32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn GetLastError() -> u32;
    fn CloseHandle(handle: Handle) -> i32;
    fn CreateFileW(
        path: *const u16,
        access: u32,
        share: u32,
        security: *const c_void,
        disposition: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    fn DeviceIoControl(
        handle: Handle,
        code: u32,
        input: *const c_void,
        input_size: u32,
        output: *mut c_void,
        output_size: u32,
        returned: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
    fn FindFirstVolumeW(name: *mut u16, length: u32) -> Handle;
    fn FindNextVolumeW(search: Handle, name: *mut u16, length: u32) -> i32;
    fn FindVolumeClose(search: Handle) -> i32;
    fn SetVolumeMountPointW(directory: *const u16, volume: *const u16) -> i32;
    fn DeleteVolumeMountPointW(directory: *const u16) -> i32;
    fn GetLogicalDrives() -> u32;
    fn GetVolumeNameForVolumeMountPointW(mount: *const u16, volume: *mut u16, length: u32) -> i32;
    fn GetDiskFreeSpaceExW(
        path: *const u16,
        available: *mut u64,
        total: *mut u64,
        free: *mut u64,
    ) -> i32;
    fn GetVolumeInformationW(
        root: *const u16,
        volume_name: *mut u16,
        volume_length: u32,
        serial: *mut u32,
        component_length: *mut u32,
        flags: *mut u32,
        filesystem: *mut u16,
        filesystem_length: u32,
    ) -> i32;
}
struct Owned(Handle);
impl Drop for Owned {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
fn status(code: u32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}
fn boolean(value: i32) -> io::Result<()> {
    if value != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
fn wide(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut value: Vec<_> = value.encode_wide().collect();
    if value.contains(&0) {
        return Err(io::Error::other("embedded NUL in trace path"));
    }
    value.push(0);
    Ok(value)
}
fn terminated_path(path: &Path) -> io::Result<Vec<u16>> {
    let mut value = wide(path.as_os_str())?;
    value.pop();
    if value.last() != Some(&u16::from(b'\\')) {
        value.push(u16::from(b'\\'));
    }
    value.push(0);
    Ok(value)
}
fn guid() -> io::Result<Guid> {
    let mut id = Guid::default();
    let result = unsafe { UuidCreate(&raw mut id) };
    if result != 0 && result != 1824 {
        status(result)?;
    }
    Ok(id)
}
fn name(id: Guid) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        id.a, id.b, id.c, id.d[0], id.d[1], id.d[2], id.d[3], id.d[4], id.d[5], id.d[6], id.d[7]
    )
}
fn storage() -> Storage {
    Storage {
        device: 2,
        vendor: Guid {
            a: 0xec984aec,
            b: 0xa0f9,
            c: 0x47e9,
            d: [0x90, 0x1f, 0x71, 0x41, 0x5a, 0x66, 0x34, 0x5b],
        },
    }
}
fn open(path: &OsStr, access: u32) -> io::Result<Owned> {
    let raw = unsafe {
        CreateFileW(
            wide(path)?.as_ptr(),
            access,
            7,
            std::ptr::null(),
            3,
            0,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID {
        Err(io::Error::last_os_error())
    } else {
        Ok(Owned(raw))
    }
}
fn control<I, O>(
    handle: Handle,
    code: u32,
    input: Option<&I>,
    output: Option<&mut O>,
) -> io::Result<()> {
    let (input, input_size) = input.map_or((std::ptr::null(), 0), |value| {
        ((value as *const I).cast(), size_of::<I>() as u32)
    });
    let (output, output_size) = output.map_or((std::ptr::null_mut(), 0), |value| {
        ((value as *mut O).cast(), size_of::<O>() as u32)
    });
    let mut returned = 0;
    boolean(unsafe {
        DeviceIoControl(
            handle,
            code,
            input,
            input_size,
            output,
            output_size,
            &raw mut returned,
            std::ptr::null_mut(),
        )
    })?;
    if returned < output_size {
        return Err(io::Error::other("truncated owned-volume control response"));
    }
    Ok(())
}
fn physical(handle: Handle) -> io::Result<(Owned, u32)> {
    let mut path = vec![0_u16; 32768];
    let mut bytes = (path.len() * size_of::<u16>()) as u32;
    status(unsafe { GetVirtualDiskPhysicalPath(handle, &raw mut bytes, path.as_mut_ptr()) })?;
    let end = path
        .iter()
        .position(|value| *value == 0)
        .ok_or_else(|| io::Error::other("unterminated VHD device path"))?;
    let disk = open(&OsString::from_wide(&path[..end]), 0xc0000000)?;
    let mut number = DeviceNumber::default();
    control::<(), _>(disk.0, 2953344, None, Some(&mut number))?;
    let mut length = 0_i64;
    control::<(), _>(disk.0, 475228, None, Some(&mut length))?;
    if length != CAPACITY as i64 {
        return Err(io::Error::other("owned VHD physical capacity mismatch"));
    }
    if number.kind != 7 || !matches!(number.partition, 0 | u32::MAX) {
        return Err(io::Error::other("VHD handle did not identify a whole disk"));
    }
    Ok((disk, number.number))
}
fn enable_volume_privilege() -> io::Result<()> {
    let mut token = std::ptr::null_mut();
    boolean(unsafe { OpenProcessToken(GetCurrentProcess(), 0x28, &raw mut token) })?;
    let token = Owned(token);
    let mut privilege = Privilege {
        count: 1,
        attributes: 2,
        ..Default::default()
    };
    boolean(unsafe {
        LookupPrivilegeValueW(
            std::ptr::null(),
            wide(OsStr::new("SeManageVolumePrivilege"))?.as_ptr(),
            &raw mut privilege.luid,
        )
    })?;
    boolean(unsafe {
        AdjustTokenPrivileges(
            token.0,
            0,
            &privilege,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    })?;
    // A successful API return can still mean the token lacks this privilege.
    status(unsafe { GetLastError() })
}
struct Search(Handle);
impl Drop for Search {
    fn drop(&mut self) {
        unsafe {
            FindVolumeClose(self.0);
        }
    }
}
fn volume_name(disk: u32) -> io::Result<OsString> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let mut buffer = vec![0_u16; 32768];
        let raw = unsafe { FindFirstVolumeW(buffer.as_mut_ptr(), buffer.len() as u32) };
        if raw == INVALID {
            return Err(io::Error::last_os_error());
        }
        let search = Search(raw);
        loop {
            let end = buffer
                .iter()
                .position(|value| *value == 0)
                .ok_or_else(|| io::Error::other("unterminated volume name"))?;
            let name = OsString::from_wide(&buffer[..end]);
            let opened_name = OsString::from_wide(
                buffer[..end]
                    .strip_suffix(&[u16::from(b'\\')])
                    .unwrap_or(&buffer[..end]),
            );
            if let Ok(handle) = open(&opened_name, 0) {
                let mut extents = Extents::default();
                if control::<(), _>(handle.0, 5636096, None, Some(&mut extents)).is_ok()
                    && extents.count == 1
                    && extents.disk.number == disk
                    && extents.disk.start == OFFSET
                    && extents.disk.length == LENGTH
                {
                    return Ok(name);
                }
            }
            if unsafe { FindNextVolumeW(search.0, buffer.as_mut_ptr(), buffer.len() as u32) } == 0 {
                break;
            }
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "owned VHD volume discovery deadline",
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub struct Volume {
    disk: Option<Owned>,
    base: PathBuf,
    directory: PathBuf,
    mounted: bool,
    attached: bool,
    format_drive: Option<OsString>,
}
impl Volume {
    pub fn create(
        base: &Path,
        format: &Path,
        invoke: impl FnMut(&mut Command) -> io::Result<()>,
    ) -> io::Result<Self> {
        enable_volume_privilege()?;
        fs::create_dir_all(base)?;
        let base = base.join(name(guid()?));
        fs::create_dir(&base)?;
        provision(&base, format, invoke)
    }
    fn mount(&mut self) -> io::Result<OsString> {
        let (disk, number) = physical(self.disk.as_ref().expect("owned VHD").0)?;
        drop(disk);
        let volume = volume_name(number)?;
        fs::create_dir(&self.directory)?;
        boolean(unsafe {
            SetVolumeMountPointW(
                terminated_path(&self.directory)?.as_ptr(),
                wide(&volume)?.as_ptr(),
            )
        })?;
        self.mounted = true;
        Ok(volume)
    }
    pub fn directory(&self) -> &Path {
        &self.directory
    }
    pub fn verify_write_read(&self) -> io::Result<()> {
        let mut filesystem = [0_u16; 32];
        boolean(unsafe {
            GetVolumeInformationW(
                terminated_path(&self.directory)?.as_ptr(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                filesystem.as_mut_ptr(),
                filesystem.len() as u32,
            )
        })?;
        let expected = wide(OsStr::new("NTFS"))?;
        if !filesystem.starts_with(&expected) {
            return Err(io::Error::other("owned trace volume is not NTFS"));
        }
        let path = self.directory.join("volume-qualification.bin");
        let expected = b"memcordon-owned-volume\n";
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(expected)?;
        file.sync_all()?;
        drop(file);
        let mut observed = Vec::new();
        fs::File::open(&path)?
            .take((expected.len() + 1) as u64)
            .read_to_end(&mut observed)?;
        if observed != expected {
            return Err(io::Error::other("owned trace volume write/read mismatch"));
        }
        fs::remove_file(path)
    }
    fn verify_drive(&self, root: &OsStr) -> io::Result<()> {
        let mut buffer = vec![0_u16; 32768];
        boolean(unsafe {
            GetVolumeNameForVolumeMountPointW(
                wide(root)?.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
            )
        })?;
        let end = buffer
            .iter()
            .position(|unit| *unit == 0)
            .ok_or_else(|| io::Error::other("unterminated formatter drive mapping"))?;
        let name = buffer[..end]
            .strip_suffix(&[u16::from(b'\\')])
            .ok_or_else(|| io::Error::other("invalid formatter drive volume name"))?;
        let mapped = open(&OsString::from_wide(name), 0)?;
        let mut extents = Extents::default();
        control::<(), _>(mapped.0, 5636096, None, Some(&mut extents))?;
        let (_disk, number) = physical(self.disk.as_ref().expect("owned VHD").0)?;
        if extents.count != 1
            || extents.disk.number != number
            || extents.disk.start != OFFSET
            || extents.disk.length != LENGTH
        {
            return Err(io::Error::other(
                "formatter drive no longer maps to the owned VHD extent",
            ));
        }
        Ok(())
    }
    fn assign_format_drive(&mut self, volume: &OsStr) -> io::Result<OsString> {
        let assigned = unsafe { GetLogicalDrives() };
        if assigned == 0 {
            return Err(io::Error::last_os_error());
        }
        for letter in (b'D'..=b'Z').rev() {
            if assigned & (1_u32 << (letter - b'A')) != 0 {
                continue;
            }
            let operand = OsString::from_wide(&[u16::from(letter), u16::from(b':')]);
            let root = OsString::from_wide(&[u16::from(letter), u16::from(b':'), u16::from(b'\\')]);
            // SetVolumeMountPoint refuses an occupied assignment. Never remove an
            // existing mapping to make this succeed, including after a race.
            boolean(unsafe {
                SetVolumeMountPointW(wide(&root)?.as_ptr(), wide(volume)?.as_ptr())
            })?;
            self.format_drive = Some(root.clone());
            self.verify_drive(&root)?;
            return Ok(operand);
        }
        Err(io::Error::other(
            "no unassigned formatter drive letter available",
        ))
    }
    fn release_format_drive(&mut self) -> io::Result<()> {
        if let Some(root) = &self.format_drive {
            self.verify_drive(root)?;
            boolean(unsafe { DeleteVolumeMountPointW(wide(root)?.as_ptr()) })?;
            self.format_drive = None;
        }
        Ok(())
    }
    fn release(&mut self, remove: bool) -> io::Result<()> {
        self.release_format_drive()?;
        if self.mounted {
            boolean(unsafe {
                DeleteVolumeMountPointW(terminated_path(&self.directory)?.as_ptr())
            })?;
            self.mounted = false;
        }
        if self.attached {
            status(unsafe { DetachVirtualDisk(self.disk.as_ref().expect("owned VHD").0, 0, 0) })?;
            self.attached = false;
        }
        self.disk.take();
        if self.directory.exists() {
            fs::remove_dir(&self.directory)?;
        }
        if remove {
            fs::remove_file(self.base.join("trace.vhd"))?;
            fs::remove_dir(&self.base)?;
        }
        Ok(())
    }
    pub fn close(mut self) -> io::Result<()> {
        self.release(true)
    }
}
impl Drop for Volume {
    fn drop(&mut self) {
        let _ = self.release(false);
    }
}

/// Called only by the contained, deadline-limited provisioning subprocess.
fn provision(
    base: &Path,
    format: &Path,
    mut invoke: impl FnMut(&mut Command) -> io::Result<()>,
) -> io::Result<Volume> {
    let mut handle = std::ptr::null_mut();
    let parameters = CreateParameters {
        version: 1,
        parameters: CreateVersionOne {
            id: guid()?,
            maximum: CAPACITY,
            block: 0,
            sector: 512,
            parent: std::ptr::null(),
            source: std::ptr::null(),
        },
    };
    status(unsafe {
        CreateVirtualDisk(
            &storage(),
            wide(base.join("trace.vhd").as_os_str())?.as_ptr(),
            4128768,
            std::ptr::null(),
            0,
            0,
            &parameters,
            std::ptr::null(),
            &raw mut handle,
        )
    })?;
    let mut volume = Volume {
        disk: Some(Owned(handle)),
        base: base.into(),
        directory: base.join("mount"),
        mounted: false,
        attached: false,
        format_drive: None,
    };
    let initialized = (|| {
        status(unsafe {
            AttachVirtualDisk(
                handle,
                std::ptr::null(),
                2,
                0,
                &AttachParameters {
                    version: 1,
                    parameters: [0; 2],
                },
                std::ptr::null(),
            )
        })?;
        volume.attached = true;
        let (disk, _) = physical(handle)?;
        let id = guid()?;
        control::<_, ()>(
            disk.0,
            507992,
            Some(&CreateDisk {
                style: 1,
                id,
                partitions: 128,
            }),
            None,
        )?;
        let layout = Layout {
            style: 1,
            count: 1,
            id,
            start: OFFSET,
            length: LENGTH,
            max: 128,
            partition: Partition {
                style: 1,
                start: OFFSET,
                length: LENGTH,
                number: 1,
                rewrite: true,
                service: false,
                kind: Guid {
                    a: 0xebd0a0a2,
                    b: 0xb9e5,
                    c: 0x4433,
                    d: [0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7],
                },
                id: guid()?,
                attributes: 0,
                name: [0; 36],
            },
        };
        control::<_, ()>(disk.0, 507988, Some(&layout), None)?;
        control::<(), ()>(disk.0, 459072, None, None)?;
        drop(disk);
        let native_volume = volume.mount()?;
        // The formatter's documented drive operand is backed by a newly assigned
        // mount whose actual extent is rechecked, never a guessed existing drive.
        let format_target = volume.assign_format_drive(&native_volume)?;
        let mut command = Command::new(format);
        command
            .args(super::super::formatter_arguments(&format_target)?)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        invoke(&mut command).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "formatter stage failed for verified owned trace volume: executable={format:?}; target={:?}; arguments={:?}; {error}",
                    format_target,
                    command.get_args().collect::<Vec<_>>()
                ),
            )
        })?;
        volume.release_format_drive()?;
        let mut available = 0;
        let mut total = 0;
        let mut free = 0;
        boolean(unsafe {
            GetDiskFreeSpaceExW(
                terminated_path(&volume.directory)?.as_ptr(),
                &raw mut available,
                &raw mut total,
                &raw mut free,
            )
        })?;
        if total > CAPACITY || available < 96 * 1024 * 1024 {
            return Err(io::Error::other(
                "owned trace filesystem capacity/free-space mismatch",
            ));
        }
        Ok::<_, io::Error>(())
    })();
    match initialized {
        Ok(()) => Ok(volume),
        Err(error) => {
            let cleanup = volume.release(true);
            Err(io::Error::new(
                error.kind(),
                format!(
                    "trace volume provisioning failed: {error}; owned_base={base:?}; cleanup={cleanup:?}"
                ),
            ))
        }
    }
}
