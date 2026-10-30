//! Live native process identity held by component tests.
pub struct HeldNativeProcess {
    handle: std::os::windows::io::OwnedHandle,
    pub identity: memcordon_core::WindowsProcessIdentityV1,
}
impl HeldNativeProcess {
    pub fn raw(&self) -> windows_sys::Win32::Foundation::HANDLE {
        use std::os::windows::io::AsRawHandle;
        self.handle.as_raw_handle()
    }
    pub fn open(process_id: u32) -> Self {
        use std::os::windows::io::{AsRawHandle, FromRawHandle};
        use windows_sys::Win32::System::Threading::{
            GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        // SAFETY: OpenProcess receives a PID observed from an owned live Job or
        // Child; the returned handle is immediately owned and retained.
        let raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | 0x0010_0000,
                0,
                process_id,
            )
        };
        assert!(
            !raw.is_null(),
            "native component process identity could not be held"
        );
        let handle = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw) };
        let mut created = windows_sys::Win32::Foundation::FILETIME::default();
        let mut exited = windows_sys::Win32::Foundation::FILETIME::default();
        let mut kernel = windows_sys::Win32::Foundation::FILETIME::default();
        let mut user = windows_sys::Win32::Foundation::FILETIME::default();
        // SAFETY: retained handle and four initialized writable output buffers.
        assert_ne!(
            unsafe {
                GetProcessTimes(
                    handle.as_raw_handle(),
                    &mut created,
                    &mut exited,
                    &mut kernel,
                    &mut user,
                )
            },
            0
        );
        Self {
            handle,
            identity: memcordon_core::WindowsProcessIdentityV1 {
                process_id,
                creation_time_100ns: (u64::from(created.dwHighDateTime) << 32)
                    | u64::from(created.dwLowDateTime),
            },
        }
    }
    pub fn exited(&self) -> bool {
        use std::os::windows::io::AsRawHandle;
        // SAFETY: this object retains ownership of the queried native handle.
        let status = unsafe {
            windows_sys::Win32::System::Threading::WaitForSingleObject(
                self.handle.as_raw_handle(),
                0,
            )
        };
        assert!(
            status == windows_sys::Win32::Foundation::WAIT_OBJECT_0
                || status == windows_sys::Win32::Foundation::WAIT_TIMEOUT
        );
        status == windows_sys::Win32::Foundation::WAIT_OBJECT_0
    }
}
