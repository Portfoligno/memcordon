//! Native inventory authority: volume and file identity from an owned descriptor.
use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
};

pub fn windows_file_identity(file: &File) -> io::Result<(u64, [u8; 16])> {
    let mut information = std::mem::MaybeUninit::<FILE_ID_INFO>::uninit();
    // SAFETY: the borrowed File owns a live handle throughout this synchronous
    // call; the output allocation has exactly the required native layout/size.
    let success = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            information.as_mut_ptr().cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful FileIdInfo fills the entire FILE_ID_INFO output.
    let information = unsafe { information.assume_init() };
    Ok((
        information.VolumeSerialNumber,
        information.FileId.Identifier,
    ))
}
