use std::io;
use std::os::fd::RawFd;
use std::process::{Child, Command};

pub struct Guardian {
    child: Child,
    control: RawFd,
}

impl Guardian {
    pub fn spawn(process_group: i32) -> io::Result<Self> {
        let mut descriptors = [0_i32; 2];
        // SAFETY: `descriptors` points to storage for both pipe descriptors.
        if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // The guardian must not retain its own copy of the write end across exec, otherwise
        // wrapper death would never produce EOF on the read end.
        // SAFETY: both descriptors were returned by `pipe`; this only changes descriptor flags.
        if unsafe { libc::fcntl(descriptors[1], libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            let error = io::Error::last_os_error();
            // SAFETY: spawn has not occurred and both descriptors are uniquely owned here.
            unsafe {
                libc::close(descriptors[0]);
                libc::close(descriptors[1]);
            }
            return Err(error);
        }
        let child = Command::new(std::env::current_exe()?)
            .args([
                "__guardian",
                &descriptors[0].to_string(),
                &process_group.to_string(),
            ])
            .spawn();
        // SAFETY: the read descriptor belongs to the guardian after successful spawn and is
        // unused in the parent; after failure both descriptors must be closed.
        unsafe {
            libc::close(descriptors[0]);
        }
        match child {
            Ok(child) => Ok(Self {
                child,
                control: descriptors[1],
            }),
            Err(error) => {
                // SAFETY: guardian spawn failed, so the parent uniquely owns the write end.
                unsafe {
                    libc::close(descriptors[1]);
                }
                Err(error)
            }
        }
    }

    pub fn disarm(mut self) -> io::Result<()> {
        let marker = 1_u8;
        // SAFETY: `control` is the uniquely owned write end and `marker` is readable for one byte.
        let written = unsafe { libc::write(self.control, (&raw const marker).cast(), 1) };
        // SAFETY: the control descriptor is closed exactly once.
        unsafe {
            libc::close(self.control);
        }
        self.control = -1;
        if written != 1 {
            return Err(io::Error::last_os_error());
        }
        self.child.wait().map(|_| ())
    }
}

impl Drop for Guardian {
    fn drop(&mut self) {
        if self.control >= 0 {
            // Unexpected parent-side drop closes the pipe. The guardian treats EOF as a crash.
            // SAFETY: the descriptor is uniquely owned and not used after this close.
            unsafe {
                libc::close(self.control);
            }
            self.control = -1;
        }
    }
}
