//! Real frontend streams for the measured recovery fixture; no drain threads.
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Instant;

const OUTPUT_LIMIT: usize = 16 * 1024 * 1024;

struct Output {
    peer: UnixStream,
    file: File,
    length: usize,
    eof: bool,
}

pub struct Capture {
    outputs: [Output; 2],
    deadline: Instant,
}

impl Capture {
    pub fn acquire(root: &Path, deadline: Instant) -> Result<(Self, [OwnedFd; 3]), String> {
        let (stdin, peer) = UnixStream::pair().map_err(|error| error.to_string())?;
        stdin
            .set_nonblocking(true)
            .map_err(|error| error.to_string())?;
        drop(peer); // Genuine empty frontend input, observed as EOF by the relay.
        let mut endpoints = Vec::new();
        let mut outputs = Vec::new();
        for leaf in ["target-stdout.bin", "target-stderr.bin"] {
            let (endpoint, peer) = UnixStream::pair().map_err(|error| error.to_string())?;
            endpoint
                .set_nonblocking(true)
                .map_err(|error| error.to_string())?;
            peer.set_nonblocking(true)
                .map_err(|error| error.to_string())?;
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(root.join(leaf))
                .map_err(|error| error.to_string())?;
            endpoints.push(OwnedFd::from(endpoint));
            outputs.push(Output {
                peer,
                file,
                length: 0,
                eof: false,
            });
        }
        let stderr = endpoints.pop().expect("two output endpoints");
        let stdout = endpoints.pop().expect("two output endpoints");
        Ok((
            Self {
                outputs: outputs.try_into().ok().expect("two output captures"),
                deadline,
            },
            [stdin.into(), stdout, stderr],
        ))
    }

    pub fn observe(&mut self, finished: bool) -> Result<(), String> {
        loop {
            if Instant::now() >= self.deadline {
                return Err("native frontend capture work deadline elapsed".into());
            }
            for output in &mut self.outputs {
                let mut buffer = [0_u8; 64 * 1024];
                while !output.eof {
                    match output.peer.read(&mut buffer) {
                        Ok(0) => {
                            output.eof = true;
                            output.file.sync_all().map_err(|error| error.to_string())?;
                        }
                        Ok(count) => {
                            output.length = output
                                .length
                                .checked_add(count)
                                .ok_or("native frontend capture size overflow")?;
                            if output.length > OUTPUT_LIMIT {
                                return Err(
                                    "native frontend capture exceeds original output bound".into(),
                                );
                            }
                            output
                                .file
                                .write_all(&buffer[..count])
                                .map_err(|error| error.to_string())?;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(error) => {
                            return Err(format!("native frontend capture failed: {error}"));
                        }
                    }
                    if Instant::now() >= self.deadline {
                        return Err("native frontend capture work deadline elapsed".into());
                    }
                }
            }
            if !finished || self.outputs.iter().all(|output| output.eof) {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}
