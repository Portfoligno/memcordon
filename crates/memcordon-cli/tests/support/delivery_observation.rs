//! Bounded test receiver; its records are diagnostic, never result authority.
use std::io;
use std::os::unix::net::UnixDatagram;
use std::process::Command;

pub struct Observer {
    directory: tempfile::TempDir,
    socket: UnixDatagram,
}

impl Observer {
    pub fn new() -> Self {
        // Darwin sockaddr_un has a small path capacity. Keep the private socket
        // beneath /tmp rather than the potentially long test output directory.
        let directory = tempfile::Builder::new()
            .prefix("mc-delivery-")
            .tempdir_in("/tmp")
            .expect("private observation directory");
        let socket = UnixDatagram::bind(directory.path().join("d"))
            .expect("bind observation datagram receiver");
        socket.set_nonblocking(true).expect("nonblocking receiver");
        Self { directory, socket }
    }

    pub fn prefix(&self, command: &mut Command) {
        command
            .arg("__observe-delivery-v1")
            .arg(self.directory.path().join("d"))
            .arg("--");
    }

    pub fn collect(&self) -> Result<Vec<serde_json::Value>, String> {
        let mut records = Vec::new();
        // The frontend emits execution + delivery. A bounded allowance makes
        // unexpected duplicate emission visible without unbounded collection.
        for _ in 0..4 {
            let mut bytes = [0_u8; 2049];
            match self.socket.recv(&mut bytes) {
                Ok(length) if length <= 2048 => {
                    let value: serde_json::Value = serde_json::from_slice(&bytes[..length])
                        .map_err(|error| {
                            format!("invalid observation: {error}; prior={records:?}")
                        })?;
                    if value["schema"] != 1 {
                        return Err(format!(
                            "unsupported observation: {value:?}; prior={records:?}"
                        ));
                    }
                    records.push(value);
                }
                Ok(_) => return Err(format!("oversized observation; prior={records:?}")),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(records),
                Err(error) => {
                    return Err(format!("observation receive: {error}; prior={records:?}"));
                }
            }
        }
        Err(format!("too many observations: {records:?}"))
    }
}

impl AsRef<UnixDatagram> for Observer {
    fn as_ref(&self) -> &UnixDatagram {
        &self.socket
    }
}
