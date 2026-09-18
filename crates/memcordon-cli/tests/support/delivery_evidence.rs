use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::Command;

pub struct Evidence {
    reader: UnixStream,
    writer: UnixStream,
}

impl Evidence {
    pub fn attach(command: &mut Command) -> Self {
        let (reader, writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        writer.set_nonblocking(true).unwrap();
        let descriptor = memcordon_platform::test_support::inherit_test_descriptor(
            command,
            writer.try_clone().unwrap().into(),
        )
        .unwrap();
        command.args(["__delivery-observed-v1", &descriptor.to_string()]);
        Self { reader, writer }
    }

    #[allow(dead_code)]
    pub fn fill(&mut self) {
        let bytes = [b'x'; 4096];
        loop {
            match self.writer.write(&bytes) {
                Ok(0) => panic!("evidence channel unexpectedly closed"),
                Ok(_) => (),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("filling evidence channel: {error}"),
            }
        }
    }

    pub fn finish(self) -> String {
        drop(self.writer);
        let mut bytes = Vec::new();
        // Read at most one tiny event; failures and full channels cannot block.
        let result = self.reader.take(1024).read_to_end(&mut bytes);
        if let Err(error) = result {
            assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        }
        String::from_utf8(bytes).expect("typed evidence is UTF-8")
    }
}
