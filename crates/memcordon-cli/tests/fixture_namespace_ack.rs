#[path = "private/fixture_namespace_ack.rs"]
mod acknowledgement;
use std::{
    cell::Cell,
    io::{self, BufReader, Read},
    rc::Rc,
};

struct Pipe {
    bytes: Vec<u8>,
    at: usize,
    fragment: usize,
    remaining: Rc<Cell<usize>>,
}
impl Read for Pipe {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let length = out.len().min(self.fragment).min(self.bytes.len() - self.at);
        out[..length].copy_from_slice(&self.bytes[self.at..self.at + length]);
        self.at += length;
        self.remaining.set(self.bytes.len() - self.at);
        Ok(length)
    }
}
fn pipe(bytes: &[u8], fragment: usize) -> (BufReader<Pipe>, Rc<Cell<usize>>) {
    let remaining = Rc::new(Cell::new(bytes.len()));
    (
        BufReader::with_capacity(
            8192,
            Pipe {
                bytes: bytes.to_vec(),
                at: 0,
                fragment,
                remaining: remaining.clone(),
            },
        ),
        remaining,
    )
}

#[test]
fn complete_ack_prefetch_does_not_wait_for_a_second_kernel_ready_event() {
    let expected = b"canonical-diagnostic-release-ack\n";
    let (mut input, remaining) = pipe(expected, expected.len());
    let mut polls = 0;
    acknowledgement::read_ack(
        &mut input,
        expected,
        || {
            polls += 1;
            assert!(
                polls <= 1,
                "prefetched ACK bytes were stranded behind an empty OS pipe"
            );
            Ok(remaining.get() != 0)
        },
        || Ok(()),
    )
    .unwrap();
    assert_eq!(remaining.get(), 0);
    assert_eq!(polls, 1);
}

#[test]
fn partial_fragments_preserve_exact_ack_nonce_and_bounded_length() {
    let expected = b"nonce-7\n";
    for fragment in 1..=expected.len() {
        let (mut input, remaining) = pipe(expected, fragment);
        acknowledgement::read_ack(&mut input, expected, || Ok(remaining.get() != 0), || Ok(()))
            .unwrap();
    }
    for bytes in [b"nonce-8\n".to_vec(), vec![b'x'; 129]] {
        let (mut input, remaining) = pipe(&bytes, bytes.len());
        assert!(
            acknowledgement::read_ack(&mut input, expected, || Ok(remaining.get() != 0), || Ok(()))
                .is_err()
        );
    }
}

#[test]
fn missing_newline_rechecks_original_cutoff_instead_of_blocking() {
    let (mut input, remaining) = pipe(b"partial-no-newline", 3);
    let mut checks = 0;
    let error = acknowledgement::read_ack(
        &mut input,
        b"complete\n",
        || Ok(remaining.get() != 0),
        || {
            checks += 1;
            if checks > 20 {
                Err(io::Error::new(io::ErrorKind::TimedOut, "original cutoff"))
            } else {
                Ok(())
            }
        },
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    let (mut input, _) = pipe(b"", 1);
    assert_eq!(
        acknowledgement::read_ack(&mut input, b"complete\n", || Ok(true), || Ok(()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
}
