//! Native CI only: every endpoint is an ordinary test-owned pipe or socket.
use crate::linux::{descriptor_custody::provider_owned_byte_pipes, private_relay::PrivateRelay};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};

fn pair() -> (UnixStream, UnixStream) {
    let (first, second) = UnixStream::pair().unwrap();
    first.set_nonblocking(true).unwrap();
    second.set_nonblocking(true).unwrap();
    (first, second)
}
fn nonblocking(file: &File) {
    let flags = rustix::fs::fcntl_getfl(file).unwrap();
    rustix::fs::fcntl_setfl(file, flags | rustix::fs::OFlags::NONBLOCK).unwrap();
}
fn read_some(source: &mut impl Read, bytes: &mut Vec<u8>) -> bool {
    let mut buffer = [0; 1024];
    match source.read(&mut buffer) {
        Ok(0) => true,
        Ok(count) => {
            bytes.extend_from_slice(&buffer[..count]);
            false
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
        Err(error) => panic!("owned relay read failed: {error}"),
    }
}

#[test]
fn closed_input_discards_only_input_and_keeps_both_outputs_live() {
    let (target, provider) = provider_owned_byte_pipes().unwrap();
    let mut stdout = File::from(target.stdout_fd().try_clone_to_owned().unwrap());
    let mut stderr = File::from(target.stderr_fd().try_clone_to_owned().unwrap());
    let (mut input, input_relay) = pair();
    let (output_relay, mut output) = pair();
    let (error_relay, mut error) = pair();
    let mut relay = PrivateRelay::prepare(
        provider,
        [input_relay.into(), output_relay.into(), error_relay.into()],
    )
    .unwrap();
    input.write_all(b"ignored finite input").unwrap();
    drop(target); // Only the original stdin reader closes; output writers remain owned.
    relay.tick(Duration::ZERO).unwrap();
    assert!(
        !relay.completed(),
        "stdin closure is not target/output completion"
    );
    assert!(
        input.write(b"undeliverable").is_err(),
        "input source must retire too"
    );
    stdout.write_all(b"stdout\0\xff").unwrap();
    stderr.write_all(b"stderr\xff\0").unwrap();
    drop(stdout);
    drop(stderr);
    let cutoff = Instant::now() + Duration::from_secs(5);
    let mut out = Vec::new();
    let mut err = Vec::new();
    while !relay.completed() {
        assert!(
            Instant::now() < cutoff,
            "original relay drain cutoff exhausted"
        );
        relay.tick(Duration::ZERO).unwrap();
        read_some(&mut output, &mut out);
        read_some(&mut error, &mut err);
    }
    while !read_some(&mut output, &mut out) {
        assert!(Instant::now() < cutoff);
    }
    while !read_some(&mut error, &mut err) {
        assert!(Instant::now() < cutoff);
    }
    assert_eq!(out, b"stdout\0\xff");
    assert_eq!(err, b"stderr\xff\0");
}

#[test]
fn broken_output_is_still_a_fatal_directional_error() {
    for stderr_lane in [false, true] {
        let (target, provider) = provider_owned_byte_pipes().unwrap();
        let mut writer = File::from(
            if stderr_lane {
                target.stderr_fd()
            } else {
                target.stdout_fd()
            }
            .try_clone_to_owned()
            .unwrap(),
        );
        let (input, input_relay) = pair();
        let (output_relay, output) = pair();
        let (error_relay, error) = pair();
        let mut relay = PrivateRelay::prepare(
            provider,
            [input_relay.into(), output_relay.into(), error_relay.into()],
        )
        .unwrap();
        drop(input);
        if stderr_lane {
            drop(error);
        } else {
            drop(output);
        }
        writer.write_all(b"must not be discarded").unwrap();
        let error = relay.tick(Duration::ZERO).unwrap_err();
        assert!(
            error.contains(if stderr_lane {
                "lane=stderr"
            } else {
                "lane=stdout"
            }),
            "{error}"
        );
        assert!(error.contains("operation=write"), "{error}");
    }
}

#[test]
fn finite_eof_and_backpressured_output_preserve_independent_exact_bytes() {
    let (target, provider) = provider_owned_byte_pipes().unwrap();
    let mut target_input = File::from(target.stdin_fd().try_clone_to_owned().unwrap());
    nonblocking(&target_input);
    let mut stdout = Some(File::from(target.stdout_fd().try_clone_to_owned().unwrap()));
    nonblocking(stdout.as_ref().unwrap());
    let mut stderr = Some(File::from(target.stderr_fd().try_clone_to_owned().unwrap()));
    nonblocking(stderr.as_ref().unwrap());
    let (mut input, input_relay) = pair();
    let (output_relay, mut output) = pair();
    let (error_relay, mut error) = pair();
    let mut relay = PrivateRelay::prepare(
        provider,
        [input_relay.into(), output_relay.into(), error_relay.into()],
    )
    .unwrap();
    drop(target);
    let expected_input = vec![b'R'; 16384];
    input.write_all(&expected_input).unwrap();
    drop(input);
    let expected_out: Vec<_> = (0..65536).map(|index| (index % 256) as u8).collect();
    let expected_err: Vec<_> = (0..32768).map(|index| (255 - index % 256) as u8).collect();
    let mut out_offset = 0;
    let mut err_offset = 0;
    let mut received_input = Vec::new();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let cutoff = Instant::now() + Duration::from_secs(5);
    while !relay.completed() {
        assert!(
            Instant::now() < cutoff,
            "original bounded relay iteration cutoff exhausted"
        );
        for (writer, bytes, offset) in [
            (&mut stdout, &expected_out, &mut out_offset),
            (&mut stderr, &expected_err, &mut err_offset),
        ] {
            if let Some(file) = writer.as_mut() {
                match file.write(&bytes[*offset..]) {
                    Ok(count) => *offset += count,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
                    Err(error) => panic!("owned output writer failed: {error}"),
                }
                if *offset == bytes.len() {
                    writer.take();
                }
            }
        }
        relay.tick(Duration::ZERO).unwrap();
        read_some(&mut target_input, &mut received_input);
        read_some(&mut output, &mut out);
        read_some(&mut error, &mut err);
    }
    while !read_some(&mut target_input, &mut received_input) {
        assert!(Instant::now() < cutoff);
    }
    while !read_some(&mut output, &mut out) {
        assert!(Instant::now() < cutoff);
    }
    while !read_some(&mut error, &mut err) {
        assert!(Instant::now() < cutoff);
    }
    assert_eq!(received_input, expected_input);
    assert_eq!(out, expected_out);
    assert_eq!(err, expected_err);
}
