//! Fixture network handlers; invoked only through the command registry.
use super::*;

pub(super) fn tcp_loopback(mut args: impl Iterator<Item = OsString>) {
    use std::io::{Read, Write};
    let marker = PathBuf::from(take_value(&mut args, "TCP completion marker"));
    if args.next().is_some() {
        fail("tcp-loopback accepts one marker path");
    }
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .unwrap_or_else(|error| fail(error.to_string()));
    let address = listener.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        stream.write_all(&byte).unwrap();
    });
    let mut stream =
        std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"x").unwrap();
    let mut byte = [0];
    stream.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"x");
    worker.join().unwrap();
    fs::write(marker, b"tcp-echo-complete\n").unwrap();
}

pub(super) fn tcp_client(mut args: impl Iterator<Item = OsString>) {
    use std::io::{Read, Write};
    let port: u16 = take_value(&mut args, "TCP peer port")
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let marker = PathBuf::from(take_value(&mut args, "TCP completion marker"));
    if args.next().is_some() {
        fail("tcp-client accepts port and marker");
    }
    let address = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
    let mut stream =
        std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"x").unwrap();
    let mut byte = [0];
    stream.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"x");
    fs::write(marker, b"tcp-echo-complete\n").unwrap();
}

pub(super) fn command_tcp_loopback(args: std::env::ArgsOs) -> i32 {
    {
        tcp_loopback(args);
        0
    }
}

pub(super) fn command_tcp_client(args: std::env::ArgsOs) -> i32 {
    {
        tcp_client(args);
        0
    }
}
