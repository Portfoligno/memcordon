#![cfg(all(target_os = "linux", feature = "test-support"))]

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};

use crate::linux::launcher::{
    receive_authentication_response_for_test, set_receive_credentials_for_test,
    socket_peer_pid_for_test, write_authentication_response_for_test,
};
use crate::protocol::{Frame, MessageKind};

fn authentication_request() -> Frame {
    Frame {
        kind: MessageKind::BrokerAuthenticate,
        nonce: [0x31; 16],
        attempt_id: [0x72; 16],
        payload: Vec::new(),
    }
}

fn authentication_response(request: &Frame) -> Frame {
    Frame {
        kind: MessageKind::BrokerAuthenticated,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: Vec::new(),
    }
}

#[test]
fn activation_authentication_identifies_the_accepted_stream_worker() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("launcher.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let mut client = UnixStream::connect(&socket).unwrap();
    let (server, _) = listener.accept().unwrap();
    let listener_owner = socket_peer_pid_for_test(&client).unwrap();
    // SAFETY: getpid only reads the identity of this synchronous test process.
    assert_eq!(listener_owner, unsafe { libc::getpid() });
    set_receive_credentials_for_test(&client, true).unwrap();

    let request = authentication_request();
    let response = authentication_response(&request);
    // SAFETY: the child performs one bounded response/ack exchange and exits without unwinding.
    let worker = unsafe { libc::fork() };
    assert!(worker >= 0);
    if worker == 0 {
        drop(client);
        drop(listener);
        let mut server = server;
        let success = write_authentication_response_for_test(&server, &response).is_ok()
            && server.read_exact(&mut [0_u8; 1]).is_ok();
        // SAFETY: the forked worker must not unwind through inherited test-harness state.
        unsafe { libc::_exit(i32::from(!success)) };
    }

    drop(server);
    let responder = receive_authentication_response_for_test(&client, &request).unwrap();
    assert_eq!(responder, worker);
    assert_ne!(responder, listener_owner);
    client.write_all(&[1]).unwrap();
    let mut status = 0;
    // SAFETY: `worker` is this process's unreaped child.
    assert_eq!(unsafe { libc::waitpid(worker, &raw mut status, 0) }, worker);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
}

#[test]
fn launcher_authentication_requires_kernel_credentials() {
    let (receiver, sender) = UnixStream::pair().unwrap();
    let request = authentication_request();
    write_authentication_response_for_test(&sender, &authentication_response(&request)).unwrap();
    let error = receive_authentication_response_for_test(&receiver, &request).unwrap_err();
    assert!(error.contains("authenticated credentials missing"));
}

#[test]
fn launcher_authentication_response_is_bound_to_the_exchange() {
    let (receiver, sender) = UnixStream::pair().unwrap();
    set_receive_credentials_for_test(&receiver, true).unwrap();
    let request = authentication_request();
    let mut response = authentication_response(&request);
    response.nonce[0] ^= 1;
    write_authentication_response_for_test(&sender, &response).unwrap();
    let error = receive_authentication_response_for_test(&receiver, &request).unwrap_err();
    assert!(error.contains("invalid authentication response"));
}
