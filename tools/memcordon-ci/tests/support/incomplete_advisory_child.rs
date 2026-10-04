use std::io::{self, Write};

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("rejected") => {
            io::stderr()
                .write_all(b"memcordon: failed to fill whole buffer\n")
                .unwrap();
            std::process::exit(125);
        }
        Some("success") => {}
        Some("plan-on-error") => {
            io::stdout()
                .write_all(b"{\"format\":\"memcordon.plan\",\"authorizes_launch\":false}\n")
                .unwrap();
            io::stderr().write_all(b"memcordon: rejected\n").unwrap();
            std::process::exit(125);
        }
        Some("no-diagnostic") => std::process::exit(125),
        Some("launcher-error") => {
            io::stderr()
                .write_all(b"setpriv: failed to execute CLI\n")
                .unwrap();
            std::process::exit(125);
        }
        Some("empty-cli-error") => {
            io::stderr().write_all(b"memcordon: \n").unwrap();
            std::process::exit(125);
        }
        _ => panic!("unknown bounded advisory fixture mode"),
    }
}
