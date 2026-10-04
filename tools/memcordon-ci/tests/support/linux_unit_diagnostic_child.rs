use std::io::{self, Write};

fn main() {
    io::stdout().write_all(b"actual unit status\xff\n").unwrap();
    io::stderr().write_all(b"actual startup rejection\xfe\n").unwrap();
    std::process::exit(3);
}
