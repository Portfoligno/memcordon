use std::io::{self, Write};

fn main() {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    assert_eq!(arguments.first().map(String::as_str), Some("package"));
    let (stdout, stderr): (&[u8], &[u8]) = match arguments.get(1).map(String::as_str) {
        Some("install") => (
            b"install stdout\xff\n",
            b"install: protected image rejected\xfe\n",
        ),
        Some("uninstall") => (
            b"uninstall stdout\xfd\n",
            b"uninstall: native service stop failed\xfc\n",
        ),
        _ => panic!("unexpected diagnostic fixture operation"),
    };
    io::stdout().write_all(stdout).unwrap();
    io::stderr().write_all(stderr).unwrap();
    std::process::exit(125);
}
