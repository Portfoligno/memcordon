//! Dedicated digest authority: no controller, build, or directory-enumeration commands.
use memcordon_ci::native_file_digest;

fn main() {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let result = if arguments.len() == 2 && arguments[0] == "--path" {
        native_file_digest::protected_digest(std::path::Path::new(&arguments[1]))
    } else {
        Err(std::io::Error::other(
            "usage: memcordon-native-input-digest --path PATH",
        ))
    };
    match result {
        Ok(digest) => println!("{digest}"),
        Err(error) => {
            eprintln!("protected system digest: {error}");
            std::process::exit(1);
        }
    }
}
