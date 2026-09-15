use memcordon_ci::native_file_digest::{
    parse_digest_output, protected_digest, validate_system_path,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

fn valid_output() -> (String, Vec<u8>) {
    let digest = hex::encode(Sha256::digest(b"bounded native digest fixture"));
    let mut output = digest.as_bytes().to_vec();
    output.push(b'\n');
    (digest, output)
}

#[test]
fn digest_protocol_accepts_only_one_complete_lowercase_sha256_line() {
    let (digest, output) = valid_output();
    assert_eq!(parse_digest_output(&output).unwrap(), digest);

    let mut missing_newline = output.clone();
    missing_newline.pop();
    let mut truncated = digest.as_bytes().to_vec();
    truncated.pop();
    truncated.push(b'\n');
    let mut extra_line = output.clone();
    extra_line.extend_from_slice(b"additional output\n");
    let mut non_hex = output.clone();
    non_hex[0] = b'g';
    let mut non_ascii = output.clone();
    non_ascii[0] = u8::MAX;
    let upper = output
        .iter()
        .map(u8::to_ascii_uppercase)
        .collect::<Vec<_>>();
    for invalid in [
        Vec::new(),
        missing_newline,
        truncated,
        extra_line,
        non_hex,
        non_ascii,
        upper,
        b"sudo: authentication failed\n".to_vec(),
    ] {
        assert!(
            parse_digest_output(&invalid).is_err(),
            "invalid helper output was accepted: {invalid:?}"
        );
    }
}

#[test]
fn digest_authority_rejects_arbitrary_files_and_relative_paths() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("private-data");
    fs::write(&file, b"must not be disclosed by the digest helper\n").unwrap();
    assert!(validate_system_path(&file).is_err());
    assert!(protected_digest(&file).is_err());
    assert!(validate_system_path(Path::new("usr/bin/true")).is_err());
    assert!(validate_system_path(Path::new("/usr/bin/../..")).is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn readable_system_binary_digest_matches_the_bytes() {
    for executable in [
        "/usr/bin/true",
        "/bin/echo",
        "/usr/sbin/sysctl",
        "/sbin/md5",
    ] {
        let path = Path::new(executable);
        let expected = hex::encode(Sha256::digest(fs::read(path).unwrap()));
        assert_eq!(protected_digest(path).unwrap(), expected, "{executable}");
    }
    for root in ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/lib"] {
        assert!(validate_system_path(Path::new(root)).is_err(), "{root}");
    }
    assert!(validate_system_path(Path::new("/usr/lib/cron")).is_err());
}

#[test]
fn helper_output_is_bounded_before_protocol_parsing() {
    use std::process::Command;
    use std::time::Duration;

    let mut command = Command::new(env!("CARGO_BIN_EXE_memcordon-native-input-digest"));
    command.arg("--invalid-argument");
    let error =
        memcordon_testkit::run_with_deadline_output_limit(&mut command, Duration::from_secs(5), 1)
            .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("subprocess output exceeds byte limit"),
        "unexpected bounded-capture error: {error}"
    );
}
