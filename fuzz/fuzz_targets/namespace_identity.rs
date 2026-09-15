#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::sealed_provider::envelope::parse_namespace_identity;

fuzz_target!(|data: &[u8]| {
    if let Ok(identity) = std::str::from_utf8(data)
        && let Ok(inode) = parse_namespace_identity(identity, "pid")
    {
        assert_eq!(
            parse_namespace_identity(&format!("pid:[{inode}]"), "pid"),
            Ok(inode)
        );
        assert!(parse_namespace_identity(identity, "mnt").is_err());
        assert!(parse_namespace_identity(&format!("{identity}trailing"), "pid").is_err());
    }
});
