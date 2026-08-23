use std::ffi::OsStr;

#[test]
fn compiled_package_metadata_uses_fixed_root_service_identity() {
    memcordon_sealed_agent::package::run(OsStr::new("verify"), false).unwrap();
}
