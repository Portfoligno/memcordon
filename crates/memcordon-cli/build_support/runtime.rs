//! Target-only selection, independent of the build host.
pub fn static_msvc(target_os: &str, target_env: &str) -> bool {
    target_os == "windows" && target_env == "msvc"
}
