#![forbid(unsafe_code)]

/// Returns the exact libtest name for a test compiled inside a module.
pub fn exact_test_name(test_module: &str, test_name: &str) -> String {
    [test_module, test_name].join("::")
}
