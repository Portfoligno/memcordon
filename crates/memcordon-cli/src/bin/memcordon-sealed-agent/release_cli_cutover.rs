//! Reject unsupported command families and package forms before argument dispatch.

use std::ffi::OsString;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReleasePlatform {
    Linux,
    Windows,
    Other,
}

impl ReleasePlatform {
    pub(crate) fn current() -> Self {
        #[cfg(target_os = "linux")]
        {
            Self::Linux
        }
        #[cfg(target_os = "windows")]
        {
            Self::Windows
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            Self::Other
        }
    }
}

fn windows_product_package_command(arguments: &[OsString]) -> bool {
    let fixed = |index: usize, value: &str| {
        arguments.get(index).and_then(|argument| argument.to_str()) == Some(value)
    };
    let product_operation = |index: usize| {
        ["install", "upgrade", "uninstall"]
            .into_iter()
            .any(|operation| fixed(index, operation))
    };
    match arguments.len() {
        2 => fixed(1, "inspect") || fixed(1, "verify") || product_operation(1),
        3 => fixed(2, "--json") && (fixed(1, "inspect") || fixed(1, "verify")),
        4 => fixed(1, "policy") && fixed(2, "inspect") && fixed(3, "--json"),
        5 => fixed(1, "policy") && fixed(2, "apply") && fixed(3, "--file"),
        _ => false,
    }
}

fn linux_entrypoint_install_command(arguments: &[OsString]) -> bool {
    matches!(
        arguments,
        [package, policy, entrypoint, operation, definition, _, source, _]
            if package == "package"
                && policy == "policy"
                && entrypoint == "entrypoint"
                && operation == "install"
                && definition == "--definition"
                && source == "--source"
    )
}

fn linux_runtime_image_install_command(arguments: &[OsString]) -> bool {
    matches!(arguments,
        [package, policy, image, operation, definition, _, source_root, _, json]
            if package == "package" && policy == "policy" && image == "image"
                && operation == "install" && definition == "--definition"
                && source_root == "--source-root" && json == "--json")
}

fn linux_runtime_image_retire_command(arguments: &[OsString]) -> bool {
    matches!(arguments,
        [package, policy, image, operation, definition, _, json]
            if package == "package" && policy == "policy" && image == "image"
                && operation == "retire" && definition == "--definition"
                && json == "--json")
}

pub(crate) fn retired_release_command(platform: ReleasePlatform, arguments: &[OsString]) -> bool {
    let Some(command) = arguments.first().and_then(|argument| argument.to_str()) else {
        return false;
    };
    if command == "package" {
        if platform == ReleasePlatform::Linux
            && (linux_entrypoint_install_command(arguments)
                || linux_runtime_image_install_command(arguments)
                || linux_runtime_image_retire_command(arguments))
        {
            return false;
        }
        return !matches!(platform, ReleasePlatform::Linux | ReleasePlatform::Windows)
            || !windows_product_package_command(arguments);
    }
    command == "policy-decision-peer"
        || command.starts_with("release-")
        || command.starts_with("public-")
        || command.starts_with("private-release-")
}
