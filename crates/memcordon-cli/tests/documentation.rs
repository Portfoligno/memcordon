use std::fs;
use std::path::Path;
use std::process::Command;

use memcordon::invocation::{
    CLEAN_USAGE, DOCTOR_USAGE, PLAN_USAGE, PUBLIC_POLICY_OPTIONS, REFERENCE_URL, ROOT_USAGE,
};

fn workspace_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("CLI crate should be inside the workspace")
        .to_path_buf()
}

fn stdout(arguments: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .args(arguments)
        .output()
        .expect("memcordon should run");
    assert!(output.status.success(), "arguments={arguments:?}");
    assert!(output.stderr.is_empty(), "arguments={arguments:?}");
    String::from_utf8(output.stdout).expect("public help should be UTF-8")
}

#[test]
fn generated_public_help_is_exact_complete_and_keeps_private_routes_hidden() {
    for (arguments, expected) in [
        (&["--help"][..], ROOT_USAGE),
        (&["doctor", "--help"][..], DOCTOR_USAGE),
        (&["plan", "--help"][..], PLAN_USAGE),
        (&["clean", "--help"][..], CLEAN_USAGE),
    ] {
        assert_eq!(stdout(arguments), format!("{expected}\n"));
        assert!(expected.contains(REFERENCE_URL));
        for private in ["__memcordon-launch", "__memcordon-guardian"] {
            assert!(!expected.contains(private));
        }
    }
    for option in PUBLIC_POLICY_OPTIONS {
        assert!(ROOT_USAGE.contains(option), "root help omits {option}");
        assert!(PLAN_USAGE.contains(option), "plan help omits {option}");
    }

    let examples = ROOT_USAGE.find("Examples:").expect("root examples");
    let policy = ROOT_USAGE
        .find("Policy options")
        .expect("root policy options");
    assert!(
        examples < policy,
        "ordinary examples should precede policy depth"
    );
    assert!(ROOT_USAGE.contains("returns the command's exit status"));
    assert!(PLAN_USAGE.contains("No workload is launched"));
    assert!(CLEAN_USAGE.contains("Without --dry-run"));
}

#[test]
fn reference_and_generated_help_cover_the_same_public_interface() {
    let reference = fs::read_to_string(workspace_root().join("docs/reference.md"))
        .expect("reference should be readable");
    for syntax in [
        "memcordon [EXECUTION OPTIONS] [BUDGET]... [--] COMMAND [ARGUMENT]...",
        "memcordon doctor [--json] [--require hard|watchdog]",
        "memcordon plan [POLICY OPTIONS] [--json] [BUDGET]...",
        "memcordon clean [--dry-run] [--json]",
    ] {
        assert!(reference.contains(syntax), "reference omits `{syntax}`");
    }
    for option in PUBLIC_POLICY_OPTIONS {
        assert!(reference.contains(option), "reference omits {option}");
    }
}
