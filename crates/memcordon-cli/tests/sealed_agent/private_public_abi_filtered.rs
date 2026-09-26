#![cfg(target_os = "linux")]

use crate::linux::private_public_abi_filtered::validate_branch_claims_for_test;

fn report() -> (serde_json::Value, Option<(u64, u64)>) {
    let helper = if cfg!(target_arch = "aarch64") {
        Some((55, 66))
    } else {
        None
    };
    let children = if cfg!(target_arch = "x86_64") {
        vec![
            serde_json::json!({
                "branch": "x32", "pid": 601, "start_time_ticks": 801,
                "audit_arch": 0xc000003e_u32, "syscall_number": 0x40000027_u32,
                "terminal_signal": libc::SIGSYS, "helper_device": null, "helper_inode": null
            }),
            serde_json::json!({
                "branch": "i386", "pid": 602, "start_time_ticks": 802,
                "audit_arch": 0x40000003_u32, "syscall_number": 20,
                "terminal_signal": libc::SIGSYS, "helper_device": null, "helper_inode": null
            }),
        ]
    } else {
        vec![serde_json::json!({
            "branch": "arm32", "pid": 601, "start_time_ticks": 801,
            "audit_arch": 0x40000028_u32, "syscall_number": 20,
            "terminal_signal": libc::SIGSYS, "helper_device": 55, "helper_inode": 66
        })]
    };
    (
        serde_json::json!({
            "schema_version": 1,
            "evidence_scope": "filtered-public-target-claims-require-kernel-join",
            "challenge": "11".repeat(32),
            "target_pid": 600,
            "target_start_time_ticks": 800,
            "target_uid": 1001,
            "target_gid": 1001,
            "no_new_privs": true,
            "seccomp_mode": 2,
            "seccomp_filters": 2,
            "native_getpid": 600,
            "children": children
        }),
        helper,
    )
}

fn validate(value: &serde_json::Value, helper: Option<(u64, u64)>) -> Result<(), String> {
    validate_branch_claims_for_test(&serde_json::to_vec(value).unwrap(), 600, 800, helper)
}

#[test]
fn filtered_public_abi_branch_claims_are_exact_and_ordered() {
    let (mut value, helper) = report();
    validate(&value, helper).expect("reviewed target claim shape");

    value["children"][0]["terminal_signal"] = serde_json::json!(0);
    assert!(validate(&value, helper).is_err());
    let (mut value, helper) = report();
    value["children"][0]["pid"] = serde_json::json!(600);
    assert!(validate(&value, helper).is_err());
    let (mut value, helper) = report();
    value["children"][0]["audit_arch"] = serde_json::json!(0);
    assert!(validate(&value, helper).is_err());
    let (mut value, helper) = report();
    value["seccomp_filters"] = serde_json::json!(1);
    assert!(validate(&value, helper).is_err());
    let (mut value, helper) = report();
    value["children"][0]["start_time_ticks"] = serde_json::json!(0);
    assert!(validate(&value, helper).is_err());

    if cfg!(target_arch = "x86_64") {
        let (mut value, helper) = report();
        value["children"].as_array_mut().unwrap().swap(0, 1);
        assert!(validate(&value, helper).is_err());
        let (mut value, helper) = report();
        value["children"][1]["pid"] = serde_json::json!(601);
        assert!(validate(&value, helper).is_err());
    } else {
        let (mut value, helper) = report();
        value["children"][0]["helper_inode"] = serde_json::json!(67);
        assert!(validate(&value, helper).is_err());
    }
}
