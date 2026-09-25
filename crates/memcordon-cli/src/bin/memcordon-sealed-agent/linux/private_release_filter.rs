//! Target-side filter-mode and native-machine observation for one candidate
//! selector. The exact installed cBPF digest is independently bound by the
//! native checkpoint and package lease, not inferred from these target bytes.

use std::ffi::CStr;

pub(crate) const SELECTOR: &str = "private_tcp::native_filter_digest_and_abi_bound";

pub(crate) fn expected_projection() -> [u8; 2] {
    let abi = match super::runtime_manifest::target()
        .expect("fixed release candidate supports only a reviewed native ABI")
    {
        "x86_64-unknown-linux-gnu" => 1,
        "aarch64-unknown-linux-gnu" => 2,
        _ => unreachable!("reviewed candidate target must map to its native ABI"),
    };
    [2, abi]
}

pub(crate) fn observe_target_projection() -> Result<[u8; 2], String> {
    // SAFETY: PR_GET_SECCOMP reads only the current process's scalar mode.
    let mode = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
    if mode != 2 {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: seccomp filter mode differs".into());
    }
    let mut information = std::mem::MaybeUninit::<libc::utsname>::uninit();
    // SAFETY: uname initializes the complete writable utsname slot on success.
    if unsafe { libc::uname(information.as_mut_ptr()) } != 0 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE-FIXTURE: uname: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful uname initialized the complete structure.
    let information = unsafe { information.assume_init() };
    if !information.machine.contains(&0) {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: uname machine is unterminated".into());
    }
    // SAFETY: the checked machine array contains a terminator within bounds.
    let machine = unsafe { CStr::from_ptr(information.machine.as_ptr()) };
    let expected = expected_projection();
    let expected_machine: &[u8] = match expected[1] {
        1 => b"x86_64",
        2 => b"aarch64",
        _ => return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: ABI projection differs".into()),
    };
    if machine.to_bytes() != expected_machine {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: kernel machine differs".into());
    }
    Ok(expected)
}
