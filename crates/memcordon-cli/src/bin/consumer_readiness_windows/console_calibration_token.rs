//! Default-security variants of disposable calibration primaries only.
use super::{
    fixture_default_dacl::plan_console_user,
    native_fixture_default_dacl::{Snapshot, set_private_default_acl, snapshot},
};
use serde_json::{Value, json};
use std::{io, mem::size_of};
use windows_sys::Win32::{
    Foundation::HANDLE,
    Security::{SetTokenInformation, TOKEN_OWNER, TokenOwner},
};

pub(super) fn evidence(token: &Snapshot) -> Value {
    let envelope = token.envelope();
    let acl = token.default_acl();
    json!({
        "user_sid":envelope.user_sid,"owner_sid":envelope.owner_sid,
        "primary_group_sid":envelope.primary_group_sid,
        "default_dacl_bytes":acl.map(<[u8]>::len),
        "default_dacl_hex":acl.filter(|bytes| bytes.len() <= 384)
            .map(|bytes| bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>()),
        "default_dacl_sha256":acl.map(super::descriptor::gate_precondition::sha256),
    })
}

pub(super) fn vary(
    source: HANDLE,
    derived: HANDLE,
    held: &Snapshot,
    user: &[u8],
    dacl: bool,
    owner: bool,
) -> io::Result<()> {
    let source_before = snapshot(source)?;
    let before = snapshot(derived)?;
    if source == derived || !before.same_input(held) {
        return Err(io::Error::other("calibration fresh reduced input differs"));
    }
    let planned = if dacl {
        let acl = plan_console_user(before.default_acl(), user)?;
        if before.default_acl() != Some(&acl) {
            set_private_default_acl(derived, &acl)?;
        }
        Some(acl)
    } else {
        None
    };
    let mut expected = before.envelope().clone();
    if owner && expected.owner_sid != expected.user_sid {
        let mut words = vec![0usize; user.len().div_ceil(size_of::<usize>())];
        // SAFETY: the measured user SID fits the aligned backing allocation.
        unsafe {
            std::ptr::copy_nonoverlapping(
                user.as_ptr(),
                words.as_mut_ptr().cast::<u8>(),
                user.len(),
            )
        };
        let selected = TOKEN_OWNER {
            Owner: words.as_mut_ptr().cast(),
        };
        // SAFETY: the header and measured SID live through the synchronous call.
        if unsafe {
            SetTokenInformation(
                derived,
                TokenOwner,
                (&selected as *const TOKEN_OWNER).cast(),
                size_of::<TOKEN_OWNER>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        expected.owner_sid.clone_from(&expected.user_sid);
    }
    let after = snapshot(derived)?;
    if after.envelope() != &expected
        || after.default_acl() != planned.as_deref().or_else(|| before.default_acl())
        || snapshot(source)? != source_before
    {
        return Err(io::Error::other(
            "calibration token variant readback differs",
        ));
    }
    Ok(())
}
