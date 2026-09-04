#![cfg(all(windows, feature = "test-support"))]

use std::ffi::{OsStr, OsString};
use std::mem::{align_of, offset_of, size_of};
use std::os::windows::ffi::{OsStrExt, OsStringExt};

use memcordon_platform::test_support::{
    windows_assignment_failure, windows_current_token_contains_world_sid,
    windows_current_token_user_sid_string, windows_encode_command_line, windows_kill_on_job_close,
    windows_nested_assignment, windows_target_remains_suspended_until_assignment,
    windows_token_group_entries, windows_token_group_entries_range, windows_token_group_sid_range,
    windows_token_group_storage_contains, windows_token_user_sid_range,
    windows_token_user_storage_matches,
};
use windows_sys::Win32::Security::{SID, SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_USER};
use windows_sys::Win32::System::SystemServices::{SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY};

struct TokenGroupFixture {
    words: Vec<usize>,
    byte_length: usize,
    sid_offsets: Vec<usize>,
}

struct TokenUserFixture {
    words: Vec<usize>,
    byte_length: usize,
    sid_offset: usize,
}

impl TokenUserFixture {
    fn storage(&self) -> &[u8] {
        // SAFETY: every usize word is initialized and the byte view remains
        // borrowed from the live fixture allocation.
        unsafe {
            std::slice::from_raw_parts(
                self.words.as_ptr().cast(),
                self.words.len() * size_of::<usize>(),
            )
        }
    }

    fn storage_mut(&mut self) -> &mut [u8] {
        // SAFETY: the fixture owns the initialized storage exclusively.
        unsafe {
            std::slice::from_raw_parts_mut(
                self.words.as_mut_ptr().cast(),
                self.words.len() * size_of::<usize>(),
            )
        }
    }
}

impl TokenGroupFixture {
    fn storage(&self) -> &[u8] {
        // SAFETY: every usize word is initialized and the byte view stays
        // within the live Vec allocation.
        unsafe {
            std::slice::from_raw_parts(
                self.words.as_ptr().cast(),
                self.words.len() * size_of::<usize>(),
            )
        }
    }

    fn storage_mut(&mut self) -> &mut [u8] {
        // SAFETY: every usize word is initialized, the byte view is unique,
        // and it stays within the live Vec allocation.
        unsafe {
            std::slice::from_raw_parts_mut(
                self.words.as_mut_ptr().cast(),
                self.words.len() * size_of::<usize>(),
            )
        }
    }
}

fn test_sid(sub_authority: u32) -> Vec<u8> {
    let mut sid = vec![0_u8; offset_of!(SID, SubAuthority) + size_of::<u32>()];
    sid[offset_of!(SID, Revision)] = 1;
    sid[offset_of!(SID, SubAuthorityCount)] = 1;
    sid[offset_of!(SID, IdentifierAuthority) + size_of::<[u8; 6]>() - 1] = 1;
    sid[offset_of!(SID, SubAuthority)..].copy_from_slice(&sub_authority.to_ne_bytes());
    sid
}

fn sid_words(sid: &[u8]) -> Vec<u32> {
    let mut words = vec![0_u32; sid.len().div_ceil(size_of::<u32>())];
    // SAFETY: every u32 word is initialized and the byte view stays within
    // the unique Vec allocation.
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(words.as_mut_ptr().cast(), words.len() * size_of::<u32>())
    };
    bytes[..sid.len()].copy_from_slice(sid);
    words
}

fn token_group_fixture(groups: &[(u32, u32)]) -> TokenGroupFixture {
    let entries_offset = offset_of!(TOKEN_GROUPS, Groups);
    let entries_end = entries_offset + groups.len() * size_of::<SID_AND_ATTRIBUTES>();
    let sids = groups
        .iter()
        .map(|(sub_authority, _)| test_sid(*sub_authority))
        .collect::<Vec<_>>();
    let byte_length = entries_end + sids.iter().map(Vec::len).sum::<usize>();
    let mut words = vec![0_usize; byte_length.div_ceil(size_of::<usize>())];
    let storage_length = words.len() * size_of::<usize>();
    let base = words.as_mut_ptr().cast::<u8>();
    // SAFETY: every usize word is initialized and the byte view stays within
    // the unique Vec allocation.
    let storage = unsafe { std::slice::from_raw_parts_mut(base, storage_length) };
    let count_offset = offset_of!(TOKEN_GROUPS, GroupCount);
    storage[count_offset..count_offset + size_of::<u32>()].copy_from_slice(
        &u32::try_from(groups.len())
            .expect("fixture group count must fit u32")
            .to_ne_bytes(),
    );

    let mut sid_offset = entries_end;
    let mut sid_offsets = Vec::with_capacity(groups.len());
    for (index, ((_, attributes), sid)) in groups.iter().zip(&sids).enumerate() {
        storage[sid_offset..sid_offset + sid.len()].copy_from_slice(sid);
        let entry = SID_AND_ATTRIBUTES {
            // SAFETY: sid_offset identifies the SID bytes just copied into
            // this stable allocation.
            Sid: unsafe { base.add(sid_offset) }.cast(),
            Attributes: *attributes,
        };
        // SAFETY: the destination lies in the checked entry array allocation;
        // write_unaligned also keeps the fixture construction independent of
        // the host structure alignment.
        unsafe {
            std::ptr::write_unaligned(
                base.add(entries_offset + index * size_of::<SID_AND_ATTRIBUTES>())
                    .cast(),
                entry,
            );
        }
        sid_offsets.push(sid_offset);
        sid_offset += sid.len();
    }
    TokenGroupFixture {
        words,
        byte_length,
        sid_offsets,
    }
}

fn token_user_fixture(sub_authority: u32) -> TokenUserFixture {
    let user_offset = offset_of!(TOKEN_USER, User);
    let header_end = user_offset + size_of::<SID_AND_ATTRIBUTES>();
    let sid = test_sid(sub_authority);
    let byte_length = header_end + sid.len();
    let mut words = vec![0_usize; byte_length.div_ceil(size_of::<usize>())];
    let base = words.as_mut_ptr().cast::<u8>();
    let storage_length = words.len() * size_of::<usize>();
    // SAFETY: every word is initialized and this unique byte view is bounded
    // by the fixture allocation.
    let storage = unsafe { std::slice::from_raw_parts_mut(base, storage_length) };
    storage[header_end..header_end + sid.len()].copy_from_slice(&sid);
    let user = SID_AND_ATTRIBUTES {
        // SAFETY: header_end addresses the SID copied into this stable Vec.
        Sid: unsafe { base.add(header_end) }.cast(),
        Attributes: 0,
    };
    // SAFETY: the complete User field is inside the checked header extent;
    // write_unaligned makes the fixture independent of structure alignment.
    unsafe {
        std::ptr::write_unaligned(base.add(user_offset).cast(), user);
    }
    TokenUserFixture {
        words,
        byte_length,
        sid_offset: header_end,
    }
}

#[test]
fn windows_native_encoder_quotes_without_shell_interpretation() {
    let encoded = windows_encode_command_line(
        OsString::from("program.exe"),
        vec![
            OsString::from("plain"),
            OsString::from("two words"),
            OsString::from("a\"b"),
            OsString::new(),
        ],
    );
    let expected: Vec<u16> = OsStr::new("program.exe plain \"two words\" \"a\\\"b\" \"\"")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    assert_eq!(encoded, expected);
}

#[test]
fn windows_native_encoder_preserves_unpaired_wide_units() {
    let native = OsString::from_wide(&[b'a'.into(), 0xd800, b'b'.into()]);
    let encoded = windows_encode_command_line(OsString::from("program.exe"), vec![native]);
    assert!(encoded.contains(&0xd800));
    assert!(!encoded.contains(&0xfffd));
}

#[test]
fn target_remains_suspended_until_successful_job_assignment() {
    assert!(
        windows_target_remains_suspended_until_assignment()
            .expect("suspended assignment scenario should complete")
    );
}

#[test]
fn kill_on_job_close_terminates_a_running_member() {
    assert!(windows_kill_on_job_close().expect("kill-on-close scenario should complete"));
}

#[test]
fn nested_assignment_is_accounted_by_the_memcordon_job() {
    assert!(windows_nested_assignment().expect("nested assignment scenario should complete"));
}

#[test]
fn assignment_failure_terminates_suspended_target_before_execution() {
    assert!(windows_assignment_failure().expect("assignment failure scenario should complete"));
}

#[test]
fn token_group_parser_preserves_multi_entry_storage_and_matches_non_first_sid() {
    let fixture = token_group_fixture(&[
        (10, SE_GROUP_ENABLED as u32),
        (20, SE_GROUP_ENABLED as u32),
        (30, SE_GROUP_ENABLED as u32),
    ]);
    let entries = windows_token_group_entries(fixture.storage(), fixture.byte_length)
        .expect("aligned multi-entry fixture should parse");
    assert_eq!(entries.len(), 3);
    assert_eq!(
        entries[1].0,
        fixture.storage().as_ptr() as usize + fixture.sid_offsets[1],
        "the non-first entry must remain anchored in the live response storage"
    );

    let non_first = sid_words(&test_sid(20));
    assert!(
        windows_token_group_storage_contains(fixture.storage(), fixture.byte_length, &non_first)
            .expect("non-first SID lookup should be safe")
    );
    let absent = sid_words(&test_sid(99));
    assert!(
        !windows_token_group_storage_contains(fixture.storage(), fixture.byte_length, &absent)
            .expect("absent SID lookup should be safe")
    );
}

#[test]
fn token_group_match_requires_enabled_non_deny_entry() {
    let fixture = token_group_fixture(&[
        (20, 0),
        (20, (SE_GROUP_ENABLED | SE_GROUP_USE_FOR_DENY_ONLY) as u32),
    ]);
    let expected = sid_words(&test_sid(20));
    assert!(
        !windows_token_group_storage_contains(fixture.storage(), fixture.byte_length, &expected)
            .expect("disabled and deny-only entries should be parsed safely")
    );
}

#[test]
fn token_group_parser_rejects_truncated_count_storage_and_allocation() {
    let fixture =
        token_group_fixture(&[(10, SE_GROUP_ENABLED as u32), (20, SE_GROUP_ENABLED as u32)]);
    let entries_offset = offset_of!(TOKEN_GROUPS, Groups);
    let one_entry_end = entries_offset + size_of::<SID_AND_ATTRIBUTES>();

    assert!(
        windows_token_group_entries(fixture.storage(), entries_offset - 1)
            .expect_err("truncated count prefix must fail")
            .contains("truncated")
    );
    assert!(
        windows_token_group_entries(fixture.storage(), one_entry_end)
            .expect_err("count exceeding declared entry storage must fail")
            .contains("truncated")
    );
    assert!(
        windows_token_group_entries(fixture.storage(), fixture.storage().len() + 1)
            .expect_err("declared response exceeding allocation must fail")
            .contains("exceeds its allocation")
    );
}

#[test]
fn token_group_parser_rejects_overflow_and_unaligned_entries() {
    assert!(
        windows_token_group_entries_range(usize::MAX, usize::MAX)
            .expect_err("entry byte multiplication overflow must fail")
            .contains("overflows")
    );

    let fixture = token_group_fixture(&[(10, SE_GROUP_ENABLED as u32)]);
    let alignment = align_of::<SID_AND_ATTRIBUTES>();
    let mut backing = vec![0_u8; fixture.storage().len() + alignment];
    let start = (0..alignment)
        .find(|offset| {
            (backing.as_ptr() as usize + offset + offset_of!(TOKEN_GROUPS, Groups)) % alignment != 0
        })
        .expect("an unaligned byte-slice offset must exist");
    let unaligned = &mut backing[start..start + fixture.storage().len()];
    unaligned.copy_from_slice(fixture.storage());
    assert!(
        windows_token_group_entries(unaligned, fixture.byte_length)
            .expect_err("unaligned entry storage must fail")
            .contains("misaligned")
    );
}

#[test]
fn token_group_sid_bounds_reject_outside_and_truncated_sid_storage() {
    let mut fixture = token_group_fixture(&[(10, SE_GROUP_ENABLED as u32)]);
    let sid_offset = fixture.sid_offsets[0];
    let valid = windows_token_group_sid_range(fixture.storage(), fixture.byte_length, sid_offset)
        .expect("complete in-buffer SID should have a bounded range");
    assert_eq!(valid.start, sid_offset);
    assert!(
        windows_token_group_sid_range(fixture.storage(), fixture.byte_length, usize::MAX)
            .expect_err("wrapped outside SID pointer must fail")
            .contains("outside")
    );

    fixture.storage_mut()[sid_offset + 1] = u8::MAX;
    assert!(
        windows_token_group_storage_contains(
            fixture.storage(),
            fixture.byte_length,
            &sid_words(&test_sid(10)),
        )
        .expect_err("count-derived SID extent beyond storage must fail")
        .contains("truncated")
    );
}

#[test]
fn current_process_token_group_scan_completes_without_access_violation() {
    assert!(
        windows_current_token_contains_world_sid()
            .expect("native current-process TokenGroups scan should complete")
    );
}

#[test]
fn token_user_parser_keeps_the_complete_sid_anchored_and_matches_it() {
    let fixture = token_user_fixture(42);
    let range = windows_token_user_sid_range(fixture.storage(), fixture.byte_length)
        .expect("complete in-buffer TOKEN_USER SID should parse");
    assert_eq!(range.start, fixture.sid_offset);
    assert_eq!(range.end, fixture.byte_length);
    assert!(
        windows_token_user_storage_matches(
            fixture.storage(),
            fixture.byte_length,
            &sid_words(&test_sid(42)),
        )
        .expect("matching TOKEN_USER SID should compare safely")
    );
    assert!(
        !windows_token_user_storage_matches(
            fixture.storage(),
            fixture.byte_length,
            &sid_words(&test_sid(43)),
        )
        .expect("nonmatching TOKEN_USER SID should compare safely")
    );
}

#[test]
fn token_user_parser_rejects_truncated_and_outside_storage() {
    let mut fixture = token_user_fixture(42);
    let header_end = offset_of!(TOKEN_USER, User) + size_of::<SID_AND_ATTRIBUTES>();
    assert!(
        windows_token_user_sid_range(fixture.storage(), header_end - 1)
            .expect_err("truncated TOKEN_USER header must fail")
            .contains("truncated")
    );
    assert!(
        windows_token_user_sid_range(fixture.storage(), fixture.storage().len() + 1)
            .expect_err("declared TOKEN_USER response exceeding allocation must fail")
            .contains("exceeds its allocation")
    );

    let outside = SID_AND_ATTRIBUTES {
        Sid: fixture
            .storage()
            .as_ptr()
            .wrapping_add(fixture.storage().len() + 1) as *mut _,
        Attributes: 0,
    };
    let user_offset = offset_of!(TOKEN_USER, User);
    // SAFETY: the complete User field remains inside the fixture header.
    unsafe {
        std::ptr::write_unaligned(
            fixture.storage_mut().as_mut_ptr().add(user_offset).cast(),
            outside,
        );
    }
    assert!(
        windows_token_user_sid_range(fixture.storage(), fixture.byte_length)
            .expect_err("out-of-buffer TOKEN_USER SID pointer must fail")
            .contains("outside")
    );
}

#[test]
fn token_user_parser_rejects_truncated_and_invalid_sid_extents() {
    let mut fixture = token_user_fixture(42);
    let sid_offset = fixture.sid_offset;
    fixture.storage_mut()[sid_offset + offset_of!(SID, SubAuthorityCount)] = u8::MAX;
    assert!(
        windows_token_user_sid_range(fixture.storage(), fixture.byte_length)
            .expect_err("count-derived TOKEN_USER SID extent beyond storage must fail")
            .contains("truncated")
    );

    let mut fixture = token_user_fixture(42);
    fixture.storage_mut()[sid_offset + offset_of!(SID, Revision)] = 2;
    assert!(
        windows_token_user_sid_range(fixture.storage(), fixture.byte_length)
            .expect_err("invalid TOKEN_USER SID revision must fail")
            .contains("invalid")
    );
}

#[test]
fn current_process_token_user_scan_keeps_native_storage_live() {
    let sid = windows_current_token_user_sid_string().expect(
        "native current-process TokenUser scan should complete without an access violation",
    );
    assert!(sid.starts_with("S-1-"));
}
