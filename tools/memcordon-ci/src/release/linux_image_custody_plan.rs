//! Descriptor arithmetic for the complete, finite image-case plan.
use std::io;

pub const FILES_PER_SHARD: usize = 128;
pub const IMPORT_CASES: usize = 8;
pub const EXPORT_CASES: usize = 6;
// Per import: three byte captures, eighteen protocol/result artifacts, and
// three retirement receipts. Export common records: challenge, contract, ready,
// source, invocation, wait, family, worker receipt/journal, and three stream or
// refusal records, plus each export's frozen memory receipt. Two loader probes
// retain their own frozen memory receipts. Only the last concurrent-writer case has its helper's
// eleven protocol publications, three writer receipts, retained executable,
// two streams, and seven capture/retirement witnesses. Device has two receipts.
pub const IMPORT_ARTIFACT_OWNERS: usize = 3 + 18 + 3;
pub const EXPORT_ARTIFACT_OWNERS: usize = 9 + 3 + 1;
pub const CONCURRENT_ARTIFACT_OWNERS: usize = 11 + 3 + 1 + 2 + 7;
pub const DEVICE_ARTIFACT_OWNERS: usize = 2;
pub const LOADER_BUDGET_OWNERS: usize = 2;
// One copy may fail before its readonly handoff; the first failure stops the
// remaining import loop. Other file generations are either transient or in
// the artifact allowance above, never a retained unbounded writer list.
pub const PARTIAL_WRITERS: usize = 1;
// Current copy input/output/readback (3), two channel endpoints while spawning,
// executable/proc-exe verification (2), maximum rejected ancillary receipt
// adopted by the native transport (64), directory edge
// and census descriptor (2), command stdin/stdout/stderr pipes (6), and native
// retirement/status queries (4). These are additional to measured baseline.
pub const TRANSIENT_OWNERS: usize = 3 + 2 + 2 + 64 + 2 + 6 + 5 + 4;
pub const JOURNAL_OWNERS: usize = 2;
// Actual preopened spare descriptors released before failure finalization:
// three pipe pairs for a cleanup command and four native census/status opens.
pub const CLEANUP_RESERVE_OWNERS: usize = 6 + 4;
// Each importer retains pidfd+image. Two refusal probes keep six frontend
// access owners. Each export has four pidfd/image pairs, one cgroup, at most
// two worker/descendant pairs, and six frontend access owners. Fourteen cover
// the one helper's pidfd/image/peer/streams and five administrative plus three
// device handles. Active capture pipes are in TRANSIENT_OWNERS.
pub const NATIVE_FAMILY_OWNERS: usize =
    IMPORT_CASES * 2 + 2 * 6 + EXPORT_CASES * (4 * 2 + 1 + 2 * 2 + 6) + 14;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plan {
    pub remote_files: usize,
    pub channels: usize,
    pub directory_owners: usize,
    pub artifact_owners: usize,
    pub maximum_parent_descriptors: usize,
}

impl Plan {
    pub fn new(
        baseline: usize,
        regular_members: usize,
        directory_owners: usize,
        extra_directory_owners: usize,
        soft_limit: u64,
    ) -> io::Result<Self> {
        let overflow = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "image descriptor plan arithmetic overflow",
            )
        };
        // One original source set, eight distinct staged sets, and one loader
        // configuration member that a negative case deliberately adds.
        let remote_files = regular_members
            .checked_mul(IMPORT_CASES + 1)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(overflow)?;
        let channels = remote_files
            .checked_add(directory_owners)
            .ok_or_else(overflow)?
            .div_ceil(FILES_PER_SHARD);
        let artifact_owners = IMPORT_CASES
            .checked_mul(IMPORT_ARTIFACT_OWNERS)
            .and_then(|n| {
                EXPORT_CASES
                    .checked_mul(EXPORT_ARTIFACT_OWNERS)
                    .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| {
                n.checked_add(
                    CONCURRENT_ARTIFACT_OWNERS + DEVICE_ARTIFACT_OWNERS + LOADER_BUDGET_OWNERS,
                )
            })
            .ok_or_else(overflow)?;
        // Conservatively count both the channel and a possible Rust Child
        // backend pidfd for every shard, independent of backend availability.
        let process_channels = channels.checked_mul(2).ok_or_else(overflow)?;
        let maximum_parent_descriptors = [
            baseline,
            process_channels,
            extra_directory_owners,
            artifact_owners,
            PARTIAL_WRITERS,
            TRANSIENT_OWNERS,
            JOURNAL_OWNERS,
            CLEANUP_RESERVE_OWNERS,
            NATIVE_FAMILY_OWNERS,
        ]
        .into_iter()
        .try_fold(0usize, |sum, value| {
            sum.checked_add(value).ok_or_else(overflow)
        })?;
        if regular_members == 0 || maximum_parent_descriptors as u64 >= soft_limit {
            return Err(io::Error::other(format!(
                "image custody descriptor plan is infeasible: baseline={baseline}; remote-files={remote_files}; channels={channels}; remote-directories={directory_owners}; local-directories={extra_directory_owners}; artifacts={artifact_owners}; native-family={NATIVE_FAMILY_OWNERS}; partial-writers={PARTIAL_WRITERS}; transient={TRANSIENT_OWNERS}; journals={JOURNAL_OWNERS}; cleanup-reserve={CLEANUP_RESERVE_OWNERS}; maximum={maximum_parent_descriptors}; soft-limit={soft_limit}"
            )));
        }
        Ok(Self {
            remote_files,
            channels,
            directory_owners,
            artifact_owners,
            maximum_parent_descriptors,
        })
    }
}
