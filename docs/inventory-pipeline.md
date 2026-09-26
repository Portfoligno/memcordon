# Native inventory scheduling

Source and Windows, Linux, and macOS native roots share one 16-thread executor per managed measurement. Each root
fences all its tasks before reporting completion; the executor is joined before
the complete measurement returns. Two controllers overlap the source and native
domains. Native required roots precede discovery roots, sharing one visited set;
source owns its own visited set. Their joined records retain equal-path
multiplicity and source-first order under the existing stable path sort. Root enrollment,
source-output exclusions and the final serialized Input identity are unchanged.

The coordinator alone owns sorted depth-first traversal and canonical visited
identities. Workers prepare paths, enumerate complete sorted directories, resolve
links, and open/read/post-validate files. Preparation streams in sorted order:
an earlier child can run while a later sibling is still being prepared. Ready
ancestor preparations retain their window credits. A globally reserved frontier
slot allows arbitrarily deep descent without allocating a window at each depth.

Each domain admits at most 16 unreceived tasks, eight file tasks, and eight
queued/running/ready but unconsumed preparation results. Aggregate limits remain
32/16/16. Standalone native snapshots retain their existing 32/16/16 session
limits. Each controller owns its completion channel and reserved frontier credit;
workers never wait for another domain's admission. Workers never
submit child tasks. The completion channel can hold all outstanding results.
Preparation lookahead stays within runs of entries hinted as regular files;
it stops before directories, links, or unknown entries. This prevents ready
ancestor siblings from consuming the deeper frontier's preparation window.
Hints are cached by enumeration workers and affect scheduling only. Classification
and validation remain authoritative, and the reserved frontier slot still allows
progress if a hinted leaf becomes a directory before preparation.
Each file task opens its own handles after admission and retains every original
enumeration/pre-read/post-read stamp and current-path file-id check. Windows exact-size
reads still reject early EOF and require post-validation; Unix reads through EOF
because virtual regular files may expose bytes beyond their reported size. Cancellation also
rejects empty-file results.

Linux files bind device/inode and content/permission metadata before and after
reading and after reopening the current path. Native opens refuse final symlinks
and cannot block waiting for a substituted FIFO. Access time is excluded from
the comparison because reading can update it. Linux null-device records remain
limited to native descendants; missing links and proven access-denied descendants
retain their existing identities. macOS and source retain ordinary EOF reader
acceptance; this scheduling change does not silently apply Linux read hardening
to them. macOS protected fallback alone enters a process-shared one-slot gate,
after typed permission denial and system-path validation. Cancellation is checked
before and after acquiring it. The helper retains its 30-second/8,192-byte capture
limit and now binds the protected read to the enumerated stamp before and after
execution; concurrent protected-file mutation fails explicitly.

Errors use logical traversal order: an earlier admitted file failure wins over
a later directory/preparation failure after the root fence settles the earlier
file tasks. This makes mixed worker/controller error precedence deterministic;
the previous implementation could return the controller failure while dropping
an earlier pending file failure. No failed or canceled traversal returns a
partial manifest. Speculative errors are consumed only at their sorted frontier.
Both domains settle on failure; source errors take precedence over native errors,
independent of completion order. Neither domain cancels the other on failure.

Observations rotate through two slots per domain, `inventory-source-0/1.json` and
`inventory-native-0/1.json`. Root ordinal, domain, limits and status disambiguate
local task ids. After both joins, `inventory-domains.json` records elapsed time,
committed files/bytes and outcomes. Queue/payload limits, loss counters and bounded
acknowledgement waits remain in place. Standalone snapshots retain their original
two filenames. These observations never enter the measured content identity.

Cancellation is cooperative between actions and read chunks. It cannot interrupt
an indefinitely blocked filesystem call; the bootstrap process supervisor still
owns the hard deadline. Observer/task diagnostics are excluded from Input bytes.

Directory enumeration is off the coordinator thread, but the committed directory
frontier remains ordered. This is not concurrent recursive enumeration of all
sibling directories. Likewise bounded tasks do not imply bounded total memory:
directory listings, the manifest and visited paths remain proportional to input
size. Neither this scheduling change nor type checking establishes a native
elapsed-time improvement; full-scope native measurements are still required.
