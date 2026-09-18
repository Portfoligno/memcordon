# Native inventory scheduling

Windows and Linux native roots use one 16-thread executor per measurement. Each root
fences all its tasks before reporting completion; the executor is joined before
the complete measurement returns. Source inventory and other native paths
retain their existing synchronous filesystem protocol. Root enrollment,
source-output exclusions and the final serialized Input identity are unchanged.

The coordinator alone owns sorted depth-first traversal and canonical visited
identities. Workers prepare paths, enumerate complete sorted directories, resolve
links, and open/read/post-validate files. Preparation streams in sorted order:
an earlier child can run while a later sibling is still being prepared. Ready
ancestor preparations retain their window credits. A globally reserved frontier
slot allows arbitrarily deep descent without allocating a window at each depth.

At most 32 tasks are admitted but unreceived, 16 file tasks are admitted, and
16 preparation results are queued/running/ready but unconsumed. Workers never
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
retain their existing identities. macOS retains its protected-file helper route.

Errors use logical traversal order: an earlier admitted file failure wins over
a later directory/preparation failure after the root fence settles the earlier
file tasks. This makes mixed worker/controller error precedence deterministic;
the previous implementation could return the controller failure while dropping
an earlier pending file failure. No failed or canceled traversal returns a
partial manifest. Speculative errors are consumed only at their sorted frontier.

Cancellation is cooperative between actions and read chunks. It cannot interrupt
an indefinitely blocked filesystem call; the bootstrap process supervisor still
owns the hard deadline. Observer/task diagnostics are excluded from Input bytes.

Directory enumeration is off the coordinator thread, but the committed directory
frontier remains ordered. This is not concurrent recursive enumeration of all
sibling directories. Likewise bounded tasks do not imply bounded total memory:
directory listings, the manifest and visited paths remain proportional to input
size. Neither this scheduling change nor type checking establishes a native
elapsed-time improvement; full-scope native measurements are still required.
