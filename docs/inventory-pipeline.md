# Native inventory scheduling

Windows native roots use one 16-thread executor per measurement. Each root
fences all its tasks before reporting completion; the executor is joined before
the complete measurement returns. Source inventory and portable native paths
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
Each file task opens its own handles after admission and retains every original
enumeration/pre-read/post-read stamp and current-path file-id check. Exact-size
reads still reject early EOF and require post-validation; cancellation also
rejects empty-file results.

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
size. Neither this scheduling change nor type checking establishes a Windows
elapsed-time improvement; full-scope native measurements are still required.
