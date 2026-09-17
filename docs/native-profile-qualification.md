# Windows native profile qualification

`memcordon-ci qualify-native-profile` constructs and verifies a job-local copy
of selected native tooling. It is an acquisition qualification tool, not a
production build context or a cache-key producer. Production Windows builds
continue to measure all existing conventional installation roots and all
environment-selected native roots. The tool rejects policies requesting
production admission. Its evidence cannot be loaded by `--build-context`.

## Invocation and selection

Invoke the freshly built controller directly with:

```text
memcordon-ci qualify-native-profile --policy ci/native-profiles/windows-staged-v1.json --selection selection.json --destination ABSOLUTE_EXISTING_JOB_TEMP_DIRECTORY
memcordon-ci audit-native-profile --specification ABSOLUTE_SPECIFICATION_PATH
```

Each invocation is one executable with separate arguments. The destination
must be an existing, private, job-owned directory outside every selected source
and external input. The tool adds no custom environment variables, executes no
shell scripts or compiler commands, and installs no software. On a hosted
Windows worker, obtain explicit selectors from that worker's installed native
environment; do not assume a runner label pins toolset contents. Example input:

```json
{
  "architecture": "x64",
  "installation": "C:\\Program Files\\Microsoft Visual Studio\\18\\Enterprise",
  "toolset_version": "14.51.36231",
  "sdk": "C:\\Program Files (x86)\\Windows Kits\\10",
  "sdk_version": "10.0.26100.0",
  "git": "C:\\Program Files\\Git",
  "llvm": "C:\\Program Files\\LLVM",
  "rustup_bin": "C:\\Users\\runneradmin\\.cargo\\bin",
  "system_root": "C:\\Windows",
  "additional_support": []
}
```

These are illustrative paths/versions, not pinned runner facts. `arm64` selects
Hostarm64/arm64. Native tools must exist and satisfy the existing MSVC/SDK/Git/
LLVM admission checks. Paths must be absolute, losslessly Unicode, and free of
links, reparses, unsupported special entries and invalid Windows names. This
first qualification profile rejects all links instead of pruning them or
claiming relocation support it has not proved. Additional complete support
roots can be declared; there is no per-file exclusion language.

The checked-in policy requires the review set covering controller,
release-native, backend-windows-job, windows-loader-production,
windows-provider-lifecycle and windows-package-channel. Listing these recipes
does not certify their closure; the evidence outcome explicitly remains
`copy-verified-closure-unqualified`.

## Retained inputs and environment

The projection copies the entire selected MSVC toolset, VC/Auxiliary/Build,
VC/Redist when present, the **entire selected WindowsSdkDir**, whole selected
Git and LLVM installations, and any additional support trees. Unversioned SDK
resources and other SDK versions remain included. The selected rustup bin and
the existing kernel32.dll, ntdll.dll, ucrtbase.dll, msvcp_win.dll, cmd.exe and
ping.exe system inputs remain external, fully measured runtime roots.

The generated native environment uses explicit staged VSINSTALLDIR,
VCINSTALLDIR, VCToolsInstallDir and WindowsSdkDir, exact versions, staged
include/library paths, and the existing positive PATH admission. It does not
append ambient INCLUDE/LIB or manufacture ProgramFiles values. The qualifier
checks that every environment-selected native root is within the stage and
also measures the whole staged ancestor, catching files added between selected
subtrees. Production `windows_native_roots` and `native_environment_roots`
retain their existing behavior; this module does not switch their contract.

The environment in the specification is the native selection overlay, not a
claim to capture the complete environment of a production Cargo invocation.
The qualifier does not compile the controller using the stage. Replacing the
production bootstrap environment remains part of the gated migration below.

## Publication and evidence lifecycle

Under the destination, the stable layout is:

```text
windows-staged-native-qualification-v1/
  x64/                         (or arm64)
    lease
    active/tree/               (runtime inputs)
    control/specification.json
    control/evidence.json
```

A create-new lease and exclusive `active` reservation prevent a second
cooperating acquisition from adopting or replacing this generation. Copying
uses a uniquely named incoming sibling. Publication moves it into the reserved
active directory; no compiler or inventory uses incoming paths. Unexpected
existing directories, leases or reparse ancestors fail admission. The private
job-owned directory and trusted worker are preconditions: this is not a
directory-publication primitive secure against a hostile concurrent writer
with authority over that directory.

The lease deliberately remains after success or failure. Reinvocation fails
rather than merging, clearing or reusing the candidate. Failure before evidence
publication leaves no accepted result. Failed incoming data and published
candidate/control files remain for diagnosis and normal whole-job cleanup;
native input trees are not automatically deleted on an error path. A fresh
hosted job may use the identical absolute layout.

`specification.json` freezes the policy, roots, selected versions, native
environment and acquisition absence predicates. It contains no inventory,
completion flag or self-digest. Its bytes never change after publication.
`evidence.json` separately contains complete canonical scanner Input records,
the specification digest, stage timings and the qualification-only outcome.
Both control files are outside all runtime/source roots. File publication uses
no-clobber persistence; a partial diagnostic generation cannot masquerade as
completed evidence.

The actual final absolute paths remain in scanner identities. Different
incoming tokens at the same final location produce equal runtime records for
equal contents. Different actual final roots correctly change identities; no
path normalization hides that difference. Cross-job reuse is not promised:
this tool does not emit a production cache key at all.

## Verification and its limits

The qualifier performs:

1. Complete strict source capture before copying.
2. Copy through validated source handles, then an independent streaming byte
   comparison of each source/destination file, preserving permissions.
3. Publication and staged tool/environment admission, then frozen specification
   publication.
4. Complete source snapshot S1, compared with the pre-copy snapshot.
5. Destination snapshots D, explicitly compared with corresponding source
   records by relative path/content/type/mode. Original canonical runtime
   records are retained unchanged. The complete stage ancestor and external
   runtime inputs are also captured.
6. Complete source snapshot S2, compared with S1, plus absence checks for
   optional support that was absent at selection.
7. Fresh destination/external publication audit and unchanged-specification
   check before writing completed evidence.

The strict scanner supplies existing content and identity checks. The copy
protocol additionally checks lengths, modification stamps, path/handle
identity and byte equality. Source reenumeration catches observed membership
changes. No operation is a transactionally atomic filesystem snapshot. An
adversarial mutate-and-restore writer or modification between observations can
evade endpoint comparisons. Do not run qualification concurrently with native
installation/update activity. Detected drift fails; retries until stable are
not an acceptance method.

The public `qualify_with_observer` API supplies checkpoints for supervisors and
deterministic fault tests. An observer error cancels without completed evidence.
Checkpoints cannot interrupt a blocked filesystem syscall: hard deadlines and
process termination remain the responsibility of an external supervisor. A
process killed after publication can leave a candidate and lease, which cannot
be adopted as successful evidence.

`audit-native-profile` reloads the frozen specification and matching complete
evidence, validates root coverage/environment coherence, freshly measures every
staged/external input, and confirms both control files remain unchanged. It does
not rewrite either control file. Original copied source installations are
acquisition provenance after success; mutation there is not staged runtime
drift unless that source remains an explicitly external runtime input.

All copy/hash/audit work counts in performance accounting. For B copied bytes,
the source pre-copy capture, copy read, byte-comparison read, S1 and S2 amount to
roughly 5B logical source reads. Copying writes B bytes; byte comparison reads B
destination bytes. Per-root destination captures and the additional whole-stage
capture each read approximately B, as do their publication-audit repetitions.
External roots add their own capture/audit work. These deliberately conservative
qualification costs are recorded by stage; they may exceed savings from omitted
unrelated installations. Report total acquisition plus every scan/audit, not
just the staged scan. No 1,800-second completion guarantee follows.

## Gates before any production migration

Production migration requires a separate reviewed change with:

* Exact pinned ring, cc, find-msvc-tools, static_vcruntime and all native build
  script/helper branch review covering every listed recipe and architecture.
* Closure of non-OS helper/DLL/resource dependencies and explicit treatment of
  registry/COM/package discovery, current-directory lookups and absolute paths.
  PATH admission alone does not close Windows DLL loading.
* Relocation evidence on actual hosted Windows x64 and ARM64 toolsets,
  including compiler/linker/resource operations and generated compile tests.
* A complete closed production environment, bootstrap ordering, new isolated
  cache contract/namespace, and existing pre/post/final drift audits.
* Same-profile exact Input equivalence for scanner scheduling changes, and a
  separate closure/behavior review for deliberately different legacy/staged
  identities. Production source changes can change full context digests even
  when the fixed native inventory is equal.
* Representative end-to-end Windows timings and resource limits, including
  copy/validation/audit costs and all failures. Local fixture success is not
  native Windows execution or performance qualification.

Until those gates pass, full production installation scanning remains enabled.
No native compiler bundle is distributed or cached by this qualification tool;
existing dependency/compiled-output cache rules remain unchanged.
