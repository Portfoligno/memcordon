# crates.memcordon-cli.src.bin.memcordon-sealed-agent.windows.loader_access

Status: source-grounded proposed decision; independent review and acceptance pending.

Source: `crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/loader_access.rs`  
Registry owner: `sealed-provider`  
Design disposition: Likely decomposition candidate  
Work packages: `GOV-01`, `GOV-06`, `PROV-01`, `WIN-01`

## Decision

Decompose pure API-set/forwarder parsing, graph canonicalization and evidence validation from native resource capture. Keep one native attestation coordinator holding all source pins and the shared deadline/progress budget through target-access verification.

## Observed phases and custody

`resolve_native_loader_resources` (line 1045) checks the exact installed bootstrap image, rejects reparse components, validates native machine and absence of delay-load imports, bounds ancestor inventory, then retains holder-primary opens as mutation pins. Its comment explicitly distinguishes those pins from target-access evidence. Later graph resolution, KnownDll selection and access probes are distinct operations with different authority: path identity cannot substitute for opening the final object as the target.

The seam is value parsing/graph planning → retained native identity capture → effective-token access probes → bound evidence. `NativeLoaderAttestationBudget` spans the sequence. Any extraction must return owned resources or complete immutable values, never raw handles whose lifetime silently ends before comparison. Unknown/denied native objects must remain failures rather than absence.

## Compatibility and evidence gates

Preserve graph/import/export digest canonicalization, API-set parent/host selection and `NativeLoaderAccessEvidenceV2`. Existing security-suite cases distinguish ancestor identity from final access, KnownDll absence from denial, exact map stages and target-tier canaries. Pure fixture vectors are suitable first extraction tests. Native Windows gates still require pinned-leaf replacement attempts, effective-thread token access, KnownDll namespace probes and loader progress deadlines on supported architectures. The proposed coordinator name in the design is a target, not an existing type. Review and safe native extraction remain pending.


## Measurement and review accounting

The tracked-source boundary report identifies this candidate by the stable id above and binds its source SHA-256, item/visibility/unsafe/cfg metrics, lexical dependencies, call components and bounded cochange pair counts. Match the recorded source hash before reusing a measurement; Git HEAD alone is insufficient for a dirty capture. Pair counts are not statistical cochange clusters, and lexical test references are not execution evidence.

This decision is authored from the source inspections named above. It is not independently reviewed merely because it is recorded. No production split, native test pass or compatibility certification is claimed. Required native and characterization gates remain open until their actual evidence is attached.
