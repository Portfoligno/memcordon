# Windows loader external-capture procedure

This procedure is diagnostic-only. It never gates provider qualification and
must be run on a disposable Windows VM after the native, unobserved laboratory
has produced one failing/pass comparison pair.

1. Restore a clean VM snapshot. Record the Windows build, architecture, VM
   image identity, MemCordon package digest, symbol digest, and production
   launch-plan digest in the run directory.
2. Install exactly that package and its matching symbols. Create a fresh,
   uniquely named laboratory run directory. Do not reuse services, pipes,
   window stations, desktops, profiles, Jobs, or trace-session names from an
   earlier run.
3. Keep the completed native run directory immutable while capturing. Start
   Procmon or WPR before replaying either recorded side. Capture only the
   unobserved production-replica scenario and the single comparison scenario
   that formed the discriminating pair. Do not attach a debugger, enable
   loader snaps, or change ACLs for this comparison.
4. Restrict the exported view to the two child PIDs and their descendants, the
   recorded creation-time interval, and failed/result-status operations. Keep
   enough preceding events to identify the first divergence. Record the first
   differing object identity, requested and granted rights, native result,
   stack, and loaded module when the collector provides them.
5. Store the native trace only as a restricted attachment. Produce a separate
   redacted export that hashes user paths, SIDs, account names, and object
   names. Never retain pipe nonces, environment values, command secrets, or
   user data. Every attachment entry must use a run-relative path, SHA-256,
   byte length, media type, and redaction class.
6. Stop and delete the trace session, then prove the laboratory Job has zero
   active processes and that its service, pipes, desktops, window stations,
   profiles, and temporary files are absent. A cleanup or evidence failure is
   a harness failure; a reproduced loader failure remains an observation.
7. For each side, write an `ExternalCaptureSummaryV1` JSON sidecar. Bind it to
   the existing run id, source scenario id, source-result SHA-256, launch-plan
   and package digests, recorded target PID, trace SHA-256, capture interval,
   collector build, symbol identity, profile/result filters, event count, and
   first divergent object/operation/rights/result/stack-module digests. Then
   run `memcordon-windows-loader-lab attach-external --run-directory <run>
   --external-trace <left> --external-trace <right> --external-summary <left>
   --external-summary <right>`. The attach phase rejects an incomplete or
   mismatched pair before augmenting the manifest.
8. Export both raw and redacted manifests, then restore the clean VM snapshot.

Observer experiments (debug-event pump, full debugger, loader snaps, passive
ETW/WPR, or Procmon) are permitted only after step 3's native pair exists. They
must be separate scenarios and may explain a failure, but cannot promote or
replace the production qualification outcome.
