//! Reviewed finite outer ceilings for the retained literal operations.
//! Native child deadlines remain unchanged. Byte-only phases receive explicit
//! planning room; these are ceilings, never observed execution measurements.

pub(super) fn reviewed_legacy_minutes(command: &str) -> Option<u64> {
    let words = command.split_whitespace().collect::<Vec<_>>();
    if words.first() == Some(&"tar") {
        return Some(15); // bounded selected archives; no compilation or runtime tests
    }
    if command.starts_with("rustup run ") && words.contains(&"cargo") && words.contains(&"build") {
        // Direct fixture/verifier/helper builds retain the largest current native
        // compiler cap. Managed driver/rehearsal builds have their own exact caps.
        return Some(60);
    }
    if command.starts_with("rustup run ") && words.contains(&"cargo") && words.contains(&"fmt") {
        return Some(15); // suites::CARGO_DEADLINE, same pinned format assertion
    }
    if command.ends_with(" ci policy") {
        return Some(60); // retained original complete policy-job work envelope
    }
    if command.ends_with(" ci workflow-scope") || command.ends_with(" ci performance-plan") {
        return Some(5); // bounded event/configuration parsing; no subprocess
    }
    if command.ends_with(" ci aggregate-stress") || command.ends_with(" ci aggregate-macos") {
        return Some(10); // finite selected phase reports; no workload execution
    }
    if words.first().is_some_and(|program| {
        program.ends_with("/consumer-readiness") || program.ends_with("/consumer-readiness.exe")
    }) {
        return match words.get(1).copied() {
            // consumer-readiness.rs Identity: Git30+archive60, bounded records.
            Some("identity") => Some(10),
            // Acquire's actual shared monotonic150min includes its15min child
            // cleanup; generation must group the later cleanup under that clock.
            Some("acquire") => Some(160),
            Some("cleanup") => Some(20),
            Some("seal-producer") => Some(10), // bounded local typed JSON/hash/fsync
            _ => None,
        };
    }
    if words.get(1) == Some(&"consumer-readiness-native-components") {
        return Some(if words.contains(&"--cleanup") {
            20
        } else {
            155
        });
    }
    if words.get(1) == Some(&"consumer-readiness-loader-diagnostic") {
        // original_loader_diagnostic: shared210s work +60s cleanup; outer room
        // includes the bounded production-owner/input reads before clock acquire.
        return Some(10);
    }
    if let Some((_, args)) = command.split_once(" release ") {
        let operation = args.split_whitespace().next()?;
        return match operation {
            // source::metadata is bounded120s; selection/recheck uses bounded Git
            // reads. These outer ceilings include bounded local data validation.
            "select" | "select-preparation" | "verify-source" => Some(15),
            // finalize.rs additionally runs policy and complete package metadata.
            "check-preparation" => Some(20),
            // No native process or compilation: exact bounded archive inputs and
            // byte-preserving artifact envelopes only (mod/finalize/bundle).
            "publication-tool" | "rehearsal-tool" => Some(10),
            "assemble" | "finalize-preparation" => Some(20),
            // PackageOutput::command is one30min cargo package invocation, with
            // selected-source metadata/rechecks and archive validation around it.
            "packages" => Some(45),
            // recovery::ORIGINAL_VALIDATION_BUDGET is5min plus exact source input.
            "recovery-inputs" => Some(15),
            // publish::run uses one20min transport deadline plus bounded bundle IO.
            "publish" => Some(30),
            // public_consumer: registry visibility5 + lock5 + downstream15 +
            // installation30 + actual CLI cases, all unchanged.
            "public-consumer" => Some(70),
            // read-only ordinary context/restore validates packaged sources,
            // compiler identity and original resolved metadata (5min queries).
            "consumer-cache" | "consumer-cache-context" | "prepare-restored-consumer-cache" => {
                Some(20)
            }
            // Installed channels retain the former full210min outer work ceiling:
            // actual Cargo builds/installation, optional predecessor and lifecycle.
            "installed-consumers" => Some(210),
            // The working Windows channel uses the accepted backend installed
            // production planning envelope as a newly enforced Actions step
            // guard. It is not a shared Rust clock or a child-deadline change.
            "working-windows-consumer" => Some(135),
            // readiness_report::run has an original15min verifier deadline.
            "consumer-readiness-report" => Some(20),
            _ => None,
        };
    }
    None
}
