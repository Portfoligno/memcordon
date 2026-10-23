use memcordon_ci::release::linux_recovery_owners::{Owners, await_retirement};
use memcordon_readiness_verifier::HeldProcessIdentity;
use std::time::{Duration, Instant};

fn owners(frontend_retired: bool, worker_retired: bool) -> Owners {
    let identity = |pid, retirement_observed| HeldProcessIdentity {
        pid,
        birth: u64::from(pid) + 100,
        parent_pid: Some(1),
        parent_birth: Some(7),
        retirement_observed,
    };
    Owners {
        frontend: identity(10, frontend_retired),
        worker: identity(20, worker_retired),
    }
}

#[test]
fn exclusive_lease_is_not_a_substitute_for_both_original_owner_retirements() {
    // A worker can release its shared lease during unwind but still be alive.
    // The actual producer uses this same seam with only its original held pidfds.
    let mut observations = [owners(true, false), owners(true, true)].into_iter();
    let mut calls = 0;
    let result = await_retirement(
        owners(false, false),
        Instant::now() + Duration::from_secs(1),
        || {
            calls += 1;
            Ok(observations
                .next()
                .expect("must stop after both original owners retire"))
        },
    );
    assert!(result.retired);
    assert_eq!(calls, 2);
    assert!(!result.before.worker.retirement_observed);
    assert!(result.after.worker.retirement_observed);
}

#[test]
fn original_cutoff_and_foreign_identity_never_authorize_recovery() {
    let result = await_retirement(owners(true, false), Instant::now(), || {
        panic!("expired original cutoff must not sample or renew")
    });
    assert!(!result.retired);
    assert!(result.reason.contains("original cleanup cutoff expired"));
    for role in ["frontend", "worker"] {
        for field in ["pid", "birth", "parent_pid", "parent_birth"] {
            let mut foreign = owners(true, true);
            let identity = if role == "frontend" {
                &mut foreign.frontend
            } else {
                &mut foreign.worker
            };
            match field {
                "pid" => identity.pid += 1,
                "birth" => identity.birth += 1,
                "parent_pid" => identity.parent_pid = Some(2),
                "parent_birth" => identity.parent_birth = Some(8),
                _ => unreachable!(),
            }
            let result = await_retirement(
                owners(false, false),
                Instant::now() + Duration::from_secs(1),
                || Ok(foreign.clone()),
            );
            assert!(!result.retired, "{role}/{field}");
            assert!(result.reason.contains("identity changed"));
        }
    }
    let result = await_retirement(
        owners(false, false),
        Instant::now() + Duration::from_secs(1),
        || Err("actual held pidfd poll failed".into()),
    );
    assert!(!result.retired);
    assert!(result.reason.contains("actual held pidfd poll failed"));
}
