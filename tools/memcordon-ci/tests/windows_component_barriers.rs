#[path = "../src/windows_component_barriers.rs"]
mod barriers;

use barriers::ComponentBarriers;
use std::sync::{Arc, Mutex};

struct Event {
    name: String,
    closed: Arc<Mutex<Vec<String>>>,
}

impl Drop for Event {
    fn drop(&mut self) {
        self.closed.lock().unwrap().push(self.name.clone());
    }
}

#[test]
fn callback_completion_keeps_both_original_barriers_owned_until_outer_recovery_finishes() {
    let closed = Arc::new(Mutex::new(Vec::new()));
    let mut created = Vec::new();
    let owner = ComponentBarriers::create(Some("original-start"), true, |name| {
        created.push(name.to_owned());
        Ok(Event {
            name: name.to_owned(),
            closed: Arc::clone(&closed),
        })
    })
    .unwrap();
    assert_eq!(
        created,
        ["original-start", "original-start-toolchain-observer"]
    );
    let callback = owner.callback_start().unwrap();
    assert_eq!(callback.name, "original-start");
    drop(callback);
    assert!(closed.lock().unwrap().is_empty());
    // Model the existing outer retirement/recovery scope completing AFTER callback exit.
    drop(owner);
    assert_eq!(*closed.lock().unwrap(), created);
}

#[test]
fn absent_start_refuses_before_creation_and_observer_creation_failure_closes_only_owned_start() {
    let mut attempts = 0;
    assert!(
        ComponentBarriers::<()>::create(None, true, |_| {
            attempts += 1;
            Ok(())
        })
        .is_err()
    );
    assert_eq!(attempts, 0);
    let closed = Arc::new(Mutex::new(Vec::new()));
    let result = ComponentBarriers::create(Some("original-start"), true, |name| {
        if name.ends_with("-toolchain-observer") {
            return Err(std::io::Error::from_raw_os_error(183));
        }
        Ok(Event {
            name: name.to_owned(),
            closed: Arc::clone(&closed),
        })
    });
    assert_eq!(result.err().unwrap().raw_os_error(), Some(183));
    assert_eq!(*closed.lock().unwrap(), ["original-start"]);
    let none = ComponentBarriers::<()>::create(None, false, |_| {
        panic!("non-held case creates no barrier")
    })
    .unwrap();
    assert!(none.callback_start().is_none());
}

#[test]
fn diagnostic_failures_do_not_gate_actual_settlement_stages_or_renew_cutoff() {
    use barriers::{SettlementStage, settle};
    for failing in [
        "owner-status",
        "exact-invocation",
        "converge-invocation",
        "converge-result",
    ] {
        let closed = Arc::new(Mutex::new(Vec::new()));
        let owner = ComponentBarriers::create(Some("settlement-start"), true, |name| {
            Ok(Event {
                name: name.to_owned(),
                closed: Arc::clone(&closed),
            })
        })
        .unwrap();
        let cutoff = std::time::Instant::now();
        let mut stages = Vec::new();
        let result = settle(
            cutoff,
            |operation: String, diagnostic| format!("{operation}; diagnostic={diagnostic}"),
            |stage, received, diagnostics| {
                assert_eq!(received, cutoff);
                assert!(closed.lock().unwrap().is_empty());
                assert!(owner.callback_start().is_some());
                stages.push(stage);
                match stage {
                    SettlementStage::OwnerStatus if failing == "owner-status" => {
                        return Err("owner-status".to_owned());
                    }
                    SettlementStage::ExactRecovery => {
                        // The command callback is still reached if invocation persistence fails.
                        diagnostics.diagnostic(if failing == "exact-invocation" {
                            Err(failing.to_owned())
                        } else {
                            Ok(())
                        });
                    }
                    SettlementStage::Converge => {
                        diagnostics.diagnostic(if failing == "converge-invocation" {
                            Err(failing.to_owned())
                        } else {
                            Ok(())
                        });
                        diagnostics.diagnostic(if failing == "converge-result" {
                            Err(failing.to_owned())
                        } else {
                            Ok(())
                        });
                    }
                    _ => {}
                }
                Ok(())
            },
        );
        assert_eq!(
            stages,
            [
                SettlementStage::OwnerStatus,
                SettlementStage::ExactRecovery,
                SettlementStage::Converge,
                SettlementStage::HeldRetirement
            ]
        );
        assert_eq!(result, Err(failing.to_owned()));
        assert!(closed.lock().unwrap().is_empty());
        drop(owner);
        assert_eq!(closed.lock().unwrap().len(), 2);
    }
}

#[test]
fn original_operational_error_survives_diagnostic_failure_and_independent_convergence_runs() {
    use barriers::{SettlementStage, settle};
    let mut attempted = Vec::new();
    let cleanup = settle(
        7_u64,
        |operation, diagnostic| format!("{operation}; diagnostic={diagnostic}"),
        |stage, cutoff, errors| {
            assert_eq!(cutoff, 7);
            attempted.push(stage);
            match stage {
                SettlementStage::OwnerStatus => Err("owner-status-retention".to_owned()),
                SettlementStage::ExactRecovery => Err("authenticated-exact-recovery".to_owned()),
                _ => {
                    errors.diagnostic(Err::<(), _>("later-retention".to_owned()));
                    Ok(())
                }
            }
        },
    );
    assert_eq!(
        cleanup,
        Err("authenticated-exact-recovery; diagnostic=owner-status-retention".to_owned())
    );
    assert_eq!(attempted.len(), 4);
    let original_collection: Result<(), String> = Err("original-collection".to_owned());
    assert_eq!(
        original_collection.and(cleanup),
        Err("original-collection".to_owned())
    );
}
