use std::collections::BTreeMap;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug)]
struct SettlementLeaseEntry {
    owner: Option<(u32, u64)>,
    attempt_id: Option<String>,
}

#[derive(Debug, Default)]
struct SettlementState {
    exclusive: bool,
    poisoned: bool,
    next_id: u64,
    leases: BTreeMap<u64, SettlementLeaseEntry>,
}

/// Tracks live durable-state writers independently of native Job handles.
/// A worker retains its lease through terminal publication and acknowledgment.
#[derive(Debug, Default)]
pub struct SettlementGate {
    state: Mutex<SettlementState>,
    changed: Condvar,
}

#[derive(Debug)]
pub struct SettlementReadLease<'a> {
    gate: &'a SettlementGate,
    id: u64,
}

impl Drop for SettlementReadLease<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.gate.state.lock() {
            state.leases.remove(&self.id);
            if state.leases.is_empty() {
                self.gate.changed.notify_all();
            }
        }
    }
}

#[derive(Debug)]
pub struct SettlementWriteLease<'a> {
    gate: &'a SettlementGate,
}

impl Drop for SettlementWriteLease<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.gate.state.lock() {
            if std::thread::panicking() {
                state.poisoned = true;
            } else {
                state.exclusive = false;
            }
            self.gate.changed.notify_all();
        }
    }
}

impl SettlementGate {
    pub fn enter(&self) -> Result<SettlementReadLease<'_>, String> {
        self.enter_inner(None, None)
    }

    #[allow(dead_code)]
    pub fn enter_owned(
        &self,
        owner: (u32, u64),
        attempt_id: Option<String>,
    ) -> Result<SettlementReadLease<'_>, String> {
        self.enter_inner(Some(owner), attempt_id)
    }

    fn enter_inner(
        &self,
        owner: Option<(u32, u64)>,
        attempt_id: Option<String>,
    ) -> Result<SettlementReadLease<'_>, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "launcher settlement gate is poisoned".to_owned())?;
        while state.exclusive && !state.poisoned {
            state = self
                .changed
                .wait(state)
                .map_err(|_| "launcher settlement gate is poisoned".to_owned())?;
        }
        if state.poisoned {
            return Err("launcher settlement gate is poisoned".to_owned());
        }
        let id = state.next_id;
        state.next_id = state
            .next_id
            .checked_add(1)
            .ok_or_else(|| "launcher settlement lease sequence exhausted".to_owned())?;
        state
            .leases
            .insert(id, SettlementLeaseEntry { owner, attempt_id });
        Ok(SettlementReadLease { gate: self, id })
    }

    /// The callback drives Job termination and checks preexisting admissions.
    /// The returned lease excludes writers throughout recovery and inventory.
    pub fn settle_until(
        &self,
        deadline: Instant,
        quiesce: impl FnMut() -> Result<bool, String>,
    ) -> Result<SettlementWriteLease<'_>, String> {
        self.settle_until_reclaiming(deadline, quiesce, |_, _| false)
    }

    /// Same as `settle_until`, except that after `quiesce` succeeds, any
    /// remaining attempt-scoped lease whose owner thread and durable-state
    /// publication are proved extinct by `can_reclaim` is reclaimed.
    #[allow(dead_code)]
    pub fn settle_until_reclaiming(
        &self,
        deadline: Instant,
        mut quiesce: impl FnMut() -> Result<bool, String>,
        mut can_reclaim: impl FnMut((u32, u64), &str) -> bool,
    ) -> Result<SettlementWriteLease<'_>, String> {
        let started = Instant::now();
        let requested = deadline.saturating_duration_since(started);
        loop {
            let quiescent = quiesce()?;
            let mut exclusive_attempted = false;
            let mut exclusive_would_block = false;
            if quiescent {
                exclusive_attempted = true;
                let candidates = {
                    let mut state = self
                        .state
                        .lock()
                        .map_err(|_| "launcher settlement gate is poisoned".to_owned())?;
                    if state.poisoned {
                        return Err("launcher settlement gate is poisoned".to_owned());
                    }
                    if !state.exclusive && state.leases.is_empty() {
                        state.exclusive = true;
                        return Ok(SettlementWriteLease { gate: self });
                    }
                    if state.exclusive {
                        Vec::new()
                    } else {
                        state
                            .leases
                            .iter()
                            .filter_map(|(&id, entry)| {
                                Some((id, entry.owner?, entry.attempt_id.clone()?))
                            })
                            .collect::<Vec<_>>()
                    }
                };
                if !candidates.is_empty() {
                    let reclaimable: Vec<(u64, (u32, u64), String)> = candidates
                        .into_iter()
                        .filter(|&(_, owner, ref attempt_id)| can_reclaim(owner, attempt_id))
                        .collect();
                    if !reclaimable.is_empty() {
                        let mut state = self
                            .state
                            .lock()
                            .map_err(|_| "launcher settlement gate is poisoned".to_owned())?;
                        if state.poisoned {
                            return Err("launcher settlement gate is poisoned".to_owned());
                        }
                        for (id, owner, attempt_id) in reclaimable {
                            let matches = state.leases.get(&id).is_some_and(|entry| {
                                entry.owner == Some(owner)
                                    && entry.attempt_id.as_deref() == Some(attempt_id.as_str())
                            });
                            if matches {
                                state.leases.remove(&id);
                            }
                        }
                        if !state.exclusive && state.leases.is_empty() {
                            state.exclusive = true;
                            return Ok(SettlementWriteLease { gate: self });
                        }
                    }
                }
                exclusive_would_block = true;
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(format!(
                    "phase=wait-launcher-settlement deadline expired before live writers and admissions retired; last-quiesce={quiescent}; last-exclusive-attempted={exclusive_attempted}; last-exclusive-would-block={exclusive_would_block}; elapsed-ms={}; requested-ms={}",
                    now.saturating_duration_since(started).as_millis(),
                    requested.as_millis(),
                ));
            }
            std::thread::sleep(Duration::from_millis(10).min(deadline - now));
        }
    }
}
