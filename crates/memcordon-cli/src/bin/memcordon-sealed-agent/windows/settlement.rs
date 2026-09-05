use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard, TryLockError};
use std::time::{Duration, Instant};

/// Tracks live durable-state writers independently of native Job handles.
/// A worker retains its lease through terminal publication and acknowledgment.
#[derive(Default)]
pub struct SettlementGate(RwLock<()>);

impl SettlementGate {
    pub fn enter(&self) -> Result<RwLockReadGuard<'_, ()>, String> {
        self.0
            .read()
            .map_err(|_| "launcher settlement gate is poisoned".to_owned())
    }

    /// The callback drives Job termination and checks preexisting admissions.
    /// The returned lease excludes writers throughout recovery and inventory.
    pub fn settle_until(
        &self,
        deadline: Instant,
        mut quiesce: impl FnMut() -> Result<bool, String>,
    ) -> Result<RwLockWriteGuard<'_, ()>, String> {
        loop {
            if quiesce()? {
                match self.0.try_write() {
                    Ok(lease) => return Ok(lease),
                    Err(TryLockError::WouldBlock) => {}
                    Err(TryLockError::Poisoned(_)) => {
                        return Err("launcher settlement gate is poisoned".to_owned());
                    }
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(
                    "phase=wait-launcher-settlement deadline expired before live writers and admissions retired"
                        .to_owned(),
                );
            }
            std::thread::sleep(Duration::from_millis(10).min(deadline - now));
        }
    }
}
