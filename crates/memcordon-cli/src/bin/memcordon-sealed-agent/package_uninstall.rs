//! Keep package file compensation available until uninstall cleanup succeeds.

pub fn finish<T>(
    transaction: T,
    cleanup: impl FnOnce() -> Result<(), String>,
    commit: impl FnOnce(T) -> Result<(), String>,
    rollback: impl FnOnce(T) -> Result<(), String>,
    reload: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    match cleanup() {
        Ok(()) => commit(transaction),
        Err(primary) => {
            let restored = rollback(transaction);
            let reloaded = reload();
            match (restored, reloaded) {
                (Ok(()), Ok(())) => Err(primary),
                (restored, reloaded) => Err(format!(
                    "{primary}; package uninstall rollback={restored:?}; restored unit reload={reloaded:?}"
                )),
            }
        }
    }
}
