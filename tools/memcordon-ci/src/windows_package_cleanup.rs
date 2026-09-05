use crate::{CiError, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivePackageMutation {
    Upgrade,
    Uninstall,
}

impl ActivePackageMutation {
    pub fn argument(self) -> &'static str {
        match self {
            Self::Upgrade => "upgrade",
            Self::Uninstall => "uninstall",
        }
    }
}

/// Certify convergence before reporting a completed package mutation.
/// Provider removal must never be followed by a live recovery-pipe request.
pub fn certify_active_package_mutation(
    mutation: ActivePackageMutation,
    observe_active: impl FnOnce() -> Result<()>,
    mutate: impl FnOnce() -> Result<()>,
    await_completion: impl FnOnce() -> Result<()>,
    prove_present: impl FnOnce() -> Result<()>,
    prove_absent: impl FnOnce() -> Result<()>,
) -> Result<()> {
    observe_active()?;
    mutate()?;
    await_completion()?;
    match mutation {
        ActivePackageMutation::Upgrade => prove_present(),
        ActivePackageMutation::Uninstall => prove_absent(),
    }
}

pub fn complete_optional_install_cleanup<T, Inspect, Uninstall, ProveAbsent>(
    primary: Result<T>,
    inspect_installed_image: Inspect,
    uninstall: Uninstall,
    prove_absent: ProveAbsent,
) -> Result<T>
where
    Inspect: FnOnce() -> Result<bool>,
    Uninstall: FnOnce() -> Result<()>,
    ProveAbsent: FnOnce() -> Result<bool>,
{
    let uninstall = match inspect_installed_image() {
        Ok(true) => uninstall(),
        Ok(false) => Ok(()),
        Err(error) => Err(error),
    };
    let absence = prove_absent().and_then(|absent| {
        if absent {
            Ok(())
        } else {
            Err(CiError::Message(
                "rollback certification left provider state".to_owned(),
            ))
        }
    });
    let cleanup = uninstall.and(absence);
    match (primary, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(CiError::Message(format!(
            "{primary}; secondary cleanup failure: {cleanup}"
        ))),
    }
}
