//! A same-account attempt cannot dispatch its successor before measured recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Attempt,
    Recovery,
}
impl Stage {
    pub fn phase(self) -> &'static str {
        match self {
            Self::Attempt => "export-case",
            Self::Recovery => "export-recovery",
        }
    }
}
pub struct Failure<'a, E> {
    pub scenario: &'a str,
    pub stage: Stage,
    pub error: E,
}

pub fn run<'a, T, E>(
    owner: &mut T,
    scenarios: &[&'a str],
    mut attempt: impl FnMut(&mut T, &str) -> Result<(), E>,
    mut recover: impl FnMut(&mut T) -> Result<(), E>,
) -> Result<(), Failure<'a, E>> {
    for &scenario in scenarios {
        attempt(owner, scenario).map_err(|error| Failure {
            scenario,
            stage: Stage::Attempt,
            error,
        })?;
        recover(owner).map_err(|error| Failure {
            scenario,
            stage: Stage::Recovery,
            error,
        })?;
    }
    Ok(())
}
