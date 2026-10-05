//! Independent test-side arithmetic; these values never change production policy.
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetError {
    Overflow,
    InconsistentScenario,
}

pub fn sum(parts: &[Duration]) -> Result<Duration, BudgetError> {
    parts.iter().try_fold(Duration::ZERO, |total, part| {
        total.checked_add(*part).ok_or(BudgetError::Overflow)
    })
}

pub fn startup_deadline_guard(
    startup_cap: Duration,
    work_from_attempt_origin: Duration,
    retirement: Duration,
    delivery: Duration,
    margin: Duration,
) -> Result<Duration, BudgetError> {
    sum(&[
        startup_cap.min(work_from_attempt_origin),
        retirement,
        delivery,
        margin,
    ])
}

pub fn running_deadline_guard(
    work_from_attempt_origin: Duration,
    retirement: Duration,
    delivery: Duration,
    margin: Duration,
) -> Result<Duration, BudgetError> {
    sum(&[work_from_attempt_origin, retirement, delivery, margin])
}

pub fn natural_root_guard(
    startup_cap: Duration,
    root_exit_observation: Duration,
    retirement: Duration,
    delivery: Duration,
    margin: Duration,
    descendant_natural_lifetime: Duration,
) -> Result<Duration, BudgetError> {
    let guard = sum(&[
        startup_cap,
        root_exit_observation,
        retirement,
        delivery,
        margin,
    ])?;
    if guard >= descendant_natural_lifetime {
        return Err(BudgetError::InconsistentScenario);
    }
    Ok(guard)
}
