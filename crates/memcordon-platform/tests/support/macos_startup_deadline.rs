use super::*;

#[derive(Debug)]
pub struct StartupDeadlineObservations {
    pub kind: io::ErrorKind,
    pub diagnostic: memcordon_core::NativeStartupDiagnosticV1,
    pub release: memcordon_core::ReleaseEvidence,
    pub terminal_observed: Option<u64>,
    pub retirement_observed: Option<u64>,
    pub work_expires: u64,
    pub published_at: u64,
    pub cleanup_observations: Vec<serde_json::Value>,
}

pub fn startup_deadline_observations(
    command: &CommandSpec,
    image: &Path,
) -> Result<StartupDeadlineObservations, String> {
    // This fixture must reach configured guardian readiness before expiry;
    // the public CLI regression independently retains its 100 ms cutoff.
    let budget = Duration::from_secs(1);
    let work = crate::macos_deadline::continuous_nanos()
        .and_then(|now| crate::macos_deadline::add(now, budget))
        .map_err(|error| error.to_string())?;
    let deadline = Instant::now() + budget;
    match launch_configured(
        command,
        image,
        deadline,
        deadline + Duration::from_secs(3),
        LaunchConfiguration {
            runtime: None,
            fault: Some(LaunchFault::GuardianReadyExpiredRetirementDelayed),
            work: Some(work),
            grace: Duration::ZERO,
            signal: None,
        },
    ) {
        Err(error) => {
            // Publication latency must not replace either native receipt.
            std::thread::sleep(Duration::from_millis(500));
            Ok(StartupDeadlineObservations {
                kind: error.error.kind(),
                diagnostic: error.diagnostic,
                release: error.release,
                terminal_observed: error.terminal_observed,
                retirement_observed: error.retirement_observed,
                work_expires: work,
                published_at: crate::macos_deadline::continuous_nanos()
                    .map_err(|error| error.to_string())?,
                cleanup_observations: error
                    .cleanup_observations
                    .iter()
                    .map(serde_json::to_value)
                    .collect::<Result<_, _>>()
                    .map_err(|error| error.to_string())?,
            })
        }
        Ok(mut launch) => {
            let _ = launch.child.kill();
            drop(launch.guardian);
            let _ = launch.child.retire(Instant::now() + Duration::from_secs(3));
            Err("delayed startup retirement unexpectedly authorized the target".into())
        }
    }
}

pub fn startup_deadline_fault(
    command: &CommandSpec,
    image: &Path,
    fault: LaunchFault,
) -> Result<
    (
        io::ErrorKind,
        memcordon_core::NativeStartupDiagnosticV1,
        memcordon_core::ReleaseEvidence,
    ),
    String,
> {
    let observation = startup_deadline_fault_observations(command, image, fault)?;
    Ok((
        observation.kind,
        observation.diagnostic,
        observation.release,
    ))
}

pub fn startup_deadline_fault_observations(
    command: &CommandSpec,
    image: &Path,
    fault: LaunchFault,
) -> Result<StartupDeadlineObservations, String> {
    let budget = Duration::from_secs(1);
    let work = crate::macos_deadline::continuous_nanos()
        .and_then(|now| crate::macos_deadline::add(now, budget))
        .map_err(|error| error.to_string())?;
    let deadline = Instant::now() + budget;
    match launch_configured(
        command,
        image,
        deadline,
        deadline + Duration::from_secs(3),
        LaunchConfiguration {
            runtime: None,
            fault: Some(fault),
            work: Some(work),
            grace: Duration::ZERO,
            signal: None,
        },
    ) {
        Err(error) => Ok(StartupDeadlineObservations {
            kind: error.error.kind(),
            diagnostic: error.diagnostic,
            release: error.release,
            terminal_observed: error.terminal_observed,
            retirement_observed: error.retirement_observed,
            work_expires: work,
            published_at: crate::macos_deadline::continuous_nanos()
                .map_err(|error| error.to_string())?,
            cleanup_observations: error
                .cleanup_observations
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<_, _>>()
                .map_err(|error| error.to_string())?,
        }),
        Ok(mut launch) => {
            let _ = launch.child.kill();
            drop(launch.guardian);
            let _ = launch.child.retire(Instant::now() + Duration::from_secs(3));
            Err("injected startup deadline unexpectedly authorized the target".into())
        }
    }
}
