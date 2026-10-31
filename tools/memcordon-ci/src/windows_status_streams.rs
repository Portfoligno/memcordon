//! Exact wrapper diagnostics for controlled Windows status fixtures.
use memcordon_core::execution_facts::OutcomeKindV1;

pub fn validate(
    stdout: &[u8],
    stderr: &[u8],
    status: i32,
    outcome: OutcomeKindV1,
    frontend_pid: Option<u32>,
    restricted: bool,
) -> Result<(), String> {
    if !stdout.is_empty() {
        return Err("controlled status fixture wrote unexpected workload stdout".into());
    }
    let mut expected = String::new();
    if matches!(status, 123..=125) {
        let label = match outcome {
            OutcomeKindV1::Completed => "child exited",
            OutcomeKindV1::Deadline => "deadline exceeded",
            OutcomeKindV1::ConfirmedMemoryLimit => "memory limit exceeded",
            _ => return Err("status fixture has unsupported summary outcome".into()),
        };
        expected.push_str(&format!(
            "memcordon: {label} {status}; backend windows-job-object; attempts 1; restarts 0\n"
        ));
    }
    if status != 0 {
        let pid = frontend_pid
            .filter(|pid| *pid != 0)
            .ok_or("nonzero status fixture lacks original held frontend identity")?;
        let code = status as u32;
        expected.push_str(&format!("native-frontend phase=inner-child-exited child-pid={pid} exit-code={code} exit-code-hex=0x{code:08x} restricted={restricted} system-environment=true\n"));
    }
    if stderr != expected.as_bytes() {
        return Err(format!(
            "controlled Windows wrapper diagnostics differ; expected-bytes={}; actual-bytes={}; status={status}",
            expected.len(),
            stderr.len()
        ));
    }
    Ok(())
}
