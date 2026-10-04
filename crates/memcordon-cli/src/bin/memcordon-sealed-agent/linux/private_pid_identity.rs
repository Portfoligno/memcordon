//! Read-only PID mapping from the initially transferred, gated target pidfd.

// Linux permits 32 nested PID namespaces, plus the procfs-visible root.
const MAX_PID_NAMESPACE_DEPTH: usize = 32;

/// Kernel mapping pinned while the target is gated. The journal names the
/// host PID; the task-affine init observer names the namespace-local PID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateNamespaceTargetIdentity {
    host_pid: i32,
    namespace_pid: i32,
}

impl PrivateNamespaceTargetIdentity {
    pub fn host_pid(self) -> i32 {
        self.host_pid
    }

    pub fn require_exec_pid(
        self,
        journal_host_pid: u32,
        observed_namespace_pid: i32,
    ) -> Result<(), String> {
        if self.host_pid as u32 == journal_host_pid && self.namespace_pid == observed_namespace_pid
        {
            Ok(())
        } else {
            Err("MCSEALED-PRIVATE-EXEC: init exec-event association differs".into())
        }
    }
}

pub fn parse_target_pidfd_identity(
    contents: &str,
) -> Result<PrivateNamespaceTargetIdentity, String> {
    let unique_field = |prefix: &str| -> Result<&str, String> {
        let mut values = contents
            .lines()
            .filter_map(|line| line.strip_prefix(prefix));
        let value = values
            .next()
            .ok_or("MCSEALED-PRIVATE-INIT: pidfd identity field absent")?;
        if values.next().is_some() {
            return Err("MCSEALED-PRIVATE-INIT: ambiguous pidfd identity field".into());
        }
        Ok(value)
    };
    let positive_pid = |value: &str| -> Result<i32, String> {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("MCSEALED-PRIVATE-INIT: invalid pidfd PID".into());
        }
        let pid = value
            .parse::<i32>()
            .map_err(|_| "MCSEALED-PRIVATE-INIT: invalid pidfd PID")?;
        if pid <= 0 {
            return Err("MCSEALED-PRIVATE-INIT: pidfd target not visible to provider".into());
        }
        Ok(pid)
    };
    let host_pid = positive_pid(unique_field("Pid:")?.trim_ascii())?;
    let mut namespace_pid = None;
    for (index, value) in unique_field("NSpid:")?.split_ascii_whitespace().enumerate() {
        if index > MAX_PID_NAMESPACE_DEPTH {
            return Err("MCSEALED-PRIVATE-INIT: pidfd namespace depth exceeds kernel bound".into());
        }
        let pid = positive_pid(value)?;
        if index == 0 && pid != host_pid {
            return Err("MCSEALED-PRIVATE-INIT: pidfd host and namespace PID differ".into());
        }
        namespace_pid = Some(pid);
    }
    Ok(PrivateNamespaceTargetIdentity {
        host_pid,
        namespace_pid: namespace_pid.ok_or("MCSEALED-PRIVATE-INIT: empty pidfd namespace PID")?,
    })
}
