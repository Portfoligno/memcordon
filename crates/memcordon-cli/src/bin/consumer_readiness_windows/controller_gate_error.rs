//! Closed failure context for the existing controller wait boundary.
use std::{error::Error, fmt, io};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Open,
    Wait,
    PublishRelease,
}

struct BoundaryError {
    stage: Stage,
    wait_status: Option<u32>,
    original: io::Error,
    diagnostic: Option<String>,
}

impl fmt::Display for BoundaryError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (operation, access) = match self.stage {
            Stage::Open => ("OpenEventW-controller-wait", 0x0010_0000),
            Stage::Wait => ("WaitForSingleObject-controller-wait", 0x0010_0000),
            Stage::PublishRelease => ("controller-released-transcript", 0),
        };
        write!(
            out,
            "operation={operation}; access={access:#x}; kind={:?}; raw-os-error={:?}; wait-status={:?}",
            self.original.kind(),
            self.original.raw_os_error(),
            self.wait_status
        )?;
        if let Some(diagnostic) = &self.diagnostic {
            write!(out, "; failure-only-effective-token={diagnostic}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for BoundaryError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, out)
    }
}

impl Error for BoundaryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.original)
    }
}

pub fn context(stage: Stage, wait_status: Option<u32>, original: io::Error) -> io::Error {
    io::Error::new(
        original.kind(),
        BoundaryError {
            stage,
            wait_status,
            original,
            diagnostic: None,
        },
    )
}

pub fn open_diagnostic(original: io::Error, diagnostic: Result<String, io::Error>) -> io::Error {
    const DISPLAY_BOUND: usize = 64 * 1024;
    let diagnostic = match diagnostic {
        Ok(value) if value.len() <= DISPLAY_BOUND - 1024 => value,
        Ok(_) => "{\"observed\":false,\"reason\":\"diagnostic-bound-exceeded\"}".into(),
        Err(error) => format!(
            "{{\"observed\":false,\"reason\":\"diagnostic-encoding-failed\",\"kind\":\"{:?}\",\"raw_os_error\":{}}}",
            error.kind(),
            error
                .raw_os_error()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "null".into())
        ),
    };
    io::Error::new(
        original.kind(),
        BoundaryError {
            stage: Stage::Open,
            wait_status: None,
            original,
            diagnostic: Some(diagnostic),
        },
    )
}
