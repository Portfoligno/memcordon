//! Bounded context for the fixture-owned registry input's native failures.
use std::{error::Error, fmt, io};

const TEXT_BYTES: usize = 4096;
const LABEL_BYTES: usize = 128;

struct Text {
    text: String,
    remaining: usize,
    truncated: bool,
}
impl fmt::Write for Text {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let mut end = value.len().min(self.remaining);
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        self.text.push_str(&value[..end]);
        self.remaining -= end;
        if end != value.len() {
            self.truncated = true;
            return Err(fmt::Error);
        }
        Ok(())
    }
}
fn bounded(f: &mut fmt::Formatter<'_>, value: &dyn fmt::Display, limit: usize) -> fmt::Result {
    let mut text = Text {
        text: String::new(),
        remaining: limit,
        truncated: false,
    };
    let result = fmt::write(&mut text, format_args!("{value}"));
    f.write_str(&text.text)?;
    if text.truncated {
        f.write_str("[truncated]")
    } else {
        result
    }
}
fn native_code(error: &(dyn Error + 'static), remaining: &mut usize) -> Option<i32> {
    if *remaining == 0 {
        return None;
    }
    *remaining -= 1;
    if let Some(error) = error.downcast_ref::<io::Error>() {
        if let Some(code) = error.raw_os_error() {
            return Some(code);
        }
        if let Some(code) = error
            .get_ref()
            .and_then(|inner| native_code(inner, remaining))
        {
            return Some(code);
        }
    }
    error
        .source()
        .and_then(|inner| native_code(inner, remaining))
}

#[derive(Debug)]
struct Context {
    phase: &'static str,
    api: &'static str,
    domain: &'static str,
    access: Option<u32>,
    code: Option<i32>,
    original: io::Error,
}
impl fmt::Display for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("registry phase=")?;
        bounded(f, &self.phase, LABEL_BYTES)?;
        f.write_str("; API=")?;
        bounded(f, &self.api, LABEL_BYTES)?;
        f.write_str("; domain=")?;
        bounded(f, &self.domain, LABEL_BYTES)?;
        write!(
            f,
            "; native-code={:?}; access-mask={:?}; cause=",
            self.code, self.access
        )?;
        bounded(f, &self.original, TEXT_BYTES)
    }
}
impl Error for Context {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.original)
    }
}

pub fn at<T>(
    result: io::Result<T>,
    phase: &'static str,
    api: &'static str,
    domain: &'static str,
    access: Option<u32>,
) -> io::Result<T> {
    result.map_err(|original| {
        let code = native_code(&original, &mut 32);
        io::Error::new(
            original.kind(),
            Context {
                phase,
                api,
                domain,
                access,
                code,
                original,
            },
        )
    })
}

/// Both owned failures remain typed; the original operation remains primary.
#[derive(Debug)]
pub struct RegistryFailures {
    pub primary: io::Error,
    pub secondary: io::Error,
}
impl fmt::Display for RegistryFailures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        bounded(f, &self.primary, TEXT_BYTES)?;
        f.write_str("; independent owned registry cleanup: ")?;
        bounded(f, &self.secondary, TEXT_BYTES)
    }
}
impl Error for RegistryFailures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.primary)
    }
}
pub fn failures(primary: io::Error, secondary: io::Error) -> io::Error {
    io::Error::new(primary.kind(), RegistryFailures { primary, secondary })
}

/// Classify only the unwrapped native denial; contextual failures are not proof.
pub fn require_access_denied<T>(
    result: io::Result<T>,
    phase: &'static str,
    api: &'static str,
    access: Option<u32>,
) -> io::Result<()> {
    match result {
        Err(error) if error.raw_os_error() == Some(5) => Ok(()),
        Err(error) => at(Err(error), phase, api, "LSTATUS", access),
        Ok(value) => {
            drop(value);
            at(
                Err(io::Error::other(
                    "sealed registry input permits mutation access",
                )),
                phase,
                api,
                "LSTATUS",
                access,
            )
        }
    }
}
