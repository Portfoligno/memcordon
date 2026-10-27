//! Settle original image owners after every collection result is captured.
use std::fmt::{Debug, Display};

pub fn finish<E: Debug + Display>(
    observed: Result<(), E>,
    diagnostics: Result<(), E>,
    normalized: Result<(), E>,
    settle: impl FnOnce() -> Result<(), E>,
) -> Result<(), String> {
    let custody = settle();
    if let Err(primary) = observed {
        return Err(format!(
            "{primary}; diagnostic-retention={diagnostics:?}; case-normalization={normalized:?}; image-custody-retirement={custody:?}"
        ));
    }
    if let Err(primary) = diagnostics {
        return Err(format!(
            "{primary}; case-normalization={normalized:?}; image-custody-retirement={custody:?}"
        ));
    }
    if let Err(primary) = normalized {
        return Err(format!("{primary}; image-custody-retirement={custody:?}"));
    }
    custody.map_err(|error| error.to_string())
}
