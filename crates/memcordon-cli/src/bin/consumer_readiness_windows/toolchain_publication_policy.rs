//! Checks observations supplied by the owner of the original file handles.
//! These facts alone do not confer ownership of a pathname.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub volume: u32,
    pub index: u64,
    pub attributes: u32,
    pub links: u32,
    pub length: u64,
}

pub fn destination(
    expected: Option<&Identity>,
    actual: Option<&Identity>,
) -> Result<(), &'static str> {
    match (expected, actual) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err("diagnostic destination was not created by this execution"),
        (Some(_), None) => Err("owned diagnostic destination disappeared"),
        (Some(expected), Some(actual)) => {
            if actual.attributes & (0x10 | 0x400) != 0 || actual.links != 1 {
                return Err("diagnostic destination is not an ordinary single-link file");
            }
            if expected != actual {
                return Err("diagnostic destination differs from original held file");
            }
            Ok(())
        }
    }
}
