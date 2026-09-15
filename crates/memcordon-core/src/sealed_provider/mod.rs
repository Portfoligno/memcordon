//! Versioned provider wire and inspection contracts shared by shipped helpers,
//! integration tests, and fuzz harnesses. These modules carry no OS authority.

pub mod cgroup_membership;
pub mod envelope;
#[cfg(feature = "test-support")]
pub mod fingerprint;
pub mod inspection;
pub mod protocol;
pub mod qualification;
pub mod request;
pub mod terminal;
