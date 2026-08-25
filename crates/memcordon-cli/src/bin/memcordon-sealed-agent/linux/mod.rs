pub mod attempt;
pub mod cgroup;
mod cgroup_membership;
pub mod clock;
pub mod envelope;
pub mod guardian;
pub mod launch;
pub mod launcher;
pub mod namespace;
pub mod qualification;
mod qualification_schema;
pub mod recovery;
pub mod service;
pub mod startup;
pub mod transport;

pub const SOCKET_PATH: &str = "/run/memcordon/sealed-agent.sock";
pub const STATE_ROOT: &str = "/var/lib/memcordon/sealed";
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup/memcordon-sealed";
