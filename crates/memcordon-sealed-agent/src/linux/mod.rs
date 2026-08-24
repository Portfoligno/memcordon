pub mod attempt;
pub mod cgroup;
pub mod clock;
pub mod guardian;
pub mod launch;
pub mod namespace;
pub mod qualification;
pub mod recovery;
pub mod service;
pub mod startup;
pub mod transport;

pub const SOCKET_PATH: &str = "/run/memcordon/sealed-agent.sock";
pub const STATE_ROOT: &str = "/var/lib/memcordon/sealed";
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup/memcordon-sealed";
