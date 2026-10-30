//! Source-controlled arguments for actual Linux installed fixture operations.
use crate::{CiError, Result};
use memcordon_core::{identifiers::LogicalId, workload_files::RootRelativePath};
use std::path::Path;
use std::time::Duration;
#[derive(Clone, Debug)]
pub struct ScenarioName {
    pub family: String,
    pub scenario: String,
}
#[derive(Clone)]
pub struct Scenario {
    pub key: ScenarioName,
    pub mode: String,
    pub arguments: Vec<std::ffi::OsString>,
    pub requirements: Vec<memcordon_core::workload_requirements::RequirementRequestV1>,
    pub output_files: Vec<RootRelativePath>,
    pub memory: std::ffi::OsString,
    pub product_deadline: std::ffi::OsString,
    pub observation_limit: Duration,
}

/// Actual fixture operations selected directly by this invocation.
pub fn scenarios() -> Result<Vec<Scenario>> {
    use memcordon_core::workload_requirements::{
        DeniedOperationRequestV1 as D, LocalPortRequestV1, PrivatePeerRequestV1,
        RequirementRequestV1 as R,
    };
    let tcp = R::TcpListener {
        id: id("tcp")?,
        local_port: LocalPortRequestV1::KernelAssigned,
        peer: PrivatePeerRequestV1::DynamicLoopbackWithinThisAttempt,
    };
    let unix = vec![
        R::UnixStreamPair { id: id("pair")? },
        R::UnixPathStream {
            id: id("pathname")?,
            writable_root: id("work")?,
        },
        R::UnixAbstractStream {
            id: id("abstract")?,
        },
        R::IntraAttemptDescriptorTransfer { id: id("rights")? },
    ];
    let child_error_pair = R::UnixSeqpacketPair {
        id: id("child-error-pair")?,
    };
    let mut result = Vec::new();
    let mut add = |family: &str,
                   scenario: &str,
                   mode: &str,
                   args: Vec<std::ffi::OsString>,
                   mut requirements: Vec<R>,
                   outputs: Vec<RootRelativePath>,
                   deadline: &str| {
        if requirements
            .iter()
            .any(|requirement| matches!(requirement, R::GeneratedExecutable { .. }))
        {
            requirements.push(child_error_pair.clone());
        }
        result.push(Scenario {
            key: ScenarioName {
                family: family.into(),
                scenario: scenario.into(),
            },
            mode: mode.into(),
            arguments: args,
            requirements,
            output_files: outputs,
            memory: "+2GiB".into(),
            product_deadline: deadline.into(),
            observation_limit: Duration::from_secs(600),
        });
    };
    let mut joint = vec![tcp.clone()];
    joint.extend(unix.clone());
    joint.push(R::GeneratedExecutable {
        id: id("generated")?,
        writable_root: id("work")?,
    });
    let build_args = vec![
        "/work",
        "/toolchain/bin/cargo",
        "/toolchain/bin/rustc",
        "/usr/bin/cc",
        "/owned-source/Cargo.toml",
    ]
    .into_iter()
    .map(std::ffi::OsString::from)
    .collect::<Vec<_>>();
    let exports = [
        "generated-readiness-artifact.bin",
        "generated-child-executable.bin",
        "generated-child-created.json",
        "generated-child-retired.json",
    ]
    .iter()
    .map(|name| path(&Path::new("work").join(name)))
    .collect::<Result<Vec<_>>>()?;
    add(
        "L-MIX-01",
        "joint-build-tcp-unix-http",
        "joint",
        build_args.clone(),
        joint.clone(),
        exports.clone(),
        "+300s",
    );
    add(
        "L-IMG-03",
        "dynamic-rust-build-and-exec",
        "joint",
        build_args.clone(),
        joint.clone(),
        exports.clone(),
        "+300s",
    );
    add(
        "L-IMG-03",
        "image-only-entrypoint",
        "joint",
        build_args.clone(),
        joint.clone(),
        exports,
        "+300s",
    );
    for scenario in ["deadline", "memory", "cancellation", "reserved-target-exit"] {
        add(
            "L-LIFE-03",
            scenario,
            match scenario {
                "memory" => "joint-memory",
                "reserved-target-exit" => "joint-reserved-exit",
                _ => "joint",
            },
            build_args.clone(),
            joint.clone(),
            Vec::new(),
            "+300s",
        );
    }
    add(
        "C-STATUS",
        "memory",
        "population-deadline",
        Vec::new(),
        Vec::new(),
        Vec::new(),
        "+300s",
    );
    add(
        "L-MIX-02",
        "endpoint-mismatch",
        "endpoint-mismatch",
        Vec::new(),
        vec![tcp.clone()],
        Vec::new(),
        "+30s",
    );
    add(
        "L-MIX-03",
        "listener-and-file-transfer",
        "unix-rights",
        vec!["/work".into()],
        unix.clone(),
        Vec::new(),
        "+30s",
    );
    add(
        "L-MIX-04",
        "cooperation",
        "cooperation",
        Vec::new(),
        vec![tcp.clone()],
        Vec::new(),
        "+30s",
    );
    add(
        "C-IO",
        "binary-streams",
        "raw-byte-streams",
        Vec::new(),
        Vec::new(),
        Vec::new(),
        "+30s",
    );
    add(
        "L-MIX-05",
        "binary-streams",
        "raw-byte-streams",
        Vec::new(),
        Vec::new(),
        Vec::new(),
        "+30s",
    );
    for family in ["C-IO", "L-MIX-05"] {
        add(
            family,
            "empty-message",
            "empty-message",
            Vec::new(),
            vec![R::UnixStreamPair {
                id: id("empty-pair")?,
            }],
            Vec::new(),
            "+30s",
        );
    }
    add(
        "C-IO",
        "binary-file",
        "binary-file",
        Vec::new(),
        Vec::new(),
        vec![path(Path::new("work/binary-file.bin"))?],
        "+30s",
    );
    for family in ["C-IO", "L-MIX-05"] {
        add(
            family,
            "empty-input",
            "empty-input",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            "+30s",
        );
        add(
            family,
            "bounded-large-output",
            "bounded-large-output",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            "+30s",
        );
    }
    for (scenario, mode, operation) in [
        ("ipv6", "authority-denial", D::Inet6),
        ("udp", "authority-denial", D::Udp),
        ("raw", "authority-denial", D::Raw),
        ("packet", "authority-denial", D::Packet),
        ("netlink", "authority-denial", D::Netlink),
    ] {
        add(
            "L-ISO-01",
            scenario,
            mode,
            vec![scenario.into()],
            vec![
                tcp.clone(),
                R::ExpectedDenial {
                    id: id("denial")?,
                    operation,
                },
            ],
            Vec::new(),
            "+30s",
        );
    }
    add(
        "L-ISO-01",
        "host-tcp",
        "forbidden-tcp",
        Vec::new(),
        vec![
            tcp.clone(),
            R::ExpectedDenial {
                id: id("host-tcp-denial")?,
                operation: D::HostTcp,
            },
        ],
        Vec::new(),
        "+30s",
    );
    add(
        "L-ISO-01",
        "nonloopback",
        "forbidden-tcp",
        Vec::new(),
        vec![
            tcp.clone(),
            R::ExpectedDenial {
                id: id("nonloopback-denial")?,
                operation: D::HostTcp,
            },
        ],
        Vec::new(),
        "+30s",
    );
    add(
        "L-ISO-03",
        "host-abstract",
        "forbidden-abstract",
        Vec::new(),
        vec![
            tcp.clone(),
            R::ExpectedDenial {
                id: id("host-abstract-denial")?,
                operation: D::HostUnixAbstract,
            },
        ],
        Vec::new(),
        "+30s",
    );
    add(
        "L-ISO-03",
        "other-attempt-abstract",
        "forbidden-abstract",
        Vec::new(),
        vec![
            R::UnixAbstractStream {
                id: id("own-abstract")?,
            },
            R::ExpectedDenial {
                id: id("other-attempt-denial")?,
                operation: D::OtherAttempt,
            },
        ],
        Vec::new(),
        "+30s",
    );
    for scenario in ["host-run-socket", "host-temp-socket"] {
        add(
            "L-ISO-02",
            scenario,
            "forbidden-unix-path",
            Vec::new(),
            vec![
                R::UnixStreamPair { id: id("pair")? },
                R::ExpectedDenial {
                    id: id("host-path-denial")?,
                    operation: D::HostUnixPath,
                },
            ],
            Vec::new(),
            "+30s",
        );
    }
    for scenario in ["input-socket", "imported-socket", "caller-writable-tree"] {
        add(
            "L-ISO-02",
            scenario,
            "forbidden-unix-path",
            Vec::new(),
            vec![R::UnixStreamPair { id: id("pair")? }],
            Vec::new(),
            "+30s",
        );
    }
    add(
        "L-ISO-03",
        "own-abstract-positive",
        "own-abstract",
        Vec::new(),
        vec![R::UnixAbstractStream {
            id: id("own-abstract")?,
        }],
        Vec::new(),
        "+30s",
    );
    add(
        "L-ISO-06",
        "same-uid-process",
        "tcp-http",
        Vec::new(),
        vec![tcp.clone()],
        Vec::new(),
        "+30s",
    );
    add(
        "L-ISO-06",
        "account-alias",
        "tcp-http",
        Vec::new(),
        vec![tcp.clone()],
        Vec::new(),
        "+30s",
    );
    add(
        "L-ISO-06",
        "stale-reservation",
        "tcp-http",
        Vec::new(),
        vec![tcp.clone()],
        Vec::new(),
        "+30s",
    );
    for (scenario, operation) in [
        ("pidfd-getfd", D::ProcessImport),
        ("ptrace", D::ProcessImport),
        ("namespace-entry", D::NamespaceEntry),
    ] {
        add(
            "L-ISO-05",
            scenario,
            "authority-denial",
            vec![scenario.into()],
            vec![
                tcp.clone(),
                R::ExpectedDenial {
                    id: id("denial")?,
                    operation,
                },
            ],
            Vec::new(),
            "+30s",
        );
    }
    for scenario in ["stdio-host-socket", "extra-host-fd"] {
        add(
            "L-ISO-05",
            scenario,
            "descriptor-isolation",
            Vec::new(),
            vec![R::UnixStreamPair { id: id("pair")? }],
            Vec::new(),
            "+30s",
        );
    }
    for (scenario, status) in [
        ("zero", 0),
        ("nonzero", 42),
        ("exit-123", 123),
        ("exit-124", 124),
        ("exit-125", 125),
        ("exit-126", 126),
        ("exit-127", 127),
    ] {
        add(
            "C-STATUS",
            scenario,
            "bytes-argv-status",
            vec![status.to_string().into()],
            Vec::new(),
            Vec::new(),
            "+30s",
        );
    }
    add(
        "C-PARSER",
        "valid-current-result",
        "bytes-argv-status",
        vec!["0".into()],
        Vec::new(),
        Vec::new(),
        "+30s",
    );
    let orphan_output = vec![
        path(Path::new("work/orphan-descendant.bin"))?,
        path(Path::new("work/orphan-completion.json"))?,
    ];
    for actor in ["frontend", "worker", "guardian", "control"] {
        for phase in ["allocation", "release", "drain"] {
            add(
                "L-LIFE-02",
                &format!("{actor}-{phase}"),
                if phase == "drain" {
                    "root-first"
                } else {
                    "held-tree"
                },
                Vec::new(),
                Vec::new(),
                if phase == "drain" {
                    orphan_output.clone()
                } else {
                    Vec::new()
                },
                "+300s",
            );
        }
    }
    add(
        "L-LIFE-01",
        "root-first-resource-descendant",
        "root-first",
        Vec::new(),
        Vec::new(),
        orphan_output.clone(),
        "+30s",
    );
    add(
        "L-LIFE-05",
        "relay-backpressure",
        "relay-backpressure",
        Vec::new(),
        Vec::new(),
        Vec::new(),
        "+30s",
    );
    for scenario in [
        "symlink",
        "dotdot",
        "proc-root",
        "proc-cwd",
        "proc-fd",
        "hardlink",
        "opath",
        "mount-alias",
    ] {
        add(
            "L-ISO-04",
            scenario,
            "outside-file",
            vec![scenario.into()],
            Vec::new(),
            Vec::new(),
            "+30s",
        );
    }
    add(
        "L-LIFE-05",
        "report-persistence-failure",
        "bytes-argv-status",
        vec!["0".into()],
        Vec::new(),
        Vec::new(),
        "+300s",
    );
    add(
        "C-LIFETIME",
        "root-first",
        "root-first",
        Vec::new(),
        Vec::new(),
        orphan_output,
        "+30s",
    );
    add(
        "C-STATUS",
        "deadline",
        "population-deadline",
        Vec::new(),
        Vec::new(),
        Vec::new(),
        "+2s",
    );
    add(
        "C-ADMISSION",
        "positive",
        "tcp-http",
        Vec::new(),
        vec![tcp.clone()],
        Vec::new(),
        "+30s",
    );
    use std::os::unix::ffi::OsStringExt;
    add(
        "C-IO",
        "native-argv",
        "bytes-argv-status",
        vec![
            "0".into(),
            "".into(),
            "white space".into(),
            "tab\toperand".into(),
            "embedded\"quote".into(),
            "trailing\\".into(),
            std::ffi::OsString::from_vec(vec![0x61, 0xff, 0x62]),
        ],
        Vec::new(),
        Vec::new(),
        "+30s",
    );
    let mut generated = result
        .iter()
        .find(|scenario| scenario.key.family == "L-MIX-01")
        .ok_or_else(|| CiError::Message("actual generated joint fixture operation absent".into()))?
        .clone();
    generated.key = ScenarioName {
        family: "L-ID-01".into(),
        scenario: "generated-descendants".into(),
    };
    result.push(generated);
    for scenario in [
        "fixed-sandbox-credentials",
        "empty-groups-and-capabilities",
        "unprivileged-caller-inputs",
    ] {
        result.push(Scenario {
            key: ScenarioName {
                family: "L-ID-01".into(),
                scenario: scenario.into(),
            },
            mode: "bytes-argv-status".into(),
            arguments: vec!["0".into()],
            requirements: Vec::new(),
            output_files: Vec::new(),
            memory: "+128MiB".into(),
            product_deadline: "+30s".into(),
            observation_limit: Duration::from_secs(30),
        });
    }
    for scenario in ["held-before-release", "after-release"] {
        result.push(Scenario {
            key: ScenarioName {
                family: "C-CANCEL".into(),
                scenario: scenario.into(),
            },
            mode: "deadline-demand".into(),
            arguments: Vec::new(),
            requirements: Vec::new(),
            output_files: Vec::new(),
            memory: "+128MiB".into(),
            product_deadline: "+30s".into(),
            observation_limit: Duration::from_secs(30),
        });
    }
    for (scenario, kind, destination) in [
        ("export-symlink", "symlink", "work/exported.bin"),
        ("export-fifo", "fifo", "work/exported.bin"),
        ("export-device", "device", "work/exported.bin"),
        ("export-socket", "socket", "work/exported.bin"),
        ("export-traversal", "traversal", "work/parent/exported.bin"),
        (
            "export-concurrent-writer",
            "concurrent-writer",
            "work/exported.bin",
        ),
    ] {
        result.push(Scenario {
            key: ScenarioName {
                family: "L-IMG-04".into(),
                scenario: scenario.into(),
            },
            mode: "export-object".into(),
            arguments: vec![kind.into()],
            requirements: Vec::new(),
            output_files: vec![
                RootRelativePath::new(destination.into()).map_err(CiError::Message)?,
            ],
            memory: "+128MiB".into(),
            product_deadline: "+30s".into(),
            observation_limit: Duration::from_secs(30),
        });
    }
    Ok(result)
}

fn id(value: &str) -> Result<LogicalId> {
    LogicalId::new(value.into()).map_err(CiError::Message)
}
fn path(value: &Path) -> Result<RootRelativePath> {
    RootRelativePath::new(
        value
            .to_str()
            .ok_or_else(|| CiError::Message("fixture path is not UTF-8".into()))?
            .into(),
    )
    .map_err(CiError::Message)
}
