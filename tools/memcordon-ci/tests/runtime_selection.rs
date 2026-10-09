use memcordon_ci::release::distribution::{RuntimeSelection, TargetDistribution};

#[test]
fn readiness_profile_is_explicit_and_keeps_ordinary_macos_selection() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let ordinary = memcordon_ci::release::distribution::Distribution::read(root).unwrap();
    assert!(
        ordinary
            .targets
            .iter()
            .all(|target| target.runtime_selection().unwrap() == RuntimeSelection::CliOnly)
    );
    let selected = ordinary.clone().consumer_readiness().unwrap();
    assert_eq!(
        ordinary
            .targets
            .iter()
            .filter(|target| target.features.is_empty())
            .count(),
        6
    );
    for target in selected.targets {
        let expected = if target.target.ends_with("linux-gnu") {
            RuntimeSelection::LinuxPrivateTcp
        } else if target.target.ends_with("windows-msvc") {
            RuntimeSelection::WindowsSealed
        } else {
            RuntimeSelection::CliOnly
        };
        assert_eq!(target.runtime_selection().unwrap(), expected);
        if expected == RuntimeSelection::LinuxPrivateTcp {
            assert_eq!(target.units.len(), 7);
            assert_eq!(target.binaries.len(), 2);
        }
        if expected == RuntimeSelection::WindowsSealed {
            assert_eq!(target.binaries.len(), 4);
        }
    }
}

fn linux(features: &[&str]) -> TargetDistribution {
    let runtime = !features.is_empty();
    let private = features.contains(&"private-tcp");
    let mut selection = TargetDistribution {
        target: "x86_64-unknown-linux-gnu".into(),
        features: features.iter().map(|value| (*value).into()).collect(),
        binaries: vec!["memcordon".into()],
        units: Vec::new(),
    };
    if runtime {
        selection.binaries.push("memcordon-sealed-agent".into());
        selection.units.extend(
            [
                "memcordon-sealed-agent.service",
                "memcordon-sealed-agent.socket",
                "memcordon-sealed-launcher.service",
                "memcordon-sealed-launcher.socket",
                "memcordon.conf",
            ]
            .map(String::from),
        );
    }
    if private {
        selection.units.extend(
            [
                "memcordon-sealed-network-launcher.service",
                "memcordon-sealed-network-launcher.socket",
            ]
            .map(String::from),
        );
    }
    selection
}

#[test]
fn feature_closure_matches_native_runtime_including_transitive_spelling() {
    for target in ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"] {
        for (features, expected) in [
            (vec![], RuntimeSelection::CliOnly),
            (vec!["sealed-runtime"], RuntimeSelection::LinuxBaseline),
            (vec!["private-tcp"], RuntimeSelection::LinuxPrivateTcp),
            (
                vec!["sealed-runtime", "private-tcp"],
                RuntimeSelection::LinuxPrivateTcp,
            ),
        ] {
            let mut selection = linux(&features);
            selection.target = target.into();
            assert_eq!(selection.runtime_selection().unwrap(), expected);
        }
    }
    for target in ["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"] {
        for features in [
            vec!["windows-sealed-runtime"],
            vec!["sealed-runtime", "windows-sealed-runtime"],
        ] {
            let selection = TargetDistribution {
                target: target.into(),
                features: features.into_iter().map(String::from).collect(),
                binaries: [
                    "memcordon",
                    "memcordon-sealed-agent",
                    "memcordon-target-desktop-bootstrap",
                    "memcordon-session-broker",
                ]
                .map(String::from)
                .into(),
                units: Vec::new(),
            };
            assert_eq!(
                selection.runtime_selection().unwrap(),
                RuntimeSelection::WindowsSealed
            );
        }
    }
}

#[test]
fn runtime_resolution_rejects_untrusted_or_incomplete_selection() {
    let mut unknown = linux(&["private-tcp"]);
    unknown.features.push("unknown".into());
    let mut duplicate = linux(&["private-tcp"]);
    duplicate.features.push("private-tcp".into());
    let mut missing_unit = linux(&["private-tcp"]);
    missing_unit.units.pop();
    let mut missing_agent = linux(&["private-tcp"]);
    missing_agent.binaries.pop();
    let mut wrong_platform = linux(&["private-tcp"]);
    wrong_platform.target = "aarch64-apple-darwin".into();
    for invalid in [
        unknown,
        duplicate,
        missing_unit,
        missing_agent,
        wrong_platform,
    ] {
        assert!(invalid.runtime_selection().is_err());
    }
}
