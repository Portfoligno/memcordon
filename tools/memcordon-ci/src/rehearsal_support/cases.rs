//! Finite mandatory publication cases and their actual fault boundaries.
use super::protocol::*;

#[derive(Clone, Debug)]
pub struct Case {
    pub group: &'static str,
    pub variant: String,
    pub fault: Fault,
    pub seed: bool,
    pub recover: bool,
    pub positive: bool,
}
pub fn selected(files: usize, crates: usize) -> Vec<Case> {
    let mut cases = Vec::new();
    let mut add = |group, variant: String, fault, seed, recover, positive| {
        cases.push(Case {
            group,
            variant,
            fault,
            seed,
            recover,
            positive,
        })
    };
    add("R00", "clean".into(), Fault::None, false, false, true);
    add("R01", "matching".into(), Fault::None, true, false, true);
    add(
        "R02",
        "partial".into(),
        Fault::Barrier {
            boundary: Boundary::Draft,
        },
        false,
        true,
        true,
    );
    let mut boundaries = vec![Boundary::Draft];
    if files > 0 {
        boundaries.push(Boundary::Asset(0));
    }
    if files > 1 {
        boundaries.push(Boundary::Asset(
            u32::try_from(files - 1).expect("validated inventory fits ordinal"),
        ));
    }
    boundaries.extend((0..crates).map(|ordinal| {
        Boundary::Registry(u32::try_from(ordinal).expect("validated inventory fits ordinal"))
    }));
    boundaries.push(Boundary::Visibility);
    for (ordinal, boundary) in boundaries.into_iter().enumerate() {
        add(
            "R03",
            ordinal.to_string(),
            Fault::Loss {
                boundary: boundary.clone(),
            },
            false,
            false,
            true,
        );
        add(
            "R04",
            ordinal.to_string(),
            Fault::Barrier { boundary },
            false,
            true,
            true,
        );
    }
    for (variant, fault) in [
        ("same-length", Fault::ConflictAsset),
        ("registry", Fault::ConflictRegistry),
        ("yanked", Fault::Yanked),
    ] {
        add("R05", variant.into(), fault, true, false, false);
    }
    for kind in [
        ReadFault::Forbidden,
        ReadFault::ServerError,
        ReadFault::MalformedJson,
        ReadFault::DuplicateKeys,
        ReadFault::DuplicateIds,
        ReadFault::MissingFields,
        ReadFault::Truncated,
        ReadFault::NonterminatingPages,
    ] {
        for after_effect in [false, true] {
            add(
                "R06",
                format!("{kind:?}-{after_effect}"),
                Fault::UnknownRead { kind, after_effect },
                false,
                false,
                false,
            );
        }
    }
    add(
        "R07",
        "delayed".into(),
        Fault::VisibilityDelay {
            polls: 2,
            expire: false,
        },
        false,
        false,
        true,
    );
    add(
        "R07",
        "expired".into(),
        Fault::VisibilityDelay {
            polls: 0,
            expire: true,
        },
        false,
        false,
        false,
    );
    add(
        "R08",
        "asset-corrupt".into(),
        Fault::CorruptAsset { truncate: false },
        true,
        false,
        false,
    );
    add(
        "R08",
        "asset-truncated".into(),
        Fault::CorruptAsset { truncate: true },
        true,
        false,
        false,
    );
    add(
        "R08",
        "registry-corrupt".into(),
        Fault::CorruptRegistry,
        true,
        false,
        false,
    );
    for kind in [
        RedirectKind::Controlled,
        RedirectKind::Loop,
        RedirectKind::UnknownOrigin,
    ] {
        add(
            "R09",
            format!("{kind:?}"),
            Fault::Redirect { kind },
            false,
            false,
            kind == RedirectKind::Controlled,
        );
    }
    add(
        "R10",
        "source".into(),
        Fault::SourceDrift {
            before_visibility: false,
        },
        false,
        false,
        false,
    );
    add(
        "R10",
        "source-before-visible".into(),
        Fault::SourceDrift {
            before_visibility: true,
        },
        false,
        false,
        false,
    );
    add(
        "R10",
        "annotated".into(),
        Fault::AnnotatedTag,
        false,
        false,
        true,
    );
    add(
        "R10",
        "cyclic".into(),
        Fault::CyclicTag,
        false,
        false,
        false,
    );
    for field in [
        MetadataField::Notes,
        MetadataField::Prerelease,
        MetadataField::Tag,
    ] {
        add(
            "R10",
            format!("{field:?}"),
            Fault::MetadataDrift { field },
            true,
            false,
            false,
        );
    }
    add("R10", "private".into(), Fault::Private, false, false, true);
    add(
        "R11",
        "starter".into(),
        Fault::StarterResidue,
        false,
        false,
        false,
    );
    add(
        "R12",
        "throttle".into(),
        Fault::RateLimit { excessive: false },
        false,
        false,
        true,
    );
    add(
        "R12",
        "excessive-retry".into(),
        Fault::RateLimit { excessive: true },
        false,
        false,
        false,
    );
    add("R12", "stalled".into(), Fault::Stall, false, false, false);
    add(
        "R13",
        "fixture-loss".into(),
        Fault::FixtureLoss {
            boundary: Boundary::Draft,
        },
        false,
        false,
        false,
    );
    add(
        "R13",
        "cancellation".into(),
        Fault::Barrier {
            boundary: Boundary::Draft,
        },
        false,
        true,
        false,
    );
    // Input and broken-oracle controls have no remote fault. The coordinator
    // executes their deliberately invalid controls and requires rejection.
    add(
        "R14",
        "input-controls".into(),
        Fault::None,
        false,
        false,
        true,
    );
    add(
        "R15",
        "oracle-controls".into(),
        Fault::None,
        false,
        false,
        true,
    );
    cases
}
