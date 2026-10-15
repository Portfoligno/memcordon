use memcordon_ci::release::{
    distribution::Distribution, finalize::validate_public_package_inventory, source,
};
use std::{path::Path, sync::OnceLock};

fn fixture() -> &'static (cargo_metadata::Metadata, Distribution, semver::Version) {
    static FIXTURE: OnceLock<(cargo_metadata::Metadata, Distribution, semver::Version)> =
        OnceLock::new();
    FIXTURE.get_or_init(|| {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let metadata = source::metadata(&root).unwrap();
        let version = metadata
            .workspace_packages()
            .into_iter()
            .find(|package| package.name.as_str() == "memcordon-core")
            .unwrap()
            .version
            .clone();
        (metadata, Distribution::read(&root).unwrap(), version)
    })
}

#[test]
fn actual_distribution_and_readiness_inventory_accept_independent_valid_orders() {
    let (metadata, distribution, version) = fixture();
    validate_public_package_inventory(metadata, version, &distribution.packages).unwrap();
    let readiness = distribution.clone().consumer_readiness().unwrap();
    validate_public_package_inventory(metadata, version, &readiness.packages).unwrap();
    let derived = source::public_order(metadata, version).unwrap();
    validate_public_package_inventory(metadata, version, &derived).unwrap();
}

#[test]
fn missing_extra_and_duplicate_packages_are_rejected() {
    let (metadata, distribution, version) = fixture();
    let mut missing = distribution.packages.clone();
    missing.pop();
    let mut extra = distribution.packages.clone();
    extra.push("unexpected-public-package".into());
    let mut duplicate = distribution.packages.clone();
    duplicate[1] = duplicate[0].clone();
    for packages in [missing, extra, duplicate] {
        assert!(
            validate_public_package_inventory(metadata, version, &packages)
                .unwrap_err()
                .to_string()
                .contains("inventory differs")
        );
    }
}

#[test]
fn selected_versions_registry_and_internal_dependency_checks_remain_required() {
    let (metadata, distribution, version) = fixture();
    let mut wrong_version = version.clone();
    wrong_version.patch = wrong_version.patch.checked_add(1).unwrap();
    assert!(
        validate_public_package_inventory(metadata, &wrong_version, &distribution.packages)
            .unwrap_err()
            .to_string()
            .contains("version/registry differs")
    );

    let mut wrong_registry = metadata.clone();
    wrong_registry
        .packages
        .iter_mut()
        .find(|package| package.name.as_str() == "memcordon-core")
        .unwrap()
        .publish = Some(Vec::new());
    assert!(
        validate_public_package_inventory(&wrong_registry, version, &distribution.packages)
            .unwrap_err()
            .to_string()
            .contains("version/registry differs")
    );

    let mut wrong_dependency = metadata.clone();
    let dependency = wrong_dependency
        .packages
        .iter_mut()
        .find(|package| package.name.as_str() == "memcordon")
        .unwrap()
        .dependencies
        .iter_mut()
        .find(|dependency| {
            dependency.kind != cargo_metadata::DependencyKind::Development
                && source::PUBLIC_PACKAGES.contains(&dependency.name.as_str())
        })
        .unwrap();
    dependency.req = semver::VersionReq::parse(">=0").unwrap();
    assert!(
        validate_public_package_inventory(&wrong_dependency, version, &distribution.packages)
            .unwrap_err()
            .to_string()
            .contains("internal dependency version differs")
    );
}

#[test]
fn unpublished_runtime_dependencies_and_cycles_remain_rejected() {
    let (metadata, distribution, version) = fixture();
    let dependency = metadata
        .packages
        .iter()
        .find(|package| package.name.as_str() == "memcordon-platform")
        .unwrap()
        .dependencies
        .iter()
        .find(|dependency| {
            dependency.name == "memcordon-core"
                && dependency.kind != cargo_metadata::DependencyKind::Development
        })
        .unwrap()
        .clone();
    let mut unpublished = metadata.clone();
    let mut unpublished_dependency = dependency.clone();
    unpublished_dependency.name = "unpublished-helper".into();
    unpublished
        .packages
        .iter_mut()
        .find(|package| package.name.as_str() == "memcordon")
        .unwrap()
        .dependencies
        .push(unpublished_dependency);
    assert!(
        validate_public_package_inventory(&unpublished, version, &distribution.packages)
            .unwrap_err()
            .to_string()
            .contains("unpublished runtime dependency")
    );

    let mut cycle = metadata.clone();
    let mut cycle_dependency = dependency;
    cycle_dependency.name = "memcordon-platform".into();
    cycle_dependency.path = Some(
        metadata
            .packages
            .iter()
            .find(|package| package.name.as_str() == "memcordon-platform")
            .unwrap()
            .manifest_path
            .parent()
            .unwrap()
            .to_owned(),
    );
    cycle
        .packages
        .iter_mut()
        .find(|package| package.name.as_str() == "memcordon-core")
        .unwrap()
        .dependencies
        .push(cycle_dependency);
    assert!(
        validate_public_package_inventory(&cycle, version, &distribution.packages)
            .unwrap_err()
            .to_string()
            .contains("public package dependency cycle")
    );
}
