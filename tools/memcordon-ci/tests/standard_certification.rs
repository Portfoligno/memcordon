use memcordon_ci::certification_context::ExpectedCertificationOrigin;
use memcordon_ci::standard_contract::{LINUX, WINDOWS, validate_report};

#[path = "support/standard.rs"]
mod standard;

fn origin() -> ExpectedCertificationOrigin {
    ExpectedCertificationOrigin {
        source_commit: "0123456789abcdef0123456789abcdef01234567".into(),
        repository: "Portfoligno/memcordon".into(),
        run_id: 123.try_into().unwrap(),
        workflow_ref: "Portfoligno/memcordon/.github/workflows/release.yml@refs/tags/1.2.3".into(),
        workflow_commit: "0123456789abcdef0123456789abcdef01234567".into(),
    }
}

#[test]
fn standard_certificates_require_exact_mode_inventory_runtime_and_origin() {
    let origin = origin();
    for contract in [LINUX, WINDOWS] {
        let report = standard::report(contract, &origin);
        validate_report(&report, contract, &origin.source_commit, Some(&origin)).unwrap();
        for mutation in 0..12 {
            let mut report = report.clone();
            match mutation {
                0 => {
                    report.tests.pop();
                    report.tests_run -= 1;
                }
                1 => report.tests[0].ignored_selected = false,
                2 => report.tests[0].exact_name = "wrong".into(),
                3 => report.tests[0].test_binary = "wrong".into(),
                4 => report.boundary = memcordon_core::BoundaryRequirement::Sealed,
                5 => report.target = "aarch64-unknown-linux-gnu".into(),
                6 => report.provenance = None,
                7 => report.provenance.as_mut().unwrap().run_id = 124.try_into().unwrap(),
                8 => report.provenance.as_mut().unwrap().job = "sealed-job".into(),
                9 => report.schema = 2,
                10 => report.tests_skipped = 1,
                11 => {
                    report.runtime = standard::report(
                        if contract.backend_name == LINUX.backend_name {
                            WINDOWS
                        } else {
                            LINUX
                        },
                        &origin,
                    )
                    .runtime
                }
                _ => unreachable!(),
            }
            assert!(
                validate_report(&report, contract, &origin.source_commit, Some(&origin)).is_err(),
                "mutation {mutation}"
            );
        }
    }
}
