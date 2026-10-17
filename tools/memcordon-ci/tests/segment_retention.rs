use memcordon_ci::{
    segment_cache::{RetentionDecision as D, compilation_retention},
    work_outcome::WriterSettlement as W,
};

#[test]
fn every_completion_route_requires_its_own_inputs_payload_and_settled_owner() {
    for eligible in [false, true] {
        for unchanged in [false, true] {
            for payload in [false, true] {
                for writers in [W::NotStarted, W::Settled, W::Unknown] {
                    for complete in [false, true] {
                        let actual =
                            compilation_retention(eligible, unchanged, payload, writers, complete);
                        let expected = if !eligible
                            || !unchanged
                            || !payload
                            || writers == W::Unknown
                            || (complete && writers != W::Settled)
                        {
                            D::None
                        } else if complete {
                            D::Complete
                        } else {
                            D::Partial
                        };
                        assert_eq!(actual, expected);
                    }
                }
            }
        }
    }
}

#[test]
fn compilation_result_and_later_test_result_have_distinct_meanings() {
    // Aggregate job/test success is intentionally absent from the decision API.
    assert_eq!(
        compilation_retention(true, true, true, W::Settled, true),
        D::Complete
    );
    assert_eq!(
        compilation_retention(true, true, true, W::Settled, false),
        D::Partial
    );
    assert_eq!(
        compilation_retention(true, true, true, W::Unknown, true),
        D::None
    );
}
