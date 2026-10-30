use memcordon_ci::release::component_tests::assert_one_test;

#[test]
fn required_exact_operation_rejects_zero_and_ignored_execution() {
    assert_one_test(
        b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out\n",
    )
    .unwrap();
    for output in [
        b"test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out\n".as_slice(),
        b"test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 7 filtered out\n".as_slice(),
        b"test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 7 filtered out\n"
            .as_slice(),
    ] {
        assert!(assert_one_test(output).is_err());
    }
}
