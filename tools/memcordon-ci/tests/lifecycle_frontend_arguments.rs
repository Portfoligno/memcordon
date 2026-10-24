#[path = "../src/release/lifecycle_frontend_arguments.rs"]
mod arguments;

fn invocation(lifetime: &[u8], target: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut args = [
        b"--image-entrypoint".as_slice(),
        b"owned-readiness",
        b"--wait-for",
        lifetime,
        b"--",
    ]
    .map(Vec::from)
    .to_vec();
    args.extend_from_slice(target);
    args
}

#[test]
fn exact_command_and_workload_lifetimes_preserve_original_target() {
    for (lifetime, target) in [
        (
            b"command".as_slice(),
            vec![b"held-tree".to_vec(), b"original-challenge".to_vec()],
        ),
        (
            b"workload".as_slice(),
            vec![b"root-first".to_vec(), b"original-challenge".to_vec()],
        ),
        (
            b"command".as_slice(),
            vec![
                b"bytes-argv-status".to_vec(),
                b"original-challenge".to_vec(),
                b"0".to_vec(),
            ],
        ),
    ] {
        let args = invocation(lifetime, &target);
        assert_eq!(
            arguments::normalize(&args, lifetime, &target).unwrap(),
            target
        );
        let wrong = if lifetime == b"command" {
            b"workload".as_slice()
        } else {
            b"command".as_slice()
        };
        assert!(arguments::normalize(&args, wrong, &target).is_err());
        for index in args.len() - target.len()..args.len() {
            let mut changed = args.clone();
            changed[index] = b"changed-original-value".to_vec();
            assert!(arguments::normalize(&changed, lifetime, &target).is_err());
        }
    }
}

#[test]
fn missing_duplicate_or_reordered_marker_never_rebinds_target() {
    let target = vec![b"held-tree".to_vec(), b"original-challenge".to_vec()];
    let original = invocation(b"command", &target);
    let mut missing = original.clone();
    let delimiter = missing.iter().position(|value| value == b"--").unwrap();
    missing.remove(delimiter);
    assert!(arguments::normalize(&missing, b"command", &target).is_err());
    let mut duplicate = invocation(b"command", &[]);
    duplicate.extend_from_slice(&original);
    assert!(arguments::normalize(&duplicate, b"command", &target).is_err());
    let mut reordered = original.clone();
    let wait = reordered
        .iter()
        .position(|value| value == b"--wait-for")
        .unwrap();
    reordered.swap(wait, wait + 1);
    assert!(arguments::normalize(&reordered, b"command", &target).is_err());
    let mut extra = original;
    extra.insert(delimiter, b"--".to_vec());
    assert!(arguments::normalize(&extra, b"command", &target).is_err());
}
