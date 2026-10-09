use memcordon_ci::consumer_readiness_ledger::{ExclusiveAccount, validate_account_creation_paths};
use std::path::Path;

#[test]
fn original_account_cannot_redirect_matching_readback_bytes() {
    let output = Path::new("/tmp/owned-readiness-case");
    let account = ExclusiveAccount {
        name: "owned-readiness-account".into(),
        uid: 23456,
        gid: 23456,
        intent: output.join("exclusive-account-intent.json"),
        native_readback: output.join("exclusive-account-getent.bin"),
        group_readback: output.join("exclusive-group-getent.bin"),
    };
    validate_account_creation_paths(output, &account).unwrap();
    // A receipt may retain the original account when the images-only checkpoint
    // predates account acquisition. Matching bytes elsewhere are not its source.
    for field in 0..3 {
        let mut redirected = account.clone();
        match field {
            0 => redirected.intent = output.join("other-intent.json"),
            1 => redirected.native_readback = output.join("matching-passwd-copy.bin"),
            _ => redirected.group_readback = output.join("matching-group-copy.bin"),
        }
        assert!(validate_account_creation_paths(output, &redirected).is_err());
    }
    assert!(validate_account_creation_paths(Path::new("/tmp/another-cell"), &account).is_err());
    // Retrying receipt publication retains the same original creation binding.
    let persisted = serde_json::to_vec(&account).unwrap();
    let recovered: ExclusiveAccount = serde_json::from_slice(&persisted).unwrap();
    validate_account_creation_paths(output, &recovered).unwrap();
}
