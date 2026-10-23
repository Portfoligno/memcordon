use memcordon_ci::release::{native_coverage_owner::original_cutoff, source::BuildSourceIdentity};
use serde_json::json;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[test]
fn distributed_owner_uses_the_original_window_and_rejects_changed_or_expired_admission() {
    let root = if cfg!(unix) {
        tempfile::tempdir_in("/tmp").unwrap()
    } else {
        tempfile::tempdir().unwrap()
    };
    std::fs::create_dir(root.path().join(".release")).unwrap();
    let source = BuildSourceIdentity::Working {
        version: "0.5.8-dev".parse().unwrap(),
        commit: "a".repeat(40),
    };
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let start = now - 60_000;
    let valid = json!({"format":"memcordon.native-coverage.original-deadline","revision":1,"source":source,"target":"x86_64-apple-darwin",
        "started_unix_millis":start,"work_deadline_unix_millis":start+140*60*1000,"cleanup_deadline_unix_millis":start+155*60*1000});
    let path = root.path().join(".release/native-coverage-deadline.json");
    std::fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
    let before = Instant::now();
    let cutoff = original_cutoff(root.path(), &source, "x86_64-apple-darwin").unwrap();
    assert!(cutoff <= before + Duration::from_millis(start + 140 * 60 * 1000 - now));
    assert!(cutoff > before + Duration::from_secs(138 * 60));
    for (field, value) in [
        ("format", json!("foreign")),
        ("revision", json!(2)),
        ("target", json!("aarch64-apple-darwin")),
        (
            "source",
            json!(BuildSourceIdentity::Working {
                version: "0.5.8-dev".parse().unwrap(),
                commit: "b".repeat(40)
            }),
        ),
        ("started_unix_millis", json!(now + 60_000)),
        ("work_deadline_unix_millis", json!(start + 141 * 60 * 1000)),
        (
            "cleanup_deadline_unix_millis",
            json!(start + 156 * 60 * 1000),
        ),
    ] {
        let mut changed = valid.clone();
        changed[field] = value;
        std::fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(
            original_cutoff(root.path(), &source, "x86_64-apple-darwin").is_err(),
            "{field}"
        );
    }
    let expired_start = now - 141 * 60 * 1000;
    let mut expired = valid;
    expired["started_unix_millis"] = json!(expired_start);
    expired["work_deadline_unix_millis"] = json!(expired_start + 140 * 60 * 1000);
    expired["cleanup_deadline_unix_millis"] = json!(expired_start + 155 * 60 * 1000);
    std::fs::write(path, serde_json::to_vec(&expired).unwrap()).unwrap();
    assert!(original_cutoff(root.path(), &source, "x86_64-apple-darwin").is_err());
}
