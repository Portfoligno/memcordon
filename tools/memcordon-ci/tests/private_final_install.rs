use memcordon_ci::private_final_install::{
    ExpectedFinalHostReadbackV1, validate_final_host_readback,
};
use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;
use serde_json::{Value, json};

struct Fixture {
    manifest: DiagnosticSha256,
    qualification: DiagnosticSha256,
    build: DiagnosticSha256,
    certificate_file: DiagnosticSha256,
    certificate_payload: DiagnosticSha256,
    component: DiagnosticSha256,
    unit: DiagnosticSha256,
    filter: DiagnosticSha256,
    policy: DiagnosticSha256,
    epoch: DiagnosticSha256,
    public_cli: Vec<u8>,
    agent: Vec<u8>,
    helper: Option<Vec<u8>>,
}

impl Fixture {
    fn new(helper: bool) -> Self {
        Self {
            manifest: hash_bytes(b"independently expected M1"),
            qualification: hash_bytes(b"independently expected Q"),
            build: hash_bytes(b"independently expected B"),
            certificate_file: hash_bytes(b"exact signed CQ file"),
            certificate_payload: hash_bytes(b"canonical signed CQ payload"),
            component: hash_bytes(b"component inventory"),
            unit: hash_bytes(b"systemd units"),
            filter: hash_bytes(b"filter instructions"),
            policy: hash_bytes(b"root-signed policy"),
            epoch: hash_bytes(b"current installation epoch"),
            public_cli: b"public CLI image".to_vec(),
            agent: b"installed agent image".to_vec(),
            helper: helper.then(|| b"ARM32 helper image".to_vec()),
        }
    }

    fn expected(&self) -> ExpectedFinalHostReadbackV1<'_> {
        ExpectedFinalHostReadbackV1 {
            source_commit: "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
            version: "0.5.7",
            target: if self.helper.is_some() {
                "aarch64-unknown-linux-gnu"
            } else {
                "x86_64-unknown-linux-gnu"
            },
            native_machine: if self.helper.is_some() {
                "aarch64"
            } else {
                "x86_64"
            },
            boot_id: "current-boot-id",
            installation_epoch: Some(&self.epoch),
            manifest_sha256: &self.manifest,
            qualification_sha256: &self.qualification,
            build_sha256: &self.build,
            certificate_file_sha256: &self.certificate_file,
            certificate_payload_sha256: &self.certificate_payload,
            public_cli_bytes: &self.public_cli,
            agent_bytes: &self.agent,
            arm32_helper_bytes: self.helper.as_deref(),
            component_sha256: &self.component,
            unit_sha256: &self.unit,
            filter_sha256: &self.filter,
            policy_sha256: &self.policy,
            policy_version: 7,
            release_sequence: 41,
        }
    }

    fn response(&self) -> Value {
        let expected = self.expected();
        json!({
            "schema_version": 1,
            "source_commit": expected.source_commit,
            "version": expected.version,
            "target": expected.target,
            "native_machine": expected.native_machine,
            "boot_id": expected.boot_id,
            "installation_epoch": self.epoch,
            "installed_runtime_manifest_sha256": self.manifest,
            "qualification_file_sha256": self.qualification,
            "build_file_sha256": self.build,
            "certificate_file_sha256": self.certificate_file,
            "certificate_payload_sha256": self.certificate_payload,
            "public_cli_sha256": hash_bytes(&self.public_cli),
            "agent_sha256": hash_bytes(&self.agent),
            "arm32_helper_sha256": self.helper.as_deref().map(hash_bytes),
            "component_sha256": self.component,
            "unit_sha256": self.unit,
            "filter_sha256": self.filter,
            "policy_sha256": self.policy,
            "policy_version": expected.policy_version,
            "release_sequence": expected.release_sequence,
            "active_h1_receipt_sha256": hash_bytes(b"current H1 receipt"),
            "active_run_nonce": "ab".repeat(32),
            "native_run_digest": hash_bytes(b"native host run"),
            "host_prerequisites_digest": hash_bytes(b"host prerequisites"),
        })
    }

    fn accepts(&self, value: &Value) -> bool {
        validate_final_host_readback(&serde_json::to_vec(value).unwrap(), &self.expected()).is_ok()
    }
}

#[test]
fn final_h1_readback_joins_protected_release_and_installed_file_bytes() {
    for helper in [false, true] {
        let fixture = Fixture::new(helper);
        let original = fixture.response();
        assert!(fixture.accepts(&original));
        for field in [
            "source_commit",
            "version",
            "target",
            "native_machine",
            "boot_id",
            "installation_epoch",
            "installed_runtime_manifest_sha256",
            "qualification_file_sha256",
            "build_file_sha256",
            "certificate_file_sha256",
            "certificate_payload_sha256",
            "public_cli_sha256",
            "agent_sha256",
            "component_sha256",
            "unit_sha256",
            "filter_sha256",
            "policy_sha256",
            "policy_version",
            "release_sequence",
        ] {
            let mut changed = original.clone();
            changed[field] = match field {
                "policy_version" | "release_sequence" => json!(999),
                "source_commit" | "version" | "target" | "native_machine" | "boot_id" => {
                    json!("wrong")
                }
                _ => json!(hash_bytes(b"substituted evidence")),
            };
            assert!(!fixture.accepts(&changed), "accepted changed {field}");
        }
        let mut changed = original.clone();
        changed["arm32_helper_sha256"] = if helper {
            Value::Null
        } else {
            json!(hash_bytes(b"unexpected helper"))
        };
        assert!(!fixture.accepts(&changed));
    }
}

#[test]
fn final_h1_readback_rejects_replay_and_untrusted_json_extensions() {
    let fixture = Fixture::new(false);
    let original = fixture.response();
    let mut old_epoch = original.clone();
    old_epoch["installation_epoch"] = json!(hash_bytes(b"previous installation"));
    assert!(!fixture.accepts(&old_epoch));
    for field in [
        "active_h1_receipt_sha256",
        "native_run_digest",
        "host_prerequisites_digest",
    ] {
        let mut zero = original.clone();
        zero[field] = json!(DiagnosticSha256::from_bytes([0; 32]));
        assert!(!fixture.accepts(&zero), "accepted zero {field}");
    }
    let mut extra = original.clone();
    extra["self_claimed_archive_sha256"] = json!(hash_bytes(b"untrusted A claim"));
    assert!(!fixture.accepts(&extra));
    let mut missing = original.clone();
    missing.as_object_mut().unwrap().remove("policy_sha256");
    assert!(!fixture.accepts(&missing));
    let mut uppercase = original.clone();
    uppercase["active_run_nonce"] = json!("AB".repeat(32));
    assert!(!fixture.accepts(&uppercase));
    let bytes = serde_json::to_string(&original).unwrap();
    let duplicate = format!(
        "{},\"schema_version\":1}}",
        bytes.strip_suffix('}').unwrap()
    );
    assert!(validate_final_host_readback(duplicate.as_bytes(), &fixture.expected()).is_err());
    assert!(validate_final_host_readback(&vec![b' '; 64 * 1024 + 1], &fixture.expected()).is_err());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn final_install_command_cannot_claim_success_on_non_linux_host() {
    let error = memcordon_ci::private_final_install::install_final_same_host(
        std::path::Path::new("/"),
        std::path::Path::new("/unavailable/intent"),
        std::path::Path::new("/unavailable/archive"),
    )
    .err()
    .expect("non-Linux final install must fail closed");
    assert!(error.to_string().contains("native Linux"));
}
