use memcordon_readiness_verifier::{
    HeldProcessIdentity, linux_image_reference, validate_linux_generated_lifecycle,
};
use serde_json::{Value, json};

fn member(
    host: u32,
    local: u32,
    birth: u64,
    parent: u32,
    parent_birth: u64,
    target: &Value,
) -> Value {
    json!({"native":{"process_id":host,"birth":birth,"namespace_pids":[host,local],
        "user":target["user"],"mount":target["mount"],"pid":target["pid"],"network":target["network"],"ipc":target["ipc"]},
        "identity":{"pid":host,"birth":birth,"parent_pid":parent,"parent_birth":parent_birth,"retirement_observed":false},
        "executable":{"device":8,"inode":9,"length":20,"sha256":"ab".repeat(32)}})
}

#[test]
fn generated_child_requires_actual_both_controller_barriers_and_same_creation_wait() {
    // Structural vectors exercise the strict decoder; these are not native observations.
    let challenge = [7; 32];
    let token = hex::encode(challenge);
    let target = json!({"user":{"device":1,"inode":2},"mount":{"device":1,"inode":3},"pid":{"device":1,"inode":4},
        "network":{"device":1,"inode":5},"ipc":{"device":1,"inode":6}});
    let created = json!({"format":"memcordon.linux-generated-child-created","revision":1,"challenge":token,"pid":4,"birth":22,
        "parent_pid":3,"parent_birth":21,"compiler_pid":2,"compiler_birth":20,"image_device":8,"image_inode":9,
        "program":"/work/generated-child-executable.bin","output":"/work/generated-readiness-artifact.bin","creation_owner_retained":true,"ready_before_release":true});
    let retired = json!({"format":"memcordon.linux-generated-child-retired","revision":1,"challenge":token,"pid":4,"birth":22,
        "parent_pid":3,"parent_birth":21,"native_wait_status":0,"same_creation_owner_waited":true});
    let compiler = json!({"format":"memcordon.linux-native-build-barrier","revision":1,"stage":"offline-compiler-held","challenge":token,
        "attempt_id":"attempt","root_pid":100,"root_birth":10,"members":[member(200,2,20,100,10,&target)]});
    let mut generated = json!({"format":"memcordon.linux-native-build-barrier","revision":1,"stage":"joint-generated-child-held","challenge":token,
        "attempt_id":"attempt","root_pid":100,"root_birth":10,"members":[member(200,2,20,100,10,&target),member(201,3,21,200,20,&target),member(202,4,22,201,21,&target)]});
    let held = vec![
        HeldProcessIdentity {
            pid: 200,
            birth: 20,
            parent_pid: Some(100),
            parent_birth: Some(10),
            retirement_observed: true,
        },
        HeldProcessIdentity {
            pid: 201,
            birth: 21,
            parent_pid: Some(200),
            parent_birth: Some(20),
            retirement_observed: true,
        },
        HeldProcessIdentity {
            pid: 202,
            birth: 22,
            parent_pid: Some(201),
            parent_birth: Some(21),
            retirement_observed: true,
        },
    ];
    let mut elf = vec![0; 20];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[18] = 62;
    use sha2::{Digest, Sha256};
    generated["members"][2]["executable"]["sha256"] = hex::encode(Sha256::digest(&elf)).into();
    let validate = |created: &Value,
                    retired: &Value,
                    compiler: &Value,
                    generated: &Value,
                    held: &[HeldProcessIdentity]| {
        validate_linux_generated_lifecycle(
            created,
            retired,
            compiler,
            generated,
            &target,
            held,
            (100, 10),
            "attempt",
            &challenge,
            "x86_64-unknown-linux-gnu",
            &elf,
        )
    };
    validate(&created, &retired, &compiler, &generated, &held).unwrap();
    for (pointer, value) in [
        ("/pid", json!(5)),
        ("/birth", json!(23)),
        ("/parent_birth", json!(1)),
        ("/compiler_birth", json!(23)),
        ("/challenge", json!(hex::encode([8; 32]))),
        ("/creation_owner_retained", json!(false)),
        ("/ready_before_release", json!(false)),
        ("/image_inode", json!(0)),
        ("/program", json!("/bin/true")),
    ] {
        let mut changed = created.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            validate(&changed, &retired, &compiler, &generated, &held).is_err(),
            "accepted created {pointer}"
        );
    }
    for (pointer, value) in [
        ("/native_wait_status", json!(256)),
        ("/same_creation_owner_waited", json!(false)),
        ("/parent_pid", json!(2)),
    ] {
        let mut changed = retired.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            validate(&created, &changed, &compiler, &generated, &held).is_err(),
            "accepted retired {pointer}"
        );
    }
    for (pointer, value) in [
        ("/members/2/identity/retirement_observed", json!(true)),
        ("/members/2/native/network/inode", json!(999)),
        ("/members/2/identity/parent_birth", json!(20)),
        ("/members/2/native/namespace_pids/1", json!(5)),
        ("/members/2/native/process_id", json!(203)),
        ("/members/2/executable/inode", json!(99)),
        ("/members/2/executable/sha256", json!("cd".repeat(32))),
        ("/members/2/executable/length", json!(21)),
        ("/attempt_id", json!("other")),
        ("/root_birth", json!(11)),
    ] {
        let mut changed = generated.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            validate(&created, &retired, &compiler, &changed, &held).is_err(),
            "accepted held {pointer}"
        );
    }
    let mut missing = generated.clone();
    missing["members"].as_array_mut().unwrap().pop();
    assert!(validate(&created, &retired, &compiler, &missing, &held).is_err());
    let mut changed = held.clone();
    changed[2].retirement_observed = false;
    assert!(validate(&created, &retired, &compiler, &generated, &changed).is_err());
    assert!(validate(&created, &retired, &compiler, &generated, &held[..2]).is_err());
}

#[test]
fn independent_image_canonical_digest_matches_actual_codec_and_rejects_reassociation() {
    use memcordon_core::workload_registry_v3::RuntimeImageDefinitionV1;
    let image = json!({"format":"memcordon.runtime-image","revision":1,"image_id":"owned-image","target":"x86_64-unknown-linux-gnu",
        "entries":[{"kind":"regular","path":"bin/program","sha256":"ab".repeat(32),"size":20,"executable":true},
            {"kind":"symlink","path":"bin/alias","target":"bin/program"}],
        "entrypoints":[{"id":"main","path":"bin/program"}],"library_directories":["lib"],"startup_environment":[{"name":"LANG","value":"C"}]});
    let actual = RuntimeImageDefinitionV1::parse(&serde_json::to_vec(&image).unwrap())
        .unwrap()
        .reference()
        .unwrap();
    assert_eq!(
        linux_image_reference(&image, "x86_64-unknown-linux-gnu").unwrap(),
        serde_json::to_value(actual).unwrap()
    );
    let mut reordered = image.clone();
    reordered["entries"].as_array_mut().unwrap().reverse();
    assert_eq!(
        linux_image_reference(&image, "x86_64-unknown-linux-gnu").unwrap(),
        linux_image_reference(&reordered, "x86_64-unknown-linux-gnu").unwrap()
    );
    let mut changed = image.clone();
    changed["entries"][0]["sha256"] = "cd".repeat(32).into();
    assert_ne!(
        linux_image_reference(&image, "x86_64-unknown-linux-gnu").unwrap(),
        linux_image_reference(&changed, "x86_64-unknown-linux-gnu").unwrap()
    );
    let mut duplicate = image.clone();
    let entry = duplicate["entries"][0].clone();
    duplicate["entries"].as_array_mut().unwrap().push(entry);
    assert!(linux_image_reference(&duplicate, "x86_64-unknown-linux-gnu").is_err());
    let mut traversal = image.clone();
    traversal["entries"][0]["path"] = "../host".into();
    assert!(linux_image_reference(&traversal, "x86_64-unknown-linux-gnu").is_err());
    assert!(linux_image_reference(&image, "aarch64-unknown-linux-gnu").is_err());
}
