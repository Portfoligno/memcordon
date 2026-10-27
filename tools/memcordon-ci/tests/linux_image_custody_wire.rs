#[path = "../src/release/linux_image_custody_wire.rs"]
mod wire;

use wire::{Binding, Frame, Identity, Role, decode, encode};

#[test]
fn actual_tagged_hello_roundtrips_the_full_native_birth_width() {
    let current_birth = memcordon_platform::test_support::ProcessIdentity::current()
        .unwrap()
        .birth;
    for birth in [0, current_birth, u128::from(u64::MAX) + 1, u128::MAX] {
        let bytes = encode(&Frame::Hello {
            nonce: "nonce".into(),
            pid: 7,
            birth,
        })
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["birth"], birth.to_string());
        match decode(&bytes).unwrap() {
            Frame::Hello {
                nonce,
                pid,
                birth: actual,
            } => {
                assert_eq!((nonce.as_str(), pid, actual), ("nonce", 7, birth));
            }
            other => panic!("unexpected frame: {other:?}"),
        }
    }
}

#[test]
fn actual_hello_rejects_noncanonical_overflow_and_wrong_type_births() {
    let mut overflow = u128::MAX.to_string().into_bytes();
    let last = overflow.last_mut().unwrap();
    *last = last.checked_add(1).unwrap();
    let overflow = String::from_utf8(overflow).unwrap();
    assert_eq!(overflow.len(), u128::MAX.to_string().len());
    let too_long = "1".repeat(u128::MAX.to_string().len() + 1);
    for birth in [
        "", "00", "01", "+1", "-1", " 1", "1 ", "1.0", "1e2", "１２", &overflow, &too_long,
    ] {
        let value = serde_json::json!({"operation":"Hello","nonce":"nonce","pid":7,"birth":birth});
        assert!(
            decode(&serde_json::to_vec(&value).unwrap()).is_err(),
            "accepted {birth:?}"
        );
    }
    for birth in [
        serde_json::json!(0),
        serde_json::json!(null),
        serde_json::json!(true),
        serde_json::json!([]),
        serde_json::json!({}),
    ] {
        let value = serde_json::json!({"operation":"Hello","nonce":"nonce","pid":7,"birth":birth});
        assert!(decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}

#[test]
fn actual_frames_retain_closed_fields_and_other_capability_bindings() {
    let hello = serde_json::json!({"operation":"Hello","nonce":"nonce","pid":7,"birth":"1"});
    for field in ["operation", "nonce", "pid", "birth"] {
        let mut missing = hello.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(decode(&serde_json::to_vec(&missing).unwrap()).is_err());
    }
    let mut unknown = hello;
    unknown["extra"] = serde_json::json!(1);
    assert!(decode(&serde_json::to_vec(&unknown).unwrap()).is_err());
    let binding = Binding {
        nonce: "nonce".into(),
        sequence: u64::MAX,
        slot: 127,
        path: "/original/member".into(),
        identity: Identity {
            device: u64::MAX,
            inode: 42,
        },
        role: Role::AdministrativeFile,
    };
    let bytes = encode(&Frame::Ack { binding }).unwrap();
    let Frame::Ack { binding } = decode(&bytes).unwrap() else {
        panic!("wrong operation")
    };
    assert_eq!(binding.sequence, u64::MAX);
    assert_eq!(binding.slot, 127);
    assert_eq!(
        binding.identity,
        Identity {
            device: u64::MAX,
            inode: 42
        }
    );
    assert_eq!(binding.path.as_os_str(), "/original/member");
    assert_eq!(binding.role, Role::AdministrativeFile);
    let mut unknown: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    unknown["binding"]["extra"] = serde_json::json!(true);
    assert!(decode(&serde_json::to_vec(&unknown).unwrap()).is_err());
    assert!(decode(&vec![b' '; wire::FRAME_BYTES + 1]).is_err());
    let seed = "n";
    assert!(
        encode(&Frame::Hello {
            nonce: seed.repeat(wire::FRAME_BYTES.div_ceil(seed.len())),
            pid: 7,
            birth: 1
        })
        .is_err()
    );
}
