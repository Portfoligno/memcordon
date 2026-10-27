use memcordon_readiness_verifier::linux_frontend_access::resolve;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
#[path = "../../../crates/memcordon-cli/src/bin/original_native_recovery_delivery.rs"]
pub mod original_recovery_delivery;

fn receipt() -> (Value, Vec<u8>) {
    let contract = b"{\"genuine\":\"retained contract\"}\n".to_vec();
    let digest = hex::encode(Sha256::digest(&contract));
    let source = json!({"descriptor":129,"path":b"/protected/case/contract.json",
        "device":1,"inode":2,"uid":0,"gid":0,"mode":0o100600,"links":1,
        "length":contract.len(),"sha256":digest,
        "runtime":{"path":b"/protected/case/frontend/workload-contract.json".as_slice(),
          "device":1,"inode":3,"uid":0,"gid":0,"mode":0o100444,"links":1,
          "length":contract.len(),"sha256":digest}});
    (
        json!({"format":"memcordon.linux-owned-frontend-invocation","revision":1,
        "program":b"/usr/bin/setpriv","environment_cleared":true,
        "caller_uid":65534,"caller_gid":65534,"selected_cli_sha256":"a".repeat(64),
        "arguments":[b"--reuid".as_slice(),b"65534",b"--regid",b"65534",b"--clear-groups",b"--",
          b"/usr/libexec/memcordon",b"+256M",b"+30000ms",b"--sealed",
          b"--workload-contract",b"/proc/self/fd/129",b"--report-format",b"result-v2",
          b"--report",b"/proc/self/fd/130/result.json",
          b"--mixed-observation-directory",b"/proc/self/fd/130/observations",
          b"--image-entrypoint",b"owned-readiness",b"--wait-for",b"command",b"--",b"tcp-http",b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".as_slice()],
        "file_access":{"format":"memcordon.linux-frontend-file-access","revision":1,
          "contract":source,"output_directory":{"descriptor":130,
          "path":b"/protected/case/frontend","device":1,"inode":4,
          "uid":65534,"gid":65534,"mode":0o40700}}}),
        contract,
    )
}

#[test]
fn exact_descriptor_map_resolves_without_mutating_original_receipt() {
    let (command, contract) = receipt();
    let original = command.clone();
    let result = resolve(&command, Some(&contract)).unwrap();
    assert_eq!(command, original);
    assert!(result.get("file_access").is_none());
    assert_eq!(
        result["arguments"][11],
        json!(b"/protected/case/contract.json")
    );
    assert_eq!(
        result["arguments"][15],
        json!(b"/protected/case/frontend/result.json".as_slice())
    );
    assert_eq!(
        result["arguments"][17],
        json!(b"/protected/case/frontend/observations".as_slice())
    );
}

#[test]
fn hostile_descriptor_authority_and_retained_byte_substitutions_refuse() {
    let (command, contract) = receipt();
    for (pointer, value) in [
        ("/file_access/contract/descriptor", json!(128)),
        ("/file_access/output_directory/descriptor", json!(129)),
        ("/file_access/contract/uid", json!(65534)),
        ("/file_access/contract/links", json!(2)),
        ("/file_access/contract/mode", json!(0o100666)),
        ("/file_access/contract/runtime/mode", json!(0o100644)),
        (
            "/file_access/contract/runtime/sha256",
            json!("b".repeat(64)),
        ),
        (
            "/file_access/contract/runtime/path",
            json!(b"/other/workload-contract.json"),
        ),
        ("/file_access/contract/runtime/inode", json!(2)),
        ("/file_access/contract/gid", json!(u64::MAX)),
        ("/file_access/output_directory/uid", json!(null)),
        ("/file_access/output_directory/uid", json!(0)),
        ("/file_access/output_directory/mode", json!(0o40755)),
        ("/arguments/11", json!(b"/proc/self/fd/130")),
        ("/arguments/15", json!(b"/proc/self/fd/130/../result.json")),
    ] {
        let mut hostile = command.clone();
        *hostile.pointer_mut(pointer).unwrap() = value;
        assert!(resolve(&hostile, Some(&contract)).is_err(), "{pointer}");
    }
    assert!(resolve(&command, Some(b"different retained contract")).is_err());
    let mut unknown = command.clone();
    unknown["file_access"]["ambient"] = json!(true);
    assert!(resolve(&unknown, Some(&contract)).is_err());
    let mut absent = command.clone();
    absent.as_object_mut().unwrap().remove("file_access");
    assert!(resolve(&absent, Some(&contract)).is_err());
    let mut duplicate = command.clone();
    duplicate["arguments"]
        .as_array_mut()
        .unwrap()
        .extend([json!(b"--report"), json!(b"/proc/self/fd/130/result.json")]);
    assert!(resolve(&duplicate, Some(&contract)).is_err());
}

#[test]
fn endpoint_group_is_exact_and_cannot_be_downgraded_or_substituted() {
    let (mut command, contract) = receipt();
    command["arguments"][4] = json!(b"--groups=991".as_slice());
    command["endpoint_access"] = json!({
        "format":"memcordon.linux-owned-frontend-endpoint-access","revision":1,
        "path":b"/run/memcordon/sealed-agent.sock".as_slice(),
        "device":1,"inode":9,"uid":0,"gid":991,"mode":0o140660,"links":1,
        "supplementary_groups":[991],"group_argument":b"--groups=991".as_slice()
    });
    let original = command.clone();
    let resolved = resolve(&command, Some(&contract)).unwrap();
    assert_eq!(command, original);
    assert_eq!(resolved["arguments"][4], command["arguments"][4]);
    assert!(resolved.get("endpoint_access").is_none());
    for (pointer, value) in [
        (
            "/endpoint_access/path",
            json!(b"/run/other.sock".as_slice()),
        ),
        ("/endpoint_access/uid", json!(65534)),
        ("/endpoint_access/gid", json!(0)),
        ("/endpoint_access/gid", json!(u64::MAX)),
        ("/endpoint_access/mode", json!(0o140666)),
        ("/endpoint_access/links", json!(2)),
        ("/endpoint_access/supplementary_groups", json!([991, 992])),
        (
            "/endpoint_access/group_argument",
            json!(b"--groups=992".as_slice()),
        ),
        ("/arguments/4", json!(b"--clear-groups".as_slice())),
    ] {
        let mut hostile = command.clone();
        *hostile.pointer_mut(pointer).unwrap() = value;
        assert!(resolve(&hostile, Some(&contract)).is_err(), "{pointer}");
    }
    command.as_object_mut().unwrap().remove("endpoint_access");
    assert!(resolve(&command, Some(&contract)).is_err());
}

#[test]
fn original_recovery_delivery_joins_raw_operand_to_exact_resolved_native_destination() {
    let (mut command, contract) = receipt();
    let challenge = command["arguments"][24].clone();
    let args = command["arguments"].as_array_mut().unwrap();
    args.truncate(23);
    args.extend([json!(b"bytes-argv-status"), challenge, json!(b"0")]);
    let destination = json!({"format":"memcordon.linux-report-destination","revision":1,
        "path":b"/protected/case/frontend/result.json".as_slice(),"device":7,"inode":8,"uid":65534,"gid":65534,"mode":0o40700,"is_directory":true});
    let failure = json!({"format":"memcordon.linux-native-report-delivery-failure","revision":1,
        "report_path":command["arguments"][15],"submitted_report":b"original submitted report",
        "native_errno":21,"native_error_code":"MCREPORT-WRITE","frontend_pid":123,
        "destination":{"device":7,"inode":8,"uid":65534,"gid":65534,"mode":0o40700,"is_directory":true}});
    assert_ne!(failure["report_path"], destination["path"]);
    let check = |command: &Value, destination: &Value, failure: &Value, contract: &[u8]| {
        original_recovery_delivery::validate(command, contract, destination, failure, 123, 65534)
    };
    check(&command, &destination, &failure, &contract).unwrap();
    for operand in [
        b"/proc/self/fd/129/result.json".as_slice(),
        b"/proc/self/fd/130/../result.json",
        b"/protected/case/frontend/result.json",
    ] {
        let mut changed = command.clone();
        changed["arguments"][15] = json!(operand);
        assert!(check(&changed, &destination, &failure, &contract).is_err());
    }
    let mut wrong_role = command.clone();
    wrong_role["file_access"]["output_directory"]["descriptor"] = json!(129);
    assert!(check(&wrong_role, &destination, &failure, &contract).is_err());
    let mut foreign = command.clone();
    foreign["file_access"]["output_directory"]["path"] = json!(b"/protected/foreign/frontend");
    foreign["file_access"]["contract"]["runtime"]["path"] =
        json!(b"/protected/foreign/frontend/workload-contract.json".as_slice());
    resolve(&foreign, Some(&contract)).unwrap();
    assert!(check(&foreign, &destination, &failure, &contract).is_err());
    assert!(
        check(
            &command,
            &destination,
            &failure,
            b"changed original contract"
        )
        .is_err()
    );
    for (pointer, value) in [
        ("/frontend_pid", json!(124)),
        ("/report_path", destination["path"].clone()),
        ("/destination/device", json!(9)),
        ("/destination/inode", json!(9)),
        ("/destination/uid", json!(0)),
        ("/destination/gid", json!(0)),
        ("/destination/mode", json!(0o40755)),
        ("/destination/is_directory", json!(false)),
        ("/native_errno", json!(13)),
        ("/native_error_code", json!("unrelated")),
        ("/submitted_report", json!([])),
    ] {
        let mut changed = failure.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            check(&command, &destination, &changed, &contract).is_err(),
            "accepted {pointer}"
        );
    }
    let mut zero = destination.clone();
    zero["inode"] = json!(0);
    let mut zero_failure = failure.clone();
    zero_failure["destination"]["inode"] = json!(0);
    assert!(check(&command, &zero, &zero_failure, &contract).is_err());
}
