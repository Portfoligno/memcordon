use memcordon_ci::linux_export_writer::validate;
use memcordon_core::workload_request::RootRelativePath;
use serde_json::{Value, json};

type Outputs = Vec<(RootRelativePath, Vec<u8>)>;
fn fixture() -> (Value, Value, Vec<Value>, Value, Outputs) {
    let namespace = json!({"device":4,"inode":55});
    let controller = json!({"export_writer_native":{
        "writer":{"pid":9001,"birth":41,"namespace_pid":3},
        "pidfd_readable_after_stop":true,"target_alive_after_writer":true,
        "first":{"device":7,"inode":101,"bytes":[0,255,1,17]},
        "second":{"device":7,"inode":101,"bytes":[0,255,2,17]},
        "final":{"device":7,"inode":101,"bytes":[0,255,3,17]}},
        "export_candidate":{"device":7,"inode":101},
        "held_stages":[{"operation":"export-writer-held","sequence":1,"children":[{
            "namespace_pid":3,"snapshot":{"process_id":9001,"birth":41,"namespace_pids":[9001,3],"pid":namespace},
            "identity":{"pid":9001,"birth":41,"parent_pid":8000,"parent_birth":40,"retirement_observed":false}}]}]});
    let retirement = json!({"held_processes":[{"pid":9001,"birth":41,"pidfd_readable":true}]});
    let rows = vec![
        json!({"operation":"export-writer-held","sequence":1,"observation":{"pid":3,"birth":41}}),
        json!({"operation":"export-writer-retired","sequence":3,"observation":{"pid":3,"native_wait_completed":true,"raw_wait_status":0,"before_root_release":true}}),
    ];
    let native = json!({"target":{"pid":8000,"birth":40},"pid_namespace":namespace});
    let outputs = vec![(
        RootRelativePath::new("exported.bin".into()).unwrap(),
        vec![0, 255, 3, 17],
    )];
    (controller, retirement, rows, native, outputs)
}

#[test]
fn different_host_and_local_pids_bind_through_original_native_mapping() {
    let (mut controller, mut retirement, rows, native, outputs) = fixture();
    validate(&controller, &retirement, &rows, &native, &outputs).unwrap();
    controller["export_writer_native"]["writer"]["pid"] = 3.into();
    controller["held_stages"][0]["children"][0]["snapshot"]["process_id"] = 3.into();
    controller["held_stages"][0]["children"][0]["snapshot"]["namespace_pids"] = json!([3, 3]);
    controller["held_stages"][0]["children"][0]["identity"]["pid"] = 3.into();
    retirement["held_processes"][0]["pid"] = 3.into();
    validate(&controller, &retirement, &rows, &native, &outputs).unwrap();
}

#[test]
fn identity_birth_parent_and_unique_original_stage_are_mandatory() {
    for mutation in 0..21 {
        let (mut controller, retirement, mut rows, mut native, outputs) = fixture();
        match mutation {
            0 => rows[1]["observation"]["pid"] = 9001.into(),
            1 => {
                controller["export_writer_native"]["writer"]
                    .as_object_mut()
                    .unwrap()
                    .remove("namespace_pid");
            }
            2 => controller["export_writer_native"]["writer"]["birth"] = 42.into(),
            3 => controller["export_writer_native"]["writer"]["pid"] = 9002.into(),
            4 => controller["held_stages"][0]["children"][0]["snapshot"]["birth"] = 42.into(),
            5 => controller["held_stages"][0]["children"][0]["identity"]["birth"] = 42.into(),
            6 => controller["held_stages"][0]["children"][0]["namespace_pid"] = 4.into(),
            7 => {
                controller["held_stages"][0]["children"][0]["snapshot"]["namespace_pids"] =
                    json!([9002, 3])
            }
            8 => {
                controller["held_stages"][0]["children"][0]["snapshot"]["namespace_pids"] =
                    json!([9001, 4])
            }
            9 => {
                controller["held_stages"][0]["children"][0]["snapshot"]["pid"]["inode"] = 56.into()
            }
            10 => {
                controller["held_stages"][0]["children"][0]["identity"]["parent_pid"] = 8001.into()
            }
            11 => {
                controller["held_stages"][0]["children"][0]["identity"]["parent_birth"] = 39.into()
            }
            12 => rows[0]["observation"]["birth"] = 42.into(),
            13 => rows.push(rows[0].clone()),
            14 => {
                let stage = controller["held_stages"][0].clone();
                controller["held_stages"]
                    .as_array_mut()
                    .unwrap()
                    .push(stage);
            }
            15 => controller["held_stages"] = json!([]),
            16 => controller["held_stages"][0]["children"] = json!([]),
            17 => {
                let child = controller["held_stages"][0]["children"][0].clone();
                controller["held_stages"][0]["children"]
                    .as_array_mut()
                    .unwrap()
                    .push(child);
            }
            18 => {
                controller["held_stages"][0]["children"][0]["identity"]["retirement_observed"] =
                    true.into()
            }
            19 => native["target"]["birth"] = 42.into(),
            _ => {
                controller["held_stages"][0]["children"][0]["snapshot"]["namespace_pids"] =
                    Value::Null
            }
        }
        assert!(
            validate(&controller, &retirement, &rows, &native, &outputs).is_err(),
            "mutation={mutation}"
        );
    }
}

#[test]
fn original_pidfd_retirement_and_root_lifetime_cannot_be_inferred_from_receipt_pid() {
    for mutation in 0..10 {
        let (mut controller, mut retirement, mut rows, native, outputs) = fixture();
        match mutation {
            0 => retirement["held_processes"] = json!([]),
            1 => {
                let entry = retirement["held_processes"][0].clone();
                retirement["held_processes"]
                    .as_array_mut()
                    .unwrap()
                    .push(entry);
            }
            2 => retirement["held_processes"][0]["birth"] = 42.into(),
            3 => retirement["held_processes"][0]["pidfd_readable"] = false.into(),
            4 => controller["export_writer_native"]["pidfd_readable_after_stop"] = false.into(),
            5 => controller["export_writer_native"]["target_alive_after_writer"] = false.into(),
            6 => rows[1]["observation"]["native_wait_completed"] = false.into(),
            7 => rows[1]["observation"]["raw_wait_status"] = 256.into(),
            8 => rows[1]["observation"]["before_root_release"] = false.into(),
            _ => rows.push(rows[1].clone()),
        }
        assert!(
            validate(&controller, &retirement, &rows, &native, &outputs).is_err(),
            "mutation={mutation}"
        );
    }
}

#[test]
fn live_mutation_original_file_and_exact_final_bytes_remain_independent_requirements() {
    for mutation in 0..10 {
        let (mut controller, retirement, rows, native, mut outputs) = fixture();
        match mutation {
            0 => {
                controller["export_writer_native"]["second"]["bytes"] =
                    controller["export_writer_native"]["first"]["bytes"].clone()
            }
            1 => controller["export_writer_native"]["second"]["inode"] = 102.into(),
            2 => controller["export_writer_native"]["final"]["inode"] = 102.into(),
            3 => controller["export_candidate"]["inode"] = 102.into(),
            4 => controller["export_writer_native"]["second"]["device"] = 8.into(),
            5 => outputs.clear(),
            6 => outputs.push(outputs[0].clone()),
            7 => outputs[0].1[1] = 254,
            8 => {
                outputs[0].1.pop();
            }
            _ => outputs[0].1 = vec![0; 65536],
        }
        let error = validate(&controller, &retirement, &rows, &native, &outputs).unwrap_err();
        assert!(error.len() < 400, "unbounded diagnostic");
        if mutation >= 7 {
            assert!(error.contains("first-difference="));
        }
    }
}
