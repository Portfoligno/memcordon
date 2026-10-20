#[path = "support/linux_import_case.rs"]
mod linux_import_case;
#[path = "support/linux_import_exclusion_case.rs"]
mod linux_import_exclusion_case;
#[path = "support/linux_ingress_case.rs"]
mod linux_ingress_case;
#[path = "support/linux_installed_case.rs"]
mod linux_installed_case;
#[path = "support/persisted_case.rs"]
mod persisted_case;
use serde_json::json;

fn rebind_inspection(case: &mut persisted_case::PersistedCase) {
    let command = linux_installed_case::read(case, "exclusion-inspection/invocation.json");
    let census = linux_installed_case::read(case, "exclusion-inspection/stdout.json");
    linux_import_case::command_graph(case, "exclusion-inspection", command, 802, 902, 0, census);
}

#[test]
fn undeclared_socket_exclusion_requires_complete_persisted_observation() {
    let case = linux_import_exclusion_case::excluded();
    case.validate().unwrap();
}

#[test]
fn exclusion_rejects_rehashed_installed_census_and_source_authority_substitutions() {
    for mutation in 0..12 {
        let mut case = linux_import_exclusion_case::excluded();
        case.validate().unwrap();
        case.mutate("exclusion-inspection/stdout.json", |c| match mutation {
            0 => c["cutoff_unix_millis"] = json!(101),
            1 => {
                c["members"].as_array_mut().unwrap().pop();
            }
            2 => c["root"]["inode"] = json!(400),
            3 => c["members"][0]["identity"]["inode"] = json!(401),
            4 => c["members"][2]["identity"]["inode"] = json!(500),
            5 => c["members"][2]["path"] = json!("owned-source/input-socket"),
            6 => c["members"][2]["identity"]["mode"] = json!(0o140755),
            7 => c["members"][2]["object"]["sha256"] = json!("00".repeat(32)),
            8 => c["members"][2]["object"]["capability_absent"] = json!(false),
            9 => c["members"][2]["identity"]["uid"] = json!(65534),
            10 => c["members"].as_array_mut().unwrap().swap(1, 2),
            11 => c["target"] = json!("aarch64-unknown-linux-gnu"),
            _ => unreachable!(),
        });
        rebind_inspection(&mut case);
        assert!(case.validate().is_err(), "census mutation {mutation}");
    }
    for mutation in 0..3 {
        let mut case = linux_import_exclusion_case::excluded();
        case.mutate("exclusion-source-after.json", |a| match mutation {
            0 => a["inventory"]["root"]["inode"] = json!(999),
            1 => a["listener"]["inode"] = json!(999),
            2 => {
                a["inventory"]["members"].as_array_mut().unwrap().pop();
            }
            _ => unreachable!(),
        });
        assert!(case.validate().is_err(), "source mutation {mutation}");
    }
}

#[test]
fn exclusion_rejects_foreign_command_status_receipt_and_missing_retirement() {
    for mutation in 0..9 {
        let mut case = linux_import_exclusion_case::excluded();
        match mutation {
            0 => case.mutate("exclusion-inspection/invocation.json", |c| {
                c["argv"][7] = json!("101")
            }),
            1 => case.mutate("exclusion-inspection/invocation.json", |c| {
                c["program"] = json!("/tmp/foreign-agent")
            }),
            2 => case.mutate("exclusion-inspection/invocation.json", |c| {
                c["scenario"] = json!("imported-socket")
            }),
            3 => case.mutate("import/stdout.json", |r| r["member_count"] = json!(999)),
            4 => case.mutate("import/stdout.json", |r| {
                r["policy_activated"] = json!(true)
            }),
            5 => case.mutate("import/exit.json", |r| {
                r["native_exit"] = json!(1);
                r["success"] = json!(false);
            }),
            6 => case.mutate("exclusion-inspection/exit.json", |r| {
                r["native_exit"] = json!(1);
                r["success"] = json!(false);
            }),
            7 => case.mutate("import-retirement/stdout.json", |r| {
                r["storage_absent"] = json!(false)
            }),
            8 => case.mutate("case-evidence.json", |e| {
                e["outcome"]["stdout"] = json!("missing-census.json")
            }),
            _ => unreachable!(),
        }
        if mutation <= 2 {
            rebind_inspection(&mut case);
        }
        if matches!(mutation, 3 | 4) {
            let command = linux_installed_case::read(&case, "import/invocation.json");
            let receipt = linux_installed_case::read(&case, "import/stdout.json");
            linux_import_case::command_graph(&mut case, "import", command, 800, 900, 0, receipt);
            let hash = memcordon_readiness_verifier::sha256(
                &std::fs::read(case.root.path().join("import/stdout.json")).unwrap(),
            );
            case.mutate("import-census.json", |c| {
                c["stdout_sha256"] = json!(hash);
                c["native_census"]["result_sha256"] = json!(hash);
            });
        }
        if mutation == 7 {
            let command = linux_installed_case::read(&case, "import-retirement/invocation.json");
            let receipt = linux_installed_case::read(&case, "import-retirement/stdout.json");
            linux_import_case::command_graph(
                &mut case,
                "import-retirement",
                command,
                801,
                901,
                0,
                receipt,
            );
        }
        assert!(case.validate().is_err(), "command mutation {mutation}");
    }
}
