use memcordon_ci::private_candidate_facility_replay::{
    NativeFacilitySourcesV1, validate_capture_facility_source,
};
use memcordon_ci::private_candidate_replay::{ExpectedCaseSubjectV1, ReplayTaskV1};
use memcordon_ci::private_observer_session::{
    ObservedGenerationV1, ObserverIntervalRecordV1, ObserverSessionDescriptorV1, ObserverStageV1,
    ObserverSubjectV1,
};
use memcordon_ci::private_public_live::{HeldPublicTargetSamplesV1, HeldPublicTaskSampleV1};
use memcordon_core::private_facility_source_v1::*;
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use std::collections::BTreeMap;

const BASE: u64 = 1_000_000_000;
const SELECTOR: &str = "private_tcp::af_unix_socketpair_denied";
// A real native cBPF policy: AF_UNIX socket is denied; socketpair is denied;
// other calls (including close and the install itself) are allowed.
fn private_program() -> Vec<u8> {
    let mut bytes = Vec::new();
    for (code, jt, jf, k) in [
        (0x20u16, 0, 0, 0u32),
        (0x15, 0, 1, 41),
        (6, 0, 0, 0x50061),
        (0x15, 0, 1, 53),
        (6, 0, 0, 0x50001),
        (6, 0, 0, 0x7fff0000),
    ] {
        bytes.extend_from_slice(&code.to_le_bytes());
        bytes.extend_from_slice(&[jt, jf]);
        bytes.extend_from_slice(&k.to_le_bytes());
    }
    bytes
}
#[derive(Clone)]
struct Row {
    kind: u32,
    time: u64,
    pid: u32,
    occ: u64,
    nr: i64,
    args: [u64; 6],
    action: u32,
    result: i64,
    dev: u64,
    inode: u64,
    other: u32,
}
fn row(kind: u32, time: u64) -> Row {
    Row {
        kind,
        time,
        pid: 10,
        occ: 0,
        nr: 0,
        args: [0; 6],
        action: 0,
        result: 0,
        dev: 0,
        inode: 0,
        other: 0,
    }
}
fn call(kind: u32, time: u64, occ: u64, nr: i64, args: [u64; 6], action: u32, result: i64) -> Row {
    Row {
        occ,
        nr,
        args,
        action,
        result,
        ..row(kind, time)
    }
}
fn install(rows: &mut Vec<Row>, first: bool, program: &[u8]) {
    let (occ, time, head, prev, before) = if first {
        (1, 100, 0x3000, 0, 0)
    } else {
        (4, 1500, 0x4000, 0x3000, 1)
    };
    let args = [1, 0, 0x1000, 0, 0, 0];
    if !first {
        rows.push(Row {
            dev: prev,
            inode: 0,
            action: 2,
            result: 2,
            ..call(13, time - 100, occ, 317, args, 0, 0)
        });
    }
    rows.push(call(
        if first { 11 } else { 4 },
        time,
        occ,
        317,
        args,
        if first { 0 } else { 0x7fff0000 },
        0,
    ));
    rows.push(Row {
        dev: (program.len() / 8) as u64,
        inode: 0x2000,
        other: before,
        ..call(14, time + 100, occ, 317, args, 0, 0)
    });
    rows.push(call(5, time + 200, occ, 317, args, 0, 0));
    for (index, bytes) in program.chunks_exact(8).enumerate() {
        rows.push(Row {
            dev: head,
            inode: u64::from_le_bytes(bytes.try_into().unwrap()),
            other: (program.len() / 8) as u32,
            ..call(
                12,
                time + 300 + index as u64 * 20,
                occ,
                317,
                args,
                0,
                index as i64,
            )
        });
    }
    rows.push(Row {
        dev: head,
        inode: prev,
        other: before + 1,
        ..call(13, time + 450, occ, 317, args, 1, 2)
    });
}
fn decision(
    rows: &mut Vec<Row>,
    time: u64,
    occ: u64,
    nr: i64,
    args: [u64; 6],
    private: bool,
    result: i64,
) {
    rows.push(Row {
        dev: if private { 0x4000 } else { 0x3000 },
        inode: if private { 0x3000 } else { 0 },
        ..call(13, time - 20, occ, nr, args, 2, 2)
    });
    let errno = if nr == 41 { 97 } else { 1 };
    rows.push(call(
        4,
        time,
        occ,
        nr,
        args,
        if private { 0x50000 } else { 0x7fff0000 },
        if private { errno } else { 0 },
    ));
    rows.push(call(5, time + 20, occ, nr, args, 0, result));
}
fn capture(rows: &[Row]) -> Vec<u8> {
    let mut bytes = vec![0; 40];
    bytes[..4].copy_from_slice(&0x4d434b31u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&2u32.to_le_bytes());
    bytes[8..16].copy_from_slice(&(rows.len() as u64).to_le_bytes());
    bytes[24..28].copy_from_slice(&192u32.to_le_bytes());
    bytes[28..32].copy_from_slice(&31u32.to_le_bytes());
    bytes[32..36].copy_from_slice(&12u32.to_le_bytes());
    bytes[36..40].copy_from_slice(&0x01020304u32.to_le_bytes());
    for (index, row) in rows.iter().enumerate() {
        let mut raw = [0; 192];
        for (offset, value) in [
            (0, index as u64 + 1),
            (8, BASE + row.time),
            (16, 8),
            (24, 10_000_000),
            (32, row.dev),
            (40, row.inode),
            (48, row.nr as u64),
            (56, row.result as u64),
            (120, 12),
            (128, row.occ),
        ] {
            raw[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [
            (64, row.pid),
            (68, row.other),
            (72, if row.occ != 0 { 0xc000003e } else { 0 }),
            (76, row.action),
            (80, row.kind),
            (184, row.pid),
        ] {
            raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        raw[84..116].copy_from_slice(&[1; 32]);
        for (index, value) in row.args.iter().enumerate() {
            let offset = 136 + index * 8;
            raw[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&raw);
    }
    bytes
}
fn stat(pid: u32) -> String {
    let mut fields = vec!["0"; 20];
    fields[0] = "S";
    fields[19] = "1";
    format!("{pid} (facility helper) {}\n", fields.join(" "))
}
fn status(count: u32) -> Vec<u8> {
    format!("Pid:\t10\nTgid:\t10\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t{count}\n").into_bytes()
}
fn object(fd: i32) -> FacilityObjectV1 {
    FacilityObjectV1 {
        role: if fd == 5 {
            "operation-result".into()
        } else {
            "socketpair-result".into()
        },
        fd,
        device: 7,
        inode: 100 + fd as u64,
        fdinfo: format!(
            "pos:\t0\nflags:\t02000002\nmnt_id:\t1\nino:\t{}\n",
            100 + fd
        )
        .into_bytes(),
    }
}
fn held(
    begin: u64,
    end: u64,
    count: u32,
    objects: &[FacilityObjectV1],
) -> HeldPublicTargetSamplesV1 {
    let image = b"independently reviewed installed helper image".to_vec();
    let hash = hash_bytes(&image);
    let challenge = String::from(DiagnosticSha256::from_bytes([3; 32]));
    let revision = String::from(facility_source_revision_sha256());
    let mut argv = Vec::new();
    for argument in [
        "/usr/libexec/memcordon-sealed-agent",
        "release-facility-controls",
        "candidate-capability",
        SELECTOR,
        challenge.as_str(),
        "--source-revision",
        revision.as_str(),
    ] {
        argv.extend_from_slice(argument.as_bytes());
        argv.push(0);
    }
    let mut leaves=BTreeMap::from([
        ("image.raw".into(),image.clone()),("image-metadata.json".into(),serde_json::to_vec(&serde_json::json!({"device":3,"inode":4,"uid":0,"gid":0,"mode":0o100755,"nlink":1,"size":image.len(),"sha256":hash})).unwrap()),
        ("cmdline.raw".into(),argv),("status.raw".into(),status(count)),("tasks/10/status.raw".into(),status(count)),
        ("tasks/10/stat.raw".into(),stat(10).into_bytes()),("tasks/10/stat-after.raw".into(),stat(10).into_bytes()),
    ]);
    for object in objects {
        leaves.insert(format!("tasks/10/fds/{}/identity.json",object.fd),serde_json::to_vec(&serde_json::json!({"fd":object.fd,"link":format!("socket:[{}]",object.inode),"device":object.device,"inode":object.inode,"mode":0o140777})).unwrap());
        leaves.insert(
            format!("tasks/10/fds/{}/fdinfo.raw", object.fd),
            object.fdinfo.clone(),
        );
    }
    HeldPublicTargetSamplesV1 {
        schema_version: 1,
        pid: 10,
        start_time_ticks: 1,
        begin_monotonic_ns: BASE + begin,
        end_monotonic_ns: BASE + end,
        executable_sha256: hash,
        executable_device: 3,
        executable_inode: 4,
        tasks: vec![HeldPublicTaskSampleV1 {
            tid: 10,
            tgid: 10,
            start_time_ticks: 1,
            namespace_inodes: BTreeMap::from([("net".into(), 99)]),
        }],
        leaves,
    }
}
struct Fixture {
    descriptor: ObserverSessionDescriptorV1,
    sources: NativeFacilitySourcesV1,
    leaves: BTreeMap<String, Vec<u8>>,
    rows: Vec<Row>,
    report: FacilitySourceReportV1,
    fixture: DiagnosticSha256,
    filter: DiagnosticSha256,
    argv: Vec<String>,
}
impl Fixture {
    fn new() -> Self {
        let key = DiagnosticSha256::from_bytes([1; 32]);
        let marker = DiagnosticSha256::from_bytes([2; 32]);
        let source = facility_source_revision_sha256();
        let filter = hash_bytes(&private_program());
        let helper = FacilityProcessV1 {
            pid: 10,
            start_time_ticks: 1,
        };
        let objects = vec![object(5), object(6), object(7)];
        let mut rows = vec![Row {
            pid: 20,
            other: 10,
            result: 10_000_000,
            ..row(7, 50)
        }];
        install(&mut rows, true, &outer_allow_program_v1());
        decision(&mut rows, 850, 2, 41, [1, 0x80001, 0, 0, 0, 0], false, 5);
        decision(
            &mut rows,
            1150,
            3,
            53,
            [1, 0x80001, 0, 0x9000, 0, 0],
            false,
            0,
        );
        install(&mut rows, false, &private_program());
        decision(&mut rows, 2350, 5, 41, [1, 0x80001, 0, 0, 0, 0], true, -97);
        decision(
            &mut rows,
            2650,
            6,
            53,
            [1, 0x80001, 0, 0x9000, 0, 0],
            true,
            -1,
        );
        for (index, object) in objects.iter().enumerate() {
            // close is ALLOW under the actual private program.
            let time = 3000 + index as u64 * 100;
            rows.push(Row {
                dev: 0x4000,
                inode: 0x3000,
                ..call(
                    13,
                    time - 20,
                    7 + index as u64,
                    3,
                    [object.fd as u64, 0, 0, 0, 0, 0],
                    2,
                    2,
                )
            });
            rows.push(call(
                4,
                time,
                7 + index as u64,
                3,
                [object.fd as u64, 0, 0, 0, 0, 0],
                0x7fff0000,
                0,
            ));
            rows.push(call(
                5,
                time + 20,
                7 + index as u64,
                3,
                [object.fd as u64, 0, 0, 0, 0, 0],
                0,
                0,
            ));
        }
        rows.push(row(8, 3400));
        rows.push(Row {
            pid: 20,
            other: 10,
            result: 10_000_000,
            ..row(9, 3500)
        });
        let make_call =
            |operation, phase, before, after, nr, args, result, errno, operand| FacilityCallV1 {
                operation,
                phase,
                audit_arch: 0xc000003e,
                syscall_nr: nr,
                args,
                before_monotonic_ns: BASE + before,
                after_monotonic_ns: BASE + after,
                result,
                errno,
                namespace_before: 99,
                namespace_after: 99,
                operand,
            };
        let report = FacilitySourceReportV1 {
            schema_version: 1,
            source_revision_sha256: source.clone(),
            selector: SELECTOR.into(),
            parent_result_key: key.clone(),
            helper: helper.clone(),
            source_process: None,
            private_filter_sha256: filter.clone(),
            outer_filter_sha256: hash_bytes(&outer_allow_program_v1()),
            status_after_outer_install: status(1),
            status_after_private_install: status(2),
            calls: vec![
                make_call(
                    FacilityOperationV1::Socket,
                    FacilityPhaseV1::Outer,
                    800,
                    1000,
                    41,
                    [1, 0x80001, 0, 0, 0, 0],
                    5,
                    0,
                    FacilityOperandV1::Scalars,
                ),
                make_call(
                    FacilityOperationV1::Socketpair,
                    FacilityPhaseV1::Outer,
                    1100,
                    1300,
                    53,
                    [1, 0x80001, 0, 0x9000, 0, 0],
                    0,
                    0,
                    FacilityOperandV1::Socketpair {
                        output_address: 0x9000,
                        slots_before: [-1; 2],
                        slots_after: [6, 7],
                    },
                ),
                make_call(
                    FacilityOperationV1::Socket,
                    FacilityPhaseV1::Private,
                    2300,
                    2500,
                    41,
                    [1, 0x80001, 0, 0, 0, 0],
                    -1,
                    97,
                    FacilityOperandV1::Scalars,
                ),
                make_call(
                    FacilityOperationV1::Socketpair,
                    FacilityPhaseV1::Private,
                    2600,
                    2800,
                    53,
                    [1, 0x80001, 0, 0x9000, 0, 0],
                    -1,
                    1,
                    FacilityOperandV1::Socketpair {
                        output_address: 0x9000,
                        slots_before: [-1; 2],
                        slots_after: [-1; 2],
                    },
                ),
            ],
            closes: objects
                .iter()
                .enumerate()
                .map(|(index, object)| FacilityCloseV1 {
                    object: object.clone(),
                    before_monotonic_ns: BASE + 2950 + index as u64 * 100,
                    after_monotonic_ns: BASE + 3050 + index as u64 * 100,
                    result: 0,
                })
                .collect(),
            source_wait_status: None,
            helper_wait_status: 0,
        };
        let sources = NativeFacilitySourcesV1 {
            schema_version: 1,
            capture_path: "capture.bin".into(),
            clock_path: "clock.json".into(),
            admission_path: "admission.json".into(),
            report_path: "report.json".into(),
            outer_gate_path: "outer.json".into(),
            outer_ack_path: "outer.ack".into(),
            outer_held_path: "outer.sample".into(),
            private_gate_path: "private.json".into(),
            private_ack_path: "private.ack".into(),
            private_held_path: "private.sample".into(),
            source_outer_held_path: None,
            source_private_held_path: None,
            product_request_path: Some("product/request.json".into()),
        };
        let mut leaves = BTreeMap::new();
        leaves.insert("capture.bin".into(), capture(&rows));
        leaves.insert("clock.json".into(),serde_json::to_vec(&serde_json::json!({"schema_version":1,"reader_pid":42,"reader_start_ticks":1,"stat_before":stat(42),"stat_after":stat(42),"time_namespace_before":"time:[12]","time_namespace_after":"time:[12]","timens_offsets":"monotonic 0 0\nboottime 0 0\n","clk_tck_stdout":b"100\n","clk_tck_exit_success":true})).unwrap());
        let challenge = [3u8; 32];
        leaves.insert("product/request.json".into(),serde_json::to_vec(&serde_json::json!({"schema_version":1,"stage":"candidate-capability","selector":SELECTOR,"challenge":hex::encode(challenge),"result_key":key,"installation_epoch":marker,"candidate_manifest_sha256":marker,"service_generation_sha256":marker,"coordinator":{"pid":50,"start_time":1}})).unwrap());
        let admission=serde_json::to_vec(&serde_json::json!({"schema_version":1,"protocol":"candidate-independent-facility-source-v1","source_revision_sha256":source,"parent_result_key":key,"selector":SELECTOR,"challenge":challenge,"installation_epoch":marker,"candidate_manifest_sha256":marker,"filter_sha256":filter,"installed_inspection_sha256":marker,"service_generation_sha256":marker,"coordinator":{"pid":20,"start_time":1},"admission_monotonic_ns":BASE+10})).unwrap();
        let admission_sha = hash_bytes(&admission);
        leaves.insert("admission.json".into(), admission);
        leaves.insert("report.json".into(), serde_json::to_vec(&report).unwrap());
        for (phase, name, count, observed, begin, end, objects) in [
            (FacilityPhaseV1::Outer, "outer", 1, 600, 610, 650, &[][..]),
            (
                FacilityPhaseV1::Private,
                "private",
                2,
                2100,
                2110,
                2150,
                objects.as_slice(),
            ),
        ] {
            let gate=serde_json::to_vec(&serde_json::json!({"schema_version":1,"phase":phase,"parent_result_key":key,"source_revision_sha256":source,"admission_sha256":admission_sha,"helper":helper,"objects":objects,"status":status(count),"observed_monotonic_ns":BASE+observed})).unwrap();
            let ack=serde_json::to_vec(&serde_json::json!({"schema_version":1,"phase":phase,"parent_result_key":key,"source_revision_sha256":source,"gate_sha256":hash_bytes(&gate)})).unwrap();
            leaves.insert(format!("{name}.json"), gate);
            leaves.insert(format!("{name}.ack"), ack);
            leaves.insert(
                format!("{name}.sample"),
                serde_json::to_vec(&held(begin, end, count, objects)).unwrap(),
            );
        }
        let descriptor = ObserverSessionDescriptorV1 {
            schema_version: 1,
            session_nonce: hex::encode([9; 32]),
            subject: ObserverSubjectV1 {
                stage: ObserverStageV1::Candidate,
                repository_id: 1,
                run_id: 2,
                run_attempt: 1,
                job_id: 3,
                runner_id: 4,
                target: "x86_64-unknown-linux-gnu".into(),
                source_commit: "a".repeat(40),
                release_version: "0.5.7-dev".into(),
                build_sha256: marker.clone(),
                intent_sha256: marker.clone(),
                catalogue_sha256: marker.clone(),
                host_profile_sha256: marker.clone(),
            },
            enrolled_host: "test".into(),
            boot_id: "test-boot".into(),
            kernel_btf_sha256: marker.clone(),
            observer_executable_sha256: marker.clone(),
            generations: vec![ObservedGenerationV1 {
                generation: 0,
                installation_epoch: marker.clone(),
                installed_manifest_sha256: marker.clone(),
                installed_receipt_sha256: marker.clone(),
                service_identity_sha256: marker.clone(),
                broker_identity_sha256: marker.clone(),
                transaction_sha256: marker.clone(),
                observer_bundle_sha256: marker.clone(),
                begin_monotonic_ns: BASE,
                end_monotonic_ns: BASE + 4000,
            }],
            intervals: vec![ObserverIntervalRecordV1 {
                interval_id: marker.clone(),
                logical_case_key: key,
                generation: 0,
                purpose: "facility-controls".into(),
                ordinal: 0,
                capture_path: "capture.bin".into(),
                capture_sha256: hash_bytes(&leaves["capture.bin"]),
                controls_paths: Vec::new(),
                sample_paths: leaves
                    .keys()
                    .filter(|path| path.as_str() != "capture.bin")
                    .cloned()
                    .collect(),
                arm_monotonic_ns: BASE,
                begin_monotonic_ns: BASE,
                end_monotonic_ns: BASE + 4000,
                detach_monotonic_ns: BASE + 4100,
                loss_count: 0,
                first_sequence: 1,
                last_sequence: rows.len() as u64,
            }],
        };
        let fixture = held(610, 650, 1, &[]).executable_sha256;
        Self {
            descriptor,
            sources,
            leaves,
            rows,
            report,
            fixture,
            filter,
            argv: vec!["/usr/libexec/memcordon-sealed-agent".into()],
        }
    }
    fn verify(&self) -> memcordon_ci::Result<()> {
        let source = facility_source_revision_sha256();
        let challenge = [3; 32];
        let expected = ExpectedCaseSubjectV1 {
            selector: SELECTOR,
            result_key: &self.report.parent_result_key,
            fixture_sha256: &self.fixture,
            filter_sha256: &self.filter,
            fixture_argv: &self.argv,
            uid: 1000,
            gid: 1000,
            groups: &[1000],
            port: 40000,
            challenge: &challenge,
            auxiliary_semantics_sha256: None,
            filter_install_source_sha256: None,
            facility_source_sha256: Some(&source),
            host_preservation_source_sha256: None,
            reuse_source_sha256: None,
            exact_response: b"actual reviewed response",
        };
        let target = ReplayTaskV1 {
            tid: 99,
            tgid: 99,
            start_boottime_ns: 10_000_000,
            cgroup_inode: 8,
            time_ns_inode: 12,
        };
        validate_capture_facility_source(
            &self.descriptor,
            &expected,
            &target,
            "product.bin",
            0,
            &self.sources,
            &self.leaves,
        )
    }
    fn retain_rows(&mut self) {
        self.leaves
            .insert("capture.bin".into(), capture(&self.rows));
    }
}

#[test]
fn two_actual_kernel_installs_and_original_held_contexts_prove_controls() {
    Fixture::new().verify().unwrap();
}
#[test]
fn lost_legacy_substituted_filter_or_uninstalled_report_are_rejected() {
    for mutation in 0..4 {
        let mut fixture = Fixture::new();
        let bytes = fixture.leaves.get_mut("capture.bin").unwrap();
        match mutation {
            0 => bytes[16..24].copy_from_slice(&1u64.to_le_bytes()),
            1 => bytes[28..32].copy_from_slice(&15u32.to_le_bytes()),
            2 => bytes[40 + 4 * 192 + 40..40 + 4 * 192 + 48].copy_from_slice(&0u64.to_le_bytes()),
            _ => {
                fixture.rows.retain(|row| row.kind != 12);
                fixture.retain_rows();
            }
        }
        assert!(fixture.verify().is_err(), "mutation {mutation}");
    }
}
#[test]
fn actual_return_operands_object_lifetime_and_owned_reap_are_mandatory() {
    for mutation in 0..6 {
        let mut fixture = Fixture::new();
        match mutation {
            0 => {
                fixture
                    .rows
                    .iter_mut()
                    .find(|row| row.kind == 5 && row.occ == 5)
                    .unwrap()
                    .result = -1
            }
            1 => {
                fixture
                    .rows
                    .iter_mut()
                    .find(|row| row.kind == 4 && row.occ == 2)
                    .unwrap()
                    .args[0] = 2
            }
            2 => {
                fixture
                    .rows
                    .iter_mut()
                    .find(|row| row.kind == 9)
                    .unwrap()
                    .pid = 30
            }
            3 => fixture.rows.retain(|row| !(row.kind == 5 && row.occ == 7)),
            4 => {
                let bytes = fixture.leaves.get_mut("private.sample").unwrap();
                let mut sample: HeldPublicTargetSamplesV1 = serde_json::from_slice(bytes).unwrap();
                sample.leaves.remove("tasks/10/fds/5/identity.json");
                *bytes = serde_json::to_vec(&sample).unwrap();
            }
            _ => {
                fixture
                    .rows
                    .iter_mut()
                    .find(|row| row.kind == 8)
                    .unwrap()
                    .result = 9
            }
        }
        fixture.retain_rows();
        assert!(fixture.verify().is_err(), "mutation {mutation}");
    }
}
#[test]
fn independent_optin_sha_ack_enrollment_and_phase_timing_are_required() {
    for mutation in 0..5 {
        let mut fixture = Fixture::new();
        match mutation {
            0 => fixture.descriptor.intervals[0].purpose = "ordinary".into(),
            1 => fixture.sources.outer_held_path = fixture.sources.private_held_path.clone(),
            2 => fixture.leaves.get_mut("outer.ack").unwrap().fill(b' '),
            3 => fixture.descriptor.intervals[0]
                .sample_paths
                .retain(|path| path != "outer.sample"),
            _ => {
                let bytes = fixture.leaves.get_mut("private.sample").unwrap();
                let mut sample: HeldPublicTargetSamplesV1 = serde_json::from_slice(bytes).unwrap();
                sample.end_monotonic_ns = BASE + 2400;
                *bytes = serde_json::to_vec(&sample).unwrap();
            }
        }
        assert!(fixture.verify().is_err(), "mutation {mutation}");
    }
}

#[test]
fn candidate_product_request_must_bind_original_generation_and_cannot_alias_auxiliary() {
    for mutation in 0..4 {
        let mut fixture = Fixture::new();
        match mutation {
            0 => fixture.sources.product_request_path = None,
            1 => {
                fixture.sources.product_request_path = Some(fixture.sources.admission_path.clone())
            }
            _ => {
                let bytes = fixture.leaves.get_mut("product/request.json").unwrap();
                let mut request: serde_json::Value = serde_json::from_slice(bytes).unwrap();
                let field = if mutation == 2 {
                    "service_generation_sha256"
                } else {
                    "installation_epoch"
                };
                request[field] =
                    serde_json::to_value(DiagnosticSha256::from_bytes([11; 32])).unwrap();
                *bytes = serde_json::to_vec(&request).unwrap();
            }
        }
        assert!(fixture.verify().is_err(), "product mutation {mutation}");
    }
}
