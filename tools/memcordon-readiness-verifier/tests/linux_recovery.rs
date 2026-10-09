use memcordon_readiness_verifier::{
    LinuxCrashExit, LinuxCrashIntent, LinuxRecoveryProcess, validate_linux_crash_controller,
};
use sha2::{Digest, Sha256};

#[test]
fn native_recovery_process_joins_original_selected_program_and_fast_exit() {
    use memcordon_readiness_verifier::{
        LinuxRecoveryCapture, LinuxRecoveryCommandProcess, LinuxRecoveryInvocation,
        validate_linux_recovery_command_process,
    };
    let source =
        serde_json::json!({"kind":"working","commit":"1".repeat(40),"version":"0.5.8-dev"});
    let identity = serde_json::json!({"run_id":"run","source_commit":"1".repeat(40),"source_tree_sha256":"2".repeat(64),"version":"0.5.8-dev"});
    let admin = "/var/lib/memcordon-native-readiness/fixture/component-package-admin";
    let program = format!("{admin}/native-package-cleanup-agent");
    let target = "x86_64-unknown-linux-gnu";
    let digest = |bytes: &[u8]| {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let owner = serde_json::json!({"format":"memcordon.consumer-readiness.native-package-owner","revision":1,
        "source":source,"distribution":{"target":target,"features":[],"binaries":["memcordon-sealed-agent"],"units":[]},
        "cleanup_agent":program,"cleanup_agent_sha256":"ab".repeat(32),"cleanup_agent_device":1,"cleanup_agent_inode":2,
        "original_installation_absent":true,"legacy":{}});
    let owner_bytes = serde_json::to_vec(&owner).unwrap();
    let boundary = b"structural boundary";
    let ownership = b"structural ownership";
    let invocation = serde_json::json!({"format":"memcordon.native-component-recovery-invocation","revision":1,
        "identity":identity,"run_id":"run","recipe_id":"recovery","native_target":target,
        "program":program.as_bytes(),"arguments":[b"package".to_vec(),b"policy".to_vec(),b"recover".to_vec(),b"--json".to_vec()],
        "working_directory":b"/protected/workspace".to_vec(),"environment":[],"executable_sha256":"ab".repeat(32),
        "package_owner_sha256":digest(&owner_bytes),"selected_program":{"device":1,"inode":2,"length":100,"links":1,"uid":0,"mode":0o100555},
        "work_deadline_unix_millis":100,"cleanup_deadline_unix_millis":200,"boundary_sha256":digest(boundary),"ownership_sha256":digest(ownership)});
    let process = serde_json::json!({"format":"memcordon.native-component-recovery-process","revision":1,"invocation_sha256":"",
        "creation":{"process_id":101,"birth":201,"image":{"device":1,"inode":2}},"native_wait_status":0,
        "retirement":{"process_id":101,"birth":201,"pidfd_retirement_observed":true}});
    // Structural process vector; no native package execution is claimed.
    let check = |invocation: serde_json::Value, mut process: serde_json::Value| {
        let invocation_bytes = serde_json::to_vec(&invocation).unwrap();
        process["invocation_sha256"] = serde_json::json!(digest(&invocation_bytes));
        let stdout =
            b"{\"format\":\"memcordon.native-recovery\",\"revision\":1,\"outstanding\":[]}"
                .to_vec();
        let capture = LinuxRecoveryCapture {
            format: "memcordon.native-component-recovery-capture".into(),
            revision: 1,
            invocation_sha256: digest(&invocation_bytes),
            native_wait_status: 0,
            status: Some(0),
            stdout_sha256: digest(&stdout),
            stdout,
            stderr: vec![],
            stderr_sha256: digest(&[]),
        };
        let invocation: LinuxRecoveryInvocation =
            serde_json::from_value(invocation).map_err(|error| error.to_string())?;
        let process: LinuxRecoveryCommandProcess =
            serde_json::from_value(process).map_err(|error| error.to_string())?;
        validate_linux_recovery_command_process(
            &invocation,
            &process,
            &capture,
            &invocation_bytes,
            &owner_bytes,
            &source,
            &identity,
            "recovery",
            target,
            admin,
            boundary,
            ownership,
            100,
            200,
        )
    };
    check(invocation.clone(), process.clone()).unwrap();
    let mut fast = process.clone();
    fast["creation"]["image"] = serde_json::Value::Null;
    check(invocation.clone(), fast).unwrap();
    for (pointer, value) in [
        ("/program", serde_json::json!(b"/other/agent".to_vec())),
        (
            "/arguments",
            serde_json::json!([b"package".to_vec(), b"recover".to_vec(), b"--json".to_vec()]),
        ),
        ("/selected_program/inode", serde_json::json!(3)),
        ("/selected_program/mode", serde_json::json!(0o100777)),
        (
            "/environment",
            serde_json::json!([{"name":"LD_PRELOAD","value":"other"}]),
        ),
        ("/cleanup_deadline_unix_millis", serde_json::json!(201)),
        ("/package_owner_sha256", serde_json::json!("cd".repeat(32))),
    ] {
        let mut changed = invocation.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            check(changed, process.clone()).is_err(),
            "accepted native recovery command change {pointer}"
        );
    }
    for (pointer, value) in [
        ("/creation/image/inode", serde_json::json!(3)),
        ("/retirement/birth", serde_json::json!(202)),
        (
            "/retirement/pidfd_retirement_observed",
            serde_json::json!(false),
        ),
        ("/native_wait_status", serde_json::json!(9)),
    ] {
        let mut changed = process.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(check(invocation.clone(), changed).is_err());
    }
}

#[test]
fn recovery_capture_requires_real_native_zero_and_exact_complete_response() {
    use memcordon_readiness_verifier::{LinuxRecoveryCapture, validate_linux_recovery_capture};
    let invocation = b"original structural invocation";
    let stdout =
        b"{\"format\":\"memcordon.native-recovery\",\"revision\":1,\"outstanding\":[]}".to_vec();
    let digest = |bytes: &[u8]| {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let capture = LinuxRecoveryCapture {
        format: "memcordon.native-component-recovery-capture".into(),
        revision: 1,
        invocation_sha256: digest(invocation),
        native_wait_status: 0,
        status: Some(0),
        stdout_sha256: digest(&stdout),
        stdout,
        stderr: vec![],
        stderr_sha256: digest(&[]),
    };
    validate_linux_recovery_capture(&capture, invocation).unwrap();
    let mut changed = capture.clone();
    changed.native_wait_status = 9;
    changed.status = None;
    assert!(validate_linux_recovery_capture(&changed, invocation).is_err());
    let mut changed = capture.clone();
    changed.invocation_sha256 = "ab".repeat(32);
    assert!(validate_linux_recovery_capture(&changed, invocation).is_err());
    let mut changed = capture.clone();
    changed.stderr = b"uncaptured".to_vec();
    assert!(validate_linux_recovery_capture(&changed, invocation).is_err());
    for stdout in [b"{\"format\":\"memcordon.native-recovery\",\"revision\":1,\"outstanding\":[{}]}".as_slice(),
        b"{\"format\":\"memcordon.native-recovery\",\"revision\":1,\"outstanding\":[],\"account_retired\":true}".as_slice(),
        b"{\"format\":\"memcordon.native-recovery\",\"revision\":1,\"outstanding\":[],\"outstanding\":[]}".as_slice()] {
        let mut changed=capture.clone();changed.stdout=stdout.to_vec();changed.stdout_sha256=digest(stdout);
        assert!(validate_linux_recovery_capture(&changed,invocation).is_err());
    }
}

#[test]
fn pre_account_boundary_keeps_admission_pending_after_actual_native_empty() {
    use memcordon_readiness_verifier::{LinuxPreAccountNative, validate_linux_pre_account_native};
    let reference = b"actual retained metadata fixture";
    let export = b"actual retained export fixture";
    let attempt = "a1".repeat(16);
    let wire = serde_json::json!({"attempt_id":attempt,"native_wait_status":0,
        "cgroup_retirement":{"schema_version":1,"cgroup_path":format!("/sys/fs/cgroup/memcordon-sealed/{attempt}"),
            "cgroup_inode":400,"last_members":[],"empty_monotonic_ns":100,"removed_monotonic_ns":101},
        "root_layout":{},"execution_identity":{},"export_path":"/protected/export",
        "export_receipt_sha256":Sha256::digest(export).iter().map(|byte|format!("{byte:02x}")).collect::<String>(),
        "admission_reference":{"device":1,"inode":401,"length":reference.len(),"links":1,"uid":0,
            "mode":0o100600,"named_absent":false,"account_uid":10000,"retired":false}});
    // Structural primitive; layout/provider/source/root custody is not proved.
    let native: LinuxPreAccountNative = serde_json::from_value(wire.clone()).unwrap();
    validate_linux_pre_account_native(&native, 10000, reference, export).unwrap();
    for (pointer, value) in [
        ("/admission_reference/retired", serde_json::json!(true)),
        ("/admission_reference/links", serde_json::json!(0)),
        ("/cgroup_retirement/last_members", serde_json::json!([101])),
        (
            "/cgroup_retirement/removed_monotonic_ns",
            serde_json::json!(99),
        ),
        ("/native_wait_status", serde_json::json!(9)),
        ("/cgroup_retirement/cgroup_inode", serde_json::json!(0)),
    ] {
        let mut changed = wire.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            validate_linux_pre_account_native(
                &serde_json::from_value(changed).unwrap(),
                10000,
                reference,
                export
            )
            .is_err()
        );
    }
    assert!(validate_linux_pre_account_native(&native, 10001, reference, export).is_err());
    assert!(
        validate_linux_pre_account_native(&native, 10000, reference, b"changed export").is_err()
    );
    // Original ownership is structural evidence, not successful recovery.
    use memcordon_readiness_verifier::{LinuxRecoveryOwnership, validate_linux_recovery_ownership};
    let parent = "/var/lib/memcordon/sealed";
    let journal_bytes = b"original journal";
    let reservation_bytes = b"original reservation";
    let reference_path = format!("{parent}/{attempt}.mixed-admission");
    let reservation_path = format!("{parent}/account-original.reservation");
    let leaf = |path: &str, inode: u64, length: usize| {
        serde_json::json!({"path":path,"device":1,"inode":inode,
        "length":length,"links":1,"uid":0,"mode":0o100600,"parent_device":1,
        "parent_inode":20,"parent_uid":0,"parent_mode":0o040700})
    };
    let mut journal = leaf(&format!("{parent}/{attempt}"), 30, journal_bytes.len());
    journal["parent_path"] = serde_json::json!(parent);
    let mut reservation = leaf(&reservation_path, 31, reservation_bytes.len());
    reservation["bytes"] = serde_json::json!(reservation_bytes.to_vec());
    reservation["sha256"] = serde_json::json!(
        Sha256::digest(reservation_bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let ownership = serde_json::json!({"journal":journal,
        "journal_sha256":Sha256::digest(journal_bytes).iter().map(|byte|format!("{byte:02x}")).collect::<String>(),
        "account":{"attempt_id":attempt,"account_uid":10000,"reference_path":reference_path,
            "reference":wire["admission_reference"],"reservation":reservation}});
    let check = |value: serde_json::Value| {
        let parsed: LinuxRecoveryOwnership =
            serde_json::from_value(value).map_err(|error| error.to_string())?;
        validate_linux_recovery_ownership(
            &parsed,
            &native,
            journal_bytes,
            reference,
            &reference_path,
            &reservation_path,
        )
    };
    check(ownership.clone()).unwrap();
    for (pointer, value) in [
        ("/journal/parent_inode", serde_json::json!(21)),
        (
            "/journal/path",
            serde_json::json!(format!("{parent}/other")),
        ),
        ("/account/reservation/links", serde_json::json!(0)),
        (
            "/account/reservation/parent_mode",
            serde_json::json!(0o040777),
        ),
        ("/account/reservation/bytes", serde_json::json!([1, 2, 3])),
        ("/account/reference/retired", serde_json::json!(true)),
        ("/account/account_uid", serde_json::json!(10001)),
    ] {
        let mut changed = ownership.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            check(changed).is_err(),
            "accepted ownership reassociation {pointer}"
        );
    }
    let mut changed = ownership.clone();
    changed["journal"]["invented_removed"] = serde_json::json!(true);
    assert!(check(changed).is_err());
    use memcordon_readiness_verifier::{
        LinuxRecoveryReservationRecord, validate_linux_recovery_reservation,
    };
    let worker = LinuxRecoveryProcess {
        pid: 100,
        birth: 200,
    };
    let boot = "12345678-1234-1234-1234-123456789abc";
    let record = LinuxRecoveryReservationRecord {
        format: "memcordon.account-reservation".into(),
        revision: 1,
        user_namespace_device: 5,
        user_namespace_inode: 6,
        uid: 10000,
        attempt: [0xa1; 16],
        owner_pid: worker.pid,
        owner_birth: worker.birth,
        boot_identity: boot.into(),
    };
    let mut bound: LinuxRecoveryOwnership = serde_json::from_value(ownership).unwrap();
    bound.account.reservation.path = format!("{parent}/account-5-6-10000.reservation");
    bound.account.reservation.bytes = serde_json::to_vec(&record).unwrap();
    let reservation_check = |record: &LinuxRecoveryReservationRecord| {
        let mut changed = bound.clone();
        changed.account.reservation.bytes = serde_json::to_vec(record).unwrap();
        validate_linux_recovery_reservation(record, &changed, &worker, (5, 6), boot)
    };
    reservation_check(&record).unwrap();
    for pointer in [
        "/owner_pid",
        "/owner_birth",
        "/uid",
        "/user_namespace_inode",
    ] {
        let mut changed = serde_json::to_value(&record).unwrap();
        let current = changed.pointer(pointer).unwrap().as_u64().unwrap();
        *changed.pointer_mut(pointer).unwrap() = serde_json::json!(current + 1);
        assert!(reservation_check(&serde_json::from_value(changed).unwrap()).is_err());
    }
    let mut changed = record.clone();
    changed.attempt[0] ^= 1;
    assert!(reservation_check(&changed).is_err());
    let mut changed = record.clone();
    changed.boot_identity = "87654321-1234-1234-1234-123456789abc".into();
    assert!(reservation_check(&changed).is_err());
    let mut changed = bound.clone();
    changed.account.reservation.path = format!("{parent}/account-5-7-10000.reservation");
    assert!(validate_linux_recovery_reservation(&record, &changed, &worker, (5, 6), boot).is_err());
    let mut changed = bound.clone();
    changed.account.reservation.bytes = b"{}".to_vec();
    assert!(validate_linux_recovery_reservation(&record, &changed, &worker, (5, 6), boot).is_err());
    use memcordon_readiness_verifier::{
        LinuxRecoveredOwnership, validate_linux_recovered_ownership,
    };
    bound.account.reservation.length = bound.account.reservation.bytes.len() as u64;
    bound.account.reservation.sha256 = Sha256::digest(&bound.account.reservation.bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let original_bytes = serde_json::to_vec(&bound).unwrap();
    let boundary_bytes = b"structural original boundary";
    let checkpoint_bytes = b"structural original checkpoint";
    let identity = serde_json::json!({"run_id":"run","source_commit":"1".repeat(40),"source_tree_sha256":"2".repeat(64),"version":"0.5.8-dev"});
    let mut leaves = vec![];
    for (role, path, original) in [
        (
            "journal",
            bound.journal.path.as_str(),
            serde_json::to_value(&bound.journal).unwrap(),
        ),
        (
            "reference",
            bound.account.reference_path.as_str(),
            serde_json::to_value(&bound.account.reference).unwrap(),
        ),
        (
            "reservation",
            bound.account.reservation.path.as_str(),
            serde_json::to_value(&bound.account.reservation).unwrap(),
        ),
    ] {
        leaves.push(serde_json::json!({"role":role,"original":original,"path":path,
            "basename":std::path::Path::new(path).file_name().unwrap().to_str().unwrap(),"parent_path":parent,
            "parent_device":1,"parent_inode":20,"parent_uid":0,"parent_mode":0o040700,"native_errno":2}));
    }
    let digest = |bytes: &[u8]| {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let recovered = serde_json::json!({"format":"memcordon.native-component-recovered-ownership","revision":1,
        "identity":identity,"run_id":"run","recipe_id":"recovery","native_target":"x86_64-unknown-linux-gnu",
        "boundary_sha256":digest(boundary_bytes),"ownership_sha256":digest(&original_bytes),"checkpoint_sha256":digest(checkpoint_bytes),
        "attempt_id":attempt,"account_uid":10000,"account_gid":10000,"work_deadline_unix_millis":100,
        "cleanup_deadline_unix_millis":200,"absent_owned_leaves":leaves,
        "tasks":[{"pid":200,"tid":201,"birth":300,"uids":[0,0,0,0],"gids":[0,0,0,0],"groups":[0]}]});
    let check = |value: serde_json::Value| {
        let recovered: LinuxRecoveredOwnership =
            serde_json::from_value(value).map_err(|error| error.to_string())?;
        validate_linux_recovered_ownership(
            &recovered,
            &bound,
            boundary_bytes,
            &original_bytes,
            checkpoint_bytes,
            &identity,
            "recovery",
            "x86_64-unknown-linux-gnu",
            (10000, 10000),
            100,
            200,
        )
    };
    check(recovered.clone()).unwrap();
    for (pointer, value) in [
        ("/absent_owned_leaves/0/native_errno", serde_json::json!(0)),
        (
            "/absent_owned_leaves/1/path",
            serde_json::json!(format!("{parent}/other.mixed-admission")),
        ),
        ("/absent_owned_leaves/2/parent_inode", serde_json::json!(21)),
        (
            "/absent_owned_leaves/0/original/inode",
            serde_json::json!(40),
        ),
        ("/tasks/0/uids", serde_json::json!([0, 0, 10000, 0])),
        ("/tasks/0/groups", serde_json::json!([0, 10000])),
        ("/tasks/0/birth", serde_json::json!(0)),
        ("/tasks/0/tid", serde_json::json!(u32::MAX)),
        ("/cleanup_deadline_unix_millis", serde_json::json!(201)),
        ("/ownership_sha256", serde_json::json!("ab".repeat(32))),
        ("/tasks", serde_json::json!([])),
    ] {
        let mut changed = recovered.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            check(changed).is_err(),
            "accepted recovered owner reassociation {pointer}"
        );
    }
    let mut changed = recovered.clone();
    let task = changed["tasks"][0].clone();
    changed["tasks"].as_array_mut().unwrap().push(task);
    assert!(check(changed).is_err());
}

#[test]
fn lost_terminal_delivery_requires_original_worker_paths_cutoffs_and_native_error() {
    use memcordon_readiness_verifier::{
        LinuxLostTerminalReceipt, LinuxRecoveryWorker, validate_linux_lost_terminal_delivery,
    };
    let challenge = [7u8; 32];
    let worker = LinuxRecoveryProcess {
        pid: 103,
        birth: 302,
    };
    let receipt = LinuxLostTerminalReceipt {
        format: "memcordon.linux-lost-terminal-component".into(),
        revision: 1,
        run_id: "run".into(),
        recipe_id: "lost-terminal".into(),
        native_target: "x86_64-unknown-linux-gnu".into(),
        test_name: "native_mixed_recovery::native_lost_terminal_response_emit_actual_receipt"
            .into(),
        worker: LinuxRecoveryWorker {
            pid: worker.pid,
            start_time: worker.birth,
        },
        challenge_sha256: Sha256::digest(challenge)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        carrier: "native/lost/completed-terminal-carrier.json".into(),
        request: "native/lost/terminal-request.json".into(),
        delivery_error: "Io(BrokenPipe)".into(),
        native_errno: 32,
        work_deadline_unix_millis: 100,
        cleanup_deadline_unix_millis: 200,
    };
    // Structural failed-write fixture; carrier/recovery acceptance is separate.
    let check = |receipt: &LinuxLostTerminalReceipt| {
        validate_linux_lost_terminal_delivery(
            receipt,
            "run",
            "lost-terminal",
            "x86_64-unknown-linux-gnu",
            &worker,
            &challenge,
            "native/lost",
            100,
            200,
        )
    };
    check(&receipt).unwrap();
    let mut changed = receipt.clone();
    changed.worker.start_time += 1;
    assert!(check(&changed).is_err());
    let mut changed = receipt.clone();
    changed.carrier = "other/completed-terminal-carrier.json".into();
    assert!(check(&changed).is_err());
    let mut changed = receipt.clone();
    changed.native_errno = 0;
    assert!(check(&changed).is_err());
    let mut changed = receipt.clone();
    changed.delivery_error = "Io(TimedOut)".into();
    assert!(check(&changed).is_err());
    let mut changed = receipt.clone();
    changed.cleanup_deadline_unix_millis += 1;
    assert!(check(&changed).is_err());
    let mut changed = receipt.clone();
    changed.challenge_sha256 = "ab".repeat(32);
    assert!(check(&changed).is_err());
    let mut changed = receipt.clone();
    changed.test_name =
        "native_mixed_recovery::native_account_retirement_boundary_emit_actual_receipt".into();
    assert!(check(&changed).is_err());
}

#[test]
fn native_crash_requires_exact_held_identity_boundary_and_raw_wait() {
    // Structural controller fixture; it does not claim a native execution.
    let bytes = b"original source-bound boundary";
    let worker = LinuxRecoveryProcess {
        pid: 101,
        birth: 300,
    };
    let caller = LinuxRecoveryProcess {
        pid: 102,
        birth: 301,
    };
    let image = "ab".repeat(32);
    let intent = LinuxCrashIntent {
        format: "memcordon.linux-native-crash-intent".into(),
        revision: 1,
        run_id: "run".into(),
        recipe_id: "account-retirement".into(),
        native_target: "x86_64-unknown-linux-gnu".into(),
        worker_pid: worker.pid,
        worker_birth: worker.birth,
        worker_image_sha256: image.clone(),
        boundary_sha256: Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        requested_signal: "SIGKILL".into(),
        held_before_boundary: true,
        caller: caller.clone(),
    };
    let exit = LinuxCrashExit {
        format: "memcordon.linux-native-crash-exit".into(),
        revision: 1,
        worker_pid: worker.pid,
        worker_birth: worker.birth,
        worker_image_sha256: image.clone(),
        raw_wait_status: 9,
        native_signal: Some(9),
        native_exit_code: None,
        worker_pidfd_retirement_observed: true,
        caller_pidfd_retirements: vec![caller.clone()],
    };
    let check = |intent: &LinuxCrashIntent, exit: &LinuxCrashExit| {
        validate_linux_crash_controller(
            intent,
            exit,
            bytes,
            "run",
            "account-retirement",
            "x86_64-unknown-linux-gnu",
            &image,
            &worker,
            &caller,
        )
    };
    check(&intent, &exit).unwrap();
    let mut changed = exit.clone();
    changed.raw_wait_status = 137;
    assert!(check(&intent, &changed).is_err());
    let mut changed = exit.clone();
    changed.native_signal = None;
    changed.native_exit_code = Some(137);
    assert!(check(&intent, &changed).is_err());
    let mut changed = exit.clone();
    changed.worker_birth += 1;
    assert!(check(&intent, &changed).is_err());
    let mut changed = exit.clone();
    changed.worker_pidfd_retirement_observed = false;
    assert!(check(&intent, &changed).is_err());
    let mut changed = exit.clone();
    changed.caller_pidfd_retirements.clear();
    assert!(check(&intent, &changed).is_err());
    let mut changed = exit.clone();
    changed.caller_pidfd_retirements.push(caller.clone());
    assert!(check(&intent, &changed).is_err());
    let mut changed = intent.clone();
    changed.boundary_sha256 = "cd".repeat(32);
    assert!(check(&changed, &exit).is_err());
    let mut changed = intent.clone();
    changed.caller.birth += 1;
    assert!(check(&changed, &exit).is_err());
    let mut changed = intent.clone();
    changed.held_before_boundary = false;
    assert!(check(&changed, &exit).is_err());
    let mut wire = serde_json::to_value(&exit).unwrap();
    wire["invented_account_retired"] = serde_json::json!(true);
    assert!(serde_json::from_value::<LinuxCrashExit>(wire).is_err());
}
