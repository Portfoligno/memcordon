use memcordon_core::{DiagnosticSha256, private_facility_source_v1::*, workload_codec::hash_bytes};

fn object(fd: i32, role: &str, inode: u64) -> FacilityObjectV1 {
    FacilityObjectV1 {
        role: role.into(),
        fd,
        device: 2,
        inode,
        fdinfo: b"flags:\t02000002\n".to_vec(),
    }
}
fn base(
    selector: &str,
    outer: Vec<FacilityCallV1>,
    private: Vec<FacilityCallV1>,
) -> FacilitySourceReportV1 {
    let calls = outer.into_iter().chain(private).collect();
    FacilitySourceReportV1 {
        schema_version: 1,
        source_revision_sha256: facility_source_revision_sha256(),
        selector: selector.into(),
        parent_result_key: DiagnosticSha256::from_bytes([1; 32]),
        helper: FacilityProcessV1 {
            pid: 90,
            start_time_ticks: 100,
        },
        source_process: None,
        private_filter_sha256: DiagnosticSha256::from_bytes([2; 32]),
        outer_filter_sha256: hash_bytes(&outer_allow_program_v1()),
        status_after_outer_install: b"NoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n".to_vec(),
        status_after_private_install: b"NoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t2\n"
            .to_vec(),
        calls,
        closes: vec![FacilityCloseV1 {
            object: object(5, "operation-result", 99),
            before_monotonic_ns: 100,
            after_monotonic_ns: 101,
            result: 0,
        }],
        source_wait_status: None,
        helper_wait_status: 0,
    }
}
fn call(
    op: FacilityOperationV1,
    nr: i64,
    args: [u64; 6],
    operand: FacilityOperandV1,
) -> FacilityCallV1 {
    FacilityCallV1 {
        operation: op,
        phase: FacilityPhaseV1::Outer,
        audit_arch: 0xc000003e,
        syscall_nr: nr,
        args,
        before_monotonic_ns: 10,
        after_monotonic_ns: 20,
        result: 0,
        errno: 0,
        namespace_before: 50,
        namespace_after: 50,
        operand,
    }
}
fn private(outer: &FacilityCallV1) -> FacilityCallV1 {
    let mut call = outer.clone();
    call.phase = FacilityPhaseV1::Private;
    call.before_monotonic_ns = 30;
    call.after_monotonic_ns = 40;
    call.result = -1;
    call.errno = if call.operation == FacilityOperationV1::Socket {
        97
    } else {
        1
    };
    call
}
#[test]
fn real_outer_socket_and_separate_private_denial_are_not_interchangeable() {
    let mut outer = call(
        FacilityOperationV1::Socket,
        41,
        [1, 0x80001, 0, 0, 0, 0],
        FacilityOperandV1::Scalars,
    );
    outer.result = 5;
    let report = base(
        "private_tcp::af_unix_abstract_and_pathname_denied",
        vec![outer.clone()],
        vec![private(&outer)],
    );
    validate_facility_source_shape(&report).unwrap();
    for mutation in 0..5 {
        let mut changed = report.clone();
        match mutation {
            0 => changed.calls[0].result = -1,
            1 => changed.calls[0].errno = 1,
            2 => changed.calls[1].args[0] = 2,
            3 => changed.closes.clear(),
            _ => changed.helper_wait_status = 9,
        };
        assert!(validate_facility_source_shape(&changed).is_err());
    }
}
#[test]
fn valid_ring_storage_and_real_pidfd_source_are_mandatory() {
    let ring = call(
        FacilityOperationV1::IoUringSetup,
        425,
        [1, 0x1000, 0, 0, 0, 0],
        FacilityOperandV1::IoUring {
            parameter_address: 0x1000,
            parameters_before: [0; 15],
            parameters_after: [0; 15],
        },
    );
    let source = FacilityProcessV1 {
        pid: 91,
        start_time_ticks: 101,
    };
    let mut import = call(
        FacilityOperationV1::PidfdGetfd,
        438,
        [6, 7, 0, 0, 0, 0],
        FacilityOperandV1::Descriptor {
            object: object(6, "pidfd", 60),
            source: Some(object(7, "source", 70)),
            source_process: Some(source.clone()),
        },
    );
    import.result = 8;
    let mut report = base(
        "private_tcp::io_uring_and_pidfd_import_denied",
        vec![ring.clone(), import.clone()],
        vec![private(&ring), private(&import)],
    );
    report.source_process = Some(source);
    report.source_wait_status = Some(0);
    validate_facility_source_shape(&report).unwrap();
    let mut changed = report.clone();
    changed.source_wait_status = None;
    assert!(validate_facility_source_shape(&changed).is_err());
    let mut changed = report.clone();
    if let FacilityOperandV1::IoUring {
        parameters_before, ..
    } = &mut changed.calls[0].operand
    {
        parameters_before[0] = 1;
    }
    assert!(validate_facility_source_shape(&changed).is_err());
    let mut changed = report.clone();
    if let FacilityOperandV1::Descriptor {
        source: Some(object),
        ..
    } = &mut changed.calls[3].operand
    {
        object.inode = 71;
    }
    assert!(validate_facility_source_shape(&changed).is_err());
}
#[test]
fn namespace_control_is_owned_and_private_namespace_does_not_change() {
    let setns = call(
        FacilityOperationV1::Setns,
        308,
        [6, 0x40000000, 0, 0, 0, 0],
        FacilityOperandV1::Descriptor {
            object: object(6, "namespace", 50),
            source: None,
            source_process: None,
        },
    );
    let mut unshare = call(
        FacilityOperationV1::Unshare,
        272,
        [0x40000000, 0, 0, 0, 0, 0],
        FacilityOperandV1::Scalars,
    );
    unshare.namespace_after = 51;
    let mut denied_setns = private(&setns);
    denied_setns.namespace_before = 51;
    denied_setns.namespace_after = 51;
    let mut denied_unshare = private(&unshare);
    denied_unshare.namespace_before = 51;
    denied_unshare.namespace_after = 51;
    let report = base(
        "private_tcp::namespace_reentry_denied",
        vec![setns, unshare],
        vec![denied_setns, denied_unshare],
    );
    validate_facility_source_shape(&report).unwrap();
    let mut changed = report.clone();
    changed.calls[3].namespace_after = 52;
    assert!(validate_facility_source_shape(&changed).is_err());
    let mut changed = report.clone();
    changed.calls[1].namespace_after = 50;
    assert!(validate_facility_source_shape(&changed).is_err());
}
#[test]
fn scm_source_is_the_actual_successfully_transferred_object() {
    let mut control = Vec::new();
    control.extend_from_slice(&20u64.to_le_bytes());
    control.extend_from_slice(&1u32.to_le_bytes());
    control.extend_from_slice(&1u32.to_le_bytes());
    control.extend_from_slice(&7i32.to_le_bytes());
    control.extend_from_slice(&[0; 4]);
    let operand = FacilityOperandV1::ScmRights {
        socket: object(6, "scm-send", 60),
        source: object(7, "source", 70),
        message_address: 0x1000,
        iov_address: 0x2000,
        payload_address: 0x3000,
        control_address: 0x4000,
        payload: vec![0x51],
        control_bytes: control,
        transferred_device: Some(2),
        transferred_inode: Some(70),
    };
    let mut outer = call(
        FacilityOperationV1::Sendmsg,
        46,
        [6, 0x1000, 0x4000, 0, 0, 0],
        operand,
    );
    outer.result = 1;
    let mut denied = private(&outer);
    if let FacilityOperandV1::ScmRights {
        transferred_device,
        transferred_inode,
        ..
    } = &mut denied.operand
    {
        *transferred_device = None;
        *transferred_inode = None;
    }
    let report = base(
        "private_tcp::scm_rights_and_precreated_socket_denied",
        vec![outer],
        vec![denied],
    );
    validate_facility_source_shape(&report).unwrap();
    let mut changed = report.clone();
    if let FacilityOperandV1::ScmRights {
        transferred_inode, ..
    } = &mut changed.calls[0].operand
    {
        *transferred_inode = Some(71);
    }
    assert!(validate_facility_source_shape(&changed).is_err());
    let mut changed = report.clone();
    if let FacilityOperandV1::ScmRights { control_bytes, .. } = &mut changed.calls[1].operand {
        control_bytes[16] = 8;
    }
    assert!(validate_facility_source_shape(&changed).is_err());
}
