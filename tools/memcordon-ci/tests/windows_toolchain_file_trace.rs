#[path = "../src/windows_toolchain_file_trace_model.rs"]
mod model;

use memcordon_platform::windows_fileio_record::FieldId;
use model::{
    EventClass, FileEvent, Location, Operation, Process, StopDisposition, Target, Thread,
    attribute, pair,
};

const TARGET: Target = Target {
    pid: 21,
    birth_filetime: 100,
    parent_pid: 20,
    parent_birth_filetime: 80,
    native_status: 0xc000_0135,
};

fn process(pid: u32, parent: u32, key: u64, at: u64, start: bool, status: u32) -> Process {
    Process {
        pid,
        parent,
        key,
        at,
        start,
        status,
    }
}

fn thread(pid: u32, tid: u32, at: u64, start: bool) -> Thread {
    Thread {
        pid,
        tid,
        at,
        start,
    }
}

#[test]
fn process_generation_requires_matching_parent_birth_and_wait_status() {
    let mut processes = vec![
        process(21, 20, 1, 70, true, 0),
        process(21, 20, 1, 76, false, 0),
        process(20, 4, 3, 80, true, 0),
        process(21, 20, 4, 100, true, 0),
        process(21, 20, 4, 120, false, TARGET.native_status),
    ];
    let mut threads = [
        thread(21, 22, 72, true),
        thread(21, 22, 74, false),
        thread(21, 22, 103, true),
        thread(21, 22, 117, false),
        thread(30, 22, 119, true),
    ];
    let exact_clock = |at, birth| at == birth;
    let generation = attribute(TARGET, &processes, &mut threads, exact_clock).unwrap();
    assert!(generation.parent_start_observed);
    assert!(generation.contains(120));
    assert!(generation.issued(22, 110));
    assert!(!generation.issued(22, 73));
    assert!(!generation.issued(22, 118));
    assert!(!generation.issued(22, 119));

    let mismatched = Target {
        parent_birth_filetime: 79,
        ..TARGET
    };
    assert_eq!(
        attribute(mismatched, &processes, &mut threads, exact_clock).unwrap_err(),
        "parent-generation-mismatch"
    );
    let mismatched = Target {
        native_status: 0,
        ..TARGET
    };
    assert_eq!(
        attribute(mismatched, &processes, &mut threads, exact_clock).unwrap_err(),
        "ambiguous-compiler-process-lifetime"
    );
    processes.push(process(21, 20, 5, 100, true, 0));
    assert_eq!(
        attribute(TARGET, &processes, &mut threads, exact_clock).unwrap_err(),
        "ambiguous-compiler-process-start"
    );
}

#[test]
fn overlapping_thread_reuse_prevents_issuing_thread_attribution() {
    let processes = [
        process(20, 4, 1, 80, true, 0),
        process(21, 20, 2, 100, true, 0),
        process(21, 20, 2, 120, false, TARGET.native_status),
    ];
    let mut threads = [
        thread(21, 22, 102, true),
        thread(31, 22, 103, true),
        thread(21, 23, 104, true),
    ];
    let generation = attribute(TARGET, &processes, &mut threads, |at, birth| at == birth).unwrap();
    assert_eq!(generation.ambiguous_threads, 1);
    assert!(!generation.issued(22, 102));
    assert!(generation.issued(23, 106));
}

fn start(at: u64, irp: u64, path: Option<&str>) -> FileEvent {
    FileEvent {
        at,
        irp,
        operation: Operation::Create(path.and_then(Location::from_path)),
    }
}

fn end(at: u64, irp: u64, status: u32) -> FileEvent {
    FileEvent {
        at,
        irp,
        operation: Operation::End(status),
    }
}

#[test]
fn reordered_completion_and_sequential_irp_reuse_preserve_miss_then_hit() {
    let miss = 0xc000_0034;
    let records = pair(vec![
        end(20, 7, miss),
        end(40, 7, 0),
        start(
            30,
            7,
            Some(r"\Device\HarddiskVolume3\Windows\System32\Example.dll"),
        ),
        start(10, 7, Some(r"C:\Users\fixture\example.dll")),
    ]);
    assert_eq!(records.matched, 2);
    assert_eq!(records.unmatched, 0);
    assert_eq!(records.ambiguous, 0);
    assert_eq!(records.probes[0].ntstatus, Some(miss));
    assert_eq!(records.probes[1].ntstatus, Some(0));
    assert_eq!(records.probes[0].location.basename, "example.dll");
    assert_eq!(
        records.probes[1].location.directory_role,
        "windows-system32"
    );
    assert_ne!(
        records.probes[0].location.location_key,
        records.probes[1].location.location_key
    );
    let projection = serde_json::to_string(&records).unwrap();
    assert!(!projection.contains("Users"));
    assert!(!projection.contains("fixture"));
    assert!(!projection.contains("HarddiskVolume"));
}

#[test]
fn overlapping_unknown_issuer_and_missing_completion_are_explicit() {
    let path = Some(r"C:\Windows\System32\example.dll");
    let records = pair(vec![
        start(10, 7, path),
        start(15, 7, None),
        end(20, 7, 0),
        end(25, 7, 0),
        start(30, 7, path),
        end(30, 7, 0),
        start(32, 8, path),
    ]);
    assert_eq!(records.matched, 0);
    assert_eq!(records.ambiguous, 2);
    assert_eq!(records.unmatched, 1);
    assert!(records.probes.iter().all(|probe| probe.ntstatus.is_none()));
}

#[test]
fn location_keys_normalize_known_directory_roots_without_publishing_them() {
    let dos = Location::from_path(r"C:\Windows\System32\EXAMPLE.DLL").unwrap();
    let kernel =
        Location::from_path(r"\Device\HarddiskVolume9\Windows\System32\example.dll").unwrap();
    assert_eq!(dos, kernel);
    let ordinary =
        Location::from_path(r"C:\ordinary\locked-inputs\toolchain\bin\rustc_driver-abcd.dll")
            .unwrap();
    let restricted = Location::from_path(
        r"\Device\HarddiskVolume9\restricted\locked-inputs\toolchain\bin\rustc_driver-abcd.dll",
    )
    .unwrap();
    assert_eq!(ordinary, restricted);
    assert_eq!(ordinary.directory_role, "staged-compiler-bin");
    assert!(Location::from_path(r"C:\fixture\unrelated.rs").is_none());
}

#[test]
fn unsupported_versions_are_distinct_from_projection_truncation() {
    assert!(EventClass::Process.supports(4));
    assert!(EventClass::Thread.supports(3));
    assert!(EventClass::FileIo.supports(3));
    assert!(EventClass::Image.supports(2));
    assert!(!EventClass::Process.supports(5));
    assert!(!EventClass::Thread.supports(1));
    assert!(!EventClass::FileIo.supports(4));
    assert!(!EventClass::Image.supports(4));

    let path = Some(r"C:\Windows\System32\example.dll");
    let mut records = pair(vec![
        start(10, 1, path),
        end(20, 1, 0xc000_0034),
        start(30, 2, path),
        end(40, 2, 0),
    ]);
    assert!(records.truncate(1));
    assert_eq!(records.matched, 2);
    assert_eq!(records.probes.len(), 1);
    assert_eq!(records.probes[0].at_qpc, 10);
}

#[test]
fn an_already_absent_session_can_supply_partial_coverage() {
    assert!(StopDisposition::Controlled.can_open());
    assert!(StopDisposition::Controlled.allows_complete_coverage());
    assert!(StopDisposition::SessionAbsent.can_open());
    assert!(!StopDisposition::SessionAbsent.allows_complete_coverage());
    assert!(!StopDisposition::Failed.can_open());
    assert!(!StopDisposition::Failed.allows_complete_coverage());
}

#[test]
fn decode_diagnostics_identify_the_native_property_without_payloads() {
    assert_eq!(FieldId::ProcessId.name(), "ProcessId");
    assert_eq!(FieldId::ParentId.name(), "ParentId");
    assert_eq!(FieldId::IrpPtr.name(), "IrpPtr");
    assert_eq!(FieldId::Ttid.name(), "TTID");
    assert_eq!(FieldId::TThreadId.name(), "TThreadId");
    assert_eq!(FieldId::FileName.name(), "FileName");
}
