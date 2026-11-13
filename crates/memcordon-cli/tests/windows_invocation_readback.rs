#![cfg(all(windows, feature = "test-fixtures"))]

use memcordon_core::WindowsEnvironmentEntryV1;
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    process::{Child, Command},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn read_bounded(path: &std::path::Path, maximum: usize) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    if file.metadata()?.len() > maximum as u64 {
        return Err(io::Error::other(
            "native fixture observation exceeds its bound",
        ));
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(io::Error::other(
            "native fixture observation grew beyond its bound",
        ));
    }
    Ok(bytes)
}

fn native_environment() -> io::Result<Vec<WindowsEnvironmentEntryV1>> {
    use windows_sys::Win32::System::Environment::{
        FreeEnvironmentStringsW, GetEnvironmentStringsW,
    };
    // The native API owns a double-NUL-terminated allocation until its matching
    // free. Read only that allocation, with the existing core block bound.
    let raw = unsafe { GetEnvironmentStringsW() };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    let captured = (|| {
        let mut block = Vec::new();
        for index in 0..32768 {
            let unit = unsafe { *raw.add(index) };
            if unit == 0 && block.last() == Some(&0) {
                let mut entries = Vec::new();
                for entry in block
                    .split(|unit| *unit == 0)
                    .filter(|entry| !entry.is_empty())
                {
                    let skip = usize::from(entry.first() == Some(&u16::from(b'=')));
                    let split = entry
                        .iter()
                        .enumerate()
                        .skip(skip)
                        .find(|(_, unit)| **unit == u16::from(b'='))
                        .map(|(index, _)| index)
                        .ok_or_else(|| io::Error::other("native environment entry malformed"))?;
                    entries.push(WindowsEnvironmentEntryV1 {
                        name: entry[..split].to_vec(),
                        value: entry[split + 1..].to_vec(),
                    });
                }
                return Ok(entries);
            }
            block.push(unit);
        }
        Err(io::Error::other(
            "native environment exceeds the core block bound",
        ))
    })();
    let freed = if unsafe { FreeEnvironmentStringsW(raw) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    };
    match (captured, freed) {
        (Err(primary), _) => Err(primary),
        (Ok(_), Err(error)) => Err(error),
        (Ok(entries), Ok(())) => Ok(entries),
    }
}

fn child_identity(child: &Child) -> io::Result<(u32, u64)> {
    use windows_sys::Win32::{Foundation::FILETIME, System::Threading::GetProcessTimes};
    let mut created = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exited = created;
    let mut kernel = created;
    let mut user = created;
    if unsafe {
        GetProcessTimes(
            child.as_raw_handle(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok((
        child.id(),
        (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime),
    ))
}

#[test]
fn actual_envelope_fixture_records_native_environment_and_held_cwd_without_exporting_values() {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    };
    let cutoff = Instant::now() + Duration::from_secs(20);
    let (work_cutoff_qpc, qpc_frequency) =
        memcordon_testkit::windows_native_work_cutoff(cutoff).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let cwd = directory.path().to_owned();
    let cwd_owner = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(7)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&cwd)
        .unwrap();
    let cwd_identity = memcordon_testkit::windows_held_file_metadata(&cwd_owner).unwrap();
    let environment = native_environment().expect("native parent environment must be queryable");
    let environment_entries = environment.len();
    let block = memcordon_core::encode_windows_environment_block(&environment)
        .expect("native parent environment must fit the existing core grammar");
    let environment_bytes = block
        .iter()
        .flat_map(|unit| unit.to_le_bytes())
        .collect::<Vec<_>>();
    let environment_sha256 = hash(&environment_bytes);
    let output_root = cwd.join("observed");
    std::fs::create_dir(&output_root).unwrap();
    let transcript = output_root.join("fixture-events.bin");
    let challenge = vec![0u8, 255, 128, 1];
    // External wire consumer: this is the existing revision-2 Envelope schema,
    // with no new switch, environment variable, or production module mount.
    let descriptor = serde_json::to_vec(&serde_json::json!({
        "format":"memcordon.fixture-workload","revision":2,"case":"envelope",
        "output_root":output_root,"transcript":transcript,"challenge":challenge,
        "stdout_base64":"","stderr_base64":"","arguments":[],"application_status":0,
        "churn_creations":4096,"churn_live":63,"denied_write_paths":[],"sentinel_handles":[],
        "descendant_gate":null,"start_gate":null,"completion_gate":null,"cohort_gate":null,
        "generation_gate":null,"toolchain":null,
        "control_clock":{"revision":1,"work_cutoff_qpc":work_cutoff_qpc,"qpc_frequency":qpc_frequency}
    })).unwrap();
    let descriptor_path = cwd.join("input.json");
    std::fs::write(&descriptor_path, &descriptor).unwrap();
    let identity = Arc::new(Mutex::new(None));
    let original_identity = Arc::clone(&identity);
    let admitted_identity = Arc::clone(&identity);
    let fixture = option_env!("CARGO_BIN_EXE_memcordon-test-fixture")
        .expect("native invocation test requires the actual built fixture binary");
    let mut command = Command::new(fixture);
    command
        .arg("consumer-readiness-windows")
        .arg(&descriptor_path)
        .current_dir(&cwd);
    let observed = memcordon_testkit::run_until_owned_spawn_after_output_limit(
        command,
        cutoff,
        64 * 1024,
        move |mut command| {
            let child = command.spawn()?;
            // Always return the same Child to the existing sole wait owner.
            // A query failure is reported only after its Job was admitted.
            *original_identity
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = Some(child_identity(&child));
            Ok(child)
        },
        move |pid| {
            let identity = admitted_identity
                .lock()
                .map_err(|_| io::Error::other("native child identity lock poisoned"))?;
            match identity
                .as_ref()
                .ok_or_else(|| io::Error::other("native child identity absent"))?
            {
                Ok((original, _)) if *original == pid => Ok(()),
                Ok(_) => Err(io::Error::other(
                    "native child identity differs from original owner",
                )),
                Err(error) => Err(match error.raw_os_error() {
                    Some(code) => io::Error::from_raw_os_error(code),
                    None => {
                        io::Error::new(error.kind(), "native original child identity query failed")
                    }
                }),
            }
        },
    )
    .expect("original native Envelope owner must settle within its cutoff");
    assert!(
        observed.status.success(),
        "original Envelope fixture failed"
    );
    assert!(
        observed.stdout.is_empty() && observed.stderr.is_empty(),
        "Envelope emitted unexpected stream bytes"
    );
    let identity = identity.lock().unwrap();
    let (pid, birth) = *identity
        .as_ref()
        .expect("original Child identity retained")
        .as_ref()
        .expect("native Child identity available");
    let bytes = read_bounded(&output_root.join("invocation-readback.json"), 256 * 1024).unwrap();
    assert!(bytes.len() <= 256 * 1024);
    let record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(record["format"], "memcordon.windows-invocation-readback");
    assert_eq!(record["revision"], 1);
    assert_eq!(record["pid"], pid);
    assert_eq!(record["birth"], birth);
    assert_eq!(
        record["descriptor_sha256"],
        serde_json::json!(hash(&descriptor))
    );
    assert_eq!(
        record["challenge_sha256"],
        serde_json::json!(hash(&challenge))
    );
    assert_eq!(
        record["environment_sha256"],
        serde_json::json!(environment_sha256)
    );
    assert_eq!(record["environment_bytes"], environment_bytes.len());
    assert_eq!(record["environment_entries"], environment_entries);
    assert_eq!(
        record["cwd_identity"]["volume_serial"],
        cwd_identity.volume_serial
    );
    assert_eq!(
        record["cwd_identity"]["file_index"],
        cwd_identity.file_index
    );
    assert_eq!(
        record["cwd_identity"]["attributes"].as_u64().unwrap() & 0x410,
        0x10
    );
    let spelling: Vec<u16> = serde_json::from_value(record["cwd_utf16"].clone()).unwrap();
    assert!(!spelling.is_empty() && !spelling.contains(&0));
    assert_eq!(record["qpc_frequency"], qpc_frequency);
    assert_eq!(record["cutoff_qpc"], work_cutoff_qpc);
    let started = record["started_qpc"].as_u64().unwrap();
    let finished = record["finished_qpc"].as_u64().unwrap();
    assert!(started > 0 && finished >= started && finished < work_cutoff_qpc);
    let transcript = read_bounded(&transcript, 16 * 1024 * 1024).unwrap();
    let mut remaining = transcript.as_slice();
    let mut tokens = Vec::new();
    while !remaining.is_empty() {
        let length = u32::from_le_bytes(remaining[..4].try_into().unwrap()) as usize;
        remaining = &remaining[4..];
        let event: serde_json::Value = serde_json::from_slice(&remaining[..length]).unwrap();
        remaining = &remaining[length..];
        if event["stage"] == "token-envelope" {
            assert_eq!(event["pid"], pid);
            tokens.push(serde_json::from_value::<Vec<u8>>(event["value"].clone()).unwrap());
        }
    }
    assert_eq!(tokens.len(), 1);
    assert_eq!(record["token_sha256"], serde_json::json!(hash(&tokens[0])));
    for forbidden in [
        "environment",
        "environment_values",
        "raw_environment",
        "token",
        "handles",
    ] {
        assert!(
            record.get(forbidden).is_none(),
            "readback contains an unexpected raw field"
        );
    }
}
