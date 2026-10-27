//! Native event ownership tests. Actual installed target/Job proof remains native CI.
#[path = "../../src/windows_component_barriers.rs"]
mod barriers;
#[allow(unsafe_code)] // Private test-owned tokens; all original thread context is restored.
#[path = "windows_gate_access.rs"]
mod gate_access_tests;

use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows_sys::Win32::System::Threading::{OpenEventW, WaitForSingleObject};

#[allow(unsafe_code)] // Opens only this test's nonce-bound event for synchronization.
fn open(name: &str) -> std::io::Result<OwnedHandle> {
    let name: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
    // SAFETY: exact terminated name; no modification rights or inherited handle.
    let raw = unsafe { OpenEventW(0x0010_0000, 0, name.as_ptr()) };
    if raw.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: successful OpenEvent transfers one independent owned reference.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw.cast()) })
}

fn name() -> String {
    format!(
        "Local\\MemcordonComponentBarrierTest{}",
        crate::windows_causal_acceptance::sha256(&super::native::random_challenge().unwrap())
    )
}

#[test]
#[allow(unsafe_code)] // Queries only the original event handles with finite waits.
fn native_observer_stays_nonsignaled_after_initial_release_and_callback_exit() {
    const TEST_WAIT: std::time::Duration = std::time::Duration::from_secs(30);
    let name = name();
    let observer_name = format!("{name}-toolchain-observer");
    let owner = barriers::ComponentBarriers::create(Some(&name), true, |name| {
        super::native::event_create(name).map_err(std::io::Error::other)
    })
    .unwrap();
    let callback = owner.callback_start().unwrap();
    assert!(super::native::event_create(&name).is_err());
    assert!(super::native::event_create(&observer_name).is_err());
    let (ready, entered) = std::sync::mpsc::sync_channel(1);
    let observed_name = observer_name.clone();
    let waiter = std::thread::spawn(move || {
        let start = open(&name).unwrap();
        let observer = open(&observed_name).unwrap();
        ready.send(()).unwrap();
        // SAFETY: same nonce-bound original event references, retained across both waits.
        assert_eq!(
            unsafe {
                WaitForSingleObject(
                    start.as_raw_handle(),
                    u32::try_from(TEST_WAIT.as_millis()).unwrap(),
                )
            },
            0
        );
        assert_eq!(
            unsafe { WaitForSingleObject(observer.as_raw_handle(), 25) },
            258
        );
    });
    entered.recv_timeout(TEST_WAIT).unwrap();
    super::native::signal(&callback).unwrap();
    drop(callback);
    waiter.join().unwrap();
    let observer = open(&observer_name).unwrap();
    // SAFETY: the callback has exited; the outer owner still holds the nonsignaled event.
    assert_eq!(
        unsafe { WaitForSingleObject(observer.as_raw_handle(), 0) },
        258
    );
    drop(observer);
    let cutoff = std::time::Instant::now();
    let mut stages = Vec::new();
    let settlement = barriers::settle(
        cutoff,
        |operation: String, diagnostic| format!("{operation}; {diagnostic}"),
        |stage, original, errors| {
            assert_eq!(original, cutoff);
            stages.push(stage);
            assert!(owner.callback_start().is_some());
            let retained = open(&observer_name).unwrap();
            // SAFETY: each actual production sequencing phase still owns the same native barrier.
            assert_eq!(
                unsafe { WaitForSingleObject(retained.as_raw_handle(), 0) },
                258
            );
            errors.diagnostic(Err::<(), _>("injected-retention-failure".to_owned()));
            Ok(())
        },
    );
    assert!(settlement.is_err());
    assert_eq!(stages.len(), 4);
    drop(owner);
    assert_eq!(open(&observer_name).err().unwrap().raw_os_error(), Some(2));
}

#[test]
fn reused_observer_refuses_and_retires_only_newly_owned_start() {
    let name = name();
    let observer_name = format!("{name}-toolchain-observer");
    let original = super::native::event_create(&observer_name).unwrap();
    let result = barriers::ComponentBarriers::create(Some(&name), true, |name| {
        super::native::event_create(name).map_err(std::io::Error::other)
    });
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("reused an existing resource")
    );
    assert_eq!(open(&name).err().unwrap().raw_os_error(), Some(2));
    assert!(open(&observer_name).is_ok());
    drop(original);
    assert_eq!(open(&observer_name).err().unwrap().raw_os_error(), Some(2));
}
