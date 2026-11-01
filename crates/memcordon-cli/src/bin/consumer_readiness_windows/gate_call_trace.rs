//! Instrument only the existing independently owned pre-handoff control call.
use super::gate_call_trace_record::{self, NativeTrace};
use std::ffi::c_void;
use std::io;

/// The native bridge supplies only its guarded, fixed entry-byte copy.
///
/// # Safety
/// `bytes` must expose `length` readable bytes and `slot` must point to a live,
/// aligned writable scalar. Both are owned by the private native bridge call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcordon_decode_import_entry(
    machine: u32,
    pc: u64,
    bytes: *const u8,
    length: usize,
    slot: *mut u64,
) -> u32 {
    if bytes.is_null() || slot.is_null() || length > 16 {
        return 2;
    }
    // SAFETY: private bridge ABI supplies a live fixed array and writable scalar.
    let bytes = unsafe { std::slice::from_raw_parts(bytes, length) };
    match super::gate_entry_route::decode(machine, pc, bytes) {
        Ok(value) => {
            // SAFETY: caller owns the checked writable output scalar.
            unsafe { slot.write(value) };
            0
        }
        Err(error) => error as u32,
    }
}

unsafe extern "C" {
    fn memcordon_gate_trace_prepare(packet: *mut NativeTrace, cutoff: u64, frequency: u64);
    fn memcordon_gate_trace_call(
        packet: *mut NativeTrace,
        name: *const u16,
        error: *mut u32,
        called: *mut u32,
    ) -> *mut c_void;
    fn memcordon_gate_trace_mock() -> u32;
    fn memcordon_gate_trace_directories(
        packet: *const NativeTrace,
        handles: *mut u64,
        errors: *mut u32,
    );
    fn memcordon_gate_trace_release_directories(packet: *const NativeTrace);
}

pub struct Prepared {
    packet: NativeTrace,
    reference_owner: usize,
    _thread_bound: std::marker::PhantomData<std::rc::Rc<()>>,
}
pub struct Call {
    pub handle: *mut c_void,
    pub native_error: u32,
}

impl Prepared {
    pub fn new(cutoff: u64, frequency: u64) -> Self {
        let mut packet = NativeTrace::default();
        // SAFETY: C and Rust assert the identical fixed 64-bit packet layout.
        // This sets up child-local pass-through hooks, never a target hook.
        unsafe { memcordon_gate_trace_prepare(&mut packet, cutoff, frequency) };
        Self {
            packet,
            reference_owner: 0,
            _thread_bound: std::marker::PhantomData,
        }
    }

    pub fn call(&mut self, name: &[u16]) -> io::Result<Call> {
        if name.len() < 2
            || name.len() > 32768
            || name.last() != Some(&0)
            || name[..name.len() - 1].contains(&0)
            || self.packet.called != 0
        {
            return Err(io::Error::other(
                "original control call arguments or single-call state differ",
            ));
        }
        let mut error = 0;
        let mut called = 0;
        self.reference_owner = std::ptr::addr_of!(self.packet) as usize;
        // SAFETY: exact validated NUL-terminated original name and writable
        // outputs. The bridge calls OpenEventW(SYNCHRONIZE,FALSE,name) once and
        // saves its result/error before disarming or any diagnostic operation.
        let handle = unsafe {
            memcordon_gate_trace_call(&mut self.packet, name.as_ptr(), &mut error, &mut called)
        };
        if called != 1 {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        Ok(Call {
            handle,
            native_error: error,
        })
    }

    pub fn diagnostic(&self) -> serde_json::Value {
        gate_call_trace_record::diagnostic(&self.packet)
    }

    pub fn directory_references(&self) -> serde_json::Value {
        let mut handles = [0_u64; 8];
        let mut errors = [0_u32; 8];
        // SAFETY: fixed writable eight-element arrays match the private ABI.
        unsafe {
            memcordon_gate_trace_directories(
                self.reference_owner as *const NativeTrace,
                handles.as_mut_ptr(),
                errors.as_mut_ptr(),
            )
        };
        serde_json::json!({"handles":handles,"errors":errors,
            "raw_handles_are_authority":false,"diagnostic_only":true})
    }
}

impl Drop for Prepared {
    fn drop(&mut self) {
        // SAFETY: same caller thread owns all retained diagnostic references.
        unsafe {
            memcordon_gate_trace_release_directories(self.reference_owner as *const NativeTrace)
        };
    }
}

pub(super) fn mock_forwarding() -> bool {
    // SAFETY: this bridge check uses only synthetic arguments/trampolines and
    // native last-error preservation, without opening any native object.
    unsafe { memcordon_gate_trace_mock() == 1 }
}
