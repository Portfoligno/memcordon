#[no_mangle]
pub extern "C" fn memcordon_readiness_byte(index: u32) -> u32 {
    if index <= 255 { index } else { u32::MAX }
}
