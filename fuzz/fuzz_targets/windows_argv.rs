#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|arguments: Vec<Vec<u16>>| {
    if arguments.iter().any(|argument| argument.contains(&0)) {
        return;
    }
    let encoded = memcordon_core::encode_windows_command_line(&arguments);
    assert!(!encoded.contains(&0));
    assert_eq!(
        memcordon_core::decode_windows_command_line(&encoded),
        Ok(arguments)
    );
});
