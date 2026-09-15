//! Fixture memory handlers; invoked only through the command registry.
use super::*;

pub(super) fn touch_allocation(bytes: u64) -> Vec<u8> {
    let length = usize::try_from(bytes).unwrap_or_else(|_| fail("allocation does not fit usize"));
    let mut memory = vec![0_u8; length];
    for byte in memory.iter_mut().step_by(4096) {
        *byte = 1;
    }
    memory
}

pub(super) fn allocate(mut args: impl Iterator<Item = OsString>, release_before_hold: bool) {
    let mut bytes = None;
    let mut duration = None;
    let mut pid_file = None;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--bytes") => {
                let value = take_value(&mut args, "--bytes");
                bytes = Some(
                    value
                        .to_str()
                        .and_then(|text| ByteSize::from_str(text).ok())
                        .unwrap_or_else(|| fail("invalid byte size"))
                        .bytes(),
                );
            }
            Some("--hold") => duration = Some(parse_duration(&take_value(&mut args, "--hold"))),
            Some("--pid-file") => {
                pid_file = Some(PathBuf::from(take_value(&mut args, "--pid-file")))
            }
            _ => fail("unexpected allocation argument"),
        }
    }
    write_pid(pid_file.as_deref());
    let memory = touch_allocation(bytes.unwrap_or_else(|| fail("allocation requires --bytes")));
    if release_before_hold {
        drop(memory);
        thread::yield_now();
        thread::sleep(duration.unwrap_or(Duration::from_secs(30)));
    } else {
        thread::sleep(duration.unwrap_or(Duration::from_secs(30)));
        drop(memory);
    }
}

pub(super) fn command_allocate(args: std::env::ArgsOs) -> i32 {
    {
        allocate(args, false);
        0
    }
}

pub(super) fn command_burst(args: std::env::ArgsOs) -> i32 {
    {
        allocate(args, true);
        0
    }
}
