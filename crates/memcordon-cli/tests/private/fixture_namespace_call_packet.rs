use std::io;

pub const CODE: u32 = 0xE04D4352;
pub const VERSION: u64 = 1;
pub const PHASE_PRE: u64 = 1;
pub const PHASE_POST: u64 = 2;
pub const PARAMETERS: usize = 7;
const _: () = assert!(CODE & (1 << 28) == 0);

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid replay call marker")
}

fn nonce(value: &str) -> io::Result<[u64; 2]> {
    let mut bytes = [0u8; 16];
    if value.len() != bytes.len() * 2 {
        return Err(invalid());
    }
    for (output, pair) in bytes.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let digit = |value| match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            _ => Err(invalid()),
        };
        *output = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    let (first, second) = bytes.split_at(size_of::<u64>());
    Ok([
        u64::from_le_bytes(first.try_into().map_err(|_| invalid())?),
        u64::from_le_bytes(second.try_into().map_err(|_| invalid())?),
    ])
}

pub struct Packet;
impl Packet {
    pub fn pre(replay_nonce: &str, api: u64) -> io::Result<[u64; PARAMETERS]> {
        Self::make(replay_nonce, api, PHASE_PRE, false, 0)
    }
    pub fn post(
        replay_nonce: &str,
        api: u64,
        opened: bool,
        error: u32,
    ) -> io::Result<[u64; PARAMETERS]> {
        Self::make(replay_nonce, api, PHASE_POST, opened, error)
    }
    fn make(
        replay_nonce: &str,
        api: u64,
        phase: u64,
        opened: bool,
        error: u32,
    ) -> io::Result<[u64; PARAMETERS]> {
        if api == 0 || (opened && error != 0) {
            return Err(invalid());
        }
        let nonce = nonce(replay_nonce)?;
        Ok([
            VERSION,
            phase,
            nonce[0],
            nonce[1],
            api,
            u64::from(opened),
            u64::from(error),
        ])
    }
}
