//! Decode only the original-entry normal-import thunks recognized by Detours.
//! Decoding does not establish IAT membership, import binding, or object identity.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DecodeError {
    Machine = 1,
    Truncated = 2,
    Opcode = 3,
    Overflow = 4,
    Unaligned = 5,
}

pub fn decode(machine: u32, pc: u64, bytes: &[u8]) -> Result<u64, DecodeError> {
    match machine {
        0x8664 => {
            let instruction = bytes.get(..6).ok_or(DecodeError::Truncated)?;
            if instruction[..2] != [0xff, 0x25] {
                return Err(DecodeError::Opcode);
            }
            let displacement =
                i32::from_le_bytes(instruction[2..6].try_into().expect("instruction extent"));
            pc.checked_add(6)
                .and_then(|next| next.checked_add_signed(i64::from(displacement)))
                .ok_or(DecodeError::Overflow)
        }
        0xaa64 => {
            if pc % 4 != 0 {
                return Err(DecodeError::Unaligned);
            }
            let instruction = bytes.get(..12).ok_or(DecodeError::Truncated)?;
            pc.checked_add(12).ok_or(DecodeError::Overflow)?;
            let word = |index: usize| {
                u32::from_le_bytes(
                    instruction[index..index + 4]
                        .try_into()
                        .expect("instruction extent"),
                )
            };
            let page = word(0);
            let load = word(4);
            if page & 0x9f00_001f != 0x9000_0010
                || load & 0xffe0_03ff != 0xf940_0210
                || word(8) != 0xd61f_0200
            {
                return Err(DecodeError::Opcode);
            }
            let immediate = ((page >> 5) & 0x7ffff) << 2 | ((page >> 29) & 3);
            let signed = (i64::from(immediate) << (64 - 21)) >> (64 - 21);
            let offset = u64::from((load >> 10) & 0xfff) * 8;
            (pc & !0xfff)
                .checked_add_signed(signed * 4096)
                .and_then(|base| base.checked_add(offset))
                .ok_or(DecodeError::Overflow)
        }
        _ => Err(DecodeError::Machine),
    }
}
