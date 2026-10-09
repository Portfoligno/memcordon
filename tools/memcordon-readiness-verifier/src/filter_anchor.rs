//! Independent fixed GNU ABI catalogue and scalar rules. No operational
//! compiler or host libc constants participate in this expectation.
use crate::{Instruction, VerificationResult};
const ALLOW: u32 = 0x7fff0000;
const DENY: u32 = 0x50001;
fn w(code: u16, jt: u8, jf: u8, k: u32) -> Instruction {
    Instruction { code, jt, jf, k }
}
fn load(offset: u32) -> Instruction {
    w(0x20, 0, 0, offset)
}
fn equal(value: u32, jt: u8, jf: u8) -> Instruction {
    w(0x15, jt, jf, value)
}
fn ret(value: u32) -> Instruction {
    w(6, 0, 0, value)
}
fn commands(offset: u32, values: &[u32]) -> Vec<Instruction> {
    let mut result = vec![load(offset + 4), equal(0, 1, 0), ret(DENY), load(offset)];
    for value in values {
        result.extend([equal(*value, 0, 1), ret(ALLOW)]);
    }
    result.push(ret(DENY));
    result
}
fn flags(offset: u32, mask: u32) -> Vec<Instruction> {
    vec![
        load(offset + 4),
        equal(0, 1, 0),
        ret(DENY),
        load(offset),
        w(0x45, 0, 1, !mask),
        ret(DENY),
        ret(ALLOW),
    ]
}
fn dispatch(program: &mut Vec<Instruction>, number: u32, body: Vec<Instruction>) {
    program.extend([equal(number, 1, 0), w(5, 0, 0, body.len() as u32)]);
    program.extend(body);
    program.push(load(0));
}
fn socket(unix: bool) -> Vec<Instruction> {
    let family = 0x50061;
    let protocol = 0x5005d;
    let mut result = vec![
        load(20),
        equal(0, 1, 0),
        ret(family),
        load(16),
        equal(if unix { 1 } else { 2 }, 1, 0),
        ret(family),
        load(28),
        equal(0, 1, 0),
        ret(protocol),
        load(24),
        w(0x45, 0, 1, !(1 | 0x800 | 0x80000)),
        ret(protocol),
        w(0x54, 0, 0, 15),
        equal(1, 1, 0),
        ret(protocol),
        load(36),
        equal(0, 1, 0),
        ret(protocol),
        load(32),
    ];
    if unix {
        result.push(equal(0, 1, 0));
    } else {
        result.extend([equal(0, 2, 0), equal(6, 1, 0)]);
    }
    result.extend([ret(protocol), ret(ALLOW)]);
    result
}
fn clone_rule() -> Vec<Instruction> {
    // VM, FS, FILES, SIGHAND, VFORK, THREAD, SYSVSEM, SETTLS,
    // PARENT_SETTID, CHILD_CLEARTID, CHILD_SETTID; exit signal zero/SIGCHLD.
    let allowed = 0x100
        | 0x200
        | 0x400
        | 0x800
        | 0x4000
        | 0x10000
        | 0x40000
        | 0x80000
        | 0x100000
        | 0x200000
        | 0x1000000;
    vec![
        load(20),
        equal(0, 1, 0),
        ret(DENY),
        load(16),
        w(0x45, 0, 1, !(allowed | 255)),
        ret(DENY),
        load(16),
        w(0x54, 0, 0, 255),
        equal(0, 2, 0),
        equal(17, 1, 0),
        ret(DENY),
        load(16),
        w(0x45, 0, 8, 0x10000),
        load(16),
        w(0x54, 0, 0, 0x900),
        equal(0x900, 1, 0),
        ret(DENY),
        load(16),
        w(0x54, 0, 0, 255),
        equal(0, 1, 0),
        ret(DENY),
        ret(ALLOW),
    ]
}
fn fcntl() -> Vec<Instruction> {
    let mut result = commands(24, &[1, 3, 1034, 0, 1030, 5, 6, 7, 36, 37, 38]);
    result.pop();
    // GNU x64 and ARM64 O_LARGEFILE is zero, unlike the raw kernel UAPI.
    for (command, mask) in [(2, 1), (4, 3 | 1024 | 2048)] {
        let body = flags(32, mask);
        result.extend([equal(command, 1, 0), w(5, 0, 0, body.len() as u32)]);
        result.extend(body);
        result.push(load(24));
    }
    result.push(ret(DENY));
    result
}
fn options(read: bool) -> Vec<Instruction> {
    let mut sol = vec![2, 9, 8, 7, 20, 21, 13];
    if read {
        sol.extend([4, 3, 39, 38, 30]);
    }
    let mut result = vec![
        load(28),
        equal(0, 1, 0),
        ret(DENY),
        load(36),
        equal(0, 1, 0),
        ret(DENY),
        load(24),
    ];
    for (level, values) in [(1, sol), (6, vec![1, 4, 5, 6])] {
        let mut body = vec![load(32)];
        for value in values {
            body.extend([equal(value, 0, 1), ret(ALLOW)]);
        }
        body.push(ret(DENY));
        result.extend([equal(level, 1, 0), w(5, 0, 0, body.len() as u32)]);
        result.extend(body);
        result.push(load(24));
    }
    result.push(ret(DENY));
    result
}

const X64: &[u32] = &[
    0, 1, 19, 20, 17, 18, 295, 296, 327, 328, 8, 3, 436, 32, 33, 22, 40, 326, 275, 276, 278, 2,
    257, 437, 85, 4, 6, 5, 262, 332, 137, 138, 21, 269, 439, 78, 217, 89, 267, 79, 80, 81, 83, 258,
    84, 87, 263, 82, 264, 316, 86, 265, 88, 266, 90, 91, 268, 452, 92, 93, 94, 260, 95, 76, 77,
    285, 74, 75, 132, 235, 261, 280, 73, 191, 192, 193, 194, 195, 196, 188, 189, 190, 197, 198,
    199, 12, 9, 10, 11, 25, 28, 27, 324, 26, 202, 449, 273, 274, 334, 218, 24, 204, 145, 143, 309,
    219, 228, 229, 230, 96, 201, 35, 7, 271, 23, 270, 213, 233, 232, 281, 441, 284, 286, 287, 13,
    14, 127, 128, 130, 15, 131, 62, 200, 234, 129, 297, 282, 37, 36, 38, 34, 39, 110, 186, 102,
    107, 104, 108, 118, 120, 115, 125, 121, 111, 124, 97, 98, 63, 99, 318, 57, 58, 59, 322, 61,
    247, 60, 231, 109, 112, 49, 50, 43, 42, 51, 52, 48, 44, 45,
];
const ARM64: &[u32] = &[
    63, 64, 65, 66, 67, 68, 69, 70, 286, 287, 62, 57, 436, 23, 71, 285, 76, 77, 75, 56, 437, 80,
    79, 291, 43, 44, 48, 439, 61, 78, 17, 49, 50, 34, 35, 38, 276, 37, 36, 52, 53, 452, 55, 54,
    166, 45, 46, 47, 82, 83, 88, 32, 8, 9, 10, 11, 12, 13, 5, 6, 7, 14, 15, 16, 214, 222, 226, 215,
    216, 233, 232, 283, 227, 98, 449, 99, 100, 293, 96, 124, 123, 120, 121, 168, 128, 113, 114,
    115, 169, 101, 73, 72, 21, 22, 441, 86, 87, 134, 135, 136, 137, 133, 139, 132, 129, 130, 131,
    138, 240, 102, 103, 172, 173, 178, 174, 175, 176, 177, 148, 150, 158, 90, 155, 156, 163, 165,
    160, 179, 278, 221, 281, 260, 95, 93, 94, 154, 157, 200, 201, 202, 203, 204, 205, 210, 206,
    207,
];

pub fn frozen_linux_filter_program(abi: &str) -> VerificationResult<Vec<Instruction>> {
    let (arch, numbers, catalogue, rights) = match abi {
        "x86_64" => (
            0xc000003e,
            [
                56, 72, 16, 55, 54, 157, 302, 288, 293, 292, 290, 291, 289, 283, 53, 41,
            ],
            X64,
            [46, 47],
        ),
        "aarch64" => (
            0xc00000b7,
            [
                220, 25, 29, 209, 208, 167, 261, 242, 59, 24, 19, 20, 74, 85, 199, 198,
            ],
            ARM64,
            [211, 212],
        ),
        _ => return Err("unknown frozen Linux filter ABI".into()),
    };
    let mut program = vec![load(4), equal(arch, 1, 0), ret(0x80000000), load(0)];
    if abi == "x86_64" {
        program.extend([w(0x45, 0, 1, 0x40000000), ret(0x80000000)]);
    }
    program.extend([equal(435, 0, 1), ret(0x50026)]);
    let bodies = vec![
        clone_rule(),
        fcntl(),
        commands(24, &[0x5421, 0x541b, 0x5401, 0x5413]),
        options(true),
        options(false),
        commands(16, &[39, 3, 16, 15, 21, 27, 30]),
        vec![
            load(20),
            equal(0, 1, 0),
            ret(DENY),
            load(16),
            equal(0, 1, 0),
            ret(DENY),
            ret(ALLOW),
        ],
        flags(40, 0x80800),
        flags(24, 0x80800),
        flags(32, 0x80000),
        flags(24, 0x80800),
        flags(16, 0x80000),
        flags(40, 0x80800),
        flags(24, 0x80800),
    ];
    for (number, body) in numbers[..14].iter().copied().zip(bodies) {
        dispatch(&mut program, number, body);
    }
    if abi == "x86_64" {
        dispatch(&mut program, 158, commands(16, &[0x1002, 0x1003]));
    }
    dispatch(&mut program, numbers[14], socket(true));
    let unix = socket(true);
    let mut mixed = vec![load(16), equal(1, 1, 0), w(5, 0, 0, unix.len() as u32)];
    mixed.extend(unix);
    mixed.extend(socket(false));
    dispatch(&mut program, numbers[15], mixed);
    for number in catalogue.iter().copied().chain(rights) {
        program.extend([equal(number, 0, 1), ret(ALLOW)]);
    }
    program.push(ret(DENY));
    Ok(program)
}
