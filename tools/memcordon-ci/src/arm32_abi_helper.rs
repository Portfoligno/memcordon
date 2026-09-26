//! Fixed static ARM EABI executable for the physical AArch32 entry probe.
//! The instruction words below are the reviewed assembly, in little endian.
//! No host assembler, dynamic loader, emulator, or runtime input changes B.

const LOAD_OFFSET: usize = 4096;
const LOAD_BASE: u32 = 0x10000;
const CODE: [u32; 14] = [
    0xe3a0_7014, // mov r7, #20       ; __NR_getpid, first syscall after exec
    0xef00_0000, // svc #0
    0xe24d_d004, // sub sp, sp, #4
    0xe3a0_0041, // mov r0, #'A'
    0xe5cd_0000, // strb r0, [sp]
    0xe1a0_100d, // mov r1, sp
    0xe3a0_0001, // mov r0, #1        ; stdout
    0xe3a0_2001, // mov r2, #1
    0xe3a0_7004, // mov r7, #4        ; __NR_write
    0xef00_0000, // svc #0
    0xe3a0_0000, // mov r0, #0
    0xe3a0_7001, // mov r7, #1        ; __NR_exit
    0xef00_0000, // svc #0
    0xeaff_fffe, // b .              ; a returned exit cannot become success
];

/// ET_EXEC, one RX PT_LOAD, ARM EABI5, no interpreter or relocations. The
/// executable itself is inventoried as B on aarch64 GNU candidate builds.
pub fn static_aarch32_helper() -> Vec<u8> {
    let file_size = LOAD_OFFSET + CODE.len() * std::mem::size_of::<u32>();
    let mut bytes = vec![0_u8; file_size];
    bytes[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    put16(&mut bytes, 16, 2); // ET_EXEC
    put16(&mut bytes, 18, 40); // EM_ARM
    put32(&mut bytes, 20, 1); // EV_CURRENT
    put32(&mut bytes, 24, LOAD_BASE + LOAD_OFFSET as u32);
    put32(&mut bytes, 28, 52); // program header offset
    put32(&mut bytes, 36, 0x0500_0000); // ARM EABI5
    put16(&mut bytes, 40, 52); // ELF header size
    put16(&mut bytes, 42, 32); // program header size
    put16(&mut bytes, 44, 1); // one program header
    put32(&mut bytes, 52, 1); // PT_LOAD
    put32(&mut bytes, 56, 0); // complete file is mapped
    put32(&mut bytes, 60, LOAD_BASE);
    put32(&mut bytes, 64, LOAD_BASE);
    put32(&mut bytes, 68, file_size as u32);
    put32(&mut bytes, 72, file_size as u32);
    put32(&mut bytes, 76, 5); // PF_R | PF_X
    put32(&mut bytes, 80, LOAD_OFFSET as u32);
    for (index, instruction) in CODE.iter().enumerate() {
        put32(&mut bytes, LOAD_OFFSET + index * 4, *instruction);
    }
    bytes
}

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
