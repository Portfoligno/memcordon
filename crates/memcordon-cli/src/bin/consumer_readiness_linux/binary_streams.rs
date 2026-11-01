//! Independent fixture byte products; no process or transport behavior here.
use std::io::{self, Write};

pub const LARGE_BLOCKS: usize = 8192;

pub fn raw(stdout: &mut impl Write, stderr: &mut impl Write) -> io::Result<()> {
    let ascending: Vec<u8> = (u8::MIN..=u8::MAX).collect();
    let descending: Vec<u8> = ascending.iter().copied().rev().collect();
    stdout.write_all(&ascending)?;
    stdout.flush()?;
    stderr.write_all(&descending)?;
    stderr.flush()
}

pub fn large(stdout: &mut impl Write, stderr: &mut impl Write) -> io::Result<()> {
    let ascending: Vec<u8> = (u8::MIN..=u8::MAX).collect();
    let descending: Vec<u8> = ascending.iter().copied().rev().collect();
    for _ in 0..LARGE_BLOCKS {
        stdout.write_all(&ascending)?;
        stderr.write_all(&descending)?;
    }
    stdout.flush()?;
    stderr.flush()
}
