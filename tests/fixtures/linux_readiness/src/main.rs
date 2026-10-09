fn main() -> std::io::Result<()> {
    use std::io::Write;
    let mut arguments = std::env::args_os().skip(1);
    let output = arguments.next().ok_or_else(|| std::io::Error::other("owned output absent"))?;
    if arguments.next().is_some() { return Err(std::io::Error::other("unexpected argument")); }
    // Keep the actual creation owner observable before any generated effect.
    use std::io::Read;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&[0xA5])?;
    stdout.flush()?;
    let mut release = [0];
    std::io::stdin().read_exact(&mut release)?;
    if release != [b'R'] { return Err(std::io::Error::other("generated child release differs")); }
    let bytes: Vec<u8> = (u8::MIN..=u8::MAX).collect();
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(output)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}
