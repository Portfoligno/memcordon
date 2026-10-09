fn main() -> std::io::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let input = args.next().expect("input path");
    let output = args.next().expect("output path");
    assert!(args.next().is_none());
    std::fs::write(output, std::fs::read(input)?)
}
