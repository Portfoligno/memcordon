// Observe filesystem paths and literal argv; this is not a runtime result.
fn main() {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let mut arguments = arguments.iter();
    for expected in [
        "+4GiB",
        "+120s",
        "--sealed",
        "--report-format",
        "result-v1",
        "--report",
    ] {
        assert_eq!(arguments.next().unwrap(), expected);
    }
    let report = std::path::Path::new(arguments.next().unwrap());
    assert_eq!(arguments.next().unwrap(), "--");
    let fixture = std::path::Path::new(arguments.next().unwrap());
    assert_eq!(arguments.next().unwrap(), "exit");
    assert_eq!(arguments.next().unwrap(), "--code");
    assert_eq!(arguments.next().unwrap(), "0");
    assert!(arguments.next().is_none());
    assert!(report.is_absolute());
    assert!(fixture.is_absolute());
    assert_eq!(
        std::fs::canonicalize(report.parent().unwrap()).unwrap(),
        std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap()
    );
    let bytes = std::fs::read(fixture).unwrap();
    let mut sink = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(report)
        .unwrap();
    std::io::Write::write_all(&mut sink, &bytes).unwrap();
}
