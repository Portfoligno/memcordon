// A native filesystem probe for the production installed-consumer argv builder.
// The output is a path observation, not a MemCordon result or acceptance claim.
fn main() {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let report_index = arguments
        .iter()
        .position(|value| value == "--report")
        .unwrap();
    let fixture_index = arguments.iter().position(|value| value == "--").unwrap();
    let report = std::path::Path::new(&arguments[report_index + 1]);
    let fixture = std::path::Path::new(&arguments[fixture_index + 1]);
    assert!(report.is_absolute());
    assert!(fixture.is_absolute());
    assert!(report.parent().unwrap().is_dir());
    assert_ne!(std::env::current_dir().unwrap(), report.parent().unwrap());
    let observed = std::fs::read(fixture).unwrap();
    std::fs::write(report, observed).unwrap();
}
