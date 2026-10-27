#[path = "../src/release/linux_recovery_io.rs"]
mod recovery;
use std::{error::Error, io, path::Path};
#[test]
fn original_enoent_retains_operation_exact_path_kind_raw_and_source() {
    let path = Path::new("/protected/original/recovery-harness-acquisition/owner.json");
    let error = recovery::context("held-source-open", path, io::Error::from_raw_os_error(2));
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    let text = error.to_string();
    assert!(text.starts_with("operation=held-source-open; kind=NotFound; raw-os-error=Some(2)"));
    assert!(text.contains(path.to_str().unwrap()));
    assert!(text.contains("omitted-path-bytes=0"));
    let source = error
        .get_ref()
        .unwrap()
        .source()
        .unwrap()
        .downcast_ref::<io::Error>()
        .unwrap();
    assert_eq!(source.raw_os_error(), Some(2));
}
#[test]
fn huge_utf8_paths_are_bounded_and_unformattable_original_errors_are_never_rendered() {
    #[derive(Debug)]
    struct Private;
    impl std::fmt::Display for Private {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("private cause must not be formatted")
        }
    }
    impl Error for Private {}
    let seed = "界\u{1}";
    let text = format!(
        "/{}last-owned-leaf",
        seed.repeat(recovery::PATH_BOUND.div_ceil(seed.len()) * 4)
    );
    let error = recovery::context("record-sync", Path::new(&text), io::Error::other(Private));
    let display = error.to_string();
    assert!(display.contains("last-owned-leaf"));
    assert!(!display.contains("omitted-path-bytes=0"));
    assert!(display.len() < recovery::DISPLAY_BOUND);
    assert_eq!(format!("{:?}", error.get_ref().unwrap()), display);
}
