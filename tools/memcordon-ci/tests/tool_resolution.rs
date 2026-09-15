#[cfg(unix)]
#[test]
fn executable_alias_keeps_its_invocation_name() {
    use memcordon_ci::build_context::environment;
    use std::collections::BTreeMap;
    use std::ffi::{OsStr, OsString};
    use std::fs;
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("rustup-init");
    fs::write(&target, b"fixture\n").unwrap();
    let alias = directory.path().join("rustup");
    symlink("rustup-init", &alias).unwrap();
    let environment = BTreeMap::from([(
        OsString::from("PATH"),
        directory.path().as_os_str().to_owned(),
    )]);

    for requested in [OsStr::new("rustup"), alias.as_os_str()] {
        let resolved = environment::resolve_tool(requested, &environment).unwrap();
        assert_eq!(resolved, alias, "dispatch must retain the executable alias");
        assert_eq!(
            resolved.canonicalize().unwrap(),
            target.canonicalize().unwrap()
        );
    }
}
