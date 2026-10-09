#[path = "../src/linux_path.rs"]
mod linux_path;

#[test]
fn retained_linux_parents_and_leaves_preserve_native_lexical_spelling() {
    for (path, parent, name) in [
        (
            "/run/case/result.json",
            Some("/run/case"),
            Some("result.json"),
        ),
        ("/result.json", Some("/"), Some("result.json")),
        ("//a//b", Some("//a"), Some("b")),
        ("/", None, None),
        ("/.", None, None),
        ("", None, None),
        ("result.json", Some(""), Some("result.json")),
        ("./result.json", Some("."), Some("result.json")),
        ("/a//b/./result.json//", Some("/a//b"), Some("result.json")),
        ("/a/../result.json", Some("/a/.."), Some("result.json")),
        ("/a/..", Some("/a"), None),
        ("/a/.", Some("/"), Some("a")),
        (
            "C:\\case\\result.json",
            Some(""),
            Some("C:\\case\\result.json"),
        ),
    ] {
        assert_eq!(linux_path::parent(path).as_deref(), parent, "{path}");
        assert_eq!(linux_path::file_name(path), name, "{path}");
        #[cfg(unix)]
        {
            let native = std::path::Path::new(path);
            assert_eq!(
                linux_path::parent(path).as_deref(),
                native.parent().and_then(|p| p.to_str()),
                "{path}"
            );
            assert_eq!(
                linux_path::file_name(path),
                native.file_name().and_then(|p| p.to_str()),
                "{path}"
            );
        }
    }
}

#[test]
fn retained_linux_joins_never_use_host_separators() {
    for (base, leaf, expected) in [
        ("/run/case", "observations", "/run/case/observations"),
        ("/", "observations", "/observations"),
        ("/a//b/.", "observations", "/a//b/./observations"),
        ("/a/", "", "/a/"),
        ("/a", "", "/a/"),
        ("", "observations", "observations"),
        ("/a", "/other", "/other"),
        ("/a", "C:\\foreign", "/a/C:\\foreign"),
    ] {
        assert_eq!(linux_path::join(base, leaf), expected);
        #[cfg(unix)]
        assert_eq!(
            linux_path::join(base, leaf),
            std::path::Path::new(base).join(leaf).to_str().unwrap()
        );
    }
}

#[test]
fn retained_linux_equality_preserves_components_and_authority_boundaries() {
    for (left, right, equal) in [
        ("/run//case/./result/", "/run/case/result", true),
        ("//run/case", "/run/case", true),
        ("./case", "case", false),
        ("/run/case", "run/case", false),
        ("/run/case", "/run/case-other", false),
        ("/run/case/../other", "/run/other", false),
        ("/run/case\\result", "/run/case/result", false),
        ("C:\\run\\result", "C:/run/result", false),
    ] {
        assert_eq!(
            linux_path::equivalent(left, right),
            equal,
            "{left}, {right}"
        );
        #[cfg(unix)]
        assert_eq!(
            linux_path::equivalent(left, right),
            std::path::Path::new(left) == std::path::Path::new(right)
        );
    }
}

#[test]
fn retained_linux_ancestry_preserves_exact_root_chain() {
    assert_eq!(
        linux_path::ancestors("/tmp/case"),
        ["/tmp/case", "/tmp", "/"]
    );
    #[cfg(unix)]
    for path in ["/", "", "a/b", "/a//b/./c/", "//a//b", "/a/.."] {
        assert_eq!(
            linux_path::ancestors(path),
            std::path::Path::new(path)
                .ancestors()
                .map(|p| p.to_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        );
    }
}
