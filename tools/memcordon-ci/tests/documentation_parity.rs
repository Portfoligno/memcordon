use std::collections::BTreeMap;

use memcordon_ci::config::Release;

fn markdown_table(document: &str, heading: &str) -> BTreeMap<String, String> {
    let lines: Vec<_> = document.lines().collect();
    let heading: Vec<_> = heading.lines().collect();
    assert!(
        !heading.is_empty(),
        "documented table heading must not be empty"
    );
    let start = lines
        .windows(heading.len())
        .position(|candidate| candidate == heading)
        .expect("documented table heading must exist")
        + heading.len();
    lines[start..]
        .iter()
        .copied()
        .take_while(|line| line.starts_with("| "))
        .map(|line| {
            let cells = line
                .strip_prefix("| ")
                .and_then(|line| line.strip_suffix(" |"))
                .expect("table row must have enclosing pipes")
                .split_once(" | ")
                .expect("table row must have exactly two cells");
            (cells.0.to_owned(), cells.1.to_owned())
        })
        .collect()
}

#[test]
fn markdown_tables_preserve_exact_cells_across_checkout_line_endings() {
    let document = "intro\n| Target | Runtime components |\n| --- | --- |\n| linux | agent, launcher |\n| windows | agent.exe |\n\ntrailer\n";
    let heading = "| Target | Runtime components |\n| --- | --- |\n";
    let expected = BTreeMap::from([
        ("linux".into(), "agent, launcher".into()),
        ("windows".into(), "agent.exe".into()),
    ]);
    assert_eq!(markdown_table(document, heading), expected);
    assert_eq!(
        markdown_table(&document.replace('\n', "\r\n"), heading),
        expected
    );
    assert_eq!(
        markdown_table(document, &heading.replace('\n', "\r\n")),
        expected
    );
}

fn release() -> Release {
    toml::from_str(include_str!("../../../ci/release.toml"))
        .expect("release configuration must parse")
}

#[test]
fn reference_runtime_inventory_matches_release_configuration() {
    let documented = markdown_table(
        include_str!("../../../docs/reference.md"),
        "| Target | Runtime components |\n| --- | --- |\n",
    );
    let configured: BTreeMap<_, _> = release()
        .assets
        .target
        .into_iter()
        .map(|target| {
            (
                target.id,
                target
                    .executable
                    .into_iter()
                    .map(|component| component.archive_path)
                    .collect::<Vec<_>>()
                    .join(", "),
            )
        })
        .collect();
    assert_eq!(documented, configured);
}
