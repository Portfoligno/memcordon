use super::*;

#[test]
fn standalone_context_never_requires_a_checkout() {
    let current = Path::new("/tmp/installed-owner-peer");
    let commands = vec![vec![
        "memcordon-ci",
        "external-consumer",
        "--input",
        "input.json",
        "--destination",
        "consumer",
    ]];
    #[cfg(target_os = "linux")]
    let commands = {
        let mut commands = commands;
        for command in ["current-linux-owner-probe", "current-linux-snapshot-probe"] {
            commands.push(vec![
                "memcordon-ci",
                command,
                "--input",
                "-",
                "--output",
                "response.json",
            ]);
        }
        commands
    };
    for arguments in commands {
        let cli = Cli::try_parse_from(arguments).unwrap();
        assert_eq!(
            command_root(current, &cli.command, |_| panic!(
                "standalone command requested workspace"
            ))
            .unwrap(),
            current
        );
    }
}

#[test]
fn repository_commands_keep_workspace_resolution_and_its_error() {
    let cli = Cli::try_parse_from(["memcordon-ci", "ci", "check-workflows"]).unwrap();
    let current = Path::new("/tmp/installed-owner-peer");
    let error = command_root(current, &cli.command, |observed| {
        assert_eq!(observed, current);
        Err(CiError::Message(
            "actual workspace resolution failure".into(),
        ))
    })
    .unwrap_err();
    assert_eq!(error.to_string(), "actual workspace resolution failure");
}
