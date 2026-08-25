use std::ffi::OsString;
use std::path::Path;

use memcordon_ci::sealed_identity::{
    FrontendIdentity, parse_credential_readback, parse_frontend_identity, setpriv_sudo_arguments,
};

fn identity() -> FrontendIdentity {
    FrontendIdentity {
        username: "runner".to_owned(),
        uid: 1001,
        provider_gid: 998,
    }
}

fn absolute_program() -> &'static Path {
    if cfg!(windows) {
        Path::new(r"C:\opt\memcordon.exe")
    } else {
        Path::new("/opt/memcordon")
    }
}

#[test]
fn setpriv_transition_uses_numeric_ids_and_drops_supplementary_authority() {
    let arguments = [OsString::from("doctor"), OsString::from("--json")];
    let program = absolute_program();
    assert_eq!(
        setpriv_sudo_arguments(&identity(), program, &arguments).unwrap(),
        [
            "--non-interactive",
            "--",
            "/usr/bin/setpriv",
            "--reuid",
            "1001",
            "--regid",
            "998",
            "--clear-groups",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--no-new-privs",
            "--",
            program.to_str().unwrap(),
            "doctor",
            "--json",
        ]
        .map(OsString::from)
    );
}

#[test]
fn setpriv_transition_rejects_root_ids_and_relative_programs() {
    let arguments = [OsString::from("doctor")];
    assert!(setpriv_sudo_arguments(&identity(), Path::new("memcordon"), &arguments).is_err());

    let mut root_uid = identity();
    root_uid.uid = 0;
    assert!(setpriv_sudo_arguments(&root_uid, absolute_program(), &arguments).is_err());

    let mut root_gid = identity();
    root_gid.provider_gid = 0;
    assert!(setpriv_sudo_arguments(&root_gid, absolute_program(), &arguments).is_err());
}

#[test]
fn frontend_identity_requires_exact_nonroot_user_and_provider_group() {
    assert_eq!(
        parse_frontend_identity(b"runner\n", b"1001\n", b"memcordon:x:998:\n").unwrap(),
        identity()
    );
    assert!(parse_frontend_identity(b"root\n", b"0\n", b"memcordon:x:998:\n").is_err());
    assert!(parse_frontend_identity(b"runner\n", b"0\n", b"memcordon:x:998:\n").is_err());
    assert!(parse_frontend_identity(b"runner\n", b"1001\n", b"memcordon:x:0:\n").is_err());
    assert!(parse_frontend_identity(b"runner\n", b"1001\n", b"unexpected:x:998:\n").is_err());
    assert!(parse_frontend_identity(b"runner\nextra\n", b"1001\n", b"memcordon:x:998:\n").is_err());
}

#[test]
fn proc_status_readback_requires_all_ids_empty_groups_and_no_new_privs() {
    const STATUS: &str = "Name:\tcat\nUid:\t1001\t1001\t1001\t1001\nGid:\t998\t998\t998\t998\nGroups:\t\nNoNewPrivs:\t1\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\n";
    let readback = parse_credential_readback(&identity(), STATUS.as_bytes()).unwrap();
    assert_eq!(readback.schema_version, 2);
    assert_eq!(readback.uid, 1001);
    assert_eq!(readback.gid, 998);
    assert!(readback.supplementary_groups.is_empty());
    assert!(readback.no_new_privs);
    assert_eq!(readback.capability_inheritable, 0);
    assert_eq!(readback.capability_permitted, 0);
    assert_eq!(readback.capability_effective, 0);
    assert_eq!(readback.capability_ambient, 0);

    for invalid in [
        STATUS.replace("Groups:\t\n", "Groups:\t27\n"),
        STATUS.replace("NoNewPrivs:\t1\n", "NoNewPrivs:\t0\n"),
        STATUS.replace(
            "Uid:\t1001\t1001\t1001\t1001\n",
            "Uid:\t1001\t1001\t0\t1001\n",
        ),
        STATUS.replace("Gid:\t998\t998\t998\t998\n", "Gid:\t998\t998\t998\t0\n"),
        STATUS.replace(
            "Uid:\t1001\t1001\t1001\t1001\n",
            "Uid:\t1001\t1001\t1001\t1001\nUid:\t1001\t1001\t1001\t1001\n",
        ),
    ] {
        assert!(parse_credential_readback(&identity(), invalid.as_bytes()).is_err());
    }

    for field in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
        let zero = format!("{field}:\t0000000000000000\n");
        let active = STATUS.replace(&zero, &format!("{field}:\t0000000000000001\n"));
        assert!(
            parse_credential_readback(&identity(), active.as_bytes()).is_err(),
            "active {field} must be rejected"
        );
    }

    let capability_line = "CapInh:\t0000000000000000\n";
    for invalid in [
        STATUS.replace(capability_line, ""),
        STATUS.replace(
            capability_line,
            "CapInh:\t0000000000000000\nCapInh:\t0000000000000000\n",
        ),
        STATUS.replace(capability_line, "CapInh:\tnot-hex\n"),
        STATUS.replace(capability_line, "CapInh:\t0 0\n"),
        STATUS.replace(capability_line, "CapInh:\t10000000000000000\n"),
    ] {
        assert!(parse_credential_readback(&identity(), invalid.as_bytes()).is_err());
    }
}
