#[path = "../src/release/native_unit_retirement.rs"]
mod native_unit_retirement;

#[test]
fn real_service_and_socket_observations_have_distinct_pid_contracts() {
    for unit in [
        "memcordon-sealed-agent",
        "memcordon-sealed-launcher",
        "memcordon-sealed-network-launcher",
    ] {
        let service = format!("{unit}.service");
        let socket = format!("{unit}.socket");
        native_unit_retirement::verify_inactive(&service, "MainPID=0\nActiveState=inactive\n")
            .unwrap();
        assert!(
            native_unit_retirement::verify_inactive(&service, "ActiveState=inactive\n").is_err()
        );
        native_unit_retirement::verify_inactive(&socket, "ActiveState=inactive\n").unwrap();
        for hostile in [
            "ActiveState=active\n",
            "ActiveState=inactive\nMainPID=2\n",
            "ActiveState=inactive\nActiveState=inactive\n",
            "ActiveState=inactive\nMainPID=0\nMainPID=0\n",
            "ActiveState=inactive\nUnknown=0\n",
            "",
        ] {
            assert!(native_unit_retirement::verify_inactive(&socket, hostile).is_err());
        }
    }
    assert!(
        native_unit_retirement::verify_inactive("foreign.socket", "ActiveState=inactive\n")
            .is_err()
    );
    assert!(
        native_unit_retirement::verify_inactive("memcordon.conf", "ActiveState=inactive\n")
            .is_err()
    );
}
