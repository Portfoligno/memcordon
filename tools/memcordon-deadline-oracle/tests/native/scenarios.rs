use super::*;

#[test]
fn fault_injection_is_not_preempted_by_an_unrelated_work_deadline() {
    let executable = Path::new("memcordon");
    let report = Path::new("execution.json");
    let marker = Path::new("target-identity.json");
    for (fixture, budget, target) in [
        ("frontend-loss", None, "sleep"),
        ("frontend-stopped", Some("+250ms"), "sleep"),
        ("sleep", Some("+250ms"), "sleep"),
        ("blocked-stderr", Some("+250ms"), "blocked-stderr"),
        ("zero-budget", Some("+0ms"), "sleep"),
    ] {
        let command = scenario_command(executable, fixture, report, marker).unwrap();
        assert_eq!(command.get_program(), executable);
        let mut expected: Vec<OsString> = budget.into_iter().map(OsString::from).collect();
        expected.extend([OsString::from("--summary"), OsString::from("--report")]);
        expected.push(report.into());
        expected.push("--".into());
        expected.push(std::env::current_exe().unwrap().into_os_string());
        expected.extend([OsString::from("--fixture"), OsString::from(target)]);
        expected.push(marker.into());
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            expected,
            "{fixture}"
        );
    }
}
