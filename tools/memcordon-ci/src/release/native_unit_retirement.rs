#[derive(Clone, Copy)]
pub enum SelectedUnitKind {
    Service,
    Socket,
    Configuration,
}

pub fn selected_unit_kind(unit: &str) -> Result<SelectedUnitKind, String> {
    match unit {
        "memcordon-sealed-agent.service"
        | "memcordon-sealed-launcher.service"
        | "memcordon-sealed-network-launcher.service" => Ok(SelectedUnitKind::Service),
        "memcordon-sealed-agent.socket"
        | "memcordon-sealed-launcher.socket"
        | "memcordon-sealed-network-launcher.socket" => Ok(SelectedUnitKind::Socket),
        "memcordon.conf" => Ok(SelectedUnitKind::Configuration),
        _ => Err("unsupported original native unit identity".into()),
    }
}

pub fn verify_inactive(unit: &str, text: &str) -> Result<(), String> {
    let kind = selected_unit_kind(unit)?;
    if matches!(kind, SelectedUnitKind::Configuration) {
        return Err("configuration file is not a systemd unit".into());
    }
    let mut inactive = false;
    let mut main_pid = None;
    for line in text.lines() {
        match line.split_once('=') {
            Some(("ActiveState", "inactive")) if !inactive => inactive = true,
            Some(("MainPID", "0")) if main_pid.is_none() => main_pid = Some(0),
            _ => return Err("original native unit observation differs".into()),
        }
    }
    if !inactive || matches!(kind, SelectedUnitKind::Service) && main_pid != Some(0) {
        return Err("original native unit retirement incomplete".into());
    }
    Ok(())
}
