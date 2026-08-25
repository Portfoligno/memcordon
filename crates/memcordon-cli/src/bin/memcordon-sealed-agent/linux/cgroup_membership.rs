const MAX_PROC_CGROUP_BYTES: usize = 64 * 1024;

pub fn is_sealed(input: &str) -> Result<bool, String> {
    if input.len() > MAX_PROC_CGROUP_BYTES {
        return Err("recursive provider cgroup membership exceeds the bounded input".to_owned());
    }
    if input.is_empty() || !input.ends_with('\n') || input.as_bytes().contains(&0) {
        return Err("recursive provider cgroup membership is not canonical text".to_owned());
    }
    let mut unified_membership = None;
    for line in input.lines() {
        let (hierarchy, rest) = line
            .split_once(':')
            .ok_or_else(|| "recursive provider cgroup membership is malformed".to_owned())?;
        let (controllers, path) = rest
            .split_once(':')
            .ok_or_else(|| "recursive provider cgroup membership is malformed".to_owned())?;
        if hierarchy.is_empty()
            || !hierarchy.bytes().all(|byte| byte.is_ascii_digit())
            || path.is_empty()
            || !path.starts_with('/')
        {
            return Err("recursive provider cgroup membership is malformed".to_owned());
        }
        if controllers.is_empty() && unified_membership.replace(path).is_some() {
            return Err("recursive provider cgroup membership repeats cgroup v2".to_owned());
        }
    }
    let path = unified_membership
        .ok_or_else(|| "recursive provider cgroup membership omits cgroup v2".to_owned())?;
    Ok(std::path::Path::new(path)
        .components()
        .any(|component| component.as_os_str() == "memcordon-sealed"))
}
