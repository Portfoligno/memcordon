//! Lexical operations on retained Linux-native operands, independent of host OS.

fn components(path: &str) -> Vec<(usize, usize)> {
    let mut offset = 0;
    path.split('/')
        .filter_map(|part| {
            let start = offset;
            offset += part.len() + 1;
            (!part.is_empty() && (part != "." || start == 0)).then_some((start, start + part.len()))
        })
        .collect()
}

pub(crate) fn parent(path: &str) -> Option<String> {
    let parts = components(path);
    match parts.len() {
        0 => None,
        1 if path.starts_with('/') => Some("/".into()),
        1 => Some(String::new()),
        count => Some(path[..parts[count - 2].1].into()),
    }
}

pub(crate) fn file_name(path: &str) -> Option<&str> {
    let (start, end) = *components(path).last()?;
    let name = &path[start..end];
    (!matches!(name, "." | "..")).then_some(name)
}

pub(crate) fn join(base: &str, leaf: &str) -> String {
    if leaf.starts_with('/') || base.is_empty() {
        leaf.into()
    } else if base.ends_with('/') {
        format!("{base}{leaf}")
    } else {
        format!("{base}/{leaf}")
    }
}

pub(crate) fn equivalent(left: &str, right: &str) -> bool {
    left.starts_with('/') == right.starts_with('/')
        && components(left)
            .iter()
            .map(|&(start, end)| &left[start..end])
            .eq(components(right)
                .iter()
                .map(|&(start, end)| &right[start..end]))
}

pub(crate) fn ancestors(path: &str) -> Vec<String> {
    let mut output = vec![path.to_owned()];
    while let Some(next) = parent(output.last().expect("initial path")) {
        output.push(next);
    }
    output
}
