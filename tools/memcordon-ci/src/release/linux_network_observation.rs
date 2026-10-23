//! Native sysfs observations; unavailable provenance never qualifies a link exception.
#[cfg(unix)]
mod native {
    use crate::{CiError, Result};
    use serde_json::{Value, json};
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    fn leaf(path: &Path) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        fs::File::open(path)?.take(1025).read_to_end(&mut bytes)?;
        if bytes.len() > 1024 {
            return Err(CiError::Message("sysfs network leaf exceeds bound".into()));
        }
        Ok(bytes)
    }

    fn identity(path: &Path) -> Result<Value> {
        let first = fs::metadata(path)?;
        let canonical = fs::canonicalize(path)?;
        let index = leaf(&path.join("ifindex"))?;
        let index = std::str::from_utf8(&index)
            .map_err(|error| CiError::Message(error.to_string()))?
            .trim()
            .parse::<u32>()
            .map_err(|error| CiError::Message(error.to_string()))?;
        let last = fs::metadata(path)?;
        if !first.is_dir()
            || index == 0
            || first.dev() != last.dev()
            || first.ino() != last.ino()
            || fs::canonicalize(path)? != canonical
        {
            return Err(CiError::Message(
                "sysfs network identity changed during observation".into(),
            ));
        }
        Ok(json!({"path":canonical,"device":first.dev(),"inode":first.ino(),"ifindex":index}))
    }

    fn optional_path(path: &Path) -> Result<Option<PathBuf>> {
        match fs::canonicalize(path) {
            Ok(path) => Ok(Some(path)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn relation(root: &Path, path: &Path, name: &str) -> Result<Value> {
        let mut components = Path::new(name).components();
        if !matches!(components.next(), Some(std::path::Component::Normal(_)))
            || components.next().is_some()
        {
            return Err(CiError::Message(
                "sysfs network relation name differs".into(),
            ));
        }
        if fs::canonicalize(root.join(name))? != fs::canonicalize(path)? {
            return Err(CiError::Message(
                "sysfs network relation does not join named identity".into(),
            ));
        }
        identity(path)
    }

    fn leaves(path: &Path) -> Result<BTreeMap<&'static str, Vec<u8>>> {
        ["ifindex", "address", "flags", "operstate"]
            .into_iter()
            .map(|name| Ok((name, leaf(&path.join(name))?)))
            .collect()
    }

    pub fn observe_link(root: &Path, name: &str) -> Result<Value> {
        let path = root.join(name);
        let initial = identity(&path)?;
        let values = leaves(&path)?;
        let provenance = (|| -> Result<Value> {
            let mut sampled = None;
            // Two proof samples detect churn; this is not a retry or a new baseline.
            for _ in 0..2 {
            let device = if let Some(device) = optional_path(&path.join("device"))? {
                Some(json!({"path":device,"subsystem":optional_path(&device.join("subsystem"))?,
                    "driver":optional_path(&device.join("driver"))?,"physfn":optional_path(&device.join("physfn"))?}))
            } else { None };
            let master = if let Some(master) = optional_path(&path.join("master"))? {
                let name = master.file_name().and_then(|name| name.to_str())
                    .ok_or_else(|| CiError::Message("sysfs master name is not UTF-8".into()))?;
                Some(json!({"name":name,"identity":relation(root, &master, name)?}))
            } else { None };
            let mut uppers = BTreeMap::new();
            let mut lowers = BTreeMap::new();
            for entry in fs::read_dir(&path)? {
                let entry = entry?;
                let name = entry.file_name();
                let name = name.to_str().ok_or_else(|| CiError::Message("sysfs relation name is not UTF-8".into()))?;
                let selected = name.strip_prefix("upper_").map(|name| (&mut uppers, name))
                    .or_else(|| name.strip_prefix("lower_").map(|name| (&mut lowers, name)));
                if let Some((relations, name)) = selected {
                    if !entry.file_type()?.is_symlink() {
                        return Err(CiError::Message("sysfs network relation is not a kernel symlink".into()));
                    }
                    relations.insert(name.to_owned(), relation(root, &entry.path(), name)?);
                }
            }
                let current = json!({"revision":1,"state":"observed","identity":initial,
                    "device":device,"master":master,"uppers":uppers,"lowers":lowers});
                if sampled.as_ref().is_some_and(|previous| previous != &current) {
                    return Err(CiError::Message("sysfs network topology changed during observation".into()));
                }
                sampled = Some(current);
            }
            if identity(&path)? != initial || leaves(&path)? != values {
                return Err(CiError::Message("sysfs network configuration changed during observation".into()));
            }
            Ok(sampled.expect("two native topology samples were collected"))
        })().unwrap_or_else(|error| json!({"revision":1,"state":"unavailable",
            "error":error.to_string().chars().take(1024).collect::<String>()}));
        let mut observed = serde_json::to_value(values)?;
        observed
            .as_object_mut()
            .expect("network leaves serialize as a map")
            .insert("provenance".into(), provenance);
        Ok(observed)
    }
}

#[cfg(unix)]
pub use native::observe_link;
