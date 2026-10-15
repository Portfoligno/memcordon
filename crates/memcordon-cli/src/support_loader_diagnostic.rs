//! Explicit support experiment frontend; never certification execution.
use std::{
    ffi::OsString,
    io::Read,
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

pub(super) fn execute(argv: &[OsString]) -> i32 {
    match run(argv) {
        Ok(status) => status,
        Err(error) => {
            eprintln!("error[MCCLI-SUPPORT-LOADER-DIAGNOSTIC]: {error}");
            126
        }
    }
}

fn run(argv: &[OsString]) -> Result<i32, String> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    let input = argv.get(1).ok_or("diagnostic selection path absent")?;
    let output = Path::new(argv.get(2).ok_or("diagnostic observation path absent")?);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(input)
        .map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err("diagnostic selection is not an ordinary file".into());
    }
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 4096 {
        return Err("diagnostic selection exceeds bound".into());
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)?;
    let selection: memcordon_core::WindowsLoaderDiagnosticSelectionV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_millis(),
    )
    .map_err(|error| error.to_string())?;
    selection.validate_at(now)?;
    let scope = memcordon_platform::WindowsLoaderDiagnosticScope::begin(selection)?;
    let args = match memcordon::invocation::route(
        argv.get(3..).ok_or("diagnostic execution argv absent")?,
    ) {
        Ok(memcordon::invocation::Invocation::Execute(args)) => args,
        _ => return Err("diagnostic requires typed execution argv".into()),
    };
    let status = crate::commands::execute(args, &crate::presentation::Presentation::automatic());
    let observation = scope.finish()?;
    let bytes = serde_json::to_vec(&observation).map_err(|error| error.to_string())?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err("diagnostic observation exceeds bound".into());
    }
    // The controller chooses this unprivileged frontend path. It is never
    // forwarded as a privileged provider destination or terminal authority.
    if output.try_exists().map_err(|error| error.to_string())? {
        return Err("diagnostic observation already exists".into());
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(output)
        .map_err(|error| error.to_string())?;
    use std::io::Write;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())?;
    Ok(status)
}
