//! Static recognition of the reviewed retained-descriptor child boundary.
use std::path::Path;

pub(super) fn reviewed(relative: &Path, syntax: &syn::File, pre_exec_calls: usize) -> bool {
    if relative != Path::new("tools/memcordon-ci/src/release/linux_current_phase_gate.rs")
        || pre_exec_calls != 1
    {
        return false;
    }
    let expected: syn::ItemFn = syn::parse_quote! {
        pub(crate) fn configure_extra_descriptor(
            command: &mut std::process::Command,
            source: &File,
        ) -> std::io::Result<()> {
            use std::os::unix::process::CommandExt;
            let held = rustix::io::fcntl_dupfd_cloexec(source, 129).map_err(std::io::Error::from)?;
            unsafe {
                command.pre_exec(move || {
                    if libc::fcntl(128, libc::F_GETFD) >= 0 {
                        return Err(std::io::Error::from_raw_os_error(libc::EEXIST));
                    }
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::EBADF) {
                        return Err(error);
                    }
                    if libc::dup2(held.as_raw_fd(), 128) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            Ok(())
        }
    };
    let mut candidates = syntax.items.iter().filter_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == "configure_extra_descriptor" => {
            Some(function)
        }
        _ => None,
    });
    let Some(function) = candidates.next() else {
        return false;
    };
    if candidates.next().is_some() {
        return false;
    }
    let mut function = function.clone();
    // Documentation is non-operational; every other attribute remains part
    // of the exact contract, including cfg and cfg_attr.
    function
        .attrs
        .retain(|attribute| !attribute.path().is_ident("doc"));
    function == expected
}
