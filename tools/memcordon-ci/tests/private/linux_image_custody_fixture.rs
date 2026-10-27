use super::*;

pub(super) fn custody(deadline: Instant) -> crate::release::linux_image_custodian::Custodians {
    use crate::release::linux_image_custodian::{Custodians, capacity};
    let path = match option_env!("CARGO_BIN_EXE_memcordon-ci") {
        Some(path) => PathBuf::from(path),
        None => {
            let current = std::env::current_exe().unwrap();
            let parent = current.parent().unwrap();
            let directory = if parent.file_name() == Some(std::ffi::OsStr::new("deps")) {
                parent.parent().unwrap()
            } else {
                parent
            };
            directory.join("memcordon-ci")
        }
    };
    let mut custody = Custodians::default();
    custody
        .pin_driver(
            path.clone(),
            File::open(&path)
                .expect("native fixture requires the built qualified memcordon-ci binary"),
            deadline,
        )
        .unwrap();
    let budget = memcordon_platform::test_support::image_custody_fd_budget().unwrap();
    custody
        .configure(
            capacity::Plan::new(budget.open_descriptors, 128, 512, 0, budget.soft_limit).unwrap(),
        )
        .unwrap();
    custody
}
