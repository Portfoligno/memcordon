//! Opt-in, test-support-only phase capture for the packaged Windows frontend.

use std::cell::RefCell;
use std::io::Write as _;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::rc::Rc;

thread_local! {
    static PHASE_PATH: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

#[doc(hidden)]
pub struct WindowsStackPhaseCaptureGuard {
    _not_send: PhantomData<Rc<()>>,
}

impl WindowsStackPhaseCaptureGuard {
    pub fn install(path: PathBuf) -> Self {
        PHASE_PATH.with(|slot| {
            let mut slot = slot.borrow_mut();
            assert!(slot.is_none(), "stack phase capture is already installed");
            *slot = Some(path);
        });
        Self {
            _not_send: PhantomData,
        }
    }
}

impl Drop for WindowsStackPhaseCaptureGuard {
    fn drop(&mut self) {
        PHASE_PATH.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}

pub(crate) fn phase(token: &'static str) {
    PHASE_PATH.with(|slot| {
        if let Some(path) = slot.borrow().as_ref() {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .expect("stack phase opt-in path must be writable");
            file.write_all(token.as_bytes())
                .expect("stack phase token must be writable");
            file.write_all(b"\n")
                .expect("stack phase newline must be writable");
        }
    });
}
