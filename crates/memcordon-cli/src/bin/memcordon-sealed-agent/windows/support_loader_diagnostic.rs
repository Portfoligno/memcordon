//! Internal selection established only after authenticated support dispatch and
//! exclusive provider settlement. No environment or ordinary launch enables it.
use std::{
    cell::Cell,
    cell::RefCell,
    marker::PhantomData,
    rc::Rc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use memcordon_core::{WindowsLoaderDebugObservationV1, WindowsLoaderDiagnosticSelectionV1};

pub(super) struct Execution {
    pub selection: WindowsLoaderDiagnosticSelectionV1,
    pub work: Instant,
    pub cleanup: Instant,
    pub observation: RefCell<Option<WindowsLoaderDebugObservationV1>>,
    pub comparison_started: Cell<bool>,
    pub detached_console: Cell<bool>,
    pub baseline_plan: RefCell<Option<memcordon_windows_launch_core::ProductionLoaderPlanV1>>,
    pub comparison: RefCell<Option<memcordon_core::WindowsLoaderConsoleComparisonV1>>,
    pub variant_observation: RefCell<Option<WindowsLoaderDebugObservationV1>>,
    pub active_console_plan:
        RefCell<Option<memcordon_windows_launch_core::SupportDetachedConsolePlanV1>>,
}

impl Execution {
    pub(super) fn new(selection: &WindowsLoaderDiagnosticSelectionV1) -> Result<Rc<Self>, String> {
        // Sample monotonic origin BEFORE wall clock, so conversion cannot add
        // elapsed sampling time to either supplied original absolute cutoff.
        let origin = Instant::now();
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?;
        let now = u64::try_from(wall.as_millis()).map_err(|error| error.to_string())?;
        selection.validate_at(now)?;
        let work = origin
            .checked_add(Duration::from_millis(selection.work_deadline_unix_ms - now))
            .ok_or_else(|| "diagnostic work cutoff overflowed".to_owned())?
            .min(origin + Duration::from_secs(30));
        let cleanup = origin
            .checked_add(Duration::from_millis(
                selection.cleanup_deadline_unix_ms - now,
            ))
            .ok_or_else(|| "diagnostic cleanup cutoff overflowed".to_owned())?
            .min(origin + Duration::from_secs(60));
        Ok(Rc::new(Self {
            selection: selection.clone(),
            work,
            cleanup,
            observation: RefCell::new(None),
            comparison_started: Cell::new(false),
            detached_console: Cell::new(false),
            baseline_plan: RefCell::new(None),
            comparison: RefCell::new(None),
            variant_observation: RefCell::new(None),
            active_console_plan: RefCell::new(None),
        }))
    }
}

thread_local! {
    static ACTIVE: RefCell<Option<Rc<Execution>>> = const { RefCell::new(None) };
}

pub(super) struct Scope {
    _thread: PhantomData<Rc<()>>,
}

impl Scope {
    pub(super) fn enter(execution: Rc<Execution>) -> Result<Self, String> {
        ACTIVE.with(|active| {
            let mut active = active.borrow_mut();
            if active.is_some() {
                return Err("nested loader diagnostic execution is refused".into());
            }
            *active = Some(execution);
            Ok(Self {
                _thread: PhantomData,
            })
        })
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        ACTIVE.with(|active| {
            active.borrow_mut().take();
        });
    }
}

pub(super) fn current() -> Option<Rc<Execution>> {
    ACTIVE.with(|active| active.borrow().clone())
}

pub(super) fn work_cutoff(fallback: Instant) -> Instant {
    current().map_or(fallback, |execution| fallback.min(execution.work))
}

pub(super) fn cleanup_cutoff(fallback: Instant) -> Instant {
    current().map_or(fallback, |execution| fallback.min(execution.cleanup))
}
