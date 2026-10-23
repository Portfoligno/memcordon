//! Invocation-local cache decisions. No workflow result or restored completion is input.
use crate::{
    CiError, Result,
    cache::{CacheEntry, OptionalCache},
    cache_snapshot::{self, SnapshotKind, TransferSelection},
    download_cache::{self, DownloadFamily},
    work_outcome::{WorkOutcome, WriterSettlement},
};
use std::path::Path;
use std::time::{Duration, Instant};

pub const OPTIONAL_CACHE_BUDGET: Duration = Duration::from_secs(10 * 60);

pub struct OptionalBudget {
    remaining: Duration,
}

impl Default for OptionalBudget {
    fn default() -> Self {
        Self {
            remaining: OPTIONAL_CACHE_BUDGET,
        }
    }
}

impl OptionalBudget {
    pub fn run<T>(&mut self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        let started = Instant::now();
        let result = crate::preparation::with_operation(
            crate::failure_mode::FailureMode::CollectAll,
            started + self.remaining,
            operation,
        );
        self.remaining = self.remaining.saturating_sub(started.elapsed());
        result
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionDecision {
    None,
    Complete,
    Partial,
}

pub fn compilation_retention(
    eligible: bool,
    unchanged: bool,
    payload: bool,
    writers: WriterSettlement,
    complete: bool,
) -> RetentionDecision {
    if !eligible
        || !unchanged
        || !payload
        || !writers.permits_reading()
        || (complete && writers != WriterSettlement::Settled)
    {
        RetentionDecision::None
    } else if complete {
        RetentionDecision::Complete
    } else {
        RetentionDecision::Partial
    }
}

pub fn write_event() -> bool {
    write_event_for(
        std::env::var("GITHUB_EVENT_NAME").ok().as_deref(),
        std::env::var("GITHUB_REF").ok().as_deref(),
    )
}

pub fn write_event_for(event: Option<&str>, reference: Option<&str>) -> bool {
    let Some(reference) = reference else {
        return false;
    };
    let branch = reference
        .strip_prefix("refs/heads/")
        .is_some_and(|name| !name.is_empty());
    let tag = reference
        .strip_prefix("refs/tags/")
        .is_some_and(|name| !name.is_empty());
    match event {
        Some("push") => branch || tag,
        Some("workflow_dispatch") => branch,
        _ => false,
    }
}

fn unsafe_cache(error: &CiError) -> bool {
    cache_safety_error(error) || crate::work_outcome::has_unresolved_owner(error)
}

pub fn cache_safety_error(error: &CiError) -> bool {
    match error {
        CiError::CacheSafety(_) => true,
        CiError::OwnedWork { source, .. } => cache_safety_error(source),
        CiError::LaneFailures { primary, secondary } => {
            cache_safety_error(primary) || cache_safety_error(secondary)
        }
        _ => false,
    }
}

fn remember(slot: &mut Option<CiError>, error: CiError) {
    *slot = Some(match slot.take() {
        None => error,
        Some(primary) => CiError::LaneFailures {
            primary: Box::new(primary),
            secondary: Box::new(error),
        },
    });
}

fn available(value: &OptionalCache) -> Option<&CacheEntry> {
    match value {
        OptionalCache::Available { entry } => Some(entry),
        _ => None,
    }
}

fn emit(mut values: Vec<(String, String)>) -> Result<()> {
    // A partial append must not publish readiness before its key/path records.
    values.sort_by_key(|(key, _)| key.ends_with("-save") || key.ends_with("-restore"));
    crate::workflow_output::write(
        &values
            .iter()
            .map(|(key, value)| (key.as_str(), value.clone()))
            .collect::<Vec<_>>(),
    )
}

pub fn transfer_outputs(
    root: &Path,
    slot: &str,
    transfer: Option<cache_snapshot::Transfer>,
) -> Result<()> {
    let (ready, key, path) = match transfer {
        Some(value) => (
            true,
            value.key,
            crate::workflow_output::workspace_action_path(root, &value.path)?,
        ),
        None => (false, String::new(), String::new()),
    };
    emit(vec![
        (format!("{slot}-save"), ready.to_string()),
        (format!("{slot}-key"), key),
        (format!("{slot}-path"), path),
    ])
}

fn request_outputs(
    root: &Path,
    slot: &str,
    request: Result<cache_snapshot::TransferRequest>,
) -> Result<()> {
    let request = match request {
        Ok(value) => Some(value),
        Err(error) if unsafe_cache(&error) => return Err(error),
        Err(error) => {
            eprintln!("optional cache request unavailable: {error}");
            None
        }
    };
    emit(vec![
        (format!("{slot}-restore"), request.is_some().to_string()),
        (
            format!("{slot}-key"),
            request
                .as_ref()
                .map_or_else(String::new, |value| value.key.clone()),
        ),
        (
            format!("{slot}-prefix"),
            request
                .as_ref()
                .map_or_else(String::new, |value| value.prefix.clone()),
        ),
        (
            format!("{slot}-path"),
            request
                .map(|value| crate::workflow_output::workspace_action_path(root, &value.path))
                .transpose()?
                .unwrap_or_default(),
        ),
    ])
}

#[derive(Clone, Copy)]
pub struct CompiledScope<'a> {
    pub slot: &'static str,
    pub selection: TransferSelection<'a>,
    pub completion: &'static str,
}

pub fn requests(root: &Path, scopes: &[CompiledScope<'_>], family: DownloadFamily) -> Result<()> {
    crate::preparation::with_operation(
        crate::failure_mode::FailureMode::CollectAll,
        Instant::now() + Duration::from_secs(240),
        || requests_inner(root, scopes, family),
    )
}

fn requests_inner(root: &Path, scopes: &[CompiledScope<'_>], family: DownloadFamily) -> Result<()> {
    let mut first = source_requests(root, family).err();
    // Source-only outputs are published before any unrelated compiler probe.
    for scope in scopes {
        if scope.selection.kind == SnapshotKind::ToolBuild {
            let family = DownloadFamily::for_purpose(scope.selection.purpose);
            if let Err(error) = optional_direct_request(
                &format!("{}-source", scope.slot),
                download_cache::context(root, family).map(|value| available(&value).cloned()),
            ) {
                remember(&mut first, error);
            }
        }
    }
    for scope in scopes {
        if scope.selection.kind == SnapshotKind::ToolBuild {
            let context = crate::cache::context(root, scope.selection.purpose, "complete", &[]);
            if let Err(error) = optional_direct_request(
                &format!("{}-image", scope.slot),
                context.map(|context| context.entries.get("tool").and_then(available).cloned()),
            ) {
                remember(&mut first, error);
            }
        }
        for (complete, class) in [(true, "complete"), (false, "partial")] {
            if let Err(error) = request_outputs(
                root,
                &format!("{}-{class}", scope.slot),
                cache_snapshot::transfer_request(root, scope.selection, complete),
            ) {
                remember(&mut first, error);
            }
        }
    }
    first.map_or(Ok(()), Err)
}

fn source_requests(root: &Path, family: DownloadFamily) -> Result<()> {
    let mut first = None;
    for (slot, kind) in [
        ("archives-partial", SnapshotKind::RegistryArchives),
        ("index-partial", SnapshotKind::RegistryIndex),
    ] {
        if let Err(error) = request_outputs(root, slot, cache_snapshot::source_request(root, kind))
        {
            remember(&mut first, error);
        }
    }
    let source = download_cache::context(root, family);
    if let Err(error) =
        optional_direct_request("source", source.map(|value| available(&value).cloned()))
    {
        remember(&mut first, error);
    }
    first.map_or(Ok(()), Err)
}

fn direct_request(slot: &str, entry: Option<&CacheEntry>) -> Result<()> {
    emit(vec![
        (format!("{slot}-restore"), entry.is_some().to_string()),
        (
            format!("{slot}-key"),
            entry.map_or_else(String::new, |entry| entry.exact_key.clone()),
        ),
        (
            format!("{slot}-prefix"),
            entry
                .and_then(|entry| entry.restore_prefix.clone())
                .unwrap_or_default(),
        ),
        (
            format!("{slot}-path"),
            entry
                .map(|entry| crate::workflow_output::action_paths(&entry.paths))
                .transpose()?
                .unwrap_or_default(),
        ),
    ])
}

fn optional_direct_request(slot: &str, result: Result<Option<CacheEntry>>) -> Result<()> {
    match result {
        Ok(entry) => direct_request(slot, entry.as_ref()),
        Err(error) if unsafe_cache(&error) => Err(error),
        Err(error) => {
            eprintln!("optional direct cache request unavailable: {error}");
            direct_request(slot, None)
        }
    }
}

pub struct SourceSession {
    family: DownloadFamily,
    before: Result<OptionalCache>,
    slot: &'static str,
    partial: bool,
}

impl SourceSession {
    pub fn blocks_work(&self) -> bool {
        self.before.as_ref().err().is_some_and(unsafe_cache)
    }

    pub fn begin(root: &Path, family: DownloadFamily) -> Self {
        Self {
            family,
            before: download_cache::context(root, family),
            slot: "source",
            partial: true,
        }
    }

    fn tool(root: &Path, family: DownloadFamily, slot: &'static str) -> Self {
        Self {
            family,
            before: download_cache::context(root, family),
            slot,
            partial: false,
        }
    }

    /// All source outputs are attempted independently; callers preserve primary work failure.
    pub fn finish<T>(self, root: &Path, outcome: &WorkOutcome<T>) -> Result<()> {
        if self.blocks_work() || !outcome.writers().permits_reading() {
            let mut first = match self.before {
                Err(error) if unsafe_cache(&error) => Some(error),
                _ => None,
            };
            if let Err(error) = emit(vec![(
                format!("{}-complete-save", self.slot),
                "false".into(),
            )]) {
                remember(&mut first, error);
            }
            if self.partial {
                for slot in ["archives-partial", "index-partial"] {
                    if let Err(error) = transfer_outputs(root, slot, None) {
                        remember(&mut first, error);
                    }
                }
            }
            return first.map_or(Ok(()), Err);
        }
        let after = download_cache::context(root, self.family);
        if after.as_ref().err().is_some_and(unsafe_cache) {
            let blocked = WorkOutcome::observed(Ok(()), WriterSettlement::Unknown);
            let outputs = self.finish(root, &blocked);
            return WorkOutcome::from_result(after.map(|_| ()))
                .post_finalization(outputs)
                .into_result();
        }
        let readers_settled = !self.before.as_ref().err().is_some_and(unsafe_cache)
            && !after.as_ref().err().is_some_and(unsafe_cache);
        let same = self
            .before
            .as_ref()
            .ok()
            .and_then(available)
            .zip(after.as_ref().ok().and_then(available))
            .filter(|(before, after)| {
                before.exact_key == after.exact_key && before.paths == after.paths
            });
        let mut first = None;
        let complete = if write_event() && readers_settled && outcome.writers().permits_reading() {
            same.filter(|(_, entry)| {
                download_cache::populated_key(self.family).as_deref()
                    == Some(entry.exact_key.as_str())
            })
            .map(|(_, entry)| entry)
        } else {
            None
        };
        let result = (|| {
            let _locks = if complete.is_some() {
                cache_snapshot::source_read_locks(root)?
            } else {
                Vec::new()
            };
            if let Some(entry) = complete {
                for path in &entry.paths {
                    cache_snapshot::ordinary(path)?;
                }
            }
            emit(vec![
                (
                    format!("{}-complete-save", self.slot),
                    complete.is_some().to_string(),
                ),
                (
                    format!("{}-complete-key", self.slot),
                    complete.map_or_else(String::new, |e| e.exact_key.clone()),
                ),
                (
                    format!("{}-complete-path", self.slot),
                    complete
                        .map(|entry| crate::workflow_output::action_paths(&entry.paths))
                        .transpose()?
                        .unwrap_or_default(),
                ),
            ])
        })();
        let complete_offered = complete.is_some() && result.is_ok();
        if let Err(error) = result {
            remember(&mut first, error);
        }
        for (slot, kind) in [
            ("archives-partial", SnapshotKind::RegistryArchives),
            ("index-partial", SnapshotKind::RegistryIndex),
        ] {
            if !self.partial {
                continue;
            }
            let transfer = if !(kind == SnapshotKind::RegistryArchives && complete_offered)
                && write_event()
                && readers_settled
                && outcome.writers().permits_reading()
            {
                match cache_snapshot::stage_source(root, kind) {
                    Ok(value) => Some(value),
                    Err(error) => {
                        if unsafe_cache(&error) {
                            remember(&mut first, error);
                        } else {
                            eprintln!("optional source snapshot unavailable: {error}");
                        }
                        None
                    }
                }
            } else {
                None
            };
            if let Err(error) = transfer_outputs(root, slot, transfer) {
                remember(&mut first, error);
            }
        }
        if let Err(error) = self.before
            && unsafe_cache(&error)
        {
            remember(&mut first, error);
        }
        if let Err(error) = after
            && unsafe_cache(&error)
        {
            remember(&mut first, error);
        }
        first.map_or(Ok(()), Err)
    }
}

pub struct Session<'a> {
    scopes: Vec<(CompiledScope<'a>, Option<String>)>,
    source: Option<SourceSession>,
    tool_sources: Vec<SourceSession>,
    images: Vec<(&'static str, &'a str, Option<CacheEntry>)>,
    setup_error: Option<CiError>,
    source_not_started: bool,
    cache_remaining: Duration,
    scope_writers: std::collections::BTreeMap<&'static str, WriterSettlement>,
}

fn input(root: &Path, selection: TransferSelection<'_>) -> Result<Option<String>> {
    let context = crate::cache::context_partition(
        root,
        selection.purpose,
        selection.shard,
        &[],
        selection.partition,
    )?;
    Ok(context
        .entries
        .get(if selection.kind == SnapshotKind::ToolBuild {
            "tool-build"
        } else {
            "product"
        })
        .and_then(available)
        .map(|entry| entry.exact_key.clone()))
}

impl<'a> Session<'a> {
    pub fn begin(
        root: &Path,
        scopes: Vec<CompiledScope<'a>>,
        family: DownloadFamily,
    ) -> Result<Self> {
        Self::begin_selected(root, scopes, family, true)
    }

    pub fn begin_selected(
        root: &Path,
        scopes: Vec<CompiledScope<'a>>,
        family: DownloadFamily,
        retain_sources: bool,
    ) -> Result<Self> {
        Self::begin_selected_restoring(root, scopes, family, retain_sources, true)
    }

    pub fn begin_selected_restoring(
        root: &Path,
        scopes: Vec<CompiledScope<'a>>,
        family: DownloadFamily,
        retain_sources: bool,
        restore_inputs: bool,
    ) -> Result<Self> {
        let started = Instant::now();
        let mut session = crate::preparation::with_operation(
            crate::failure_mode::FailureMode::CollectAll,
            started + OPTIONAL_CACHE_BUDGET,
            || Self::begin_inner(root, scopes, family, retain_sources, restore_inputs),
        )?;
        session.cache_remaining = OPTIONAL_CACHE_BUDGET.saturating_sub(started.elapsed());
        Ok(session)
    }

    fn begin_inner(
        root: &Path,
        scopes: Vec<CompiledScope<'a>>,
        family: DownloadFamily,
        retain_sources: bool,
        restore_inputs: bool,
    ) -> Result<Self> {
        let source = retain_sources.then(|| SourceSession::begin(root, family));
        let mut tool_sources = Vec::new();
        let mut images = Vec::new();
        let mut setup_error = None;
        let mut source_safe = true;
        if source.as_ref().is_some_and(SourceSession::blocks_work) {
            source_safe = false;
            setup_error = Some(CiError::Message(
                "source admission refused further work".into(),
            ));
        }
        for kind in [SnapshotKind::RegistryArchives, SnapshotKind::RegistryIndex] {
            if !retain_sources || setup_error.is_some() {
                continue;
            }
            if let Err(error) = cache_snapshot::import_source(root, kind) {
                source_safe = false;
                setup_error = Some(error);
                break;
            }
        }
        let mut selected = Vec::new();
        let setup = (|| -> Result<()> {
            for scope in scopes {
                if setup_error.is_some() {
                    break;
                }
                if scope.selection.kind == SnapshotKind::ToolBuild {
                    let (family, slot) = match scope.selection.purpose {
                        "cargo-audit" => (DownloadFamily::ToolCargoAudit, "cargo-audit-source"),
                        "cargo-deny" => (DownloadFamily::ToolCargoDeny, "cargo-deny-source"),
                        "cargo-fuzz" => (DownloadFamily::ToolCargoFuzz, "cargo-fuzz-source"),
                        _ => return Err(CiError::Message("unknown tool source scope".into())),
                    };
                    tool_sources.push(SourceSession::tool(root, family, slot));
                    if tool_sources.last().is_some_and(SourceSession::blocks_work) {
                        return Err(CiError::Message(
                            "tool source admission refused further work".into(),
                        ));
                    }
                    let context =
                        crate::cache::context(root, scope.selection.purpose, "complete", &[])?;
                    images.push((
                        scope.slot,
                        scope.selection.purpose,
                        context.entries.get("tool").and_then(available).cloned(),
                    ));
                }
                let before = input(root, scope.selection)?;
                if restore_inputs && before.is_some() {
                    cache_snapshot::import_transfer(root, scope.selection)?;
                }
                selected.push((scope, before));
            }
            Ok(())
        })();
        if let Err(error) = setup {
            setup_error = Some(error);
        }
        let source_not_started = source_safe && setup_error.is_some();
        Ok(Self {
            scopes: selected,
            source,
            tool_sources,
            images,
            setup_error,
            source_not_started,
            cache_remaining: Duration::ZERO,
            scope_writers: Default::default(),
        })
    }

    pub fn execute(self, root: &Path, operation: impl FnOnce() -> Result<()>) -> Result<()> {
        self.execute_with(root, |_| operation())
    }

    /// Root-specific ownership from the actual compiler pair. Shared source
    /// retention still receives the conjunction through the aggregate result.
    pub fn execute_pair(
        self,
        root: &Path,
        first_slots: &[&str],
        operation: impl FnOnce() -> Result<crate::preparation::PairOutcome<(), ()>>,
    ) -> Result<()> {
        self.execute_with(root, |session| {
            let pair = operation()?;
            for (scope, _) in &session.scopes {
                session.scope_writers.insert(
                    scope.slot,
                    if first_slots.contains(&scope.slot) {
                        pair.first.writers()
                    } else {
                        pair.second.writers()
                    },
                );
            }
            pair.into_result()
        })
    }

    pub fn optional<T>(&mut self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        let started = Instant::now();
        let result = crate::preparation::with_operation(
            crate::failure_mode::FailureMode::CollectAll,
            started + self.cache_remaining,
            operation,
        );
        self.cache_remaining = self.cache_remaining.saturating_sub(started.elapsed());
        result
    }

    /// Record only a writer observed for a root admitted by this live session.
    pub fn record_scope_writers(
        &mut self,
        slot: &'static str,
        writers: WriterSettlement,
    ) -> Result<()> {
        if !self.scopes.iter().any(|(scope, _)| scope.slot == slot) {
            return Err(CiError::Message("writer scope was not admitted".into()));
        }
        self.scope_writers.insert(slot, writers);
        Ok(())
    }

    pub fn execute_with(
        mut self,
        root: &Path,
        operation: impl FnOnce(&mut Self) -> Result<()>,
    ) -> Result<()> {
        if self.source.as_ref().is_some_and(SourceSession::blocks_work)
            || self.tool_sources.iter().any(SourceSession::blocks_work)
        {
            remember(
                &mut self.setup_error,
                CiError::Message("source admission refused further work".into()),
            );
        }
        let result = match self.setup_error.take() {
            Some(error) => Err(error),
            None => operation(&mut self),
        };
        self.finish(root, WorkOutcome::from_result(result))
    }

    pub fn finish(self, root: &Path, outcome: WorkOutcome<()>) -> Result<()> {
        if !outcome.is_ok() {
            eprintln!(
                "[ci segment] required work failed; writer-settlement={:?}; attempting independent retention",
                outcome.writers()
            );
        }
        if self.scope_writers.is_empty()
            && ((!self.source_not_started && !outcome.writers().permits_reading())
                || self.source.as_ref().is_some_and(SourceSession::blocks_work)
                || self.tool_sources.iter().any(SourceSession::blocks_work))
        {
            let blocked = WorkOutcome::observed(Ok(()), WriterSettlement::Unknown);
            let mut failure = None;
            for source in self.source.into_iter().chain(self.tool_sources) {
                if let Err(error) = source.finish(root, &blocked) {
                    remember(&mut failure, error);
                }
            }
            return outcome
                .post_finalization(failure.map_or(Ok(()), Err))
                .into_result();
        }
        // Work time was outside this optional envelope. Original work deadlines
        // are unchanged; exhausted retention never invents a completed transfer.
        let deadline = Instant::now() + self.cache_remaining;
        if self.cache_remaining <= Duration::from_secs(10)
            && !self.source.as_ref().is_some_and(SourceSession::blocks_work)
            && !self.tool_sources.iter().any(SourceSession::blocks_work)
        {
            return outcome.into_result();
        }
        crate::preparation::with_finalization(deadline, || self.finish_inner(root, outcome))
    }

    fn finish_inner(self, root: &Path, outcome: WorkOutcome<()>) -> Result<()> {
        let mut failure = None;
        let source_unstarted = WorkOutcome::observed(Ok(()), WriterSettlement::NotStarted);
        let source_outcome = if self.source_not_started {
            &source_unstarted
        } else {
            &outcome
        };
        // Independent source retention is not contingent on compiler probes.
        if let Some(source) = self.source
            && let Err(error) = source.finish(root, source_outcome)
        {
            remember(&mut failure, error);
        }
        if self.scope_writers.is_empty() && failure.as_ref().is_some_and(unsafe_cache) {
            return outcome
                .post_finalization(failure.map_or(Ok(()), Err))
                .into_result();
        }
        for source in self.tool_sources {
            if let Err(error) = source.finish(root, source_outcome) {
                remember(&mut failure, error);
            }
            if self.scope_writers.is_empty() && failure.as_ref().is_some_and(unsafe_cache) {
                return outcome
                    .post_finalization(failure.map_or(Ok(()), Err))
                    .into_result();
            }
        }
        if self.scope_writers.is_empty()
            && (!outcome.writers().permits_reading() || failure.as_ref().is_some_and(unsafe_cache))
        {
            return outcome
                .post_finalization(failure.map_or(Ok(()), Err))
                .into_result();
        }
        for (slot, purpose, before) in self.images {
            let writers = self
                .scope_writers
                .get(slot)
                .copied()
                .unwrap_or(outcome.writers());
            if !writers.permits_reading() {
                continue;
            }
            if self.scope_writers.is_empty() && failure.as_ref().is_some_and(unsafe_cache) {
                continue;
            }
            let current = crate::cache::context(root, purpose, "complete", &[]);
            if current.as_ref().err().is_some_and(unsafe_cache) {
                if let Err(error) = current {
                    remember(&mut failure, error);
                }
                continue;
            }
            let ready_fact = match purpose {
                "cargo-audit" => "tool-cargo-audit-ready",
                "cargo-deny" => "tool-cargo-deny-ready",
                "cargo-fuzz" => "tool-cargo-fuzz-ready",
                _ => unreachable!(),
            };
            let entry = before
                .as_ref()
                .zip(
                    current
                        .as_ref()
                        .ok()
                        .and_then(|context| context.entries.get("tool"))
                        .and_then(available),
                )
                .filter(|(before, after)| {
                    before.exact_key == after.exact_key && before.paths == after.paths
                })
                .filter(|_| {
                    write_event()
                        && writers.permits_reading()
                        && crate::workflow_output::compiled_in_invocation(ready_fact)
                })
                .map(|(_, entry)| entry);
            let result = (|| {
                if let Some(entry) = entry {
                    for path in &entry.paths {
                        cache_snapshot::ordinary(path)?;
                        if !std::fs::metadata(path)?.is_file() {
                            return Err(CiError::CacheSafety(Box::new(CiError::Message(
                                "tool image is not regular".into(),
                            ))));
                        }
                    }
                }
                emit(vec![
                    (format!("{slot}-image-save"), entry.is_some().to_string()),
                    (
                        format!("{slot}-image-key"),
                        entry.map_or_else(String::new, |e| e.exact_key.clone()),
                    ),
                    (
                        format!("{slot}-image-path"),
                        entry
                            .map(|entry| crate::workflow_output::action_paths(&entry.paths))
                            .transpose()?
                            .unwrap_or_default(),
                    ),
                ])
            })();
            if let Err(error) = result {
                remember(&mut failure, error);
            }
            if let Err(error) = current
                && unsafe_cache(&error)
            {
                remember(&mut failure, error);
            }
        }
        let mut pending = Vec::new();
        for (scope, before) in self.scopes {
            let writers = self
                .scope_writers
                .get(scope.slot)
                .copied()
                .unwrap_or(outcome.writers());
            if !writers.permits_reading() {
                pending.push((scope, RetentionDecision::None));
                continue;
            }
            let after = input(root, scope.selection);
            if after.as_ref().err().is_some_and(unsafe_cache) {
                if let Err(error) = after {
                    remember(&mut failure, error);
                }
                continue;
            }
            let unchanged = before
                .as_ref()
                .zip(after.as_ref().ok().and_then(|value| value.as_ref()))
                .is_some_and(|(a, b)| a == b);
            let complete = crate::workflow_output::compiled_in_invocation(scope.completion);
            let decision = compilation_retention(write_event(), unchanged, true, writers, complete);
            pending.push((scope, decision));
            if let Err(error) = after
                && unsafe_cache(&error)
            {
                remember(&mut failure, error);
            }
        }
        for pair in pending.chunks(2) {
            let selected = |index: usize| {
                pair.get(index)
                    .and_then(|(scope, decision)| match decision {
                        RetentionDecision::None => None,
                        RetentionDecision::Complete => Some((scope.selection, true)),
                        RetentionDecision::Partial => Some((scope.selection, false)),
                    })
            };
            let transfers = cache_snapshot::stage_transfer_pair(root, selected(0), selected(1));
            for ((scope, decision), transfer) in pair.iter().zip(transfers) {
                let transfer = match transfer {
                    Ok(value) => value,
                    Err(error) => {
                        if unsafe_cache(&error) {
                            remember(&mut failure, error);
                        } else {
                            eprintln!("optional compiler snapshot unavailable: {error}");
                        }
                        None
                    }
                };
                let mut transfer = transfer;
                for (class, chosen) in [
                    ("complete", *decision == RetentionDecision::Complete),
                    ("partial", *decision == RetentionDecision::Partial),
                ] {
                    if let Err(error) = transfer_outputs(
                        root,
                        &format!("{}-{class}", scope.slot),
                        if chosen { transfer.take() } else { None },
                    ) {
                        remember(&mut failure, error);
                    }
                }
            }
        }
        outcome
            .post_finalization(failure.map_or(Ok(()), Err))
            .into_result()
    }
}

pub fn cleanup(root: &Path, scopes: &[CompiledScope<'_>]) -> Result<()> {
    let mut first = None;
    for scope in scopes {
        if let Err(error) = cache_snapshot::cleanup_transfers(root, scope.selection) {
            remember(&mut first, error);
        }
    }
    if let Err(error) = cache_snapshot::cleanup_source(root) {
        remember(&mut first, error);
    }
    first.map_or(Ok(()), Err)
}
