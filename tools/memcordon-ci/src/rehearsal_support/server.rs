//! Disposable HTTP/1 fixture. Received bytes, not expected input paths, back all objects.
use super::{protocol::*, wire};
use crate::{CiError, Result};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{
    Request, Response,
    body::{Body, Bytes, Frame, Incoming, SizeHint},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, BufRead, Read, Seek, SeekFrom, Write},
    net::{Ipv4Addr, SocketAddrV4},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::{Instant, timeout_at},
};

type ResponseBody = BoxBody<Bytes, io::Error>;
struct Shared {
    setup: Setup,
    root: PathBuf,
    record: FixtureRecord,
    snapshot: Mutex<Snapshot>,
    reads: Arc<Semaphore>,
    writes: Arc<Semaphore>,
    resume: Semaphore,
    stop: Notify,
    active_reads: AtomicU32,
    active_writes: AtomicU32,
    active_connections: AtomicU32,
    next_request: AtomicU64,
    deadline: Instant,
    maximum: u64,
    quota: u64,
}
fn invalid(message: &str) -> CiError {
    CiError::Message(message.into())
}
fn transport_error(message: &str) -> io::Error {
    io::Error::other(message)
}
fn unix_ms() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid("fixture clock precedes epoch"))?
            .as_millis(),
    )
    .map_err(|_| invalid("fixture clock overflow"))
}

pub fn serve(case_id: &str, state: &Path, ready: &Path) -> Result<()> {
    let bytes = bounded_file(&state.join("setup.json"), 1024 * 1024)?;
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).map_err(CiError::Message)?;
    let setup: Setup = serde_json::from_slice(&bytes)?;
    if setup.revision != REVISION
        || setup.case_id != case_id
        || setup.selection.files.is_empty()
        || setup.selection.files.len() > 128
    {
        return Err(invalid("fixture setup identity differs"));
    }
    let mut names = std::collections::BTreeSet::new();
    let mut quota = 0_u64;
    let mut maximum = 0_u64;
    for file in &setup.selection.files {
        crate::release::artifacts::safe_basename(&file.name)?;
        if !names.insert(&file.name)
            || file.sha256.len() != Sha256::output_size() * 2
            || !file.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid("fixture inventory malformed"));
        }
        quota = quota
            .checked_add(file.size)
            .and_then(|total| total.checked_add(if file.package.is_some() { file.size } else { 0 }))
            .ok_or_else(|| invalid("fixture quota overflow"))?;
        maximum = maximum.max(file.size);
    }
    if setup.selection.repository.split('/').count() != 2
        || crate::release::source::validate_oid(&setup.selection.commit).is_err()
        || semver::Version::parse(&setup.selection.version).is_err()
    {
        return Err(invalid("fixture selection malformed"));
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime.block_on(run(setup, state, ready, maximum, quota))
}
async fn run(setup: Setup, state: &Path, ready: &Path, maximum: u64, quota: u64) -> Result<()> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await?;
    let address = match listener.local_addr()? {
        std::net::SocketAddr::V4(address) => address,
        _ => return Err(invalid("fixture listener is not IPv4")),
    };
    let now = unix_ms()?;
    let expires = now
        .checked_add(setup.budget.seconds() * 1000)
        .ok_or_else(|| invalid("fixture deadline overflow"))?
        .min(setup.work_unix_ms);
    if expires <= now {
        return Err(invalid("fixture work cutoff already elapsed"));
    }
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random).map_err(|_| invalid("fixture session generation failed"))?;
    let record = FixtureRecord {
        revision: REVISION,
        address,
        session: hex::encode(random),
        budget: setup.budget,
        expires_unix_ms: expires,
    };
    let mut snapshot = if state.join("snapshot.json").exists() {
        read_snapshot(state)?
    } else {
        Snapshot::default()
    };
    snapshot.fault_reached = false;
    snapshot.fault_boundary = None;
    apply_seed_fault(&setup, state, &mut snapshot)?;
    fs::create_dir_all(state.join("objects"))?;
    let shared = Arc::new(Shared {
        setup,
        root: state.into(),
        record: record.clone(),
        snapshot: Mutex::new(snapshot),
        reads: Arc::new(Semaphore::new(4)),
        writes: Arc::new(Semaphore::new(1)),
        resume: Semaphore::new(0),
        stop: Notify::new(),
        active_reads: AtomicU32::new(0),
        active_writes: AtomicU32::new(0),
        active_connections: AtomicU32::new(0),
        next_request: AtomicU64::new(0),
        deadline: Instant::now() + Duration::from_millis(expires - now),
        maximum,
        quota,
    });
    save(&shared, &*shared.snapshot.lock().await)?;
    let mut ready_file = File::options().write(true).create_new(true).open(ready)?;
    serde_json::to_writer(&mut ready_file, &record)?;
    ready_file.write_all(b"\n")?;
    ready_file.flush()?;
    ready_file.sync_all()?;
    let control = shared.clone();
    std::thread::spawn(move || {
        let input = io::stdin();
        let mut reader = input.lock();
        while let Ok(Some(line)) = control_line(&mut reader) {
            match line.as_slice() {
                b"continue\n" => control.resume.add_permits(1),
                b"stop\n" => {
                    control.stop.notify_one();
                    break;
                }
                _ => {
                    control.stop.notify_one();
                    break;
                }
            }
        }
        control.stop.notify_one();
    });
    let connections = Arc::new(Semaphore::new(8));
    let mut tasks = JoinSet::new();
    loop {
        let permit = tokio::select! {permit=connections.clone().acquire_owned()=>permit.map_err(|_|invalid("fixture connection admission closed"))?,_ = shared.stop.notified()=>break,_ = tokio::time::sleep_until(shared.deadline)=>break};
        let accepted = tokio::select! {accepted=listener.accept()=>accepted?,_ = shared.stop.notified()=>break,_ = tokio::time::sleep_until(shared.deadline)=>break};
        let owner = shared.clone();
        let current = owner.active_connections.fetch_add(1, Ordering::SeqCst) + 1;
        {
            let mut snapshot = owner.snapshot.lock().await;
            snapshot.max_active_connections = snapshot.max_active_connections.max(current);
            save(&owner, &snapshot)?;
        }
        tasks.spawn(async move {
            let connection_owner = owner.clone();
            let service = service_fn(move |request| handle(request, owner.clone()));
            let mut builder = http1::Builder::new();
            builder
                .max_buf_size(32 * 1024)
                .max_headers(64)
                .header_read_timeout(Duration::from_secs(10))
                .timer(TokioTimer::new())
                .keep_alive(false);
            let _ = timeout_at(
                connection_owner.deadline,
                builder.serve_connection(TokioIo::new(accepted.0), service),
            )
            .await;
            connection_owner
                .active_connections
                .fetch_sub(1, Ordering::SeqCst);
            drop(permit);
        });
        while tasks.try_join_next().is_some() {}
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    save(&shared, &*shared.snapshot.lock().await)?;
    Ok(())
}
fn control_line(reader: &mut impl BufRead) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(transport_error("fixture control truncated"))
            };
        }
        let size = buffer
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(buffer.len(), |position| position + 1);
        if line
            .len()
            .checked_add(size)
            .is_none_or(|length| length > 32)
        {
            return Err(transport_error("fixture control byte bound exceeded"));
        }
        line.extend_from_slice(&buffer[..size]);
        reader.consume(size);
        if line.last() == Some(&b'\n') {
            return Ok(Some(line));
        }
    }
}

pub fn read_snapshot(root: &Path) -> Result<Snapshot> {
    let bytes = bounded_file(&root.join("snapshot.json"), 4 * 1024 * 1024)?;
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).map_err(CiError::Message)?;
    Ok(serde_json::from_slice(&bytes)?)
}
fn bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    if file.metadata()?.len() > maximum {
        return Err(invalid("fixture file byte bound exceeded"));
    }
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(invalid("fixture file byte bound exceeded"));
    }
    Ok(bytes)
}
fn save(shared: &Shared, snapshot: &Snapshot) -> Result<()> {
    let bytes = serde_json::to_vec(snapshot)?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(invalid("fixture request trace bound exceeded"));
    }
    let temporary = shared.root.join("snapshot.incomplete");
    let mut file = File::create(&temporary)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.flush()?;
    file.sync_all()?;
    fs::rename(temporary, shared.root.join("snapshot.json"))?;
    Ok(())
}
fn apply_seed_fault(setup: &Setup, root: &Path, snapshot: &mut Snapshot) -> Result<()> {
    match &setup.fault {
        Fault::ConflictAsset => {
            let asset = snapshot
                .assets
                .first_mut()
                .ok_or_else(|| invalid("asset conflict needs actual seeded state"))?;
            mutate_byte(&root.join(&asset.path))?;
            asset.sha256 = file_digest(&root.join(&asset.path))?;
            snapshot.fault_reached = true;
        }
        Fault::ConflictRegistry => {
            let package = snapshot
                .crates
                .first_mut()
                .ok_or_else(|| invalid("registry conflict needs actual seeded state"))?;
            mutate_byte(&root.join(&package.path))?;
            package.sha256 = file_digest(&root.join(&package.path))?;
            package.index["cksum"] = json!(package.sha256);
            snapshot.fault_reached = true;
        }
        Fault::Yanked => {
            let package = snapshot
                .crates
                .first_mut()
                .ok_or_else(|| invalid("yank conflict needs actual seeded state"))?;
            package.yanked = true;
            package.index["yanked"] = json!(true);
            snapshot.fault_reached = true;
        }
        Fault::MetadataDrift { field } => {
            let release = snapshot
                .release
                .as_mut()
                .ok_or_else(|| invalid("metadata drift needs actual seeded state"))?;
            match field {
                MetadataField::Notes => release.body.push_str("changed"),
                MetadataField::Tag => release.tag_name.push_str("changed"),
                MetadataField::Prerelease => release.prerelease = !release.prerelease,
            }
            snapshot.fault_reached = true;
        }
        _ => {}
    }
    Ok(())
}
fn mutate_byte(path: &Path) -> Result<()> {
    let mut file = File::options().read(true).write(true).open(path)?;
    let mut byte = [0];
    file.read_exact(&mut byte)?;
    byte[0] ^= 1;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&byte)?;
    file.sync_all()?;
    Ok(())
}
fn file_digest(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex::encode(digest.finalize()))
}

async fn handle(
    request: Request<Incoming>,
    shared: Arc<Shared>,
) -> std::result::Result<Response<ResponseBody>, io::Error> {
    timeout_at(shared.deadline, handle_inner(request, shared))
        .await
        .map_err(|_| transport_error("fixture case deadline elapsed"))?
        .map_err(|_| transport_error("fixture rejected request"))
}
async fn handle_inner(
    request: Request<Incoming>,
    shared: Arc<Shared>,
) -> Result<Response<ResponseBody>> {
    let service = request
        .headers()
        .get(SERVICE_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(FixtureService::parse)
        .ok_or_else(|| invalid("fixture service missing"))?;
    if request
        .headers()
        .get(SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        != Some(&shared.record.session)
    {
        return Err(invalid("fixture session differs"));
    }
    let method = request.method().as_str().to_owned();
    let write = matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE");
    let permit = if write {
        shared.writes.clone()
    } else {
        shared.reads.clone()
    }
    .acquire_owned()
    .await
    .map_err(|_| invalid("fixture request admission closed"))?;
    let current = if write {
        shared.active_writes.fetch_add(1, Ordering::SeqCst) + 1
    } else {
        shared.active_reads.fetch_add(1, Ordering::SeqCst) + 1
    };
    let admission = Admission {
        shared: shared.clone(),
        write,
        _permit: permit,
    };
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or("").to_owned();
    let authorization = request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok());
    let role = match authorization {
        None => "absent",
        Some(value) if value.strip_prefix("Bearer ") == Some(GITHUB_TOKEN) => "github",
        Some(REGISTRY_TOKEN) => "registry",
        _ => "incorrect",
    };
    let private = shared.setup.fault == Fault::Private;
    let valid_role = match service {
        FixtureService::GithubApi => role == "github" || (!write && !private && role == "absent"),
        FixtureService::GithubUpload => role == "github",
        FixtureService::RegistryUpload => role == "registry",
        _ => role == "absent",
    };
    {
        let mut snapshot = shared.snapshot.lock().await;
        if snapshot.requests.len() < 4096 {
            snapshot.requests.push(RequestObservation {
                method: method.clone(),
                service,
                path: path.clone(),
                credential_role: role.into(),
                body_len: 0,
            });
        } else {
            snapshot.omitted_requests += 1;
        }
        if write {
            snapshot.max_active_writes = snapshot.max_active_writes.max(current);
        } else {
            snapshot.max_active_reads = snapshot.max_active_reads.max(current);
        }
        if !valid_role {
            snapshot.credential_errors += 1;
        }
        save(&shared, &snapshot)?;
    }
    if !valid_role {
        return Ok(simple(403, b"credential role rejected"));
    }
    if !write && let Some(reply) = read_fault(&shared, service, &path, &query).await? {
        return Ok(reply);
    }
    let content_length = request
        .headers()
        .get("content-length")
        .map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or_else(|| invalid("fixture content length malformed"))
        })
        .transpose()?;
    let accept = request
        .headers()
        .get("accept")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let body_limit = if !write {
        0
    } else if service == FixtureService::RegistryUpload {
        shared
            .maximum
            .checked_add(4 * 1024 * 1024 + 2 * std::mem::size_of::<u32>() as u64)
            .ok_or_else(|| invalid("fixture wire bound overflow"))?
    } else if service == FixtureService::GithubUpload {
        shared.maximum
    } else {
        1024 * 1024
    };
    if content_length.is_some_and(|length| length > body_limit) {
        return Ok(simple(413, b"request body too large"));
    }
    let request_number = shared.next_request.fetch_add(1, Ordering::SeqCst);
    let incoming = shared.root.join(format!(
        "incoming-{}-{request_number}.incomplete",
        shared.record.session
    ));
    let body_len = match receive(request.into_body(), &incoming, content_length, body_limit).await {
        Ok(length) => length,
        Err(error) => {
            if incoming.exists() {
                fs::remove_file(&incoming)?;
            }
            return Err(error);
        }
    };
    {
        let mut snapshot = shared.snapshot.lock().await;
        if let Some(observation) = snapshot.requests.iter_mut().rev().find(|entry| {
            entry.method == method
                && entry.service == service
                && entry.path == path
                && entry.body_len == 0
        }) {
            observation.body_len = body_len;
        }
        snapshot.complete_requests += 1;
        save(&shared, &snapshot)?;
    }
    let result = route(
        &shared,
        service,
        RoutedRequest {
            method: &method,
            path: &path,
            query: &query,
            accept: &accept,
            incoming: &incoming,
            body_len,
        },
    )
    .await;
    if incoming.exists() {
        fs::remove_file(&incoming)?;
    }
    // File response owns the read admission until its last frame or cancellation.
    match result? {
        Routed::Reply(response) => {
            drop(admission);
            Ok(response)
        }
        Routed::File {
            path,
            corrupt,
            truncate,
        } => {
            let mut snapshot = shared.snapshot.lock().await;
            snapshot.body_downloads += 1;
            save(&shared, &snapshot)?;
            drop(snapshot);
            file_response(&path, corrupt, truncate, admission)
        }
    }
}
struct Admission {
    shared: Arc<Shared>,
    write: bool,
    _permit: OwnedSemaphorePermit,
}
impl Drop for Admission {
    fn drop(&mut self) {
        if self.write {
            self.shared.active_writes.fetch_sub(1, Ordering::SeqCst);
        } else {
            self.shared.active_reads.fetch_sub(1, Ordering::SeqCst);
        }
    }
}
async fn receive(
    mut body: Incoming,
    path: &Path,
    declared: Option<u64>,
    maximum: u64,
) -> Result<u64> {
    let mut file = File::options().write(true).create_new(true).open(path)?;
    let mut total = 0_u64;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| invalid("fixture body framing failed"))?;
        if let Ok(bytes) = frame.into_data() {
            total = total
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| invalid("fixture request body overflow"))?;
            if total > maximum || declared.is_some_and(|declared| total > declared) {
                return Err(invalid("fixture request body overlong"));
            }
            file.write_all(&bytes)?;
        }
    }
    if declared.is_some_and(|declared| declared != total) {
        return Err(invalid("fixture request body short"));
    }
    file.flush()?;
    file.sync_all()?;
    Ok(total)
}
enum Routed {
    Reply(Response<ResponseBody>),
    File {
        path: PathBuf,
        corrupt: bool,
        truncate: bool,
    },
}
fn simple(status: u16, bytes: &[u8]) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .body(
            Full::new(Bytes::copy_from_slice(bytes))
                .map_err(|never| match never {})
                .boxed(),
        )
        .expect("fixed response")
}
fn json_response(status: u16, value: &Value) -> Result<Response<ResponseBody>> {
    let mut response = simple(status, &serde_json::to_vec(value)?);
    response.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("application/json"),
    );
    Ok(response)
}
fn asset_json(asset: &AssetState) -> Value {
    json!({"id":asset.id,"name":asset.name,"size":asset.size,"digest":format!("sha256:{}",asset.sha256),"state":asset.state})
}
fn release_json(release: &ReleaseState, name: &str) -> Value {
    json!({"id":release.id,"name":name,"tag_name":release.tag_name,"body":release.body,"prerelease":release.prerelease,"draft":release.draft})
}
fn body_json(path: &Path) -> Result<Value> {
    let bytes = fs::read(path)?;
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).map_err(CiError::Message)?;
    Ok(serde_json::from_slice(&bytes)?)
}
fn page(query: &str) -> Result<usize> {
    let pairs = url::form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>();
    if pairs.iter().filter(|(key, _)| key == "page").count() > 1 {
        return Err(invalid("fixture duplicate page"));
    }
    pairs
        .iter()
        .find(|(key, _)| key == "page")
        .map_or(Ok(1), |(_, value)| {
            value.parse().map_err(|_| invalid("fixture page invalid"))
        })
}
fn selected_tail<'a>(shared: &Shared, path: &'a str) -> Result<Vec<&'a str>> {
    let parts: Vec<_> = path.trim_start_matches('/').split('/').collect();
    let repository: Vec<_> = shared.setup.selection.repository.split('/').collect();
    if parts.len() < 3 || parts[..3] != ["repos", repository[0], repository[1]] {
        return Err(invalid("fixture repository route differs"));
    }
    Ok(parts.into_iter().skip(3).collect())
}

async fn read_fault(
    shared: &Shared,
    service: FixtureService,
    path: &str,
    query: &str,
) -> Result<Option<Response<ResponseBody>>> {
    let mut snapshot = shared.snapshot.lock().await;
    match &shared.setup.fault {
        Fault::UnknownRead { kind, after_effect }
            if service == FixtureService::GithubApi
                && (!*after_effect || !snapshot.effects.is_empty())
                && path.ends_with("/releases") =>
        {
            snapshot.fault_reached = true;
            save(shared, &snapshot)?;
            let response = match kind {
                ReadFault::Forbidden => simple(403, b"unavailable"),
                ReadFault::ServerError => simple(500, b"unavailable"),
                ReadFault::MalformedJson => simple(200, b"{"),
                ReadFault::DuplicateKeys => simple(200, b"[{\"id\":1,\"id\":2}]"),
                ReadFault::DuplicateIds => json_response(
                    200,
                    &json!([{"id":1,"tag_name":"unrelated","draft":true},{"id":1,"tag_name":"other","draft":true}]),
                )?,
                ReadFault::MissingFields => json_response(200, &json!([{"id":1}]))?,
                ReadFault::Truncated => {
                    return Err(invalid("fixture deliberately truncated response"));
                }
                ReadFault::NonterminatingPages => {
                    let mut response = json_response(200, &json!([]))?;
                    let mut next =
                        url::Url::parse("https://api.github.com").expect("constant fixture origin");
                    next.set_path(path);
                    next.query_pairs_mut()
                        .append_pair("per_page", "100")
                        .append_pair(
                            "page",
                            &page(query)?
                                .checked_add(1)
                                .ok_or_else(|| invalid("fixture next page overflow"))?
                                .to_string(),
                        );
                    response.headers_mut().insert(
                        "link",
                        hyper::header::HeaderValue::from_str(&format!("<{next}>; rel=\"next\""))
                            .map_err(|_| invalid("fixture next-page header malformed"))?,
                    );
                    response
                }
            };
            return Ok(Some(response));
        }
        Fault::RateLimit { excessive }
            if service == FixtureService::RegistryIndex
                && (*excessive || !snapshot.fault_reached) =>
        {
            snapshot.fault_reached = true;
            save(shared, &snapshot)?;
            drop(snapshot);
            if !*excessive {
                let overlap_cutoff = (Instant::now() + Duration::from_secs(1)).min(shared.deadline);
                loop {
                    if shared.snapshot.lock().await.max_active_reads > 1 {
                        break;
                    }
                    if Instant::now() >= overlap_cutoff {
                        return Err(invalid("fixture throttle never observed concurrent reads"));
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
            let mut response = simple(429, b"retry");
            response.headers_mut().insert(
                "retry-after",
                hyper::header::HeaderValue::from_static(if *excessive { "999999" } else { "1" }),
            );
            return Ok(Some(response));
        }
        Fault::Stall if service == FixtureService::RegistryIndex => {
            snapshot.fault_reached = true;
            save(shared, &snapshot)?;
            drop(snapshot);
            tokio::time::sleep_until(shared.deadline).await;
            return Err(invalid("fixture stalled response deadline"));
        }
        _ => {}
    }
    Ok(None)
}

struct RoutedRequest<'a> {
    method: &'a str,
    path: &'a str,
    query: &'a str,
    accept: &'a str,
    incoming: &'a Path,
    body_len: u64,
}

async fn route(
    shared: &Shared,
    service: FixtureService,
    request: RoutedRequest<'_>,
) -> Result<Routed> {
    let RoutedRequest {
        method,
        path,
        query,
        accept,
        incoming,
        body_len,
    } = request;
    match service {
        FixtureService::GithubApi => github(shared, method, path, query, accept, incoming).await,
        FixtureService::GithubUpload => {
            asset_upload(shared, method, path, query, incoming, body_len).await
        }
        FixtureService::RegistryUpload => registry_upload(shared, method, path, incoming).await,
        FixtureService::RegistryIndex => registry_index(shared, method, path).await,
        FixtureService::RegistryDownload => registry_download(shared, method, path).await,
        FixtureService::Redirect => redirect_download(shared, method, path).await,
    }
}
async fn github(
    shared: &Shared,
    method: &str,
    path: &str,
    query: &str,
    _accept: &str,
    incoming: &Path,
) -> Result<Routed> {
    let tail = selected_tail(shared, path)?;
    let selection = &shared.setup.selection;
    let mut snapshot = shared.snapshot.lock().await;
    let response = match (method, tail.as_slice()) {
        ("GET", []) => {
            if shared.setup.fault == Fault::Private {
                snapshot.fault_reached = true;
                save(shared, &snapshot)?;
            }
            json_response(
                200,
                &json!({"full_name":selection.repository,"private":shared.setup.fault==Fault::Private}),
            )?
        }
        ("GET", ["git", "ref", "tags", tag]) if *tag == selection.version => {
            let late = snapshot.assets.len() == selection.files.len()
                && snapshot.crates.len()
                    == selection
                        .files
                        .iter()
                        .filter(|file| file.package.is_some())
                        .count();
            let drift = matches!(
                shared.setup.fault,
                Fault::SourceDrift {
                    before_visibility: false
                }
            ) || matches!(
                shared.setup.fault,
                Fault::SourceDrift {
                    before_visibility: true
                }
            ) && late;
            if drift || matches!(shared.setup.fault, Fault::AnnotatedTag | Fault::CyclicTag) {
                snapshot.fault_reached = true;
                save(shared, &snapshot)?;
            }
            let (kind, commit) = if drift {
                ("commit", "0000000000000000000000000000000000000000")
            } else if matches!(shared.setup.fault, Fault::AnnotatedTag | Fault::CyclicTag) {
                ("tag", "1111111111111111111111111111111111111111")
            } else {
                ("commit", selection.commit.as_str())
            };
            json_response(200, &json!({"object":{"type":kind,"sha":commit}}))?
        }
        ("GET", ["git", "tags", "1111111111111111111111111111111111111111"]) => json_response(
            200,
            &json!({"object":{"type":if shared.setup.fault==Fault::CyclicTag{"tag"}else{"commit"},"sha":if shared.setup.fault==Fault::CyclicTag{"1111111111111111111111111111111111111111"}else{selection.commit.as_str()}}}),
        )?,
        ("GET", ["releases"]) => {
            let rows = if page(query)? == 1 {
                snapshot
                    .release
                    .as_ref()
                    .map(|release| vec![release_json(release, &selection.version)])
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            json_response(200, &json!(rows))?
        }
        ("POST", ["releases"]) => {
            if snapshot.release.is_some() {
                return Ok(Routed::Reply(simple(422, b"duplicate release")));
            }
            let value = body_json(incoming)?;
            if value["tag_name"] != selection.version
                || value["target_commitish"] != selection.commit
                || value["body"] != selection.notes
                || value["draft"] != true
                || value["prerelease"] != selection.prerelease
            {
                return Err(invalid("fixture draft request metadata differs"));
            }
            let release = ReleaseState {
                id: 1,
                tag_name: selection.version.clone(),
                body: selection.notes.clone(),
                prerelease: selection.prerelease,
                draft: true,
            };
            snapshot.release = Some(release.clone());
            drop(snapshot);
            commit_event(shared, Boundary::Draft, 1, "release".into()).await?;
            json_response(201, &release_json(&release, &selection.version))?
        }
        ("GET", ["releases", "1", "assets"]) => {
            let start = page(query)?
                .checked_sub(1)
                .and_then(|page| page.checked_mul(100))
                .ok_or_else(|| invalid("fixture pagination overflow"))?;
            let rows: Vec<_> = snapshot
                .assets
                .iter()
                .skip(start)
                .take(100)
                .map(asset_json)
                .collect();
            json_response(200, &json!(rows))?
        }
        ("GET", ["releases", "assets", id]) => {
            let id = id
                .parse::<u64>()
                .map_err(|_| invalid("fixture asset id invalid"))?;
            let asset = snapshot
                .assets
                .iter()
                .find(|asset| asset.id == id)
                .ok_or_else(|| invalid("fixture asset missing"))?
                .clone();
            if let Fault::Redirect { kind } = &shared.setup.fault {
                snapshot.fault_reached = true;
                save(shared, &snapshot)?;
                let destination = match kind {
                    RedirectKind::Controlled => {
                        format!("https://memcordon-rehearsal.invalid/assets/{id}")
                    }
                    RedirectKind::Loop => format!("https://api.github.com{path}"),
                    RedirectKind::UnknownOrigin => {
                        "https://unrecognized-rehearsal.invalid/asset".into()
                    }
                };
                return Ok(Routed::Reply(redirect(&destination)?));
            }
            let (corrupt, truncate) = if let Fault::CorruptAsset { truncate } = &shared.setup.fault
            {
                snapshot.fault_reached = true;
                save(shared, &snapshot)?;
                (true, *truncate)
            } else {
                (false, false)
            };
            return Ok(Routed::File {
                path: shared.root.join(asset.path),
                corrupt,
                truncate,
            });
        }
        ("PATCH", ["releases", "1"]) => {
            let value = body_json(incoming)?;
            if value != json!({"draft":false}) {
                return Err(invalid("fixture visibility request differs"));
            }
            if snapshot.assets.len() != selection.files.len()
                || snapshot.crates.len()
                    != selection
                        .files
                        .iter()
                        .filter(|file| file.package.is_some())
                        .count()
                || snapshot.crates.iter().any(|package| !package.visible)
            {
                return Err(invalid("fixture visibility before complete effects"));
            }
            let release = snapshot
                .release
                .as_mut()
                .ok_or_else(|| invalid("fixture draft missing"))?;
            if !release.draft {
                return Ok(Routed::Reply(simple(422, b"duplicate visibility effect")));
            }
            release.draft = false;
            let release = release.clone();
            drop(snapshot);
            commit_event(shared, Boundary::Visibility, 1, "release".into()).await?;
            json_response(200, &release_json(&release, &selection.version))?
        }
        _ => simple(404, b"unsupported fixture route"),
    };
    Ok(Routed::Reply(response))
}
async fn asset_upload(
    shared: &Shared,
    method: &str,
    path: &str,
    query: &str,
    incoming: &Path,
    body_len: u64,
) -> Result<Routed> {
    if method != "POST" || selected_tail(shared, path)?.as_slice() != ["releases", "1", "assets"] {
        return Ok(Routed::Reply(simple(404, b"unsupported asset route")));
    }
    let pairs: Vec<_> = url::form_urlencoded::parse(query.as_bytes()).collect();
    if pairs.len() != 1 || pairs[0].0 != "name" {
        return Err(invalid("fixture asset query differs"));
    }
    let name = pairs[0].1.as_ref();
    let ordinal = shared
        .setup
        .selection
        .files
        .iter()
        .position(|file| file.name == name)
        .ok_or_else(|| invalid("fixture asset is unselected"))?;
    let expected = &shared.setup.selection.files[ordinal];
    let digest = file_digest(incoming)?;
    if body_len != expected.size || digest != expected.sha256 {
        return Err(invalid("received asset differs from selected bytes"));
    }
    let mut snapshot = shared.snapshot.lock().await;
    if snapshot.assets.iter().any(|asset| asset.name == name) {
        return Ok(Routed::Reply(simple(422, b"duplicate asset")));
    }
    check_quota(shared, &snapshot, body_len)?;
    let id = u64::try_from(ordinal).map_err(|_| invalid("asset ordinal overflow"))? + 1;
    let relative = format!("objects/asset-{id}");
    fs::rename(incoming, shared.root.join(&relative))?;
    let residue = shared.setup.fault == Fault::StarterResidue;
    if residue {
        let file = File::options()
            .write(true)
            .open(shared.root.join(&relative))?;
        file.set_len(0)?;
        file.sync_all()?;
    }
    let asset = AssetState {
        id,
        name: name.into(),
        size: if residue { 0 } else { body_len },
        sha256: digest,
        path: relative,
        state: if residue { "starter" } else { "uploaded" }.into(),
    };
    snapshot.assets.push(asset.clone());
    if residue {
        snapshot.fault_reached = true;
        save(shared, &snapshot)?;
        drop(snapshot);
        commit_event(
            shared,
            Boundary::Asset(u32::try_from(ordinal).map_err(|_| invalid("asset ordinal overflow"))?),
            id,
            name.into(),
        )
        .await?;
        return Ok(Routed::Reply(simple(502, b"starter residue")));
    }
    drop(snapshot);
    commit_event(
        shared,
        Boundary::Asset(u32::try_from(ordinal).map_err(|_| invalid("asset ordinal overflow"))?),
        id,
        name.into(),
    )
    .await?;
    Ok(Routed::Reply(json_response(201, &asset_json(&asset))?))
}
fn check_quota(shared: &Shared, snapshot: &Snapshot, additional: u64) -> Result<()> {
    let used = snapshot
        .assets
        .iter()
        .map(|asset| asset.size)
        .chain(snapshot.crates.iter().map(|package| {
            fs::metadata(shared.root.join(&package.path))
                .map(|metadata| metadata.len())
                .unwrap_or(u64::MAX)
        }))
        .try_fold(0_u64, u64::checked_add)
        .ok_or_else(|| invalid("fixture committed byte accounting overflow"))?;
    if used
        .checked_add(additional)
        .is_none_or(|total| total > shared.quota)
    {
        return Err(invalid("fixture committed byte quota exceeded"));
    }
    Ok(())
}
async fn registry_upload(
    shared: &Shared,
    method: &str,
    path: &str,
    incoming: &Path,
) -> Result<Routed> {
    if method != "PUT" || path != "/api/v1/crates/new" {
        return Ok(Routed::Reply(simple(404, b"unsupported registry upload")));
    }
    let number = { shared.snapshot.lock().await.crates.len() };
    let decoded = wire::decode_upload(incoming, incoming, shared.maximum)?;
    let selected: Vec<_> = shared
        .setup
        .selection
        .files
        .iter()
        .filter(|file| file.package.is_some())
        .collect();
    let ordinal = selected
        .iter()
        .position(|file| file.package.as_deref() == Some(&decoded.name))
        .ok_or_else(|| invalid("fixture registry name unselected"))?;
    if decoded.version != shared.setup.selection.version
        || decoded.sha256 != selected[ordinal].sha256
        || decoded.archive_len != selected[ordinal].size
    {
        return Err(invalid(
            "received registry archive differs from selected bytes",
        ));
    }
    let mut snapshot = shared.snapshot.lock().await;
    if snapshot
        .crates
        .iter()
        .any(|package| package.name == decoded.name)
    {
        return Ok(Routed::Reply(simple(422, b"duplicate registry version")));
    }
    check_quota(shared, &snapshot, decoded.archive_len)?;
    for dependency in decoded.index["deps"]
        .as_array()
        .expect("oracle validated dependencies")
    {
        if !matches!(dependency["kind"].as_str(), Some("normal" | "build")) {
            continue;
        }
        let name = dependency["package"]
            .as_str()
            .or_else(|| dependency["name"].as_str())
            .expect("validated dependency");
        if selected
            .iter()
            .any(|file| file.package.as_deref() == Some(name))
            && !snapshot
                .crates
                .iter()
                .any(|package| package.name == name && package.visible && !package.yanked)
        {
            return Err(invalid(
                "registry predecessor not visible before dependent upload",
            ));
        }
    }
    let committed = format!("objects/registry-{number}");
    fs::rename(incoming, shared.root.join(&committed))?;
    let delayed = matches!(shared.setup.fault, Fault::VisibilityDelay { .. });
    snapshot.crates.push(CrateState {
        name: decoded.name.clone(),
        version: decoded.version,
        sha256: decoded.sha256,
        path: committed,
        index: decoded.index,
        visible: !delayed,
        yanked: false,
    });
    drop(snapshot);
    commit_event(
        shared,
        Boundary::Registry(
            u32::try_from(ordinal).map_err(|_| invalid("registry ordinal overflow"))?,
        ),
        number as u64 + 1,
        decoded.name,
    )
    .await?;
    Ok(Routed::Reply(json_response(200, &json!({"ok":true}))?))
}
async fn registry_index(shared: &Shared, method: &str, path: &str) -> Result<Routed> {
    if method != "GET" {
        return Ok(Routed::Reply(simple(405, b"read only")));
    }
    let parts: Vec<_> = path.trim_start_matches('/').split('/').collect();
    if parts.len() != 3
        || parts[..2] != ["me", "mc"]
        || !shared
            .setup
            .selection
            .files
            .iter()
            .any(|file| file.package.as_deref() == Some(parts[2]))
    {
        return Ok(Routed::Reply(simple(404, b"unselected index")));
    }
    let mut snapshot = shared.snapshot.lock().await;
    let Some(position) = snapshot
        .crates
        .iter()
        .position(|package| package.name == parts[2])
    else {
        return Ok(Routed::Reply(simple(404, b"absent version")));
    };
    if let Fault::VisibilityDelay { polls, expire } = &shared.setup.fault
        && !snapshot.crates[position].visible
    {
        snapshot.fault_reached = true;
        let last_upload = snapshot
            .requests
            .iter()
            .rposition(|request| request.service == FixtureService::RegistryUpload)
            .ok_or_else(|| invalid("visibility check missing actual upload"))?;
        let observations = snapshot
            .requests
            .iter()
            .skip(last_upload + 1)
            .filter(|request| {
                request.service == FixtureService::RegistryIndex && request.path == path
            })
            .count();
        if !*expire
            && observations
                > usize::try_from(*polls).map_err(|_| invalid("visibility poll count overflow"))?
        {
            snapshot.crates[position].visible = true;
        }
        save(shared, &snapshot)?;
    }
    if !snapshot.crates[position].visible {
        return Ok(Routed::Reply(simple(404, b"pending visibility")));
    }
    let mut bytes = serde_json::to_vec(&snapshot.crates[position].index)?;
    bytes.push(b'\n');
    Ok(Routed::Reply(simple(200, &bytes)))
}
async fn registry_download(shared: &Shared, method: &str, path: &str) -> Result<Routed> {
    if method != "GET" {
        return Ok(Routed::Reply(simple(405, b"read only")));
    }
    let parts: Vec<_> = path.trim_start_matches('/').split('/').collect();
    if parts.len() != 3 || parts[0] != "crates" {
        return Ok(Routed::Reply(simple(404, b"unsupported registry download")));
    }
    let mut snapshot = shared.snapshot.lock().await;
    let package = snapshot
        .crates
        .iter()
        .find(|package| {
            package.name == parts[1]
                && parts[2] == format!("{}-{}.crate", package.name, package.version)
        })
        .ok_or_else(|| invalid("fixture registry download absent"))?
        .clone();
    let corrupt = shared.setup.fault == Fault::CorruptRegistry;
    if corrupt {
        snapshot.fault_reached = true;
        save(shared, &snapshot)?;
    }
    Ok(Routed::File {
        path: shared.root.join(package.path),
        corrupt,
        truncate: false,
    })
}
fn redirect(destination: &str) -> Result<Response<ResponseBody>> {
    let mut response = simple(302, b"");
    response.headers_mut().insert(
        "location",
        hyper::header::HeaderValue::from_str(destination)
            .map_err(|_| invalid("fixture redirect invalid"))?,
    );
    Ok(response)
}
async fn redirect_download(shared: &Shared, method: &str, path: &str) -> Result<Routed> {
    if method != "GET" {
        return Ok(Routed::Reply(simple(405, b"read only")));
    }
    let id = path
        .strip_prefix("/assets/")
        .and_then(|id| id.parse::<u64>().ok())
        .ok_or_else(|| invalid("fixture redirect path invalid"))?;
    let snapshot = shared.snapshot.lock().await;
    let asset = snapshot
        .assets
        .iter()
        .find(|asset| asset.id == id)
        .ok_or_else(|| invalid("fixture redirect asset missing"))?;
    Ok(Routed::File {
        path: shared.root.join(&asset.path),
        corrupt: false,
        truncate: false,
    })
}

async fn commit_event(shared: &Shared, boundary: Boundary, id: u64, name: String) -> Result<()> {
    let mut snapshot = shared.snapshot.lock().await;
    snapshot.effects.push(EffectObservation {
        boundary: boundary.clone(),
        id,
        name,
    });
    let fault = !snapshot.fault_reached
        && matches!(&shared.setup.fault,Fault::Loss{boundary:selected}|Fault::Barrier{boundary:selected}|Fault::FixtureLoss{boundary:selected} if selected==&boundary);
    if fault {
        snapshot.fault_reached = true;
        snapshot.fault_boundary = Some(boundary.clone());
    }
    save(shared, &snapshot)?;
    let barrier = fault
        && matches!(
            shared.setup.fault,
            Fault::Barrier { .. } | Fault::FixtureLoss { .. }
        );
    let event = ControlEvent {
        event: "committed".into(),
        boundary,
        ordinal: snapshot.effects.len() as u64,
        barrier,
    };
    drop(snapshot);
    {
        let output = io::stdout();
        let mut output = output.lock();
        serde_json::to_writer(&mut output, &event)?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
    if fault && matches!(shared.setup.fault, Fault::FixtureLoss { .. }) {
        shared.stop.notify_one();
        return Err(invalid("fixture deliberately lost after committed effect"));
    }
    if barrier {
        let permit = timeout_at(shared.deadline, shared.resume.acquire())
            .await
            .map_err(|_| invalid("fixture barrier deadline elapsed"))?
            .map_err(|_| invalid("fixture barrier closed"))?;
        permit.forget();
    }
    if fault && matches!(shared.setup.fault, Fault::Loss { .. }) {
        return Err(invalid("fixture deliberately lost committed write reply"));
    }
    Ok(())
}

struct FileBody {
    file: File,
    remaining: u64,
    corrupt: bool,
    first: bool,
    _admission: Admission,
}
impl Body for FileBody {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, io::Error>>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }
        if Instant::now() >= self._admission.shared.deadline {
            return Poll::Ready(Some(Err(transport_error(
                "fixture stream deadline elapsed",
            ))));
        }
        let length = self.remaining.min(64 * 1024) as usize;
        let mut buffer = vec![0; length];
        match self.file.read(&mut buffer) {
            Ok(0) => Poll::Ready(Some(Err(transport_error("fixture stored body truncated")))),
            Ok(count) => {
                buffer.truncate(count);
                self.remaining -= count as u64;
                if self.corrupt && self.first {
                    buffer[0] ^= 1;
                }
                self.first = false;
                Poll::Ready(Some(Ok(Frame::data(Bytes::from(buffer)))))
            }
            Err(error) => Poll::Ready(Some(Err(error))),
        }
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
}
fn file_response(
    path: &Path,
    corrupt: bool,
    truncate: bool,
    admission: Admission,
) -> Result<Response<ResponseBody>> {
    let file = File::open(path)?;
    let size = file.metadata()?.len();
    let remaining = if truncate {
        size.saturating_sub(1)
    } else {
        size
    };
    Ok(Response::builder()
        .status(200)
        .header("content-type", "application/octet-stream")
        .body(
            FileBody {
                file,
                remaining,
                corrupt,
                first: true,
                _admission: admission,
            }
            .boxed(),
        )
        .expect("fixed file response"))
}
