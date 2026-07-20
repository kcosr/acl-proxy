use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use http::HeaderName;
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex, Notify};
use tokio::task::JoinHandle;
use tokio::time::{self, Instant};

use super::process_response::{
    read_process_response, DecisionOnlyProviderDecision, ProcessResponse, ProcessResponseSchema,
};
use super::protocol::{
    read_provider_response_prefix, DirectProviderStdout, ProviderBodyReplacement,
    ProviderCredentialSet, ProviderDecision, ProviderOutputRegistry, ProviderRequest,
    RequestStreamError, PROCESS_PROVIDER_CORRELATION_ID_BYTES,
};
use crate::config::compiler::{CompiledProviderFailureMode, ProcessProviderPlan};
use crate::runtime::{
    AuthorizationInvocationMode, BoxFuture, CleanupReason, GenerationOwner, PublicationGuard,
    RuntimeError,
};
use crate::safety::{HttpWireBodyGuard, ProviderResponseCharge};

const CHILD_EXIT_POLL_INTERVAL: Duration = Duration::from_millis(20);
const TERMINATE_GRACE: Duration = Duration::from_secs(1);

pub(crate) struct ProcessProvider {
    inner: Arc<Inner>,
}

struct Inner {
    spawn: SpawnConfig,
    response_schema: ProcessResponseSchema,
    failure_mode: CompiledProviderFailureMode,
    include_headers: Box<[HeaderName]>,
    include_request_body: bool,
    max_request_body_bytes: usize,
    max_decoded_request_body_bytes: usize,
    timeout: Duration,
    max_stdout_line_bytes: usize,
    max_pending_requests: usize,
    restart_backoff: Duration,
    retire_timeout: Duration,
    state: Mutex<ProcessState>,
    requests: Mutex<RequestTable>,
    pending_count: AtomicUsize,
    next_dispatch: AtomicU64,
    events: mpsc::UnboundedSender<SupervisorEvent>,
    event_tasks: Mutex<Vec<JoinHandle<()>>>,
    reader: Mutex<Option<EpochReader>>,
    supervisor: Mutex<Option<JoinHandle<()>>>,
    cleanup: CleanupState,
    #[cfg(test)]
    cleanup_starts: AtomicUsize,
    #[cfg(test)]
    cleanup_reasons: Mutex<Vec<CleanupReason>>,
    #[cfg(test)]
    reader_correlation_gate: Mutex<Option<Arc<tokio::sync::Barrier>>>,
}

struct SpawnConfig {
    command: PathBuf,
    working_directory: PathBuf,
    args: Box<[String]>,
    environment: Box<[(OsString, OsString)]>,
}

struct ProcessState {
    phase: Phase,
    available: bool,
    exit_draining: bool,
    reader_assigned: bool,
    retirement_deadline: Option<Instant>,
    epoch: u64,
    child: Option<Child>,
    process_group_id: Option<u32>,
    writer: Option<Arc<AsyncMutex<ChildStdin>>>,
    cancellation: EpochCancellation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Candidate,
    Active,
    Retiring,
    Stopped,
}

struct PendingRequest {
    response: oneshot::Sender<Result<ProcessDecision, ProcessRequestError>>,
    response_charge: ProviderResponseCharge,
    completed: Arc<AtomicBool>,
    request_deadline: Instant,
    invocation_mode: AuthorizationInvocationMode,
    epoch: u64,
    _admission: PendingAdmission,
}

#[derive(Default)]
struct RequestTable {
    reserved: HashMap<String, ReservationBrand>,
    pending: HashMap<String, PendingRequest>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReservationBrand {
    epoch: u64,
    token: u64,
}

struct PendingAdmission {
    inner: Arc<Inner>,
}

struct StreamReservation {
    inner: Arc<Inner>,
    id: String,
    epoch: u64,
    brand: ReservationBrand,
    armed: bool,
    stream_started: bool,
}

struct RequestCancellationGuard {
    inner: Arc<Inner>,
    epoch: u64,
    completed: Arc<AtomicBool>,
}

#[derive(Clone)]
struct EpochCancellation {
    inner: Arc<EpochCancellationInner>,
}

struct EpochCancellationInner {
    cancelled: AtomicBool,
    changed: Notify,
}

struct EpochReader {
    epoch: u64,
    task: Option<JoinHandle<()>>,
    abort: tokio::task::AbortHandle,
}

enum SupervisorEvent {
    Fatal { epoch: u64 },
    Stop,
}

struct SpawnedChild {
    child: Child,
    process_group_id: Option<u32>,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

struct CleanupState {
    started: AtomicBool,
    complete: AtomicBool,
    changed: Notify,
}

pub(crate) struct ProcessPublicationGuard<'provider> {
    state: MutexGuard<'provider, ProcessState>,
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum ProcessActivationError {
    #[error("process-provider activation was cancelled")]
    Cancelled,
    #[error("process provider could not be started")]
    Spawn,
    #[error("process provider environment input is unavailable")]
    EnvironmentUnavailable,
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum ProcessRequestError {
    #[error("process provider is not available")]
    Unavailable,
    #[error("process provider has reached its pending-request limit")]
    AtCapacity,
    #[error("process-provider request frame is invalid")]
    InvalidRequest,
    #[error("process-provider request frame could not be admitted")]
    FrameAdmission,
    #[error("process-provider response assigned to this request is invalid")]
    InvalidResponse,
    #[error("process-provider request timed out")]
    Timeout,
}

pub(crate) enum ProcessDecision {
    Allow,
    AllowWithOutputs {
        credentials: Option<ProviderCredentialSet>,
        replacement: Option<ProviderBodyReplacement>,
    },
    Deny,
    Pass,
}

impl ProcessProvider {
    pub(crate) async fn activate(
        plan: ProcessProviderPlan,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<Arc<Self>, ProcessActivationError> {
        let response_schema = ProcessResponseSchema::activate(&plan);
        let ProcessProviderPlan {
            command,
            working_directory,
            args,
            timeout,
            on_failure,
            inherit_environment,
            pass_environment,
            environment,
            include_headers,
            include_request_body,
            allow_request_body_replacement,
            max_request_body_bytes,
            max_decoded_request_body_bytes,
            max_stdout_line_bytes,
            max_pending_requests,
            restart_backoff,
            retire_timeout,
            outputs,
        } = plan;

        let _ = (allow_request_body_replacement, outputs);

        check_cancellation(&mut is_cancelled)?;
        let environment = capture_environment(
            inherit_environment,
            &pass_environment,
            environment,
            &mut is_cancelled,
        );
        check_cancellation(&mut is_cancelled)?;
        let environment = environment?;
        let spawn = SpawnConfig {
            command,
            working_directory,
            args: args.into_boxed_slice(),
            environment,
        };

        check_cancellation(&mut is_cancelled)?;
        let spawned = spawn_child(&spawn).await?;
        if let Err(error) = check_cancellation(&mut is_cancelled) {
            terminate_child(spawned.child, spawned.process_group_id).await;
            return Err(error);
        }

        let (events, event_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner {
            spawn,
            response_schema,
            failure_mode: on_failure,
            include_headers: include_headers.into_boxed_slice(),
            include_request_body,
            max_request_body_bytes,
            max_decoded_request_body_bytes,
            timeout,
            max_stdout_line_bytes,
            max_pending_requests,
            restart_backoff,
            retire_timeout,
            state: Mutex::new(ProcessState {
                phase: Phase::Candidate,
                available: true,
                exit_draining: false,
                reader_assigned: false,
                retirement_deadline: None,
                epoch: 1,
                child: Some(spawned.child),
                process_group_id: spawned.process_group_id,
                writer: None,
                cancellation: EpochCancellation::new(),
            }),
            requests: Mutex::new(RequestTable::default()),
            pending_count: AtomicUsize::new(0),
            next_dispatch: AtomicU64::new(1),
            events,
            event_tasks: Mutex::new(Vec::new()),
            reader: Mutex::new(None),
            supervisor: Mutex::new(None),
            cleanup: CleanupState {
                started: AtomicBool::new(false),
                complete: AtomicBool::new(false),
                changed: Notify::new(),
            },
            #[cfg(test)]
            cleanup_starts: AtomicUsize::new(0),
            #[cfg(test)]
            cleanup_reasons: Mutex::new(Vec::new()),
            #[cfg(test)]
            reader_correlation_gate: Mutex::new(None),
        });
        install_io_tasks(&inner, 1, spawned.stdin, spawned.stdout);
        let supervisor_inner = inner.clone();
        let supervisor = tokio::spawn(async move {
            run_supervisor(supervisor_inner, event_rx).await;
        });
        *lock(&inner.supervisor) = Some(supervisor);
        Ok(Arc::new(Self { inner }))
    }

    pub(crate) fn include_headers(&self) -> &[HeaderName] {
        &self.inner.include_headers
    }

    pub(crate) fn failure_mode(&self) -> CompiledProviderFailureMode {
        self.inner.failure_mode
    }

    pub(crate) fn include_request_body(&self) -> bool {
        self.inner.include_request_body
    }

    pub(crate) fn max_decoded_request_body_bytes(&self) -> usize {
        self.inner.max_decoded_request_body_bytes
    }

    pub(crate) fn max_request_body_bytes(&self) -> usize {
        self.inner.max_request_body_bytes
    }

    pub(crate) fn outputs(&self) -> Option<&ProviderOutputRegistry> {
        self.inner.response_schema.outputs()
    }

    #[cfg(test)]
    async fn decide_effects_allowed_for_test(
        &self,
        request: ProviderRequest<'_>,
        guard: &HttpWireBodyGuard,
        request_deadline: Instant,
    ) -> Result<ProcessDecision, ProcessRequestError> {
        self.decide(
            request,
            AuthorizationInvocationMode::EffectsAllowed,
            guard,
            request_deadline,
        )
        .await
    }

    pub(crate) async fn decide(
        &self,
        request: ProviderRequest<'_>,
        invocation_mode: AuthorizationInvocationMode,
        guard: &HttpWireBodyGuard,
        request_deadline: Instant,
    ) -> Result<ProcessDecision, ProcessRequestError> {
        let valid_body_shape = match invocation_mode {
            AuthorizationInvocationMode::EffectsAllowed => {
                request.body.is_some() == self.inner.include_request_body
            }
            AuthorizationInvocationMode::DecisionOnly => request.body.is_none(),
        };
        if !valid_body_shape {
            return Err(ProcessRequestError::InvalidRequest);
        }
        let operation_deadline =
            operation_deadline(Instant::now(), request_deadline, self.inner.timeout);
        let (receiver, cancellation) = match time::timeout_at(
            operation_deadline,
            self.dispatch_before_response(request, invocation_mode, guard, request_deadline),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => return Err(ProcessRequestError::Timeout),
        };
        let result = match time::timeout_at(operation_deadline, receiver).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(ProcessRequestError::Unavailable),
            Err(_) => Err(ProcessRequestError::Timeout),
        };
        drop(cancellation);
        result
    }

    async fn dispatch_before_response(
        &self,
        request: ProviderRequest<'_>,
        invocation_mode: AuthorizationInvocationMode,
        guard: &HttpWireBodyGuard,
        request_deadline: Instant,
    ) -> Result<
        (
            oneshot::Receiver<Result<ProcessDecision, ProcessRequestError>>,
            RequestCancellationGuard,
        ),
        ProcessRequestError,
    > {
        let admission = PendingAdmission::reserve(self.inner.clone())?;
        let (response, receiver) = oneshot::channel();
        let (epoch, writer, epoch_cancellation) = {
            let state = lock(&self.inner.state);
            if !accepts_dispatch(&state) {
                return Err(rejection_for_state(&state, request_deadline));
            }
            let Some(writer) = state.writer.as_ref() else {
                return Err(ProcessRequestError::Unavailable);
            };
            (state.epoch, writer.clone(), state.cancellation.clone())
        };
        let Some(token) = take_dispatch_counter(&self.inner.next_dispatch) else {
            self.inner.report_fatal(epoch);
            return Err(ProcessRequestError::Unavailable);
        };
        let id = correlation_id(epoch, token);
        let brand = ReservationBrand { epoch, token };
        {
            let state = lock(&self.inner.state);
            if state.epoch != epoch || !accepts_dispatch(&state) {
                return Err(rejection_for_state(&state, request_deadline));
            }
            let replaced = lock(&self.inner.requests)
                .reserved
                .insert(id.clone(), brand);
            debug_assert!(replaced.is_none(), "process-provider wire ID reused");
        }
        let mut reservation = StreamReservation {
            inner: self.inner.clone(),
            id: id.clone(),
            epoch,
            brand,
            armed: true,
            stream_started: false,
        };
        let mut writer = tokio::select! {
            biased;
            _ = epoch_cancellation.cancelled() => {
                return Err(self.inner.current_dispatch_error(request_deadline));
            }
            writer = writer.lock() => writer,
        };
        self.inner.check_dispatch_epoch(epoch, request_deadline)?;
        let mut scratch = guard
            .stream_scratch()
            .map_err(|_| ProcessRequestError::FrameAdmission)?;
        reservation.stream_started = true;
        let streamed = tokio::select! {
            biased;
            _ = epoch_cancellation.cancelled() => {
                return Err(self.inner.current_dispatch_error(request_deadline));
            }
            streamed = request.stream_before_commit(&id, &mut *writer, &mut scratch) => streamed,
        };
        let commit = match streamed {
            Ok(commit) => commit,
            Err(RequestStreamError::Shape(_)) => {
                reservation.stream_started = false;
                return Err(ProcessRequestError::InvalidRequest);
            }
            Err(RequestStreamError::Io(_)) => {
                return Err(self.inner.current_dispatch_error(request_deadline));
            }
        };
        drop(scratch);
        let response_charge = guard.provider_response_charge();

        let completed = Arc::new(AtomicBool::new(false));
        {
            let state = lock(&self.inner.state);
            if state.epoch != epoch || !accepts_dispatch(&state) {
                return Err(rejection_for_state(&state, request_deadline));
            }
            let mut requests = lock(&self.inner.requests);
            if !remove_reservation_if_brand(&mut requests, &id, brand) {
                return Err(ProcessRequestError::Unavailable);
            }
            requests.pending.insert(
                id.clone(),
                PendingRequest {
                    response,
                    response_charge,
                    completed: completed.clone(),
                    request_deadline,
                    invocation_mode,
                    epoch,
                    _admission: admission,
                },
            );
            reservation.armed = false;
        }
        let cancellation = RequestCancellationGuard {
            inner: self.inner.clone(),
            epoch,
            completed,
        };
        let committed = tokio::select! {
            biased;
            _ = epoch_cancellation.cancelled() => {
                return Err(self.inner.current_dispatch_error(request_deadline));
            }
            committed = commit.commit(&mut *writer) => committed,
        };
        if committed.is_err() {
            return Err(self.inner.current_dispatch_error(request_deadline));
        }
        drop(writer);
        Ok((receiver, cancellation))
    }

    fn begin_retirement(&self) {
        let deadline = Instant::now() + self.inner.retire_timeout;
        {
            let mut state = lock(&self.inner.state);
            if state.phase != Phase::Active {
                return;
            }
            state.phase = Phase::Retiring;
            state.retirement_deadline = Some(deadline);
        }
        let inner = self.inner.clone();
        let task = tokio::spawn(async move {
            time::sleep_until(deadline).await;
            let should_stop = {
                let mut state = lock(&inner.state);
                if state.phase == Phase::Retiring {
                    state.available = false;
                    state.writer.take();
                    state.cancellation.cancel();
                    true
                } else {
                    false
                }
            };
            if should_stop {
                inner.fail_all();
                let _ = inner.events.send(SupervisorEvent::Stop);
            }
        });
        lock(&self.inner.event_tasks).push(task);
    }

    #[cfg(test)]
    pub(crate) fn child_id(&self) -> Option<u32> {
        lock(&self.inner.state).child.as_ref().and_then(Child::id)
    }

    #[cfg(test)]
    pub(crate) fn cleanup_starts(&self) -> usize {
        self.inner.cleanup_starts.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn cleanup_reasons(&self) -> Vec<CleanupReason> {
        lock(&self.inner.cleanup_reasons).clone()
    }
}

impl fmt::Debug for ProcessProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = lock(&self.inner.state);
        formatter
            .debug_struct("ProcessProvider")
            .field("active", &(state.phase == Phase::Active))
            .field("available", &state.available)
            .field(
                "pending_count",
                &self.inner.pending_count.load(Ordering::Acquire),
            )
            .finish()
    }
}

impl PublicationGuard for ProcessPublicationGuard<'_> {
    fn commit(&mut self) {
        if self.state.phase == Phase::Candidate && self.state.available {
            self.state.phase = Phase::Active;
        }
    }
}

impl GenerationOwner for ProcessProvider {
    fn publication_guard(&self) -> Result<Box<dyn PublicationGuard + '_>, RuntimeError> {
        let mut state = lock(&self.inner.state);
        if state.phase != Phase::Candidate || !state.available {
            return Err(candidate_not_live());
        }
        let Some(child) = state.child.as_mut() else {
            state.available = false;
            state.cancellation.cancel();
            return Err(candidate_not_live());
        };
        match observe_child_exit(child) {
            Ok(false) => Ok(Box::new(ProcessPublicationGuard { state })),
            Ok(true) | Err(()) => {
                state.available = false;
                state.cancellation.cancel();
                let epoch = state.epoch;
                let _ = self.inner.events.send(SupervisorEvent::Fatal { epoch });
                Err(candidate_not_live())
            }
        }
    }

    fn retirement_started(&self, _reason: CleanupReason) {
        self.begin_retirement();
    }

    fn cleanup(&self, _reason: CleanupReason) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if self
                .inner
                .cleanup
                .started
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                #[cfg(test)]
                {
                    self.inner.cleanup_starts.fetch_add(1, Ordering::AcqRel);
                    lock(&self.inner.cleanup_reasons).push(_reason);
                }
                let inner = self.inner.clone();
                std::mem::drop(tokio::spawn(async move {
                    let _ = inner.events.send(SupervisorEvent::Stop);
                    let supervisor = lock(&inner.supervisor).take();
                    if let Some(supervisor) = supervisor {
                        let _ = supervisor.await;
                    }
                    // Also handles a supervisor task that exited unexpectedly.
                    stop_supervisor(&inner).await;
                    inner.cleanup.complete.store(true, Ordering::Release);
                    inner.cleanup.changed.notify_waiters();
                }));
            }
            loop {
                let changed = self.inner.cleanup.changed.notified();
                if self.inner.cleanup.complete.load(Ordering::Acquire) {
                    return;
                }
                changed.await;
            }
        })
    }
}

impl PendingAdmission {
    fn reserve(inner: Arc<Inner>) -> Result<Self, ProcessRequestError> {
        let mut current = inner.pending_count.load(Ordering::Acquire);
        loop {
            if current >= inner.max_pending_requests {
                return Err(ProcessRequestError::AtCapacity);
            }
            match inner.pending_count.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(Self { inner }),
                Err(observed) => current = observed,
            }
        }
    }
}

impl Drop for PendingAdmission {
    fn drop(&mut self) {
        let previous = self.inner.pending_count.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "process-provider pending count underflow");
    }
}

impl Drop for StreamReservation {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        remove_reservation_if_brand(&mut lock(&self.inner.requests), &self.id, self.brand);
        if self.stream_started {
            self.inner.report_fatal(self.epoch);
        }
    }
}

impl EpochCancellation {
    fn new() -> Self {
        Self {
            inner: Arc::new(EpochCancellationInner {
                cancelled: AtomicBool::new(false),
                changed: Notify::new(),
            }),
        }
    }

    fn cancel(&self) {
        if !self.inner.cancelled.swap(true, Ordering::AcqRel) {
            self.inner.changed.notify_waiters();
        }
    }

    async fn cancelled(&self) {
        loop {
            let changed = self.inner.changed.notified();
            if self.inner.cancelled.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }
}

fn remove_reservation_if_brand(
    requests: &mut RequestTable,
    id: &str,
    brand: ReservationBrand,
) -> bool {
    if requests.reserved.get(id) != Some(&brand) {
        return false;
    }
    requests.reserved.remove(id);
    true
}

fn take_dispatch_counter(counter: &AtomicU64) -> Option<u64> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_add(1)
        })
        .ok()
}

fn correlation_id(epoch: u64, dispatch: u64) -> String {
    let id = format!("p{epoch:016x}-{dispatch:016x}");
    debug_assert_eq!(id.len(), PROCESS_PROVIDER_CORRELATION_ID_BYTES);
    id
}

impl Drop for RequestCancellationGuard {
    fn drop(&mut self) {
        if !self.completed.load(Ordering::Acquire) {
            self.inner.report_fatal(self.epoch);
        }
    }
}

fn check_cancellation(
    is_cancelled: &mut dyn FnMut() -> bool,
) -> Result<(), ProcessActivationError> {
    if is_cancelled() {
        Err(ProcessActivationError::Cancelled)
    } else {
        Ok(())
    }
}

fn capture_environment(
    inherit_environment: bool,
    pass_environment: &[String],
    literal_environment: std::collections::BTreeMap<String, String>,
    is_cancelled: &mut dyn FnMut() -> bool,
) -> Result<Box<[(OsString, OsString)]>, ProcessActivationError> {
    let mut captured = std::collections::BTreeMap::<OsString, OsString>::new();
    if inherit_environment {
        tracing::warn!("process provider inherits its activation environment");
        check_cancellation(is_cancelled)?;
        let inherited = env::vars_os().collect::<Vec<_>>();
        check_cancellation(is_cancelled)?;
        captured.extend(inherited);
    }
    for name in pass_environment {
        check_cancellation(is_cancelled)?;
        let value = env::var_os(name);
        check_cancellation(is_cancelled)?;
        let Some(value) = value else {
            return Err(ProcessActivationError::EnvironmentUnavailable);
        };
        if !inherit_environment {
            captured.insert(OsString::from(name), value);
        }
    }
    for (name, value) in literal_environment {
        captured.insert(OsString::from(name), OsString::from(value));
    }
    Ok(captured.into_iter().collect::<Vec<_>>().into_boxed_slice())
}

async fn spawn_child(config: &SpawnConfig) -> Result<SpawnedChild, ProcessActivationError> {
    let mut command = Command::new(&config.command);
    command
        .args(config.args.iter())
        .current_dir(&config.working_directory)
        .env_clear()
        .envs(config.environment.iter().cloned())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    command.process_group(0);
    let mut child = command.spawn().map_err(|_| ProcessActivationError::Spawn)?;
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    let process_group_id = child.id();
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    let process_group_id = None;
    let Some(stdin) = child.stdin.take() else {
        terminate_child(child, process_group_id).await;
        return Err(ProcessActivationError::Spawn);
    };
    let Some(stdout) = child.stdout.take() else {
        terminate_child(child, process_group_id).await;
        return Err(ProcessActivationError::Spawn);
    };
    Ok(SpawnedChild {
        child,
        process_group_id,
        stdin,
        stdout,
    })
}

fn install_io_tasks(inner: &Arc<Inner>, epoch: u64, stdin: ChildStdin, stdout: ChildStdout) {
    {
        let mut state = lock(&inner.state);
        if state.epoch != epoch || !state.available {
            return;
        }
        state.writer = Some(Arc::new(AsyncMutex::new(stdin)));
    }
    let reader_inner = inner.clone();
    let (start, started) = oneshot::channel();
    let reader_task = tokio::spawn(async move {
        if started.await.is_err() {
            return;
        }
        run_reader(reader_inner, epoch, stdout).await;
    });
    let abort = reader_task.abort_handle();
    let previous = lock(&inner.reader).replace(EpochReader {
        epoch,
        task: Some(reader_task),
        abort,
    });
    debug_assert!(previous.is_none(), "process-provider reader was not joined");
    let _ = start.send(());
}

async fn run_reader(inner: Arc<Inner>, epoch: u64, stdout: ChildStdout) {
    let mut stdout = DirectProviderStdout::new(stdout);
    loop {
        let continuation =
            match read_provider_response_prefix(&mut stdout, inner.max_stdout_line_bytes).await {
                Ok(Some(continuation)) => continuation,
                Ok(None) if inner.clean_exit_reader_eof(epoch) => return,
                Ok(None) | Err(_) => {
                    inner.report_fatal(epoch);
                    return;
                }
            };
        #[cfg(test)]
        let correlation_gate = { lock(&inner.reader_correlation_gate).clone() };
        #[cfg(test)]
        if let Some(gate) = correlation_gate {
            gate.wait().await;
            gate.wait().await;
        }
        let pending = inner.assign_pending_response(epoch, continuation.id());
        let Some(pending) = pending else {
            inner.report_fatal(epoch);
            return;
        };
        let parsed = read_process_response(
            &mut stdout,
            continuation,
            &pending.response_charge,
            &inner.response_schema,
            pending.invocation_mode,
        )
        .await;
        match parsed {
            Ok(response) => {
                if let Some(error) = inner.assigned_delivery_error(epoch, pending.request_deadline)
                {
                    pending.completed.store(true, Ordering::Release);
                    let _ = pending.response.send(Err(error));
                    inner.finish_assigned_response(epoch);
                    inner.report_fatal(epoch);
                    return;
                }
                pending.completed.store(true, Ordering::Release);
                match response {
                    ProcessResponse::DecisionOnly(decision) => {
                        let _ = pending.response.send(Ok(ProcessDecision::from(decision)));
                    }
                    ProcessResponse::Expanded(decision) => {
                        let _ = pending.response.send(Ok(ProcessDecision::from(decision)));
                    }
                    ProcessResponse::AssignedFailure => {
                        let _ = pending
                            .response
                            .send(Err(ProcessRequestError::InvalidResponse));
                    }
                }
                if !inner.finish_assigned_response(epoch) {
                    return;
                }
            }
            Err(_) => {
                let error = inner.current_dispatch_error(pending.request_deadline);
                if error == ProcessRequestError::Timeout {
                    pending.completed.store(true, Ordering::Release);
                }
                let _ = pending.response.send(Err(error));
                inner.finish_assigned_response(epoch);
                inner.report_fatal(epoch);
                return;
            }
        }
    }
}

impl From<DecisionOnlyProviderDecision> for ProcessDecision {
    fn from(value: DecisionOnlyProviderDecision) -> Self {
        match value {
            DecisionOnlyProviderDecision::Allow => Self::Allow,
            DecisionOnlyProviderDecision::Deny => Self::Deny,
            DecisionOnlyProviderDecision::Pass => Self::Pass,
        }
    }
}

impl From<ProviderDecision> for ProcessDecision {
    fn from(value: ProviderDecision) -> Self {
        match value {
            ProviderDecision::Allow {
                credentials,
                replacement,
            } => Self::AllowWithOutputs {
                credentials: Some(credentials),
                replacement,
            },
            ProviderDecision::AllowWithoutEffects => Self::Allow,
            ProviderDecision::Deny => Self::Deny,
            ProviderDecision::Pass => Self::Pass,
        }
    }
}

impl fmt::Debug for ProcessDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => formatter.write_str("Allow"),
            Self::AllowWithOutputs {
                credentials,
                replacement,
            } => formatter
                .debug_struct("Allow")
                .field("credentials", credentials)
                .field("replacement", replacement)
                .finish(),
            Self::Deny => formatter.write_str("Deny"),
            Self::Pass => formatter.write_str("Pass"),
        }
    }
}

impl PartialEq for ProcessDecision {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::Allow, Self::Allow)
                | (Self::AllowWithOutputs { .. }, Self::AllowWithOutputs { .. })
                | (Self::Deny, Self::Deny)
                | (Self::Pass, Self::Pass)
        )
    }
}

impl Eq for ProcessDecision {}

impl Inner {
    fn assign_pending_response(&self, epoch: u64, id: &str) -> Option<PendingRequest> {
        let mut state = lock(&self.state);
        if state.epoch != epoch
            || (!state.available && !state.exit_draining)
            || state.reader_assigned
        {
            return None;
        }
        let mut requests = lock(&self.requests);
        if requests
            .pending
            .get(id)
            .is_none_or(|pending| pending.epoch != epoch)
        {
            return None;
        }
        let pending = requests.pending.remove(id)?;
        state.reader_assigned = true;
        Some(pending)
    }

    fn finish_assigned_response(&self, epoch: u64) -> bool {
        let mut state = lock(&self.state);
        if state.epoch != epoch {
            return false;
        }
        state.reader_assigned = false;
        state.available || state.exit_draining
    }

    fn clean_exit_reader_eof(&self, epoch: u64) -> bool {
        let state = lock(&self.state);
        state.epoch == epoch && state.exit_draining
    }

    fn check_dispatch_epoch(
        &self,
        epoch: u64,
        deadline: Instant,
    ) -> Result<(), ProcessRequestError> {
        let state = lock(&self.state);
        if state.epoch != epoch {
            Err(ProcessRequestError::Unavailable)
        } else if accepts_dispatch(&state) {
            Ok(())
        } else {
            Err(rejection_for_state(&state, deadline))
        }
    }

    fn current_dispatch_error(&self, deadline: Instant) -> ProcessRequestError {
        rejection_for_state(&lock(&self.state), deadline)
    }

    fn assigned_delivery_error(
        &self,
        epoch: u64,
        deadline: Instant,
    ) -> Option<ProcessRequestError> {
        let state = lock(&self.state);
        if state.epoch != epoch
            || !(state.available || state.exit_draining && state.reader_assigned)
        {
            Some(rejection_for_state(&state, deadline))
        } else {
            expired_retirement_rejection(&state, deadline)
        }
    }

    fn report_fatal(&self, epoch: u64) {
        let should_report = {
            let mut state = lock(&self.state);
            if state.epoch != epoch
                || (!state.available && !state.exit_draining)
                || state.phase == Phase::Stopped
            {
                false
            } else {
                state.available = false;
                state.exit_draining = false;
                state.writer.take();
                state.cancellation.cancel();
                true
            }
        };
        if should_report {
            self.fail_all();
            self.abort_epoch_reader(epoch);
            let _ = self.events.send(SupervisorEvent::Fatal { epoch });
        }
    }

    fn abort_epoch_reader(&self, epoch: u64) {
        if let Some(reader) = lock(&self.reader)
            .as_ref()
            .filter(|reader| reader.epoch == epoch)
        {
            reader.abort.abort();
        }
    }

    fn begin_child_exit_drain(&self, epoch: u64) -> bool {
        let mut state = lock(&self.state);
        if state.epoch != epoch || !state.available || state.phase == Phase::Stopped {
            return false;
        }
        state.available = false;
        state.exit_draining = true;
        state.writer.take();
        state.cancellation.cancel();
        true
    }

    fn finish_child_exit_drain(&self, epoch: u64) {
        let mut state = lock(&self.state);
        if state.epoch == epoch {
            state.exit_draining = false;
            state.cancellation.cancel();
        }
        drop(state);
        self.fail_all();
    }

    fn fail_all(&self) {
        let mut requests = lock(&self.requests);
        requests.reserved.clear();
        let pending = std::mem::take(&mut requests.pending);
        drop(requests);
        for (_, pending) in pending {
            let error = self.current_dispatch_error(pending.request_deadline);
            if error == ProcessRequestError::Timeout {
                pending.completed.store(true, Ordering::Release);
            }
            let _ = pending.response.send(Err(error));
        }
    }
}

async fn run_supervisor(inner: Arc<Inner>, mut events: mpsc::UnboundedReceiver<SupervisorEvent>) {
    let mut restart_at = None;
    let mut poll = time::interval(CHILD_EXIT_POLL_INTERVAL);
    poll.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            event = events.recv() => match event {
                Some(SupervisorEvent::Fatal { epoch }) => {
                    handle_fatal(&inner, epoch, &mut restart_at).await;
                }
                Some(SupervisorEvent::Stop) | None => {
                    stop_supervisor(&inner).await;
                    return;
                }
            },
            _ = poll.tick() => {
                let child_status = {
                    let mut state = lock(&inner.state);
                    if state.available {
                        match state.child.as_mut().map(observe_child_exit) {
                            Some(Ok(true)) => Some((state.epoch, true)),
                            Some(Err(())) | None => Some((state.epoch, false)),
                            Some(Ok(false)) => None,
                        }
                    } else {
                        None
                    }
                };
                if let Some((epoch, exited)) = child_status {
                    if exited {
                        if inner.begin_child_exit_drain(epoch) {
                            handle_child_exit(&inner, epoch, &mut restart_at).await;
                        }
                    } else {
                        inner.report_fatal(epoch);
                    }
                }
            },
            _ = sleep_until_optional(restart_at), if restart_at.is_some() => {
                restart_at = None;
                restart_if_active(&inner, &mut restart_at).await;
            }
        }
    }
}

async fn handle_fatal(inner: &Arc<Inner>, epoch: u64, restart_at: &mut Option<Instant>) {
    let (child, process_group_id) = {
        let mut state = lock(&inner.state);
        if state.epoch != epoch {
            return;
        }
        state.writer.take();
        (state.child.take(), state.process_group_id.take())
    };
    stop_epoch_reader(inner, Some(epoch)).await;
    if let Some(child) = child {
        terminate_child(child, process_group_id).await;
    }
    let should_restart = {
        let state = lock(&inner.state);
        state.epoch == epoch && state.phase == Phase::Active
    };
    if should_restart {
        *restart_at = Some(Instant::now() + inner.restart_backoff);
    }
}

async fn handle_child_exit(inner: &Arc<Inner>, epoch: u64, restart_at: &mut Option<Instant>) {
    let (child, process_group_id) = {
        let mut state = lock(&inner.state);
        if state.epoch != epoch {
            return;
        }
        (state.child.take(), state.process_group_id.take())
    };
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    kill_process_group(process_group_id, libc::SIGKILL);
    if let Some(child) = child {
        reap_child(child).await;
    }
    drain_epoch_reader(inner, epoch).await;
    inner.finish_child_exit_drain(epoch);
    let should_restart = {
        let state = lock(&inner.state);
        state.epoch == epoch && state.phase == Phase::Active
    };
    if should_restart {
        *restart_at = Some(Instant::now() + inner.restart_backoff);
    }
}

async fn restart_if_active(inner: &Arc<Inner>, restart_at: &mut Option<Instant>) {
    {
        let state = lock(&inner.state);
        if state.phase != Phase::Active || state.available || state.child.is_some() {
            return;
        }
    }
    let spawned = match spawn_child(&inner.spawn).await {
        Ok(spawned) => spawned,
        Err(_) => {
            *restart_at = Some(Instant::now() + inner.restart_backoff);
            return;
        }
    };
    let SpawnedChild {
        child,
        process_group_id,
        stdin,
        stdout,
    } = spawned;
    let mut child = Some(child);
    let mut process_group_id = process_group_id;
    let epoch = {
        let mut state = lock(&inner.state);
        if state.phase != Phase::Active || state.available || state.child.is_some() {
            None
        } else if let Some(next_epoch) = state.epoch.checked_add(1) {
            state.epoch = next_epoch;
            state.available = true;
            state.exit_draining = false;
            state.reader_assigned = false;
            state.cancellation = EpochCancellation::new();
            state.child = child.take();
            state.process_group_id = process_group_id.take();
            Some(state.epoch)
        } else {
            state.phase = Phase::Stopped;
            None
        }
    };
    let Some(epoch) = epoch else {
        terminate_child(child.expect("uninstalled restart child"), process_group_id).await;
        return;
    };
    install_io_tasks(inner, epoch, stdin, stdout);
}

async fn stop_supervisor(inner: &Arc<Inner>) {
    let (child, process_group_id) = {
        let mut state = lock(&inner.state);
        state.phase = Phase::Stopped;
        state.available = false;
        state.exit_draining = false;
        state.writer.take();
        state.cancellation.cancel();
        (state.child.take(), state.process_group_id.take())
    };
    inner.fail_all();
    stop_epoch_reader(inner, None).await;
    if let Some(child) = child {
        terminate_child(child, process_group_id).await;
    }
    let tasks = std::mem::take(&mut *lock(&inner.event_tasks));
    for task in tasks {
        task.abort();
        let _ = task.await;
    }
}

async fn stop_epoch_reader(inner: &Arc<Inner>, epoch: Option<u64>) {
    let reader = {
        let mut reader = lock(&inner.reader);
        if reader
            .as_ref()
            .is_some_and(|reader| epoch.is_none_or(|epoch| reader.epoch == epoch))
        {
            reader.take()
        } else {
            None
        }
    };
    if let Some(reader) = reader {
        reader.abort.abort();
        if let Some(task) = reader.task {
            let _ = task.await;
        }
    }
}

async fn drain_epoch_reader(inner: &Arc<Inner>, epoch: u64) {
    let task = {
        let mut reader = lock(&inner.reader);
        reader
            .as_mut()
            .filter(|reader| reader.epoch == epoch)
            .and_then(|reader| reader.task.take())
    };
    if let Some(mut task) = task {
        if time::timeout(TERMINATE_GRACE, &mut task).await.is_err() {
            task.abort();
            let _ = task.await;
        }
    }
    let mut reader = lock(&inner.reader);
    if reader.as_ref().is_some_and(|reader| reader.epoch == epoch) {
        reader.take();
    }
}

async fn sleep_until_optional(deadline: Option<Instant>) {
    if let Some(deadline) = deadline {
        time::sleep_until(deadline).await;
    } else {
        std::future::pending::<()>().await;
    }
}

async fn terminate_child(mut child: Child, process_group_id: Option<u32>) {
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    {
        let deadline = Instant::now() + TERMINATE_GRACE;
        kill_process_group(process_group_id, libc::SIGTERM);
        loop {
            match observe_child_exit(&mut child) {
                Ok(true) => {
                    kill_process_group(process_group_id, libc::SIGKILL);
                    reap_child(child).await;
                    return;
                }
                Ok(false) if Instant::now() < deadline => {
                    time::sleep(CHILD_EXIT_POLL_INTERVAL).await;
                }
                Ok(false) => {
                    kill_process_group(process_group_id, libc::SIGKILL);
                    let _ = child.start_kill();
                    reap_child(child).await;
                    return;
                }
                Err(()) => {
                    // This owner has not reaped the child, and a failed waitid does not reap it,
                    // so the leader still reserves the owned PID/PGID for this final signal.
                    kill_process_group(process_group_id, libc::SIGKILL);
                    let _ = child.start_kill();
                    reap_child(child).await;
                    return;
                }
            }
        }
    }
    #[cfg(all(
        unix,
        not(any(target_os = "linux", target_os = "android", target_os = "macos"))
    ))]
    {
        let _ = process_group_id;
        let deadline = Instant::now() + TERMINATE_GRACE;
        signal_child(&child, libc::SIGTERM);
        loop {
            match observe_child_exit(&mut child) {
                Ok(true) => {
                    reap_child(child).await;
                    return;
                }
                Ok(false) if Instant::now() < deadline => {
                    time::sleep(CHILD_EXIT_POLL_INTERVAL).await;
                }
                Ok(false) | Err(()) => {
                    let _ = child.start_kill();
                    reap_child(child).await;
                    return;
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = process_group_id;
        let _ = child.start_kill();
        reap_child(child).await;
    }
}

async fn reap_child(mut child: Child) {
    let _ = child.wait().await;
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
fn kill_process_group(process_group_id: Option<u32>, signal: libc::c_int) {
    let Some(process_group_id) = process_group_id.filter(|id| *id <= libc::pid_t::MAX as u32)
    else {
        return;
    };
    // Callers retain the unreaped Child leader, so this numeric PGID cannot be recycled.
    // SAFETY: kill does not dereference pointers, and the process group came from Child::id.
    unsafe {
        libc::kill(-(process_group_id as libc::pid_t), signal);
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
fn observe_child_exit(child: &mut Child) -> Result<bool, ()> {
    let pid = child.id().ok_or(())?;
    loop {
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        // SAFETY: waitid writes one siginfo_t, WNOWAIT preserves the waitable child,
        // and the PID comes from the still-owned Child handle.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid,
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == 0 {
            // SAFETY: successful waitid initialized the siginfo_t value.
            return Ok(unsafe { info.assume_init().si_pid() } != 0);
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err(());
        }
    }
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_os = "macos"))
))]
fn signal_child(child: &Child, signal: libc::c_int) {
    let Some(pid) = child.id().filter(|id| *id <= libc::pid_t::MAX as u32) else {
        return;
    };
    // The unreaped Child owns this PID when the signal is sent.
    // SAFETY: kill does not dereference pointers, and the PID came from Child::id.
    unsafe {
        libc::kill(pid as libc::pid_t, signal);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
fn observe_child_exit(child: &mut Child) -> Result<bool, ()> {
    // These targets retain no process-group ID, so reaping here cannot make a later
    // group signal target a recycled numeric identifier.
    child
        .try_wait()
        .map(|status| status.is_some())
        .map_err(|_| ())
}

fn candidate_not_live() -> RuntimeError {
    RuntimeError::CandidateNotLive(
        "process provider failed its publication liveness check".to_string(),
    )
}

fn accepts_dispatch(state: &ProcessState) -> bool {
    state.available
        && matches!(state.phase, Phase::Active | Phase::Retiring)
        && state
            .retirement_deadline
            .is_none_or(|deadline| Instant::now() < deadline)
}

fn operation_deadline(
    now: Instant,
    request_deadline: Instant,
    provider_timeout: Duration,
) -> Instant {
    request_deadline.min(now + provider_timeout)
}

fn rejection_for_state(state: &ProcessState, request_deadline: Instant) -> ProcessRequestError {
    expired_retirement_rejection(state, request_deadline)
        .unwrap_or(ProcessRequestError::Unavailable)
}

fn expired_retirement_rejection(
    state: &ProcessState,
    request_deadline: Instant,
) -> Option<ProcessRequestError> {
    state
        .retirement_deadline
        .filter(|retirement_deadline| Instant::now() >= *retirement_deadline)
        .map(|retirement_deadline| {
            if request_deadline <= retirement_deadline {
                ProcessRequestError::Timeout
            } else {
                ProcessRequestError::Unavailable
            }
        })
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::Path;

    use tempfile::TempDir;

    use super::*;
    use http::HeaderValue;

    use crate::authorization::protocol::{
        GuardedProviderBody, IncludedHeader, ProviderBodyReplacementDecodeError,
        ProviderRequestHeaders,
    };
    use crate::config::compiler::{AuthorizationProviderPlan, ProviderOutputPlan};
    use crate::config::load_and_compile_exact_config;
    use crate::safety::{WireBodyPool, WireBodyQuotaKey};

    fn write_python(directory: &TempDir, source: &str) -> PathBuf {
        let path = directory.path().join("provider.py");
        fs::write(&path, source).unwrap();
        path
    }

    fn plan(directory: &TempDir, script: &Path) -> ProcessProviderPlan {
        ProcessProviderPlan {
            command: PathBuf::from("/usr/bin/python3"),
            working_directory: directory.path().to_path_buf(),
            args: vec![script.to_string_lossy().into_owned()],
            timeout: Duration::from_secs(2),
            on_failure: CompiledProviderFailureMode::Deny,
            inherit_environment: false,
            pass_environment: vec![],
            environment: Default::default(),
            include_headers: vec![],
            include_request_body: false,
            allow_request_body_replacement: false,
            max_request_body_bytes: 1024,
            max_decoded_request_body_bytes: 1024,
            max_stdout_line_bytes: 4096,
            max_pending_requests: 8,
            restart_backoff: Duration::from_millis(25),
            retire_timeout: Duration::from_millis(100),
            outputs: Default::default(),
        }
    }

    fn request(id: &str) -> ProviderRequest<'_> {
        ProviderRequest {
            request_id: id,
            url: "https://example.test/resource",
            method: "GET",
            client_ip: "192.0.2.10",
            headers: None,
            body: None,
        }
    }

    fn request_deadline() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    fn body_guard() -> HttpWireBodyGuard {
        WireBodyPool::new(8 * 1024 * 1024, 8 * 1024 * 1024).begin_for_test(
            2 * 1024 * 1024,
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false),
        )
    }

    fn body_guard_with_pool() -> (Arc<WireBodyPool>, HttpWireBodyGuard) {
        let pool = WireBodyPool::new(8 * 1024 * 1024, 8 * 1024 * 1024);
        let guard = pool.clone().begin_for_test(
            2 * 1024 * 1024,
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false),
        );
        (pool, guard)
    }

    fn commit(provider: &ProcessProvider) {
        let mut guard = provider.publication_guard().unwrap();
        guard.commit();
    }

    async fn cleanup(provider: &ProcessProvider) {
        provider.cleanup(CleanupReason::Shutdown).await;
    }

    async fn production_decision(
        provider: &ProcessProvider,
        request_id: &str,
        url: &str,
        headers: &[(&str, &str)],
    ) -> ProcessDecision {
        let names = headers
            .iter()
            .map(|(name, _)| HeaderName::from_bytes(name.as_bytes()).unwrap())
            .collect::<Vec<_>>();
        let values = headers
            .iter()
            .map(|(_, value)| [HeaderValue::from_str(value).unwrap()])
            .collect::<Vec<_>>();
        let fields = names
            .iter()
            .zip(&values)
            .map(|(name, values)| IncludedHeader::new(name, values))
            .collect::<Vec<_>>();
        let headers = ProviderRequestHeaders::new(&fields).unwrap();
        provider
            .decide_effects_allowed_for_test(
                ProviderRequest {
                    request_id,
                    url,
                    method: "GET",
                    client_ip: "198.18.1.10",
                    headers: Some(&headers),
                    body: None,
                },
                &body_guard(),
                request_deadline(),
            )
            .await
            .unwrap()
    }

    fn assert_production_plan(
        fixture_root: &Path,
        name: &str,
        plan: &ProcessProviderPlan,
        command: &str,
        config: &str,
        include_headers: &[&str],
    ) {
        assert_eq!(plan.command, fixture_root.join(command), "{name} command");
        assert_eq!(
            plan.working_directory, fixture_root,
            "{name} working directory"
        );
        assert_eq!(plan.args, ["--config", config], "{name} arguments");
        assert_eq!(plan.timeout, Duration::from_secs(1), "{name} timeout");
        assert!(plan.on_failure == CompiledProviderFailureMode::Deny);
        assert!(!plan.inherit_environment, "{name} must use env_clear");
        assert!(
            plan.pass_environment.is_empty(),
            "{name} must not inherit named host variables"
        );
        assert_eq!(
            plan.environment
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str()))
                .collect::<Vec<_>>(),
            [("PATH", "/usr/bin:/bin")],
            "{name} must receive only its configured environment"
        );
        assert_eq!(
            plan.include_headers
                .iter()
                .map(HeaderName::as_str)
                .collect::<Vec<_>>(),
            include_headers,
            "{name} included headers"
        );
        assert!(!plan.include_request_body);
        assert!(!plan.allow_request_body_replacement);
        assert_eq!(plan.max_request_body_bytes, 10 * 1024 * 1024);
        assert_eq!(plan.max_decoded_request_body_bytes, 50 * 1024 * 1024);
        assert_eq!(plan.max_stdout_line_bytes, 1024 * 1024);
        assert_eq!(plan.max_pending_requests, 256);
        assert_eq!(plan.restart_backoff, Duration::from_secs(1));
        assert_eq!(plan.retire_timeout, Duration::from_secs(2 * 60 * 60));
        assert!(plan.outputs.is_empty());
    }

    async fn wait_for_file(path: &Path) {
        for _ in 0..100 {
            if path.exists() {
                return;
            }
            time::sleep(Duration::from_millis(10)).await;
        }
        panic!("helper did not create its synchronization file");
    }

    async fn wait_for_pid_file(path: &Path) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let last_observation = match fs::read_to_string(path) {
                Ok(contents) => match contents.trim().parse::<u32>() {
                    Ok(pid) if pid != 0 => return pid,
                    Ok(_) => "file contains invalid zero PID".to_string(),
                    Err(error) => format!("file contents {contents:?} are not a PID: {error}"),
                },
                Err(error) => format!("file could not be read: {error}"),
            };
            if Instant::now() >= deadline {
                panic!(
                    "timed out waiting for PID file {}: {last_observation}",
                    path.display(),
                );
            }
            time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn wait_for_complete_json_frame(path: &Path) -> (String, serde_json::Value) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let last_observation = match fs::read_to_string(path) {
                Ok(contents) => match serde_json::from_str(&contents) {
                    Ok(frame) => return (contents, frame),
                    Err(error) => {
                        format!("file contents {contents:?} are not a complete JSON frame: {error}")
                    }
                },
                Err(error) => format!("file could not be read: {error}"),
            };
            if Instant::now() >= deadline {
                panic!(
                    "timed out waiting for complete JSON frame in {}: {last_observation}",
                    path.display(),
                );
            }
            time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn publication_rejects_a_child_that_exited_after_eager_spawn() {
        let directory = TempDir::new().unwrap();
        let script = write_python(&directory, "raise SystemExit(0)\n");
        let provider = ProcessProvider::activate(plan(&directory, &script), || false)
            .await
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let exit_observed = {
                let mut state = lock(&provider.inner.state);
                if !state.available {
                    true
                } else {
                    let child = state
                        .child
                        .as_mut()
                        .expect("available candidate must retain its child");
                    observe_child_exit(child)
                        .expect("candidate child exit observation must remain available")
                }
            };
            if exit_observed {
                break;
            }
            if Instant::now() >= deadline {
                let state = lock(&provider.inner.state);
                panic!(
                    "candidate child did not exit before publication test deadline; \
                     phase={:?}, available={}, child_id={:?}",
                    state.phase,
                    state.available,
                    state.child.as_ref().and_then(Child::id),
                );
            }
            time::sleep(CHILD_EXIT_POLL_INTERVAL).await;
        }

        let error = match provider.publication_guard() {
            Ok(_) => panic!("exited candidate passed publication"),
            Err(error) => error,
        };
        assert!(matches!(error, RuntimeError::CandidateNotLive(_)));
        assert!(!error.to_string().contains(script.to_str().unwrap()));
        cleanup(&provider).await;
    }

    #[tokio::test]
    async fn process_provider_accepts_id_first_standard_serializer_whitespace() {
        let directory = TempDir::new().unwrap();
        let script = write_python(
            &directory,
            r#"import json, sys
for line in sys.stdin:
    request = json.loads(line)
    print(json.dumps({"id": request["id"], "type": "response", "decision": "allow"}), flush=True)
"#,
        );
        let provider = ProcessProvider::activate(plan(&directory, &script), || false)
            .await
            .unwrap();
        commit(&provider);

        assert_eq!(
            provider
                .decide_effects_allowed_for_test(
                    request("standard-serializer"),
                    &body_guard(),
                    request_deadline(),
                )
                .await,
            Ok(ProcessDecision::Allow)
        );
        cleanup(&provider).await;
    }

    #[tokio::test]
    async fn production_process_plans_activate_dispatch_retire_and_reactivate() {
        let fixture_root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/production");
        let loaded = load_and_compile_exact_config(&fixture_root.join("host-proxy.toml"))
            .expect("production host fixture must load and compile");
        let mut providers = loaded.compiled.reloadable_plan.authorization.providers;

        let AuthorizationProviderPlan::Process(gitlab_plan) = providers
            .remove("gitlab_acl")
            .expect("compiled GitLab process provider")
        else {
            panic!("gitlab_acl must compile as a process provider");
        };
        assert_production_plan(
            &fixture_root,
            "gitlab_acl",
            &gitlab_plan,
            "providers/gitlab_acl.py",
            "providers/gitlab_acl.json",
            &["x-aw-identity-token", "x-aw-policy-context"],
        );
        let gitlab_restart_plan = gitlab_plan.clone();
        let gitlab = ProcessProvider::activate(gitlab_plan, || false)
            .await
            .expect("activate compiled GitLab provider");
        assert_eq!(
            gitlab
                .inner
                .spawn
                .environment
                .iter()
                .map(|(key, value)| (key.to_str(), value.to_str()))
                .collect::<Vec<_>>(),
            [(Some("PATH"), Some("/usr/bin:/bin"))]
        );
        commit(&gitlab);
        assert_eq!(
            production_decision(
                &gitlab,
                "git-allow",
                "https://gitlab.example.test/group/internal.git",
                &[
                    ("x-aw-identity-token", "fixture-internal-identity"),
                    ("x-aw-policy-context", "fixture-internal"),
                ],
            )
            .await,
            ProcessDecision::Allow
        );
        assert_eq!(
            production_decision(
                &gitlab,
                "git-deny",
                "https://gitlab.example.test/group/private.git",
                &[("x-aw-identity-token", "fixture-internal-identity")],
            )
            .await,
            ProcessDecision::Deny
        );
        assert_eq!(
            production_decision(
                &gitlab,
                "git-missing",
                "https://gitlab.example.test/group/internal.git",
                &[("x-aw-policy-context", "fixture-internal")],
            )
            .await,
            ProcessDecision::Deny
        );
        assert_eq!(
            production_decision(
                &gitlab,
                "git-unknown",
                "https://gitlab.example.test/group/internal.git",
                &[
                    ("x-aw-identity-token", "fixture-unknown"),
                    ("x-aw-policy-context", "fixture-internal"),
                ],
            )
            .await,
            ProcessDecision::Deny
        );
        gitlab.retirement_started(CleanupReason::Retired);
        gitlab.cleanup(CleanupReason::Retired).await;
        assert_eq!(gitlab.cleanup_starts(), 1);
        assert_eq!(gitlab.cleanup_reasons(), [CleanupReason::Retired]);

        let gitlab = ProcessProvider::activate(gitlab_restart_plan, || false)
            .await
            .expect("reactivate cloned GitLab plan");
        commit(&gitlab);
        assert_eq!(
            production_decision(
                &gitlab,
                "git-restart",
                "https://gitlab.example.test/group/internal.git",
                &[
                    ("x-aw-identity-token", "fixture-internal-identity"),
                    ("x-aw-policy-context", "fixture-internal"),
                ],
            )
            .await,
            ProcessDecision::Allow
        );
        gitlab.retirement_started(CleanupReason::Retired);
        gitlab.cleanup(CleanupReason::Retired).await;

        let AuthorizationProviderPlan::Process(runner_plan) = providers
            .remove("agent_runner_acl")
            .expect("compiled agent-runner process provider")
        else {
            panic!("agent_runner_acl must compile as a process provider");
        };
        assert!(providers.is_empty(), "unexpected production providers");
        assert_production_plan(
            &fixture_root,
            "agent_runner_acl",
            &runner_plan,
            "providers/agent_runner_acl.py",
            "providers/agent_runner_acl.json",
            &["x-aw-identity-token"],
        );
        let runner_restart_plan = runner_plan.clone();
        let runner = ProcessProvider::activate(runner_plan, || false)
            .await
            .expect("activate compiled agent-runner provider");
        commit(&runner);
        assert_eq!(
            production_decision(
                &runner,
                "runner-allow",
                "https://runner.example.test/jobs/42",
                &[("x-aw-identity-token", "fixture-runner-identity")],
            )
            .await,
            ProcessDecision::Allow
        );
        assert_eq!(
            production_decision(
                &runner,
                "runner-deny",
                "https://runner.example.test/admin",
                &[("x-aw-identity-token", "fixture-runner-identity")],
            )
            .await,
            ProcessDecision::Deny
        );
        assert_eq!(
            production_decision(
                &runner,
                "runner-missing",
                "https://runner.example.test/jobs/42",
                &[],
            )
            .await,
            ProcessDecision::Deny
        );
        assert_eq!(
            production_decision(
                &runner,
                "runner-unknown",
                "https://runner.example.test/jobs/42",
                &[("x-aw-identity-token", "fixture-unknown")],
            )
            .await,
            ProcessDecision::Deny
        );
        runner.retirement_started(CleanupReason::Retired);
        runner.cleanup(CleanupReason::Retired).await;
        assert_eq!(runner.cleanup_starts(), 1);
        assert_eq!(runner.cleanup_reasons(), [CleanupReason::Retired]);

        let runner = ProcessProvider::activate(runner_restart_plan, || false)
            .await
            .expect("reactivate cloned agent-runner plan");
        commit(&runner);
        assert_eq!(
            production_decision(
                &runner,
                "runner-restart",
                "https://runner.example.test/jobs/42",
                &[("x-aw-identity-token", "fixture-runner-identity")],
            )
            .await,
            ProcessDecision::Allow
        );
        runner.retirement_started(CleanupReason::Retired);
        runner.cleanup(CleanupReason::Retired).await;
    }

    #[tokio::test]
    async fn responses_may_complete_out_of_request_order() {
        let directory = TempDir::new().unwrap();
        let script = write_python(
            &directory,
            r#"import json, sys
first = json.loads(sys.stdin.readline())
second = json.loads(sys.stdin.readline())
for request, decision in ((second, "deny"), (first, "allow")):
    print(json.dumps({"id": request["id"], "type": "response", "decision": decision}, separators=(",", ":")), flush=True)
"#,
        );
        let provider = ProcessProvider::activate(plan(&directory, &script), || false)
            .await
            .unwrap();
        commit(&provider);

        let first_guard = body_guard();
        let second_guard = body_guard();
        let first = provider.decide_effects_allowed_for_test(
            request("first"),
            &first_guard,
            request_deadline(),
        );
        let second = provider.decide_effects_allowed_for_test(
            request("second"),
            &second_guard,
            request_deadline(),
        );
        let (first, second) = tokio::join!(first, second);
        assert_eq!(first.unwrap(), ProcessDecision::Allow);
        assert_eq!(second.unwrap(), ProcessDecision::Deny);
        cleanup(&provider).await;
    }

    #[tokio::test]
    async fn clean_exit_drains_complete_responses_and_fails_only_unanswered_requests() {
        let directory = TempDir::new().unwrap();
        let first_read = directory.path().join("first-read");
        let second_read = directory.path().join("second-read");
        let third_read = directory.path().join("third-read");
        let script = write_python(
            &directory,
            r#"import json, pathlib, sys
first = json.loads(sys.stdin.readline())
pathlib.Path("first-read").write_text("ready")
second = json.loads(sys.stdin.readline())
pathlib.Path("second-read").write_text("ready")
json.loads(sys.stdin.readline())
pathlib.Path("third-read").write_text("ready")
print(json.dumps({"id": first["id"], "type": "response", "decision": "allow"}, separators=(",", ":")), flush=True)
print(json.dumps({"id": second["id"], "type": "response", "decision": "deny"}, separators=(",", ":")), flush=True)
"#,
        );
        let mut provider_plan = plan(&directory, &script);
        provider_plan.restart_backoff = Duration::from_secs(30);
        let provider = ProcessProvider::activate(provider_plan, || false)
            .await
            .unwrap();
        commit(&provider);

        let correlation_gate = Arc::new(tokio::sync::Barrier::new(2));
        *lock(&provider.inner.reader_correlation_gate) = Some(correlation_gate.clone());

        let first_provider = provider.clone();
        let first = tokio::spawn(async move {
            first_provider
                .decide_effects_allowed_for_test(
                    request("first"),
                    &body_guard(),
                    request_deadline(),
                )
                .await
        });
        wait_for_file(&first_read).await;
        let second_provider = provider.clone();
        let second = tokio::spawn(async move {
            second_provider
                .decide_effects_allowed_for_test(
                    request("second"),
                    &body_guard(),
                    request_deadline(),
                )
                .await
        });
        wait_for_file(&second_read).await;
        let third_provider = provider.clone();
        let third = tokio::spawn(async move {
            third_provider
                .decide_effects_allowed_for_test(
                    request("third"),
                    &body_guard(),
                    request_deadline(),
                )
                .await
        });
        wait_for_file(&third_read).await;

        correlation_gate.wait().await;
        for _ in 0..100 {
            if !lock(&provider.inner.state).available {
                break;
            }
            time::sleep(Duration::from_millis(10)).await;
        }
        assert!(!lock(&provider.inner.state).available);
        *lock(&provider.inner.reader_correlation_gate) = None;
        correlation_gate.wait().await;

        assert_eq!(first.await.unwrap(), Ok(ProcessDecision::Allow));
        assert_eq!(second.await.unwrap(), Ok(ProcessDecision::Deny));
        assert_eq!(third.await.unwrap(), Err(ProcessRequestError::Unavailable));
        assert_eq!(provider.inner.pending_count.load(Ordering::Acquire), 0);
        cleanup(&provider).await;
    }

    #[tokio::test]
    async fn malformed_and_unsolicited_stdout_are_provider_fatal() {
        for (name, output) in [
            ("malformed", "not-json"),
            (
                "unsolicited",
                r#"{"id":"not-pending","type":"response","decision":"allow"}"#,
            ),
        ] {
            let directory = TempDir::new().unwrap();
            let source =
                format!("import sys\nsys.stdin.readline()\nprint({output:?}, flush=True)\n");
            let script = write_python(&directory, &source);
            let mut provider_plan = plan(&directory, &script);
            provider_plan.restart_backoff = Duration::from_secs(30);
            let provider = ProcessProvider::activate(provider_plan, || false)
                .await
                .unwrap();
            commit(&provider);

            assert_eq!(
                provider
                    .decide_effects_allowed_for_test(
                        request(name),
                        &body_guard(),
                        request_deadline()
                    )
                    .await,
                Err(ProcessRequestError::Unavailable)
            );
            assert_eq!(
                provider
                    .decide_effects_allowed_for_test(
                        request("after-fatal"),
                        &body_guard(),
                        request_deadline()
                    )
                    .await,
                Err(ProcessRequestError::Unavailable)
            );
            cleanup(&provider).await;
        }
    }

    #[tokio::test]
    async fn max_pending_rejection_writes_no_frame() {
        let directory = TempDir::new().unwrap();
        let observed = directory.path().join("observed");
        let script = write_python(
            &directory,
            r#"import pathlib, sys, time
line = sys.stdin.readline()
pathlib.Path("observed").write_text(line)
time.sleep(30)
"#,
        );
        let mut provider_plan = plan(&directory, &script);
        provider_plan.max_pending_requests = 1;
        provider_plan.timeout = Duration::from_secs(30);
        let provider = ProcessProvider::activate(provider_plan, || false)
            .await
            .unwrap();
        commit(&provider);

        let first_provider = provider.clone();
        let first = tokio::spawn(async move {
            first_provider
                .decide_effects_allowed_for_test(
                    request("first"),
                    &body_guard(),
                    request_deadline(),
                )
                .await
        });
        wait_for_complete_json_frame(&observed).await;
        assert_eq!(
            provider
                .decide_effects_allowed_for_test(
                    request("second"),
                    &body_guard(),
                    request_deadline()
                )
                .await,
            Err(ProcessRequestError::AtCapacity)
        );
        let (written, frame) = wait_for_complete_json_frame(&observed).await;
        assert!(frame["id"].as_str().unwrap().starts_with('p'));
        assert_eq!(frame["requestId"], "first");
        assert_eq!(written.lines().count(), 1);

        cleanup(&provider).await;
        assert_eq!(first.await.unwrap(), Err(ProcessRequestError::Unavailable));
    }

    #[tokio::test]
    async fn active_failure_restarts_after_backoff_without_replay() {
        let directory = TempDir::new().unwrap();
        let script = write_python(
            &directory,
            r#"import json, pathlib, sys
counter = pathlib.Path("starts")
start = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(start))
for line in sys.stdin:
    request = json.loads(line)
    if start == 1:
        print("malformed", flush=True)
        raise SystemExit(0)
    print(json.dumps({"id": request["id"], "type": "response", "decision": "allow"}, separators=(",", ":")), flush=True)
"#,
        );
        let provider = ProcessProvider::activate(plan(&directory, &script), || false)
            .await
            .unwrap();
        commit(&provider);

        assert_eq!(
            provider
                .decide_effects_allowed_for_test(
                    request("failed-once"),
                    &body_guard(),
                    request_deadline()
                )
                .await,
            Err(ProcessRequestError::Unavailable)
        );
        let mut restarted = None;
        for attempt in 0..100 {
            match provider
                .decide_effects_allowed_for_test(
                    request(&format!("restart-{attempt}")),
                    &body_guard(),
                    request_deadline(),
                )
                .await
            {
                Ok(decision) => {
                    restarted = Some(decision);
                    break;
                }
                Err(ProcessRequestError::Unavailable) => {
                    time::sleep(Duration::from_millis(10)).await;
                }
                other => panic!("unexpected restart result: {other:?}"),
            }
        }
        assert_eq!(restarted, Some(ProcessDecision::Allow));
        assert_eq!(
            fs::read_to_string(directory.path().join("starts")).unwrap(),
            "2"
        );
        cleanup(&provider).await;
    }

    #[tokio::test]
    async fn repeated_logical_id_cannot_claim_a_late_duplicate_response() {
        let directory = TempDir::new().unwrap();
        let script = write_python(
            &directory,
            r#"import json, sys
first = json.loads(sys.stdin.readline())
print(json.dumps({"id": first["id"], "type": "response", "decision": "allow"}, separators=(",", ":")), flush=True)
second = json.loads(sys.stdin.readline())
print(json.dumps({"id": first["id"], "type": "response", "decision": "deny"}, separators=(",", ":")), flush=True)
print(json.dumps({"id": second["id"], "type": "response", "decision": "allow"}, separators=(",", ":")), flush=True)
"#,
        );
        let mut provider_plan = plan(&directory, &script);
        provider_plan.restart_backoff = Duration::from_secs(30);
        let provider = ProcessProvider::activate(provider_plan, || false)
            .await
            .unwrap();
        commit(&provider);

        assert_eq!(
            provider
                .decide_effects_allowed_for_test(
                    request("logical-x"),
                    &body_guard(),
                    request_deadline()
                )
                .await,
            Ok(ProcessDecision::Allow)
        );
        assert_eq!(
            provider
                .decide_effects_allowed_for_test(
                    request("logical-x"),
                    &body_guard(),
                    request_deadline()
                )
                .await,
            Err(ProcessRequestError::Unavailable)
        );
        cleanup(&provider).await;
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn inherited_old_stdout_is_joined_before_same_logical_id_restarts() {
        let directory = TempDir::new().unwrap();
        let script = write_python(
            &directory,
            r#"import json, pathlib, subprocess, sys
counter = pathlib.Path("starts")
start = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(start))
if start == 1:
    request = json.loads(sys.stdin.readline())
    code = 'import json,sys,time; time.sleep(.15); print(json.dumps({"id":sys.argv[1],"type":"response","decision":"deny"},separators=(",",":")),flush=True)'
    subprocess.Popen([sys.executable, "-c", code, request["id"]], stdout=sys.stdout)
    raise SystemExit(0)
for line in sys.stdin:
    request = json.loads(line)
    print(json.dumps({"id": request["id"], "type": "response", "decision": "allow"}, separators=(",", ":")), flush=True)
"#,
        );
        let provider = ProcessProvider::activate(plan(&directory, &script), || false)
            .await
            .unwrap();
        commit(&provider);

        assert_eq!(
            provider
                .decide_effects_allowed_for_test(
                    request("logical-x"),
                    &body_guard(),
                    request_deadline()
                )
                .await,
            Err(ProcessRequestError::Unavailable)
        );
        let mut restarted = None;
        for _ in 0..100 {
            match provider
                .decide_effects_allowed_for_test(
                    request("logical-x"),
                    &body_guard(),
                    request_deadline(),
                )
                .await
            {
                Ok(decision) => {
                    restarted = Some(decision);
                    break;
                }
                Err(ProcessRequestError::Unavailable) => {
                    time::sleep(Duration::from_millis(10)).await;
                }
                other => panic!("unexpected restart result: {other:?}"),
            }
        }
        assert_eq!(restarted, Some(ProcessDecision::Allow));
        cleanup(&provider).await;
    }

    #[tokio::test]
    async fn fatal_epoch_cancels_a_blocked_write_and_releases_capacity_for_restart() {
        let directory = TempDir::new().unwrap();
        let script = write_python(
            &directory,
            r#"import json, pathlib, subprocess, sys, time
counter = pathlib.Path("starts")
start = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(start))
if start == 1:
    subprocess.Popen([sys.executable, "-c", "import time; time.sleep(1)"], stdin=sys.stdin)
    time.sleep(.05)
    raise SystemExit(0)
for line in sys.stdin:
    request = json.loads(line)
    print(json.dumps({"id": request["id"], "type": "response", "decision": "allow"}, separators=(",", ":")), flush=True)
"#,
        );
        let mut provider_plan = plan(&directory, &script);
        provider_plan.max_pending_requests = 1;
        provider_plan.timeout = Duration::from_secs(5);
        let provider = ProcessProvider::activate(provider_plan, || false)
            .await
            .unwrap();
        commit(&provider);

        let name = HeaderName::from_static("x-large-included");
        let values = [
            HeaderValue::from_bytes(&vec![b'a'; 64 * 1024]).unwrap(),
            HeaderValue::from_bytes(&vec![b'b'; 64 * 1024]).unwrap(),
        ];
        let fields = [IncludedHeader::new(&name, &values)];
        let headers = ProviderRequestHeaders::new(&fields).unwrap();
        let mut blocked = request("logical-x");
        blocked.headers = Some(&headers);
        assert_eq!(
            time::timeout(
                Duration::from_secs(2),
                provider.decide_effects_allowed_for_test(
                    blocked,
                    &body_guard(),
                    request_deadline()
                ),
            )
            .await
            .expect("fatal epoch must interrupt the inherited blocked pipe"),
            Err(ProcessRequestError::Unavailable)
        );

        let mut restarted = None;
        for _ in 0..100 {
            match provider
                .decide_effects_allowed_for_test(
                    request("healthy"),
                    &body_guard(),
                    request_deadline(),
                )
                .await
            {
                Ok(decision) => {
                    restarted = Some(decision);
                    break;
                }
                Err(ProcessRequestError::Unavailable) => {
                    time::sleep(Duration::from_millis(10)).await;
                }
                other => panic!("unexpected restart result: {other:?}"),
            }
        }
        assert_eq!(restarted, Some(ProcessDecision::Allow));
        cleanup(&provider).await;
    }

    #[tokio::test]
    async fn environment_cwd_and_arguments_match_the_activated_plan() {
        let directory = TempDir::new().unwrap();
        let script = write_python(
            &directory,
            r#"import json, os, pathlib, sys
valid = (
    pathlib.Path.cwd() == pathlib.Path(sys.argv[1])
    and sys.argv[2] == "literal-argument"
    and os.environ.get("LITERAL_VALUE") == "configured"
    and os.environ.get("PASSED_VALUE") == "captured"
    and "HOME" not in os.environ
)
for line in sys.stdin:
    request = json.loads(line)
    decision = "allow" if valid else "deny"
    print(json.dumps({"id": request["id"], "type": "response", "decision": decision}, separators=(",", ":")), flush=True)
"#,
        );
        env::set_var("PASSED_VALUE", "captured");
        let mut provider_plan = plan(&directory, &script);
        provider_plan.args.extend([
            directory.path().to_string_lossy().into_owned(),
            "literal-argument".to_string(),
        ]);
        provider_plan.pass_environment = vec!["PASSED_VALUE".to_string()];
        provider_plan
            .environment
            .insert("LITERAL_VALUE".to_string(), "configured".to_string());
        let provider = ProcessProvider::activate(provider_plan, || false)
            .await
            .unwrap();
        env::remove_var("PASSED_VALUE");
        commit(&provider);

        assert_eq!(
            provider
                .decide_effects_allowed_for_test(
                    request("environment"),
                    &body_guard(),
                    request_deadline()
                )
                .await,
            Ok(ProcessDecision::Allow)
        );
        cleanup(&provider).await;
    }

    #[tokio::test]
    async fn missing_pass_environment_is_a_sanitized_activation_error() {
        let directory = TempDir::new().unwrap();
        let script = write_python(&directory, "raise SystemExit(0)\n");
        let missing = format!("ACL_PROXY_MISSING_ENV_{}", std::process::id());
        env::remove_var(&missing);
        for inherit_environment in [false, true] {
            let mut provider_plan = plan(&directory, &script);
            provider_plan.inherit_environment = inherit_environment;
            provider_plan.pass_environment = vec![missing.clone()];
            let error = ProcessProvider::activate(provider_plan, || false)
                .await
                .unwrap_err();
            assert_eq!(error, ProcessActivationError::EnvironmentUnavailable);
            assert!(!format!("{error:?} {error}").contains(&missing));
        }
    }

    #[tokio::test]
    async fn activation_accepts_strict_process_provider_capabilities() {
        let directory = TempDir::new().unwrap();
        let script = write_python(&directory, "raise SystemExit(0)\n");

        let mut candidate = plan(&directory, &script);
        candidate.outputs.insert(
            "credential".to_string(),
            ProviderOutputPlan::Bearer {
                required: false,
                transport_security: crate::config::compiler::CompiledTransportSecurity::TlsRequired,
            },
        );
        candidate.allow_request_body_replacement = true;
        candidate.include_request_body = true;

        let provider = ProcessProvider::activate(candidate, || false)
            .await
            .expect("strict capabilities use the guarded request and response protocols");
        cleanup(&provider).await;
    }

    #[tokio::test]
    async fn expanded_response_binds_required_outputs_and_replacement() {
        let directory = TempDir::new().unwrap();
        let script = write_python(
            &directory,
            r#"import json, sys
for line in sys.stdin:
    request = json.loads(line)
    response = {
        "id": request["id"],
        "type": "response",
        "decision": "allow",
        "values": {"token": "secret-marker"},
        "requestBody": {
            "encoding": "base64",
            "contentType": "application/json",
            "data": "e30="
        }
    }
    print(json.dumps(response, separators=(",", ":")), flush=True)
"#,
        );
        let mut provider_plan = plan(&directory, &script);
        provider_plan.outputs.insert(
            "token".to_string(),
            ProviderOutputPlan::Bearer {
                required: true,
                transport_security: crate::config::compiler::CompiledTransportSecurity::TlsRequired,
            },
        );
        provider_plan.allow_request_body_replacement = true;
        let provider = ProcessProvider::activate(provider_plan, || false)
            .await
            .unwrap();
        commit(&provider);

        let (pool, guard) = body_guard_with_pool();
        let decision = provider
            .decide_effects_allowed_for_test(request("expanded"), &guard, request_deadline())
            .await
            .unwrap();
        let ProcessDecision::AllowWithOutputs {
            credentials: Some(credentials),
            replacement: Some(replacement),
        } = decision
        else {
            panic!("expected typed credentials and replacement");
        };
        drop(credentials);
        assert_eq!(replacement.content_type(), Some("application/json"));
        let (_, _, replacement) = replacement.decode(&guard).unwrap();
        assert_eq!(
            replacement
                .segments()
                .flatten()
                .copied()
                .collect::<Vec<_>>(),
            b"{}"
        );
        drop(replacement);
        assert_eq!(pool.global_charge(), 0);
        cleanup(&provider).await;
    }

    #[tokio::test]
    async fn decision_only_invocation_ignores_expanded_requirements_and_accepts_plain_decisions() {
        let directory = TempDir::new().unwrap();
        let observed = directory.path().join("observed");
        let script = write_python(
            &directory,
            r#"import json, pathlib, sys
observed = []
for line in sys.stdin:
    request = json.loads(line)
    observed.append({"requestId": request["requestId"], "hasBody": "body" in request})
    pathlib.Path("observed").write_text(json.dumps(observed))
    decision = request["requestId"].split("-")[-1]
    print(json.dumps({"id": request["id"], "type": "response", "decision": decision}, separators=(",", ":")), flush=True)
"#,
        );
        let mut provider_plan = plan(&directory, &script);
        provider_plan.include_request_body = true;
        provider_plan.allow_request_body_replacement = true;
        provider_plan.outputs.insert(
            "token".to_string(),
            ProviderOutputPlan::Bearer {
                required: true,
                transport_security: crate::config::compiler::CompiledTransportSecurity::TlsRequired,
            },
        );
        let provider = ProcessProvider::activate(provider_plan, || false)
            .await
            .unwrap();
        commit(&provider);

        for (name, expected) in [
            ("outer-allow", ProcessDecision::Allow),
            ("outer-deny", ProcessDecision::Deny),
            ("outer-pass", ProcessDecision::Pass),
        ] {
            let actual = provider
                .decide(
                    request(name),
                    AuthorizationInvocationMode::DecisionOnly,
                    &body_guard(),
                    request_deadline(),
                )
                .await
                .unwrap();
            assert_eq!(actual, expected);
        }

        let observations: serde_json::Value =
            serde_json::from_slice(&fs::read(observed).unwrap()).unwrap();
        assert_eq!(observations.as_array().unwrap().len(), 3);
        assert!(observations
            .as_array()
            .unwrap()
            .iter()
            .all(|observation| observation["hasBody"] == false));
        cleanup(&provider).await;
    }

    #[tokio::test]
    async fn decision_only_invocation_strictly_rejects_effect_bearing_responses() {
        let directory = TempDir::new().unwrap();
        let script = write_python(
            &directory,
            r#"import json, sys
for line in sys.stdin:
    request = json.loads(line)
    if request["requestId"] == "values":
        effects = {"values": {"token": "must-not-be-retained"}}
    else:
        effects = {"requestBody": {"encoding": "base64", "data": "e30="}}
    response = {"id": request["id"], "type": "response", "decision": "allow", **effects}
    print(json.dumps(response, separators=(",", ":")), flush=True)
"#,
        );
        let mut provider_plan = plan(&directory, &script);
        provider_plan.allow_request_body_replacement = true;
        provider_plan.outputs.insert(
            "token".to_string(),
            ProviderOutputPlan::Bearer {
                required: true,
                transport_security: crate::config::compiler::CompiledTransportSecurity::TlsRequired,
            },
        );
        let provider = ProcessProvider::activate(provider_plan, || false)
            .await
            .unwrap();
        commit(&provider);

        let (pool, guard) = body_guard_with_pool();
        for name in ["values", "replacement"] {
            assert_eq!(
                provider
                    .decide(
                        request(name),
                        AuthorizationInvocationMode::DecisionOnly,
                        &guard,
                        request_deadline(),
                    )
                    .await,
                Err(ProcessRequestError::InvalidResponse)
            );
            assert_eq!(pool.global_charge(), 0, "{name} leaked guarded bytes");
        }
        cleanup(&provider).await;
    }

    #[tokio::test]
    async fn concurrent_full_and_decision_only_invocations_use_their_own_response_schema() {
        let directory = TempDir::new().unwrap();
        let script = write_python(
            &directory,
            r#"import json, sys
requests = [json.loads(sys.stdin.readline()), json.loads(sys.stdin.readline())]
for request in reversed(requests):
    if request["requestId"] == "full":
        assert "body" in request
        response = {"id": request["id"], "type": "response", "decision": "allow", "values": {"token": "full-secret"}}
    else:
        assert "body" not in request
        response = {"id": request["id"], "type": "response", "decision": "allow"}
    print(json.dumps(response, separators=(",", ":")), flush=True)
"#,
        );
        let mut provider_plan = plan(&directory, &script);
        provider_plan.include_request_body = true;
        provider_plan.outputs.insert(
            "token".to_string(),
            ProviderOutputPlan::Bearer {
                required: true,
                transport_security: crate::config::compiler::CompiledTransportSecurity::TlsRequired,
            },
        );
        let provider = ProcessProvider::activate(provider_plan, || false)
            .await
            .unwrap();
        commit(&provider);

        let decoded_guard = body_guard();
        let mut decoded = decoded_guard.buffer();
        decoded.try_extend_from_slice(b"full-body").unwrap();
        let decoded = decoded.finish();
        let mut full_request = request("full");
        full_request.body = Some(GuardedProviderBody {
            content_type: Some("text/plain"),
            content_encoding: Some("identity"),
            decoded: &decoded,
        });
        let full_guard = body_guard();
        let decision_guard = body_guard();
        let (full, decision_only) = tokio::join!(
            provider.decide(
                full_request,
                AuthorizationInvocationMode::EffectsAllowed,
                &full_guard,
                request_deadline(),
            ),
            provider.decide(
                request("outer"),
                AuthorizationInvocationMode::DecisionOnly,
                &decision_guard,
                request_deadline(),
            ),
        );

        assert!(matches!(
            full.unwrap(),
            ProcessDecision::AllowWithOutputs {
                credentials: Some(_),
                replacement: None,
            }
        ));
        assert_eq!(decision_only, Ok(ProcessDecision::Allow));
        cleanup(&provider).await;
    }

    #[tokio::test]
    async fn expanded_response_rejects_missing_output_and_invalid_replacement_without_fallback() {
        for (name, response, max_decoded_bytes) in [
            (
                "missing-output",
                r#"{"type":"response","decision":"allow"}"#,
                1024,
            ),
            (
                "malformed-replacement",
                r#"{"type":"response","decision":"allow","values":{"token":"present"},"requestBody":{"encoding":"base64","data":"%%%"}}"#,
                1024,
            ),
            (
                "noncanonical-base64-tail-bits",
                r#"{"type":"response","decision":"allow","values":{"token":"present"},"requestBody":{"encoding":"base64","data":"Zh=="}}"#,
                1024,
            ),
            (
                "wrong-body-container",
                r#"{"type":"response","decision":"allow","values":{"token":"present"},"requestBody":[]}"#,
                1024,
            ),
            (
                "wrong-content-encoding-shape",
                r#"{"type":"response","decision":"allow","values":{"token":"present"},"requestBody":{"encoding":"base64","contentEncoding":[],"data":"e30="}}"#,
                1024,
            ),
        ] {
            let directory = TempDir::new().unwrap();
            let response_literal = serde_json::to_string(response).unwrap();
            let source = format!(
                "import json, sys\nfor line in sys.stdin:\n request=json.loads(line)\n response={{'id':request['id']}}\n response.update(json.loads({response_literal}))\n print(json.dumps(response, separators=(',', ':')), flush=True)\n"
            );
            let script = write_python(&directory, &source);
            let mut provider_plan = plan(&directory, &script);
            provider_plan.outputs.insert(
                "token".to_string(),
                ProviderOutputPlan::Bearer {
                    required: true,
                    transport_security:
                        crate::config::compiler::CompiledTransportSecurity::TlsRequired,
                },
            );
            provider_plan.allow_request_body_replacement = true;
            provider_plan.max_decoded_request_body_bytes = max_decoded_bytes;
            let provider = ProcessProvider::activate(provider_plan, || false)
                .await
                .unwrap();
            commit(&provider);

            let (pool, guard) = body_guard_with_pool();
            assert_eq!(
                provider
                    .decide_effects_allowed_for_test(request(name), &guard, request_deadline())
                    .await,
                Err(ProcessRequestError::InvalidResponse),
                "{name} must terminate as an invalid provider response"
            );
            assert_eq!(pool.global_charge(), 0, "{name} leaked guarded bytes");
            cleanup(&provider).await;
        }
    }

    #[tokio::test]
    async fn provider_replacement_content_encoding_is_identity_only() {
        for (name, content_encoding, accepted) in [
            ("absent", None, true),
            ("identity", Some("identity"), true),
            ("gzip", Some("gzip"), false),
            ("mixed-case-identity", Some("Identity"), false),
        ] {
            let directory = TempDir::new().unwrap();
            let content_encoding_field = content_encoding
                .map(|value| format!(r#", "contentEncoding": {value:?}"#))
                .unwrap_or_default();
            let source = format!(
                r#"import json, sys
for line in sys.stdin:
 request=json.loads(line)
 print(json.dumps({{"id":request["id"],"type":"response","decision":"allow","requestBody":{{"encoding":"base64"{content_encoding_field},"data":"e30="}}}}, separators=(',', ':')), flush=True)
"#
            );
            let script = write_python(&directory, &source);
            let mut provider_plan = plan(&directory, &script);
            provider_plan.allow_request_body_replacement = true;
            let provider = ProcessProvider::activate(provider_plan, || false)
                .await
                .unwrap();
            commit(&provider);

            let (pool, guard) = body_guard_with_pool();
            let actual = provider
                .decide_effects_allowed_for_test(request(name), &guard, request_deadline())
                .await;
            if accepted {
                let ProcessDecision::AllowWithOutputs {
                    replacement: Some(replacement),
                    ..
                } = actual.expect("identity-coded replacement must be accepted")
                else {
                    panic!("{name} did not return its replacement");
                };
                assert_eq!(replacement.content_encoding(), content_encoding);
            } else {
                assert_eq!(actual, Err(ProcessRequestError::InvalidResponse), "{name}");
            }
            assert_eq!(pool.global_charge(), 0, "{name} leaked guarded bytes");
            cleanup(&provider).await;
        }
    }

    #[tokio::test]
    async fn expanded_response_preserves_provider_overflow_for_terminal_classification() {
        let directory = TempDir::new().unwrap();
        let script = write_python(
            &directory,
            r#"import json, sys
for line in sys.stdin:
    request = json.loads(line)
    response = {
        "id": request["id"],
        "type": "response",
        "decision": "allow",
        "requestBody": {"encoding": "base64", "data": "e30="}
    }
    print(json.dumps(response, separators=(",", ":")), flush=True)
"#,
        );
        let mut provider_plan = plan(&directory, &script);
        provider_plan.allow_request_body_replacement = true;
        provider_plan.max_decoded_request_body_bytes = 1;
        let provider = ProcessProvider::activate(provider_plan, || false)
            .await
            .unwrap();
        commit(&provider);

        let (pool, guard) = body_guard_with_pool();
        let decision = provider
            .decide_effects_allowed_for_test(
                request("oversized-replacement"),
                &guard,
                request_deadline(),
            )
            .await
            .unwrap();
        let ProcessDecision::AllowWithOutputs {
            credentials,
            replacement: Some(replacement),
        } = decision
        else {
            panic!("a canonical replacement must reach terminal classification");
        };
        drop(credentials);
        assert!(matches!(
            replacement.decode_with_limits(&guard, 1, usize::MAX),
            Err(ProviderBodyReplacementDecodeError::ProviderBodyLimit)
        ));
        assert_eq!(pool.global_charge(), 0);
        cleanup(&provider).await;
    }

    #[tokio::test]
    async fn expanded_assigned_shape_failure_does_not_restart_the_child() {
        let directory = TempDir::new().unwrap();
        let script = write_python(
            &directory,
            r#"import json, sys
count = 0
for line in sys.stdin:
    request = json.loads(line)
    if count == 0:
        print('{"id":"%s","type":"response","decision":"allow","unknown":{"nested":[1,{"ok":true}]}}' % request["id"], flush=True)
    else:
        print('{"id":"%s","type":"response","decision":"allow","values":{"token":"second-ok"}}' % request["id"], flush=True)
    count += 1
"#,
        );
        let mut provider_plan = plan(&directory, &script);
        provider_plan.outputs.insert(
            "token".to_string(),
            ProviderOutputPlan::Bearer {
                required: true,
                transport_security: crate::config::compiler::CompiledTransportSecurity::TlsRequired,
            },
        );
        let provider = ProcessProvider::activate(provider_plan, || false)
            .await
            .unwrap();
        commit(&provider);
        let (pool, guard) = body_guard_with_pool();

        assert_eq!(
            provider
                .decide_effects_allowed_for_test(
                    request("invalid-assigned"),
                    &guard,
                    request_deadline()
                )
                .await,
            Err(ProcessRequestError::InvalidResponse)
        );
        let second = provider
            .decide_effects_allowed_for_test(request("same-child"), &guard, request_deadline())
            .await
            .unwrap();
        assert!(matches!(second, ProcessDecision::AllowWithOutputs { .. }));
        drop(second);
        assert_eq!(pool.global_charge(), 0);
        cleanup(&provider).await;
    }

    #[tokio::test]
    async fn expanded_response_decodes_segmented_json_escapes_with_identity() {
        let directory = TempDir::new().unwrap();
        let script = write_python(
            &directory,
            r#"import json, sys
for line in sys.stdin:
    request = json.loads(line)
    print('{"id":"%s" , "type" : "response" , "decision" : "allow" , "values" : { "token" : "sec\\u0072et" } , "requestBody" : { "encoding" : "base64" , "contentType" : "text/plain" , "contentEncoding" : "identity" , "data" : "e3\\u0030=" }}' % request["id"], flush=True)
"#,
        );
        let mut provider_plan = plan(&directory, &script);
        provider_plan.outputs.insert(
            "token".to_string(),
            ProviderOutputPlan::Bearer {
                required: true,
                transport_security: crate::config::compiler::CompiledTransportSecurity::TlsRequired,
            },
        );
        provider_plan.allow_request_body_replacement = true;
        let provider = ProcessProvider::activate(provider_plan, || false)
            .await
            .unwrap();
        commit(&provider);
        let (pool, guard) = body_guard_with_pool();
        let ProcessDecision::AllowWithOutputs {
            credentials,
            replacement: Some(replacement),
        } = provider
            .decide_effects_allowed_for_test(request("escaped"), &guard, request_deadline())
            .await
            .unwrap()
        else {
            panic!("escaped guarded effects must be accepted");
        };
        let credentials = credentials.unwrap();
        let outputs = provider.outputs().unwrap();
        let staged = outputs
            .compact_provider_credential_wire(&credentials, &guard)
            .unwrap();
        let output = outputs.index("token").unwrap();
        let mut material = vec![0; staged.output_len(output).unwrap()];
        staged.copy_output(output, &mut material).unwrap();
        assert_eq!(material, b"secret");
        drop(staged);
        drop(credentials);
        assert_eq!(replacement.content_encoding(), Some("identity"));
        let (_, _, decoded) = replacement.decode(&guard).unwrap();
        assert_eq!(
            decoded.segments().flatten().copied().collect::<Vec<_>>(),
            b"{}"
        );
        drop(decoded);
        assert_eq!(pool.global_charge(), 0);
        cleanup(&provider).await;
    }

    #[tokio::test]
    async fn decision_only_dispatch_rejects_a_body_before_writing() {
        let directory = TempDir::new().unwrap();
        let observed = directory.path().join("observed");
        let script = write_python(
            &directory,
            r#"import pathlib, sys, time
line = sys.stdin.readline()
if line:
    pathlib.Path("observed").write_text(line)
time.sleep(30)
"#,
        );
        let provider = ProcessProvider::activate(plan(&directory, &script), || false)
            .await
            .unwrap();
        commit(&provider);

        let decoded_guard = body_guard();
        let mut decoded = decoded_guard.buffer();
        decoded.try_extend_from_slice(b"not-allowed").unwrap();
        let decoded = decoded.finish();
        let body = GuardedProviderBody {
            content_type: Some("text/plain"),
            content_encoding: None,
            decoded: &decoded,
        };
        let mut body_request = request("body");
        body_request.body = Some(body);
        assert_eq!(
            provider
                .decide(
                    body_request,
                    AuthorizationInvocationMode::DecisionOnly,
                    &body_guard(),
                    request_deadline(),
                )
                .await,
            Err(ProcessRequestError::InvalidRequest)
        );
        time::sleep(Duration::from_millis(25)).await;
        assert!(!observed.exists());
        cleanup(&provider).await;
    }

    #[tokio::test]
    async fn request_timeout_fails_the_epoch_and_releases_claimed_and_queued_admission() {
        let directory = TempDir::new().unwrap();
        let script = write_python(
            &directory,
            r#"import json, pathlib, sys, time
counter = pathlib.Path("starts")
start = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(start))
for line in sys.stdin:
    request = json.loads(line)
    if start == 1:
        sys.stdout.write('{"id":"' + request["id"] + '"')
        sys.stdout.flush()
        time.sleep(30)
    else:
        print(json.dumps({"id": request["id"], "type": "response", "decision": "allow"}, separators=(",", ":")), flush=True)
"#,
        );
        let mut provider_plan = plan(&directory, &script);
        provider_plan.timeout = Duration::from_millis(100);
        provider_plan.max_pending_requests = 2;
        let provider = ProcessProvider::activate(provider_plan, || false)
            .await
            .unwrap();
        commit(&provider);

        let first_provider = provider.clone();
        let first = tokio::spawn(async move {
            first_provider
                .decide_effects_allowed_for_test(
                    request("slow-prefix"),
                    &body_guard(),
                    request_deadline(),
                )
                .await
        });
        time::sleep(Duration::from_millis(20)).await;
        let second_provider = provider.clone();
        let second = tokio::spawn(async move {
            second_provider
                .decide_effects_allowed_for_test(
                    request("queued"),
                    &body_guard(),
                    request_deadline(),
                )
                .await
        });
        assert_eq!(first.await.unwrap(), Err(ProcessRequestError::Timeout));
        assert_eq!(second.await.unwrap(), Err(ProcessRequestError::Unavailable));

        let mut restarted = None;
        for attempt in 0..100 {
            match provider
                .decide_effects_allowed_for_test(
                    request(&format!("after-timeout-{attempt}")),
                    &body_guard(),
                    request_deadline(),
                )
                .await
            {
                Ok(decision) => {
                    restarted = Some(decision);
                    break;
                }
                Err(ProcessRequestError::Unavailable | ProcessRequestError::Timeout) => {
                    time::sleep(Duration::from_millis(10)).await;
                }
                other => panic!("unexpected timeout recovery result: {other:?}"),
            }
        }
        assert_eq!(restarted, Some(ProcessDecision::Allow));
        assert_eq!(provider.inner.pending_count.load(Ordering::Acquire), 0);
        cleanup(&provider).await;
    }

    #[tokio::test]
    async fn invalidated_epoch_cannot_deliver_an_already_claimed_response() {
        let directory = TempDir::new().unwrap();
        let script = write_python(
            &directory,
            r#"import json, signal, sys, time
def terminate(_signal, _frame):
    sys.stdout.write(',"type":"response","decision":"allow"}\n')
    sys.stdout.flush()
    time.sleep(1)

signal.signal(signal.SIGTERM, terminate)
first = json.loads(sys.stdin.readline())
json.loads(sys.stdin.readline())
sys.stdout.write('{"id":"' + first["id"] + '"')
sys.stdout.flush()
time.sleep(30)
"#,
        );
        let mut provider_plan = plan(&directory, &script);
        provider_plan.timeout = Duration::from_secs(5);
        let provider = ProcessProvider::activate(provider_plan, || false)
            .await
            .unwrap();
        commit(&provider);

        let first_provider = provider.clone();
        let first = tokio::spawn(async move {
            first_provider
                .decide_effects_allowed_for_test(
                    request("claimed"),
                    &body_guard(),
                    Instant::now() + Duration::from_secs(5),
                )
                .await
        });
        time::sleep(Duration::from_millis(10)).await;
        let second_provider = provider.clone();
        let second = tokio::spawn(async move {
            second_provider
                .decide_effects_allowed_for_test(
                    request("short-deadline"),
                    &body_guard(),
                    Instant::now() + Duration::from_millis(100),
                )
                .await
        });

        assert_eq!(second.await.unwrap(), Err(ProcessRequestError::Timeout));
        assert_eq!(
            time::timeout(Duration::from_secs(2), first)
                .await
                .unwrap()
                .unwrap(),
            Err(ProcessRequestError::Unavailable)
        );
        cleanup(&provider).await;
    }

    #[tokio::test]
    async fn absolute_timeout_covers_blocked_stdin_streaming() {
        let directory = TempDir::new().unwrap();
        let script = write_python(&directory, "import time\nwhile True:\n    time.sleep(1)\n");
        let mut provider_plan = plan(&directory, &script);
        provider_plan.timeout = Duration::from_millis(50);
        let provider = ProcessProvider::activate(provider_plan, || false)
            .await
            .unwrap();
        commit(&provider);

        let name = HeaderName::from_static("x-large-included");
        let values = [
            HeaderValue::from_bytes(&vec![b'a'; 64 * 1024]).unwrap(),
            HeaderValue::from_bytes(&vec![b'b'; 64 * 1024]).unwrap(),
        ];
        let fields = [IncludedHeader::new(&name, &values)];
        let headers = ProviderRequestHeaders::new(&fields).unwrap();
        let mut blocked = request("blocked-stdin");
        blocked.headers = Some(&headers);

        assert_eq!(
            time::timeout(
                Duration::from_secs(2),
                provider.decide_effects_allowed_for_test(
                    blocked,
                    &body_guard(),
                    request_deadline()
                ),
            )
            .await
            .expect("provider deadline must interrupt a blocked pipe write"),
            Err(ProcessRequestError::Timeout)
        );
        assert_eq!(provider.inner.pending_count.load(Ordering::Acquire), 0);
        cleanup(&provider).await;
    }

    #[tokio::test]
    async fn retirement_closes_admission_and_deadline_terminates_the_child() {
        let directory = TempDir::new().unwrap();
        let pid_path = directory.path().join("pid");
        let script = write_python(
            &directory,
            r#"import json, os, pathlib, sys
pathlib.Path("pid").write_text(str(os.getpid()))
for line in sys.stdin:
    request = json.loads(line)
    print(json.dumps({"id": request["id"], "type": "response", "decision": "allow"}, separators=(",", ":")), flush=True)
"#,
        );
        let provider = ProcessProvider::activate(plan(&directory, &script), || false)
            .await
            .unwrap();
        commit(&provider);
        let pid = wait_for_pid_file(&pid_path).await;

        provider.retirement_started(CleanupReason::Retired);
        assert_eq!(
            provider
                .decide_effects_allowed_for_test(
                    request("existing-lease"),
                    &body_guard(),
                    request_deadline(),
                )
                .await,
            Ok(ProcessDecision::Allow)
        );
        for _ in 0..100 {
            if !process_alive(pid) {
                break;
            }
            time::sleep(Duration::from_millis(10)).await;
        }
        assert!(!process_alive(pid));
        assert_eq!(
            provider
                .decide_effects_allowed_for_test(
                    request("after-deadline"),
                    &body_guard(),
                    request_deadline(),
                )
                .await,
            Err(ProcessRequestError::Unavailable)
        );
        cleanup(&provider).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_deadline_rejects_dispatch_before_timer_task_runs() {
        let directory = TempDir::new().unwrap();
        let script = write_python(&directory, "import time\nwhile True:\n    time.sleep(1)\n");
        let mut provider_plan = plan(&directory, &script);
        provider_plan.retire_timeout = Duration::from_millis(10);
        let provider = ProcessProvider::activate(provider_plan, || false)
            .await
            .unwrap();
        commit(&provider);
        provider.retirement_started(CleanupReason::Retired);

        // Block the only runtime thread so the absolute deadline passes while
        // the retirement timer task cannot update process state.
        std::thread::sleep(Duration::from_millis(30));
        {
            let state = lock(&provider.inner.state);
            assert_eq!(state.phase, Phase::Retiring);
            assert!(state.available);
        }
        assert_eq!(
            provider
                .decide_effects_allowed_for_test(
                    request("past-retirement-deadline"),
                    &body_guard(),
                    request_deadline(),
                )
                .await,
            Err(ProcessRequestError::Unavailable)
        );
        cleanup(&provider).await;
    }

    #[test]
    fn equal_retirement_and_request_deadlines_classify_as_timeout() {
        let retirement_deadline = Instant::now();
        let state = ProcessState {
            phase: Phase::Retiring,
            available: false,
            exit_draining: false,
            reader_assigned: false,
            retirement_deadline: Some(retirement_deadline),
            epoch: 1,
            child: None,
            process_group_id: None,
            writer: None,
            cancellation: EpochCancellation::new(),
        };

        assert_eq!(
            rejection_for_state(&state, retirement_deadline),
            ProcessRequestError::Timeout
        );
        assert_eq!(
            expired_retirement_rejection(&state, retirement_deadline),
            Some(ProcessRequestError::Timeout)
        );
        assert_eq!(
            rejection_for_state(&state, retirement_deadline + Duration::from_nanos(1)),
            ProcessRequestError::Unavailable
        );
        assert_eq!(
            expired_retirement_rejection(&state, retirement_deadline + Duration::from_nanos(1)),
            Some(ProcessRequestError::Unavailable)
        );
    }

    #[test]
    fn operation_deadline_is_the_earlier_provider_or_request_deadline() {
        let now = Instant::now();
        let request_deadline = now + Duration::from_millis(100);
        assert_eq!(
            operation_deadline(now, request_deadline, Duration::from_secs(1)),
            request_deadline
        );
        assert_eq!(
            operation_deadline(now, request_deadline, Duration::from_millis(25)),
            now + Duration::from_millis(25)
        );
    }

    #[test]
    fn correlation_ids_are_fixed_width_epoch_scoped_and_never_wrap() {
        let first = correlation_id(1, 1);
        let next_epoch = correlation_id(2, 1);
        assert_eq!(first.len(), PROCESS_PROVIDER_CORRELATION_ID_BYTES);
        assert_ne!(first, next_epoch);

        let counter = AtomicU64::new(u64::MAX - 1);
        assert_eq!(take_dispatch_counter(&counter), Some(u64::MAX - 1));
        assert_eq!(take_dispatch_counter(&counter), None);
        assert_eq!(counter.load(Ordering::Acquire), u64::MAX);
    }

    #[test]
    fn stale_reservation_brand_cannot_remove_a_new_claim() {
        let old = ReservationBrand { epoch: 1, token: 7 };
        let new = ReservationBrand { epoch: 2, token: 8 };
        let mut requests = RequestTable::default();
        requests.reserved.insert("wire".to_string(), new);

        assert!(!remove_reservation_if_brand(&mut requests, "wire", old));
        assert_eq!(requests.reserved.get("wire"), Some(&new));
    }

    #[tokio::test]
    async fn cleanup_is_idempotent_and_joins_the_child() {
        let directory = TempDir::new().unwrap();
        let script = write_python(&directory, "import time\nwhile True:\n    time.sleep(1)\n");
        let provider = ProcessProvider::activate(plan(&directory, &script), || false)
            .await
            .unwrap();
        commit(&provider);
        let pid = provider.child_id().unwrap();
        assert!(process_alive(pid));

        let ((), ()) = tokio::join!(cleanup(&provider), cleanup(&provider));
        assert!(!process_alive(pid));
    }

    #[tokio::test]
    async fn cleanup_allows_sigterm_handler_to_finish_within_grace() {
        let directory = TempDir::new().unwrap();
        let ready_path = directory.path().join("ready");
        let handled_path = directory.path().join("sigterm-handled");
        let script = write_python(
            &directory,
            r#"import pathlib, signal, time
def terminate(_signal, _frame):
    pathlib.Path("sigterm-handled").write_text("handled")
    raise SystemExit(0)

signal.signal(signal.SIGTERM, terminate)
pathlib.Path("ready").write_text("ready")
while True:
    time.sleep(1)
"#,
        );
        let provider = ProcessProvider::activate(plan(&directory, &script), || false)
            .await
            .unwrap();
        commit(&provider);
        wait_for_file(&ready_path).await;

        cleanup(&provider).await;

        assert_eq!(fs::read_to_string(handled_path).unwrap(), "handled");
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    #[tokio::test]
    async fn cleanup_kills_same_group_descendant_that_ignores_sigterm() {
        let directory = TempDir::new().unwrap();
        let descendant_pid = directory.path().join("descendant-pid");
        let script = write_python(
            &directory,
            r#"import subprocess, sys, time
code = 'import os,pathlib,signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); pathlib.Path("descendant-pid").write_text(str(os.getpid())); time.sleep(30)'
subprocess.Popen([sys.executable, "-c", code])
while True:
    time.sleep(1)
"#,
        );
        let provider = ProcessProvider::activate(plan(&directory, &script), || false)
            .await
            .unwrap();
        commit(&provider);
        let descendant_pid = wait_for_pid_file(&descendant_pid).await;
        assert!(process_alive(descendant_pid));

        cleanup(&provider).await;
        for _ in 0..100 {
            if !process_alive(descendant_pid) {
                return;
            }
            time::sleep(Duration::from_millis(10)).await;
        }
        panic!("same-group descendant survived provider cleanup");
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    #[tokio::test]
    async fn exit_observation_preserves_leader_until_group_signal_is_complete() {
        let mut command = Command::new("/usr/bin/python3");
        command
            .arg("-c")
            .arg("raise SystemExit(0)")
            .process_group(0)
            .kill_on_drop(true);
        let mut child = command.spawn().unwrap();
        let pid = child.id().unwrap();

        let mut exited = false;
        for _ in 0..100 {
            if observe_child_exit(&mut child).unwrap() {
                exited = true;
                break;
            }
            time::sleep(Duration::from_millis(10)).await;
        }
        assert!(exited);
        assert_eq!(child.id(), Some(pid));
        assert!(process_alive(pid));

        kill_process_group(Some(pid), libc::SIGKILL);
        reap_child(child).await;
        assert!(!process_alive(pid));
    }

    #[tokio::test]
    async fn cancellation_checks_bracket_environment_capture_and_spawn() {
        let directory = TempDir::new().unwrap();
        let script = write_python(&directory, "import time\nwhile True:\n    time.sleep(1)\n");
        let mut checks = 0usize;
        let error = ProcessProvider::activate(plan(&directory, &script), || {
            checks += 1;
            checks == 2
        })
        .await
        .unwrap_err();
        assert_eq!(error, ProcessActivationError::Cancelled);
        assert_eq!(checks, 2);

        checks = 0;
        let error = ProcessProvider::activate(plan(&directory, &script), || {
            checks += 1;
            checks == 4
        })
        .await
        .unwrap_err();
        assert_eq!(error, ProcessActivationError::Cancelled);
        assert_eq!(checks, 4);
    }

    fn process_alive(pid: u32) -> bool {
        // SAFETY: kill with signal zero performs no delivery and dereferences no pointers.
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
    }
}
