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
    read_decision_only_response, DecisionOnlyProviderDecision, DecisionOnlyResponse,
    DecisionOnlyResponseSchema,
};
use super::protocol::{
    read_provider_response_prefix, DirectProviderStdout, ProviderRequest, RequestStreamError,
    PROCESS_PROVIDER_CORRELATION_ID_BYTES,
};
use crate::config::v3_compile::{CompiledProviderFailureMode, ProcessProviderPlan};
use crate::runtime::{BoxFuture, CleanupReason, GenerationOwner, PublicationGuard, RuntimeError};
use crate::safety::{HttpWireBodyGuard, ProviderResponseCharge};

const CHILD_EXIT_POLL_INTERVAL: Duration = Duration::from_millis(20);
const TERMINATE_GRACE: Duration = Duration::from_secs(1);

pub(crate) struct ProcessProvider {
    inner: Arc<Inner>,
}

struct Inner {
    spawn: SpawnConfig,
    response_schema: DecisionOnlyResponseSchema,
    failure_mode: CompiledProviderFailureMode,
    include_headers: Box<[HeaderName]>,
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
    retirement_deadline: Option<Instant>,
    epoch: u64,
    child: Option<Child>,
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
    response: oneshot::Sender<Result<DecisionOnlyProviderDecision, ProcessRequestError>>,
    response_charge: ProviderResponseCharge,
    completed: Arc<AtomicBool>,
    request_deadline: Instant,
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
    task: JoinHandle<()>,
}

enum SupervisorEvent {
    Fatal { epoch: u64 },
    Stop,
}

struct SpawnedChild {
    child: Child,
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
    #[error("process provider requires unsupported response capabilities")]
    UnsupportedCapabilities,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProcessDecision {
    Allow,
    Deny,
    Pass,
}

impl ProcessProvider {
    pub(crate) async fn activate(
        plan: ProcessProviderPlan,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<Arc<Self>, ProcessActivationError> {
        let response_schema = DecisionOnlyResponseSchema::activate(&plan)
            .filter(|_| !plan.include_request_body)
            .ok_or(ProcessActivationError::UnsupportedCapabilities)?;
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
            max_request_body_bytes: _,
            max_decoded_request_body_bytes: _,
            max_stdout_line_bytes,
            max_pending_requests,
            restart_backoff,
            retire_timeout,
            outputs,
        } = plan;

        let _ = (
            include_request_body,
            allow_request_body_replacement,
            outputs,
        );

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
            terminate_child(spawned.child).await;
            return Err(error);
        }

        let (events, event_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner {
            spawn,
            response_schema,
            failure_mode: on_failure,
            include_headers: include_headers.into_boxed_slice(),
            timeout,
            max_stdout_line_bytes,
            max_pending_requests,
            restart_backoff,
            retire_timeout,
            state: Mutex::new(ProcessState {
                phase: Phase::Candidate,
                available: true,
                retirement_deadline: None,
                epoch: 1,
                child: Some(spawned.child),
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

    pub(crate) fn timeout(&self) -> Duration {
        self.inner.timeout
    }

    pub(crate) fn failure_mode(&self) -> CompiledProviderFailureMode {
        self.inner.failure_mode
    }

    pub(crate) async fn decide(
        &self,
        request: ProviderRequest<'_>,
        guard: &HttpWireBodyGuard,
        request_deadline: Instant,
    ) -> Result<ProcessDecision, ProcessRequestError> {
        if request.body.is_some() {
            return Err(ProcessRequestError::InvalidRequest);
        }
        let operation_deadline =
            operation_deadline(Instant::now(), request_deadline, self.inner.timeout);
        let (receiver, cancellation, epoch_cancellation) = match time::timeout_at(
            operation_deadline,
            self.dispatch_before_response(request, guard, request_deadline),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => return Err(ProcessRequestError::Timeout),
        };
        let result = tokio::select! {
            biased;
            _ = epoch_cancellation.cancelled() => {
                Err(self.inner.current_dispatch_error(request_deadline))
            }
            result = time::timeout_at(operation_deadline, receiver) => match result {
                Ok(Ok(result)) => result.map(ProcessDecision::from),
                Ok(Err(_)) => Err(ProcessRequestError::Unavailable),
                Err(_) => Err(ProcessRequestError::Timeout),
            }
        };
        drop(cancellation);
        result
    }

    async fn dispatch_before_response(
        &self,
        request: ProviderRequest<'_>,
        guard: &HttpWireBodyGuard,
        request_deadline: Instant,
    ) -> Result<
        (
            oneshot::Receiver<Result<DecisionOnlyProviderDecision, ProcessRequestError>>,
            RequestCancellationGuard,
            EpochCancellation,
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
        Ok((receiver, cancellation, epoch_cancellation))
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
        match child.try_wait() {
            Ok(None) => Ok(Box::new(ProcessPublicationGuard { state })),
            Ok(Some(_)) | Err(_) => {
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
    let mut child = command.spawn().map_err(|_| ProcessActivationError::Spawn)?;
    let Some(stdin) = child.stdin.take() else {
        terminate_child(child).await;
        return Err(ProcessActivationError::Spawn);
    };
    let Some(stdout) = child.stdout.take() else {
        terminate_child(child).await;
        return Err(ProcessActivationError::Spawn);
    };
    Ok(SpawnedChild {
        child,
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
    let previous = lock(&inner.reader).replace(EpochReader {
        epoch,
        task: reader_task,
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
                Ok(None) | Err(_) => {
                    inner.report_fatal(epoch);
                    return;
                }
            };
        let pending = {
            let mut requests = lock(&inner.requests);
            if requests
                .pending
                .get(continuation.id())
                .is_some_and(|pending| pending.epoch == epoch)
            {
                requests.pending.remove(continuation.id())
            } else {
                None
            }
        };
        let Some(pending) = pending else {
            inner.report_fatal(epoch);
            return;
        };
        let parsed = read_decision_only_response(
            &mut stdout,
            continuation,
            &pending.response_charge,
            &inner.response_schema,
        )
        .await;
        match parsed {
            Ok(response) => {
                if let Some(error) = inner.assigned_delivery_error(epoch, pending.request_deadline)
                {
                    pending.completed.store(true, Ordering::Release);
                    let _ = pending.response.send(Err(error));
                    inner.report_fatal(epoch);
                    return;
                }
                pending.completed.store(true, Ordering::Release);
                match response {
                    DecisionOnlyResponse::Decision(decision) => {
                        let _ = pending.response.send(Ok(decision));
                    }
                    DecisionOnlyResponse::AssignedFailure(_) => {
                        let _ = pending
                            .response
                            .send(Err(ProcessRequestError::InvalidResponse));
                    }
                }
            }
            Err(_) => {
                let error = inner.current_dispatch_error(pending.request_deadline);
                if error == ProcessRequestError::Timeout {
                    pending.completed.store(true, Ordering::Release);
                }
                let _ = pending.response.send(Err(error));
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

impl Inner {
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
        if state.epoch != epoch || !state.available {
            Some(rejection_for_state(&state, deadline))
        } else {
            expired_retirement_rejection(&state, deadline)
        }
    }

    fn report_fatal(&self, epoch: u64) {
        let should_report = {
            let mut state = lock(&self.state);
            if state.epoch != epoch || !state.available || state.phase == Phase::Stopped {
                false
            } else {
                state.available = false;
                state.writer.take();
                state.cancellation.cancel();
                true
            }
        };
        if should_report {
            self.fail_all();
            let _ = self.events.send(SupervisorEvent::Fatal { epoch });
        }
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
                let fatal_epoch = {
                    let mut state = lock(&inner.state);
                    if state.available {
                        match state.child.as_mut().map(Child::try_wait) {
                            Some(Ok(Some(_))) | Some(Err(_)) | None => Some(state.epoch),
                            Some(Ok(None)) => None,
                        }
                    } else {
                        None
                    }
                };
                if let Some(epoch) = fatal_epoch {
                    inner.report_fatal(epoch);
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
    let child = {
        let mut state = lock(&inner.state);
        if state.epoch != epoch {
            return;
        }
        state.writer.take();
        state.child.take()
    };
    stop_epoch_reader(inner, Some(epoch)).await;
    if let Some(child) = child {
        terminate_child(child).await;
    }
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
        stdin,
        stdout,
    } = spawned;
    let mut child = Some(child);
    let epoch = {
        let mut state = lock(&inner.state);
        if state.phase != Phase::Active || state.available || state.child.is_some() {
            None
        } else if let Some(next_epoch) = state.epoch.checked_add(1) {
            state.epoch = next_epoch;
            state.available = true;
            state.cancellation = EpochCancellation::new();
            state.child = child.take();
            Some(state.epoch)
        } else {
            state.phase = Phase::Stopped;
            None
        }
    };
    let Some(epoch) = epoch else {
        terminate_child(child.expect("uninstalled restart child")).await;
        return;
    };
    install_io_tasks(inner, epoch, stdin, stdout);
}

async fn stop_supervisor(inner: &Arc<Inner>) {
    let child = {
        let mut state = lock(&inner.state);
        state.phase = Phase::Stopped;
        state.available = false;
        state.writer.take();
        state.cancellation.cancel();
        state.child.take()
    };
    inner.fail_all();
    stop_epoch_reader(inner, None).await;
    if let Some(child) = child {
        terminate_child(child).await;
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
        reader.task.abort();
        let _ = reader.task.await;
    }
}

async fn sleep_until_optional(deadline: Option<Instant>) {
    if let Some(deadline) = deadline {
        time::sleep_until(deadline).await;
    } else {
        std::future::pending::<()>().await;
    }
}

async fn terminate_child(mut child: Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        // SAFETY: kill does not dereference pointers, and the PID came from this child handle.
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
    }
    #[cfg(not(unix))]
    let _ = child.start_kill();

    if time::timeout(TERMINATE_GRACE, child.wait()).await.is_err() {
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
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
        GuardedProviderBody, IncludedHeader, ProviderRequestHeaders,
    };
    use crate::config::v3_compile::ProviderOutputPlan;
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

    fn commit(provider: &ProcessProvider) {
        let mut guard = provider.publication_guard().unwrap();
        guard.commit();
    }

    async fn cleanup(provider: &ProcessProvider) {
        provider.cleanup(CleanupReason::Shutdown).await;
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

    #[tokio::test]
    async fn publication_rejects_a_child_that_exited_after_eager_spawn() {
        let directory = TempDir::new().unwrap();
        let script = write_python(&directory, "raise SystemExit(0)\n");
        let provider = ProcessProvider::activate(plan(&directory, &script), || false)
            .await
            .unwrap();
        time::sleep(Duration::from_millis(50)).await;

        let error = match provider.publication_guard() {
            Ok(_) => panic!("exited candidate passed publication"),
            Err(error) => error,
        };
        assert!(matches!(error, RuntimeError::CandidateNotLive(_)));
        assert!(!error.to_string().contains(script.to_str().unwrap()));
        cleanup(&provider).await;
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
        let first = provider.decide(request("first"), &first_guard, request_deadline());
        let second = provider.decide(request("second"), &second_guard, request_deadline());
        let (first, second) = tokio::join!(first, second);
        assert_eq!(first.unwrap(), ProcessDecision::Allow);
        assert_eq!(second.unwrap(), ProcessDecision::Deny);
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
                    .decide(request(name), &body_guard(), request_deadline())
                    .await,
                Err(ProcessRequestError::Unavailable)
            );
            assert_eq!(
                provider
                    .decide(request("after-fatal"), &body_guard(), request_deadline())
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
                .decide(request("first"), &body_guard(), request_deadline())
                .await
        });
        wait_for_file(&observed).await;
        assert_eq!(
            provider
                .decide(request("second"), &body_guard(), request_deadline())
                .await,
            Err(ProcessRequestError::AtCapacity)
        );
        time::sleep(Duration::from_millis(25)).await;
        let written = fs::read_to_string(&observed).unwrap();
        let frame: serde_json::Value = serde_json::from_str(&written).unwrap();
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
                .decide(request("failed-once"), &body_guard(), request_deadline())
                .await,
            Err(ProcessRequestError::Unavailable)
        );
        let mut restarted = None;
        for attempt in 0..100 {
            match provider
                .decide(
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
                .decide(request("logical-x"), &body_guard(), request_deadline())
                .await,
            Ok(ProcessDecision::Allow)
        );
        assert_eq!(
            provider
                .decide(request("logical-x"), &body_guard(), request_deadline())
                .await,
            Err(ProcessRequestError::Unavailable)
        );
        cleanup(&provider).await;
    }

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
                .decide(request("logical-x"), &body_guard(), request_deadline())
                .await,
            Err(ProcessRequestError::Unavailable)
        );
        let mut restarted = None;
        for _ in 0..100 {
            match provider
                .decide(request("logical-x"), &body_guard(), request_deadline())
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
                provider.decide(blocked, &body_guard(), request_deadline()),
            )
            .await
            .expect("fatal epoch must interrupt the inherited blocked pipe"),
            Err(ProcessRequestError::Unavailable)
        );

        let mut restarted = None;
        for _ in 0..100 {
            match provider
                .decide(request("healthy"), &body_guard(), request_deadline())
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
                .decide(request("environment"), &body_guard(), request_deadline())
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
    async fn activation_rejects_every_non_decision_only_capability() {
        let directory = TempDir::new().unwrap();
        let script = write_python(&directory, "raise SystemExit(0)\n");

        let mut with_output = plan(&directory, &script);
        with_output.outputs.insert(
            "credential".to_string(),
            ProviderOutputPlan::Bearer { required: false },
        );
        let mut with_replacement = plan(&directory, &script);
        with_replacement.allow_request_body_replacement = true;
        let mut with_body = plan(&directory, &script);
        with_body.include_request_body = true;

        for candidate in [with_output, with_replacement, with_body] {
            assert_eq!(
                ProcessProvider::activate(candidate, || false)
                    .await
                    .unwrap_err(),
                ProcessActivationError::UnsupportedCapabilities
            );
        }
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
                .decide(body_request, &body_guard(), request_deadline())
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
                .decide(request("slow-prefix"), &body_guard(), request_deadline())
                .await
        });
        time::sleep(Duration::from_millis(20)).await;
        let second_provider = provider.clone();
        let second = tokio::spawn(async move {
            second_provider
                .decide(request("queued"), &body_guard(), request_deadline())
                .await
        });
        assert_eq!(first.await.unwrap(), Err(ProcessRequestError::Timeout));
        assert_eq!(second.await.unwrap(), Err(ProcessRequestError::Unavailable));

        let mut restarted = None;
        for attempt in 0..100 {
            match provider
                .decide(
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
                Err(ProcessRequestError::Unavailable) => {
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
                .decide(
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
                .decide(
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
                provider.decide(blocked, &body_guard(), request_deadline()),
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
        wait_for_file(&pid_path).await;
        let pid: u32 = fs::read_to_string(&pid_path).unwrap().parse().unwrap();

        provider.retirement_started(CleanupReason::Retired);
        assert_eq!(
            provider
                .decide(request("existing-lease"), &body_guard(), request_deadline(),)
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
                .decide(request("after-deadline"), &body_guard(), request_deadline(),)
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
                .decide(
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
            retirement_deadline: Some(retirement_deadline),
            epoch: 1,
            child: None,
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
