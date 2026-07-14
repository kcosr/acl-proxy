use std::collections::{hash_map, HashMap, HashSet};
use std::fmt;
#[cfg(test)]
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::Instant;

use super::token::{
    generate_resume_token, OsResumeTokenSource, ResumeToken, ResumeTokenDigest, ResumeTokenSource,
};
use crate::config::compiler::PendingOperationLimit;

const MAX_TOKEN_ATTEMPTS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PendingTerminalCause {
    DeliveryFailed,
    RequestCancelled,
    RequestDeadline,
    ProviderDeadline,
    ResumeTokenDeadline,
    Shutdown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingDeadline {
    at: Instant,
    cause: PendingTerminalCause,
}

impl PendingDeadline {
    pub(crate) fn earliest(
        dispatch_start: Instant,
        request_deadline: Instant,
        provider_timeout: Duration,
        resume_token_ttl: Duration,
    ) -> Self {
        let mut selected = Self {
            at: request_deadline,
            cause: PendingTerminalCause::RequestDeadline,
        };
        let provider = dispatch_start + provider_timeout;
        if provider < selected.at {
            selected = Self {
                at: provider,
                cause: PendingTerminalCause::ProviderDeadline,
            };
        }
        let resume_token = dispatch_start + resume_token_ttl;
        if resume_token < selected.at {
            selected = Self {
                at: resume_token,
                cause: PendingTerminalCause::ResumeTokenDeadline,
            };
        }
        selected
    }

    pub(crate) fn at(self) -> Instant {
        self.at
    }

    pub(crate) fn cause(self) -> PendingTerminalCause {
        self.cause
    }
}

fn deadline_cause_at(
    operation: PendingDeadline,
    shutdown_deadline: Option<Instant>,
    occurred_at: Instant,
) -> Option<PendingTerminalCause> {
    let effective = match shutdown_deadline {
        Some(shutdown) if shutdown <= operation.at => PendingDeadline {
            at: shutdown,
            cause: PendingTerminalCause::Shutdown,
        },
        _ => operation,
    };
    (occurred_at >= effective.at).then_some(effective.cause)
}

fn terminal_cause_at(
    operation: PendingDeadline,
    shutdown_deadline: Option<Instant>,
    occurred_at: Instant,
    otherwise: PendingTerminalCause,
) -> PendingTerminalCause {
    deadline_cause_at(operation, shutdown_deadline, occurred_at).unwrap_or(otherwise)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct OperationId(u64);

struct PendingEntry<P> {
    digest: ResumeTokenDigest,
    deadline: PendingDeadline,
    payload: P,
}

struct ClaimedEntry {
    digest: ResumeTokenDigest,
    deadline: PendingDeadline,
    terminal_signal: Option<PendingTerminalCause>,
}

struct StoreState<P> {
    accepting: bool,
    shutdown_deadline: Option<Instant>,
    next_operation: u64,
    occupancy: usize,
    pending: HashMap<OperationId, PendingEntry<P>>,
    lookup: HashMap<ResumeTokenDigest, OperationId>,
    live_digests: HashSet<ResumeTokenDigest>,
    claimed: HashMap<OperationId, ClaimedEntry>,
}

struct StoreInner<P> {
    state: Mutex<StoreState<P>>,
    changed: Notify,
    #[cfg(test)]
    fail_next_reservation: std::sync::atomic::AtomicBool,
}

pub(crate) struct PendingCapabilityStore<P> {
    inner: Arc<StoreInner<P>>,
}

impl<P> Clone for PendingCapabilityStore<P> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<P> fmt::Debug for PendingCapabilityStore<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let counts = self.counts();
        formatter
            .debug_struct("PendingCapabilityStore")
            .field("accepting", &counts.accepting)
            .field("occupancy", &counts.occupancy)
            .field("pending", &counts.pending)
            .field("claimed", &counts.claimed)
            .finish()
    }
}

impl<P> PendingCapabilityStore<P> {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(StoreInner {
                state: Mutex::new(StoreState {
                    accepting: true,
                    shutdown_deadline: None,
                    next_operation: 1,
                    occupancy: 0,
                    pending: HashMap::new(),
                    lookup: HashMap::new(),
                    live_digests: HashSet::new(),
                    claimed: HashMap::new(),
                }),
                changed: Notify::new(),
                #[cfg(test)]
                fail_next_reservation: std::sync::atomic::AtomicBool::new(false),
            }),
        }
    }

    pub(crate) fn try_admit(
        &self,
        captured_limit: PendingOperationLimit,
        deadline: PendingDeadline,
        payload: P,
    ) -> Result<PendingAdmission<P>, PendingAdmissionError<P>> {
        self.try_admit_with_source(captured_limit, deadline, payload, &mut OsResumeTokenSource)
    }

    fn try_admit_with_source(
        &self,
        captured_limit: PendingOperationLimit,
        deadline: PendingDeadline,
        payload: P,
        source: &mut impl ResumeTokenSource,
    ) -> Result<PendingAdmission<P>, PendingAdmissionError<P>> {
        let mut state = match self.inner.state.lock() {
            Ok(state) => state,
            Err(_) => {
                return Err(PendingAdmissionError::new(
                    PendingAdmissionErrorKind::Poisoned,
                    payload,
                ))
            }
        };
        if !state.accepting {
            return Err(PendingAdmissionError::new(
                PendingAdmissionErrorKind::Closed,
                payload,
            ));
        }
        if state.occupancy >= captured_limit.get() {
            return Err(PendingAdmissionError::new(
                PendingAdmissionErrorKind::AtCapacity,
                payload,
            ));
        }
        let Some(next_operation) = state.next_operation.checked_add(1) else {
            return Err(PendingAdmissionError::new(
                PendingAdmissionErrorKind::IdentifierExhausted,
                payload,
            ));
        };

        #[cfg(test)]
        if self
            .inner
            .fail_next_reservation
            .swap(false, Ordering::AcqRel)
        {
            return Err(PendingAdmissionError::new(
                PendingAdmissionErrorKind::Allocation,
                payload,
            ));
        }

        let mut selected = None;
        for _ in 0..MAX_TOKEN_ATTEMPTS {
            let token = match generate_resume_token(source) {
                Ok(token) => token,
                Err(()) => {
                    return Err(PendingAdmissionError::new(
                        PendingAdmissionErrorKind::RandomSource,
                        payload,
                    ))
                }
            };
            let digest = token.digest();
            if !state.live_digests.contains(&digest) {
                selected = Some((token, digest));
                break;
            }
        }
        let Some((token, digest)) = selected else {
            return Err(PendingAdmissionError::new(
                PendingAdmissionErrorKind::CollisionExhausted,
                payload,
            ));
        };

        let prospective_occupancy = state
            .occupancy
            .checked_add(1)
            .expect("store occupancy cannot exceed its finite maximum");
        let claim_reservation = prospective_occupancy
            .checked_sub(state.claimed.len())
            .expect("claimed count cannot exceed occupancy");
        if state.pending.try_reserve(1).is_err()
            || state.lookup.try_reserve(1).is_err()
            || state.live_digests.try_reserve(1).is_err()
            || state.claimed.try_reserve(claim_reservation).is_err()
        {
            return Err(PendingAdmissionError::new(
                PendingAdmissionErrorKind::Allocation,
                payload,
            ));
        }

        let operation = OperationId(state.next_operation);
        state.next_operation = next_operation;
        state.occupancy = prospective_occupancy;
        assert!(state.live_digests.insert(digest));
        assert!(state.lookup.insert(digest, operation).is_none());
        assert!(state
            .pending
            .insert(
                operation,
                PendingEntry {
                    digest,
                    deadline,
                    payload,
                },
            )
            .is_none());

        Ok(PendingAdmission {
            token: Some(token),
            handle: Some(PendingOperationGuard {
                store: self.clone(),
                operation,
                deadline,
            }),
        })
    }

    pub(crate) fn try_claim(
        &self,
        digest: ResumeTokenDigest,
    ) -> Result<CallbackClaimResult<P>, CallbackClaimError> {
        self.try_claim_inner(digest, None)
    }

    #[cfg(test)]
    pub(crate) fn try_claim_at(
        &self,
        digest: ResumeTokenDigest,
        now: Instant,
    ) -> Result<CallbackClaimResult<P>, CallbackClaimError> {
        self.try_claim_inner(digest, Some(now))
    }

    fn try_claim_inner(
        &self,
        digest: ResumeTokenDigest,
        fixed_now: Option<Instant>,
    ) -> Result<CallbackClaimResult<P>, CallbackClaimError> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| CallbackClaimError::Poisoned)?;
        let now = fixed_now.unwrap_or_else(Instant::now);
        let operation = state
            .lookup
            .remove(&digest)
            .ok_or(CallbackClaimError::Unknown)?;
        let entry = state
            .pending
            .remove(&operation)
            .expect("pending lookup and operation table remain atomic");
        debug_assert_eq!(entry.digest, digest);
        if let Some(cause) = deadline_cause_at(entry.deadline, state.shutdown_deadline, now) {
            assert!(state.live_digests.remove(&entry.digest));
            state.occupancy = state
                .occupancy
                .checked_sub(1)
                .expect("an expired pending operation contributes one occupancy unit");
            debug_assert_counts(&state);
            if state.occupancy == 0 {
                self.inner.changed.notify_waiters();
            }
            return Ok(CallbackClaimResult::Expired(TerminalOperation {
                cause,
                payload: entry.payload,
            }));
        }
        assert!(state
            .claimed
            .insert(
                operation,
                ClaimedEntry {
                    digest,
                    deadline: entry.deadline,
                    terminal_signal: None,
                },
            )
            .is_none());
        debug_assert_counts(&state);
        self.inner.changed.notify_waiters();
        Ok(CallbackClaimResult::Claimed(CallbackClaim {
            store: self.clone(),
            operation,
            payload: Some(entry.payload),
        }))
    }

    pub(crate) fn begin_shutdown(&self, drain_deadline: Option<Instant>) -> bool {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let was_accepting = std::mem::replace(&mut state.accepting, false);
        if let Some(deadline) = drain_deadline {
            state.shutdown_deadline = Some(
                state
                    .shutdown_deadline
                    .map_or(deadline, |current| current.min(deadline)),
            );
        }
        self.inner.changed.notify_waiters();
        was_accepting
    }

    pub(crate) fn final_cancel_all(&self, cause: PendingTerminalCause) -> FinalCancellation<P> {
        self.final_cancel_all_inner(cause, None)
    }

    #[cfg(test)]
    fn final_cancel_all_at(
        &self,
        cause: PendingTerminalCause,
        occurred_at: Instant,
    ) -> FinalCancellation<P> {
        self.final_cancel_all_inner(cause, Some(occurred_at))
    }

    fn final_cancel_all_inner(
        &self,
        cause: PendingTerminalCause,
        fixed_now: Option<Instant>,
    ) -> FinalCancellation<P> {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let occurred_at = fixed_now.unwrap_or_else(Instant::now);
        state.accepting = false;
        let shutdown_deadline = state.shutdown_deadline;
        let pending = std::mem::take(&mut state.pending);
        state.lookup.clear();
        for entry in pending.values() {
            assert!(state.live_digests.remove(&entry.digest));
        }
        state.occupancy = state
            .occupancy
            .checked_sub(pending.len())
            .expect("pending count cannot exceed occupancy");
        let mut signalled_claim = false;
        for claimed in state.claimed.values_mut() {
            if claimed.terminal_signal.is_none() {
                claimed.terminal_signal = Some(terminal_cause_at(
                    claimed.deadline,
                    shutdown_deadline,
                    occurred_at,
                    cause,
                ));
                signalled_claim = true;
            }
        }
        if signalled_claim || state.occupancy == 0 {
            self.inner.changed.notify_waiters();
        }
        debug_assert_counts(&state);
        FinalCancellation {
            cause,
            occurred_at,
            shutdown_deadline,
            pending: pending.into_values(),
        }
    }

    pub(crate) async fn wait_until_empty(&self) {
        loop {
            let changed = self.inner.changed.notified();
            let empty = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .occupancy
                == 0;
            if empty {
                return;
            }
            changed.await;
        }
    }

    pub(crate) fn counts(&self) -> CapabilityStoreCounts {
        let state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        CapabilityStoreCounts {
            accepting: state.accepting,
            occupancy: state.occupancy,
            pending: state.pending.len(),
            claimed: state.claimed.len(),
        }
    }

    #[cfg(test)]
    fn fail_next_reservation(&self) {
        self.inner
            .fail_next_reservation
            .store(true, Ordering::Release);
    }
}

fn debug_assert_counts<P>(state: &StoreState<P>) {
    debug_assert_eq!(state.occupancy, state.pending.len() + state.claimed.len());
    debug_assert_eq!(state.lookup.len(), state.pending.len());
    debug_assert_eq!(state.live_digests.len(), state.occupancy);
}

#[must_use = "a pending admission must be transferred to its operation coordinator"]
pub(crate) struct PendingAdmission<P> {
    token: Option<ResumeToken>,
    handle: Option<PendingOperationGuard<P>>,
}

impl<P> PendingAdmission<P> {
    pub(crate) fn token(&self) -> &ResumeToken {
        self.token
            .as_ref()
            .expect("an active pending admission owns its resume token")
    }

    pub(crate) fn into_parts(mut self) -> (ResumeToken, PendingOperationGuard<P>) {
        let token = self
            .token
            .take()
            .expect("an active pending admission owns its resume token");
        let handle = self
            .handle
            .take()
            .expect("an active pending admission owns its operation handle");
        (token, handle)
    }
}

impl<P> fmt::Debug for PendingAdmission<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingAdmission")
            .field("token", &self.token())
            .finish_non_exhaustive()
    }
}

pub(crate) struct PendingOperationGuard<P> {
    store: PendingCapabilityStore<P>,
    operation: OperationId,
    deadline: PendingDeadline,
}

impl<P> fmt::Debug for PendingOperationGuard<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingOperationGuard")
            .finish_non_exhaustive()
    }
}

impl<P> PendingOperationGuard<P> {
    pub(crate) fn signal_handle(&self) -> PendingOperationSignal<P> {
        PendingOperationSignal {
            store: self.store.clone(),
            operation: self.operation,
        }
    }

    pub(crate) fn finish_pending(&self, cause: PendingTerminalCause) -> PendingTerminalResult<P> {
        self.signal_handle().finish_pending(cause)
    }

    #[cfg(test)]
    fn finish_pending_at(
        &self,
        cause: PendingTerminalCause,
        occurred_at: Instant,
    ) -> PendingTerminalResult<P> {
        self.signal_handle().finish_pending_at(cause, occurred_at)
    }

    pub(crate) async fn expire_at_deadline(&self) -> PendingTerminalResult<P> {
        tokio::time::sleep_until(self.deadline.at()).await;
        self.finish_pending(self.deadline.cause())
    }
}

impl<P> Drop for PendingOperationGuard<P> {
    fn drop(&mut self) {
        if let PendingTerminalResult::Won(operation) = self
            .signal_handle()
            .finish_pending_after_owner_drop(PendingTerminalCause::RequestCancelled)
        {
            drop(operation);
        }
    }
}

pub(crate) struct PendingOperationSignal<P> {
    store: PendingCapabilityStore<P>,
    operation: OperationId,
}

impl<P> Clone for PendingOperationSignal<P> {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            operation: self.operation,
        }
    }
}

impl<P> fmt::Debug for PendingOperationSignal<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingOperationSignal")
            .finish_non_exhaustive()
    }
}

impl<P> PendingOperationSignal<P> {
    pub(crate) fn is_pending(&self) -> bool {
        self.store
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pending
            .contains_key(&self.operation)
    }

    pub(crate) async fn wait_until_not_pending(&self) {
        loop {
            let changed = self.store.inner.changed.notified();
            if !self.is_pending() {
                return;
            }
            changed.await;
        }
    }

    pub(crate) fn finish_pending(&self, cause: PendingTerminalCause) -> PendingTerminalResult<P> {
        self.finish_pending_inner(cause, None, false)
    }

    #[cfg(test)]
    fn finish_pending_at(
        &self,
        cause: PendingTerminalCause,
        occurred_at: Instant,
    ) -> PendingTerminalResult<P> {
        self.finish_pending_inner(cause, Some(occurred_at), false)
    }

    fn finish_pending_after_owner_drop(
        &self,
        cause: PendingTerminalCause,
    ) -> PendingTerminalResult<P> {
        self.finish_pending_inner(cause, None, true)
    }

    fn finish_pending_inner(
        &self,
        cause: PendingTerminalCause,
        fixed_now: Option<Instant>,
        recover_poison: bool,
    ) -> PendingTerminalResult<P> {
        let mut state = match self.store.inner.state.lock() {
            Ok(state) => state,
            Err(poisoned) if recover_poison => poisoned.into_inner(),
            Err(_) => return PendingTerminalResult::Poisoned,
        };
        let occurred_at = fixed_now.unwrap_or_else(Instant::now);
        let shutdown_deadline = state.shutdown_deadline;
        if let Some(entry) = state.pending.remove(&self.operation) {
            assert_eq!(state.lookup.remove(&entry.digest), Some(self.operation));
            assert!(state.live_digests.remove(&entry.digest));
            state.occupancy = state
                .occupancy
                .checked_sub(1)
                .expect("a pending operation contributes one occupancy unit");
            debug_assert_counts(&state);
            self.store.inner.changed.notify_waiters();
            return PendingTerminalResult::Won(TerminalOperation {
                cause: terminal_cause_at(entry.deadline, shutdown_deadline, occurred_at, cause),
                payload: entry.payload,
            });
        }
        if let Some(claimed) = state.claimed.get_mut(&self.operation) {
            let signal_recorded = if claimed.terminal_signal.is_none() {
                claimed.terminal_signal = Some(terminal_cause_at(
                    claimed.deadline,
                    shutdown_deadline,
                    occurred_at,
                    cause,
                ));
                self.store.inner.changed.notify_waiters();
                true
            } else {
                false
            };
            return PendingTerminalResult::ClaimOwns { signal_recorded };
        }
        PendingTerminalResult::AlreadyTerminal
    }
}

pub(crate) struct CallbackClaim<P> {
    store: PendingCapabilityStore<P>,
    operation: OperationId,
    payload: Option<P>,
}

enum CompletionClock {
    IgnoreDeadlines,
    Current,
    #[cfg(test)]
    Fixed(Instant),
}

impl<P> CallbackClaim<P> {
    pub(crate) fn payload(&self) -> &P {
        self.payload
            .as_ref()
            .expect("an active callback claim owns its payload")
    }

    pub(crate) fn payload_mut(&mut self) -> &mut P {
        self.payload
            .as_mut()
            .expect("an active callback claim owns its payload")
    }

    pub(crate) fn terminal_signal(&self) -> Option<PendingTerminalCause> {
        let state = self
            .store
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state
            .claimed
            .get(&self.operation)
            .and_then(|entry| entry.terminal_signal)
    }

    pub(crate) async fn wait_for_terminal_signal(&self) -> PendingTerminalCause {
        loop {
            let changed = self.store.inner.changed.notified();
            if let Some(cause) = self.terminal_signal() {
                return cause;
            }
            changed.await;
        }
    }

    pub(crate) fn complete(mut self) -> Result<P, TerminalOperation<P>> {
        self.complete_with_clock(CompletionClock::Current)
    }

    #[cfg(test)]
    pub(crate) fn complete_at(mut self, now: Instant) -> Result<P, TerminalOperation<P>> {
        self.complete_with_clock(CompletionClock::Fixed(now))
    }

    fn complete_with_clock(&mut self, clock: CompletionClock) -> Result<P, TerminalOperation<P>> {
        let terminal_cause = self.release_occupancy(clock);
        let payload = self
            .payload
            .take()
            .expect("an active callback claim owns its payload");
        match terminal_cause {
            Some(cause) => Err(TerminalOperation { cause, payload }),
            None => Ok(payload),
        }
    }

    fn release_occupancy(&mut self, clock: CompletionClock) -> Option<PendingTerminalCause> {
        let mut state = self
            .store
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = match clock {
            CompletionClock::IgnoreDeadlines => None,
            CompletionClock::Current => Some(Instant::now()),
            #[cfg(test)]
            CompletionClock::Fixed(now) => Some(now),
        };
        if !state.claimed.contains_key(&self.operation) {
            return None;
        }
        let entry = state
            .claimed
            .remove(&self.operation)
            .expect("the matching claimed entry is present");
        assert!(state.live_digests.remove(&entry.digest));
        state.occupancy = state
            .occupancy
            .checked_sub(1)
            .expect("a callback claim contributes one occupancy unit");
        debug_assert_counts(&state);
        if state.occupancy == 0 {
            self.store.inner.changed.notify_waiters();
        }
        entry.terminal_signal.or_else(|| {
            now.and_then(|now| deadline_cause_at(entry.deadline, state.shutdown_deadline, now))
        })
    }
}

impl<P> fmt::Debug for CallbackClaim<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallbackClaim")
            .field("terminal_signal", &self.terminal_signal())
            .finish_non_exhaustive()
    }
}

impl<P> Drop for CallbackClaim<P> {
    fn drop(&mut self) {
        self.release_occupancy(CompletionClock::IgnoreDeadlines);
    }
}

pub(crate) enum PendingTerminalResult<P> {
    Won(TerminalOperation<P>),
    ClaimOwns { signal_recorded: bool },
    AlreadyTerminal,
    Poisoned,
}

pub(crate) enum CallbackClaimResult<P> {
    Claimed(CallbackClaim<P>),
    Expired(TerminalOperation<P>),
}

impl<P> fmt::Debug for CallbackClaimResult<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Claimed(claim) => formatter.debug_tuple("Claimed").field(claim).finish(),
            Self::Expired(operation) => formatter.debug_tuple("Expired").field(operation).finish(),
        }
    }
}

impl<P> fmt::Debug for PendingTerminalResult<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Won(operation) => formatter.debug_tuple("Won").field(operation).finish(),
            Self::ClaimOwns { signal_recorded } => formatter
                .debug_struct("ClaimOwns")
                .field("signal_recorded", signal_recorded)
                .finish(),
            Self::AlreadyTerminal => formatter.write_str("AlreadyTerminal"),
            Self::Poisoned => formatter.write_str("Poisoned"),
        }
    }
}

pub(crate) struct TerminalOperation<P> {
    cause: PendingTerminalCause,
    payload: P,
}

impl<P> TerminalOperation<P> {
    pub(crate) fn cause(&self) -> PendingTerminalCause {
        self.cause
    }

    pub(crate) fn into_payload(self) -> P {
        self.payload
    }
}

impl<P> fmt::Debug for TerminalOperation<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TerminalOperation")
            .field("cause", &self.cause)
            .finish_non_exhaustive()
    }
}

pub(crate) struct FinalCancellation<P> {
    cause: PendingTerminalCause,
    occurred_at: Instant,
    shutdown_deadline: Option<Instant>,
    pending: hash_map::IntoValues<OperationId, PendingEntry<P>>,
}

impl<P> Iterator for FinalCancellation<P> {
    type Item = TerminalOperation<P>;

    fn next(&mut self) -> Option<Self::Item> {
        self.pending.next().map(|entry| TerminalOperation {
            cause: terminal_cause_at(
                entry.deadline,
                self.shutdown_deadline,
                self.occurred_at,
                self.cause,
            ),
            payload: entry.payload,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.pending.size_hint()
    }
}

impl<P> ExactSizeIterator for FinalCancellation<P> {}

impl<P> fmt::Debug for FinalCancellation<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalCancellation")
            .field("cause", &self.cause)
            .field("pending", &self.pending.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CapabilityStoreCounts {
    pub(crate) accepting: bool,
    pub(crate) occupancy: usize,
    pub(crate) pending: usize,
    pub(crate) claimed: usize,
}

pub(crate) struct PendingAdmissionError<P> {
    kind: PendingAdmissionErrorKind,
    payload: P,
}

impl<P> PendingAdmissionError<P> {
    fn new(kind: PendingAdmissionErrorKind, payload: P) -> Self {
        Self { kind, payload }
    }

    pub(crate) fn kind(&self) -> PendingAdmissionErrorKind {
        self.kind
    }

    pub(crate) fn into_payload(self) -> P {
        self.payload
    }
}

impl<P> fmt::Debug for PendingAdmissionError<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingAdmissionError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl<P> fmt::Display for PendingAdmissionError<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(formatter)
    }
}

impl<P> std::error::Error for PendingAdmissionError<P> {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PendingAdmissionErrorKind {
    Closed,
    AtCapacity,
    Allocation,
    RandomSource,
    CollisionExhausted,
    IdentifierExhausted,
    Poisoned,
}

impl fmt::Display for PendingAdmissionErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => formatter.write_str("pending capability admission is closed"),
            Self::AtCapacity => formatter.write_str("pending capability store is at capacity"),
            Self::Allocation => formatter.write_str("pending capability store allocation failed"),
            Self::RandomSource => formatter.write_str("resume token random source failed"),
            Self::CollisionExhausted => {
                formatter.write_str("resume token collision attempts were exhausted")
            }
            Self::IdentifierExhausted => {
                formatter.write_str("pending operation identifier space is exhausted")
            }
            Self::Poisoned => formatter.write_str("pending capability store state failed"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CallbackClaimError {
    Unknown,
    Poisoned,
}

impl fmt::Display for CallbackClaimError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => formatter.write_str("resume token is unknown or already consumed"),
            Self::Poisoned => formatter.write_str("pending capability store state failed"),
        }
    }
}

impl std::error::Error for CallbackClaimError {}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::super::token::RESUME_TOKEN_RANDOM_BYTES;
    use super::*;

    struct SequenceSource {
        values: VecDeque<Result<[u8; RESUME_TOKEN_RANDOM_BYTES], ()>>,
        calls: Arc<AtomicUsize>,
    }

    struct DropObserved(Arc<AtomicUsize>);

    impl Drop for DropObserved {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    impl SequenceSource {
        fn repeated(value: [u8; RESUME_TOKEN_RANDOM_BYTES], count: usize) -> Self {
            Self {
                values: std::iter::repeat_n(Ok(value), count).collect(),
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn failing() -> Self {
            Self {
                values: VecDeque::from([Err(())]),
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl ResumeTokenSource for SequenceSource {
        fn fill(&mut self, bytes: &mut [u8; RESUME_TOKEN_RANDOM_BYTES]) -> Result<(), ()> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            let value = self.values.pop_front().unwrap_or(Err(()))?;
            *bytes = value;
            Ok(())
        }
    }

    fn operation_limit(value: usize) -> PendingOperationLimit {
        PendingOperationLimit::try_new(value).expect("test limit is within the compiled hard bound")
    }

    #[test]
    fn pending_operation_limit_enforces_exact_binary_boundaries() {
        assert_eq!(PendingOperationLimit::try_new(0), None);
        assert_eq!(
            PendingOperationLimit::try_new(crate::config::compiler::MAX_PENDING_OPERATIONS)
                .map(PendingOperationLimit::get),
            Some(crate::config::compiler::MAX_PENDING_OPERATIONS)
        );
        assert_eq!(
            PendingOperationLimit::try_new(crate::config::compiler::MAX_PENDING_OPERATIONS + 1),
            None
        );
    }

    fn admit_fixed<P>(
        store: &PendingCapabilityStore<P>,
        limit: usize,
        payload: P,
        byte: u8,
    ) -> PendingAdmission<P> {
        store
            .try_admit_with_source(
                operation_limit(limit),
                future_deadline(),
                payload,
                &mut SequenceSource::repeated([byte; RESUME_TOKEN_RANDOM_BYTES], 1),
            )
            .unwrap_or_else(|error| panic!("fixed admission failed: {}", error.kind()))
    }

    fn future_deadline() -> PendingDeadline {
        let start = Instant::now();
        PendingDeadline::earliest(
            start,
            start + Duration::from_secs(60),
            Duration::from_secs(60),
            Duration::from_secs(60),
        )
    }

    fn claim_live<P>(
        store: &PendingCapabilityStore<P>,
        digest: ResumeTokenDigest,
    ) -> CallbackClaim<P> {
        match store.try_claim_at(digest, Instant::now()).unwrap() {
            CallbackClaimResult::Claimed(claim) => claim,
            CallbackClaimResult::Expired(_) => panic!("live callback unexpectedly expired"),
        }
    }

    #[test]
    fn callback_capability_binding_and_replay_matrix() {
        let store = PendingCapabilityStore::new();
        let admission = admit_fixed(&store, 4, "generation-7", 1);
        let digest = admission.token().digest();
        let (_token, handle) = admission.into_parts();

        let claim = claim_live(&store, digest);
        assert_eq!(claim.payload(), &"generation-7");
        assert_eq!(
            store.try_claim_at(digest, Instant::now()).unwrap_err(),
            CallbackClaimError::Unknown
        );
        assert!(matches!(
            handle.finish_pending(PendingTerminalCause::RequestCancelled),
            PendingTerminalResult::ClaimOwns {
                signal_recorded: true
            }
        ));
        assert_eq!(
            claim.terminal_signal(),
            Some(PendingTerminalCause::RequestCancelled)
        );
        let completion = claim.complete_at(Instant::now()).unwrap_err();
        assert_eq!(completion.cause(), PendingTerminalCause::RequestCancelled);
        assert_eq!(completion.into_payload(), "generation-7");
        assert_eq!(
            store.try_claim_at(digest, Instant::now()).unwrap_err(),
            CallbackClaimError::Unknown
        );
        assert_eq!(store.counts().occupancy, 0);
    }

    #[test]
    fn callback_admission_is_atomic_and_never_evicts() {
        let store = PendingCapabilityStore::new();
        let first = admit_fixed(&store, 2, "first", 1);
        let second = admit_fixed(&store, 2, "second", 2);

        let rejected = admit_error(&store, 1, "successor", 3);
        assert_eq!(rejected.kind(), PendingAdmissionErrorKind::AtCapacity);
        assert_eq!(rejected.into_payload(), "successor");
        assert_eq!(store.counts().occupancy, 2);

        let first = first.into_parts().1;
        let second_digest = second.token().digest();
        assert_eq!(
            won_payload(first.finish_pending(PendingTerminalCause::ResumeTokenDeadline)),
            "first"
        );
        assert_eq!(
            claim_live(&store, second_digest)
                .complete_at(Instant::now())
                .unwrap(),
            "second"
        );
        assert_eq!(store.counts().occupancy, 0);
    }

    fn admit_error<P>(
        store: &PendingCapabilityStore<P>,
        limit: usize,
        payload: P,
        byte: u8,
    ) -> PendingAdmissionError<P> {
        store
            .try_admit_with_source(
                operation_limit(limit),
                future_deadline(),
                payload,
                &mut SequenceSource::repeated([byte; RESUME_TOKEN_RANDOM_BYTES], 1),
            )
            .expect_err("admission unexpectedly succeeded")
    }

    fn won_payload<P>(result: PendingTerminalResult<P>) -> P {
        match result {
            PendingTerminalResult::Won(operation) => operation.into_payload(),
            other => panic!("terminal transition did not win: {other:?}"),
        }
    }

    #[test]
    fn callback_token_generation_is_bounded_and_fail_closed() {
        let fresh = PendingCapabilityStore::new();
        let mut failing = SequenceSource::failing();
        let error = fresh
            .try_admit_with_source(operation_limit(1), future_deadline(), "rng", &mut failing)
            .unwrap_err();
        assert_eq!(error.kind(), PendingAdmissionErrorKind::RandomSource);
        let state = fresh.inner.state.lock().unwrap();
        assert_eq!(state.pending.capacity(), 0);
        assert_eq!(state.lookup.capacity(), 0);
        assert_eq!(state.live_digests.capacity(), 0);
        assert_eq!(state.claimed.capacity(), 0);
        drop(state);

        let store = PendingCapabilityStore::new();
        let existing = admit_fixed(&store, 3, "existing", 9);
        let mut collisions = SequenceSource::repeated([9; RESUME_TOKEN_RANDOM_BYTES], 8);
        let collision_calls = collisions.calls.clone();
        let error = store
            .try_admit_with_source(
                operation_limit(3),
                future_deadline(),
                "collision",
                &mut collisions,
            )
            .unwrap_err();
        assert_eq!(error.kind(), PendingAdmissionErrorKind::CollisionExhausted);
        assert_eq!(error.into_payload(), "collision");
        assert_eq!(collision_calls.load(Ordering::Acquire), MAX_TOKEN_ATTEMPTS);

        let mut failing = SequenceSource::failing();
        let failure_calls = failing.calls.clone();
        let error = store
            .try_admit_with_source(operation_limit(3), future_deadline(), "rng", &mut failing)
            .unwrap_err();
        assert_eq!(error.kind(), PendingAdmissionErrorKind::RandomSource);
        assert_eq!(error.into_payload(), "rng");
        assert_eq!(failure_calls.load(Ordering::Acquire), 1);
        assert_eq!(store.counts().occupancy, 1);
        drop(existing);
    }

    #[test]
    fn webhook_three_way_deadline_defaults_and_equality() {
        let start = Instant::now();
        let request = start + Duration::from_secs(30);

        let request_wins = PendingDeadline::earliest(
            start,
            start + Duration::from_secs(5),
            Duration::from_secs(30),
            Duration::from_secs(20),
        );
        assert_eq!(request_wins.at(), start + Duration::from_secs(5));
        assert_eq!(request_wins.cause(), PendingTerminalCause::RequestDeadline);

        let ttl_wins = PendingDeadline::earliest(
            start,
            request,
            Duration::from_secs(30),
            Duration::from_secs(20),
        );
        assert_eq!(ttl_wins.at(), start + Duration::from_secs(20));
        assert_eq!(ttl_wins.cause(), PendingTerminalCause::ResumeTokenDeadline);

        let provider_wins = PendingDeadline::earliest(
            start,
            request,
            Duration::from_secs(10),
            Duration::from_secs(20),
        );
        assert_eq!(
            provider_wins.cause(),
            PendingTerminalCause::ProviderDeadline
        );

        let request_equality = PendingDeadline::earliest(
            start,
            request,
            Duration::from_secs(30),
            Duration::from_secs(30),
        );
        assert_eq!(
            request_equality.cause(),
            PendingTerminalCause::RequestDeadline
        );

        let provider_equality = PendingDeadline::earliest(
            start,
            start + Duration::from_secs(31),
            Duration::from_secs(20),
            Duration::from_secs(20),
        );
        assert_eq!(
            provider_equality.cause(),
            PendingTerminalCause::ProviderDeadline
        );
    }

    #[test]
    fn callback_claim_and_completion_enforce_expiry_at_equality() {
        let start = Instant::now();
        let deadline = PendingDeadline::earliest(
            start,
            start + Duration::from_secs(30),
            Duration::from_secs(10),
            Duration::from_secs(20),
        );
        let store = PendingCapabilityStore::new();
        let admission = store
            .try_admit_with_source(
                operation_limit(2),
                deadline,
                "expired-before-claim",
                &mut SequenceSource::repeated([1; RESUME_TOKEN_RANDOM_BYTES], 1),
            )
            .unwrap();
        let digest = admission.token().digest();
        let _handle = admission.into_parts().1;

        let CallbackClaimResult::Expired(operation) =
            store.try_claim_at(digest, deadline.at()).unwrap()
        else {
            panic!("deadline equality must prevent a callback claim");
        };
        assert_eq!(operation.cause(), PendingTerminalCause::ProviderDeadline);
        assert_eq!(operation.into_payload(), "expired-before-claim");
        assert_eq!(store.counts().occupancy, 0);

        let admission = store
            .try_admit_with_source(
                operation_limit(2),
                deadline,
                "expired-before-completion",
                &mut SequenceSource::repeated([2; RESUME_TOKEN_RANDOM_BYTES], 1),
            )
            .unwrap();
        let digest = admission.token().digest();
        let _handle = admission.into_parts().1;
        let CallbackClaimResult::Claimed(claim) = store
            .try_claim_at(digest, deadline.at() - Duration::from_nanos(1))
            .unwrap()
        else {
            panic!("claim before the deadline must succeed");
        };
        let operation = claim.complete_at(deadline.at()).unwrap_err();
        assert_eq!(operation.cause(), PendingTerminalCause::ProviderDeadline);
        assert_eq!(operation.into_payload(), "expired-before-completion");
        assert_eq!(store.counts().occupancy, 0);
    }

    #[tokio::test]
    async fn pending_operation_guard_abort_releases_record_and_payload() {
        let store = PendingCapabilityStore::new();
        let drops = Arc::new(AtomicUsize::new(0));
        let admission = admit_fixed(&store, 1, DropObserved(drops.clone()), 1);
        let digest = admission.token().digest();
        let (_token, guard) = admission.into_parts();
        let inert_signal = guard.signal_handle();
        drop(inert_signal);
        assert_eq!(store.counts().occupancy, 1);

        let coordinator = tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        coordinator.abort();
        assert!(coordinator.await.unwrap_err().is_cancelled());

        assert_eq!(store.counts().occupancy, 0);
        assert_eq!(drops.load(Ordering::Acquire), 1);
        assert_eq!(
            store.try_claim_at(digest, Instant::now()).unwrap_err(),
            CallbackClaimError::Unknown
        );
    }

    #[tokio::test]
    async fn pending_operation_guard_abort_after_claim_signals_exclusive_owner() {
        let store = PendingCapabilityStore::new();
        let admission = admit_fixed(&store, 1, 43usize, 1);
        let digest = admission.token().digest();
        let (_token, guard) = admission.into_parts();
        let coordinator = tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        let claim = claim_live(&store, digest);

        coordinator.abort();
        assert!(coordinator.await.unwrap_err().is_cancelled());
        assert_eq!(
            claim.terminal_signal(),
            Some(PendingTerminalCause::RequestCancelled)
        );
        assert_eq!(store.counts().occupancy, 1);
        let operation = claim.complete_at(Instant::now()).unwrap_err();
        assert_eq!(operation.cause(), PendingTerminalCause::RequestCancelled);
        assert_eq!(operation.into_payload(), 43);
        assert_eq!(store.counts().occupancy, 0);
    }

    #[tokio::test]
    async fn request_owned_deadline_future_expires_unclaimed_record() {
        let store = PendingCapabilityStore::new();
        let start = Instant::now();
        let deadline = PendingDeadline::earliest(
            start,
            start,
            Duration::from_secs(30),
            Duration::from_secs(20),
        );
        let admission = store
            .try_admit_with_source(
                operation_limit(1),
                deadline,
                "expired",
                &mut SequenceSource::repeated([4; RESUME_TOKEN_RANDOM_BYTES], 1),
            )
            .unwrap();
        let digest = admission.token().digest();
        let (_token, guard) = admission.into_parts();

        let operation = match guard.expire_at_deadline().await {
            PendingTerminalResult::Won(operation) => operation,
            other => panic!("deadline did not own terminal transition: {other:?}"),
        };
        assert_eq!(operation.cause(), PendingTerminalCause::RequestDeadline);
        assert_eq!(operation.into_payload(), "expired");
        assert_eq!(store.counts().occupancy, 0);
        assert_eq!(
            store.try_claim_at(digest, Instant::now()).unwrap_err(),
            CallbackClaimError::Unknown
        );
    }

    #[test]
    fn reloadable_pending_limit_can_raise_and_lower_without_eviction() {
        let store = PendingCapabilityStore::new();
        let old_first = admit_fixed(&store, 2, "old-first", 1);
        let old_first_digest = old_first.token().digest();
        let (_token, old_first_guard) = old_first.into_parts();

        let lowered = admit_error(&store, 1, "lowered", 2);
        assert_eq!(lowered.kind(), PendingAdmissionErrorKind::AtCapacity);
        assert_eq!(lowered.into_payload(), "lowered");

        let old_second = admit_fixed(&store, 2, "old-second", 3);
        let old_second_digest = old_second.token().digest();
        let (_token, old_second_guard) = old_second.into_parts();

        let successor = admit_fixed(&store, 3, "successor", 4);
        let successor_digest = successor.token().digest();
        let (_token, successor_guard) = successor.into_parts();
        assert_eq!(store.counts().occupancy, 3);

        let rejected = admit_error(&store, 1, "still-lowered", 5);
        assert_eq!(rejected.kind(), PendingAdmissionErrorKind::AtCapacity);
        assert_eq!(rejected.into_payload(), "still-lowered");
        assert_eq!(store.counts().occupancy, 3);

        assert_eq!(
            claim_live(&store, old_first_digest).complete().unwrap(),
            "old-first"
        );
        assert_eq!(
            claim_live(&store, old_second_digest).complete().unwrap(),
            "old-second"
        );
        assert_eq!(
            claim_live(&store, successor_digest).complete().unwrap(),
            "successor"
        );
        drop((old_first_guard, old_second_guard, successor_guard));
        assert_eq!(store.counts().occupancy, 0);
    }

    #[test]
    fn callback_admission_allocation_failure_restores_payload_and_occupancy() {
        let store = PendingCapabilityStore::new();
        store.fail_next_reservation();
        let error = store
            .try_admit(
                operation_limit(1),
                future_deadline(),
                String::from("owned payload"),
            )
            .unwrap_err();
        assert_eq!(error.kind(), PendingAdmissionErrorKind::Allocation);
        assert_eq!(error.into_payload(), "owned payload");
        assert_eq!(store.counts().occupancy, 0);
    }

    #[test]
    fn callback_deadline_delivery_and_cancellation_races_linearize() {
        let store = PendingCapabilityStore::new();
        let handle = admit_fixed(&store, 1, 17usize, 1).into_parts().1;
        let causes = [
            PendingTerminalCause::DeliveryFailed,
            PendingTerminalCause::RequestCancelled,
            PendingTerminalCause::RequestDeadline,
        ];
        let barrier = Arc::new(Barrier::new(causes.len()));
        let signal = handle.signal_handle();
        let workers = causes.map(|cause| {
            let signal = signal.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                signal.finish_pending(cause)
            })
        });
        let mut winners = Vec::new();
        let mut already_terminal = 0;
        for worker in workers {
            match worker.join().unwrap() {
                PendingTerminalResult::Won(operation) => winners.push(operation),
                PendingTerminalResult::AlreadyTerminal => already_terminal += 1,
                other => panic!("unexpected terminal race result: {other:?}"),
            }
        }
        assert_eq!(winners.len(), 1);
        assert_eq!(already_terminal, 2);
        assert_eq!(winners.pop().unwrap().into_payload(), 17);
        assert_eq!(store.counts().occupancy, 0);
    }

    #[test]
    fn callback_claim_delivery_deadline_and_cancellation_races_linearize() {
        let store = PendingCapabilityStore::new();
        let admission = admit_fixed(&store, 1, 23usize, 1);
        let digest = admission.token().digest();
        let handle = admission.into_parts().1;
        let claim = claim_live(&store, digest);
        let causes = [
            PendingTerminalCause::DeliveryFailed,
            PendingTerminalCause::ProviderDeadline,
            PendingTerminalCause::RequestCancelled,
        ];
        let barrier = Arc::new(Barrier::new(causes.len()));
        let signal = handle.signal_handle();
        let workers = causes.map(|cause| {
            let signal = signal.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                (cause, signal.finish_pending(cause))
            })
        });
        let mut recorded = 0;
        for worker in workers {
            let (_, result) = worker.join().unwrap();
            match result {
                PendingTerminalResult::ClaimOwns { signal_recorded } => {
                    recorded += usize::from(signal_recorded)
                }
                other => panic!("claim lost terminal ownership: {other:?}"),
            }
        }
        assert_eq!(recorded, 1);
        assert!(causes.contains(&claim.terminal_signal().unwrap()));
        assert_eq!(store.counts().occupancy, 1);
        let completion = claim.complete_at(Instant::now()).unwrap_err();
        assert!(causes.contains(&completion.cause()));
        assert_eq!(completion.into_payload(), 23);
    }

    #[tokio::test]
    async fn operation_signal_observes_claim_before_callback_processing() {
        let store = PendingCapabilityStore::new();
        let admission = admit_fixed(&store, 1, 31usize, 1);
        let digest = admission.token().digest();
        let handle = admission.into_parts().1;
        let signal = handle.signal_handle();
        let waiter = tokio::spawn(async move { signal.wait_until_not_pending().await });

        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        let claim = claim_live(&store, digest);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("claim wakes delivery cancellation")
            .unwrap();

        assert_eq!(claim.complete().unwrap(), 31);
        drop(handle);
    }

    #[test]
    fn callback_claim_drop_and_terminal_signal_race_release_exactly_once() {
        let store = PendingCapabilityStore::new();
        let drops = Arc::new(AtomicUsize::new(0));
        let admission = admit_fixed(&store, 1, DropObserved(drops.clone()), 1);
        let digest = admission.token().digest();
        let handle = admission.into_parts().1;
        let claim = claim_live(&store, digest);
        let barrier = Arc::new(Barrier::new(2));

        let drop_barrier = barrier.clone();
        let dropper = thread::spawn(move || {
            drop_barrier.wait();
            drop(claim);
        });
        let signal_barrier = barrier.clone();
        let signaler = thread::spawn(move || {
            signal_barrier.wait();
            handle.finish_pending(PendingTerminalCause::RequestCancelled)
        });

        dropper.join().unwrap();
        let result = signaler.join().unwrap();
        assert!(matches!(
            result,
            PendingTerminalResult::ClaimOwns { .. } | PendingTerminalResult::AlreadyTerminal
        ));
        assert_eq!(drops.load(Ordering::Acquire), 1);
        assert_eq!(store.counts().occupancy, 0);
    }

    #[test]
    fn callback_shutdown_drain_and_claim_races_linearize() {
        let store = PendingCapabilityStore::new();
        let admission = admit_fixed(&store, 1, 29usize, 1);
        let digest = admission.token().digest();
        let barrier = Arc::new(Barrier::new(2));
        let claim_store = store.clone();
        let claim_barrier = barrier.clone();
        let claim = thread::spawn(move || {
            claim_barrier.wait();
            claim_store.try_claim_at(digest, Instant::now())
        });
        let cancel_store = store.clone();
        let cancel_barrier = barrier.clone();
        let cancellation = thread::spawn(move || {
            cancel_barrier.wait();
            cancel_store
                .final_cancel_all(PendingTerminalCause::Shutdown)
                .collect::<Vec<_>>()
        });
        let claim = claim.join().unwrap();
        let cancellation = cancellation.join().unwrap();
        match claim {
            Ok(CallbackClaimResult::Claimed(claim)) => {
                assert!(cancellation.is_empty());
                assert_eq!(
                    claim.terminal_signal(),
                    Some(PendingTerminalCause::Shutdown)
                );
                assert_eq!(
                    claim
                        .complete_at(Instant::now())
                        .unwrap_err()
                        .into_payload(),
                    29
                );
            }
            Ok(CallbackClaimResult::Expired(operation)) => {
                assert!(cancellation.is_empty());
                assert_eq!(operation.into_payload(), 29);
            }
            Err(CallbackClaimError::Unknown) => {
                assert_eq!(cancellation.len(), 1);
                assert_eq!(cancellation.into_iter().next().unwrap().into_payload(), 29);
            }
            Err(error) => panic!("unexpected claim result: {error:?}"),
        }
        assert_eq!(store.counts().occupancy, 0);
    }

    #[test]
    fn webhook_shutdown_admission_race_linearizes() {
        let store = PendingCapabilityStore::new();
        let barrier = Arc::new(Barrier::new(2));
        let admission_store = store.clone();
        let admission_barrier = barrier.clone();
        let admission = thread::spawn(move || {
            admission_barrier.wait();
            admission_store.try_admit(operation_limit(1), future_deadline(), 31usize)
        });
        let close_store = store.clone();
        let close_barrier = barrier.clone();
        let close = thread::spawn(move || {
            close_barrier.wait();
            close_store.begin_shutdown(None)
        });
        let admission = admission.join().unwrap();
        close.join().unwrap();
        assert!(!store.counts().accepting);
        match admission {
            Ok(admission) => assert_eq!(
                won_payload(
                    admission
                        .into_parts()
                        .1
                        .finish_pending(PendingTerminalCause::Shutdown)
                ),
                31
            ),
            Err(error) => {
                assert_eq!(error.kind(), PendingAdmissionErrorKind::Closed);
                assert_eq!(error.into_payload(), 31);
            }
        }
        let later = store
            .try_admit(operation_limit(1), future_deadline(), 37usize)
            .unwrap_err();
        assert_eq!(later.kind(), PendingAdmissionErrorKind::Closed);
        assert_eq!(later.into_payload(), 37);
    }

    #[test]
    fn finite_shutdown_cutoff_blocks_delayed_claim_and_completion_at_equality() {
        let start = Instant::now();
        let operation_deadline = PendingDeadline::earliest(
            start,
            start + Duration::from_secs(30),
            Duration::from_secs(30),
            Duration::from_secs(20),
        );
        let drain_deadline = start + Duration::from_secs(5);
        let store = PendingCapabilityStore::new();

        let pending = store
            .try_admit_with_source(
                operation_limit(2),
                operation_deadline,
                "pending",
                &mut SequenceSource::repeated([7; RESUME_TOKEN_RANDOM_BYTES], 1),
            )
            .unwrap();
        let pending_digest = pending.token().digest();
        let _pending_handle = pending.into_parts().1;
        let claimed = store
            .try_admit_with_source(
                operation_limit(2),
                operation_deadline,
                "claimed",
                &mut SequenceSource::repeated([8; RESUME_TOKEN_RANDOM_BYTES], 1),
            )
            .unwrap();
        let claimed_digest = claimed.token().digest();
        let _claimed_handle = claimed.into_parts().1;
        let CallbackClaimResult::Claimed(claim) = store
            .try_claim_at(claimed_digest, drain_deadline - Duration::from_nanos(1))
            .unwrap()
        else {
            panic!("pre-cutoff claim must succeed");
        };

        assert!(store.begin_shutdown(Some(drain_deadline)));
        let CallbackClaimResult::Expired(operation) =
            store.try_claim_at(pending_digest, drain_deadline).unwrap()
        else {
            panic!("drain cutoff equality must prevent a delayed claim");
        };
        assert_eq!(operation.cause(), PendingTerminalCause::Shutdown);
        assert_eq!(operation.into_payload(), "pending");

        let operation = claim.complete_at(drain_deadline).unwrap_err();
        assert_eq!(operation.cause(), PendingTerminalCause::Shutdown);
        assert_eq!(operation.into_payload(), "claimed");
        assert_eq!(store.counts().occupancy, 0);
    }

    #[tokio::test]
    async fn pending_store_empty_waiter_wakes_for_pending_and_claimed_release() {
        let store = PendingCapabilityStore::new();
        let pending = admit_fixed(&store, 2, "pending", 1);
        let pending_handle = pending.into_parts().1;
        let claimed = admit_fixed(&store, 2, "claimed", 2);
        let claimed_digest = claimed.token().digest();
        let _claimed_handle = claimed.into_parts().1;
        let claim = claim_live(&store, claimed_digest);

        let wait_store = store.clone();
        let waiter = tokio::spawn(async move { wait_store.wait_until_empty().await });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        let _ = won_payload(pending_handle.finish_pending(PendingTerminalCause::RequestCancelled));
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        drop(claim);
        waiter.await.unwrap();
        assert_eq!(store.counts().occupancy, 0);
    }

    #[test]
    fn pending_callback_survives_reload_without_cross_generation_reuse() {
        #[derive(Debug, PartialEq, Eq)]
        struct BoundPayload {
            generation: u64,
            provider_activation: u64,
            output_schema: u64,
        }

        let store = PendingCapabilityStore::new();
        let old = admit_fixed(
            &store,
            4,
            BoundPayload {
                generation: 7,
                provider_activation: 11,
                output_schema: 13,
            },
            1,
        );
        let old_digest = old.token().digest();
        let _other = admit_fixed(
            &store,
            4,
            BoundPayload {
                generation: 7,
                provider_activation: 17,
                output_schema: 19,
            },
            2,
        );
        let successor = admit_error(
            &store,
            1,
            BoundPayload {
                generation: 8,
                provider_activation: 23,
                output_schema: 29,
            },
            3,
        );
        assert_eq!(successor.kind(), PendingAdmissionErrorKind::AtCapacity);
        assert_eq!(successor.into_payload().generation, 8);

        let old = claim_live(&store, old_digest)
            .complete_at(Instant::now())
            .unwrap();
        assert_eq!(
            old,
            BoundPayload {
                generation: 7,
                provider_activation: 11,
                output_schema: 13,
            }
        );
        assert_eq!(store.counts().occupancy, 1);
    }

    #[tokio::test]
    async fn post_claim_terminal_signal_wakes_the_exclusive_claim_owner() {
        let store = PendingCapabilityStore::new();
        let admission = admit_fixed(&store, 1, 41usize, 1);
        let digest = admission.token().digest();
        let handle = admission.into_parts().1;
        let claim = claim_live(&store, digest);
        let signal = tokio::spawn(async move {
            let cause = claim.wait_for_terminal_signal().await;
            let operation = claim.complete_at(Instant::now()).unwrap_err();
            (cause, operation.into_payload())
        });
        tokio::task::yield_now().await;
        assert!(matches!(
            handle.finish_pending(PendingTerminalCause::Shutdown),
            PendingTerminalResult::ClaimOwns {
                signal_recorded: true
            }
        ));
        assert_eq!(signal.await.unwrap(), (PendingTerminalCause::Shutdown, 41));
    }
}
