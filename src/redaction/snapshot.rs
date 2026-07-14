use std::alloc::{alloc, dealloc, Layout};
#[cfg(test)]
use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::mem::MaybeUninit;
use std::ptr::NonNull;
use std::sync::Arc;

use regex_automata::dfa::regex::Regex as DfaRegex;

use crate::config::compiler::{
    build_redaction_regex, checked_redaction_matcher_resident_bytes, redaction_literal_projection,
    redaction_literal_reference_bytes, redaction_literal_scratch_bytes,
    redaction_regex_resident_bytes, remaining_redaction_matcher_resident_bytes,
    CompiledRedactionPayloads, RedactionLiteralEdge as SecretEdge,
    RedactionLiteralInterval as Interval, RedactionLiteralNode as SecretNode, RedactionPlan,
    RedactionProfilePlan, RedactionRulePlan, MAX_REDACTION_MATCHER_SCRATCH_BYTES,
};
use crate::runtime::{RedactionProfileIndex, RedactionProfileRegistry};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PayloadClass {
    Text,
    Binary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PayloadLimit {
    EncodedHttpBody,
    DecodedHttpBody,
    WebSocketFrame,
    WebSocketMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RedactionLimits {
    pub(crate) max_body_bytes: usize,
    pub(crate) max_decoded_body_bytes: usize,
    pub(crate) max_frame_bytes: usize,
    pub(crate) max_message_bytes: usize,
    pub(crate) allow_permessage_deflate: bool,
    pub(crate) matcher_scratch_bytes: usize,
    pub(crate) compiled_matcher_resident_bytes: usize,
}

#[derive(PartialEq, Eq)]
pub(crate) struct RedactedPayload {
    pub(crate) bytes: Vec<u8>,
    pub(crate) replacements: usize,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum SnapshotError {
    #[error("redaction activation was cancelled")]
    ActivationCancelled,

    #[error("redaction profile {profile_index} has too many environment literal sources")]
    SourceCount { profile_index: usize },

    #[error(
        "redaction environment literal source {source_index} in rule {rule_index} of profile {profile_index} is unavailable"
    )]
    SourceUnavailable {
        profile_index: usize,
        rule_index: usize,
        source_index: usize,
    },

    #[error(
        "redaction environment literal source {source_index} in rule {rule_index} of profile {profile_index} is empty"
    )]
    SourceEmpty {
        profile_index: usize,
        rule_index: usize,
        source_index: usize,
    },

    #[error(
        "redaction environment literal source {source_index} in rule {rule_index} of profile {profile_index} is not valid UTF-8"
    )]
    SourceInvalidUtf8 {
        profile_index: usize,
        rule_index: usize,
        source_index: usize,
    },

    #[error(
        "redaction environment literal source {source_index} in rule {rule_index} of profile {profile_index} exceeds its byte limit"
    )]
    SourceTooLarge {
        profile_index: usize,
        rule_index: usize,
        source_index: usize,
    },

    #[error("redaction profile {profile_index} exceeds its environment literal byte limit")]
    AggregateTooLarge { profile_index: usize },

    #[error("redaction profile {profile_index} could not compile its literal matcher")]
    MatcherBuild { profile_index: usize },

    #[error("redaction profile {profile_index} exceeds the compiled matcher memory ceiling")]
    CompiledMatcherTooLarge { profile_index: usize },

    #[error(
        "redaction expression {expression_index} in rule {rule_index} of profile {profile_index} is not supported by the bounded matcher"
    )]
    ExpressionBuild {
        profile_index: usize,
        rule_index: usize,
        expression_index: usize,
    },

    #[error("redaction payload exceeds the configured {payload:?} byte limit of {limit}")]
    PayloadTooLarge { payload: PayloadLimit, limit: usize },

    #[error("redaction text payload is not valid UTF-8")]
    InvalidText,

    #[error("redaction matcher allocation failed")]
    AllocationFailed,

    #[error("redaction matcher scratch exceeds its {limit}-byte ceiling")]
    MatcherScratchExceeded { limit: usize },
}

pub(crate) struct RedactionSnapshot {
    profiles: Box<[ProfileHandle]>,
    compiled_matcher_resident_bytes: usize,
}

pub(crate) struct RedactionActivation {
    profile_registry: RedactionProfileRegistry,
    snapshot: RedactionSnapshot,
}

impl fmt::Debug for RedactionActivation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.snapshot.fmt(formatter)
    }
}

impl fmt::Debug for RedactionSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedactionSnapshot")
            .field("profile_count", &self.profiles.len())
            .finish()
    }
}

impl RedactionSnapshot {
    pub(crate) fn activate(
        plan: RedactionPlan,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<RedactionActivation, SnapshotError> {
        let profile_registry = RedactionProfileRegistry::from_names(plan.profiles.keys().cloned());
        let mut profiles = Vec::with_capacity(plan.profiles.len());
        let mut compiled_matcher_resident_bytes = 0usize;
        for (profile_index, (_, profile)) in plan.profiles.into_iter().enumerate() {
            profiles.push(ProfileHandle::activate(
                profile,
                profile_index,
                &mut compiled_matcher_resident_bytes,
                &mut is_cancelled,
            )?);
        }
        Ok(RedactionActivation {
            profile_registry,
            snapshot: Self {
                profiles: profiles.into_boxed_slice(),
                compiled_matcher_resident_bytes,
            },
        })
    }

    pub(crate) fn profile(&self, index: RedactionProfileIndex) -> Option<ProfileHandle> {
        self.profiles.get(index.get()).cloned()
    }

    pub(crate) fn len(&self) -> usize {
        self.profiles.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    pub(crate) fn compiled_matcher_resident_bytes(&self) -> usize {
        self.compiled_matcher_resident_bytes
    }
}

impl crate::runtime::RedactionSnapshot for RedactionSnapshot {
    fn profile(&self, index: RedactionProfileIndex) -> Option<ProfileHandle> {
        RedactionSnapshot::profile(self, index)
    }

    fn len(&self) -> usize {
        RedactionSnapshot::len(self)
    }

    fn is_empty(&self) -> bool {
        RedactionSnapshot::is_empty(self)
    }

    fn compiled_matcher_resident_bytes(&self) -> usize {
        RedactionSnapshot::compiled_matcher_resident_bytes(self)
    }
}

impl RedactionActivation {
    pub(crate) fn profile_index(&self, name: &str) -> Option<RedactionProfileIndex> {
        self.profile_registry.get(name)
    }

    pub(crate) fn profile(&self, name: &str) -> Option<ProfileHandle> {
        self.profile_index(name)
            .and_then(|index| self.snapshot.profile(index))
    }

    pub(crate) fn profile_registry(&self) -> &RedactionProfileRegistry {
        &self.profile_registry
    }

    pub(crate) fn into_parts(self) -> (RedactionSnapshot, RedactionProfileRegistry) {
        (self.snapshot, self.profile_registry)
    }
}

impl std::ops::Deref for RedactionActivation {
    type Target = RedactionSnapshot;

    fn deref(&self) -> &Self::Target {
        &self.snapshot
    }
}

#[derive(Clone)]
pub(crate) struct ProfileHandle(Arc<ProfileSnapshot>);

impl fmt::Debug for ProfileHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedactionProfileHandle")
            .finish_non_exhaustive()
    }
}

impl ProfileHandle {
    fn activate(
        plan: RedactionProfilePlan,
        profile_index: usize,
        snapshot_matcher_resident_bytes: &mut usize,
        is_cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<Self, SnapshotError> {
        Ok(Self(Arc::new(ProfileSnapshot::activate(
            plan,
            profile_index,
            snapshot_matcher_resident_bytes,
            is_cancelled,
        )?)))
    }

    pub(crate) fn limits(&self) -> RedactionLimits {
        self.0.limits
    }

    pub(crate) fn validate_encoded_http_body_size(
        &self,
        bytes: usize,
    ) -> Result<(), SnapshotError> {
        check_size(
            bytes,
            self.0.limits.max_body_bytes,
            PayloadLimit::EncodedHttpBody,
        )
    }

    pub(crate) fn validate_websocket_frame_size(&self, bytes: usize) -> Result<(), SnapshotError> {
        check_size(
            bytes,
            self.0.limits.max_frame_bytes,
            PayloadLimit::WebSocketFrame,
        )
    }

    pub(crate) fn validate_encoded_websocket_message_size(
        &self,
        bytes: usize,
    ) -> Result<(), SnapshotError> {
        check_size(
            bytes,
            self.0.limits.max_message_bytes,
            PayloadLimit::WebSocketMessage,
        )
    }

    pub(crate) fn redact_decoded_http_body(
        &self,
        payload: Vec<u8>,
    ) -> Result<RedactedPayload, SnapshotError> {
        let class = if std::str::from_utf8(&payload).is_ok() {
            PayloadClass::Text
        } else {
            PayloadClass::Binary
        };
        self.0.redact_complete(
            payload,
            class,
            self.0.limits.max_decoded_body_bytes,
            PayloadLimit::DecodedHttpBody,
        )
    }

    pub(crate) fn redact_websocket_message(
        &self,
        payload: Vec<u8>,
        class: PayloadClass,
    ) -> Result<RedactedPayload, SnapshotError> {
        self.0.redact_complete(
            payload,
            class,
            self.0.limits.max_message_bytes,
            PayloadLimit::WebSocketMessage,
        )
    }
}

struct ProfileSnapshot {
    replacement: Vec<u8>,
    limits: RedactionLimits,
    text_literals: LiteralMatcher,
    binary_literals: LiteralMatcher,
    text_expressions: Vec<DfaRegex>,
}

impl ProfileSnapshot {
    fn activate(
        plan: RedactionProfilePlan,
        profile_index: usize,
        snapshot_matcher_resident_bytes: &mut usize,
        is_cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<Self, SnapshotError> {
        let source_count = plan
            .rules
            .iter()
            .map(|rule| rule.literal_environment_variables.len())
            .try_fold(0usize, usize::checked_add)
            .unwrap_or(usize::MAX);
        if source_count > plan.max_environment_literal_sources {
            return Err(SnapshotError::SourceCount { profile_index });
        }

        let mut limits = RedactionLimits {
            max_body_bytes: plan.max_body_bytes,
            max_decoded_body_bytes: plan.max_decoded_body_bytes,
            max_frame_bytes: plan.max_frame_bytes,
            max_message_bytes: plan.max_message_bytes,
            allow_permessage_deflate: plan.allow_permessage_deflate,
            matcher_scratch_bytes: 0,
            compiled_matcher_resident_bytes: 0,
        };
        debug_assert!(limits.matcher_scratch_bytes <= MAX_REDACTION_MATCHER_SCRATCH_BYTES);

        let mut aggregate_bytes = 0usize;
        let mut rules = Vec::with_capacity(plan.rules.len());
        for (rule_index, rule) in plan.rules.into_iter().enumerate() {
            rules.push(ResolvedRule::activate(
                rule,
                profile_index,
                rule_index,
                plan.max_environment_literal_bytes,
                plan.max_environment_literal_total_bytes,
                &mut aggregate_bytes,
                is_cancelled,
            )?);
        }

        let text_budget = remaining_matcher_resident_budget(
            limits.compiled_matcher_resident_bytes,
            *snapshot_matcher_resident_bytes,
            profile_index,
        )?;
        let (text_literals, text_literal_bytes) =
            LiteralMatcher::build(&rules, PayloadClass::Text, profile_index, text_budget)?;
        let (profile_bytes, snapshot_bytes) = checked_redaction_matcher_resident_bytes(
            limits.compiled_matcher_resident_bytes,
            *snapshot_matcher_resident_bytes,
            text_literal_bytes,
        )
        .ok_or(SnapshotError::CompiledMatcherTooLarge { profile_index })?;
        limits.compiled_matcher_resident_bytes = profile_bytes;
        *snapshot_matcher_resident_bytes = snapshot_bytes;

        let binary_budget = remaining_matcher_resident_budget(
            limits.compiled_matcher_resident_bytes,
            *snapshot_matcher_resident_bytes,
            profile_index,
        )?;
        let (binary_literals, binary_literal_bytes) =
            LiteralMatcher::build(&rules, PayloadClass::Binary, profile_index, binary_budget)?;
        let (profile_bytes, snapshot_bytes) = checked_redaction_matcher_resident_bytes(
            limits.compiled_matcher_resident_bytes,
            *snapshot_matcher_resident_bytes,
            binary_literal_bytes,
        )
        .ok_or(SnapshotError::CompiledMatcherTooLarge { profile_index })?;
        limits.compiled_matcher_resident_bytes = profile_bytes;
        *snapshot_matcher_resident_bytes = snapshot_bytes;
        limits.matcher_scratch_bytes = text_literals
            .scratch_bytes()
            .max(binary_literals.scratch_bytes());

        let mut text_expressions = Vec::new();
        for (rule_index, rule) in rules.iter_mut().enumerate() {
            if !rule.applies_to(PayloadClass::Text) {
                continue;
            }
            for (expression_index, expression) in std::mem::take(&mut rule.expressions)
                .into_iter()
                .enumerate()
            {
                let remaining_budget = remaining_matcher_resident_budget(
                    limits.compiled_matcher_resident_bytes,
                    *snapshot_matcher_resident_bytes,
                    profile_index,
                )?;
                let expression = build_redaction_regex(expression.as_str(), remaining_budget)
                    .map_err(|_| SnapshotError::ExpressionBuild {
                        profile_index,
                        rule_index,
                        expression_index,
                    })?;
                let bytes = redaction_regex_resident_bytes(&expression).ok_or(
                    SnapshotError::ExpressionBuild {
                        profile_index,
                        rule_index,
                        expression_index,
                    },
                )?;
                let (profile_bytes, snapshot_bytes) = checked_redaction_matcher_resident_bytes(
                    limits.compiled_matcher_resident_bytes,
                    *snapshot_matcher_resident_bytes,
                    bytes,
                )
                .ok_or(SnapshotError::ExpressionBuild {
                    profile_index,
                    rule_index,
                    expression_index,
                })?;
                limits.compiled_matcher_resident_bytes = profile_bytes;
                *snapshot_matcher_resident_bytes = snapshot_bytes;
                text_expressions.push(expression);
            }
        }
        Ok(Self {
            replacement: plan.replacement,
            limits,
            text_literals,
            binary_literals,
            text_expressions,
        })
    }

    fn redact_complete(
        &self,
        payload: Vec<u8>,
        class: PayloadClass,
        limit: usize,
        payload_limit: PayloadLimit,
    ) -> Result<RedactedPayload, SnapshotError> {
        check_size(payload.len(), limit, payload_limit)?;
        if matches!(class, PayloadClass::Text) {
            std::str::from_utf8(&payload).map_err(|_| SnapshotError::InvalidText)?;
        }

        let literal_matcher = match class {
            PayloadClass::Text => &self.text_literals,
            PayloadClass::Binary => &self.binary_literals,
        };
        let (mut output, mut replacements) =
            literal_matcher.replace_bounded(payload, &self.replacement, limit, payload_limit)?;
        if matches!(class, PayloadClass::Text) {
            for expression in &self.text_expressions {
                let (next, count) = replace_regex_bounded(
                    output,
                    expression,
                    &self.replacement,
                    limit,
                    payload_limit,
                )?;
                output = next;
                replacements =
                    replacements
                        .checked_add(count)
                        .ok_or(SnapshotError::PayloadTooLarge {
                            payload: payload_limit,
                            limit,
                        })?;
            }
        }
        Ok(RedactedPayload {
            bytes: output,
            replacements,
        })
    }
}

fn remaining_matcher_resident_budget(
    profile_bytes: usize,
    snapshot_bytes: usize,
    profile_index: usize,
) -> Result<usize, SnapshotError> {
    remaining_redaction_matcher_resident_bytes(profile_bytes, snapshot_bytes)
        .ok_or(SnapshotError::CompiledMatcherTooLarge { profile_index })
}

struct LiteralMatcher {
    matcher: Option<ZeroizingAhoCorasick>,
    max_pattern_len: usize,
}

impl LiteralMatcher {
    fn build(
        rules: &[ResolvedRule],
        class: PayloadClass,
        profile_index: usize,
        build_budget: usize,
    ) -> Result<(Self, usize), SnapshotError> {
        let pattern_capacity = rules
            .iter()
            .filter(|rule| rule.applies_to(class))
            .map(ResolvedRule::literal_count)
            .try_fold(0usize, usize::checked_add)
            .unwrap_or(usize::MAX);
        let mut patterns =
            ZeroizingPatternRefs::new(pattern_capacity, build_budget, profile_index)?;
        let mut max_pattern_len = 0usize;
        for rule in rules.iter().filter(|rule| rule.applies_to(class)) {
            for literal in rule.literals.iter().map(Vec::as_slice) {
                max_pattern_len = max_pattern_len.max(literal.len());
                patterns
                    .push(literal)
                    .ok_or(SnapshotError::MatcherBuild { profile_index })?;
            }
            for literal in rule.environment_literals.iter().map(SecretBytes::as_bytes) {
                max_pattern_len = max_pattern_len.max(literal.len());
                patterns
                    .push(literal)
                    .ok_or(SnapshotError::MatcherBuild { profile_index })?;
            }
        }
        debug_assert_eq!(patterns.len(), pattern_capacity);
        checked_matcher_scratch_bytes(max_pattern_len)?;
        let matcher = ZeroizingAhoCorasick::build(patterns, profile_index, build_budget)?;
        let resident_bytes = matcher
            .as_ref()
            .map(ZeroizingAhoCorasick::resident_bytes)
            .transpose()
            .map_err(|()| SnapshotError::MatcherBuild { profile_index })?
            .unwrap_or(0);
        if resident_bytes > build_budget {
            return Err(SnapshotError::CompiledMatcherTooLarge { profile_index });
        }
        Ok((
            Self {
                matcher,
                max_pattern_len,
            },
            resident_bytes,
        ))
    }

    fn replace_bounded(
        &self,
        input: Vec<u8>,
        replacement: &[u8],
        limit: usize,
        payload_limit: PayloadLimit,
    ) -> Result<(Vec<u8>, usize), SnapshotError> {
        if self.matcher.is_none() {
            return Ok((input, 0));
        }
        let mut removed = 0usize;
        let mut count = 0usize;
        self.for_each_merged_interval(&input, |interval| {
            removed = removed.checked_add(interval.end - interval.start).ok_or(
                SnapshotError::PayloadTooLarge {
                    payload: payload_limit,
                    limit,
                },
            )?;
            count = count.checked_add(1).ok_or(SnapshotError::PayloadTooLarge {
                payload: payload_limit,
                limit,
            })?;
            Ok(())
        })?;
        let output_len = checked_output_len(
            input.len(),
            removed,
            count,
            replacement.len(),
            limit,
            payload_limit,
        )?;
        if count == 0 {
            return Ok((input, 0));
        }

        let mut output = Vec::new();
        output
            .try_reserve_exact(output_len)
            .map_err(|_| SnapshotError::AllocationFailed)?;
        let mut cursor = 0usize;
        self.for_each_merged_interval(&input, |interval| {
            output.extend_from_slice(&input[cursor..interval.start]);
            output.extend_from_slice(replacement);
            cursor = interval.end;
            Ok(())
        })?;
        output.extend_from_slice(&input[cursor..]);
        debug_assert_eq!(output.len(), output_len);
        Ok((output, count))
    }

    fn scratch_bytes(&self) -> usize {
        checked_matcher_scratch_bytes(self.max_pattern_len)
            .expect("literal matcher scratch was checked during activation")
    }

    fn for_each_merged_interval(
        &self,
        input: &[u8],
        mut callback: impl FnMut(Interval) -> Result<(), SnapshotError>,
    ) -> Result<(), SnapshotError> {
        let mut pending = PendingIntervals::new(self.max_pattern_len)?;
        for interval in self
            .matcher
            .iter()
            .flat_map(|matcher| matcher.matches(input))
        {
            let finalized_end = interval.end.saturating_sub(self.max_pattern_len);
            pending.flush_through(finalized_end, &mut callback)?;
            pending.merge(interval)?;
        }
        pending.flush_all(&mut callback)
    }
}

struct PendingIntervals {
    storage: ZeroizingBox<Interval>,
    head: usize,
    len: usize,
}

impl PendingIntervals {
    fn new(interval_capacity: usize) -> Result<Self, SnapshotError> {
        checked_matcher_scratch_bytes(interval_capacity)?;
        let storage = ZeroizingBox::filled(interval_capacity, Interval::default())?;
        Ok(Self {
            storage,
            head: 0,
            len: 0,
        })
    }

    fn merge(&mut self, mut interval: Interval) -> Result<(), SnapshotError> {
        while let Some(existing) = self.back() {
            if existing.end <= interval.start {
                break;
            }
            interval.start = interval.start.min(existing.start);
            self.pop_back();
        }
        if self.len == self.storage.len() {
            return Err(SnapshotError::MatcherScratchExceeded {
                limit: MAX_REDACTION_MATCHER_SCRATCH_BYTES,
            });
        }
        let index = self.index(self.len);
        self.storage[index] = interval;
        self.len += 1;
        Ok(())
    }

    fn flush_through(
        &mut self,
        finalized_end: usize,
        callback: &mut impl FnMut(Interval) -> Result<(), SnapshotError>,
    ) -> Result<(), SnapshotError> {
        while self
            .front()
            .is_some_and(|interval| interval.end <= finalized_end)
        {
            callback(self.pop_front().expect("checked pending front"))?;
        }
        Ok(())
    }

    fn flush_all(
        &mut self,
        callback: &mut impl FnMut(Interval) -> Result<(), SnapshotError>,
    ) -> Result<(), SnapshotError> {
        while let Some(interval) = self.pop_front() {
            callback(interval)?;
        }
        Ok(())
    }

    fn front(&self) -> Option<Interval> {
        (self.len != 0).then(|| self.storage[self.head])
    }

    fn back(&self) -> Option<Interval> {
        (self.len != 0).then(|| self.storage[self.index(self.len - 1)])
    }

    fn pop_front(&mut self) -> Option<Interval> {
        let interval = self.front()?;
        self.storage[self.head] = Interval::default();
        self.head = (self.head + 1) % self.storage.len();
        self.len -= 1;
        if self.len == 0 {
            self.head = 0;
        }
        Some(interval)
    }

    fn pop_back(&mut self) {
        debug_assert!(self.len != 0);
        let index = self.index(self.len - 1);
        self.storage[index] = Interval::default();
        self.len -= 1;
        if self.len == 0 {
            self.head = 0;
        }
    }

    fn index(&self, offset: usize) -> usize {
        debug_assert!(offset < self.storage.len());
        (self.head + offset) % self.storage.len()
    }
}

struct ZeroizingPatternRefs<'a> {
    storage: Box<[MaybeUninit<&'a [u8]>]>,
    initialized: usize,
    construction_peak_bytes: usize,
}

impl<'a> ZeroizingPatternRefs<'a> {
    fn new(len: usize, build_budget: usize, profile_index: usize) -> Result<Self, SnapshotError> {
        let mut storage = Vec::new();
        storage
            .try_reserve_exact(len)
            .map_err(|_| SnapshotError::AllocationFailed)?;
        storage.resize_with(len, MaybeUninit::uninit);
        let (final_bytes, construction_peak_bytes) =
            redaction_literal_reference_bytes(storage.capacity(), len)
                .ok_or(SnapshotError::MatcherBuild { profile_index })?;
        if construction_peak_bytes > build_budget {
            return Err(SnapshotError::CompiledMatcherTooLarge { profile_index });
        }
        let storage = storage.into_boxed_slice();
        if std::mem::size_of_val(storage.as_ref()) != final_bytes {
            return Err(SnapshotError::MatcherBuild { profile_index });
        }
        Ok(Self {
            storage,
            initialized: 0,
            construction_peak_bytes,
        })
    }

    fn push(&mut self, pattern: &'a [u8]) -> Option<()> {
        let slot = self.storage.get_mut(self.initialized)?;
        slot.write(pattern);
        self.initialized += 1;
        Some(())
    }

    fn len(&self) -> usize {
        self.initialized
    }

    fn is_empty(&self) -> bool {
        self.initialized == 0
    }

    fn allocation_bytes(&self) -> usize {
        std::mem::size_of_val(self.storage.as_ref())
    }

    fn construction_peak_bytes(&self) -> usize {
        self.construction_peak_bytes
    }

    fn initialized_slice(&self) -> Option<&[&'a [u8]]> {
        (self.initialized == self.storage.len()).then(|| {
            // Every slot is initialized, and the returned borrow cannot outlive
            // either the source slices or this construction-only container.
            unsafe {
                std::slice::from_raw_parts(
                    self.storage.as_ptr().cast::<&'a [u8]>(),
                    self.storage.len(),
                )
            }
        })
    }

    fn initialized_mut_slice(&mut self) -> Option<&mut [&'a [u8]]> {
        (self.initialized == self.storage.len()).then(|| {
            // Every slot is initialized. Sorting changes only the order of
            // valid references and remains bounded by this exclusive borrow.
            unsafe {
                std::slice::from_raw_parts_mut(
                    self.storage.as_mut_ptr().cast::<&'a [u8]>(),
                    self.storage.len(),
                )
            }
        })
    }

    fn zeroize(&mut self) {
        let pointer = self.storage.as_mut_ptr().cast::<u8>();
        for index in 0..self.allocation_bytes() {
            // `MaybeUninit` permits the zero representation written here.
            unsafe { std::ptr::write_volatile(pointer.add(index), 0) };
        }
        self.initialized = 0;
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    fn allocation_is_zeroed(&self) -> bool {
        let bytes = unsafe {
            std::slice::from_raw_parts(self.storage.as_ptr().cast::<u8>(), self.allocation_bytes())
        };
        bytes.iter().all(|byte| *byte == 0)
    }
}

impl Drop for ZeroizingPatternRefs<'_> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

fn checked_matcher_scratch_bytes(max_pattern_len: usize) -> Result<usize, SnapshotError> {
    redaction_literal_scratch_bytes(max_pattern_len).ok_or(SnapshotError::MatcherScratchExceeded {
        limit: MAX_REDACTION_MATCHER_SCRATCH_BYTES,
    })
}

struct ZeroizingAhoCorasick {
    nodes: ZeroizingVec<SecretNode>,
    edges: ZeroizingVec<SecretEdge>,
}

impl ZeroizingAhoCorasick {
    fn build(
        mut patterns: ZeroizingPatternRefs<'_>,
        profile_index: usize,
        build_budget: usize,
    ) -> Result<Option<Self>, SnapshotError> {
        if patterns.is_empty() {
            return Ok(None);
        }
        let pattern_reference_bytes = patterns.allocation_bytes();
        let pattern_reference_construction_bytes = patterns.construction_peak_bytes();
        let projection = redaction_literal_projection(
            patterns
                .initialized_mut_slice()
                .ok_or(SnapshotError::MatcherBuild { profile_index })?,
            pattern_reference_bytes,
            pattern_reference_construction_bytes,
        )
        .ok_or(SnapshotError::MatcherBuild { profile_index })?;
        if projection.build_bytes > build_budget {
            return Err(SnapshotError::CompiledMatcherTooLarge { profile_index });
        }

        let mut nodes = ZeroizingVec::filled(projection.state_count, SecretNode::default())?;
        let mut edges = ZeroizingVec(Vec::new());
        edges
            .0
            .try_reserve_exact(projection.edge_count)
            .map_err(|_| SnapshotError::AllocationFailed)?;
        let mut terminal_lengths = ZeroizingVec::filled(projection.state_count, 0usize)?;
        let mut path = ZeroizingVec(Vec::new());
        path.0
            .try_reserve_exact(projection.max_pattern_len.saturating_add(1))
            .map_err(|_| SnapshotError::AllocationFailed)?;
        path.0.push(0usize);
        let actual_resident_bytes = nodes
            .0
            .capacity()
            .checked_mul(std::mem::size_of::<SecretNode>())
            .and_then(|node_bytes| {
                edges
                    .0
                    .capacity()
                    .checked_mul(std::mem::size_of::<SecretEdge>())
                    .and_then(|edge_bytes| node_bytes.checked_add(edge_bytes))
            })
            .ok_or(SnapshotError::MatcherBuild { profile_index })?;
        if actual_resident_bytes != projection.resident_bytes
            || actual_resident_bytes > build_budget
        {
            return Err(SnapshotError::CompiledMatcherTooLarge { profile_index });
        }

        let actual_trie_build_bytes = actual_resident_bytes
            .checked_add(
                terminal_lengths
                    .0
                    .capacity()
                    .checked_mul(std::mem::size_of::<usize>())
                    .ok_or(SnapshotError::MatcherBuild { profile_index })?,
            )
            .and_then(|bytes| {
                path.0
                    .capacity()
                    .checked_mul(std::mem::size_of::<usize>())
                    .and_then(|path_bytes| bytes.checked_add(path_bytes))
            })
            .and_then(|bytes| bytes.checked_add(pattern_reference_bytes))
            .ok_or(SnapshotError::MatcherBuild { profile_index })?;
        if actual_trie_build_bytes != projection.trie_build_bytes
            || actual_trie_build_bytes > build_budget
        {
            return Err(SnapshotError::CompiledMatcherTooLarge { profile_index });
        }

        let mut next_state = 1usize;
        let pattern_slice = patterns
            .initialized_slice()
            .ok_or(SnapshotError::MatcherBuild { profile_index })?;
        for index in 0..pattern_slice.len() {
            let pattern = pattern_slice[index];
            let previous = index
                .checked_sub(1)
                .map(|previous| pattern_slice[previous])
                .unwrap_or(&[]);
            if index != 0 && pattern == previous {
                continue;
            }
            let shared = common_prefix_len(previous, pattern);
            path.0.truncate(shared + 1);
            let mut source = *path.last().expect("root path is retained");
            for &byte in &pattern[shared..] {
                let target = next_state;
                next_state += 1;
                edges.0.push(SecretEdge {
                    source,
                    byte,
                    target,
                });
                path.0.push(target);
                source = target;
            }
            terminal_lengths[source] = terminal_lengths[source].max(pattern.len());
        }
        debug_assert_eq!(next_state, projection.state_count);
        debug_assert_eq!(edges.len(), projection.edge_count);
        edges.sort_unstable_by_key(|edge| (edge.source, edge.byte));
        populate_edge_ranges(&mut nodes, &edges);

        // The BFS phase does not need source pointers. Drop the exact-size box
        // now so its volatile wipe completes before the queue is allocated.
        drop(patterns);

        let mut matcher = Self { nodes, edges };
        matcher.populate_failure_links(
            &terminal_lengths,
            terminal_lengths.0.capacity(),
            path.0.capacity(),
            projection.failure_build_bytes,
            build_budget,
            profile_index,
        )?;
        Ok(Some(matcher))
    }

    fn resident_bytes(&self) -> Result<usize, ()> {
        self.nodes
            .0
            .capacity()
            .checked_mul(std::mem::size_of::<SecretNode>())
            .and_then(|node_bytes| {
                self.edges
                    .0
                    .capacity()
                    .checked_mul(std::mem::size_of::<SecretEdge>())
                    .and_then(|edge_bytes| node_bytes.checked_add(edge_bytes))
            })
            .ok_or(())
    }

    fn populate_failure_links(
        &mut self,
        terminal_lengths: &[usize],
        terminal_capacity: usize,
        path_capacity: usize,
        projected_build_bytes: usize,
        build_budget: usize,
        profile_index: usize,
    ) -> Result<(), SnapshotError> {
        let mut queue = ZeroizingVec(Vec::new());
        queue
            .0
            .try_reserve_exact(self.nodes.len())
            .map_err(|_| SnapshotError::AllocationFailed)?;
        let actual_build_bytes = self
            .resident_bytes()
            .ok()
            .and_then(|bytes| {
                terminal_capacity
                    .checked_mul(std::mem::size_of::<usize>())
                    .and_then(|terminal_bytes| bytes.checked_add(terminal_bytes))
            })
            .and_then(|bytes| {
                path_capacity
                    .checked_mul(std::mem::size_of::<usize>())
                    .and_then(|path_bytes| bytes.checked_add(path_bytes))
            })
            .and_then(|bytes| {
                queue
                    .0
                    .capacity()
                    .checked_mul(std::mem::size_of::<usize>())
                    .and_then(|queue_bytes| bytes.checked_add(queue_bytes))
            })
            .ok_or(SnapshotError::MatcherBuild { profile_index })?;
        if actual_build_bytes != projected_build_bytes || actual_build_bytes > build_budget {
            return Err(SnapshotError::CompiledMatcherTooLarge { profile_index });
        }
        self.nodes[0].output_len = terminal_lengths[0];
        let root_edges = self.edge_range(0);
        for edge_index in root_edges {
            let target = self.edges[edge_index].target;
            self.nodes[target].output_len = terminal_lengths[target];
            queue.0.push(target);
        }

        let mut cursor = 0usize;
        while cursor < queue.len() {
            let source = queue[cursor];
            cursor += 1;
            let source_failure = self.nodes[source].failure;
            let edges = self.edge_range(source);
            for edge_index in edges {
                let edge = self.edges[edge_index];
                let mut failure = source_failure;
                while failure != 0 && self.transition(failure, edge.byte).is_none() {
                    failure = self.nodes[failure].failure;
                }
                let failure_target = self.transition(failure, edge.byte).unwrap_or(0);
                self.nodes[edge.target].failure = failure_target;
                self.nodes[edge.target].output_len =
                    terminal_lengths[edge.target].max(self.nodes[failure_target].output_len);
                queue.0.push(edge.target);
            }
        }
        Ok(())
    }

    fn for_each_match(&self, input: &[u8], mut callback: impl FnMut(usize, usize) -> bool) {
        for interval in self.matches(input) {
            if !callback(interval.start, interval.end) {
                return;
            }
        }
    }

    fn matches<'matcher, 'input>(
        &'matcher self,
        input: &'input [u8],
    ) -> ZeroizingMatchIter<'matcher, 'input> {
        ZeroizingMatchIter {
            matcher: self,
            input,
            state: 0,
            index: 0,
        }
    }

    fn transition(&self, state: usize, byte: u8) -> Option<usize> {
        let edges = &self.edges[self.edge_range(state)];
        edges
            .binary_search_by_key(&byte, |edge| edge.byte)
            .ok()
            .map(|index| edges[index].target)
    }

    fn edge_range(&self, state: usize) -> std::ops::Range<usize> {
        let node = self.nodes[state];
        node.edge_start..node.edge_start + node.edge_len
    }

    #[cfg(test)]
    fn zeroize(&mut self) {
        self.nodes.zeroize();
        self.edges.zeroize();
    }
}

struct ZeroizingMatchIter<'matcher, 'input> {
    matcher: &'matcher ZeroizingAhoCorasick,
    input: &'input [u8],
    state: usize,
    index: usize,
}

impl Iterator for ZeroizingMatchIter<'_, '_> {
    type Item = Interval;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.input.len() {
            let byte = self.input[self.index];
            while self.state != 0 && self.matcher.transition(self.state, byte).is_none() {
                self.state = self.matcher.nodes[self.state].failure;
            }
            self.state = self.matcher.transition(self.state, byte).unwrap_or(0);
            self.index += 1;
            let length = self.matcher.nodes[self.state].output_len;
            if length != 0 {
                return Some(Interval {
                    start: self.index - length,
                    end: self.index,
                });
            }
        }
        None
    }
}

fn common_prefix_len(left: &[u8], right: &[u8]) -> usize {
    left.iter()
        .zip(right)
        .take_while(|(left, right)| left == right)
        .count()
}

fn populate_edge_ranges(nodes: &mut [SecretNode], edges: &[SecretEdge]) {
    let mut cursor = 0usize;
    while cursor < edges.len() {
        let source = edges[cursor].source;
        let start = cursor;
        while cursor < edges.len() && edges[cursor].source == source {
            cursor += 1;
        }
        nodes[source].edge_start = start;
        nodes[source].edge_len = cursor - start;
    }
}

mod zero_valid {
    use super::{Interval, SecretEdge, SecretNode};

    pub(super) trait Sealed {}

    /// Types whose initialized values remain valid after a bytewise zero fill.
    ///
    /// # Safety
    /// Every byte being zero must be a valid representation of `Self`. `Copy`
    /// excludes destructors that a bytewise overwrite could bypass.
    pub(super) unsafe trait ZeroValid: Sealed + Copy + Default {}

    impl Sealed for u8 {}
    // SAFETY: every `u8` bit pattern, including zero, is valid.
    unsafe impl ZeroValid for u8 {}

    impl Sealed for usize {}
    // SAFETY: the all-zero representation is the integer value zero.
    unsafe impl ZeroValid for usize {}

    impl Sealed for Interval {}
    // SAFETY: `Interval` contains only `usize` fields, for which all-zero is valid.
    unsafe impl ZeroValid for Interval {}

    impl Sealed for SecretEdge {}
    // SAFETY: `SecretEdge` contains only `usize` and `u8` fields; zero is valid
    // for every field and padding bytes carry no validity invariant.
    unsafe impl ZeroValid for SecretEdge {}

    impl Sealed for SecretNode {}
    // SAFETY: `SecretNode` contains only `usize` fields, for which all-zero is valid.
    unsafe impl ZeroValid for SecretNode {}
}

use zero_valid::ZeroValid;

struct ZeroizingVec<T: ZeroValid>(Vec<T>);

impl<T: ZeroValid> ZeroizingVec<T> {
    fn filled(len: usize, value: T) -> Result<Self, SnapshotError> {
        let mut values = Vec::new();
        values
            .try_reserve_exact(len)
            .map_err(|_| SnapshotError::AllocationFailed)?;
        values.resize(len, value);
        Ok(Self(values))
    }

    fn zeroize(&mut self) {
        wipe_vec_capacity(&mut self.0);
    }
}

impl<T: ZeroValid> std::ops::Deref for ZeroizingVec<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: ZeroValid> std::ops::DerefMut for ZeroizingVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: ZeroValid> Drop for ZeroizingVec<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

struct ZeroizingBox<T: ZeroValid> {
    pointer: NonNull<T>,
    len: usize,
    layout: Layout,
}

impl<T: ZeroValid> ZeroizingBox<T> {
    fn filled(len: usize, value: T) -> Result<Self, SnapshotError> {
        let layout = Layout::array::<T>(len).map_err(|_| SnapshotError::AllocationFailed)?;
        let pointer = if layout.size() == 0 {
            NonNull::dangling()
        } else {
            NonNull::new(unsafe { alloc(layout).cast::<T>() })
                .ok_or(SnapshotError::AllocationFailed)?
        };
        for index in 0..len {
            unsafe { pointer.as_ptr().add(index).write(value) };
        }
        Ok(Self {
            pointer,
            len,
            layout,
        })
    }

    fn layout_bytes(&self) -> usize {
        self.layout.size()
    }

    fn zeroize(&mut self) {
        let pointer = self.pointer.as_ptr().cast::<u8>();
        for index in 0..self.layout.size() {
            // The allocation remains live throughout the volatile full-layout wipe.
            unsafe { std::ptr::write_volatile(pointer.add(index), 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    fn allocation_is_zeroed(&self) -> bool {
        let bytes = unsafe {
            std::slice::from_raw_parts(self.pointer.as_ptr().cast::<u8>(), self.layout.size())
        };
        bytes.iter().all(|byte| *byte == 0)
    }
}

impl<T: ZeroValid> std::ops::Deref for ZeroizingBox<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        unsafe { std::slice::from_raw_parts(self.pointer.as_ptr(), self.len) }
    }
}

impl<T: ZeroValid> std::ops::DerefMut for ZeroizingBox<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { std::slice::from_raw_parts_mut(self.pointer.as_ptr(), self.len) }
    }
}

impl<T: ZeroValid> Drop for ZeroizingBox<T> {
    fn drop(&mut self) {
        self.zeroize();
        if self.layout.size() != 0 {
            unsafe { dealloc(self.pointer.as_ptr().cast::<u8>(), self.layout) };
        }
    }
}

struct ResolvedRule {
    literals: Vec<Vec<u8>>,
    environment_literals: Vec<SecretBytes>,
    expressions: Vec<String>,
    payloads: CompiledRedactionPayloads,
}

impl ResolvedRule {
    fn activate(
        plan: RedactionRulePlan,
        profile_index: usize,
        rule_index: usize,
        individual_limit: usize,
        aggregate_limit: usize,
        aggregate_bytes: &mut usize,
        is_cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<Self, SnapshotError> {
        let mut environment_literals = Vec::with_capacity(plan.literal_environment_variables.len());
        for (source_index, variable) in plan.literal_environment_variables.into_iter().enumerate() {
            let value = read_environment_literal(
                &variable,
                individual_limit,
                profile_index,
                rule_index,
                source_index,
                is_cancelled,
            )?;
            if value.is_empty() {
                return Err(SnapshotError::SourceEmpty {
                    profile_index,
                    rule_index,
                    source_index,
                });
            }
            std::str::from_utf8(value.as_bytes()).map_err(|_| {
                SnapshotError::SourceInvalidUtf8 {
                    profile_index,
                    rule_index,
                    source_index,
                }
            })?;
            *aggregate_bytes = aggregate_bytes
                .checked_add(value.len())
                .filter(|total| *total <= aggregate_limit)
                .ok_or(SnapshotError::AggregateTooLarge { profile_index })?;
            environment_literals.push(value);
        }
        Ok(Self {
            literals: plan.literals,
            environment_literals,
            expressions: plan.expressions,
            payloads: plan.payloads,
        })
    }

    fn applies_to(&self, class: PayloadClass) -> bool {
        matches!(
            (self.payloads, class),
            (CompiledRedactionPayloads::Text, PayloadClass::Text)
                | (CompiledRedactionPayloads::Binary, PayloadClass::Binary)
                | (CompiledRedactionPayloads::Both, _)
        )
    }

    fn literal_count(&self) -> usize {
        self.literals
            .len()
            .saturating_add(self.environment_literals.len())
    }
}

fn replace_regex_bounded(
    input: Vec<u8>,
    expression: &DfaRegex,
    replacement: &[u8],
    limit: usize,
    payload_limit: PayloadLimit,
) -> Result<(Vec<u8>, usize), SnapshotError> {
    let (output_len, count) = replacement_shape(
        input.len(),
        expression.find_iter(&input).map(|matched| matched.len()),
        replacement.len(),
        limit,
        payload_limit,
    )?;
    if count == 0 {
        return Ok((input, 0));
    }

    let mut output = Vec::new();
    output
        .try_reserve_exact(output_len)
        .map_err(|_| SnapshotError::AllocationFailed)?;
    let mut cursor = 0;
    for matched in expression.find_iter(&input) {
        output.extend_from_slice(&input[cursor..matched.start()]);
        output.extend_from_slice(replacement);
        cursor = matched.end();
    }
    output.extend_from_slice(&input[cursor..]);
    debug_assert_eq!(output.len(), output_len);
    Ok((output, count))
}

fn replacement_shape(
    input_len: usize,
    match_lengths: impl Iterator<Item = usize>,
    replacement_len: usize,
    limit: usize,
    payload: PayloadLimit,
) -> Result<(usize, usize), SnapshotError> {
    let mut removed = 0usize;
    let mut count = 0usize;
    for matched_len in match_lengths {
        removed = removed
            .checked_add(matched_len)
            .ok_or(SnapshotError::PayloadTooLarge { payload, limit })?;
        count = count
            .checked_add(1)
            .ok_or(SnapshotError::PayloadTooLarge { payload, limit })?;
    }
    let output_len =
        checked_output_len(input_len, removed, count, replacement_len, limit, payload)?;
    Ok((output_len, count))
}

fn checked_output_len(
    input_len: usize,
    removed: usize,
    count: usize,
    replacement_len: usize,
    limit: usize,
    payload: PayloadLimit,
) -> Result<usize, SnapshotError> {
    input_len
        .checked_sub(removed)
        .and_then(|retained| {
            replacement_len
                .checked_mul(count)
                .and_then(|added| retained.checked_add(added))
        })
        .filter(|output_len| *output_len <= limit)
        .ok_or(SnapshotError::PayloadTooLarge { payload, limit })
}

fn check_size(bytes: usize, limit: usize, payload: PayloadLimit) -> Result<(), SnapshotError> {
    if bytes > limit {
        return Err(SnapshotError::PayloadTooLarge { payload, limit });
    }
    Ok(())
}

struct SecretBytes(Vec<u8>);

impl SecretBytes {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        wipe_vec_capacity(&mut self.0);
    }
}

fn wipe_vec_capacity<T: ZeroValid>(values: &mut Vec<T>) {
    let byte_len = values
        .capacity()
        .checked_mul(std::mem::size_of::<T>())
        .expect("vector allocation byte length is representable");
    let pointer = values.as_mut_ptr().cast::<u8>();
    for index in 0..byte_len {
        // The allocation remains live for this entire wipe, including capacity slack.
        unsafe { std::ptr::write_volatile(pointer.add(index), 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

enum EnvironmentReadError {
    Unavailable,
    TooLarge,
}

fn read_environment_literal(
    variable: &str,
    individual_limit: usize,
    profile_index: usize,
    rule_index: usize,
    source_index: usize,
    is_cancelled: &mut dyn FnMut() -> bool,
) -> Result<SecretBytes, SnapshotError> {
    if is_cancelled() {
        return Err(SnapshotError::ActivationCancelled);
    }
    let result = read_environment_bytes(variable, individual_limit);
    if is_cancelled() {
        return Err(SnapshotError::ActivationCancelled);
    }
    result.map_err(|error| match error {
        EnvironmentReadError::Unavailable => SnapshotError::SourceUnavailable {
            profile_index,
            rule_index,
            source_index,
        },
        EnvironmentReadError::TooLarge => SnapshotError::SourceTooLarge {
            profile_index,
            rule_index,
            source_index,
        },
    })
}

fn read_environment_bytes(
    variable: &str,
    individual_limit: usize,
) -> Result<SecretBytes, EnvironmentReadError> {
    let value = env::var_os(variable).ok_or(EnvironmentReadError::Unavailable)?;
    let bytes = SecretBytes(value.into_encoded_bytes());
    if bytes.len() > individual_limit {
        return Err(EnvironmentReadError::TooLarge);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::config::compiler::{
        MAX_REDACTION_COMPILED_MATCHER_BYTES_PER_PROFILE,
        MAX_REDACTION_COMPILED_MATCHER_BYTES_PER_SNAPSHOT,
    };

    fn activate(plan: RedactionPlan) -> Result<RedactionActivation, SnapshotError> {
        RedactionSnapshot::activate(plan, || false)
    }

    fn redaction_profile_index(index: usize) -> RedactionProfileIndex {
        let name = format!("index-{index:08}");
        RedactionProfileRegistry::from_names((0..=index).map(|value| format!("index-{value:08}")))
            .get(&name)
            .unwrap()
    }

    static NEXT_ENV: AtomicUsize = AtomicUsize::new(0);

    struct EnvGuard(String);

    impl EnvGuard {
        fn set(value: &str) -> Self {
            let name = format!(
                "ACL_PROXY_REDACTION_SNAPSHOT_TEST_{}_{}",
                std::process::id(),
                NEXT_ENV.fetch_add(1, Ordering::Relaxed)
            );
            env::set_var(&name, value);
            Self(name)
        }

        fn missing() -> Self {
            let name = format!(
                "ACL_PROXY_REDACTION_SNAPSHOT_TEST_{}_{}",
                std::process::id(),
                NEXT_ENV.fetch_add(1, Ordering::Relaxed)
            );
            env::remove_var(&name);
            Self(name)
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            env::remove_var(&self.0);
        }
    }

    fn boxed_pattern_refs<'a>(patterns: &[&'a [u8]]) -> ZeroizingPatternRefs<'a> {
        let mut refs = ZeroizingPatternRefs::new(
            patterns.len(),
            MAX_REDACTION_COMPILED_MATCHER_BYTES_PER_PROFILE,
            0,
        )
        .unwrap();
        for pattern in patterns.iter().copied() {
            refs.push(pattern).unwrap();
        }
        refs
    }

    fn profile(variable: Option<String>) -> RedactionProfilePlan {
        RedactionProfilePlan {
            replacement: b"[MASKED]".to_vec(),
            max_body_bytes: 32,
            max_decoded_body_bytes: 128,
            max_frame_bytes: 16,
            max_message_bytes: 128,
            allow_permessage_deflate: true,
            max_environment_literal_sources: 2,
            max_environment_literal_bytes: 64,
            max_environment_literal_total_bytes: 96,
            rules: vec![RedactionRulePlan {
                literals: vec![b"literal".to_vec()],
                literal_environment_variables: variable.into_iter().collect(),
                expressions: vec![r"token-[0-9]+".to_string()],
                payloads: CompiledRedactionPayloads::Text,
            }],
        }
    }

    fn plan(profile: RedactionProfilePlan) -> RedactionPlan {
        RedactionPlan {
            profiles: BTreeMap::from([("main".to_string(), profile)]),
        }
    }

    #[test]
    fn fixed_replacement_obeys_payload_selection() {
        let source = EnvGuard::set("environment-secret");
        let mut profile_plan = profile(Some(source.0.clone()));
        profile_plan.rules.push(RedactionRulePlan {
            literals: vec![b"binary-secret".to_vec()],
            literal_environment_variables: vec![],
            expressions: vec![],
            payloads: CompiledRedactionPayloads::Binary,
        });
        let snapshot = activate(plan(profile_plan)).unwrap();
        let rendered = format!("{snapshot:?} {:?}", snapshot.profile("main").unwrap());
        assert!(!rendered.contains("environment-secret"));
        assert!(!rendered.contains(&source.0));
        let profile = snapshot.profile("main").unwrap();

        let text = profile
            .redact_decoded_http_body(b"literal environment-secret token-12 binary-secret".to_vec())
            .unwrap();
        assert_eq!(text.replacements, 3);
        assert_eq!(text.bytes, b"[MASKED] [MASKED] [MASKED] binary-secret");
        let binary = profile
            .redact_websocket_message(b"literal binary-secret".to_vec(), PayloadClass::Binary)
            .unwrap();
        assert_eq!(binary.replacements, 1);
        assert_eq!(binary.bytes, b"literal [MASKED]");
    }

    #[test]
    fn activation_returns_deterministic_indices_then_drops_profile_names() {
        let source = EnvGuard::set("indexed-environment-secret");
        let activation = activate(RedactionPlan {
            profiles: BTreeMap::from([
                ("z-profile-marker".to_string(), profile(None)),
                (
                    "a-profile-marker".to_string(),
                    profile(Some(source.0.clone())),
                ),
            ]),
        })
        .unwrap();

        assert_eq!(
            activation.profile_index("a-profile-marker"),
            Some(redaction_profile_index(0))
        );
        assert_eq!(
            activation.profile_index("z-profile-marker"),
            Some(redaction_profile_index(1))
        );
        let (snapshot, indices) = activation.into_parts();
        assert_eq!(indices.len(), 2);
        drop(indices);

        let rendered = format!("{snapshot:?}");
        assert!(!rendered.contains("a-profile-marker"));
        assert!(!rendered.contains("z-profile-marker"));
        assert!(!rendered.contains(&source.0));
        assert!(snapshot.profile(redaction_profile_index(0)).is_some());
        assert!(snapshot.profile(redaction_profile_index(1)).is_some());
        assert!(snapshot.profile(redaction_profile_index(2)).is_none());
    }

    #[test]
    fn literal_overlaps_merge_across_authored_and_environment_sources() {
        let mut authored_plan = profile(None);
        authored_plan.rules[0].literals = vec![b"abc".to_vec(), b"bcdef".to_vec()];
        authored_plan.rules[0].expressions.clear();
        let authored = activate(plan(authored_plan))
            .unwrap()
            .profile("main")
            .unwrap()
            .redact_decoded_http_body(b"abcdef".to_vec())
            .unwrap();
        assert_eq!(authored.replacements, 1);
        assert_eq!(authored.bytes, b"[MASKED]");

        let source = EnvGuard::set("secret-token");
        let mut profile_plan = profile(None);
        profile_plan.rules[0].literals = vec![b"secret".to_vec(), b"token".to_vec()];
        profile_plan.rules.push(RedactionRulePlan {
            literals: vec![],
            literal_environment_variables: vec![source.0.clone()],
            expressions: vec![],
            payloads: CompiledRedactionPayloads::Text,
        });
        let prefix_handle = activate(plan(profile_plan))
            .unwrap()
            .profile("main")
            .unwrap();
        let output = prefix_handle
            .redact_decoded_http_body(b"secret-token".to_vec())
            .unwrap();
        assert_eq!(output.replacements, 1);
        assert_eq!(output.bytes, b"[MASKED]");

        let later_source = EnvGuard::set("cd");
        let mut later_plan = profile(None);
        later_plan.rules[0].literals = vec![b"abcd".to_vec()];
        later_plan.rules.push(RedactionRulePlan {
            literals: vec![],
            literal_environment_variables: vec![later_source.0.clone()],
            expressions: vec![],
            payloads: CompiledRedactionPayloads::Text,
        });
        let later = activate(plan(later_plan))
            .unwrap()
            .profile("main")
            .unwrap()
            .redact_decoded_http_body(b"abcd".to_vec())
            .unwrap();
        assert_eq!(later.replacements, 1);
        assert_eq!(later.bytes, b"[MASKED]");

        let overlap_source = EnvGuard::set("aaa");
        let overlap = activate(plan(profile(Some(overlap_source.0.clone()))))
            .unwrap()
            .profile("main")
            .unwrap()
            .redact_decoded_http_body(b"aaaa".to_vec())
            .unwrap();
        assert_eq!(overlap.replacements, 1);
        assert_eq!(overlap.bytes, b"[MASKED]");
    }

    #[test]
    fn transport_fragments_are_only_validated_and_complete_payload_is_redacted() {
        let source = EnvGuard::set("boundary-secret");
        let profile = activate(plan(profile(Some(source.0.clone()))))
            .unwrap()
            .profile("main")
            .unwrap();
        let first = b"prefix boundary-";
        let second = b"secret suffix";
        profile
            .validate_encoded_http_body_size(first.len())
            .unwrap();
        profile.validate_websocket_frame_size(second.len()).unwrap();
        assert_eq!(first, b"prefix boundary-");
        assert_eq!(second, b"secret suffix");

        let output = profile
            .redact_websocket_message(
                [first.as_slice(), second.as_slice()].concat(),
                PayloadClass::Text,
            )
            .unwrap();
        assert_eq!(output.bytes, b"prefix [MASKED] suffix");
    }

    #[test]
    fn narrow_handle_survives_snapshot_drop() {
        let source = EnvGuard::set("retained-secret");
        let snapshot = activate(plan(profile(Some(source.0.clone())))).unwrap();
        let profile = snapshot.profile("main").unwrap();
        drop(snapshot);

        let output = profile
            .redact_websocket_message(b"retained-secret".to_vec(), PayloadClass::Text)
            .unwrap();
        assert_eq!(output.bytes, b"[MASKED]");
        assert!(!format!("{profile:?}").contains("retained-secret"));
    }

    #[test]
    fn snapshot_rotation_is_atomic() {
        let source = EnvGuard::set("old-secret");
        let old = activate(plan(profile(Some(source.0.clone()))))
            .unwrap()
            .profile("main")
            .unwrap();
        env::set_var(&source.0, "new-secret");
        let new = activate(plan(profile(Some(source.0.clone()))))
            .unwrap()
            .profile("main")
            .unwrap();

        assert_eq!(
            old.redact_decoded_http_body(b"old-secret new-secret".to_vec())
                .unwrap()
                .bytes,
            b"[MASKED] new-secret"
        );
        assert_eq!(
            new.redact_decoded_http_body(b"old-secret new-secret".to_vec())
                .unwrap()
                .bytes,
            b"old-secret [MASKED]"
        );
    }

    #[test]
    fn environment_reads_are_bracketed_by_cancellation_checks() {
        let source = EnvGuard::set("sensitive-cancelled-literal");
        let mut checks = 0usize;
        let error = RedactionSnapshot::activate(plan(profile(Some(source.0.clone()))), || {
            checks += 1;
            checks == 2
        })
        .unwrap_err();

        assert_eq!(error, SnapshotError::ActivationCancelled);
        assert_eq!(checks, 2);
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(&source.0));
        assert!(!rendered.contains("sensitive-cancelled-literal"));
    }

    #[test]
    fn missing_empty_and_individual_oversize_errors_are_sanitized() {
        let missing = EnvGuard::missing();
        let error = activate(plan(profile(Some(missing.0.clone())))).unwrap_err();
        assert!(matches!(error, SnapshotError::SourceUnavailable { .. }));
        assert!(!format!("{error:?} {error}").contains(&missing.0));

        let empty = EnvGuard::set("");
        let error = activate(plan(profile(Some(empty.0.clone())))).unwrap_err();
        assert!(matches!(error, SnapshotError::SourceEmpty { .. }));

        let value = "sensitive-value-that-is-deliberately-longer-than-the-individual-source-limit";
        let large = EnvGuard::set(value);
        let error = activate(plan(profile(Some(large.0.clone())))).unwrap_err();
        assert!(matches!(error, SnapshotError::SourceTooLarge { .. }));
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(&large.0));
        assert!(!rendered.contains(value));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_source_is_rejected_without_disclosure() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let source = EnvGuard::missing();
        env::set_var(&source.0, OsString::from_vec(vec![b's', 0xff, b'x']));
        let error = activate(plan(profile(Some(source.0.clone())))).unwrap_err();
        assert!(matches!(error, SnapshotError::SourceInvalidUtf8 { .. }));
        assert!(!format!("{error:?} {error}").contains(&source.0));
    }

    #[test]
    fn source_count_and_aggregate_limits_are_enforced() {
        let one = EnvGuard::set("12345678");
        let two = EnvGuard::set("abcdefgh");
        let mut count_profile = profile(None);
        count_profile.max_environment_literal_sources = 1;
        count_profile.rules[0].literal_environment_variables = vec![one.0.clone(), two.0.clone()];
        assert!(matches!(
            activate(plan(count_profile)).unwrap_err(),
            SnapshotError::SourceCount { .. }
        ));

        let mut aggregate_profile = profile(None);
        aggregate_profile.max_environment_literal_total_bytes = 15;
        aggregate_profile.rules[0].literal_environment_variables =
            vec![one.0.clone(), two.0.clone()];
        assert!(matches!(
            activate(plan(aggregate_profile)).unwrap_err(),
            SnapshotError::AggregateTooLarge { .. }
        ));
    }

    #[test]
    fn validation_limits_and_scratch_metadata_are_exact() {
        let snapshot = activate(plan(profile(None))).unwrap();
        let handle = snapshot.profile("main").unwrap();
        assert_eq!(
            handle.limits().matcher_scratch_bytes,
            b"literal".len() * std::mem::size_of::<Interval>()
        );
        assert!(handle.limits().matcher_scratch_bytes <= MAX_REDACTION_MATCHER_SCRATCH_BYTES);
        assert!(handle.limits().compiled_matcher_resident_bytes > 0);
        assert!(
            handle.limits().compiled_matcher_resident_bytes
                <= MAX_REDACTION_COMPILED_MATCHER_BYTES_PER_PROFILE
        );
        assert_eq!(
            snapshot.compiled_matcher_resident_bytes(),
            handle.limits().compiled_matcher_resident_bytes
        );
        assert!(
            snapshot.compiled_matcher_resident_bytes()
                <= MAX_REDACTION_COMPILED_MATCHER_BYTES_PER_SNAPSHOT
        );
        assert!(handle.validate_encoded_http_body_size(32).is_ok());
        assert!(matches!(
            handle.validate_encoded_http_body_size(33),
            Err(SnapshotError::PayloadTooLarge {
                payload: PayloadLimit::EncodedHttpBody,
                limit: 32
            })
        ));
        assert!(handle.validate_websocket_frame_size(16).is_ok());
        assert!(handle.validate_encoded_websocket_message_size(128).is_ok());

        let mut expression_only = profile(None);
        expression_only.rules[0].literals.clear();
        let expression_only = activate(plan(expression_only))
            .unwrap()
            .profile("main")
            .unwrap();
        assert_eq!(expression_only.limits().matcher_scratch_bytes, 0);
    }

    #[test]
    fn activation_resident_accounting_matches_the_pure_sparse_projection() {
        let mut profile_plan = profile(None);
        profile_plan.rules[0].expressions.clear();
        let snapshot = activate(plan(profile_plan)).unwrap();
        let mut patterns = boxed_pattern_refs(&[b"literal".as_slice()]);
        let reference_bytes = patterns.allocation_bytes();
        let reference_construction_bytes = patterns.construction_peak_bytes();
        let projection = redaction_literal_projection(
            patterns.initialized_mut_slice().unwrap(),
            reference_bytes,
            reference_construction_bytes,
        )
        .unwrap();

        assert_eq!(
            snapshot.compiled_matcher_resident_bytes(),
            projection.resident_bytes
        );
    }

    #[test]
    fn invalid_text_and_replacement_expansion_fail_before_output_allocation() {
        let mut profile_plan = profile(None);
        profile_plan.max_decoded_body_bytes = 32;
        let profile = activate(plan(profile_plan))
            .unwrap()
            .profile("main")
            .unwrap();
        assert!(matches!(
            profile.redact_websocket_message(vec![0xff], PayloadClass::Text),
            Err(SnapshotError::InvalidText)
        ));
        assert!(matches!(
            profile.redact_decoded_http_body(b"literal literal literal literal".to_vec()),
            Err(SnapshotError::PayloadTooLarge {
                payload: PayloadLimit::DecodedHttpBody,
                limit: 32
            })
        ));
    }

    #[test]
    fn adversarial_dense_matches_remain_bounded() {
        let mut profile_plan = profile(None);
        profile_plan.replacement = b"0123456789".to_vec();
        profile_plan.max_message_bytes = 1024;
        profile_plan.rules[0].literals = vec![b"a".to_vec(), b"aa".to_vec(), b"aaa".to_vec()];
        profile_plan.rules[0].expressions.clear();
        let profile = activate(plan(profile_plan))
            .unwrap()
            .profile("main")
            .unwrap();

        let output = profile
            .redact_websocket_message(vec![b'a'; 300], PayloadClass::Text)
            .unwrap();
        assert_eq!(output.replacements, 1);
        assert_eq!(output.bytes, b"0123456789");
        assert!(output.bytes.capacity() <= 1024);
    }

    #[test]
    fn pending_interval_ring_wraps_and_merges_overlapping_suffixes() {
        let mut pending = PendingIntervals::new(4).unwrap();
        assert_eq!(
            pending.storage.layout_bytes(),
            4 * std::mem::size_of::<Interval>()
        );
        for (start, end) in [(0, 1), (2, 3), (4, 5)] {
            pending.merge(Interval { start, end }).unwrap();
        }
        let mut emitted = Vec::new();
        pending
            .flush_through(3, &mut |interval| {
                emitted.push((interval.start, interval.end));
                Ok(())
            })
            .unwrap();
        pending.merge(Interval { start: 6, end: 7 }).unwrap();
        pending.merge(Interval { start: 8, end: 9 }).unwrap();
        pending.merge(Interval { start: 6, end: 10 }).unwrap();
        pending
            .flush_all(&mut |interval| {
                emitted.push((interval.start, interval.end));
                Ok(())
            })
            .unwrap();

        assert_eq!(emitted, vec![(0, 1), (2, 3), (4, 5), (6, 10)]);
    }

    #[test]
    fn pending_interval_storage_has_an_exact_wipeable_layout() {
        let mut pending = PendingIntervals::new(7).unwrap();
        assert_eq!(pending.storage.len(), 7);
        assert_eq!(
            pending.storage.layout_bytes(),
            7 * std::mem::size_of::<Interval>()
        );
        pending.storage.fill(Interval { start: 1, end: 2 });
        pending.storage.zeroize();
        assert!(pending.storage.allocation_is_zeroed());

        let empty = PendingIntervals::new(0).unwrap();
        assert!(empty.storage.is_empty());
        assert_eq!(empty.storage.layout_bytes(), 0);
    }

    #[test]
    fn dense_adjacent_matches_with_long_nonmatching_horizon_remain_linear() {
        const HORIZON: usize = 32 * 1024;
        const PAYLOAD_BYTES: usize = 256 * 1024;
        let mut profile_plan = profile(None);
        profile_plan.replacement = b"X".to_vec();
        profile_plan.max_message_bytes = PAYLOAD_BYTES;
        profile_plan.rules[0].literals = vec![b"a".to_vec(), vec![b'b'; HORIZON]];
        profile_plan.rules[0].expressions.clear();
        let profile = activate(plan(profile_plan))
            .unwrap()
            .profile("main")
            .unwrap();

        let output = profile
            .redact_websocket_message(vec![b'a'; PAYLOAD_BYTES], PayloadClass::Text)
            .unwrap();

        assert_eq!(output.replacements, PAYLOAD_BYTES);
        assert_eq!(output.bytes, vec![b'X'; PAYLOAD_BYTES]);
    }

    #[test]
    fn nested_authored_pattern_density_does_not_enumerate_raw_matches() {
        const PAYLOAD_BYTES: usize = 512 * 1024;
        const PATTERN_COUNT: usize = 512;
        let mut profile_plan = profile(None);
        profile_plan.replacement = b"X".to_vec();
        profile_plan.max_message_bytes = PAYLOAD_BYTES;
        profile_plan.rules[0].literals = (1..=PATTERN_COUNT)
            .map(|length| vec![b'a'; length])
            .collect();
        profile_plan.rules[0].expressions.clear();
        let profile = activate(plan(profile_plan))
            .unwrap()
            .profile("main")
            .unwrap();
        assert_eq!(
            profile.limits().matcher_scratch_bytes,
            PATTERN_COUNT * std::mem::size_of::<Interval>()
        );

        let output = profile
            .redact_websocket_message(vec![b'a'; PAYLOAD_BYTES], PayloadClass::Text)
            .unwrap();

        assert_eq!(output.replacements, 1);
        assert_eq!(output.bytes, b"X");
    }

    #[test]
    fn multi_megabyte_dense_authored_matches_stream_with_bounded_scratch() {
        const PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
        let mut profile_plan = profile(None);
        profile_plan.replacement = b"X".to_vec();
        profile_plan.max_message_bytes = PAYLOAD_BYTES;
        profile_plan.rules[0].literals = vec![b"a".to_vec()];
        profile_plan.rules[0].expressions.clear();
        let profile = activate(plan(profile_plan))
            .unwrap()
            .profile("main")
            .unwrap();
        let payload = b"a_".repeat(PAYLOAD_BYTES / 2);

        let output = profile
            .redact_websocket_message(payload, PayloadClass::Text)
            .unwrap();

        assert_eq!(output.replacements, PAYLOAD_BYTES / 2);
        assert_eq!(output.bytes.len(), PAYLOAD_BYTES);
        assert!(output.bytes.chunks_exact(2).all(|chunk| chunk == b"X_"));
    }

    #[test]
    fn dense_environment_matches_stream_with_exact_scratch() {
        let source = EnvGuard::set("a");
        let mut profile_plan = profile(Some(source.0.clone()));
        profile_plan.replacement = b"X".to_vec();
        profile_plan.max_message_bytes = 100_000;
        profile_plan.rules[0].literals.clear();
        profile_plan.rules[0].expressions.clear();
        let profile = activate(plan(profile_plan))
            .unwrap()
            .profile("main")
            .unwrap();
        assert_eq!(
            profile.limits().matcher_scratch_bytes,
            std::mem::size_of::<Interval>()
        );
        let output = profile
            .redact_websocket_message(b"a_".repeat(50_000), PayloadClass::Text)
            .unwrap();
        assert_eq!(output.replacements, 50_000);
        assert_eq!(output.bytes.len(), 100_000);
        assert!(output.bytes.chunks_exact(2).all(|chunk| chunk == b"X_"));
    }

    #[test]
    fn literal_horizon_exceeding_scratch_ceiling_is_rejected_at_activation() {
        let interval_limit = MAX_REDACTION_MATCHER_SCRATCH_BYTES / std::mem::size_of::<Interval>();
        let mut profile_plan = profile(None);
        profile_plan.rules[0].literals = vec![vec![b'a'; interval_limit + 1]];
        profile_plan.rules[0].expressions.clear();

        assert!(matches!(
            activate(plan(profile_plan)).unwrap_err(),
            SnapshotError::MatcherScratchExceeded {
                limit: MAX_REDACTION_MATCHER_SCRATCH_BYTES
            }
        ));
    }

    #[test]
    fn environment_automaton_state_is_exact_and_zeroizable() {
        let she = SecretBytes(b"she".to_vec());
        let he = SecretBytes(b"he".to_vec());
        let hers = SecretBytes(b"hers".to_vec());
        let mut matcher = ZeroizingAhoCorasick::build(
            boxed_pattern_refs(&[she.as_bytes(), he.as_bytes(), hers.as_bytes()]),
            0,
            MAX_REDACTION_COMPILED_MATCHER_BYTES_PER_PROFILE,
        )
        .unwrap()
        .unwrap();
        let mut matches = Vec::new();
        matcher.for_each_match(b"ushers", |start, end| {
            matches.push(start..end);
            true
        });
        assert_eq!(matches, vec![1..4, 2..6]);
        assert!(matcher.edges.iter().any(|edge| edge.byte != 0));

        matcher.zeroize();
        assert!(matcher
            .nodes
            .iter()
            .all(|node| *node == SecretNode::default()));
        assert!(matcher
            .edges
            .iter()
            .all(|edge| *edge == SecretEdge::default()));
        assert_allocation_zeroed(&matcher.nodes.0);
        assert_allocation_zeroed(&matcher.edges.0);
    }

    #[test]
    fn environment_automaton_rejects_oversized_resident_and_temporary_state() {
        let secret = SecretBytes(vec![b'x'; 300 * 1024]);
        let error = ZeroizingAhoCorasick::build(
            boxed_pattern_refs(&[secret.as_bytes()]),
            3,
            MAX_REDACTION_COMPILED_MATCHER_BYTES_PER_PROFILE,
        )
        .err()
        .expect("the projected build peak exceeds the profile ceiling");
        assert_eq!(
            error,
            SnapshotError::CompiledMatcherTooLarge { profile_index: 3 }
        );

        let literal = vec![b'x'; 1023];
        let mut patterns = boxed_pattern_refs(&[literal.as_slice()]);
        let reference_bytes = patterns.allocation_bytes();
        let reference_construction_bytes = patterns.construction_peak_bytes();
        let projection = redaction_literal_projection(
            patterns.initialized_mut_slice().unwrap(),
            reference_bytes,
            reference_construction_bytes,
        )
        .unwrap();
        assert!(projection.build_bytes > projection.resident_bytes);
    }

    #[test]
    fn duplicate_pattern_references_are_counted_exactly_and_zeroizable() {
        let literal = SecretBytes(b"duplicate-secret".to_vec());
        let source_patterns = vec![literal.as_bytes(); 4096];
        let mut patterns = boxed_pattern_refs(&source_patterns);
        let reference_bytes = patterns.allocation_bytes();
        let reference_construction_bytes = patterns.construction_peak_bytes();
        let projection = redaction_literal_projection(
            patterns.initialized_mut_slice().unwrap(),
            reference_bytes,
            reference_construction_bytes,
        )
        .unwrap();

        assert_eq!(
            reference_bytes,
            source_patterns.len() * std::mem::size_of::<&[u8]>()
        );
        assert_eq!(
            projection.reference_build_bytes,
            reference_construction_bytes
        );
        assert_eq!(
            projection.trie_build_bytes,
            projection.resident_bytes
                + projection.state_count * std::mem::size_of::<usize>()
                + (projection.max_pattern_len + 1) * std::mem::size_of::<usize>()
                + reference_bytes
        );
        assert_eq!(
            projection.build_bytes,
            projection
                .reference_build_bytes
                .max(projection.trie_build_bytes)
                .max(projection.failure_build_bytes)
        );

        patterns.zeroize();
        assert_eq!(patterns.len(), 0);
        assert!(patterns.allocation_is_zeroed());

        let preconversion_error =
            ZeroizingPatternRefs::new(source_patterns.len(), reference_bytes * 2 - 1, 7)
                .err()
                .expect("the staging and final reference allocations can coexist");
        assert_eq!(
            preconversion_error,
            SnapshotError::CompiledMatcherTooLarge { profile_index: 7 }
        );

        let error = ZeroizingAhoCorasick::build(
            boxed_pattern_refs(&source_patterns),
            7,
            projection.build_bytes - 1,
        )
        .err()
        .expect("the pre-dedup reference box is part of the build ceiling");
        assert_eq!(
            error,
            SnapshotError::CompiledMatcherTooLarge { profile_index: 7 }
        );
        assert!(ZeroizingAhoCorasick::build(
            boxed_pattern_refs(&source_patterns),
            7,
            projection.build_bytes,
        )
        .unwrap()
        .is_some());
    }

    #[test]
    fn activation_defensively_rejects_cache_requiring_regex_syntax() {
        const EXPRESSION_MARKER: &str = "activation-regex-secret-marker";
        let mut profile_plan = profile(None);
        profile_plan.rules[0].expressions = vec![format!(r"\b{EXPRESSION_MARKER}\b")];
        let error = activate(plan(profile_plan)).unwrap_err();
        assert!(matches!(
            error,
            SnapshotError::ExpressionBuild {
                profile_index: 0,
                rule_index: 0,
                expression_index: 0
            }
        ));
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(EXPRESSION_MARKER));
    }

    fn assert_allocation_zeroed<T>(values: &Vec<T>) {
        let byte_len = values.capacity() * std::mem::size_of::<T>();
        // The test reads only the still-live allocation after the explicit wipe.
        let bytes = unsafe { std::slice::from_raw_parts(values.as_ptr().cast::<u8>(), byte_len) };
        assert!(bytes.iter().all(|byte| *byte == 0));
    }
}
