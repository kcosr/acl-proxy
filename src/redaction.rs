use std::collections::BTreeMap;
use std::env;

use http_access_redaction::{
    ActivationError, BufferFailure, ExternalLiteralBinding, ExternalLiteralSlot,
    PreparedRedactionSnapshot, RedactionBody, RedactionBufferContext, RedactionExactBytes,
    RedactionLimits, RedactionOutput, RedactionProjection, SecretLiteral, SecretLiteralError,
};
use http_access_types::SnapshotIdentity;
use zeroize::Zeroizing;

use crate::observation::{
    CaptureAllocationCharge, CaptureAllocationError, CaptureBody, CaptureExactBytes,
    CaptureOperation, ReservedCaptureBodyBuilder,
};
use crate::safety::wire_body::{
    GuardedAllocationCharge, GuardedExactBytes, ReservedGuardedBodyBuilder, WireBodyBufferError,
};
use crate::safety::{GuardedBody, HttpWireBodyGuard};

pub(crate) struct ProductRedactionPlan {
    pub(crate) profiles: BTreeMap<String, ProductRedactionProfile>,
    pub(crate) prepared: PreparedRedactionSnapshot,
    pub(crate) sources: Vec<ProductExternalLiteralSource>,
}

#[derive(Clone)]
pub(crate) struct ProductRedactionProfile {
    pub(crate) limits: RedactionLimits,
    pub(crate) projection: RedactionProjection,
    pub(crate) has_text_expressions: bool,
}

pub(crate) struct ProductExternalLiteralSource {
    pub(crate) slot: ExternalLiteralSlot,
    pub(crate) variable: String,
    pub(crate) profile: usize,
    pub(crate) rule: usize,
    pub(crate) source_index: usize,
    pub(crate) max_bytes: usize,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum ProductRedactionActivationError {
    #[error("redaction activation was cancelled")]
    Cancelled,
    #[error(
        "redaction environment literal source {source_index} in rule {rule} of profile {profile} is unavailable"
    )]
    SourceUnavailable {
        profile: usize,
        rule: usize,
        source_index: usize,
    },
    #[error(
        "redaction environment literal source {source_index} in rule {rule} of profile {profile} is empty"
    )]
    SourceEmpty {
        profile: usize,
        rule: usize,
        source_index: usize,
    },
    #[error(
        "redaction environment literal source {source_index} in rule {rule} of profile {profile} is not valid UTF-8"
    )]
    SourceInvalidUtf8 {
        profile: usize,
        rule: usize,
        source_index: usize,
    },
    #[error(
        "redaction environment literal source {source_index} in rule {rule} of profile {profile} exceeds its byte limit"
    )]
    SourceTooLarge {
        profile: usize,
        rule: usize,
        source_index: usize,
    },
    #[error("redaction environment literal allocation failed")]
    AllocationFailed,
    #[error(transparent)]
    Shared(ActivationError),
}

impl ProductRedactionPlan {
    pub(crate) fn activate(
        self,
        identity: SnapshotIdentity,
        version: u64,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<http_access_redaction::RedactionSnapshot, ProductRedactionActivationError> {
        let mut bindings = Vec::new();
        bindings
            .try_reserve_exact(self.sources.len())
            .map_err(|_| ProductRedactionActivationError::AllocationFailed)?;
        for source in self.sources {
            if is_cancelled() {
                return Err(ProductRedactionActivationError::Cancelled);
            }
            let value = env::var_os(&source.variable)
                .map(|value| Zeroizing::new(value.into_encoded_bytes()));
            if is_cancelled() {
                return Err(ProductRedactionActivationError::Cancelled);
            }
            let mut bytes = value.ok_or(ProductRedactionActivationError::SourceUnavailable {
                profile: source.profile,
                rule: source.rule,
                source_index: source.source_index,
            })?;
            if bytes.len() > source.max_bytes {
                return Err(ProductRedactionActivationError::SourceTooLarge {
                    profile: source.profile,
                    rule: source.rule,
                    source_index: source.source_index,
                });
            }
            let literal =
                SecretLiteral::new(std::mem::take(&mut *bytes)).map_err(|error| match error {
                    SecretLiteralError::Empty => ProductRedactionActivationError::SourceEmpty {
                        profile: source.profile,
                        rule: source.rule,
                        source_index: source.source_index,
                    },
                    SecretLiteralError::InvalidText => {
                        ProductRedactionActivationError::SourceInvalidUtf8 {
                            profile: source.profile,
                            rule: source.rule,
                            source_index: source.source_index,
                        }
                    }
                    SecretLiteralError::TooLarge => {
                        ProductRedactionActivationError::SourceTooLarge {
                            profile: source.profile,
                            rule: source.rule,
                            source_index: source.source_index,
                        }
                    }
                    SecretLiteralError::AllocationFailed => {
                        ProductRedactionActivationError::AllocationFailed
                    }
                })?;
            bindings.push(ExternalLiteralBinding::new(source.slot, literal));
        }
        if is_cancelled() {
            return Err(ProductRedactionActivationError::Cancelled);
        }
        http_access_redaction::RedactionSnapshot::activate(
            identity,
            version,
            self.prepared,
            bindings,
            is_cancelled,
        )
        .map_err(|error| match error {
            ActivationError::Cancelled => ProductRedactionActivationError::Cancelled,
            error => ProductRedactionActivationError::Shared(error),
        })
    }
}

fn wire_failure(error: WireBodyBufferError) -> BufferFailure {
    match error {
        WireBodyBufferError::CursorPeakExceeded
        | WireBodyBufferError::QuotaExhausted
        | WireBodyBufferError::GlobalExhausted => BufferFailure::CapacityExhausted,
        WireBodyBufferError::AllocationFailed => BufferFailure::AllocationFailed,
        WireBodyBufferError::ForeignGuard => BufferFailure::ForeignBody,
        WireBodyBufferError::ReservedLengthMismatch => BufferFailure::ReservationMismatch,
    }
}

fn capture_failure(error: CaptureAllocationError) -> BufferFailure {
    match error {
        CaptureAllocationError::CeilingExceeded => BufferFailure::CapacityExhausted,
        CaptureAllocationError::AllocationFailed => BufferFailure::AllocationFailed,
        CaptureAllocationError::ForeignAuthority => BufferFailure::ForeignBody,
        CaptureAllocationError::ReservedLengthMismatch => BufferFailure::ReservationMismatch,
    }
}

impl RedactionBody for GuardedBody {
    fn len(&self) -> usize {
        GuardedBody::len(self)
    }

    fn try_for_each_segment<E>(
        &self,
        visitor: &mut impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        for segment in self.segments() {
            visitor(segment)?;
        }
        Ok(())
    }
}

impl RedactionBody for CaptureBody {
    fn len(&self) -> usize {
        CaptureBody::len(self)
    }

    fn try_for_each_segment<E>(
        &self,
        visitor: &mut impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        for segment in self.segments() {
            visitor(segment)?;
        }
        Ok(())
    }
}

impl RedactionExactBytes for GuardedExactBytes {
    fn as_bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn as_mut_bytes(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl RedactionExactBytes for CaptureExactBytes {
    fn as_bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn as_mut_bytes(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl RedactionOutput for ReservedGuardedBodyBuilder {
    type Body = GuardedBody;

    fn try_extend(&mut self, bytes: &[u8]) -> Result<(), BufferFailure> {
        self.try_extend_from_slice(bytes).map_err(wire_failure)
    }

    fn finish(self) -> Result<Self::Body, BufferFailure> {
        self.finish().map_err(wire_failure)
    }
}

impl RedactionOutput for ReservedCaptureBodyBuilder {
    type Body = CaptureBody;

    fn try_extend(&mut self, bytes: &[u8]) -> Result<(), BufferFailure> {
        self.try_extend_from_slice(bytes).map_err(capture_failure)
    }

    fn finish(self) -> Result<Self::Body, BufferFailure> {
        self.finish().map_err(capture_failure)
    }
}

impl RedactionBufferContext for HttpWireBodyGuard {
    type Body = GuardedBody;
    type Output = ReservedGuardedBodyBuilder;
    type ExactBytes = GuardedExactBytes;
    type ScratchCharge = GuardedAllocationCharge;

    fn validate_body(&self, body: &Self::Body) -> Result<(), BufferFailure> {
        HttpWireBodyGuard::validate_body(self, body).map_err(wire_failure)
    }

    fn reserve_output(&self, len: usize) -> Result<Self::Output, BufferFailure> {
        self.reserve_exact_buffer(len).map_err(wire_failure)
    }

    fn allocate_exact_bytes(&self, len: usize) -> Result<Self::ExactBytes, BufferFailure> {
        self.exact_bytes(len).map_err(wire_failure)
    }

    fn charge_scratch(&self, bytes: usize) -> Result<Self::ScratchCharge, BufferFailure> {
        self.charge_exact_allocation(bytes).map_err(wire_failure)
    }
}

impl RedactionBufferContext for CaptureOperation {
    type Body = CaptureBody;
    type Output = ReservedCaptureBodyBuilder;
    type ExactBytes = CaptureExactBytes;
    type ScratchCharge = CaptureAllocationCharge;

    fn validate_body(&self, body: &Self::Body) -> Result<(), BufferFailure> {
        CaptureOperation::validate_body(self, body).map_err(capture_failure)
    }

    fn reserve_output(&self, len: usize) -> Result<Self::Output, BufferFailure> {
        self.reserve_exact_body(len).map_err(capture_failure)
    }

    fn allocate_exact_bytes(&self, len: usize) -> Result<Self::ExactBytes, BufferFailure> {
        self.exact_bytes(len).map_err(capture_failure)
    }

    fn charge_scratch(&self, bytes: usize) -> Result<Self::ScratchCharge, BufferFailure> {
        self.charge_exact_allocation(bytes).map_err(capture_failure)
    }
}

pub(crate) struct UpgradeRedactionBody(Zeroizing<Box<[u8]>>);

impl UpgradeRedactionBody {
    pub(crate) fn new(bytes: Vec<u8>) -> Result<Self, BufferFailure> {
        let source = Zeroizing::new(bytes);
        exact_box(&source).map(|bytes| Self(Zeroizing::new(bytes)))
    }

    pub(crate) fn into_vec(self) -> Result<Vec<u8>, BufferFailure> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.0.len())
            .map_err(|_| BufferFailure::AllocationFailed)?;
        if bytes.capacity() != self.0.len() {
            return Err(BufferFailure::AllocationFailed);
        }
        bytes.extend_from_slice(&self.0);
        Ok(bytes)
    }
}

impl RedactionBody for UpgradeRedactionBody {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn try_for_each_segment<E>(
        &self,
        visitor: &mut impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        visitor(&self.0)
    }
}

pub(crate) struct UpgradeRedactionOutput {
    bytes: Zeroizing<Box<[u8]>>,
    offset: usize,
}

impl RedactionOutput for UpgradeRedactionOutput {
    type Body = UpgradeRedactionBody;

    fn try_extend(&mut self, bytes: &[u8]) -> Result<(), BufferFailure> {
        let final_len = self
            .offset
            .checked_add(bytes.len())
            .ok_or(BufferFailure::ReservationMismatch)?;
        if final_len > self.bytes.len() {
            return Err(BufferFailure::ReservationMismatch);
        }
        self.bytes[self.offset..final_len].copy_from_slice(bytes);
        self.offset = final_len;
        Ok(())
    }

    fn finish(self) -> Result<Self::Body, BufferFailure> {
        if self.offset != self.bytes.len() {
            return Err(BufferFailure::ReservationMismatch);
        }
        Ok(UpgradeRedactionBody(self.bytes))
    }
}

pub(crate) struct UpgradeRedactionExactBytes(Zeroizing<Box<[u8]>>);

impl RedactionExactBytes for UpgradeRedactionExactBytes {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

pub(crate) struct UpgradeRedactionScratchCharge;

pub(crate) struct UpgradeRedactionContext {
    limit: usize,
    matcher_scratch_bytes: usize,
}

impl UpgradeRedactionContext {
    pub(crate) fn for_profile(profile: &http_access_redaction::RedactionProfile) -> Self {
        Self {
            limit: profile.limits().max_message_bytes(),
            matcher_scratch_bytes: profile.metrics().matcher_scratch_bytes(),
        }
    }

    fn zeroed(&self, len: usize) -> Result<Zeroizing<Box<[u8]>>, BufferFailure> {
        if len > self.limit {
            return Err(BufferFailure::CapacityExhausted);
        }
        let mut exact = Vec::new();
        exact
            .try_reserve_exact(len)
            .map_err(|_| BufferFailure::AllocationFailed)?;
        if exact.capacity() != len {
            return Err(BufferFailure::AllocationFailed);
        }
        exact.resize(len, 0);
        Ok(Zeroizing::new(exact.into_boxed_slice()))
    }
}

impl RedactionBufferContext for UpgradeRedactionContext {
    type Body = UpgradeRedactionBody;
    type Output = UpgradeRedactionOutput;
    type ExactBytes = UpgradeRedactionExactBytes;
    type ScratchCharge = UpgradeRedactionScratchCharge;

    fn validate_body(&self, body: &Self::Body) -> Result<(), BufferFailure> {
        (body.len() <= self.limit)
            .then_some(())
            .ok_or(BufferFailure::CapacityExhausted)
    }

    fn reserve_output(&self, len: usize) -> Result<Self::Output, BufferFailure> {
        if len > self.limit {
            return Err(BufferFailure::CapacityExhausted);
        }
        Ok(UpgradeRedactionOutput {
            bytes: self.zeroed(len)?,
            offset: 0,
        })
    }

    fn allocate_exact_bytes(&self, len: usize) -> Result<Self::ExactBytes, BufferFailure> {
        self.zeroed(len).map(UpgradeRedactionExactBytes)
    }

    fn charge_scratch(&self, bytes: usize) -> Result<Self::ScratchCharge, BufferFailure> {
        // The established stream retains the aggregate RAII admission that
        // includes this exact matcher-scratch projection for its full life.
        (bytes <= self.matcher_scratch_bytes)
            .then_some(UpgradeRedactionScratchCharge)
            .ok_or(BufferFailure::CapacityExhausted)
    }
}

fn exact_box(bytes: &[u8]) -> Result<Box<[u8]>, BufferFailure> {
    let mut exact = Vec::new();
    exact
        .try_reserve_exact(bytes.len())
        .map_err(|_| BufferFailure::AllocationFailed)?;
    if exact.capacity() != bytes.len() {
        return Err(BufferFailure::AllocationFailed);
    }
    exact.extend_from_slice(bytes);
    Ok(exact.into_boxed_slice())
}

#[cfg(test)]
pub(crate) struct TestProfile {
    pub(crate) name: String,
    pub(crate) replacement: Vec<u8>,
    pub(crate) max_body_bytes: usize,
    pub(crate) max_decoded_body_bytes: usize,
    pub(crate) max_frame_bytes: usize,
    pub(crate) max_message_bytes: usize,
    pub(crate) allow_permessage_deflate: bool,
    pub(crate) literals: Vec<Vec<u8>>,
}

#[cfg(test)]
pub(crate) fn test_snapshot(
    profiles: Vec<TestProfile>,
) -> (
    http_access_redaction::RedactionSnapshot,
    BTreeMap<String, http_access_types::RedactionRef>,
) {
    use http_access_redaction::{
        RedactionProfileSpec, RedactionRuleSpec, RedactionSnapshotSpec, RulePayloads,
    };
    use http_access_types::{RedactionRef, SnapshotIdentity, StableId};

    let identity = SnapshotIdentity::new();
    let version = 1;
    let mut references = BTreeMap::new();
    let specs = profiles
        .into_iter()
        .map(|profile| {
            let id = StableId::new(profile.name.clone()).unwrap();
            references.insert(
                profile.name,
                RedactionRef::new(identity.clone(), id.clone(), version).unwrap(),
            );
            let limits = RedactionLimits::new(
                profile.max_body_bytes,
                profile.max_decoded_body_bytes,
                profile.max_frame_bytes,
                profile.max_message_bytes,
                profile.allow_permessage_deflate,
                1,
                1,
                1,
            )
            .unwrap();
            RedactionProfileSpec::new(
                id,
                profile.replacement,
                limits,
                vec![RedactionRuleSpec::new(
                    if profile.literals.is_empty() {
                        vec![b"__test_no_match__".to_vec()]
                    } else {
                        profile.literals
                    },
                    Vec::new(),
                    Vec::new(),
                    RulePayloads::Both,
                )],
            )
        })
        .collect();
    let prepared =
        PreparedRedactionSnapshot::prepare(RedactionSnapshotSpec::new(specs), || false).unwrap();
    let snapshot = http_access_redaction::RedactionSnapshot::activate(
        identity,
        version,
        prepared,
        Vec::new(),
        || false,
    )
    .unwrap();
    (snapshot, references)
}

#[cfg(test)]
mod product_source_tests {
    use super::*;
    use http_access_redaction::{
        RedactionProfileSpec, RedactionRuleSpec, RedactionSnapshotSpec, RulePayloads,
    };
    use http_access_types::StableId;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn source_plan(variable: &str, max_bytes: usize) -> ProductRedactionPlan {
        let slot = ExternalLiteralSlot::new();
        let limits = RedactionLimits::new(64, 64, 64, 64, false, 1, max_bytes, max_bytes).unwrap();
        let spec = RedactionSnapshotSpec::new(vec![RedactionProfileSpec::new(
            StableId::new("source-test").unwrap(),
            b"[MASKED]".to_vec(),
            limits,
            vec![RedactionRuleSpec::new(
                Vec::new(),
                vec![slot.clone()],
                Vec::new(),
                RulePayloads::Both,
            )],
        )]);
        ProductRedactionPlan {
            profiles: BTreeMap::new(),
            prepared: PreparedRedactionSnapshot::prepare(spec, || false).unwrap(),
            sources: vec![ProductExternalLiteralSource {
                slot,
                variable: variable.to_owned(),
                profile: 0,
                rule: 0,
                source_index: 0,
                max_bytes,
            }],
        }
    }

    fn activate(
        plan: ProductRedactionPlan,
    ) -> Result<http_access_redaction::RedactionSnapshot, ProductRedactionActivationError> {
        plan.activate(SnapshotIdentity::new(), 1, || false)
    }

    #[test]
    fn required_environment_source_is_sanitized_and_fail_closed() {
        const VARIABLE: &str = "ACL_PROXY_REDACTION_REQUIRED_7E31";
        std::env::remove_var(VARIABLE);
        let error = activate(source_plan(VARIABLE, 64)).unwrap_err();
        assert_eq!(
            error,
            ProductRedactionActivationError::SourceUnavailable {
                profile: 0,
                rule: 0,
                source_index: 0,
            }
        );
        assert!(!error.to_string().contains(VARIABLE));
    }

    #[test]
    fn empty_environment_source_is_rejected() {
        const VARIABLE: &str = "ACL_PROXY_REDACTION_EMPTY_63A2";
        std::env::set_var(VARIABLE, "");
        let error = activate(source_plan(VARIABLE, 64)).unwrap_err();
        std::env::remove_var(VARIABLE);
        assert_eq!(
            error,
            ProductRedactionActivationError::SourceEmpty {
                profile: 0,
                rule: 0,
                source_index: 0,
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_environment_source_is_rejected() {
        use std::os::unix::ffi::OsStringExt;

        const VARIABLE: &str = "ACL_PROXY_REDACTION_NON_UTF8_019B";
        std::env::set_var(VARIABLE, std::ffi::OsString::from_vec(vec![0xff]));
        let error = activate(source_plan(VARIABLE, 64)).unwrap_err();
        std::env::remove_var(VARIABLE);
        assert_eq!(
            error,
            ProductRedactionActivationError::SourceInvalidUtf8 {
                profile: 0,
                rule: 0,
                source_index: 0,
            }
        );
    }

    #[test]
    fn oversized_environment_source_is_rejected_before_secret_binding() {
        const VARIABLE: &str = "ACL_PROXY_REDACTION_OVERSIZED_2D6C";
        std::env::set_var(VARIABLE, "too-large");
        let error = activate(source_plan(VARIABLE, 4)).unwrap_err();
        std::env::remove_var(VARIABLE);
        assert_eq!(
            error,
            ProductRedactionActivationError::SourceTooLarge {
                profile: 0,
                rule: 0,
                source_index: 0,
            }
        );
    }

    #[test]
    fn cancellation_after_environment_read_wins_even_when_source_is_missing() {
        const VARIABLE: &str = "ACL_PROXY_REDACTION_CANCELLED_READ_D4F8";
        std::env::remove_var(VARIABLE);
        let checks = AtomicUsize::new(0);
        let error = source_plan(VARIABLE, 64)
            .activate(SnapshotIdentity::new(), 1, || {
                checks.fetch_add(1, Ordering::SeqCst) == 1
            })
            .unwrap_err();
        assert_eq!(error, ProductRedactionActivationError::Cancelled);
        assert_eq!(checks.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn cancellation_after_environment_read_wins_with_a_present_secret() {
        const VARIABLE: &str = "ACL_PROXY_REDACTION_CANCELLED_SECRET_E2C7";
        std::env::set_var(VARIABLE, "secret-value");
        let checks = AtomicUsize::new(0);
        let error = source_plan(VARIABLE, 64)
            .activate(SnapshotIdentity::new(), 1, || {
                checks.fetch_add(1, Ordering::SeqCst) == 1
            })
            .unwrap_err();
        std::env::remove_var(VARIABLE);
        assert_eq!(error, ProductRedactionActivationError::Cancelled);
        assert_eq!(checks.load(Ordering::SeqCst), 2);
    }
}
