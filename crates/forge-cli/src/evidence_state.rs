//! Content-addressed encoding and schema-aware decoding for immutable Evidence state.

mod canonical_json;
mod contract_shape;

use std::collections::{BTreeMap, BTreeSet};

use forge_core::domain::{CommandEnforcement, CoverageDimension, Intent, Mutability};
use forge_core::evidence::{
    BaseTaskDependency, CommandEvidenceObservation, DependencyValue, EvidenceDependencyFingerprint,
    EvidenceOutcome, ExecutionDependencyFingerprint, ReceiptValidityInput,
    aggregate_command_evidence,
};
use forge_core::fingerprint::process_output_unavailable_digests;
use forge_core::{Digest, coverage_dimension_name, evidence_outcome_to_wire};
use forge_runtime::hash::Blake3Hasher;
use forge_runtime::state::{
    EVIDENCE_GC_MAX_RECEIPTS, EVIDENCE_OBJECT_MAX_BYTES, EvidenceRetentionMetadata,
    EvidenceRetentionTime, EvidenceStateDecodeError, EvidenceStateMetadataDecoder,
    EvidenceStateObjectName, EvidenceStateVersion, RECEIPT_OBJECT_MAX_BYTES,
    ReceiptRetentionMetadata, ReceiptStateReference, ReferenceClosure, UtcTimestamp,
    parse_utc_rfc3339,
};
use forge_schema::{
    BaseTaskDependencyV2Data, CommandDetailV2Data, CommandEnforcementData,
    ComparisonBaselineV2Data, ComparisonBasisV2Data, ComparisonProtocolV2Data,
    DigestDependencyV2Data, Envelope, EvidenceData, EvidenceId, EvidenceV2Data,
    GitObjectFormatV2Data, GitObjectIdV2Data, IntentData, JsonErrorStatusV2Data, MutabilityData,
    NativeStringData, NativeStringEncodingData, OutcomeData, PathEncoding, ReceiptData, ReceiptId,
    ReceiptV2Data, ReceiptValidityReasonV2Data, ReceiptValidityV2Data, RepositoryDependencyV2Data,
    SchemaKind, StaleReceiptV2Data, TaskAcceptanceV2Data, WirePath,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use self::canonical_json::ParsedJson;
use self::contract_shape::has_unknown_contract_content;

const RECEIPT_IDENTITY_DOMAIN: &[u8] = b"forge.receipt-identity/v1";
const EVIDENCE_IDENTITY_DOMAIN: &[u8] = b"forge.evidence-identity/v1";
const RECEIPT_BINDING_COVERAGE_DOMAIN: &[u8] = b"forge.receipt-binding-coverage/v1";
const RECEIPT_ID_PREFIX: &str = "receipt:blake3:";
const EVIDENCE_ID_PREFIX: &str = "evidence:blake3:";
const LOG_PATH_PREFIX: &str = "logs/v1/";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DocumentKind {
    Receipt,
    Evidence,
}

impl DocumentKind {
    const fn identity_domain(self) -> &'static [u8] {
        match self {
            Self::Receipt => RECEIPT_IDENTITY_DOMAIN,
            Self::Evidence => EVIDENCE_IDENTITY_DOMAIN,
        }
    }

    const fn id_prefix(self) -> &'static str {
        match self {
            Self::Receipt => RECEIPT_ID_PREFIX,
            Self::Evidence => EVIDENCE_ID_PREFIX,
        }
    }

    const fn max_bytes(self) -> usize {
        match self {
            Self::Receipt => RECEIPT_OBJECT_MAX_BYTES,
            Self::Evidence => EVIDENCE_OBJECT_MAX_BYTES,
        }
    }
}

/// A current immutable object whose identity and retention metadata were validated together.
///
/// Construction stays private so callers cannot pair arbitrary bytes with a trusted filename.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparedEvidenceStateObject {
    object_name: EvidenceStateObjectName,
    bytes: Vec<u8>,
}

impl PreparedEvidenceStateObject {
    #[must_use]
    pub(crate) const fn object_name(&self) -> &EvidenceStateObjectName {
        &self.object_name
    }

    #[must_use]
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// JSON implementation of the storage layer's fail-closed metadata boundary.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct JsonEvidenceStateCodec;

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedReceipt {
    V1(Envelope<ReceiptData>),
    V2(Envelope<ReceiptV2Data>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedEvidence {
    V1(Envelope<EvidenceData>),
    V2(Envelope<EvidenceV2Data>),
}

/// A Receipt whose schema, content identity, and filename were validated together.
///
/// Same-major fields unknown to this binary participate in immutable identity and make the Receipt
/// non-proving. The caller retains the original snapshot bytes; this wrapper keeps only the bounded
/// typed facts needed for validation and current evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedReceipt {
    version: EvidenceStateVersion,
    object_name: EvidenceStateObjectName,
    // Typed `unknown` dependencies remain safe to project into the pure validity evaluator even
    // though they can never make the Receipt proving. Future/opaque contract content does not.
    can_evaluate_current_validity: bool,
    // This stronger predicate also guards persisted `valid_receipts` bindings.
    can_support_current_evidence: bool,
    parsed: ParsedReceipt,
}

impl ValidatedReceipt {
    fn parsed(&self) -> &ParsedReceipt {
        &self.parsed
    }

    fn state_reference(&self) -> ReceiptStateReference {
        ReceiptStateReference::new(self.version, self.object_name.clone())
    }

    /// Copies only the bounded facts needed to bind an Evidence summary to this Receipt.
    ///
    /// The raw immutable document remains behind the validated Receipt boundary. In particular,
    /// retaining binding facts for an Evidence run cannot accidentally retain every Receipt body.
    #[must_use]
    pub(crate) fn binding_fact(&self) -> ReceiptBindingFact {
        let (intent, outcome, coverage_digest) = match self.parsed() {
            ParsedReceipt::V1(envelope) => (envelope.data.intent, envelope.data.outcome, None),
            ParsedReceipt::V2(envelope) => (
                envelope.data.intent,
                envelope.data.outcome,
                Some(receipt_binding_coverage_digest(&envelope.data.coverage)),
            ),
        };
        ReceiptBindingFact {
            reference: self.state_reference(),
            can_support_current_evidence: self.can_support_current_evidence,
            intent,
            outcome,
            coverage_digest,
        }
    }

    /// Projects only the facts needed for current validity evaluation and Evidence binding.
    ///
    /// Historical v1 and same-major v2 extensions remain visible but have no `current` facts and
    /// therefore cannot become proving observations.
    pub(crate) fn evaluation_projection(
        &self,
    ) -> Result<ReceiptEvaluationProjection, EvidenceStateDecodeError> {
        let binding = self.binding_fact();
        match self.parsed() {
            ParsedReceipt::V1(envelope) => Ok(ReceiptEvaluationProjection {
                version: EvidenceStateVersion::V1,
                binding,
                id: envelope.data.id.clone(),
                intent: envelope.data.intent,
                domain_intent: intent_from_wire(envelope.data.intent),
                started_at: None,
                outcome: outcome_from_wire(envelope.data.outcome),
                coverage: Vec::new(),
                current: None,
            }),
            ParsedReceipt::V2(envelope) => {
                let receipt = &envelope.data;
                let started_at = parse_utc_rfc3339(&receipt.started_at)
                    .map_err(|_| EvidenceStateDecodeError::InvalidTimestamp)?;
                let current = self
                    .can_evaluate_current_validity
                    .then(|| current_receipt_projection(receipt))
                    .transpose()?;
                Ok(ReceiptEvaluationProjection {
                    version: EvidenceStateVersion::V2,
                    binding,
                    id: receipt.id.clone(),
                    intent: receipt.intent,
                    domain_intent: intent_from_wire(receipt.intent),
                    started_at: Some(started_at),
                    outcome: outcome_from_wire(receipt.outcome),
                    coverage: receipt.coverage.clone(),
                    current,
                })
            }
        }
    }
}

fn current_receipt_projection(
    receipt: &ReceiptV2Data,
) -> Result<CurrentReceiptEvaluationProjection, EvidenceStateDecodeError> {
    let dependencies = &receipt.dependencies;
    let repository = match &dependencies.repository {
        RepositoryDependencyV2Data::Known(value) => DependencyValue::Known(value.clone()),
        RepositoryDependencyV2Data::Unknown => DependencyValue::Unknown,
        _ => return Err(EvidenceStateDecodeError::Malformed),
    };
    let scope_before = digest_dependency_from_wire(&dependencies.scope_before)?;
    let execution = ExecutionDependencyFingerprint::new(
        digest_dependency_from_wire(&dependencies.command)?,
        digest_dependency_from_wire(&dependencies.toolchain)?,
        digest_dependency_from_wire(&dependencies.environment)?,
    );
    let fingerprint = EvidenceDependencyFingerprint::new(
        repository,
        digest_dependency_from_wire(&dependencies.scope_after)?,
        execution,
        digest_dependency_from_wire(&dependencies.policy)?,
        match &dependencies.base_task {
            BaseTaskDependencyV2Data::Known(value) => BaseTaskDependency::Known(value.clone()),
            BaseTaskDependencyV2Data::NotApplicable => BaseTaskDependency::NotApplicable,
            BaseTaskDependencyV2Data::Unknown => BaseTaskDependency::Unknown,
            _ => return Err(EvidenceStateDecodeError::Malformed),
        },
        digest_dependency_from_wire(&dependencies.forge_behavior)?,
    );
    let mutability = aggregate_receipt_mutability(
        receipt
            .observations
            .iter()
            .map(|observation| observation.command.command.mutability),
    );
    let aggregate_inputs = receipt
        .observations
        .iter()
        .map(|observation| {
            let enforcement = enforcement_from_wire(observation.command.enforcement)
                .ok_or(EvidenceStateDecodeError::Malformed)?;
            let coverage = coverage_from_wire(&observation.command.command.coverage)?;
            if !coverage.complete {
                return Err(EvidenceStateDecodeError::Malformed);
            }
            Ok(CommandEvidenceObservation::new(
                enforcement,
                outcome_from_wire(observation.outcome),
                coverage.dimensions,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let aggregation = aggregate_command_evidence(&aggregate_inputs);
    Ok(CurrentReceiptEvaluationProjection {
        commands: receipt
            .observations
            .iter()
            .map(|observation| observation.command.clone())
            .collect(),
        recorded: ReceiptValidityInput::new(
            fingerprint,
            scope_before,
            mutability,
            outcome_from_wire(receipt.outcome),
        ),
        advisory: aggregation
            .advisory()
            .iter()
            .map(coverage_dimension_name)
            .collect(),
        not_verified: aggregation
            .not_verified()
            .iter()
            .map(coverage_dimension_name)
            .collect(),
    })
}

fn digest_dependency_from_wire(
    dependency: &DigestDependencyV2Data,
) -> Result<DependencyValue<Digest>, EvidenceStateDecodeError> {
    match dependency {
        DigestDependencyV2Data::Known(value) => Ok(DependencyValue::Known(value.clone())),
        DigestDependencyV2Data::Unknown => Ok(DependencyValue::Unknown),
        _ => Err(EvidenceStateDecodeError::Malformed),
    }
}

fn aggregate_receipt_mutability(values: impl IntoIterator<Item = MutabilityData>) -> Mutability {
    let mut aggregate = Mutability::ReadOnly;
    for value in values {
        match value {
            MutabilityData::WorkingTreeWrite => return Mutability::WorkingTreeWrite,
            MutabilityData::ExternalSideEffect => aggregate = Mutability::ExternalSideEffect,
            MutabilityData::ReadOnly => {}
            MutabilityData::Unknown => return Mutability::Unknown,
            _ => return Mutability::Unknown,
        }
    }
    aggregate
}

/// Fixed-size semantic projection of a validated Receipt used while preparing Evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReceiptBindingFact {
    reference: ReceiptStateReference,
    can_support_current_evidence: bool,
    intent: IntentData,
    outcome: OutcomeData,
    coverage_digest: Option<Digest>,
}

impl ReceiptBindingFact {
    pub(crate) const fn can_support_current_evidence(&self) -> bool {
        self.can_support_current_evidence
    }
}

/// Compact facts copied from one identity-validated Receipt while visiting immutable state.
///
/// The scanner can evaluate and then drop this value in one callback. Only fixed binding facts are
/// retained across callbacks, so a repository with many maximum-size Receipt objects does not make
/// every raw document resident at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReceiptEvaluationProjection {
    pub(crate) version: EvidenceStateVersion,
    pub(crate) binding: ReceiptBindingFact,
    pub(crate) id: ReceiptId,
    pub(crate) intent: IntentData,
    pub(crate) domain_intent: Option<Intent>,
    pub(crate) started_at: Option<UtcTimestamp>,
    pub(crate) outcome: EvidenceOutcome,
    pub(crate) coverage: Vec<String>,
    pub(crate) current: Option<CurrentReceiptEvaluationProjection>,
}

/// Current-v2-only facts whose complete semantics were validated by the codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CurrentReceiptEvaluationProjection {
    pub(crate) commands: Vec<CommandDetailV2Data>,
    pub(crate) recorded: ReceiptValidityInput,
    pub(crate) advisory: Vec<String>,
    pub(crate) not_verified: Vec<String>,
}

/// An Evidence document whose schema, content identity, and filename were validated together.
///
/// Persisted `valid_receipts`, coverage, and `local_state` remain historical summaries. This type
/// intentionally grants no current sufficiency meaning; current decisions must reload Receipt
/// objects, recompute freshness and policy, and aggregate again. The caller retains the original
/// snapshot bytes while this wrapper keeps only bounded typed facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedEvidence {
    parsed: ParsedEvidence,
}

impl ValidatedEvidence {
    fn parsed(&self) -> &ParsedEvidence {
        &self.parsed
    }
}

/// Checks every persisted Evidence receipt summary against its immutable referenced object.
///
/// A successful result does not establish dependency freshness, policy sufficiency, or local
/// validity. Callers must recompute all three from Receipt facts and current repository inputs.
pub(crate) fn validate_evidence_receipt_bindings<'a>(
    evidence: &ValidatedEvidence,
    receipts: impl IntoIterator<Item = &'a ReceiptBindingFact>,
) -> Result<(), EvidenceStateDecodeError> {
    let summaries = match evidence.parsed() {
        ParsedEvidence::V1(envelope) => EvidenceReceiptSummaries::V1(&envelope.data),
        ParsedEvidence::V2(envelope) => EvidenceReceiptSummaries::V2(&envelope.data),
    };
    validate_receipt_bindings(summaries, receipts)
}

#[derive(Debug, Clone, Copy)]
enum EvidenceReceiptSummaries<'a> {
    V1(&'a EvidenceData),
    V2(&'a EvidenceV2Data),
}

fn validate_receipt_bindings<'a>(
    summaries: EvidenceReceiptSummaries<'_>,
    receipts: impl IntoIterator<Item = &'a ReceiptBindingFact>,
) -> Result<(), EvidenceStateDecodeError> {
    let mut index = BTreeMap::new();
    for (offset, receipt) in receipts.into_iter().enumerate() {
        if offset >= EVIDENCE_GC_MAX_RECEIPTS {
            return Err(EvidenceStateDecodeError::Malformed);
        }
        if index.insert(receipt.reference.clone(), receipt).is_some() {
            return Err(EvidenceStateDecodeError::InvalidReference);
        }
    }

    let mut references = BTreeSet::new();
    match summaries {
        EvidenceReceiptSummaries::V1(evidence) => {
            for summary in &evidence.valid_receipts {
                let reference = receipt_reference(EvidenceStateVersion::V1, summary.id.as_str())?;
                let receipt = require_indexed_receipt(&index, &reference)?;
                if receipt.intent != summary.intent || receipt.outcome != summary.outcome {
                    return Err(EvidenceStateDecodeError::InvalidReference);
                }
                references.insert(reference);
            }
            for summary in &evidence.stale_receipts {
                let reference = receipt_reference(EvidenceStateVersion::V1, summary.id.as_str())?;
                require_indexed_receipt(&index, &reference)?;
                references.insert(reference);
            }
        }
        EvidenceReceiptSummaries::V2(evidence) => {
            for summary in &evidence.valid_receipts {
                let reference = receipt_reference(EvidenceStateVersion::V2, summary.id.as_str())?;
                let receipt = require_indexed_receipt(&index, &reference)?;
                // The v2 semantic validator makes `can_support_current_evidence` false for every
                // unknown or incomplete contract fact. Check that proving predicate before binding
                // a persisted valid-Receipt summary.
                if !receipt.can_support_current_evidence
                    || receipt.intent != summary.intent
                    || receipt.outcome != OutcomeData::Pass
                    || receipt.coverage_digest.as_ref()
                        != Some(&receipt_binding_coverage_digest(&summary.coverage))
                {
                    return Err(EvidenceStateDecodeError::InvalidReference);
                }
                references.insert(reference);
            }
            for summary in &evidence.stale_receipts {
                let (reference, matches) = match summary {
                    StaleReceiptV2Data::ReceiptV1 {
                        id,
                        intent,
                        outcome,
                        ..
                    } => {
                        let reference = receipt_reference(EvidenceStateVersion::V1, id.as_str())?;
                        let receipt = require_indexed_receipt(&index, &reference)?;
                        let matches = receipt.intent == *intent && receipt.outcome == *outcome;
                        (reference, matches)
                    }
                    StaleReceiptV2Data::ReceiptV2 {
                        id,
                        intent,
                        validity,
                    } => {
                        let reference = receipt_reference(EvidenceStateVersion::V2, id.as_str())?;
                        let receipt = require_indexed_receipt(&index, &reference)?;
                        let matches = receipt.intent == *intent
                            && receipt.outcome == validity.as_inner().outcome;
                        (reference, matches)
                    }
                    _ => continue,
                };
                if !matches || !references.insert(reference) {
                    return Err(EvidenceStateDecodeError::InvalidReference);
                }
            }
        }
    }

    Ok(())
}

fn require_indexed_receipt<'a>(
    index: &BTreeMap<ReceiptStateReference, &'a ReceiptBindingFact>,
    reference: &ReceiptStateReference,
) -> Result<&'a ReceiptBindingFact, EvidenceStateDecodeError> {
    index
        .get(reference)
        .copied()
        .ok_or(EvidenceStateDecodeError::InvalidReference)
}

/// Loads a Receipt without exposing a plain-deserialization path that could skip identity checks.
pub(crate) fn load_receipt(
    version: EvidenceStateVersion,
    filename: &EvidenceStateObjectName,
    bytes: &[u8],
) -> Result<ValidatedReceipt, EvidenceStateDecodeError> {
    let decoded = decode_receipt(version, bytes)?;
    if &decoded.object_name != filename {
        return Err(EvidenceStateDecodeError::InvalidReference);
    }
    Ok(ValidatedReceipt {
        version,
        object_name: decoded.object_name,
        can_evaluate_current_validity: decoded.can_evaluate_current_validity,
        can_support_current_evidence: decoded.can_support_current_evidence,
        parsed: decoded.document,
    })
}

/// Loads Evidence without exposing a plain-deserialization path that could skip identity checks.
pub(crate) fn load_evidence(
    version: EvidenceStateVersion,
    filename: &EvidenceStateObjectName,
    bytes: &[u8],
) -> Result<ValidatedEvidence, EvidenceStateDecodeError> {
    let decoded = decode_evidence(version, bytes)?;
    if &decoded.object_name != filename {
        return Err(EvidenceStateDecodeError::InvalidReference);
    }
    Ok(ValidatedEvidence {
        parsed: decoded.document,
    })
}

impl EvidenceStateMetadataDecoder for JsonEvidenceStateCodec {
    fn decode_receipt(
        &self,
        version: EvidenceStateVersion,
        bytes: &[u8],
    ) -> Result<ReceiptRetentionMetadata, EvidenceStateDecodeError> {
        Ok(decode_receipt(version, bytes)?.metadata)
    }

    fn decode_evidence(
        &self,
        version: EvidenceStateVersion,
        bytes: &[u8],
    ) -> Result<EvidenceRetentionMetadata, EvidenceStateDecodeError> {
        Ok(decode_evidence(version, bytes)?.metadata)
    }
}

/// Assigns the content identity, emits deterministic pretty JSON, and validates the result.
pub(crate) fn prepare_receipt(
    mut envelope: Envelope<ReceiptV2Data>,
) -> Result<PreparedEvidenceStateObject, EvidenceStateDecodeError> {
    validate_writable_envelope(&envelope.schema, envelope.ok, envelope.truncated, "receipt")?;
    if !validate_receipt_v2_semantics(&envelope.data, false)?.diagnostic_summaries_are_current {
        return Err(EvidenceStateDecodeError::Malformed);
    }
    let raw = serde_json::to_value(&envelope).map_err(|_| EvidenceStateDecodeError::Malformed)?;
    let (public_id, _) = calculate_identity(&raw, DocumentKind::Receipt)?;
    envelope.data.id = ReceiptId::new(public_id);
    prepare_document(envelope, DocumentKind::Receipt)
}

/// Binds every Receipt summary, assigns the content identity, and validates the encoded result.
///
/// Requiring compact facts here makes it impossible to obtain persistable Evidence bytes from an
/// unverified caller-authored summary. The facts must themselves come from [`ValidatedReceipt`].
pub(crate) fn prepare_evidence<'a>(
    mut envelope: Envelope<EvidenceV2Data>,
    receipt_facts: impl IntoIterator<Item = &'a ReceiptBindingFact>,
) -> Result<PreparedEvidenceStateObject, EvidenceStateDecodeError> {
    validate_writable_envelope(
        &envelope.schema,
        envelope.ok,
        envelope.truncated,
        "evidence",
    )?;
    validate_evidence_v2_semantics(&envelope.data)?;
    validate_receipt_bindings(EvidenceReceiptSummaries::V2(&envelope.data), receipt_facts)?;
    let raw = serde_json::to_value(&envelope).map_err(|_| EvidenceStateDecodeError::Malformed)?;
    let (public_id, _) = calculate_identity(&raw, DocumentKind::Evidence)?;
    envelope.data.id = EvidenceId::new(public_id);
    prepare_document(envelope, DocumentKind::Evidence)
}

fn prepare_document<T: Serialize>(
    envelope: Envelope<T>,
    kind: DocumentKind,
) -> Result<PreparedEvidenceStateObject, EvidenceStateDecodeError> {
    let mut bytes =
        serde_json::to_vec_pretty(&envelope).map_err(|_| EvidenceStateDecodeError::Malformed)?;
    bytes.push(b'\n');
    let object_name = match kind {
        DocumentKind::Receipt => decode_receipt(EvidenceStateVersion::V2, &bytes)?.object_name,
        DocumentKind::Evidence => decode_evidence(EvidenceStateVersion::V2, &bytes)?.object_name,
    };
    Ok(PreparedEvidenceStateObject { object_name, bytes })
}

fn validate_writable_envelope(
    schema: &str,
    ok: bool,
    truncated: bool,
    domain: &str,
) -> Result<(), EvidenceStateDecodeError> {
    if schema != format!("forge.{domain}/v2") || !ok || truncated {
        return Err(EvidenceStateDecodeError::Malformed);
    }
    Ok(())
}

#[derive(Debug)]
struct DecodedReceipt {
    object_name: EvidenceStateObjectName,
    metadata: ReceiptRetentionMetadata,
    can_evaluate_current_validity: bool,
    can_support_current_evidence: bool,
    document: ParsedReceipt,
}

#[derive(Debug)]
struct DecodedEvidence {
    object_name: EvidenceStateObjectName,
    metadata: EvidenceRetentionMetadata,
    document: ParsedEvidence,
}

fn decode_receipt(
    version: EvidenceStateVersion,
    bytes: &[u8],
) -> Result<DecodedReceipt, EvidenceStateDecodeError> {
    let raw = parse_identity_json(bytes, DocumentKind::Receipt)?;
    let schema_kind = match version {
        EvidenceStateVersion::V1 => SchemaKind::ReceiptV1,
        EvidenceStateVersion::V2 => SchemaKind::Receipt,
    };
    let has_unknown_contract_content = has_unknown_contract_content(schema_kind, raw.semantic())
        .map_err(|()| EvidenceStateDecodeError::Malformed)?;
    match version {
        EvidenceStateVersion::V1 => {
            // The v1 wire schema predates immutable storage, but this repository has never had a
            // writer for the v1 directories. ADR-0021 therefore governs staged historical v1
            // objects too; accepting a looser legacy ID would silently invent a compatibility
            // contract. Supporting such objects later requires an explicit migration.
            let envelope: Envelope<ReceiptData> =
                parse_envelope(&raw, "receipt", EvidenceStateVersion::V1)?;
            let object_name =
                validate_identity(&raw, envelope.data.id.as_str(), DocumentKind::Receipt)?;
            let decoded_log_references = receipt_v1_log_references(&envelope.data)?;
            let log_references = if has_unknown_contract_content || !decoded_log_references.complete
            {
                ReferenceClosure::retain_all()
            } else {
                ReferenceClosure::complete(decoded_log_references.references)
            };
            Ok(DecodedReceipt {
                metadata: ReceiptRetentionMetadata::with_log_reference_closure(
                    object_name.clone(),
                    EvidenceRetentionTime::Legacy,
                    log_references,
                ),
                object_name,
                can_evaluate_current_validity: false,
                can_support_current_evidence: false,
                document: ParsedReceipt::V1(envelope),
            })
        }
        EvidenceStateVersion::V2 => {
            let envelope: Envelope<ReceiptV2Data> =
                parse_envelope(&raw, "receipt", EvidenceStateVersion::V2)?;
            let object_name =
                validate_identity(&raw, envelope.data.id.as_str(), DocumentKind::Receipt)?;
            let started_at = parse_utc_rfc3339(&envelope.data.started_at)
                .map_err(|_| EvidenceStateDecodeError::InvalidTimestamp)?;
            let ReceiptV2SemanticValidation {
                log_references: known_log_references,
                log_references_complete,
                can_evaluate_current_validity,
                can_support_current_evidence,
                diagnostic_summaries_are_current: _,
            } = validate_receipt_v2_semantics(&envelope.data, has_unknown_contract_content)?;
            let log_references = if has_unknown_contract_content || !log_references_complete {
                ReferenceClosure::retain_all()
            } else {
                ReferenceClosure::complete(known_log_references)
            };
            Ok(DecodedReceipt {
                metadata: ReceiptRetentionMetadata::with_log_reference_closure(
                    object_name.clone(),
                    EvidenceRetentionTime::Current(started_at),
                    log_references,
                ),
                object_name,
                can_evaluate_current_validity,
                can_support_current_evidence,
                document: ParsedReceipt::V2(envelope),
            })
        }
    }
}

fn decode_evidence(
    version: EvidenceStateVersion,
    bytes: &[u8],
) -> Result<DecodedEvidence, EvidenceStateDecodeError> {
    let raw = parse_identity_json(bytes, DocumentKind::Evidence)?;
    let schema_kind = match version {
        EvidenceStateVersion::V1 => SchemaKind::EvidenceV1,
        EvidenceStateVersion::V2 => SchemaKind::Evidence,
    };
    let has_unknown_contract_content = has_unknown_contract_content(schema_kind, raw.semantic())
        .map_err(|()| EvidenceStateDecodeError::Malformed)?;
    match version {
        EvidenceStateVersion::V1 => {
            // See the matching Receipt branch: v1 is historical/read-only, not an escape hatch
            // around ADR-0021 content-address validation.
            let envelope: Envelope<EvidenceData> =
                parse_envelope(&raw, "evidence", EvidenceStateVersion::V1)?;
            let object_name =
                validate_identity(&raw, envelope.data.id.as_str(), DocumentKind::Evidence)?;
            let known_receipts = evidence_v1_receipt_references(&envelope.data)?;
            if known_receipts.len()
                != envelope.data.valid_receipts.len() + envelope.data.stale_receipts.len()
            {
                return Err(EvidenceStateDecodeError::InvalidReference);
            }
            let (receipt_references, log_references) = if has_unknown_contract_content {
                (
                    ReferenceClosure::retain_all(),
                    ReferenceClosure::retain_all(),
                )
            } else {
                (
                    ReferenceClosure::complete(known_receipts),
                    ReferenceClosure::complete([]),
                )
            };
            Ok(DecodedEvidence {
                metadata: EvidenceRetentionMetadata::with_reference_closures(
                    object_name.clone(),
                    EvidenceRetentionTime::Legacy,
                    receipt_references,
                    log_references,
                ),
                object_name,
                document: ParsedEvidence::V1(envelope),
            })
        }
        EvidenceStateVersion::V2 => {
            validate_raw_evidence_receipt_ids_in_document(raw.semantic())?;
            let envelope = parse_evidence_v2_envelope(&raw, has_unknown_contract_content)?;
            let object_name =
                validate_identity(&raw, envelope.data.id.as_str(), DocumentKind::Evidence)?;
            let created_at = parse_utc_rfc3339(&envelope.data.created_at)
                .map_err(|_| EvidenceStateDecodeError::InvalidTimestamp)?;
            let (known_receipts, known_logs, log_references_complete) =
                validate_evidence_v2_semantics(&envelope.data)?;
            let receipt_references = if has_unknown_contract_content {
                ReferenceClosure::retain_all()
            } else {
                ReferenceClosure::complete(known_receipts)
            };
            let log_references = if has_unknown_contract_content || !log_references_complete {
                ReferenceClosure::retain_all()
            } else {
                ReferenceClosure::complete(known_logs)
            };
            Ok(DecodedEvidence {
                metadata: EvidenceRetentionMetadata::with_reference_closures(
                    object_name.clone(),
                    EvidenceRetentionTime::Current(created_at),
                    receipt_references,
                    log_references,
                ),
                object_name,
                document: ParsedEvidence::V2(envelope),
            })
        }
    }
}

fn parse_envelope<T: DeserializeOwned + PartialEq>(
    raw: &ParsedJson,
    domain: &str,
    version: EvidenceStateVersion,
) -> Result<Envelope<T>, EvidenceStateDecodeError> {
    validate_schema(raw.semantic(), domain, version)?;
    let envelope: Envelope<T> =
        deserialize_consistent_semantic_projection(raw.semantic(), raw.alternate_semantic())?;
    if !envelope.ok || envelope.truncated {
        return Err(EvidenceStateDecodeError::Malformed);
    }
    Ok(envelope)
}

fn parse_evidence_v2_envelope(
    raw: &ParsedJson,
    has_unknown_contract_content: bool,
) -> Result<Envelope<EvidenceV2Data>, EvidenceStateDecodeError> {
    match parse_envelope(raw, "evidence", EvidenceStateVersion::V2) {
        Ok(envelope) => Ok(envelope),
        Err(EvidenceStateDecodeError::Malformed) if has_unknown_contract_content => {
            let projected = project_forward_compatible_stale_receipts(raw.semantic())?;
            let alternate = raw
                .alternate_semantic()
                .map(project_forward_compatible_stale_receipts)
                .transpose()?;
            let envelope: Envelope<EvidenceV2Data> =
                deserialize_consistent_semantic_projection(&projected, alternate.as_ref())?;
            if !envelope.ok || envelope.truncated {
                return Err(EvidenceStateDecodeError::Malformed);
            }
            Ok(envelope)
        }
        Err(error) => Err(error),
    }
}

fn deserialize_consistent_semantic_projection<T: DeserializeOwned + PartialEq>(
    value: &Value,
    alternate: Option<&Value>,
) -> Result<T, EvidenceStateDecodeError> {
    let parsed: T =
        serde_json::from_value(value.clone()).map_err(|_| EvidenceStateDecodeError::Malformed)?;
    if let Some(alternate) = alternate {
        let alternate: T = serde_json::from_value(alternate.clone())
            .map_err(|_| EvidenceStateDecodeError::Malformed)?;
        if parsed != alternate {
            return Err(EvidenceStateDecodeError::Malformed);
        }
    }
    Ok(parsed)
}

/// Drops only stale summaries whose typed non-satisfying proof contains a future enum value.
///
/// The original JSON remains the identity and retention source. The typed projection exists only
/// to validate all semantics this binary does know; omitting an opaque stale item cannot make it
/// proving because the enclosing Evidence is marked incomplete and retains all references.
fn project_forward_compatible_stale_receipts(
    raw: &Value,
) -> Result<Value, EvidenceStateDecodeError> {
    let mut projected = raw.clone();
    let data = projected
        .get_mut("data")
        .and_then(Value::as_object_mut)
        .ok_or(EvidenceStateDecodeError::Malformed)?;
    let stale_receipts = data
        .get_mut("stale_receipts")
        .and_then(Value::as_array_mut)
        .ok_or(EvidenceStateDecodeError::Malformed)?;
    let mut known = Vec::with_capacity(stale_receipts.len());
    for summary in std::mem::take(stale_receipts) {
        if serde_json::from_value::<StaleReceiptV2Data>(summary.clone()).is_ok() {
            known.push(summary);
        } else if !stale_receipt_has_forward_compatible_validity(&summary)? {
            return Err(EvidenceStateDecodeError::Malformed);
        }
    }
    *stale_receipts = known;
    Ok(projected)
}

fn validate_raw_evidence_receipt_ids_in_document(
    raw: &Value,
) -> Result<(), EvidenceStateDecodeError> {
    let data = raw
        .get("data")
        .and_then(Value::as_object)
        .ok_or(EvidenceStateDecodeError::Malformed)?;
    let valid_receipts = data
        .get("valid_receipts")
        .and_then(Value::as_array)
        .ok_or(EvidenceStateDecodeError::Malformed)?;
    let stale_receipts = data
        .get("stale_receipts")
        .and_then(Value::as_array)
        .ok_or(EvidenceStateDecodeError::Malformed)?;
    validate_raw_evidence_receipt_ids(valid_receipts, stale_receipts)
}

fn validate_raw_evidence_receipt_ids(
    valid_receipts: &[Value],
    stale_receipts: &[Value],
) -> Result<(), EvidenceStateDecodeError> {
    let mut ids = BTreeSet::new();
    for summary in valid_receipts.iter().chain(stale_receipts) {
        let object = summary
            .as_object()
            .ok_or(EvidenceStateDecodeError::Malformed)?;
        let schema = object
            .get("schema")
            .and_then(Value::as_str)
            .ok_or(EvidenceStateDecodeError::Malformed)?;
        let known_schema = matches!(schema, "forge.receipt/v1" | "forge.receipt/v2");
        let Some(id) = object.get("id") else {
            if known_schema {
                return Err(EvidenceStateDecodeError::Malformed);
            }
            continue;
        };
        let Some(id) = id.as_str() else {
            if known_schema {
                return Err(EvidenceStateDecodeError::Malformed);
            }
            continue;
        };
        if parse_public_id(id, RECEIPT_ID_PREFIX).is_err() {
            if known_schema {
                return Err(EvidenceStateDecodeError::InvalidReference);
            }
            continue;
        }
        if !ids.insert(id) {
            return Err(EvidenceStateDecodeError::InvalidReference);
        }
    }
    Ok(())
}

fn stale_receipt_has_forward_compatible_validity(
    summary: &Value,
) -> Result<bool, EvidenceStateDecodeError> {
    let object = summary
        .as_object()
        .ok_or(EvidenceStateDecodeError::Malformed)?;
    if object.get("schema").and_then(Value::as_str) != Some("forge.receipt/v2") {
        return Ok(false);
    }
    let id = object
        .get("id")
        .and_then(Value::as_str)
        .ok_or(EvidenceStateDecodeError::Malformed)?;
    receipt_reference(EvidenceStateVersion::V2, id)?;
    serde_json::from_value::<IntentData>(
        object
            .get("intent")
            .cloned()
            .ok_or(EvidenceStateDecodeError::Malformed)?,
    )
    .map_err(|_| EvidenceStateDecodeError::Malformed)?;
    let validity: ReceiptValidityV2Data = serde_json::from_value(
        object
            .get("validity")
            .cloned()
            .ok_or(EvidenceStateDecodeError::Malformed)?,
    )
    .map_err(|_| EvidenceStateDecodeError::Malformed)?;
    Ok(matches!(
        validity.dependency_validity,
        forge_schema::DependencyValidityV2Data::Unknown
    ) || matches!(
        validity.applicability,
        forge_schema::ReceiptApplicabilityV2Data::Unknown
    ) || matches!(validity.outcome, OutcomeData::Unknown)
        || validity
            .reasons
            .contains(&ReceiptValidityReasonV2Data::Unknown))
}

fn validate_schema(
    raw: &Value,
    domain: &str,
    version: EvidenceStateVersion,
) -> Result<(), EvidenceStateDecodeError> {
    let schema = raw
        .get("schema")
        .and_then(Value::as_str)
        .ok_or(EvidenceStateDecodeError::Malformed)?;
    let expected = format!("forge.{domain}/v{}", version.major());
    if schema == expected {
        return Ok(());
    }
    let prefix = format!("forge.{domain}/v");
    let is_future_schema = schema
        .strip_prefix(&prefix)
        .filter(|major| !major.is_empty())
        .filter(|major| major.bytes().all(|byte| byte.is_ascii_digit()))
        .filter(|major| !major.starts_with('0'))
        .and_then(|major| major.parse::<u16>().ok())
        .is_some_and(|major| major > version.major());
    if is_future_schema {
        return Err(EvidenceStateDecodeError::FutureSchema);
    }
    Err(EvidenceStateDecodeError::Malformed)
}

fn validate_identity(
    raw: &ParsedJson,
    declared: &str,
    kind: DocumentKind,
) -> Result<EvidenceStateObjectName, EvidenceStateDecodeError> {
    let (expected, object_name) = calculate_parsed_identity(raw, kind)?;
    let declared_name = parse_public_id(declared, kind.id_prefix())?;
    if declared != expected || declared_name != object_name {
        return Err(EvidenceStateDecodeError::InvalidReference);
    }
    Ok(object_name)
}

fn calculate_identity(
    raw: &Value,
    kind: DocumentKind,
) -> Result<(String, EvidenceStateObjectName), EvidenceStateDecodeError> {
    let bytes = serde_json::to_vec(raw).map_err(|_| EvidenceStateDecodeError::Malformed)?;
    let raw = parse_identity_json(&bytes, kind)?;
    calculate_parsed_identity(&raw, kind)
}

fn calculate_parsed_identity(
    raw: &ParsedJson,
    kind: DocumentKind,
) -> Result<(String, EvidenceStateObjectName), EvidenceStateDecodeError> {
    let canonical = raw
        .canonical_without_data_id()
        .map_err(|()| EvidenceStateDecodeError::Malformed)?;
    let digest = Blake3Hasher::digest_chunks(&[kind.identity_domain(), &canonical]);
    let payload = digest
        .as_str()
        .strip_prefix("blake3:")
        .ok_or(EvidenceStateDecodeError::Malformed)?;
    let object_name = EvidenceStateObjectName::new(payload.to_owned())
        .map_err(|_| EvidenceStateDecodeError::Malformed)?;
    Ok((format!("{}{}", kind.id_prefix(), payload), object_name))
}

fn parse_identity_json(
    bytes: &[u8],
    kind: DocumentKind,
) -> Result<ParsedJson, EvidenceStateDecodeError> {
    canonical_json::parse(bytes, kind.max_bytes()).map_err(|()| EvidenceStateDecodeError::Malformed)
}

fn parse_public_id(
    value: &str,
    prefix: &str,
) -> Result<EvidenceStateObjectName, EvidenceStateDecodeError> {
    let payload = value
        .strip_prefix(prefix)
        .ok_or(EvidenceStateDecodeError::InvalidReference)?;
    EvidenceStateObjectName::new(payload.to_owned())
        .map_err(|_| EvidenceStateDecodeError::InvalidReference)
}

fn receipt_v1_log_references(
    receipt: &ReceiptData,
) -> Result<DecodedLogReferences, EvidenceStateDecodeError> {
    let mut decoded = decode_log_references(&receipt.log_refs)?;
    for observation in &receipt.observations {
        let observation = decode_log_references(&observation.log_refs)?;
        decoded.complete &= observation.complete;
        decoded.references.extend(observation.references);
    }
    Ok(decoded)
}

struct ReceiptV2SemanticValidation {
    log_references: BTreeSet<EvidenceStateObjectName>,
    log_references_complete: bool,
    can_evaluate_current_validity: bool,
    can_support_current_evidence: bool,
    diagnostic_summaries_are_current: bool,
}

fn validate_receipt_v2_semantics(
    receipt: &ReceiptV2Data,
    has_unknown_contract_content: bool,
) -> Result<ReceiptV2SemanticValidation, EvidenceStateDecodeError> {
    let top_intent = intent_from_wire(receipt.intent);
    if receipt.observations.is_empty() {
        return Err(EvidenceStateDecodeError::Malformed);
    }
    let mut can_evaluate_current_validity = !has_unknown_contract_content
        && top_intent.is_some()
        && receipt_command_set_confidence_is_complete(receipt)
        && !matches!(receipt.outcome, OutcomeData::Unknown)
        && validate_comparison_basis(&receipt.comparison_basis)?;
    let mut can_support_current_evidence =
        can_evaluate_current_validity && receipt_dependencies_are_complete(&receipt.dependencies);

    let mut command_ids = BTreeSet::new();
    let mut aggregate_inputs = Vec::with_capacity(receipt.observations.len());
    let mut aggregate_is_complete = !matches!(receipt.outcome, OutcomeData::Unknown);
    let mut diagnostic_summaries_are_current = true;
    let mut observation_logs = BTreeSet::new();
    let mut observation_logs_are_complete = true;
    for observation in &receipt.observations {
        let command = &observation.command;
        let command_intent = intent_from_wire(command.command.intent);
        if top_intent.is_some() && command_intent.is_some() && command_intent != top_intent {
            return Err(EvidenceStateDecodeError::Malformed);
        }
        if !command_ids.insert(command.command.id.as_str()) {
            return Err(EvidenceStateDecodeError::Malformed);
        }
        let native_is_complete = validate_native_command_alignment(command)?;
        let enforcement = enforcement_from_wire(command.enforcement);
        let coverage = coverage_from_wire(&command.command.coverage)?;
        let observation_outcome = outcome_from_wire(observation.outcome);
        let observation_outcome_validation =
            validate_observation_outcome(observation, observation_outcome)?;
        diagnostic_summaries_are_current &=
            observation_outcome_validation.diagnostic_summary_is_current;
        let logs = decode_log_references(&observation.log_refs)?;
        observation_logs_are_complete &= logs.complete;
        observation_logs.extend(logs.references);
        let command_is_evaluable = command_intent.is_some()
            && native_is_complete
            && enforcement.is_some()
            && command_semantics_are_complete(command)
            && coverage.complete
            && !coverage.dimensions.is_empty()
            && logs.complete
            && observation_outcome_validation.can_evaluate_current_validity;
        can_evaluate_current_validity &= command_is_evaluable;
        can_support_current_evidence &=
            command_is_evaluable && observation_outcome_validation.can_support_current_evidence;
        match enforcement {
            Some(enforcement)
                if coverage.complete && observation_outcome_validation.aggregate_is_known =>
            {
                aggregate_inputs.push(CommandEvidenceObservation::new(
                    enforcement,
                    observation_outcome,
                    coverage.dimensions,
                ));
            }
            Some(_) | None => aggregate_is_complete = false,
        }
    }

    if aggregate_is_complete {
        let aggregate = aggregate_command_evidence(&aggregate_inputs);
        if receipt.outcome != evidence_outcome_to_wire(aggregate.outcome()) {
            return Err(EvidenceStateDecodeError::Malformed);
        }
        let expected_coverage = aggregate
            .verified()
            .iter()
            .map(coverage_dimension_name)
            .collect::<Vec<_>>();
        if receipt.coverage != expected_coverage {
            return Err(EvidenceStateDecodeError::Malformed);
        }
    } else {
        can_evaluate_current_validity = false;
        can_support_current_evidence = false;
    }

    let top_logs = decode_log_references(&receipt.log_refs)?;
    if top_logs.complete && observation_logs_are_complete && top_logs.references != observation_logs
    {
        return Err(EvidenceStateDecodeError::InvalidReference);
    }
    let log_references_are_complete = top_logs.complete && observation_logs_are_complete;
    can_evaluate_current_validity &= log_references_are_complete;
    can_support_current_evidence &= log_references_are_complete;
    Ok(ReceiptV2SemanticValidation {
        log_references: top_logs.references,
        log_references_complete: log_references_are_complete,
        can_evaluate_current_validity,
        can_support_current_evidence,
        diagnostic_summaries_are_current,
    })
}

fn receipt_dependencies_are_complete(
    dependencies: &forge_schema::ReceiptDependenciesV2Data,
) -> bool {
    use forge_schema::{
        BaseTaskDependencyV2Data, DigestDependencyV2Data, RepositoryDependencyV2Data,
    };

    matches!(
        &dependencies.repository,
        RepositoryDependencyV2Data::Known(_)
    ) && matches!(&dependencies.scope_before, DigestDependencyV2Data::Known(_))
        && matches!(&dependencies.scope_after, DigestDependencyV2Data::Known(_))
        && matches!(&dependencies.command, DigestDependencyV2Data::Known(_))
        && matches!(&dependencies.toolchain, DigestDependencyV2Data::Known(_))
        && matches!(&dependencies.environment, DigestDependencyV2Data::Known(_))
        && matches!(&dependencies.policy, DigestDependencyV2Data::Known(_))
        && matches!(
            &dependencies.base_task,
            BaseTaskDependencyV2Data::Known(_) | BaseTaskDependencyV2Data::NotApplicable
        )
        && matches!(
            &dependencies.forge_behavior,
            DigestDependencyV2Data::Known(_)
        )
}

fn receipt_command_set_confidence_is_complete(receipt: &ReceiptV2Data) -> bool {
    use forge_schema::ConfidenceData;

    matches!(
        receipt.resolution_confidence,
        Some(ConfidenceData::Medium | ConfidenceData::High)
    ) && matches!(
        receipt.coverage_confidence,
        Some(ConfidenceData::Medium | ConfidenceData::High)
    )
}

fn command_semantics_are_complete(detail: &forge_schema::CommandDetailV2Data) -> bool {
    use forge_schema::{CommandSourceData, ConfidenceData, MutabilityData, NetworkIntentData};

    !matches!(detail.command.mutability, MutabilityData::Unknown)
        && !matches!(detail.command.network, NetworkIntentData::Unknown)
        && !matches!(detail.command.confidence, ConfidenceData::Unknown)
        && !matches!(detail.source_detail, CommandSourceData::Unknown)
        && !success_predicate_contains_unknown(&detail.success)
        && !matches!(detail.command.cwd.encoding, PathEncoding::Unknown)
}

fn success_predicate_contains_unknown(predicate: &forge_schema::SuccessPredicateData) -> bool {
    match predicate {
        forge_schema::SuccessPredicateData::All { predicates } => {
            predicates.iter().any(success_predicate_contains_unknown)
        }
        forge_schema::SuccessPredicateData::Unknown => true,
        _ => false,
    }
}

struct ObservationOutcomeValidation {
    aggregate_is_known: bool,
    can_evaluate_current_validity: bool,
    can_support_current_evidence: bool,
    diagnostic_summary_is_current: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiagnosticSummaryValidation {
    LegacyOrUnknown,
    Observed,
    Unavailable,
}

fn validate_diagnostic_summary(
    observation: &forge_schema::CommandObservationV2Data,
    has_unavailable_marker: bool,
) -> Result<DiagnosticSummaryValidation, EvidenceStateDecodeError> {
    use forge_schema::CommandDiagnosticSummaryStateV2Data;

    let Some(summary) = &observation.diagnostic_summary else {
        return Ok(DiagnosticSummaryValidation::LegacyOrUnknown);
    };
    match summary.state {
        CommandDiagnosticSummaryStateV2Data::Observed => {
            if summary.stdout_total_bytes.is_none()
                || summary.stderr_total_bytes.is_none()
                || summary.stdout_total_bytes != observation.stdout_total_bytes
                || observation.process_error_kind.is_some()
                || has_unavailable_marker
            {
                return Err(EvidenceStateDecodeError::Malformed);
            }
            Ok(DiagnosticSummaryValidation::Observed)
        }
        CommandDiagnosticSummaryStateV2Data::Unavailable => {
            if summary.stdout_total_bytes.is_some()
                || summary.stderr_total_bytes.is_some()
                || observation.process_error_kind.is_none()
                || !has_unavailable_marker
            {
                return Err(EvidenceStateDecodeError::Malformed);
            }
            Ok(DiagnosticSummaryValidation::Unavailable)
        }
        CommandDiagnosticSummaryStateV2Data::Unknown => {
            Ok(DiagnosticSummaryValidation::LegacyOrUnknown)
        }
        _ => Ok(DiagnosticSummaryValidation::LegacyOrUnknown),
    }
}

fn validate_observation_outcome(
    observation: &forge_schema::CommandObservationV2Data,
    recorded: EvidenceOutcome,
) -> Result<ObservationOutcomeValidation, EvidenceStateDecodeError> {
    let (unavailable_stdout, unavailable_stderr) =
        process_output_unavailable_digests(&Blake3Hasher);
    let has_unavailable_marker = observation.stdout_digest == unavailable_stdout
        || observation.stderr_digest == unavailable_stderr;
    let diagnostic_summary = validate_diagnostic_summary(observation, has_unavailable_marker)?;
    if observation.process_error_kind.is_some() {
        if !matches!(recorded, EvidenceOutcome::InfrastructureFailure)
            || observation.raw_exit_code.is_some()
            || observation.signal.is_some()
            || observation.timed_out
            || observation.interrupted
            || observation.stdout_digest != unavailable_stdout
            || observation.stderr_digest != unavailable_stderr
            || observation.stdout_total_bytes.is_some()
            || observation.json_error_status.is_some()
            || observation.stdout_truncated.is_some()
            || observation.stderr_truncated.is_some()
            || !observation.output_truncated
            || !observation.log_refs.is_empty()
        {
            return Err(EvidenceStateDecodeError::Malformed);
        }
        let diagnostic_summary_is_current =
            diagnostic_summary == DiagnosticSummaryValidation::Unavailable;
        return Ok(ObservationOutcomeValidation {
            aggregate_is_known: true,
            can_evaluate_current_validity: diagnostic_summary_is_current,
            // An infrastructure observation is explicit and aggregatable, but it can never prove
            // that the selected command satisfied its declared success predicate.
            can_support_current_evidence: false,
            diagnostic_summary_is_current,
        });
    }
    // Current unavailable markers are sentinels, not output digests. Removing the typed kind must
    // not make a current observation silently look like an early-v2 legacy observation.
    if has_unavailable_marker {
        return Err(EvidenceStateDecodeError::Malformed);
    }
    let stream_truncation_is_complete =
        match (observation.stdout_truncated, observation.stderr_truncated) {
            (Some(stdout), Some(stderr)) => {
                if observation.output_truncated != (stdout || stderr) {
                    return Err(EvidenceStateDecodeError::Malformed);
                }
                true
            }
            (Some(true), None) | (None, Some(true)) if !observation.output_truncated => {
                return Err(EvidenceStateDecodeError::Malformed);
            }
            _ => false,
        };
    if matches!(recorded, EvidenceOutcome::Unknown) {
        return Ok(ObservationOutcomeValidation {
            aggregate_is_known: false,
            can_evaluate_current_validity: false,
            can_support_current_evidence: false,
            diagnostic_summary_is_current: diagnostic_summary
                == DiagnosticSummaryValidation::Observed,
        });
    }
    if observation.raw_exit_code.is_none()
        && observation.signal.is_none()
        && !observation.timed_out
        && !observation.interrupted
        && matches!(recorded, EvidenceOutcome::InfrastructureFailure)
    {
        // Process-boundary failures have no termination status in v2. Without a typed error kind
        // they remain useful historical facts but cannot support current Evidence.
        return Ok(ObservationOutcomeValidation {
            aggregate_is_known: true,
            can_evaluate_current_validity: false,
            can_support_current_evidence: false,
            diagnostic_summary_is_current: false,
        });
    }
    let legacy_truncation_is_ambiguous = !stream_truncation_is_complete
        && observation.stdout_total_bytes == Some(0)
        && observation.output_truncated;
    let expected = if legacy_truncation_is_ambiguous {
        None
    } else if observation.timed_out && observation.interrupted {
        Some(EvidenceOutcome::Unknown)
    } else if observation.timed_out {
        Some(EvidenceOutcome::TimedOut)
    } else if observation.interrupted {
        Some(EvidenceOutcome::Interrupted)
    } else if (observation.raw_exit_code.is_some() && observation.signal.is_some())
        || (observation.stdout_total_bytes == Some(0) && observation.stdout_truncated == Some(true))
    {
        Some(EvidenceOutcome::Unknown)
    } else if observation.raw_exit_code.is_none() {
        Some(if observation.signal.is_some() {
            EvidenceOutcome::ProductFailure
        } else {
            EvidenceOutcome::Inconclusive
        })
    } else {
        outcome_from_success_predicate(&observation.command.success, observation)
    };

    let Some(expected) = expected else {
        return Ok(ObservationOutcomeValidation {
            aggregate_is_known: false,
            can_evaluate_current_validity: false,
            can_support_current_evidence: false,
            diagnostic_summary_is_current: diagnostic_summary
                == DiagnosticSummaryValidation::Observed,
        });
    };
    if expected != recorded {
        return Err(EvidenceStateDecodeError::Malformed);
    }
    // Early v2 writers did not record complete stdout length. Keep those receipts readable, but
    // do not let an unreplayable output/truncation boundary satisfy current Evidence.
    let complete_current_observation = observation.stdout_total_bytes.is_some()
        && stream_truncation_is_complete
        && diagnostic_summary == DiagnosticSummaryValidation::Observed;
    Ok(ObservationOutcomeValidation {
        aggregate_is_known: true,
        can_evaluate_current_validity: complete_current_observation,
        can_support_current_evidence: complete_current_observation,
        diagnostic_summary_is_current: diagnostic_summary == DiagnosticSummaryValidation::Observed,
    })
}

fn outcome_from_success_predicate(
    predicate: &forge_schema::SuccessPredicateData,
    observation: &forge_schema::CommandObservationV2Data,
) -> Option<EvidenceOutcome> {
    use forge_schema::SuccessPredicateData;

    match predicate {
        SuccessPredicateData::ExitZero => Some(if observation.raw_exit_code == Some(0) {
            EvidenceOutcome::Pass
        } else {
            EvidenceOutcome::ProductFailure
        }),
        SuccessPredicateData::ExitZeroAndStdoutEmpty if observation.raw_exit_code != Some(0) => {
            Some(EvidenceOutcome::ProductFailure)
        }
        SuccessPredicateData::ExitZeroAndStdoutEmpty => {
            observation.stdout_total_bytes.map(|stdout_total_bytes| {
                if stdout_total_bytes == 0 {
                    EvidenceOutcome::Pass
                } else {
                    EvidenceOutcome::ProductFailure
                }
            })
        }
        SuccessPredicateData::JsonHasNoErrors => match observation.json_error_status {
            Some(JsonErrorStatusV2Data::NoErrors) => Some(EvidenceOutcome::Pass),
            Some(JsonErrorStatusV2Data::HasErrors | JsonErrorStatusV2Data::Invalid) => {
                Some(EvidenceOutcome::ProductFailure)
            }
            Some(_) | None => None,
        },
        SuccessPredicateData::All { predicates } if predicates.is_empty() => {
            Some(EvidenceOutcome::ProductFailure)
        }
        SuccessPredicateData::All { predicates } => {
            let mut all_pass = true;
            for predicate in predicates {
                match outcome_from_success_predicate(predicate, observation) {
                    Some(EvidenceOutcome::ProductFailure) => {
                        return Some(EvidenceOutcome::ProductFailure);
                    }
                    Some(EvidenceOutcome::Pass) => {}
                    _ => all_pass = false,
                }
            }
            all_pass.then_some(EvidenceOutcome::Pass)
        }
        _ => None,
    }
}

fn validate_evidence_v2_semantics(
    evidence: &EvidenceV2Data,
) -> Result<
    (
        BTreeSet<ReceiptStateReference>,
        BTreeSet<EvidenceStateObjectName>,
        bool,
    ),
    EvidenceStateDecodeError,
> {
    let _comparison_is_complete = validate_comparison_basis(&evidence.comparison.basis)?;
    if !evidence.external_attestations.is_empty() {
        return Err(EvidenceStateDecodeError::Malformed);
    }

    let mut receipt_ids = BTreeSet::new();
    for receipt in &evidence.valid_receipts {
        if !receipt_ids.insert(receipt.id.as_str()) {
            return Err(EvidenceStateDecodeError::InvalidReference);
        }
    }
    for receipt in &evidence.stale_receipts {
        let id = match receipt {
            StaleReceiptV2Data::ReceiptV1 { id, .. } | StaleReceiptV2Data::ReceiptV2 { id, .. } => {
                id.as_str()
            }
            _ => continue,
        };
        if !receipt_ids.insert(id) {
            return Err(EvidenceStateDecodeError::InvalidReference);
        }
    }
    let receipt_references = evidence_v2_receipt_references(evidence)?;
    let expected_reference_count = evidence.valid_receipts.len()
        + evidence
            .stale_receipts
            .iter()
            .filter(|receipt| {
                matches!(
                    receipt,
                    StaleReceiptV2Data::ReceiptV1 { .. } | StaleReceiptV2Data::ReceiptV2 { .. }
                )
            })
            .count();
    if receipt_references.len() != expected_reference_count {
        return Err(EvidenceStateDecodeError::InvalidReference);
    }
    for receipt in &evidence.valid_receipts {
        let coverage = coverage_from_wire(&receipt.coverage)?;
        if !coverage.complete {
            continue;
        }
        let canonical = coverage
            .dimensions
            .iter()
            .map(coverage_dimension_name)
            .collect::<Vec<_>>();
        if receipt.coverage != canonical {
            return Err(EvidenceStateDecodeError::Malformed);
        }
    }
    let log_references = decode_log_references(&evidence.log_refs)?;
    Ok((
        receipt_references,
        log_references.references,
        log_references.complete,
    ))
}

fn validate_comparison_basis(
    basis: &ComparisonBasisV2Data,
) -> Result<bool, EvidenceStateDecodeError> {
    let protocol_known = matches!(basis.protocol, ComparisonProtocolV2Data::WorktreeV1);
    let task_known = matches!(basis.task_acceptance, TaskAcceptanceV2Data::NotApplicable);
    let baseline_known = matches!(
        &basis.baseline,
        ComparisonBaselineV2Data::Head {
            commit: GitObjectIdV2Data::Sha1 { .. } | GitObjectIdV2Data::Sha256 { .. },
        } | ComparisonBaselineV2Data::Unborn {
            object_format: GitObjectFormatV2Data::Sha1 | GitObjectFormatV2Data::Sha256,
        }
    );
    let policy_base_known = matches!(
        &basis.policy_base_digest,
        forge_schema::DigestDependencyV2Data::Known(_)
    );
    Ok(protocol_known && task_known && baseline_known && policy_base_known)
}

fn validate_native_command_alignment(
    detail: &forge_schema::CommandDetailV2Data,
) -> Result<bool, EvidenceStateDecodeError> {
    let mut complete = validate_native_string(&detail.native_program, &detail.command.program)?;
    if detail.native_args.len() != detail.command.args.len()
        || detail.native_environment_names.len() != detail.command.environment_names.len()
    {
        return Err(EvidenceStateDecodeError::Malformed);
    }
    for (native, legacy) in detail.native_args.iter().zip(&detail.command.args) {
        complete &= validate_native_string(native, legacy)?;
    }
    for (native, legacy) in detail
        .native_environment_names
        .iter()
        .zip(&detail.command.environment_names)
    {
        complete &= validate_native_string(native, legacy)?;
    }
    Ok(complete)
}

fn validate_native_string(
    native: &NativeStringData,
    legacy: &str,
) -> Result<bool, EvidenceStateDecodeError> {
    match native.encoding {
        NativeStringEncodingData::Utf8
            if native.raw_base64.is_none() && native.display == legacy =>
        {
            Ok(true)
        }
        NativeStringEncodingData::Utf8 => Err(EvidenceStateDecodeError::Malformed),
        NativeStringEncodingData::Unknown => Ok(false),
        NativeStringEncodingData::UnixBytes | NativeStringEncodingData::WindowsWide
            if native.raw_base64.is_some() =>
        {
            Ok(true)
        }
        _ => Err(EvidenceStateDecodeError::Malformed),
    }
}

fn intent_from_wire(value: IntentData) -> Option<Intent> {
    match value {
        IntentData::Setup => Some(Intent::Setup),
        IntentData::FormatCheck => Some(Intent::FormatCheck),
        IntentData::Format => Some(Intent::Format),
        IntentData::Check => Some(Intent::Check),
        IntentData::Fix => Some(Intent::Fix),
        IntentData::Test => Some(Intent::Test),
        IntentData::Verify => Some(Intent::Verify),
        IntentData::Build => Some(Intent::Build),
        _ => None,
    }
}

fn enforcement_from_wire(value: CommandEnforcementData) -> Option<CommandEnforcement> {
    match value {
        CommandEnforcementData::Required => Some(CommandEnforcement::Required),
        CommandEnforcementData::Advisory => Some(CommandEnforcement::Advisory),
        _ => None,
    }
}

const fn outcome_from_wire(value: OutcomeData) -> EvidenceOutcome {
    match value {
        OutcomeData::Pass => EvidenceOutcome::Pass,
        OutcomeData::ProductFailure => EvidenceOutcome::ProductFailure,
        OutcomeData::InfrastructureFailure => EvidenceOutcome::InfrastructureFailure,
        OutcomeData::Inconclusive => EvidenceOutcome::Inconclusive,
        OutcomeData::TimedOut => EvidenceOutcome::TimedOut,
        OutcomeData::Interrupted => EvidenceOutcome::Interrupted,
        _ => EvidenceOutcome::Unknown,
    }
}

struct DecodedCoverage {
    dimensions: BTreeSet<CoverageDimension>,
    complete: bool,
}

fn coverage_from_wire(values: &[String]) -> Result<DecodedCoverage, EvidenceStateDecodeError> {
    let mut seen = BTreeSet::new();
    let mut dimensions = BTreeSet::new();
    let mut complete = true;
    for value in values {
        if !seen.insert(value.as_str()) {
            return Err(EvidenceStateDecodeError::Malformed);
        }
        let dimension = match value.as_str() {
            "format" => CoverageDimension::Format,
            "compile" => CoverageDimension::Compile,
            "lint" => CoverageDimension::Lint,
            "unit-test" => CoverageDimension::UnitTest,
            "integration-test" => CoverageDimension::IntegrationTest,
            "build" => CoverageDimension::Build,
            "security" => CoverageDimension::Security,
            value if value.starts_with("custom:") => {
                CoverageDimension::Custom(value["custom:".len()..].to_owned())
            }
            _ => {
                complete = false;
                continue;
            }
        };
        if !dimensions.insert(dimension) {
            return Err(EvidenceStateDecodeError::Malformed);
        }
    }
    Ok(DecodedCoverage {
        dimensions,
        complete,
    })
}

fn receipt_binding_coverage_digest(values: &[String]) -> Digest {
    let mut chunks = Vec::with_capacity(values.len() + 1);
    chunks.push(RECEIPT_BINDING_COVERAGE_DOMAIN);
    chunks.extend(values.iter().map(|value| value.as_bytes()));
    // `digest_chunks` length-prefixes every member, so both item boundaries and ordering are part
    // of this fixed-size projection. The Evidence-side coverage is canonicalized independently.
    Blake3Hasher::digest_chunks(&chunks)
}

struct DecodedLogReferences {
    references: BTreeSet<EvidenceStateObjectName>,
    complete: bool,
}

fn decode_log_references(
    references: &[WirePath],
) -> Result<DecodedLogReferences, EvidenceStateDecodeError> {
    let mut parsed = BTreeSet::new();
    let mut complete = true;
    for path in references {
        if matches!(path.encoding, PathEncoding::Unknown) {
            complete = false;
            continue;
        }
        if !parsed.insert(log_reference(path)?) {
            return Err(EvidenceStateDecodeError::InvalidReference);
        }
    }
    Ok(DecodedLogReferences {
        references: parsed,
        complete,
    })
}

fn log_reference(path: &WirePath) -> Result<EvidenceStateObjectName, EvidenceStateDecodeError> {
    if path.encoding != PathEncoding::Utf8 || path.raw_base64.is_some() {
        return Err(EvidenceStateDecodeError::InvalidReference);
    }
    let payload = path
        .display
        .strip_prefix(LOG_PATH_PREFIX)
        .and_then(|value| value.strip_suffix(".log"))
        .ok_or(EvidenceStateDecodeError::InvalidReference)?;
    EvidenceStateObjectName::new(payload.to_owned())
        .map_err(|_| EvidenceStateDecodeError::InvalidReference)
}

fn evidence_v1_receipt_references(
    evidence: &EvidenceData,
) -> Result<BTreeSet<ReceiptStateReference>, EvidenceStateDecodeError> {
    evidence
        .valid_receipts
        .iter()
        .map(|receipt| receipt.id.as_str())
        .chain(
            evidence
                .stale_receipts
                .iter()
                .map(|receipt| receipt.id.as_str()),
        )
        .map(|id| receipt_reference(EvidenceStateVersion::V1, id))
        .collect()
}

fn evidence_v2_receipt_references(
    evidence: &EvidenceV2Data,
) -> Result<BTreeSet<ReceiptStateReference>, EvidenceStateDecodeError> {
    let mut references = BTreeSet::new();
    for receipt in &evidence.valid_receipts {
        references.insert(receipt_reference(
            EvidenceStateVersion::V2,
            receipt.id.as_str(),
        )?);
    }
    for receipt in &evidence.stale_receipts {
        let (version, id) = match receipt {
            StaleReceiptV2Data::ReceiptV1 { id, .. } => (EvidenceStateVersion::V1, id.as_str()),
            StaleReceiptV2Data::ReceiptV2 { id, .. } => (EvidenceStateVersion::V2, id.as_str()),
            _ => continue,
        };
        references.insert(receipt_reference(version, id)?);
    }
    Ok(references)
}

fn receipt_reference(
    version: EvidenceStateVersion,
    id: &str,
) -> Result<ReceiptStateReference, EvidenceStateDecodeError> {
    Ok(ReceiptStateReference::new(
        version,
        parse_public_id(id, RECEIPT_ID_PREFIX)?,
    ))
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::path::Path;

    use forge_runtime::state::{
        EvidenceRetentionMetadata, EvidenceRetentionTime, EvidenceStateMetadataDecoder as _,
        EvidenceStateVersion, ReceiptRetentionMetadata, ReceiptStateReference, ReferenceClosure,
        parse_utc_rfc3339,
    };
    use forge_schema::{
        Envelope, EvidenceV2Data, IntentData, OutcomeData, ReceiptV2Data, SuccessPredicateData,
    };
    use serde_json::{Value, json};

    use super::{
        DocumentKind, JsonEvidenceStateCodec, ParsedEvidence, ParsedReceipt, calculate_identity,
        load_evidence, load_receipt, prepare_evidence, prepare_receipt,
        validate_evidence_receipt_bindings,
    };

    type TestResult = Result<(), Box<dyn Error>>;

    fn envelope(schema: &str, data: Value) -> Value {
        json!({
            "schema": schema,
            "tool_version": "0.0.0",
            "ok": true,
            "data": data,
            "diagnostics": [],
            "truncated": false,
            "artifacts": []
        })
    }

    fn receipt_value(log_refs: Value) -> Result<Value, Box<dyn Error>> {
        sign(
            envelope(
                "forge.receipt/v2",
                json!({
                    "id": "receipt:blake3:placeholder",
                    "intent": "test",
                    "resolution_confidence": "high",
                    "coverage_confidence": "high",
                    "observations": [{
                        "command": {
                            "command": {
                                "id": "rust.test",
                                "intent": "test",
                                "program": "cargo",
                                "args": ["test"],
                                "cwd": {"display": "", "encoding": "utf8"},
                                "environment_names": ["RUSTUP_AUTO_INSTALL"],
                                "timeout_seconds": 300,
                                "mutability": "read-only",
                                "network": "inherit",
                                "source": "language-default",
                                "confidence": "high",
                                "coverage": ["unit-test"]
                            },
                            "native_program": {"display": "cargo", "encoding": "utf8"},
                            "native_args": [{"display": "test", "encoding": "utf8"}],
                            "native_environment_names": [{
                                "display": "RUSTUP_AUTO_INSTALL",
                                "encoding": "utf8"
                            }],
                            "source_detail": {
                                "kind": "language-default",
                                "provider": "rust",
                                "rule": "cargo-test"
                            },
                            "enforcement": "required",
                            "success": {"kind": "exit-zero"}
                        },
                        "raw_exit_code": 0,
                        "signal": null,
                        "outcome": "pass",
                        "duration_ms": 10,
                        "timed_out": false,
                        "interrupted": false,
                        "diagnostic_summary": {
                            "state": "observed",
                            "stdout_total_bytes": 0,
                            "stderr_total_bytes": 0
                        },
                        "stdout_digest": "blake3:stdout",
                        "stdout_total_bytes": 0,
                        "stderr_digest": "blake3:stderr",
                        "stdout_truncated": false,
                        "stderr_truncated": false,
                        "output_truncated": false,
                        "log_refs": log_refs.clone()
                    }],
                    "comparison_basis": {
                        "protocol": "forge.worktree-comparison/v1",
                        "baseline": {"state": "unborn", "object_format": "sha1"},
                        "task_acceptance": {"state": "not-applicable"},
                        "policy_base_digest": {"state": "known", "value": "blake3:policy"}
                    },
                    "dependencies": {
                        "repository": {"state": "known", "value": "local:blake3:repo"},
                        "scope_before": {"state": "known", "value": "blake3:scope"},
                        "scope_after": {"state": "known", "value": "blake3:scope"},
                        "command": {"state": "known", "value": "blake3:command"},
                        "toolchain": {"state": "known", "value": "blake3:toolchain"},
                        "environment": {"state": "known", "value": "blake3:environment"},
                        "policy": {"state": "known", "value": "blake3:policy"},
                        "base_task": {"state": "not-applicable"},
                        "forge_behavior": {"state": "known", "value": "blake3:forge"}
                    },
                    "started_at": "2026-07-27T00:00:00Z",
                    "duration_ms": 12,
                    "outcome": "pass",
                    "coverage": ["unit-test"],
                    "log_refs": log_refs
                }),
            ),
            DocumentKind::Receipt,
        )
    }

    fn typed_infrastructure_receipt(process_error_kind: &str) -> Result<Value, Box<dyn Error>> {
        let mut receipt = receipt_value(json!([]))?;
        let (stdout_digest, stderr_digest) =
            forge_core::fingerprint::process_output_unavailable_digests(
                &forge_runtime::hash::Blake3Hasher,
            );
        let observation = receipt["data"]["observations"][0]
            .as_object_mut()
            .ok_or_else(|| std::io::Error::other("observation is not an object"))?;
        observation.insert(String::from("raw_exit_code"), Value::Null);
        observation.insert(String::from("signal"), Value::Null);
        observation.insert(String::from("outcome"), json!("infrastructure-failure"));
        observation.insert(
            String::from("process_error_kind"),
            json!(process_error_kind),
        );
        observation.insert(
            String::from("diagnostic_summary"),
            json!({"state": "unavailable"}),
        );
        observation.insert(String::from("stdout_digest"), json!(stdout_digest.as_str()));
        observation.insert(String::from("stderr_digest"), json!(stderr_digest.as_str()));
        observation.remove("stdout_total_bytes");
        observation.remove("json_error_status");
        observation.remove("stdout_truncated");
        observation.remove("stderr_truncated");
        observation.insert(String::from("output_truncated"), json!(true));
        observation.insert(String::from("log_refs"), json!([]));
        receipt["data"]["outcome"] = json!("infrastructure-failure");
        receipt["data"]["coverage"] = json!([]);
        sign(receipt, DocumentKind::Receipt)
    }

    fn receipt_v1_value() -> Result<Value, Box<dyn Error>> {
        sign(
            envelope(
                "forge.receipt/v1",
                json!({
                    "id": "receipt:blake3:placeholder",
                    "intent": "test",
                    "observations": [],
                    "head": null,
                    "scope_digest_before": "blake3:before",
                    "scope_digest_after": "blake3:after",
                    "command_digest": "blake3:command",
                    "toolchain_digest": "blake3:toolchain",
                    "environment_digest": "blake3:environment",
                    "policy_digest": "blake3:policy",
                    "started_at": "2026-07-27T00:00:00Z",
                    "duration_ms": 12,
                    "outcome": "pass",
                    "coverage": ["unit-test"],
                    "log_refs": []
                }),
            ),
            DocumentKind::Receipt,
        )
    }

    fn evidence_value(receipt_id: &str, log_refs: Value) -> Result<Value, Box<dyn Error>> {
        sign(
            envelope(
                "forge.evidence/v2",
                json!({
                    "id": "evidence:blake3:placeholder",
                    "created_at": "2026-07-27T00:01:00Z",
                    "repository": "local:blake3:repo",
                    "comparison": {
                        "basis": {
                            "protocol": "forge.worktree-comparison/v1",
                            "baseline": {"state": "unborn", "object_format": "sha1"},
                            "task_acceptance": {"state": "not-applicable"},
                            "policy_base_digest": {"state": "known", "value": "blake3:policy"}
                        },
                        "candidate_scope_digest": {"state": "known", "value": "blake3:scope"}
                    },
                    "risk": {"level": "low", "matched": [], "provenance": []},
                    "valid_receipts": [{
                        "schema": "forge.receipt/v2",
                        "id": receipt_id,
                        "intent": "test",
                        "outcome": "pass",
                        "coverage": ["unit-test"]
                    }],
                    "stale_receipts": [{
                        "schema": "forge.receipt/v1",
                        "id": format!("receipt:blake3:{}", "b".repeat(64)),
                        "intent": "test",
                        "outcome": "pass",
                        "dependency_validity": "unknown",
                        "applicability": "unknown",
                        "reason": "historical-incompatible"
                    }],
                    "coverage_and_gaps": {
                        "verified": ["unit-test"],
                        "advisory": [],
                        "not_verified": [],
                        "external_required": []
                    },
                    "local_state": "sufficient",
                    "external_requirements": [],
                    "external_attestations": [],
                    "log_refs": log_refs
                }),
            ),
            DocumentKind::Evidence,
        )
    }

    fn evidence_v1_value(valid_id: &str, stale_id: &str) -> Result<Value, Box<dyn Error>> {
        sign(
            envelope(
                "forge.evidence/v1",
                json!({
                    "id": "evidence:blake3:placeholder",
                    "repository": "local:blake3:repo",
                    "task_reference": null,
                    "base_commit": null,
                    "head_commit": null,
                    "diff_digest": "blake3:diff",
                    "risk": {"level": "low", "matched": [], "provenance": []},
                    "valid_receipts": [{
                        "id": valid_id,
                        "intent": "test",
                        "outcome": "pass"
                    }],
                    "stale_receipts": [{"id": stale_id, "reasons": ["historical"]}],
                    "coverage_and_gaps": {
                        "verified": [],
                        "advisory": [],
                        "not_verified": ["unit-test"],
                        "external_required": []
                    },
                    "local_state": "insufficient",
                    "external_requirements": [],
                    "external_attestations": []
                }),
            ),
            DocumentKind::Evidence,
        )
    }

    fn sign(mut value: Value, kind: DocumentKind) -> Result<Value, Box<dyn Error>> {
        let (identity, _) = calculate_identity(&value, kind)?;
        let id = value
            .pointer_mut("/data/id")
            .ok_or_else(|| std::io::Error::other("fixture has no data.id"))?;
        *id = Value::String(identity);
        Ok(value)
    }

    fn bytes(value: &Value) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(serde_json::to_vec_pretty(value)?)
    }

    fn validate_fixture_against_checked_in_schema(
        fixture: &Value,
        schema_file: &str,
    ) -> TestResult {
        let schema_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/schemas")
            .join(schema_file);
        let schema: Value = serde_json::from_slice(&fs::read(&schema_path)?)?;
        assert_eq!(
            fixture.get("schema"),
            schema.get("$id"),
            "fixture and checked-in schema disagree: {}",
            schema_path.display()
        );
        let validator = jsonschema::validator_for(&schema)?;
        let failures = validator
            .iter_errors(fixture)
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        assert!(
            failures.is_empty(),
            "fixture did not satisfy {}: {failures:#?}\n{}",
            schema_path.display(),
            serde_json::to_string_pretty(fixture)?
        );
        Ok(())
    }

    fn load_v2_receipt_fixture(receipt: &Value) -> Result<super::ValidatedReceipt, Box<dyn Error>> {
        let object_name = super::parse_public_id(
            receipt["data"]["id"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("receipt id is not a string"))?,
            super::RECEIPT_ID_PREFIX,
        )?;
        Ok(load_receipt(
            EvidenceStateVersion::V2,
            &object_name,
            &bytes(receipt)?,
        )?)
    }

    fn load_v1_receipt_fixture(receipt: &Value) -> Result<super::ValidatedReceipt, Box<dyn Error>> {
        let object_name = super::parse_public_id(
            receipt["data"]["id"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("receipt id is not a string"))?,
            super::RECEIPT_ID_PREFIX,
        )?;
        Ok(load_receipt(
            EvidenceStateVersion::V1,
            &object_name,
            &bytes(receipt)?,
        )?)
    }

    fn log_path(name: &str) -> Value {
        json!({
            "display": format!("logs/v1/{name}.log"),
            "encoding": "utf8"
        })
    }

    fn log_object_name_fixture()
    -> Result<forge_runtime::state::EvidenceStateObjectName, Box<dyn Error>> {
        Ok(forge_runtime::state::EvidenceStateObjectName::new(
            "a".repeat(64),
        )?)
    }

    #[test]
    fn canonical_identity_ignores_object_order_and_input_whitespace() -> TestResult {
        let left = super::parse_identity_json(
            br#"{"schema":"forge.receipt/v2","data":{"id":"ignored","body":{"z":1,"a":2}},"extra":true}"#,
            DocumentKind::Receipt,
        )?;
        let right = super::parse_identity_json(
            br#"{
                "extra": true,
                "data": {"body": {"a": 2, "z": 1}, "id": "different"},
                "schema": "forge.receipt/v2"
            }"#,
            DocumentKind::Receipt,
        )?;

        assert_eq!(
            super::calculate_parsed_identity(&left, DocumentKind::Receipt)?,
            super::calculate_parsed_identity(&right, DocumentKind::Receipt)?
        );
        Ok(())
    }

    #[test]
    fn same_major_unknown_fields_are_identity_inputs() -> TestResult {
        let mut first = receipt_value(json!([]))?;
        first["future_same_major"] = json!({"enabled": true});
        let mut second = first.clone();
        second["future_same_major"]["enabled"] = json!(false);

        assert_ne!(
            calculate_identity(&first, DocumentKind::Receipt)?,
            calculate_identity(&second, DocumentKind::Receipt)?
        );
        Ok(())
    }

    #[test]
    fn changed_body_with_old_public_id_is_rejected() -> TestResult {
        let mut receipt = receipt_value(json!([]))?;
        receipt["data"]["duration_ms"] = json!(13);

        assert_eq!(
            JsonEvidenceStateCodec.decode_receipt(EvidenceStateVersion::V2, &bytes(&receipt)?),
            Err(forge_runtime::state::EvidenceStateDecodeError::InvalidReference)
        );
        Ok(())
    }

    #[test]
    fn filename_must_match_recomputed_public_identity() -> TestResult {
        let receipt = receipt_value(json!([]))?;
        let wrong = forge_runtime::state::EvidenceStateObjectName::new("f".repeat(64))?;

        assert_eq!(
            load_receipt(EvidenceStateVersion::V2, &wrong, &bytes(&receipt)?),
            Err(forge_runtime::state::EvidenceStateDecodeError::InvalidReference)
        );
        let evidence = evidence_value(&format!("receipt:blake3:{}", "a".repeat(64)), json!([]))?;
        assert_eq!(
            load_evidence(EvidenceStateVersion::V2, &wrong, &bytes(&evidence)?),
            Err(forge_runtime::state::EvidenceStateDecodeError::InvalidReference)
        );
        Ok(())
    }

    #[test]
    fn future_schema_and_duplicate_keys_fail_closed() -> TestResult {
        let mut future = receipt_value(json!([]))?;
        future["schema"] = json!("forge.receipt/v3");
        assert_eq!(
            JsonEvidenceStateCodec.decode_receipt(EvidenceStateVersion::V2, &bytes(&future)?),
            Err(forge_runtime::state::EvidenceStateDecodeError::FutureSchema)
        );
        assert_eq!(
            JsonEvidenceStateCodec.decode_receipt(
                EvidenceStateVersion::V2,
                br#"{"schema":"forge.receipt/v2","schema":"forge.receipt/v2"}"#,
            ),
            Err(forge_runtime::state::EvidenceStateDecodeError::Malformed)
        );
        Ok(())
    }

    #[test]
    fn future_receipt_reference_schema_is_retained_without_trusting_its_references() -> TestResult {
        let receipt_id = format!("receipt:blake3:{}", "a".repeat(64));
        let mut evidence = evidence_value(&receipt_id, json!([]))?;
        evidence["data"]["stale_receipts"][0]["schema"] = json!("forge.receipt/v3");
        evidence = sign(evidence, DocumentKind::Evidence)?;
        let evidence_name = super::parse_public_id(
            evidence["data"]["id"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("evidence id is not a string"))?,
            super::EVIDENCE_ID_PREFIX,
        )?;

        assert_eq!(
            JsonEvidenceStateCodec.decode_evidence(EvidenceStateVersion::V2, &bytes(&evidence)?,)?,
            EvidenceRetentionMetadata::with_reference_closures(
                evidence_name,
                EvidenceRetentionTime::Current(parse_utc_rfc3339("2026-07-27T00:01:00Z")?),
                ReferenceClosure::RetainAll,
                ReferenceClosure::RetainAll,
            )
        );
        Ok(())
    }

    #[test]
    fn malformed_and_out_of_state_references_are_rejected() -> TestResult {
        let invalid_log = receipt_value(json!([{
            "display": "logs/v1/../secret.log",
            "encoding": "utf8"
        }]))?;
        assert_eq!(
            JsonEvidenceStateCodec.decode_receipt(EvidenceStateVersion::V2, &bytes(&invalid_log)?,),
            Err(forge_runtime::state::EvidenceStateDecodeError::InvalidReference)
        );

        let mut evidence =
            evidence_value(&format!("receipt:blake3:{}", "a".repeat(64)), json!([]))?;
        evidence["data"]["valid_receipts"][0]["id"] =
            json!(format!("receipt:blake3:{}", "A".repeat(64)));
        evidence = sign(evidence, DocumentKind::Evidence)?;
        assert_eq!(
            JsonEvidenceStateCodec.decode_evidence(EvidenceStateVersion::V2, &bytes(&evidence)?,),
            Err(forge_runtime::state::EvidenceStateDecodeError::InvalidReference)
        );
        Ok(())
    }

    #[test]
    fn receipt_v2_semantics_are_recomputed_instead_of_trusted() -> TestResult {
        let mut invalid_receipts = Vec::new();

        let mut empty = receipt_value(json!([]))?;
        empty["data"]["observations"] = json!([]);
        empty["data"]["coverage"] = json!([]);
        empty["data"]["outcome"] = json!("unknown");
        invalid_receipts.push(sign(empty, DocumentKind::Receipt)?);

        for pointer in [
            "/data/observations/0/command/native_program/display",
            "/data/observations/0/command/native_args/0/display",
            "/data/observations/0/command/native_environment_names/0/display",
        ] {
            let mut mismatched = receipt_value(json!([]))?;
            let value = mismatched
                .pointer_mut(pointer)
                .ok_or_else(|| std::io::Error::other("receipt mutation path is missing"))?;
            *value = json!("mismatch");
            invalid_receipts.push(sign(mismatched, DocumentKind::Receipt)?);
        }

        let mut wrong_outcome = receipt_value(json!([]))?;
        wrong_outcome["data"]["outcome"] = json!("product-failure");
        invalid_receipts.push(sign(wrong_outcome, DocumentKind::Receipt)?);

        let mut wrong_coverage = receipt_value(json!([]))?;
        wrong_coverage["data"]["coverage"] = json!(["compile"]);
        invalid_receipts.push(sign(wrong_coverage, DocumentKind::Receipt)?);

        let mut hidden_infrastructure_failure = receipt_value(json!([]))?;
        hidden_infrastructure_failure["data"]["observations"][0]["raw_exit_code"] = Value::Null;
        hidden_infrastructure_failure["data"]["observations"][0]["outcome"] =
            json!("infrastructure-failure");
        invalid_receipts.push(sign(hidden_infrastructure_failure, DocumentKind::Receipt)?);

        for (pointer, value) in [
            ("/data/observations/0/raw_exit_code", json!(1)),
            ("/data/observations/0/timed_out", json!(true)),
            ("/data/observations/0/interrupted", json!(true)),
            ("/data/observations/0/signal", json!(9)),
            ("/data/observations/0/output_truncated", json!(true)),
            ("/data/observations/0/stdout_truncated", json!(true)),
            ("/data/observations/0/stderr_truncated", json!(true)),
        ] {
            let mut contradictory = receipt_value(json!([]))?;
            *contradictory
                .pointer_mut(pointer)
                .ok_or_else(|| std::io::Error::other("observation mutation path is missing"))? =
                value;
            invalid_receipts.push(sign(contradictory, DocumentKind::Receipt)?);
        }

        for receipt in invalid_receipts {
            assert_eq!(
                JsonEvidenceStateCodec.decode_receipt(EvidenceStateVersion::V2, &bytes(&receipt)?,),
                Err(forge_runtime::state::EvidenceStateDecodeError::Malformed)
            );
        }
        Ok(())
    }

    #[test]
    fn complete_observation_facts_recompute_stdout_and_json_predicates() -> TestResult {
        for (predicate, fact_field, contradictory_fact) in [
            ("exit-zero-and-stdout-empty", "stdout_total_bytes", json!(1)),
            (
                "json-has-no-errors",
                "json_error_status",
                json!("has-errors"),
            ),
            ("json-has-no-errors", "json_error_status", json!("invalid")),
        ] {
            let mut receipt = receipt_value(json!([]))?;
            receipt["data"]["observations"][0]["command"]["success"] = json!({"kind": predicate});
            receipt["data"]["observations"][0][fact_field] = contradictory_fact;
            receipt = sign(receipt, DocumentKind::Receipt)?;

            assert_eq!(
                JsonEvidenceStateCodec.decode_receipt(EvidenceStateVersion::V2, &bytes(&receipt)?,),
                Err(forge_runtime::state::EvidenceStateDecodeError::Malformed),
                "predicate: {predicate}"
            );
        }

        for predicate in ["exit-zero-and-stdout-empty", "json-has-no-errors"] {
            let mut receipt = receipt_value(json!([]))?;
            receipt["data"]["observations"][0]["command"]["success"] = json!({"kind": predicate});
            if predicate == "json-has-no-errors" {
                receipt["data"]["observations"][0]["json_error_status"] = json!("no-errors");
            }
            receipt = sign(receipt, DocumentKind::Receipt)?;

            assert!(
                load_v2_receipt_fixture(&receipt)?.can_support_current_evidence,
                "predicate: {predicate}"
            );
        }

        let mut nonzero_with_empty_stdout = receipt_value(json!([]))?;
        nonzero_with_empty_stdout["data"]["observations"][0]["command"]["success"] =
            json!({"kind": "exit-zero-and-stdout-empty"});
        nonzero_with_empty_stdout["data"]["observations"][0]["raw_exit_code"] = json!(1);
        nonzero_with_empty_stdout["data"]["observations"][0]["outcome"] = json!("product-failure");
        nonzero_with_empty_stdout["data"]["outcome"] = json!("product-failure");
        nonzero_with_empty_stdout["data"]["coverage"] = json!([]);
        nonzero_with_empty_stdout = sign(nonzero_with_empty_stdout, DocumentKind::Receipt)?;
        assert!(
            load_v2_receipt_fixture(&nonzero_with_empty_stdout)?.can_support_current_evidence,
            "a nonzero exit must fail even when stdout is empty",
        );
        Ok(())
    }

    #[test]
    fn all_success_predicate_has_explicit_empty_pass_failure_and_unknown_cases() -> TestResult {
        let receipt: Envelope<ReceiptV2Data> = serde_json::from_value(receipt_value(json!([]))?)?;
        let observation = &receipt.data.observations[0];
        let outcome = |predicates| {
            super::outcome_from_success_predicate(
                &SuccessPredicateData::All { predicates },
                observation,
            )
        };

        assert_eq!(
            outcome(Vec::new()),
            Some(super::EvidenceOutcome::ProductFailure)
        );
        assert_eq!(
            outcome(vec![
                SuccessPredicateData::ExitZero,
                SuccessPredicateData::ExitZeroAndStdoutEmpty,
            ]),
            Some(super::EvidenceOutcome::Pass),
        );
        assert_eq!(
            outcome(vec![
                SuccessPredicateData::ExitZero,
                SuccessPredicateData::Unknown,
            ]),
            None,
        );

        let mut failed_observation = observation.clone();
        failed_observation.raw_exit_code = Some(1);
        assert_eq!(
            super::outcome_from_success_predicate(
                &SuccessPredicateData::All {
                    predicates: vec![
                        SuccessPredicateData::ExitZero,
                        SuccessPredicateData::Unknown,
                    ],
                },
                &failed_observation,
            ),
            Some(super::EvidenceOutcome::ProductFailure),
        );
        Ok(())
    }

    #[test]
    fn diagnostic_summary_is_compatible_on_read_and_required_for_current_writes() -> TestResult {
        let current = receipt_value(json!([]))?;
        assert!(load_v2_receipt_fixture(&current)?.can_support_current_evidence);

        let mut legacy = current.clone();
        legacy["data"]["observations"][0]
            .as_object_mut()
            .ok_or_else(|| std::io::Error::other("observation is not an object"))?
            .remove("diagnostic_summary");
        legacy = sign(legacy, DocumentKind::Receipt)?;
        assert!(!load_v2_receipt_fixture(&legacy)?.can_support_current_evidence);
        let legacy: Envelope<ReceiptV2Data> = serde_json::from_value(legacy)?;
        assert_eq!(
            prepare_receipt(legacy),
            Err(forge_runtime::state::EvidenceStateDecodeError::Malformed)
        );

        let mut future = current.clone();
        future["data"]["observations"][0]["diagnostic_summary"]["state"] = json!("future-summary");
        future = sign(future, DocumentKind::Receipt)?;
        assert!(!load_v2_receipt_fixture(&future)?.can_support_current_evidence);
        let future: Envelope<ReceiptV2Data> = serde_json::from_value(future)?;
        assert_eq!(
            prepare_receipt(future),
            Err(forge_runtime::state::EvidenceStateDecodeError::Malformed)
        );
        Ok(())
    }

    #[test]
    fn diagnostic_summary_known_states_require_exact_stream_facts() -> TestResult {
        let current = receipt_value(json!([]))?;
        for field in ["stdout_total_bytes", "stderr_total_bytes"] {
            let mut missing = current.clone();
            missing["data"]["observations"][0]["diagnostic_summary"]
                .as_object_mut()
                .ok_or_else(|| std::io::Error::other("summary is not an object"))?
                .remove(field);
            missing = sign(missing, DocumentKind::Receipt)?;
            assert_eq!(
                JsonEvidenceStateCodec.decode_receipt(EvidenceStateVersion::V2, &bytes(&missing)?),
                Err(forge_runtime::state::EvidenceStateDecodeError::Malformed),
                "field: {field}"
            );
        }

        let mut mismatched = current.clone();
        mismatched["data"]["observations"][0]["diagnostic_summary"]["stdout_total_bytes"] =
            json!(1);
        mismatched = sign(mismatched, DocumentKind::Receipt)?;
        assert_eq!(
            JsonEvidenceStateCodec.decode_receipt(EvidenceStateVersion::V2, &bytes(&mismatched)?,),
            Err(forge_runtime::state::EvidenceStateDecodeError::Malformed)
        );

        let mut unavailable_normal = current.clone();
        unavailable_normal["data"]["observations"][0]["diagnostic_summary"] =
            json!({"state": "unavailable"});
        unavailable_normal = sign(unavailable_normal, DocumentKind::Receipt)?;
        assert_eq!(
            JsonEvidenceStateCodec
                .decode_receipt(EvidenceStateVersion::V2, &bytes(&unavailable_normal)?,),
            Err(forge_runtime::state::EvidenceStateDecodeError::Malformed)
        );

        let mut observed_failure = typed_infrastructure_receipt("spawn")?;
        observed_failure["data"]["observations"][0]["diagnostic_summary"] = json!({
            "state": "observed",
            "stdout_total_bytes": 0,
            "stderr_total_bytes": 0
        });
        observed_failure = sign(observed_failure, DocumentKind::Receipt)?;
        assert_eq!(
            JsonEvidenceStateCodec
                .decode_receipt(EvidenceStateVersion::V2, &bytes(&observed_failure)?,),
            Err(forge_runtime::state::EvidenceStateDecodeError::Malformed)
        );

        let mut unavailable_with_count = typed_infrastructure_receipt("spawn")?;
        unavailable_with_count["data"]["observations"][0]["diagnostic_summary"]["stderr_total_bytes"] =
            json!(1);
        unavailable_with_count = sign(unavailable_with_count, DocumentKind::Receipt)?;
        assert_eq!(
            JsonEvidenceStateCodec
                .decode_receipt(EvidenceStateVersion::V2, &bytes(&unavailable_with_count)?,),
            Err(forge_runtime::state::EvidenceStateDecodeError::Malformed)
        );

        let mut unavailable_with_explicit_null = typed_infrastructure_receipt("spawn")?;
        unavailable_with_explicit_null["data"]["observations"][0]["diagnostic_summary"]["stdout_total_bytes"] =
            serde_json::Value::Null;
        unavailable_with_explicit_null["data"]["observations"][0]["diagnostic_summary"]["stderr_total_bytes"] =
            serde_json::Value::Null;
        unavailable_with_explicit_null =
            sign(unavailable_with_explicit_null, DocumentKind::Receipt)?;
        assert!(
            !load_v2_receipt_fixture(&unavailable_with_explicit_null)?.can_support_current_evidence
        );

        let (_, first_name) = calculate_identity(&current, DocumentKind::Receipt)?;
        let mut other_stderr_size = current;
        other_stderr_size["data"]["observations"][0]["diagnostic_summary"]["stderr_total_bytes"] =
            json!(1);
        let (_, second_name) = calculate_identity(&other_stderr_size, DocumentKind::Receipt)?;
        assert_ne!(first_name, second_name);
        Ok(())
    }

    #[test]
    fn legacy_missing_v2_facts_and_unknown_status_remain_non_proving() -> TestResult {
        let mut legacy = receipt_value(json!([]))?;
        let data = legacy["data"]
            .as_object_mut()
            .ok_or_else(|| std::io::Error::other("receipt data is not an object"))?;
        data.remove("resolution_confidence");
        data.remove("coverage_confidence");
        let observation = legacy["data"]["observations"][0]
            .as_object_mut()
            .ok_or_else(|| std::io::Error::other("observation is not an object"))?;
        observation.remove("diagnostic_summary");
        observation.remove("stdout_total_bytes");
        observation.remove("json_error_status");
        observation.remove("stdout_truncated");
        observation.remove("stderr_truncated");
        legacy = sign(legacy, DocumentKind::Receipt)?;

        let loaded_legacy = load_v2_receipt_fixture(&legacy)?;
        assert!(!loaded_legacy.can_support_current_evidence);
        let ParsedReceipt::V2(parsed_legacy) = loaded_legacy.parsed() else {
            return Err("legacy v2 Receipt loaded as the wrong schema generation".into());
        };
        assert_eq!(parsed_legacy.data.observations[0].stdout_total_bytes, None);
        assert_eq!(parsed_legacy.data.observations[0].diagnostic_summary, None);
        assert_eq!(parsed_legacy.data.observations[0].json_error_status, None);
        assert_eq!(parsed_legacy.data.observations[0].stdout_truncated, None);
        assert_eq!(parsed_legacy.data.observations[0].stderr_truncated, None);
        assert_eq!(parsed_legacy.data.resolution_confidence, None);
        assert_eq!(parsed_legacy.data.coverage_confidence, None);

        let mut ambiguous_legacy_truncation = receipt_value(json!([]))?;
        let observation = ambiguous_legacy_truncation["data"]["observations"][0]
            .as_object_mut()
            .ok_or_else(|| std::io::Error::other("observation is not an object"))?;
        observation.remove("stdout_truncated");
        observation.remove("stderr_truncated");
        observation.insert(String::from("output_truncated"), json!(true));
        ambiguous_legacy_truncation = sign(ambiguous_legacy_truncation, DocumentKind::Receipt)?;
        assert!(
            !load_v2_receipt_fixture(&ambiguous_legacy_truncation)?.can_support_current_evidence
        );

        let mut ambiguous_recorded_failure = receipt_value(json!([]))?;
        let observation = ambiguous_recorded_failure["data"]["observations"][0]
            .as_object_mut()
            .ok_or_else(|| std::io::Error::other("observation is not an object"))?;
        observation.remove("stdout_truncated");
        observation.remove("stderr_truncated");
        observation.insert(String::from("output_truncated"), json!(true));
        observation.insert(String::from("outcome"), json!("product-failure"));
        ambiguous_recorded_failure["data"]["outcome"] = json!("product-failure");
        ambiguous_recorded_failure["data"]["coverage"] = json!([]);
        ambiguous_recorded_failure = sign(ambiguous_recorded_failure, DocumentKind::Receipt)?;
        assert!(
            !load_v2_receipt_fixture(&ambiguous_recorded_failure)?.can_support_current_evidence,
            "ambiguous legacy facts must remain readable without recomputing their recorded failure",
        );

        let mut missing_stdout_total = receipt_value(json!([]))?;
        let observation = missing_stdout_total["data"]["observations"][0]
            .as_object_mut()
            .ok_or_else(|| std::io::Error::other("observation is not an object"))?;
        observation.remove("stdout_total_bytes");
        observation.remove("diagnostic_summary");
        missing_stdout_total = sign(missing_stdout_total, DocumentKind::Receipt)?;
        assert!(!load_v2_receipt_fixture(&missing_stdout_total)?.can_support_current_evidence);

        let mut missing_stream_facts = receipt_value(json!([]))?;
        let observation = missing_stream_facts["data"]["observations"][0]
            .as_object_mut()
            .ok_or_else(|| std::io::Error::other("observation is not an object"))?;
        observation.remove("stdout_truncated");
        observation.remove("stderr_truncated");
        missing_stream_facts = sign(missing_stream_facts, DocumentKind::Receipt)?;
        assert!(!load_v2_receipt_fixture(&missing_stream_facts)?.can_support_current_evidence);

        for (missing, retained) in [
            ("stderr_truncated", "stdout_truncated"),
            ("stdout_truncated", "stderr_truncated"),
        ] {
            let mut partial = receipt_value(json!([]))?;
            let observation = partial["data"]["observations"][0]
                .as_object_mut()
                .ok_or_else(|| std::io::Error::other("observation is not an object"))?;
            observation.remove(missing);
            observation.insert(String::from(retained), json!(true));
            observation.insert(String::from("output_truncated"), json!(true));
            partial = sign(partial, DocumentKind::Receipt)?;
            assert!(
                !load_v2_receipt_fixture(&partial)?.can_support_current_evidence,
                "partial stream truncation facts must remain readable but non-proving: {missing}",
            );

            let mut contradictory = receipt_value(json!([]))?;
            let observation = contradictory["data"]["observations"][0]
                .as_object_mut()
                .ok_or_else(|| std::io::Error::other("observation is not an object"))?;
            observation.remove(missing);
            observation.insert(String::from(retained), json!(true));
            observation.insert(String::from("output_truncated"), json!(false));
            contradictory = sign(contradictory, DocumentKind::Receipt)?;
            assert_eq!(
                JsonEvidenceStateCodec
                    .decode_receipt(EvidenceStateVersion::V2, &bytes(&contradictory)?),
                Err(forge_runtime::state::EvidenceStateDecodeError::Malformed),
                "partial stream truncation facts contradict the aggregate flag: {missing}",
            );
        }

        for field in ["resolution_confidence", "coverage_confidence"] {
            for confidence in ["low", "unknown"] {
                let mut receipt = receipt_value(json!([]))?;
                receipt["data"][field] = json!(confidence);
                receipt = sign(receipt, DocumentKind::Receipt)?;
                assert!(
                    !load_v2_receipt_fixture(&receipt)?.can_support_current_evidence,
                    "{field}={confidence} unexpectedly became proving"
                );
            }
        }

        let mut missing_json_status = receipt_value(json!([]))?;
        missing_json_status["data"]["observations"][0]["command"]["success"] =
            json!({"kind": "json-has-no-errors"});
        missing_json_status["data"]["observations"][0]
            .as_object_mut()
            .ok_or_else(|| std::io::Error::other("observation is not an object"))?
            .remove("json_error_status");
        missing_json_status = sign(missing_json_status, DocumentKind::Receipt)?;
        assert!(!load_v2_receipt_fixture(&missing_json_status)?.can_support_current_evidence);

        let mut unknown_status = receipt_value(json!([]))?;
        unknown_status["data"]["observations"][0]["command"]["success"] =
            json!({"kind": "json-has-no-errors"});
        unknown_status["data"]["observations"][0]["json_error_status"] = json!("unknown");
        unknown_status = sign(unknown_status, DocumentKind::Receipt)?;
        assert!(!load_v2_receipt_fixture(&unknown_status)?.can_support_current_evidence);

        let mut unknown_outcome = receipt_value(json!([]))?;
        unknown_outcome["data"]["observations"][0]["outcome"] = json!("unknown");
        unknown_outcome = sign(unknown_outcome, DocumentKind::Receipt)?;
        assert!(!load_v2_receipt_fixture(&unknown_outcome)?.can_support_current_evidence);
        Ok(())
    }

    #[test]
    fn legacy_truncation_ambiguity_requires_all_three_facts() -> TestResult {
        let mut complete_stream = receipt_value(json!([]))?;
        complete_stream["data"]["observations"][0]["stdout_truncated"] = json!(true);
        complete_stream["data"]["observations"][0]["output_truncated"] = json!(true);

        let mut nonzero_stdout = receipt_value(json!([]))?;
        let observation = nonzero_stdout["data"]["observations"][0]
            .as_object_mut()
            .ok_or_else(|| std::io::Error::other("observation is not an object"))?;
        observation.remove("stdout_truncated");
        observation.remove("stderr_truncated");
        observation.insert(String::from("stdout_total_bytes"), json!(1));
        observation.insert(String::from("output_truncated"), json!(true));
        observation.insert(String::from("outcome"), json!("product-failure"));
        nonzero_stdout["data"]["outcome"] = json!("product-failure");
        nonzero_stdout["data"]["coverage"] = json!([]);

        let mut not_truncated = receipt_value(json!([]))?;
        let observation = not_truncated["data"]["observations"][0]
            .as_object_mut()
            .ok_or_else(|| std::io::Error::other("observation is not an object"))?;
        observation.remove("stdout_truncated");
        observation.remove("stderr_truncated");
        observation.insert(String::from("outcome"), json!("product-failure"));
        not_truncated["data"]["outcome"] = json!("product-failure");
        not_truncated["data"]["coverage"] = json!([]);

        for (missing_fact, receipt) in [
            ("stream facts are complete", complete_stream),
            ("stdout is nonzero", nonzero_stdout),
            ("aggregate truncation is false", not_truncated),
        ] {
            let receipt = sign(receipt, DocumentKind::Receipt)?;
            assert_eq!(
                JsonEvidenceStateCodec.decode_receipt(EvidenceStateVersion::V2, &bytes(&receipt)?),
                Err(forge_runtime::state::EvidenceStateDecodeError::Malformed),
                "legacy ambiguity accepted when {missing_fact}",
            );
        }
        Ok(())
    }

    #[test]
    fn process_boundary_failure_is_recordable_but_non_proving() -> TestResult {
        let mut receipt = receipt_value(json!([]))?;
        receipt["data"]["observations"][0]["raw_exit_code"] = Value::Null;
        receipt["data"]["observations"][0]["outcome"] = json!("infrastructure-failure");
        receipt["data"]["outcome"] = json!("infrastructure-failure");
        receipt["data"]["coverage"] = json!([]);
        receipt = sign(receipt, DocumentKind::Receipt)?;
        let object_name = super::parse_public_id(
            receipt["data"]["id"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("receipt id is not a string"))?,
            super::RECEIPT_ID_PREFIX,
        )?;

        let loaded = load_receipt(EvidenceStateVersion::V2, &object_name, &bytes(&receipt)?)?;
        assert!(!loaded.can_support_current_evidence);
        Ok(())
    }

    #[test]
    fn budget_terminal_observations_prepare_decode_and_cannot_bind_as_valid() -> TestResult {
        let (stdout_digest, stderr_digest) = forge_runtime::process::empty_process_output_digests();
        let (unavailable_stdout, unavailable_stderr) =
            forge_core::fingerprint::process_output_unavailable_digests(
                &forge_runtime::hash::Blake3Hasher,
            );
        assert_ne!(stdout_digest, unavailable_stdout);
        assert_ne!(stderr_digest, unavailable_stderr);

        for (outcome, timed_out, interrupted) in
            [("timed-out", true, false), ("interrupted", false, true)]
        {
            let mut receipt = receipt_value(json!([]))?;
            let observation = receipt["data"]["observations"][0]
                .as_object_mut()
                .ok_or_else(|| std::io::Error::other("observation is not an object"))?;
            observation.insert(String::from("raw_exit_code"), Value::Null);
            observation.insert(String::from("signal"), Value::Null);
            observation.insert(String::from("outcome"), json!(outcome));
            observation.insert(String::from("duration_ms"), json!(0));
            observation.insert(String::from("timed_out"), json!(timed_out));
            observation.insert(String::from("interrupted"), json!(interrupted));
            observation.remove("process_error_kind");
            observation.insert(String::from("stdout_digest"), json!(stdout_digest.as_str()));
            observation.insert(String::from("stdout_total_bytes"), json!(0));
            observation.insert(String::from("stderr_digest"), json!(stderr_digest.as_str()));
            observation.insert(String::from("stdout_truncated"), json!(false));
            observation.insert(String::from("stderr_truncated"), json!(false));
            observation.insert(String::from("output_truncated"), json!(false));
            observation.insert(String::from("log_refs"), json!([]));
            receipt["data"]["outcome"] = json!(outcome);
            receipt["data"]["coverage"] = json!([]);

            let receipt: Envelope<ReceiptV2Data> = serde_json::from_value(receipt)?;
            let prepared = prepare_receipt(receipt)?;
            let loaded = load_receipt(
                EvidenceStateVersion::V2,
                prepared.object_name(),
                prepared.bytes(),
            )?;
            let ParsedReceipt::V2(parsed) = loaded.parsed() else {
                return Err("v2 Receipt loaded as the wrong schema generation".into());
            };
            assert_eq!(
                serde_json::to_value(parsed.data.observations[0].outcome)?,
                json!(outcome)
            );

            let receipt_id = format!("receipt:blake3:{}", prepared.object_name().as_str());
            let mut evidence = evidence_value(&receipt_id, json!([]))?;
            evidence["data"]["stale_receipts"] = json!([]);
            let evidence: Envelope<EvidenceV2Data> = serde_json::from_value(evidence)?;
            let binding = loaded.binding_fact();
            assert!(matches!(
                prepare_evidence(evidence, [&binding]),
                Err(forge_runtime::state::EvidenceStateDecodeError::InvalidReference)
            ));
        }
        Ok(())
    }

    #[test]
    fn typed_process_boundary_failure_is_exact_and_non_proving() -> TestResult {
        let receipt = typed_infrastructure_receipt("executable-unavailable")?;
        let loaded = load_v2_receipt_fixture(&receipt)?;

        assert!(!loaded.can_support_current_evidence);
        assert!(loaded.can_evaluate_current_validity);
        assert!(loaded.evaluation_projection()?.current.is_some());
        Ok(())
    }

    #[test]
    fn advisory_process_failure_with_required_pass_is_projectable_but_not_supporting() -> TestResult
    {
        let passing = receipt_value(json!([]))?;
        let mut receipt = typed_infrastructure_receipt("spawn")?;
        receipt["data"]["observations"][0]["command"]["enforcement"] = json!("advisory");
        let mut required = passing["data"]["observations"][0].clone();
        required["command"]["command"]["id"] = json!("rust.test.required");
        receipt["data"]["observations"]
            .as_array_mut()
            .ok_or_else(|| std::io::Error::other("observations are not an array"))?
            .push(required);
        receipt["data"]["outcome"] = json!("pass");
        receipt["data"]["coverage"] = json!(["unit-test"]);
        receipt = sign(receipt, DocumentKind::Receipt)?;

        let loaded = load_v2_receipt_fixture(&receipt)?;
        assert!(loaded.can_evaluate_current_validity);
        assert!(!loaded.can_support_current_evidence);
        let projection = loaded
            .evaluation_projection()?
            .current
            .ok_or_else(|| std::io::Error::other("current projection is missing"))?;
        assert_eq!(
            projection.recorded.outcome(),
            forge_core::evidence::EvidenceOutcome::Pass
        );
        Ok(())
    }

    #[test]
    fn unavailable_output_sentinels_require_a_typed_process_failure() -> TestResult {
        let (unavailable_stdout, unavailable_stderr) =
            forge_core::fingerprint::process_output_unavailable_digests(
                &forge_runtime::hash::Blake3Hasher,
            );

        for (pointer, digest) in [
            (
                "/data/observations/0/stdout_digest",
                unavailable_stdout.as_str(),
            ),
            (
                "/data/observations/0/stderr_digest",
                unavailable_stderr.as_str(),
            ),
        ] {
            let mut receipt = receipt_value(json!([]))?;
            *receipt
                .pointer_mut(pointer)
                .ok_or_else(|| std::io::Error::other("output digest pointer is missing"))? =
                json!(digest);
            receipt = sign(receipt, DocumentKind::Receipt)?;

            assert_eq!(
                JsonEvidenceStateCodec.decode_receipt(EvidenceStateVersion::V2, &bytes(&receipt)?),
                Err(forge_runtime::state::EvidenceStateDecodeError::Malformed),
                "an unavailable sentinel without process_error_kind was accepted: {pointer}",
            );
        }
        Ok(())
    }

    #[test]
    fn typed_process_boundary_failure_rejects_incoherent_fields() -> TestResult {
        let mutations = [
            ("/data/observations/0/raw_exit_code", json!(1)),
            ("/data/observations/0/signal", json!(9)),
            ("/data/observations/0/timed_out", json!(true)),
            ("/data/observations/0/interrupted", json!(true)),
            ("/data/observations/0/outcome", json!("unknown")),
            (
                "/data/observations/0/stdout_digest",
                json!("blake3:not-the-unavailable-marker"),
            ),
            (
                "/data/observations/0/stderr_digest",
                json!("blake3:not-the-unavailable-marker"),
            ),
            ("/data/observations/0/stdout_total_bytes", json!(0)),
            ("/data/observations/0/json_error_status", json!("no-errors")),
            ("/data/observations/0/stdout_truncated", json!(false)),
            ("/data/observations/0/stderr_truncated", json!(false)),
            ("/data/observations/0/output_truncated", json!(false)),
            (
                "/data/observations/0/log_refs",
                json!([{"display": "logs/v1/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.log", "encoding": "utf8"}]),
            ),
        ];

        for (pointer, value) in mutations {
            let mut receipt = typed_infrastructure_receipt("wait")?;
            if let Some(target) = receipt.pointer_mut(pointer) {
                *target = value;
            } else {
                let field = pointer
                    .rsplit('/')
                    .next()
                    .ok_or_else(|| std::io::Error::other("mutation field is missing"))?;
                receipt["data"]["observations"][0]
                    .as_object_mut()
                    .ok_or_else(|| std::io::Error::other("observation is not an object"))?
                    .insert(field.to_owned(), value);
            }
            if pointer == "/data/observations/0/outcome" {
                receipt["data"]["outcome"] = json!("unknown");
            }
            receipt = sign(receipt, DocumentKind::Receipt)?;
            assert_eq!(
                JsonEvidenceStateCodec.decode_receipt(EvidenceStateVersion::V2, &bytes(&receipt)?),
                Err(forge_runtime::state::EvidenceStateDecodeError::Malformed),
                "incoherent typed process failure was accepted: {pointer}",
            );
        }

        let mut missing_kind = typed_infrastructure_receipt("wait")?;
        missing_kind["data"]["observations"][0]
            .as_object_mut()
            .ok_or_else(|| std::io::Error::other("observation is not an object"))?
            .remove("process_error_kind");
        missing_kind = sign(missing_kind, DocumentKind::Receipt)?;
        assert_eq!(
            JsonEvidenceStateCodec.decode_receipt(EvidenceStateVersion::V2, &bytes(&missing_kind)?),
            Err(forge_runtime::state::EvidenceStateDecodeError::Malformed),
        );
        Ok(())
    }

    #[test]
    fn future_process_failure_kind_is_preserved_and_non_proving() -> TestResult {
        let receipt = typed_infrastructure_receipt("future-process-boundary")?;
        let loaded = load_v2_receipt_fixture(&receipt)?;

        assert!(!loaded.can_support_current_evidence);
        assert!(!loaded.can_evaluate_current_validity);
        assert!(loaded.evaluation_projection()?.current.is_none());
        let ParsedReceipt::V2(parsed) = loaded.parsed() else {
            return Err("v2 Receipt loaded as the wrong schema generation".into());
        };
        assert_eq!(
            parsed.data.observations[0].process_error_kind,
            Some(forge_schema::ProcessErrorKindV2Data::Unknown)
        );
        Ok(())
    }

    #[test]
    fn process_boundary_failure_requires_every_boundary_fact() -> TestResult {
        for (pointer, value, observation_outcome) in [
            (
                "/data/observations/0/raw_exit_code",
                json!(1),
                "infrastructure-failure",
            ),
            (
                "/data/observations/0/signal",
                json!(9),
                "infrastructure-failure",
            ),
            (
                "/data/observations/0/timed_out",
                json!(true),
                "infrastructure-failure",
            ),
            (
                "/data/observations/0/interrupted",
                json!(true),
                "infrastructure-failure",
            ),
            (
                "/data/observations/0/outcome",
                json!("product-failure"),
                "product-failure",
            ),
        ] {
            let mut receipt = receipt_value(json!([]))?;
            receipt["data"]["observations"][0]["raw_exit_code"] = Value::Null;
            receipt["data"]["observations"][0]["outcome"] = json!("infrastructure-failure");
            receipt["data"]["outcome"] = json!(observation_outcome);
            receipt["data"]["coverage"] = json!([]);
            *receipt
                .pointer_mut(pointer)
                .ok_or_else(|| std::io::Error::other("boundary pointer is missing"))? = value;
            receipt = sign(receipt, DocumentKind::Receipt)?;

            assert_eq!(
                JsonEvidenceStateCodec.decode_receipt(EvidenceStateVersion::V2, &bytes(&receipt)?),
                Err(forge_runtime::state::EvidenceStateDecodeError::Malformed),
                "incomplete process-boundary failure was accepted: {pointer}",
            );
        }
        Ok(())
    }

    #[test]
    fn same_major_unknown_receipt_semantics_are_accepted_but_non_proving() -> TestResult {
        for (pointer, value) in [
            (
                "/data/observations/0/command/command/intent",
                json!("future-intent"),
            ),
            (
                "/data/comparison_basis/protocol",
                json!("forge.future-comparison/v1"),
            ),
            (
                "/data/comparison_basis/baseline/state",
                json!("future-state"),
            ),
            (
                "/data/comparison_basis/task_acceptance/state",
                json!("future-state"),
            ),
            (
                "/data/observations/0/command/success/kind",
                json!("future-predicate"),
            ),
            (
                "/data/observations/0/command/command/coverage/0",
                json!("future-coverage"),
            ),
        ] {
            let mut receipt = receipt_value(json!([]))?;
            *receipt
                .pointer_mut(pointer)
                .ok_or_else(|| std::io::Error::other("receipt mutation path is missing"))? = value;
            receipt = sign(receipt, DocumentKind::Receipt)?;
            let object_name = super::parse_public_id(
                receipt["data"]["id"]
                    .as_str()
                    .ok_or_else(|| std::io::Error::other("receipt id is not a string"))?,
                super::RECEIPT_ID_PREFIX,
            )?;
            let loaded = load_receipt(EvidenceStateVersion::V2, &object_name, &bytes(&receipt)?)?;
            assert!(!loaded.can_support_current_evidence, "pointer: {pointer}");
        }

        let mut explicit_unknown = receipt_value(json!([]))?;
        explicit_unknown["data"]["intent"] = json!("unknown");
        explicit_unknown = sign(explicit_unknown, DocumentKind::Receipt)?;
        let object_name = super::parse_public_id(
            explicit_unknown["data"]["id"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("receipt id is not a string"))?,
            super::RECEIPT_ID_PREFIX,
        )?;
        let loaded = load_receipt(
            EvidenceStateVersion::V2,
            &object_name,
            &bytes(&explicit_unknown)?,
        )?;
        assert!(!loaded.can_support_current_evidence);
        Ok(())
    }

    #[test]
    fn receipt_log_summary_must_exactly_match_unique_observation_refs() -> TestResult {
        let log_name = log_object_name_fixture()?;
        let path = log_path(log_name.as_str());

        let mut missing_observation_ref = receipt_value(json!([]))?;
        missing_observation_ref["data"]["log_refs"] = json!([path.clone()]);
        missing_observation_ref = sign(missing_observation_ref, DocumentKind::Receipt)?;
        assert_eq!(
            JsonEvidenceStateCodec
                .decode_receipt(EvidenceStateVersion::V2, &bytes(&missing_observation_ref)?,),
            Err(forge_runtime::state::EvidenceStateDecodeError::InvalidReference)
        );

        let duplicate = receipt_value(json!([path.clone(), path.clone()]))?;
        assert_eq!(
            JsonEvidenceStateCodec.decode_receipt(EvidenceStateVersion::V2, &bytes(&duplicate)?,),
            Err(forge_runtime::state::EvidenceStateDecodeError::InvalidReference)
        );

        let mut shared_across_observations = receipt_value(json!([path.clone()]))?;
        let mut second = shared_across_observations["data"]["observations"][0].clone();
        second["command"]["command"]["id"] = json!("rust.test.second");
        shared_across_observations["data"]["observations"] = json!([
            shared_across_observations["data"]["observations"][0].clone(),
            second
        ]);
        shared_across_observations = sign(shared_across_observations, DocumentKind::Receipt)?;
        JsonEvidenceStateCodec.decode_receipt(
            EvidenceStateVersion::V2,
            &bytes(&shared_across_observations)?,
        )?;
        Ok(())
    }

    #[test]
    fn evidence_v2_rejects_external_authority_and_ambiguous_receipt_sets() -> TestResult {
        let receipt_id = format!("receipt:blake3:{}", "a".repeat(64));
        let mut invalid_evidence = Vec::new();

        let mut attested = evidence_value(&receipt_id, json!([]))?;
        attested["data"]["external_attestations"] = json!([{
            "source": "untrusted-input",
            "trust_level": "external-attestation",
            "verified": true,
            "reference": "text-only"
        }]);
        invalid_evidence.push((
            sign(attested, DocumentKind::Evidence)?,
            forge_runtime::state::EvidenceStateDecodeError::Malformed,
        ));

        let mut duplicate_valid = evidence_value(&receipt_id, json!([]))?;
        let duplicated = duplicate_valid["data"]["valid_receipts"][0].clone();
        duplicate_valid["data"]["valid_receipts"] = json!([duplicated.clone(), duplicated]);
        invalid_evidence.push((
            sign(duplicate_valid, DocumentKind::Evidence)?,
            forge_runtime::state::EvidenceStateDecodeError::InvalidReference,
        ));

        let mut duplicate_across_sets = evidence_value(&receipt_id, json!([]))?;
        duplicate_across_sets["data"]["stale_receipts"][0]["id"] = json!(receipt_id);
        invalid_evidence.push((
            sign(duplicate_across_sets, DocumentKind::Evidence)?,
            forge_runtime::state::EvidenceStateDecodeError::InvalidReference,
        ));

        let mut non_passing_valid =
            evidence_value(&format!("receipt:blake3:{}", "a".repeat(64)), json!([]))?;
        non_passing_valid["data"]["valid_receipts"][0]["outcome"] = json!("product-failure");
        invalid_evidence.push((
            sign(non_passing_valid, DocumentKind::Evidence)?,
            forge_runtime::state::EvidenceStateDecodeError::Malformed,
        ));

        let mut historical_as_valid =
            evidence_value(&format!("receipt:blake3:{}", "a".repeat(64)), json!([]))?;
        historical_as_valid["data"]["valid_receipts"][0]["schema"] = json!("forge.receipt/v1");
        invalid_evidence.push((
            sign(historical_as_valid, DocumentKind::Evidence)?,
            forge_runtime::state::EvidenceStateDecodeError::Malformed,
        ));

        let mut noncanonical_coverage = evidence_value(&receipt_id, json!([]))?;
        noncanonical_coverage["data"]["valid_receipts"][0]["coverage"] =
            json!(["unit-test", "compile"]);
        invalid_evidence.push((
            sign(noncanonical_coverage, DocumentKind::Evidence)?,
            forge_runtime::state::EvidenceStateDecodeError::Malformed,
        ));

        let log_name = log_object_name_fixture()?;
        let path = log_path(log_name.as_str());
        let duplicate_logs = evidence_value(
            &format!("receipt:blake3:{}", "a".repeat(64)),
            json!([path.clone(), path]),
        )?;
        invalid_evidence.push((
            duplicate_logs,
            forge_runtime::state::EvidenceStateDecodeError::InvalidReference,
        ));

        for (evidence, expected) in invalid_evidence {
            assert_eq!(
                JsonEvidenceStateCodec
                    .decode_evidence(EvidenceStateVersion::V2, &bytes(&evidence)?,),
                Err(expected)
            );
        }
        Ok(())
    }

    #[test]
    fn same_major_unknown_evidence_semantics_are_accepted_with_retain_all() -> TestResult {
        let mut evidence =
            evidence_value(&format!("receipt:blake3:{}", "a".repeat(64)), json!([]))?;
        evidence["data"]["comparison"]["basis"]["protocol"] = json!("forge.future-comparison/v1");
        evidence = sign(evidence, DocumentKind::Evidence)?;
        let evidence_name = super::parse_public_id(
            evidence["data"]["id"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("evidence id is not a string"))?,
            super::EVIDENCE_ID_PREFIX,
        )?;
        let evidence_bytes = bytes(&evidence)?;
        load_evidence(EvidenceStateVersion::V2, &evidence_name, &evidence_bytes)?;

        assert_eq!(
            JsonEvidenceStateCodec.decode_evidence(EvidenceStateVersion::V2, &evidence_bytes)?,
            EvidenceRetentionMetadata::with_reference_closures(
                evidence_name.clone(),
                EvidenceRetentionTime::Current(parse_utc_rfc3339("2026-07-27T00:01:00Z")?),
                ReferenceClosure::RetainAll,
                ReferenceClosure::RetainAll,
            )
        );

        let mut unknown_coverage =
            evidence_value(&format!("receipt:blake3:{}", "a".repeat(64)), json!([]))?;
        unknown_coverage["data"]["valid_receipts"][0]["coverage"] = json!(["future-coverage"]);
        unknown_coverage = sign(unknown_coverage, DocumentKind::Evidence)?;
        let unknown_coverage_name = super::parse_public_id(
            unknown_coverage["data"]["id"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("evidence id is not a string"))?,
            super::EVIDENCE_ID_PREFIX,
        )?;
        load_evidence(
            EvidenceStateVersion::V2,
            &unknown_coverage_name,
            &bytes(&unknown_coverage)?,
        )?;
        Ok(())
    }

    #[test]
    fn receipt_identity_has_a_fixed_golden_vector() -> TestResult {
        let receipt = receipt_value(json!([]))?;
        let (_, object_name) = calculate_identity(&receipt, DocumentKind::Receipt)?;

        assert_eq!(
            object_name.as_str(),
            "6b076aa57657dc7f2911447c7f060b4b716bdebc94888b7690df8c6c971264b2"
        );
        Ok(())
    }

    #[test]
    fn evidence_identity_has_a_fixed_golden_vector() -> TestResult {
        let evidence = evidence_value(&format!("receipt:blake3:{}", "a".repeat(64)), json!([]))?;
        let (_, evidence_name) = calculate_identity(&evidence, DocumentKind::Evidence)?;

        assert_eq!(
            evidence_name.as_str(),
            "990d0908a4e661b6807fa15a5e56dab6b0e5c92b6fcf1160df699a7b9c7343ec"
        );
        Ok(())
    }

    #[test]
    fn v2_metadata_keeps_receipt_and_log_reference_closure() -> TestResult {
        let log_name = log_object_name_fixture()?;
        let log = log_path(log_name.as_str());
        let receipt = receipt_value(json!([log.clone()]))?;
        let receipt_id = receipt["data"]["id"]
            .as_str()
            .ok_or_else(|| std::io::Error::other("receipt fixture id is not a string"))?;
        let receipt_name = super::parse_public_id(receipt_id, super::RECEIPT_ID_PREFIX)?;
        let evidence = evidence_value(receipt_id, json!([log]))?;
        let evidence_id = evidence["data"]["id"]
            .as_str()
            .ok_or_else(|| std::io::Error::other("evidence fixture id is not a string"))?;
        let evidence_name = super::parse_public_id(evidence_id, super::EVIDENCE_ID_PREFIX)?;
        let receipt_time = parse_utc_rfc3339("2026-07-27T00:00:00Z")?;
        let evidence_time = parse_utc_rfc3339("2026-07-27T00:01:00Z")?;

        assert_eq!(
            JsonEvidenceStateCodec.decode_receipt(EvidenceStateVersion::V2, &bytes(&receipt)?,)?,
            ReceiptRetentionMetadata::new(
                receipt_name.clone(),
                EvidenceRetentionTime::Current(receipt_time),
                [log_name.clone()],
            )
        );
        assert_eq!(
            JsonEvidenceStateCodec.decode_evidence(EvidenceStateVersion::V2, &bytes(&evidence)?,)?,
            EvidenceRetentionMetadata::new(
                evidence_name,
                EvidenceRetentionTime::Current(evidence_time),
                [
                    ReceiptStateReference::new(EvidenceStateVersion::V2, receipt_name),
                    ReceiptStateReference::new(
                        EvidenceStateVersion::V1,
                        super::parse_public_id(
                            &format!("receipt:blake3:{}", "b".repeat(64)),
                            super::RECEIPT_ID_PREFIX,
                        )?,
                    ),
                ],
                [log_name],
            )
        );
        Ok(())
    }

    #[test]
    fn v1_evidence_is_legacy_and_keeps_both_receipt_reference_sets() -> TestResult {
        let valid_id = format!("receipt:blake3:{}", "c".repeat(64));
        let stale_id = format!("receipt:blake3:{}", "d".repeat(64));
        let evidence = evidence_v1_value(&valid_id, &stale_id)?;
        let evidence_id = evidence["data"]["id"]
            .as_str()
            .ok_or_else(|| std::io::Error::other("evidence fixture id is not a string"))?;
        let evidence_name = super::parse_public_id(evidence_id, super::EVIDENCE_ID_PREFIX)?;

        assert_eq!(
            JsonEvidenceStateCodec.decode_evidence(EvidenceStateVersion::V1, &bytes(&evidence)?,)?,
            EvidenceRetentionMetadata::new(
                evidence_name,
                EvidenceRetentionTime::Legacy,
                [
                    ReceiptStateReference::new(
                        EvidenceStateVersion::V1,
                        super::parse_public_id(&valid_id, super::RECEIPT_ID_PREFIX)?,
                    ),
                    ReceiptStateReference::new(
                        EvidenceStateVersion::V1,
                        super::parse_public_id(&stale_id, super::RECEIPT_ID_PREFIX)?,
                    ),
                ],
                [],
            )
        );
        Ok(())
    }

    #[test]
    fn v1_receipt_and_evidence_fixtures_satisfy_checked_in_schemas() -> TestResult {
        let receipt = receipt_v1_value()?;
        validate_fixture_against_checked_in_schema(&receipt, "receipt-v1.schema.json")?;

        let valid_id = receipt["data"]["id"]
            .as_str()
            .ok_or_else(|| std::io::Error::other("v1 receipt fixture id is not a string"))?;
        let stale_id = format!("receipt:blake3:{}", "d".repeat(64));
        let evidence = evidence_v1_value(valid_id, &stale_id)?;
        validate_fixture_against_checked_in_schema(&evidence, "evidence-v1.schema.json")
    }

    #[test]
    fn load_returns_typed_documents_only_after_filename_validation() -> TestResult {
        let receipt_v1 = receipt_v1_value()?;
        let receipt_v1_name = super::parse_public_id(
            receipt_v1["data"]["id"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("v1 receipt id is not a string"))?,
            super::RECEIPT_ID_PREFIX,
        )?;
        let receipt_v1_bytes = bytes(&receipt_v1)?;
        let loaded_receipt_v1 = load_receipt(
            EvidenceStateVersion::V1,
            &receipt_v1_name,
            &receipt_v1_bytes,
        )?;
        let ParsedReceipt::V1(parsed_receipt_v1) = loaded_receipt_v1.parsed() else {
            return Err("v1 Receipt loaded as the wrong schema generation".into());
        };
        assert_eq!(parsed_receipt_v1.schema, "forge.receipt/v1");
        assert_eq!(loaded_receipt_v1.version, EvidenceStateVersion::V1);
        assert_eq!(loaded_receipt_v1.object_name, receipt_v1_name);

        let receipt_v2 = receipt_value(json!([]))?;
        let receipt_v2_name = super::parse_public_id(
            receipt_v2["data"]["id"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("v2 receipt id is not a string"))?,
            super::RECEIPT_ID_PREFIX,
        )?;
        let loaded_receipt_v2 = load_receipt(
            EvidenceStateVersion::V2,
            &receipt_v2_name,
            &bytes(&receipt_v2)?,
        )?;
        let ParsedReceipt::V2(parsed_receipt_v2) = loaded_receipt_v2.parsed() else {
            return Err("v2 Receipt loaded as the wrong schema generation".into());
        };
        assert_eq!(parsed_receipt_v2.schema, "forge.receipt/v2");

        let valid_id = format!("receipt:blake3:{}", "c".repeat(64));
        let stale_id = format!("receipt:blake3:{}", "d".repeat(64));
        let evidence_v1 = evidence_v1_value(&valid_id, &stale_id)?;
        let evidence_v1_name = super::parse_public_id(
            evidence_v1["data"]["id"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("v1 evidence id is not a string"))?,
            super::EVIDENCE_ID_PREFIX,
        )?;
        let loaded_evidence_v1 = load_evidence(
            EvidenceStateVersion::V1,
            &evidence_v1_name,
            &bytes(&evidence_v1)?,
        )?;
        let ParsedEvidence::V1(parsed_evidence_v1) = loaded_evidence_v1.parsed() else {
            return Err("v1 Evidence loaded as the wrong schema generation".into());
        };
        assert_eq!(parsed_evidence_v1.schema, "forge.evidence/v1");

        let evidence_v2 = evidence_value(&valid_id, json!([]))?;
        let evidence_v2_name = super::parse_public_id(
            evidence_v2["data"]["id"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("v2 evidence id is not a string"))?,
            super::EVIDENCE_ID_PREFIX,
        )?;
        let evidence_v2_bytes = bytes(&evidence_v2)?;
        let loaded_evidence_v2 = load_evidence(
            EvidenceStateVersion::V2,
            &evidence_v2_name,
            &evidence_v2_bytes,
        )?;
        let ParsedEvidence::V2(parsed_evidence_v2) = loaded_evidence_v2.parsed() else {
            return Err("v2 Evidence loaded as the wrong schema generation".into());
        };
        assert_eq!(parsed_evidence_v2.schema, "forge.evidence/v2");

        let wrong = forge_runtime::state::EvidenceStateObjectName::new("e".repeat(64))?;
        assert_eq!(
            load_evidence(EvidenceStateVersion::V2, &wrong, &bytes(&evidence_v2)?,),
            Err(forge_runtime::state::EvidenceStateDecodeError::InvalidReference)
        );
        Ok(())
    }

    #[test]
    fn loaded_documents_preserve_identity_bearing_unknown_fields() -> TestResult {
        let mut receipt = receipt_value(json!([]))?;
        receipt["future_same_major"] = json!({
            "nested": {"reference": "logs/v1/future.log"}
        });
        receipt = sign(receipt, DocumentKind::Receipt)?;
        let object_name = super::parse_public_id(
            receipt["data"]["id"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("receipt id is not a string"))?,
            super::RECEIPT_ID_PREFIX,
        )?;
        let original = bytes(&receipt)?;

        let loaded = load_receipt(EvidenceStateVersion::V2, &object_name, &original)?;
        assert!(!loaded.can_support_current_evidence);
        assert!(!loaded.can_evaluate_current_validity);
        assert!(loaded.evaluation_projection()?.current.is_none());
        assert_eq!(
            receipt.pointer("/future_same_major/nested/reference"),
            Some(&json!("logs/v1/future.log"))
        );
        let ParsedReceipt::V2(parsed) = loaded.parsed() else {
            return Err("v2 Receipt loaded as the wrong schema generation".into());
        };
        assert!(
            serde_json::to_value(parsed)?
                .get("future_same_major")
                .is_none()
        );
        assert_eq!(
            JsonEvidenceStateCodec.decode_receipt(EvidenceStateVersion::V2, &original)?,
            ReceiptRetentionMetadata::with_log_reference_closure(
                object_name,
                EvidenceRetentionTime::Current(parse_utc_rfc3339("2026-07-27T00:00:00Z")?),
                ReferenceClosure::RetainAll,
            )
        );
        Ok(())
    }

    #[test]
    fn evidence_receipt_summaries_are_bound_to_immutable_receipts() -> TestResult {
        let receipt_v2 = receipt_value(json!([]))?;
        let receipt_v2_id = receipt_v2["data"]["id"]
            .as_str()
            .ok_or_else(|| std::io::Error::other("v2 receipt id is not a string"))?;
        let receipt_v2_name = super::parse_public_id(receipt_v2_id, super::RECEIPT_ID_PREFIX)?;
        let loaded_receipt_v2 = load_receipt(
            EvidenceStateVersion::V2,
            &receipt_v2_name,
            &bytes(&receipt_v2)?,
        )?;

        let receipt_v1 = receipt_v1_value()?;
        let receipt_v1_id = receipt_v1["data"]["id"]
            .as_str()
            .ok_or_else(|| std::io::Error::other("v1 receipt id is not a string"))?;
        let receipt_v1_name = super::parse_public_id(receipt_v1_id, super::RECEIPT_ID_PREFIX)?;
        let loaded_receipt_v1 = load_receipt(
            EvidenceStateVersion::V1,
            &receipt_v1_name,
            &bytes(&receipt_v1)?,
        )?;

        let mut evidence = evidence_value(receipt_v2_id, json!([]))?;
        evidence["data"]["stale_receipts"][0]["id"] = json!(receipt_v1_id);
        evidence = sign(evidence, DocumentKind::Evidence)?;
        let evidence_name = super::parse_public_id(
            evidence["data"]["id"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("evidence id is not a string"))?,
            super::EVIDENCE_ID_PREFIX,
        )?;
        let loaded_evidence =
            load_evidence(EvidenceStateVersion::V2, &evidence_name, &bytes(&evidence)?)?;
        let receipt_facts = [
            loaded_receipt_v2.binding_fact(),
            loaded_receipt_v1.binding_fact(),
        ];
        validate_evidence_receipt_bindings(&loaded_evidence, &receipt_facts)?;

        let mut wrong_v1_stale_intent = receipt_facts[1].clone();
        wrong_v1_stale_intent.intent = IntentData::Build;
        assert_eq!(
            validate_evidence_receipt_bindings(
                &loaded_evidence,
                [&receipt_facts[0], &wrong_v1_stale_intent],
            ),
            Err(forge_runtime::state::EvidenceStateDecodeError::InvalidReference),
        );
        let mut wrong_v1_stale_outcome = receipt_facts[1].clone();
        wrong_v1_stale_outcome.outcome = OutcomeData::ProductFailure;
        assert_eq!(
            validate_evidence_receipt_bindings(
                &loaded_evidence,
                [&receipt_facts[0], &wrong_v1_stale_outcome],
            ),
            Err(forge_runtime::state::EvidenceStateDecodeError::InvalidReference),
        );

        let mut stale_v2_evidence = evidence_value(receipt_v2_id, json!([]))?;
        stale_v2_evidence["data"]["valid_receipts"] = json!([]);
        stale_v2_evidence["data"]["stale_receipts"] = json!([{
            "schema": "forge.receipt/v2",
            "id": receipt_v2_id,
            "intent": "test",
            "validity": {
                "dependency_validity": "stale",
                "applicability": "eligible",
                "outcome": "pass",
                "reasons": [{"code": "dependency-changed", "dependency": "scope"}]
            }
        }]);
        let stale_v2_evidence: Envelope<EvidenceV2Data> =
            serde_json::from_value(stale_v2_evidence)?;
        super::validate_receipt_bindings(
            super::EvidenceReceiptSummaries::V2(&stale_v2_evidence.data),
            [&receipt_facts[0]],
        )?;

        let mut wrong_v2_stale_intent = receipt_facts[0].clone();
        wrong_v2_stale_intent.intent = IntentData::Build;
        assert_eq!(
            super::validate_receipt_bindings(
                super::EvidenceReceiptSummaries::V2(&stale_v2_evidence.data),
                [&wrong_v2_stale_intent],
            ),
            Err(forge_runtime::state::EvidenceStateDecodeError::InvalidReference),
        );
        let mut wrong_v2_stale_outcome = receipt_facts[0].clone();
        wrong_v2_stale_outcome.outcome = OutcomeData::ProductFailure;
        assert_eq!(
            super::validate_receipt_bindings(
                super::EvidenceReceiptSummaries::V2(&stale_v2_evidence.data),
                [&wrong_v2_stale_outcome],
            ),
            Err(forge_runtime::state::EvidenceStateDecodeError::InvalidReference),
        );

        let mut wrong_v2_intent = receipt_facts[0].clone();
        wrong_v2_intent.intent = IntentData::Build;
        assert_eq!(
            validate_evidence_receipt_bindings(
                &loaded_evidence,
                [&wrong_v2_intent, &receipt_facts[1]],
            ),
            Err(forge_runtime::state::EvidenceStateDecodeError::InvalidReference),
            "a v2 valid Receipt intent mismatch must fail even when its outcome matches",
        );
        let mut wrong_v2_outcome = receipt_facts[0].clone();
        wrong_v2_outcome.outcome = OutcomeData::ProductFailure;
        assert_eq!(
            validate_evidence_receipt_bindings(
                &loaded_evidence,
                [&wrong_v2_outcome, &receipt_facts[1]],
            ),
            Err(forge_runtime::state::EvidenceStateDecodeError::InvalidReference),
            "a v2 valid Receipt outcome mismatch must fail even when its intent matches",
        );

        let mut mismatched = evidence;
        mismatched["data"]["valid_receipts"][0]["coverage"] = json!(["compile"]);
        mismatched = sign(mismatched, DocumentKind::Evidence)?;
        let mismatched_name = super::parse_public_id(
            mismatched["data"]["id"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("evidence id is not a string"))?,
            super::EVIDENCE_ID_PREFIX,
        )?;
        let loaded_mismatched = load_evidence(
            EvidenceStateVersion::V2,
            &mismatched_name,
            &bytes(&mismatched)?,
        )?;
        assert_eq!(
            validate_evidence_receipt_bindings(&loaded_mismatched, &receipt_facts,),
            Err(forge_runtime::state::EvidenceStateDecodeError::InvalidReference)
        );
        Ok(())
    }

    #[test]
    fn v1_receipt_bindings_check_each_summary_axis() -> TestResult {
        let valid_receipt = receipt_v1_value()?;
        let valid_loaded = load_v1_receipt_fixture(&valid_receipt)?;
        let valid_id = valid_receipt["data"]["id"]
            .as_str()
            .ok_or_else(|| std::io::Error::other("valid receipt id is not a string"))?;

        let mut stale_receipt = receipt_v1_value()?;
        stale_receipt["data"]["duration_ms"] = json!(13);
        stale_receipt = sign(stale_receipt, DocumentKind::Receipt)?;
        let stale_loaded = load_v1_receipt_fixture(&stale_receipt)?;
        let stale_id = stale_receipt["data"]["id"]
            .as_str()
            .ok_or_else(|| std::io::Error::other("stale receipt id is not a string"))?;

        let evidence = evidence_v1_value(valid_id, stale_id)?;
        let evidence_name = super::parse_public_id(
            evidence["data"]["id"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("evidence id is not a string"))?,
            super::EVIDENCE_ID_PREFIX,
        )?;
        let loaded_evidence =
            load_evidence(EvidenceStateVersion::V1, &evidence_name, &bytes(&evidence)?)?;
        let valid_fact = valid_loaded.binding_fact();
        let stale_fact = stale_loaded.binding_fact();

        validate_evidence_receipt_bindings(&loaded_evidence, [&valid_fact, &stale_fact])?;

        let mut wrong_intent = valid_fact.clone();
        wrong_intent.intent = IntentData::Build;
        assert_eq!(
            validate_evidence_receipt_bindings(&loaded_evidence, [&wrong_intent, &stale_fact]),
            Err(forge_runtime::state::EvidenceStateDecodeError::InvalidReference),
            "a v1 valid Receipt intent mismatch must fail even when its outcome matches",
        );

        let mut wrong_outcome = valid_fact;
        wrong_outcome.outcome = OutcomeData::ProductFailure;
        assert_eq!(
            validate_evidence_receipt_bindings(&loaded_evidence, [&wrong_outcome, &stale_fact]),
            Err(forge_runtime::state::EvidenceStateDecodeError::InvalidReference),
            "a v1 valid Receipt outcome mismatch must fail even when its intent matches",
        );

        Ok(())
    }

    #[test]
    fn prepare_evidence_cannot_emit_a_summary_unbound_from_its_receipt() -> TestResult {
        let receipt = receipt_value(json!([]))?;
        let receipt_id = receipt["data"]["id"]
            .as_str()
            .ok_or_else(|| std::io::Error::other("receipt id is not a string"))?;
        let mut evidence = evidence_value(receipt_id, json!([]))?;
        evidence["data"]["stale_receipts"] = json!([]);
        evidence["data"]["valid_receipts"][0]["intent"] = json!("build");
        evidence["data"]["valid_receipts"][0]["coverage"] = json!(["compile"]);
        let evidence: Envelope<EvidenceV2Data> = serde_json::from_value(evidence)?;
        let receipt = load_v2_receipt_fixture(&receipt)?;
        let receipt_facts = [receipt.binding_fact()];

        assert_eq!(
            prepare_evidence(evidence, &receipt_facts),
            Err(forge_runtime::state::EvidenceStateDecodeError::InvalidReference)
        );
        Ok(())
    }

    #[test]
    fn v2_evidence_rejects_a_public_receipt_id_reused_across_schema_versions() -> TestResult {
        let receipt_id = format!("receipt:blake3:{}", "a".repeat(64));
        let mut evidence = evidence_value(&receipt_id, json!([]))?;
        evidence["data"]["stale_receipts"][0]["id"] = json!(receipt_id);
        let evidence: Envelope<EvidenceV2Data> = serde_json::from_value(evidence)?;

        assert_eq!(
            super::validate_evidence_v2_semantics(&evidence.data),
            Err(forge_runtime::state::EvidenceStateDecodeError::InvalidReference),
        );
        Ok(())
    }

    #[test]
    fn raw_number_identity_is_exact_across_the_rfc_8259_domain() -> TestResult {
        let identity = |number: &str| {
            let raw =
                format!("{{\"data\":{{\"id\":\"receipt:placeholder\"}},\"future\":{number}}}");
            let parsed = super::parse_identity_json(raw.as_bytes(), DocumentKind::Receipt)?;
            super::calculate_parsed_identity(&parsed, DocumentKind::Receipt)
        };
        assert_eq!(identity("1")?, identity("1.0")?);
        assert_eq!(identity("1")?, identity("1e0")?);
        assert_eq!(identity("0")?, identity("-0")?);
        assert_ne!(
            identity("184467440737095516160000000000000000001")?,
            identity("184467440737095516160000000000000000002")?
        );

        let escaped = super::parse_identity_json(
            br#"{"data":{"id":"receipt:placeholder"},"future":"\u0061"}"#,
            DocumentKind::Receipt,
        )?;
        let literal = super::parse_identity_json(
            br#"{"data":{"id":"receipt:placeholder"},"future":"a"}"#,
            DocumentKind::Receipt,
        )?;
        assert_eq!(
            super::calculate_parsed_identity(&escaped, DocumentKind::Receipt)?,
            super::calculate_parsed_identity(&literal, DocumentKind::Receipt)?
        );
        Ok(())
    }

    #[test]
    fn same_major_unknown_decimal_round_trips_without_becoming_proving() -> TestResult {
        let receipt = receipt_value(json!([]))?;
        let old_id = receipt["data"]["id"]
            .as_str()
            .ok_or_else(|| std::io::Error::other("receipt id is not a string"))?;
        let mut raw = serde_json::to_string(&receipt)?;
        raw.pop().filter(|last| *last == '}').ok_or_else(|| {
            std::io::Error::other("serialized receipt did not end with an object delimiter")
        })?;
        raw.push_str(",\"future_decimal\":1.2500e-3}");
        let parsed = super::parse_identity_json(raw.as_bytes(), DocumentKind::Receipt)?;
        let (public_id, object_name) =
            super::calculate_parsed_identity(&parsed, DocumentKind::Receipt)?;
        let raw = raw.replacen(old_id, &public_id, 1).into_bytes();

        let loaded = load_receipt(EvidenceStateVersion::V2, &object_name, &raw)?;
        assert!(!loaded.can_support_current_evidence);
        assert_eq!(
            JsonEvidenceStateCodec.decode_receipt(EvidenceStateVersion::V2, &raw)?,
            ReceiptRetentionMetadata::with_log_reference_closure(
                object_name,
                EvidenceRetentionTime::Current(parse_utc_rfc3339("2026-07-27T00:00:00Z")?),
                ReferenceClosure::RetainAll,
            )
        );
        Ok(())
    }

    #[test]
    fn unrepresentable_number_in_a_known_numeric_field_fails_closed() -> TestResult {
        let receipt = receipt_value(json!([]))?;
        let raw = serde_json::to_string(&receipt)?.replacen(
            "\"duration_ms\":12",
            "\"duration_ms\":18446744073709551616",
            1,
        );
        assert!(raw.contains("\"duration_ms\":18446744073709551616"));

        assert_eq!(
            JsonEvidenceStateCodec.decode_receipt(EvidenceStateVersion::V2, raw.as_bytes()),
            Err(forge_runtime::state::EvidenceStateDecodeError::Malformed)
        );
        Ok(())
    }

    #[test]
    fn same_major_unknown_evidence_number_preserves_bounded_reference_closure() -> TestResult {
        let receipt_id = format!("receipt:blake3:{}", "a".repeat(64));
        let evidence = evidence_value(&receipt_id, json!([]))?;
        let old_id = evidence["data"]["id"]
            .as_str()
            .ok_or_else(|| std::io::Error::other("evidence id is not a string"))?;
        let mut raw = serde_json::to_string(&evidence)?;
        raw.pop().filter(|last| *last == '}').ok_or_else(|| {
            std::io::Error::other("serialized evidence did not end with an object delimiter")
        })?;
        raw.push_str(",\"future_wide_integer\":184467440737095516160000000000000000001}");
        let parsed = super::parse_identity_json(raw.as_bytes(), DocumentKind::Evidence)?;
        let (public_id, object_name) =
            super::calculate_parsed_identity(&parsed, DocumentKind::Evidence)?;
        let raw = raw.replacen(old_id, &public_id, 1).into_bytes();

        load_evidence(EvidenceStateVersion::V2, &object_name, &raw)?;
        assert_eq!(
            JsonEvidenceStateCodec.decode_evidence(EvidenceStateVersion::V2, &raw)?,
            EvidenceRetentionMetadata::with_reference_closures(
                object_name,
                EvidenceRetentionTime::Current(parse_utc_rfc3339("2026-07-27T00:01:00Z")?),
                ReferenceClosure::RetainAll,
                ReferenceClosure::RetainAll,
            )
        );
        Ok(())
    }

    #[test]
    fn receipt_binding_coverage_digest_frames_items_and_order() {
        let left = [String::from("custom:ab"), String::from("custom:c")];
        let different_boundaries = [String::from("custom:a"), String::from("custom:bc")];
        let reversed = [String::from("custom:c"), String::from("custom:ab")];

        assert_ne!(
            super::receipt_binding_coverage_digest(&left),
            super::receipt_binding_coverage_digest(&different_boundaries)
        );
        assert_ne!(
            super::receipt_binding_coverage_digest(&left),
            super::receipt_binding_coverage_digest(&reversed)
        );
    }

    #[test]
    fn incomplete_top_or_observation_log_refs_force_conservative_retention() -> TestResult {
        let mut receipt = receipt_value(json!([]))?;
        receipt["data"]["observations"][0]["log_refs"] = json!([{
            "display": "known explicit unknown observation log",
            "encoding": "unknown"
        }]);
        receipt = sign(receipt, DocumentKind::Receipt)?;
        let object_name = super::parse_public_id(
            receipt["data"]["id"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("receipt id is not a string"))?,
            super::RECEIPT_ID_PREFIX,
        )?;
        let raw = bytes(&receipt)?;
        let loaded = load_receipt(EvidenceStateVersion::V2, &object_name, &raw)?;
        assert!(!loaded.can_support_current_evidence);
        assert_eq!(
            JsonEvidenceStateCodec.decode_receipt(EvidenceStateVersion::V2, &raw)?,
            ReceiptRetentionMetadata::with_log_reference_closure(
                object_name,
                EvidenceRetentionTime::Current(parse_utc_rfc3339("2026-07-27T00:00:00Z")?),
                ReferenceClosure::RetainAll,
            )
        );

        let mut receipt = receipt_value(json!([]))?;
        receipt["data"]["observations"][0]["log_refs"] = json!([{
            "display": "future opaque observation log",
            "encoding": "future-path-v1"
        }]);
        receipt = sign(receipt, DocumentKind::Receipt)?;
        let object_name = super::parse_public_id(
            receipt["data"]["id"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("receipt id is not a string"))?,
            super::RECEIPT_ID_PREFIX,
        )?;
        let raw = bytes(&receipt)?;

        assert_eq!(
            JsonEvidenceStateCodec.decode_receipt(EvidenceStateVersion::V2, &raw)?,
            ReceiptRetentionMetadata::with_log_reference_closure(
                object_name,
                EvidenceRetentionTime::Current(parse_utc_rfc3339("2026-07-27T00:00:00Z")?),
                ReferenceClosure::RetainAll,
            )
        );

        let mut receipt = receipt_value(json!([]))?;
        receipt["data"]["log_refs"] = json!([{
            "display": "unknown top-level log",
            "encoding": "unknown"
        }]);
        receipt = sign(receipt, DocumentKind::Receipt)?;
        let object_name = super::parse_public_id(
            receipt["data"]["id"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("receipt id is not a string"))?,
            super::RECEIPT_ID_PREFIX,
        )?;
        let raw = bytes(&receipt)?;
        let loaded = load_receipt(EvidenceStateVersion::V2, &object_name, &raw)?;
        assert!(!loaded.can_support_current_evidence);
        assert_eq!(
            JsonEvidenceStateCodec.decode_receipt(EvidenceStateVersion::V2, &raw)?,
            ReceiptRetentionMetadata::with_log_reference_closure(
                object_name,
                EvidenceRetentionTime::Current(parse_utc_rfc3339("2026-07-27T00:00:00Z")?),
                ReferenceClosure::RetainAll,
            )
        );
        Ok(())
    }

    #[test]
    fn every_typed_unknown_v2_dependency_is_projectable_but_never_proving() -> TestResult {
        let baseline = load_v2_receipt_fixture(&receipt_value(json!([]))?)?
            .evaluation_projection()?
            .current
            .ok_or_else(|| std::io::Error::other("baseline current projection is missing"))?;
        let current = baseline.recorded.dependencies().clone();
        for (pointer, dependency) in [
            (
                "/data/dependencies/repository",
                forge_core::evidence::EvidenceDependency::Repository,
            ),
            (
                "/data/dependencies/scope_before",
                forge_core::evidence::EvidenceDependency::Scope,
            ),
            (
                "/data/dependencies/scope_after",
                forge_core::evidence::EvidenceDependency::Scope,
            ),
            (
                "/data/dependencies/command",
                forge_core::evidence::EvidenceDependency::Command,
            ),
            (
                "/data/dependencies/toolchain",
                forge_core::evidence::EvidenceDependency::Toolchain,
            ),
            (
                "/data/dependencies/environment",
                forge_core::evidence::EvidenceDependency::Environment,
            ),
            (
                "/data/dependencies/policy",
                forge_core::evidence::EvidenceDependency::Policy,
            ),
            (
                "/data/dependencies/base_task",
                forge_core::evidence::EvidenceDependency::BaseTask,
            ),
            (
                "/data/dependencies/forge_behavior",
                forge_core::evidence::EvidenceDependency::ForgeBehavior,
            ),
        ] {
            let mut receipt = receipt_value(json!([]))?;
            *receipt
                .pointer_mut(pointer)
                .ok_or_else(|| std::io::Error::other("dependency pointer is missing"))? =
                json!({"state": "unknown"});
            receipt = sign(receipt, DocumentKind::Receipt)?;
            let loaded = load_v2_receipt_fixture(&receipt)?;
            assert!(
                !loaded.can_support_current_evidence,
                "unknown dependency remained proving: {pointer}",
            );
            assert!(
                loaded.can_evaluate_current_validity,
                "typed unknown dependency erased the current projection: {pointer}",
            );
            let projected = loaded
                .evaluation_projection()?
                .current
                .ok_or_else(|| std::io::Error::other("current projection is missing"))?;
            let validity =
                forge_core::evidence::evaluate_receipt_validity(&projected.recorded, &current);
            assert_eq!(
                validity.dependency_reasons(),
                &[forge_core::evidence::DependencyReason::Unknown(dependency)],
                "typed unknown dependency produced unrelated reasons: {pointer}",
            );
            assert!(
                validity.applicability_reasons().is_empty(),
                "typed unknown dependency erased known applicability: {pointer}",
            );
        }
        Ok(())
    }

    #[test]
    fn every_unknown_command_semantic_prevents_current_evidence() -> TestResult {
        for (pointer, value) in [
            (
                "/data/observations/0/command/command/mutability",
                json!("unknown"),
            ),
            (
                "/data/observations/0/command/command/network",
                json!("unknown"),
            ),
            (
                "/data/observations/0/command/command/confidence",
                json!("unknown"),
            ),
            (
                "/data/observations/0/command/source_detail",
                json!({"kind": "unknown"}),
            ),
            (
                "/data/observations/0/command/success",
                json!({"kind": "unknown"}),
            ),
            (
                "/data/observations/0/command/command/cwd/encoding",
                json!("unknown"),
            ),
        ] {
            let mut receipt = receipt_value(json!([]))?;
            *receipt
                .pointer_mut(pointer)
                .ok_or_else(|| std::io::Error::other("command pointer is missing"))? = value;
            receipt = sign(receipt, DocumentKind::Receipt)?;
            let loaded = load_v2_receipt_fixture(&receipt)?;
            assert!(
                !loaded.can_support_current_evidence,
                "unknown command semantic remained proving: {pointer}",
            );
            assert!(
                !loaded.can_evaluate_current_validity,
                "unknown command semantic became projectable: {pointer}",
            );
        }
        Ok(())
    }

    #[test]
    fn same_major_unknown_paths_and_stale_reasons_are_retained_non_proving() -> TestResult {
        let unknown_path = json!({
            "display": "future opaque path",
            "encoding": "future-path-v1"
        });
        let mut receipt = receipt_value(json!([]))?;
        receipt["data"]["observations"][0]["log_refs"] = json!([unknown_path.clone()]);
        receipt["data"]["log_refs"] = json!([unknown_path.clone()]);
        receipt = sign(receipt, DocumentKind::Receipt)?;
        let receipt_name = super::parse_public_id(
            receipt["data"]["id"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("receipt id is not a string"))?,
            super::RECEIPT_ID_PREFIX,
        )?;
        let receipt_bytes = bytes(&receipt)?;
        let loaded_receipt = load_receipt(EvidenceStateVersion::V2, &receipt_name, &receipt_bytes)?;
        assert!(!loaded_receipt.can_support_current_evidence);
        assert_eq!(
            JsonEvidenceStateCodec.decode_receipt(EvidenceStateVersion::V2, &receipt_bytes)?,
            ReceiptRetentionMetadata::with_log_reference_closure(
                receipt_name,
                EvidenceRetentionTime::Current(parse_utc_rfc3339("2026-07-27T00:00:00Z")?),
                ReferenceClosure::RetainAll,
            )
        );
        let mut evidence_for_unknown_receipt = evidence_value(
            receipt["data"]["id"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("receipt id is not a string"))?,
            json!([]),
        )?;
        evidence_for_unknown_receipt["data"]["stale_receipts"] = json!([]);
        let evidence_for_unknown_receipt: Envelope<EvidenceV2Data> =
            serde_json::from_value(evidence_for_unknown_receipt)?;
        let receipt_facts = [loaded_receipt.binding_fact()];
        assert_eq!(
            prepare_evidence(evidence_for_unknown_receipt, &receipt_facts),
            Err(forge_runtime::state::EvidenceStateDecodeError::InvalidReference)
        );

        let explicit_unknown_path = json!({
            "display": "unknown path",
            "encoding": "unknown"
        });
        let mut explicit_unknown_receipt = receipt_value(json!([]))?;
        explicit_unknown_receipt["data"]["observations"][0]["log_refs"] =
            json!([explicit_unknown_path.clone()]);
        explicit_unknown_receipt["data"]["log_refs"] = json!([explicit_unknown_path.clone()]);
        explicit_unknown_receipt = sign(explicit_unknown_receipt, DocumentKind::Receipt)?;
        let explicit_unknown_name = super::parse_public_id(
            explicit_unknown_receipt["data"]["id"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("receipt id is not a string"))?,
            super::RECEIPT_ID_PREFIX,
        )?;
        let explicit_unknown_bytes = bytes(&explicit_unknown_receipt)?;
        let explicit_unknown = load_receipt(
            EvidenceStateVersion::V2,
            &explicit_unknown_name,
            &explicit_unknown_bytes,
        )?;
        assert!(!explicit_unknown.can_support_current_evidence);
        assert_eq!(
            JsonEvidenceStateCodec
                .decode_receipt(EvidenceStateVersion::V2, &explicit_unknown_bytes)?,
            ReceiptRetentionMetadata::with_log_reference_closure(
                explicit_unknown_name,
                EvidenceRetentionTime::Current(parse_utc_rfc3339("2026-07-27T00:00:00Z")?),
                ReferenceClosure::RetainAll,
            )
        );

        let valid_id = format!("receipt:blake3:{}", "a".repeat(64));
        let mut explicit_unknown_evidence =
            evidence_value(&valid_id, json!([explicit_unknown_path]))?;
        explicit_unknown_evidence = sign(explicit_unknown_evidence, DocumentKind::Evidence)?;
        let explicit_unknown_evidence_name = super::parse_public_id(
            explicit_unknown_evidence["data"]["id"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("evidence id is not a string"))?,
            super::EVIDENCE_ID_PREFIX,
        )?;
        let typed_explicit_unknown_evidence: Envelope<EvidenceV2Data> =
            serde_json::from_value(explicit_unknown_evidence.clone())?;
        let known_receipts =
            super::evidence_v2_receipt_references(&typed_explicit_unknown_evidence.data)?;
        assert_eq!(
            JsonEvidenceStateCodec.decode_evidence(
                EvidenceStateVersion::V2,
                &bytes(&explicit_unknown_evidence)?,
            )?,
            EvidenceRetentionMetadata::with_reference_closures(
                explicit_unknown_evidence_name,
                EvidenceRetentionTime::Current(parse_utc_rfc3339("2026-07-27T00:01:00Z")?),
                ReferenceClosure::complete(known_receipts),
                ReferenceClosure::RetainAll,
            )
        );

        let mut evidence_with_unknown_path = evidence_value(&valid_id, json!([]))?;
        evidence_with_unknown_path["data"]["log_refs"] = json!([unknown_path]);
        evidence_with_unknown_path = sign(evidence_with_unknown_path, DocumentKind::Evidence)?;
        let evidence_name = super::parse_public_id(
            evidence_with_unknown_path["data"]["id"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("evidence id is not a string"))?,
            super::EVIDENCE_ID_PREFIX,
        )?;
        assert_eq!(
            JsonEvidenceStateCodec.decode_evidence(
                EvidenceStateVersion::V2,
                &bytes(&evidence_with_unknown_path)?,
            )?,
            EvidenceRetentionMetadata::with_reference_closures(
                evidence_name,
                EvidenceRetentionTime::Current(parse_utc_rfc3339("2026-07-27T00:01:00Z")?),
                ReferenceClosure::RetainAll,
                ReferenceClosure::RetainAll,
            )
        );

        let stale_id = format!("receipt:blake3:{}", "b".repeat(64));
        let mut evidence_with_future_reason = evidence_value(&valid_id, json!([]))?;
        evidence_with_future_reason["data"]["valid_receipts"] = json!([]);
        evidence_with_future_reason["data"]["stale_receipts"] = json!([{
            "schema": "forge.receipt/v2",
            "id": stale_id,
            "intent": "test",
            "validity": {
                "dependency_validity": "stale",
                "applicability": "eligible",
                "outcome": "pass",
                "reasons": [{"code": "future-reason"}]
            }
        }]);
        evidence_with_future_reason = sign(evidence_with_future_reason, DocumentKind::Evidence)?;
        let future_reason_name = super::parse_public_id(
            evidence_with_future_reason["data"]["id"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("evidence id is not a string"))?,
            super::EVIDENCE_ID_PREFIX,
        )?;
        let future_reason_bytes = bytes(&evidence_with_future_reason)?;
        let loaded = load_evidence(
            EvidenceStateVersion::V2,
            &future_reason_name,
            &future_reason_bytes,
        )?;
        let no_facts = [];
        validate_evidence_receipt_bindings(&loaded, &no_facts)?;
        assert_eq!(
            JsonEvidenceStateCodec
                .decode_evidence(EvidenceStateVersion::V2, &future_reason_bytes,)?,
            EvidenceRetentionMetadata::with_reference_closures(
                future_reason_name,
                EvidenceRetentionTime::Current(parse_utc_rfc3339("2026-07-27T00:01:00Z")?),
                ReferenceClosure::RetainAll,
                ReferenceClosure::RetainAll,
            )
        );
        Ok(())
    }

    #[test]
    fn same_major_unknown_content_does_not_hide_known_contradictions() -> TestResult {
        let unsafe_path = json!({
            "display": "logs/v1/../secret.log",
            "encoding": "utf8"
        });
        let mut unsafe_receipt = receipt_value(json!([]))?;
        unsafe_receipt["future_field"] = json!(true);
        unsafe_receipt["data"]["observations"][0]["log_refs"] = json!([unsafe_path.clone()]);
        unsafe_receipt["data"]["log_refs"] = json!([unsafe_path]);
        unsafe_receipt = sign(unsafe_receipt, DocumentKind::Receipt)?;
        assert_eq!(
            JsonEvidenceStateCodec
                .decode_receipt(EvidenceStateVersion::V2, &bytes(&unsafe_receipt)?,),
            Err(forge_runtime::state::EvidenceStateDecodeError::InvalidReference)
        );

        let mut duplicate_commands = receipt_value(json!([]))?;
        duplicate_commands["future_field"] = json!(true);
        let duplicate = duplicate_commands["data"]["observations"][0].clone();
        duplicate_commands["data"]["observations"] = json!([duplicate.clone(), duplicate]);
        duplicate_commands = sign(duplicate_commands, DocumentKind::Receipt)?;
        assert_eq!(
            JsonEvidenceStateCodec
                .decode_receipt(EvidenceStateVersion::V2, &bytes(&duplicate_commands)?,),
            Err(forge_runtime::state::EvidenceStateDecodeError::Malformed)
        );

        let valid_id = format!("receipt:blake3:{}", "a".repeat(64));
        let mut duplicate_receipts = evidence_value(&valid_id, json!([]))?;
        duplicate_receipts["future_field"] = json!(true);
        let duplicate = duplicate_receipts["data"]["valid_receipts"][0].clone();
        duplicate_receipts["data"]["valid_receipts"] = json!([duplicate.clone(), duplicate]);
        duplicate_receipts = sign(duplicate_receipts, DocumentKind::Evidence)?;
        assert_eq!(
            JsonEvidenceStateCodec
                .decode_evidence(EvidenceStateVersion::V2, &bytes(&duplicate_receipts)?,),
            Err(forge_runtime::state::EvidenceStateDecodeError::InvalidReference)
        );

        let mut duplicate_hidden_by_future_schema = evidence_value(&valid_id, json!([]))?;
        duplicate_hidden_by_future_schema["data"]["stale_receipts"][0]["schema"] =
            json!("forge.receipt/v3");
        duplicate_hidden_by_future_schema["data"]["stale_receipts"][0]["id"] = json!(valid_id);
        duplicate_hidden_by_future_schema =
            sign(duplicate_hidden_by_future_schema, DocumentKind::Evidence)?;
        assert_eq!(
            JsonEvidenceStateCodec.decode_evidence(
                EvidenceStateVersion::V2,
                &bytes(&duplicate_hidden_by_future_schema)?,
            ),
            Err(forge_runtime::state::EvidenceStateDecodeError::InvalidReference)
        );
        Ok(())
    }

    #[test]
    fn prepared_current_documents_are_pretty_and_self_validating() -> TestResult {
        let receipt: Envelope<ReceiptV2Data> = serde_json::from_value(receipt_value(json!([]))?)?;
        let prepared_receipt = prepare_receipt(receipt)?;
        assert!(prepared_receipt.bytes().ends_with(b"\n"));

        let receipt_id = format!("receipt:blake3:{}", prepared_receipt.object_name().as_str());
        let receipt = load_receipt(
            EvidenceStateVersion::V2,
            prepared_receipt.object_name(),
            prepared_receipt.bytes(),
        )?;
        let receipt_facts = [receipt.binding_fact()];
        let mut evidence = evidence_value(&receipt_id, json!([]))?;
        evidence["data"]["stale_receipts"] = json!([]);
        let evidence: Envelope<EvidenceV2Data> = serde_json::from_value(evidence)?;
        let prepared_evidence = prepare_evidence(evidence, &receipt_facts)?;
        assert!(prepared_evidence.bytes().ends_with(b"\n"));
        Ok(())
    }
}
