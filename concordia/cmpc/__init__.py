"""CMPC (Cross-Mandate Promise Chain) bilateral primitive set.

This module ships the bilateral subset for Concordia v0.7-alpha, including
RevocationRecord. Multilateral primitives, transparency log, and Verascore
scoring-dimension wire-up land in later stages.
"""

from .canonical import (
    canonicalize_atomic_activation_proof,
    canonicalize_chain_session,
    canonicalize_closure_predicate,
    canonicalize_conditional_commitment,
    canonicalize_revocation_record,
    canonicalize_unwind_record,
)
from .chain_session import (
    LEGAL_TRANSITIONS,
    ChainSession,
    ChainSessionState,
    InvalidTransitionError,
    TransitionRecord,
    verify_transcript,
)
from .errors import CMPCError, InvalidPrimitiveError, SchemaValidationError
from .predicate import (
    ClosurePredicate,
    PredicateResult,
    evaluate_predicate,
)
from .signing import (
    sign_atomic_activation_proof,
    sign_conditional_commitment,
    sign_unwind_record,
    verify_atomic_activation_proof,
    verify_conditional_commitment,
    verify_unwind_record,
)
from .revocation import (
    CandidateArtifact,
    CascadeResult,
    InadmissibleArtifact,
    cascade_revocation,
    sign_revocation_record,
    verify_revocation_record,
)
from .types import (
    AtomicActivationProof,
    ConditionalCommitment,
    RevocationRecord,
    RevocationScope,
    UnwindRecord,
)

__all__ = [
    "ChainSession",
    "ChainSessionState",
    "InvalidTransitionError",
    "LEGAL_TRANSITIONS",
    "TransitionRecord",
    "ConditionalCommitment",
    "ClosurePredicate",
    "PredicateResult",
    "AtomicActivationProof",
    "UnwindRecord",
    "RevocationRecord",
    "RevocationScope",
    "CandidateArtifact",
    "CascadeResult",
    "InadmissibleArtifact",
    "canonicalize_chain_session",
    "canonicalize_conditional_commitment",
    "canonicalize_closure_predicate",
    "canonicalize_atomic_activation_proof",
    "canonicalize_unwind_record",
    "canonicalize_revocation_record",
    "sign_conditional_commitment",
    "verify_conditional_commitment",
    "sign_atomic_activation_proof",
    "verify_atomic_activation_proof",
    "sign_unwind_record",
    "verify_unwind_record",
    "sign_revocation_record",
    "verify_revocation_record",
    "cascade_revocation",
    "CMPCError",
    "InvalidPrimitiveError",
    "SchemaValidationError",
    "verify_transcript",
    "evaluate_predicate",
]
