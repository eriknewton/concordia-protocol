"""Sign and verify CMPC bilateral primitives."""

from __future__ import annotations

import base64
from dataclasses import replace
from typing import Callable, TypeVar

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from concordia.signing import KeyPair

from .canonical import (
    canonicalize_atomic_activation_proof,
    canonicalize_conditional_commitment,
    canonicalize_unwind_record,
)
from .schemas import (
    validate_atomic_activation_proof,
    validate_conditional_commitment,
    validate_unwind_record,
)
from .types import AtomicActivationProof, ConditionalCommitment, UnwindRecord

T = TypeVar("T", ConditionalCommitment, AtomicActivationProof, UnwindRecord)


def _sign(
    primitive: T,
    key_pair: KeyPair,
    canonicalize: Callable[[T], bytes],
    validate: Callable[[dict[str, object]], None],
) -> T:
    unsigned = replace(primitive, signature="", algorithm="EdDSA")
    signature = base64.urlsafe_b64encode(key_pair.private_key.sign(canonicalize(unsigned))).decode()
    signed = replace(unsigned, signature=signature)
    validate(signed.to_dict())
    return signed


def _verify(
    primitive: T,
    public_key: Ed25519PublicKey,
    canonicalize: Callable[[T], bytes],
    validate: Callable[[dict[str, object]], None],
) -> bool:
    try:
        validate(primitive.to_dict())
        raw_signature = base64.urlsafe_b64decode(primitive.signature.encode())
        public_key.verify(raw_signature, canonicalize(primitive))
        return True
    except Exception:
        return False


def sign_conditional_commitment(
    commitment: ConditionalCommitment,
    key_pair: KeyPair,
) -> ConditionalCommitment:
    return _sign(commitment, key_pair, canonicalize_conditional_commitment, validate_conditional_commitment)


def verify_conditional_commitment(
    commitment: ConditionalCommitment,
    public_key: Ed25519PublicKey,
) -> bool:
    return _verify(commitment, public_key, canonicalize_conditional_commitment, validate_conditional_commitment)


def sign_atomic_activation_proof(
    proof: AtomicActivationProof,
    key_pair: KeyPair,
) -> AtomicActivationProof:
    return _sign(proof, key_pair, canonicalize_atomic_activation_proof, validate_atomic_activation_proof)


def verify_atomic_activation_proof(
    proof: AtomicActivationProof,
    public_key: Ed25519PublicKey,
) -> bool:
    return _verify(proof, public_key, canonicalize_atomic_activation_proof, validate_atomic_activation_proof)


def sign_unwind_record(record: UnwindRecord, key_pair: KeyPair) -> UnwindRecord:
    return _sign(record, key_pair, canonicalize_unwind_record, validate_unwind_record)


def verify_unwind_record(record: UnwindRecord, public_key: Ed25519PublicKey) -> bool:
    return _verify(record, public_key, canonicalize_unwind_record, validate_unwind_record)
