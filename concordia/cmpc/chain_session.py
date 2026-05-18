"""CMPC bilateral chain-session state machine."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Any

from concordia.canonicalization import canonicalize_jcs


class ChainSessionState(str, Enum):
    PROPOSED = "PROPOSED"
    OPEN = "OPEN"
    ACTIVATED = "ACTIVATED"
    DISSOLVED = "DISSOLVED"
    EXPIRED = "EXPIRED"


LEGAL_TRANSITIONS: dict[ChainSessionState, set[ChainSessionState]] = {
    ChainSessionState.PROPOSED: {ChainSessionState.OPEN},
    ChainSessionState.OPEN: {
        ChainSessionState.ACTIVATED,
        ChainSessionState.DISSOLVED,
        ChainSessionState.EXPIRED,
    },
    ChainSessionState.ACTIVATED: set(),
    ChainSessionState.DISSOLVED: set(),
    ChainSessionState.EXPIRED: set(),
}


class InvalidTransitionError(Exception):
    """Raised when a ChainSession state transition is not allowed."""


def _enum_value(value: ChainSessionState | str) -> str:
    return value.value if isinstance(value, ChainSessionState) else value


@dataclass(kw_only=True)
class TransitionRecord:
    from_state: ChainSessionState | str
    to_state: ChainSessionState | str
    transitioned_at: datetime
    evidence: dict[str, Any] | None
    prev_transition_hash: str | None
    transition_hash: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.from_state, str):
            self.from_state = ChainSessionState(self.from_state)
        if isinstance(self.to_state, str):
            self.to_state = ChainSessionState(self.to_state)

    def canonical_bytes_excl_hash(self) -> bytes:
        data = {
            "from_state": _enum_value(self.from_state),
            "to_state": _enum_value(self.to_state),
            "transitioned_at": self.transitioned_at.isoformat(),
            "evidence": self.evidence,
            "prev_transition_hash": self.prev_transition_hash,
        }
        return canonicalize_jcs(data)

    def compute_hash(self) -> str:
        return hashlib.sha256(self.canonical_bytes_excl_hash()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "from_state": _enum_value(self.from_state),
            "to_state": _enum_value(self.to_state),
            "transitioned_at": self.transitioned_at,
            "evidence": self.evidence,
            "prev_transition_hash": self.prev_transition_hash,
            "transition_hash": self.transition_hash,
        }


@dataclass(kw_only=True)
class ChainSession:
    chain_session_id: str
    participants: list[str]
    closure_predicate_ref: str
    state: ChainSessionState | str
    created_at: datetime
    activation_deadline: datetime
    activated_at: datetime | None = None
    dissolved_at: datetime | None = None
    commitments: list[str] = field(default_factory=list)
    unwind_record_id: str | None = None
    activation_proof_id: str | None = None
    transitions: list[TransitionRecord] = field(default_factory=list)

    def __post_init__(self) -> None:
        if isinstance(self.state, str):
            self.state = ChainSessionState(self.state)
        self.transitions = [
            record
            if isinstance(record, TransitionRecord)
            else TransitionRecord(**record)
            for record in self.transitions
        ]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ChainSession":
        return cls(**data)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "chain_session_id": self.chain_session_id,
            "participants": self.participants,
            "closure_predicate_ref": self.closure_predicate_ref,
            "state": _enum_value(self.state),
            "created_at": self.created_at,
            "activation_deadline": self.activation_deadline,
            "activated_at": self.activated_at,
            "dissolved_at": self.dissolved_at,
            "commitments": self.commitments,
            "unwind_record_id": self.unwind_record_id,
            "activation_proof_id": self.activation_proof_id,
        }
        if self.transitions:
            data["transitions"] = [record.to_dict() for record in self.transitions]
        return data

    def transition_to(
        self,
        new_state: ChainSessionState,
        evidence: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> None:
        now = now or datetime.now(timezone.utc)
        current_state = ChainSessionState(self.state)
        if new_state not in LEGAL_TRANSITIONS.get(current_state, set()):
            raise InvalidTransitionError(
                f"Illegal transition: {current_state.value} -> {new_state.value}"
            )

        self._validate_transition_preconditions(new_state, now)
        prev_hash = self.transitions[-1].transition_hash if self.transitions else None
        record = TransitionRecord(
            from_state=self.state,
            to_state=new_state,
            transitioned_at=now,
            evidence=evidence,
            prev_transition_hash=prev_hash,
        )
        record.transition_hash = record.compute_hash()
        self.transitions.append(record)
        self.state = new_state
        if new_state == ChainSessionState.ACTIVATED:
            self.activated_at = now
        elif new_state in (ChainSessionState.DISSOLVED, ChainSessionState.EXPIRED):
            self.dissolved_at = now

    def expire_due_to_timeout(self, now: datetime | None = None) -> None:
        self.transition_to(
            ChainSessionState.EXPIRED,
            evidence={"reason": "activation_timeout"},
            now=now,
        )

    def _validate_transition_preconditions(
        self,
        new_state: ChainSessionState,
        now: datetime,
    ) -> None:
        if self.state == ChainSessionState.PROPOSED and new_state == ChainSessionState.OPEN:
            if len(self.commitments) != len(self.participants):
                raise InvalidTransitionError(
                    "PROPOSED -> OPEN requires "
                    f"len(commitments)={len(self.commitments)} == "
                    f"len(participants)={len(self.participants)}"
                )

        if self.state == ChainSessionState.OPEN and new_state == ChainSessionState.ACTIVATED:
            if self.activation_proof_id is None:
                raise InvalidTransitionError(
                    "OPEN -> ACTIVATED requires activation_proof_id"
                )
            if now >= self.activation_deadline:
                raise InvalidTransitionError(
                    "OPEN -> ACTIVATED requires now < activation_deadline; "
                    f"got now={now.isoformat()}, "
                    f"deadline={self.activation_deadline.isoformat()}"
                )

        if self.state == ChainSessionState.OPEN and new_state == ChainSessionState.DISSOLVED:
            if self.unwind_record_id is None:
                raise InvalidTransitionError(
                    "OPEN -> DISSOLVED requires unwind_record_id"
                )

        if self.state == ChainSessionState.OPEN and new_state == ChainSessionState.EXPIRED:
            if now < self.activation_deadline:
                raise InvalidTransitionError(
                    "OPEN -> EXPIRED requires now >= activation_deadline"
                )
            if self.activation_proof_id is not None:
                raise InvalidTransitionError(
                    "OPEN -> EXPIRED requires no activation_proof_id"
                )


def verify_transcript(chain_session: ChainSession) -> bool:
    prev_hash: str | None = None
    for record in chain_session.transitions:
        if record.prev_transition_hash != prev_hash:
            return False
        if record.transition_hash != record.compute_hash():
            return False
        prev_hash = record.transition_hash
    return True
