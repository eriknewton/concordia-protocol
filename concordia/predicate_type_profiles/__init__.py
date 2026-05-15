"""Predicate type-profile registry for v0.6 deterministic semantics."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import Any

from jsonschema import Draft202012Validator


@dataclass(frozen=True)
class PredicateTypeProfile:
    type_id: str
    is_deterministic: bool
    condition_schema: dict[str, Any]


_BUILTIN_MODULES = {
    "urn:concordia:predicate-type:authority_gate:v1": "authority_gate",
    "urn:concordia:predicate-type:approval_gate:v1": "authority_gate",
    "urn:concordia:predicate-type:jcs_edge:v1": "authority_gate",
    "urn:concordia:predicate-type:procurement_eligibility:v1": "procurement_eligibility",
    "urn:concordia:predicate-type:policy_gate:v1": "policy_gate",
    "urn:concordia:predicate-type:non_deterministic_test:v1": "non_deterministic_test",
}
_REGISTRY: dict[str, PredicateTypeProfile] = {}


def register_predicate_type_profile(
    type_id: str,
    *,
    is_deterministic: bool,
    condition_schema: dict[str, Any],
) -> PredicateTypeProfile:
    """Register or replace a predicate type profile."""
    profile = PredicateTypeProfile(type_id, is_deterministic, condition_schema)
    _REGISTRY[type_id] = profile
    return profile


def get_predicate_type_profile(type_id: str) -> PredicateTypeProfile | None:
    """Return a registered profile, loading builtins lazily."""
    if type_id in _REGISTRY:
        return _REGISTRY[type_id]
    module_name = _BUILTIN_MODULES.get(type_id)
    if module_name is None:
        return None
    module = import_module(f"{__name__}.{module_name}")
    return register_predicate_type_profile(
        type_id,
        is_deterministic=bool(module.IS_DETERMINISTIC),
        condition_schema=dict(module.CONDITION_SCHEMA),
    )


def validate_condition_for_profile(type_id: str, condition: Any) -> list[str]:
    """Validate profile registration and deterministic-result semantics."""
    profile = get_predicate_type_profile(type_id)
    if profile is None:
        return [f"predicate type profile must be registered before signing: {type_id}"]
    if not isinstance(condition, dict):
        return ["condition must be an object"]
    if not profile.is_deterministic and "result" in condition:
        return [
            "deterministic-semantics gate violation: condition.result is only "
            "allowed for deterministic predicate type profiles"
        ]
    if profile.is_deterministic and "result" in condition:
        validator = Draft202012Validator(profile.condition_schema)
        return [error.message for error in validator.iter_errors(condition)]
    return []


__all__ = [
    "PredicateTypeProfile",
    "register_predicate_type_profile",
    "get_predicate_type_profile",
    "validate_condition_for_profile",
]
