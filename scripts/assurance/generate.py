#!/usr/bin/env python3
"""Validate Concordia's assurance registry and generate its public projections."""

from __future__ import annotations

import argparse
import difflib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATH = REPO_ROOT / "docs" / "assurance.json"
OUTPUT_PATHS = {
    REPO_ROOT / "ASSURANCE_MATRIX.md": "matrix",
    REPO_ROOT / "docs" / "ASSURANCE_ROADMAP.md": "roadmap",
    REPO_ROOT / "docs" / "CLAIM_VOCABULARY.md": "vocabulary",
}
EXPECTED_IDS = [
    "agreement_integrity",
    "agreement_authority",
    "agreement_voluntariness",
    "agreement_justice",
    "payload_confidentiality",
    "metadata_privacy",
]
STATUS_FIELDS = [
    "design",
    "implementation",
    "test",
    "drill",
    "external_reproduction",
    "public_claim",
]
# Reviewed current-status floor for every public assurance cell. This is an
# exact pin rather than an ordering heuristic because some vocabularies contain
# non-monotonic states (for example, public_claim.overclaimed). Any status
# change therefore requires both new evidence and a reviewed validator edit.
CURRENT_STATUS_FLOORS = {
    "agreement_integrity": {
        "design": "specified",
        "implementation": "implemented",
        "test": "verified",
        "drill": "not_verified",
        "external_reproduction": "partial",
        "public_claim": "bounded",
    },
    "agreement_authority": {
        "design": "specified",
        "implementation": "partial",
        "test": "verified",
        "drill": "not_verified",
        "external_reproduction": "none",
        "public_claim": "bounded",
    },
    "agreement_voluntariness": {
        "design": "partial",
        "implementation": "not_implemented",
        "test": "not_verified",
        "drill": "not_verified",
        "external_reproduction": "none",
        "public_claim": "bounded",
    },
    "agreement_justice": {
        "design": "partial",
        "implementation": "not_implemented",
        "test": "not_verified",
        "drill": "not_verified",
        "external_reproduction": "none",
        "public_claim": "bounded",
    },
    "payload_confidentiality": {
        "design": "partial",
        "implementation": "not_implemented",
        "test": "not_verified",
        "drill": "not_verified",
        "external_reproduction": "none",
        "public_claim": "bounded",
    },
    "metadata_privacy": {
        "design": "partial",
        "implementation": "not_implemented",
        "test": "not_verified",
        "drill": "not_verified",
        "external_reproduction": "none",
        "public_claim": "bounded",
    },
}
DIMENSION_FIELDS = {
    "id",
    "name",
    "definition",
    "bounded_claim",
    "not_claimed",
    "statuses",
    "evidence",
    "limitations",
    "next_proof",
    "dependencies",
}
EVIDENCE_FIELDS = {"kind", "path", "anchor", "summary"}
EVIDENCE_KINDS = {"spec", "implementation", "test", "conformance", "external_reproduction"}
TOP_LEVEL_FIELDS = {
    "schema_version",
    "title",
    "scope",
    "status_vocabulary",
    "dimensions",
}


class AssuranceError(ValueError):
    """The assurance source is malformed or overstates its evidence."""


def _nonempty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AssuranceError(f"{field} must be a non-empty string")
    return value


def _string_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise AssuranceError(f"{field} must be a non-empty list")
    result = [_nonempty_string(item, f"{field}[]") for item in value]
    if len(result) != len(set(result)):
        raise AssuranceError(f"{field} contains duplicate values")
    return result


def _validate_evidence(item: Any, dimension_id: str, index: int) -> None:
    field = f"dimensions[{dimension_id}].evidence[{index}]"
    if not isinstance(item, dict) or set(item) != EVIDENCE_FIELDS:
        raise AssuranceError(f"{field} must have exactly {sorted(EVIDENCE_FIELDS)}")
    for key in EVIDENCE_FIELDS:
        _nonempty_string(item[key], f"{field}.{key}")
    if item["kind"] not in EVIDENCE_KINDS:
        raise AssuranceError(f"{field}.kind must be one of {sorted(EVIDENCE_KINDS)}")
    relative = Path(item["path"])
    if relative.is_absolute() or ".." in relative.parts:
        raise AssuranceError(f"{field}.path must stay inside the repository")
    if not (REPO_ROOT / relative).exists():
        raise AssuranceError(f"{field}.path does not exist: {item['path']}")
    if item["anchor"] != "module":
        source = (REPO_ROOT / relative).read_text(encoding="utf-8")
        if item["anchor"].casefold() not in source.casefold():
            raise AssuranceError(
                f"{field}.anchor does not exist in {item['path']}: {item['anchor']}"
            )


def validate(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise AssuranceError("source must be a JSON object")
    if set(data) != TOP_LEVEL_FIELDS:
        raise AssuranceError(f"source must have exactly {sorted(TOP_LEVEL_FIELDS)}")
    if data.get("schema_version") != 1:
        raise AssuranceError("schema_version must be 1")
    _nonempty_string(data.get("title"), "title")
    _nonempty_string(data.get("scope"), "scope")

    vocabulary = data.get("status_vocabulary")
    if not isinstance(vocabulary, dict) or list(vocabulary) != STATUS_FIELDS:
        raise AssuranceError(
            f"status_vocabulary keys must be exactly {STATUS_FIELDS} in that order"
        )
    for field in STATUS_FIELDS:
        statuses = vocabulary[field]
        if not isinstance(statuses, dict) or not statuses:
            raise AssuranceError(f"status_vocabulary.{field} must be a non-empty object")
        for status, meaning in statuses.items():
            _nonempty_string(status, f"status_vocabulary.{field} status")
            _nonempty_string(meaning, f"status_vocabulary.{field}.{status}")

    dimensions = data.get("dimensions")
    if not isinstance(dimensions, list):
        raise AssuranceError("dimensions must be a list")
    ids = [item.get("id") if isinstance(item, dict) else None for item in dimensions]
    if ids != EXPECTED_IDS:
        raise AssuranceError(f"dimension ids must be exactly {EXPECTED_IDS} in that order")

    for item in dimensions:
        dimension_id = item["id"]
        if set(item) != DIMENSION_FIELDS:
            raise AssuranceError(
                f"dimensions[{dimension_id}] must have exactly {sorted(DIMENSION_FIELDS)}"
            )
        for key in ["name", "definition", "bounded_claim", "not_claimed", "next_proof"]:
            _nonempty_string(item[key], f"dimensions[{dimension_id}].{key}")
        statuses = item["statuses"]
        if not isinstance(statuses, dict) or list(statuses) != STATUS_FIELDS:
            raise AssuranceError(
                f"dimensions[{dimension_id}].statuses keys must be exactly {STATUS_FIELDS}"
            )
        for field in STATUS_FIELDS:
            if statuses[field] not in vocabulary[field]:
                raise AssuranceError(
                    f"dimensions[{dimension_id}].statuses.{field} has unknown value "
                    f"{statuses[field]!r}"
                )
            reviewed_floor = CURRENT_STATUS_FLOORS[dimension_id][field]
            if statuses[field] != reviewed_floor:
                raise AssuranceError(
                    f"dimensions[{dimension_id}].statuses.{field} differs from reviewed "
                    f"current-status floor {reviewed_floor!r}; a status change requires "
                    "new evidence and a paired validator update"
                )
        if not isinstance(item["evidence"], list) or not item["evidence"]:
            raise AssuranceError(f"dimensions[{dimension_id}].evidence must be non-empty")
        for index, evidence in enumerate(item["evidence"]):
            _validate_evidence(evidence, dimension_id, index)
        _string_list(item["limitations"], f"dimensions[{dimension_id}].limitations")
        _string_list(item["dependencies"], f"dimensions[{dimension_id}].dependencies")

    integrity = dimensions[0]
    integrity_text = " ".join(
        [integrity["bounded_claim"], *integrity["limitations"]]
    ).lower()
    for required in ["0.3.0", "1,541", "first-party", "not an independent implementation"]:
        if required.lower() not in integrity_text:
            raise AssuranceError(f"agreement_integrity must preserve bound: {required}")
    integrity_exclusions = integrity["not_claimed"].lower()
    for required in ["real-world identity", "mandate", "voluntariness", "justice"]:
        if required not in integrity_exclusions:
            raise AssuranceError(f"agreement_integrity must not promote signatures to {required}")
    if not any(
        "does not objectively prove" in limitation.lower()
        for limitation in integrity["limitations"]
    ):
        raise AssuranceError("FulfillmentAttestation must remain a signer assertion, not objective proof")
    authority = next(d for d in dimensions if d["id"] == "agreement_authority")
    if authority["statuses"]["implementation"] != "partial":
        raise AssuranceError("agreement_authority implementation must remain partial")
    if "supplied" not in authority["bounded_claim"].lower():
        raise AssuranceError("agreement_authority must remain relative to supplied verification inputs")
    confidentiality = next(d for d in dimensions if d["id"] == "payload_confidentiality")
    if confidentiality["statuses"]["implementation"] != "not_implemented":
        raise AssuranceError("payload_confidentiality implementation must remain not_implemented")
    metadata = next(d for d in dimensions if d["id"] == "metadata_privacy")
    if metadata["statuses"]["implementation"] != "not_implemented":
        raise AssuranceError("metadata_privacy implementation must remain not_implemented")
    if metadata["statuses"]["test"] != "not_verified":
        raise AssuranceError("field-minimization tests do not verify metadata_privacy")
    if "not transport metadata privacy" not in metadata["bounded_claim"].lower():
        raise AssuranceError("metadata_privacy must distinguish field minimization from transport metadata privacy")
    external_paths = {
        evidence["path"]
        for dimension in dimensions
        for evidence in dimension["evidence"]
        if evidence["kind"] == "external_reproduction"
    }
    if external_paths != {"docs/interop/a2a-1920-fulfillment-sample/README.md"}:
        raise AssuranceError("the registry must record exactly the one current external reproduction source")
    return data


def load_source() -> dict[str, Any]:
    try:
        raw = json.loads(SOURCE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AssuranceError(f"cannot load {SOURCE_PATH.relative_to(REPO_ROOT)}: {exc}") from exc
    return validate(raw)


def _header(title: str) -> list[str]:
    return [
        f"# {title}",
        "",
        "GENERATED FILE. Source: `docs/assurance.json`.",
        "",
        "Regenerate with `python3 scripts/assurance/generate.py`. Check committed output with "
        "`python3 scripts/assurance/generate.py --check`.",
        "",
    ]


def _label(value: str) -> str:
    return value.replace("_", " ")


def _link_evidence(evidence: dict[str, str]) -> str:
    return f"[`{evidence['path']}`]({evidence['path']}) ({evidence['anchor']}): {evidence['summary']}"


def render_matrix(data: dict[str, Any]) -> str:
    lines = _header("Concordia Assurance Matrix")
    lines.extend(
        [
            data["scope"],
            "",
            "The status cells are deliberately separate. Implementation is not a test, a test is not an external reproduction, and a signature is not authority, voluntariness, or justice.",
            "",
            "## Summary",
            "",
            "| Dimension | Design | Implementation | Test | Drill | External reproduction | Public claim |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for dimension in data["dimensions"]:
        status = dimension["statuses"]
        lines.append(
            f"| [{dimension['name']}](#{dimension['id'].replace('_', '-')}) | "
            f"{_label(status['design'])} | {_label(status['implementation'])} | "
            f"{_label(status['test'])} | {_label(status['drill'])} | "
            f"{_label(status['external_reproduction'])} | {_label(status['public_claim'])} |"
        )

    for dimension in data["dimensions"]:
        lines.extend(
            [
                "",
                f"## {dimension['name']}",
                "",
                dimension["definition"],
                "",
                "**Bounded claim:** " + dimension["bounded_claim"],
                "",
                "**This does not claim:** " + dimension["not_claimed"],
                "",
                "### Evidence",
                "",
            ]
        )
        lines.extend(f"- {_link_evidence(evidence)}" for evidence in dimension["evidence"])
        lines.extend(["", "### Limitations", ""])
        lines.extend(f"- {limitation}" for limitation in dimension["limitations"])
        lines.extend(["", "**Next proof:** " + dimension["next_proof"]])
    return "\n".join(lines).rstrip() + "\n"


def render_roadmap(data: dict[str, Any]) -> str:
    lines = _header("Concordia Assurance Roadmap")
    lines.extend(
        [
            "This roadmap tracks the next proof needed for each stable assurance dimension. It is a proof backlog, not a promise that every item is implemented.",
            "",
            "| Dimension | Current bound | Missing proof | Dependencies |",
            "| --- | --- | --- | --- |",
        ]
    )
    for dimension in data["dimensions"]:
        dependencies = "<br>".join(f"`{item}`" for item in dimension["dependencies"])
        lines.append(
            f"| [{dimension['name']}](../ASSURANCE_MATRIX.md#{dimension['id'].replace('_', '-')}) | "
            f"{dimension['bounded_claim']} | {dimension['next_proof']} | {dependencies} |"
        )
    lines.extend(
        [
            "",
            "## Priority order",
            "",
            "1. Obtain a third-party receipt-set-binding run. This closes the largest gap between first-party cross-runtime parity and independent implementation.",
            "2. Pin a provider-neutral authority profile with issuer resolution and revocation inputs.",
            "3. Write distinct voluntariness and justice threat models. Neither should be collapsed into signature validity.",
            "4. Complete an end-to-end payload-encryption design before behavior changes.",
            "5. Inventory observer-visible metadata and define measurable leakage bounds separately from record-content minimization.",
            "",
            "A roadmap item changes status only when its evidence is added to `docs/assurance.json` and the generated projections pass their drift check.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_vocabulary(data: dict[str, Any]) -> str:
    lines = _header("Concordia Claim Vocabulary")
    lines.extend(
        [
            "Use these terms as separate claim atoms. Passing one dimension never promotes another.",
            "",
            "| Term | Means | Does not mean |",
            "| --- | --- | --- |",
        ]
    )
    for dimension in data["dimensions"]:
        lines.append(
            f"| **{dimension['name']}** (`{dimension['id']}`) | "
            f"{dimension['definition']} | {dimension['not_claimed']} |"
        )
    lines.extend(
        [
            "",
            "## Required distinctions",
            "",
            "- **Signature validity vs. identity:** a signature proves that a resolved key signed bytes. It does not prove who controls the key in the real world.",
            "- **Identity vs. authority:** knowing or resolving a signer does not prove that signer held a valid mandate for this action.",
            "- **Authority vs. voluntariness:** an authorized signer may still act under duress, manipulation, or incapacity.",
            "- **Voluntariness vs. justice:** freely signed terms can still be exploitative or harmful to affected non-signers.",
            "- **Integrity vs. objective fulfillment:** a FulfillmentAttestation binds a signer's assertion. It does not prove an external-world event without separate evidence.",
            "- **First-party parity vs. independent implementation:** the Python and Node.js runners agree on 1,541 vectors with zero divergence, but both are first-party authored.",
            "- **Record minimization vs. payload confidentiality:** excluding raw terms from an attestation does not encrypt negotiation messages.",
            "- **Payload confidentiality vs. metadata privacy:** encrypted content would not by itself hide counterparties, timing, routing, or volume.",
            "",
            "## Status language",
            "",
        ]
    )
    for field, values in data["status_vocabulary"].items():
        lines.extend([f"### {_label(field).title()}", ""])
        lines.extend(f"- `{value}`: {meaning}" for value, meaning in values.items())
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_all(data: dict[str, Any]) -> dict[Path, str]:
    renderers = {
        "matrix": render_matrix,
        "roadmap": render_roadmap,
        "vocabulary": render_vocabulary,
    }
    return {path: renderers[kind](data) for path, kind in OUTPUT_PATHS.items()}


def check_outputs(outputs: dict[Path, str]) -> int:
    failed = False
    for path, expected in outputs.items():
        try:
            actual = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            actual = ""
        relative = path.relative_to(REPO_ROOT).as_posix()
        if actual == expected:
            print(f"[OK] {relative}")
            continue
        failed = True
        print(f"[FAIL] {relative} drifted from docs/assurance.json", file=sys.stderr)
        for line in difflib.unified_diff(
            actual.splitlines(keepends=True),
            expected.splitlines(keepends=True),
            fromfile=relative,
            tofile=f"generated {relative}",
        ):
            print(line, end="", file=sys.stderr)
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        data = load_source()
        outputs = render_all(data)
    except AssuranceError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    if args.check:
        return check_outputs(outputs)
    for path, output in outputs.items():
        path.write_text(output, encoding="utf-8")
        print(f"Wrote {path.relative_to(REPO_ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
