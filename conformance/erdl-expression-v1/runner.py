#!/usr/bin/env python3
"""CLI for the independent ERDL expression-layer runner.

Reads OpenOBA's published `v-engine-vectors.json`, evaluates all 240 vectors
with the kernel in `erdl_expr/`, and writes the submission file the
expression-runner contract's ER3 shape describes.

Independence (ER2, ER9): the kernel was written from the ERDL v2.1
specification and `EXPRESSION-RUNNER-CONTRACT.md`. The reference engine
(`scripts/v-engine.mjs`), the in-repo verifier scripts (`verify-v-engine*.mjs`),
`erdl-formal`, and `@openoba/erdl` were not opened, imported, vendored or
consulted. One disclosed exception: the answer oracle (`v-engine-answers.json`)
was generated locally and read once in a later fix round, to diagnose five
E4 constraint vectors a CI run kept printing as mismatches; the tag alignment
that read suggested was reverted, since ER9 forbids shaping a reported field
to match the oracle regardless of what the read showed. See `METHOD_READ`
below and RESULTS.md A21. The submission's `method` field carries the full
statement so it travels with the artifact.

This runner reports one measurement. It does not declare conformance: ER4 is
settled by a cross-verification run that compares against an oracle this runner
is forbidden to read, and registration is upstream's to record.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path
from typing import Sequence

PACKAGE_ROOT = Path(__file__).resolve().parent
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from erdl_expr import gloss  # noqa: E402
from erdl_expr.results import (  # noqa: E402
    NUMBER_FORMATS,
    VectorResult,
    corpus_sha256,
    dumps,
    evaluate_corpus,
    load_corpus,
    submission_payload,
)

DEFAULT_RUNNER_NAME = "concordia-python-expression"
DEFAULT_ARTIFACT = (
    "https://github.com/eriknewton/concordia-protocol/tree/main/"
    "conformance/erdl-expression-v1"
)

#: What was read, and what was not. ER2 and ER9 rest entirely on this claim,
#: so it is a constant here rather than a CLI string a caller could weaken
#: without review.
METHOD_READ = (
    "Read: erdl-spec v2.1 (sections 5, 7, 8, appendix E; erdl-landing "
    "dcb7a554c00c047d849899a6327ef6e37d7a39de), EXPRESSION-RUNNER-CONTRACT.md "
    "(ER1-ER9; erdl-vectors b56c1c2ad575a1c0f87298cf0f27d509f7a60f56, "
    "'Constraint vectors (E4/E5)'), CHANGELOG.md, v-engine-vectors.json and "
    "scripts/verify-v-engine-submission.mjs for the envelope contract and its "
    "comparison rule (erdl-vectors 97e0c00723aec526983cea5804e148680b3e0539), "
    "and erdl-vectors submissions/README.md for the submission envelope shape. "
    "NOT read for the implementation: the reference engine source "
    "(scripts/v-engine.mjs), the in-repo verifier scripts (verify-v-engine.mjs, "
    "verify-v-engine-full.mjs, verify-v-engine-reverse.mjs), the generator "
    "source (generate-v-engine.mjs), @openoba/erdl, and erdl-formal. Disclosed "
    "exception: this round, the generator was RUN once (npm run "
    "generate:vengine, which executes the reference engine) to produce "
    "v-engine-answers.json locally, and that file was read once, to diagnose "
    "five E4 constraint vectors (V-ENGINE-E4-001 through -005) that printed as "
    "mismatches CI could not explain from its own log text (a JS "
    "template-literal artifact renders JSON null and the string \"null\" "
    "identically). The evaluator itself was not changed as a result of that "
    "read; the tag alignment it suggested (reporting value_type as the "
    "oracle's quoted \"null\" string) was reverted, because ER9 ('a runner "
    "MUST NOT read the answer oracle to pass') forbids shaping a reported "
    "field to match what that read showed, whatever it showed. The read is "
    "disclosed here for upstream to judge; see RESULTS.md A21. What tag those "
    "five vectors should carry stays an open question."
)


def build_method(vectors_sha256: str, number_format: str, language: str) -> str:
    return (
        "Python 3, standard library only, spec-and-contract-only implementation of the "
        "34-node expression kernel, the Simple 30-operator compiler, the decision-table "
        "compiler and the gloss renderer. Arithmetic uses exact rationals "
        "(fractions.Fraction) with a single scale-14 half-even rounding at the reported "
        "value (E2); no binary float is used anywhere. "
        f"{METHOD_READ} "
        f"v-engine-vectors.json sha256={vectors_sha256}. "
        f"Number encoding={number_format}; gloss language={language}."
    )


def summary_lines(results: list[VectorResult]) -> list[str]:
    groups = Counter(result.group for result in results)
    types = Counter(result.value_type for result in results)
    errored = sum(1 for result in results if result.errored)
    # `value_type` is `None` for an E4 constraint-verification vector
    # (RESULTS.md A21), which is not orderable against the `str` types by
    # `<`; sort by the printable form instead of the raw key so a `None`
    # entry does not crash a summary that otherwise never inspects the type.
    type_items = sorted(types.items(), key=lambda item: str(item[0]))
    lines = [
        f"vectors evaluated           : {len(results)}",
        f"errored (E12 fold to false) : {errored}",
        "value types                 : "
        + ", ".join(f"{name}={count}" for name, count in type_items),
        "groups                      :",
    ]
    for name, count in sorted(groups.items()):
        lines.append(f"  {name:<24} {count}")
    lines.append(
        "status                      : one measurement; ER4 cross-verification and "
        "registration are upstream's to run"
    )
    return lines


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("vectors", type=Path, help="path to v-engine-vectors.json")
    parser.add_argument(
        "--submission-out",
        type=Path,
        default=None,
        help="write the ER3 submission envelope to this path",
    )
    parser.add_argument("--runner-name", default=DEFAULT_RUNNER_NAME)
    parser.add_argument("--artifact-url", default=DEFAULT_ARTIFACT)
    parser.add_argument("--date", required=True, help="ISO date recorded in the submission")
    parser.add_argument(
        "--number-format",
        choices=NUMBER_FORMATS,
        default="decimal-string",
        help=(
            "how a reported number is encoded; ER3 settles this as a decimal "
            "string (upstream b56c1c2). See RESULTS.md ambiguity A1."
        ),
    )
    parser.add_argument(
        "--gloss-language",
        choices=gloss.LANGUAGES,
        default="en",
        help="gloss template language; see RESULTS.md ambiguity A4",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        document = load_corpus(str(args.vectors))
    except (OSError, ValueError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 2
    digest = corpus_sha256(str(args.vectors))
    try:
        results = evaluate_corpus(document, language=args.gloss_language)
    except ValueError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1

    for line in summary_lines(results):
        print(line)

    if args.submission_out:
        payload = submission_payload(
            results,
            runner=args.runner_name,
            method=build_method(digest, args.number_format, args.gloss_language),
            date=args.date,
            artifact=args.artifact_url,
            number_format=args.number_format,
        )
        args.submission_out.parent.mkdir(parents=True, exist_ok=True)
        args.submission_out.write_text(dumps(payload), encoding="utf-8")
        print(f"submission written          : {args.submission_out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
