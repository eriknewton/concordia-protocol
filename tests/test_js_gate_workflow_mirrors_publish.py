"""Guard: js-sdk-gate.yml must include every JS SDK publish and CI gate.

The always-running JS SDK gate is the required-status-check surface. The
path-filtered js-sdk-ci.yml matrix and manual js-sdk-publish.yml workflow may
carry extra release or matrix details, but every npm/node quality gate they run
before publish must also appear in js-sdk-gate.yml.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _job_run_commands(workflow_text: str, job_name: str) -> list[str]:
    lines = workflow_text.splitlines()
    commands: list[str] = []
    in_target_job = False
    job_indent = None
    job_pattern = re.compile(rf"^  {re.escape(job_name)}:\s*$")
    for line in lines:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if job_pattern.match(line):
            in_target_job = True
            job_indent = indent
            continue
        if (
            in_target_job
            and stripped
            and indent <= (job_indent or 0)
            and not job_pattern.match(line)
        ):
            in_target_job = False
        if in_target_job and stripped.startswith("run:"):
            commands.append(stripped[len("run:") :].strip())
    return commands


def _commands_before_npm_publish(commands: list[str]) -> list[str]:
    for index, command in enumerate(commands):
        if command.startswith("npm publish"):
            return commands[:index]
    raise AssertionError("parser found no npm publish command")


def _npm_node_gate_commands(commands: list[str]) -> list[str]:
    return [command for command in commands if command.startswith(("npm ", "node "))]


def test_js_sdk_gate_carries_every_publish_gate_before_npm_publish() -> None:
    publish = (
        REPO_ROOT / ".github" / "workflows" / "js-sdk-publish.yml"
    ).read_text(encoding="utf-8")
    gate = (REPO_ROOT / ".github" / "workflows" / "js-sdk-gate.yml").read_text(
        encoding="utf-8"
    )

    publish_cmds = _job_run_commands(publish, "publish")
    gate_cmds = _job_run_commands(gate, "js-sdk-gate")
    publish_gate_cmds = _npm_node_gate_commands(
        _commands_before_npm_publish(publish_cmds)
    )

    assert publish_gate_cmds, "parser found no pre-publish npm/node gates"
    missing = [command for command in publish_gate_cmds if command not in gate_cmds]
    assert not missing, (
        "js-sdk-gate.yml is missing js-sdk-publish.yml pre-publish gate commands "
        f"(manual npm publishes can enforce checks merges never ran): {missing}"
    )


def test_js_sdk_gate_carries_every_ci_gate() -> None:
    ci = (REPO_ROOT / ".github" / "workflows" / "js-sdk-ci.yml").read_text(
        encoding="utf-8"
    )
    gate = (REPO_ROOT / ".github" / "workflows" / "js-sdk-gate.yml").read_text(
        encoding="utf-8"
    )

    ci_gate_cmds = _job_run_commands(ci, "test")
    gate_cmds = _job_run_commands(gate, "js-sdk-gate")

    assert ci_gate_cmds, "parser found no js-sdk-ci.yml npm/node gates"
    missing = [command for command in ci_gate_cmds if command not in gate_cmds]
    assert not missing, (
        "js-sdk-gate.yml is missing js-sdk-ci.yml gate commands "
        f"(the merge-blocking JS gate drifted from the matrix CI): {missing}"
    )
