"""Guard: publish.yml's test job must mirror ci.yml's test job run commands.

publish.yml re-runs the CI gates on a release tag so a red tree can never
publish. That mirror is maintained by copy, which drifts: the v0.9.0 tag
failed to publish because ci.yml's test job gained an `npm ci` step (P2-C)
that publish.yml never received. This test makes the drift a red test job
instead of a failed release.

The invariant is directional: every `run:` command in ci.yml's `test` job
must appear in publish.yml's `test` job. publish.yml may carry extra steps.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _test_job_run_commands(workflow_text: str) -> list[str]:
    lines = workflow_text.splitlines()
    commands: list[str] = []
    in_test_job = False
    job_indent = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if re.match(r"^  test:\s*$", line):
            in_test_job = True
            job_indent = indent
            continue
        if in_test_job and stripped and indent <= (job_indent or 0) and not line.startswith("  test"):
            in_test_job = False
        if in_test_job and stripped.startswith("run:"):
            commands.append(stripped[len("run:"):].strip())
    return commands


def test_publish_test_job_carries_every_ci_test_run_command() -> None:
    ci = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    publish = (REPO_ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")

    ci_cmds = _test_job_run_commands(ci)
    publish_cmds = _test_job_run_commands(publish)

    assert ci_cmds, "parser found no run commands in ci.yml test job (parser broke?)"
    missing = [c for c in ci_cmds if c not in publish_cmds]
    assert not missing, (
        "publish.yml test job is missing CI test-job run commands "
        f"(release tags will fail to publish): {missing}"
    )
