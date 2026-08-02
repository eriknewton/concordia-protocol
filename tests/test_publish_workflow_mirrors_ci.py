"""Guard: publish.yml's publish gates must mirror ci.yml's run commands.

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

import pytest

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
            commands.append(stripped[len("run:"):].strip())
    return commands


@pytest.mark.parametrize("job_name", ["test", "onboarding-smoke"])
def test_publish_jobs_carry_every_ci_run_command(job_name: str) -> None:
    ci = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    publish = (REPO_ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")

    ci_cmds = _job_run_commands(ci, job_name)
    publish_cmds = _job_run_commands(publish, job_name)

    assert ci_cmds, f"parser found no run commands in ci.yml {job_name} job (parser broke?)"
    missing = [c for c in ci_cmds if c not in publish_cmds]
    assert not missing, (
        f"publish.yml {job_name} job is missing CI {job_name} job run commands "
        f"(release tags will fail to publish): {missing}"
    )
