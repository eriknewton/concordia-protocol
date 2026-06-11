## Summary

- Fix source typing errors surfaced when a tiny external consumer imports Concordia under `mypy --strict`.
- Keep changes limited to annotations, casts at `Any` boundaries, and type narrowing for existing signing branches.
- Preserve runtime behavior and canonical signing bytes.

## Verification

- `./.venv/bin/pytest -q tests/test_packaging_typed.py` -> `2 passed`
- `./.venv/bin/pytest -q` -> `1401 passed`

Note: the worker prompt expected a count `>= 1404`, but this prepared worktree currently reports `1401 passed` for the full suite.
