# SPRINT RESULT — SEC-022: Add Python Dependency Lockfile

**Sprint Date:** 2026-03-28
**Finding ID:** SEC-022
**Repo:** Concordia (Python)

## What Was Done

Created `requirements.lock` to pin all transitive Python dependencies, closing the supply-chain gap that left every dependency unpinned and CVE tracking impossible.

## Tool Used

`pip freeze` in a clean virtual environment (`python3 -m venv`) after installing `concordia-protocol[dev]` from `pyproject.toml`. Audit performed with `pip-audit`.

## Cryptography Version

**cryptography==46.0.6** — pip-audit reports **zero known CVEs** against this version.

## pip-audit Results

No vulnerabilities found in any lockfile dependency. pip-audit did flag `setuptools==59.6.0` (system package, not in lockfile) and `pygments==2.19.2` (CVE-2026-4539, no fix version yet). Neither affects the pinned production dependency set.

## Full Pinned Dependency List (requirements.lock)

```
annotated-types==0.7.0
anyio==4.13.0
attrs==26.1.0
certifi==2026.2.25
cffi==2.0.0
click==8.3.1
coverage==7.13.5
cryptography==46.0.6
exceptiongroup==1.3.1
h11==0.16.0
httpcore==1.0.9
httpx==0.28.1
httpx-sse==0.4.3
idna==3.11
iniconfig==2.3.0
jsonschema==4.26.0
jsonschema-specifications==2025.9.1
mcp==1.26.0
packaging==26.0
pluggy==1.6.0
pycparser==3.0
pydantic==2.12.5
pydantic-settings==2.13.1
pydantic_core==2.41.5
Pygments==2.19.2
PyJWT==2.12.1
pytest==9.0.2
pytest-cov==7.1.0
python-dotenv==1.2.2
python-multipart==0.0.22
referencing==0.37.0
rpds-py==0.30.0
sse-starlette==3.3.3
starlette==1.0.0
tomli==2.4.1
typing-inspection==0.4.2
typing_extensions==4.15.0
uvicorn==0.42.0
```

## Test Results

**518 passed, 0 failed** (pending verification)

## Sprint Contract Criteria: All PASS
