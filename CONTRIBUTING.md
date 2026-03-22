# Contributing to Concordia

Thank you for your interest in Concordia. This document covers how to contribute to the protocol specification and the reference implementation.

## Running Tests

```bash
# Install the package with dev dependencies
pip install -e ".[dev]"

# Run the test suite
pytest -v

# Run the demo scripts
python examples/demo_camera_negotiation.py
python examples/demo_quick_negotiation.py
```

## Submitting Code Changes

1. Fork the repository and create a branch from `main`.
2. Write your code with **type hints on all function signatures**.
3. Add or update tests for any new behavior.
4. Run `pytest -v` and confirm all tests pass.
5. Open a pull request against `main`.

### Code Style

- Type hints are required on all public functions and methods.
- Keep dependencies minimal. The SDK depends only on `cryptography` and `jsonschema` — additions need strong justification.
- Follow the existing module structure. Each module has a clear, single responsibility.
- Docstrings should reference the relevant spec section (e.g. "§6.1").

## Protocol Changes (RFCs)

Changes to the Concordia Protocol specification go through an RFC process:

1. Create a file in `rfcs/` following the naming convention `NNNN-short-title.md`.
2. Use the structure of `SPEC.md` as your guide — define the problem, propose the change, describe the message format and state transitions affected.
3. Open a pull request with the RFC. Discussion happens on the PR.
4. Once accepted, the RFC is merged and the spec is updated accordingly.

RFCs are appropriate for: new message types, changes to the state machine, new offer types, new attestation fields, new resolution mechanisms, and changes to the security model.

RFCs are **not** needed for: SDK bug fixes, documentation improvements, new test cases, or new example scripts.

## License

All contributions are licensed under the [Apache License 2.0](LICENSE). By submitting a pull request, you agree that your contribution is licensed under the same terms.
