"""Test that pyproject.toml declares version 0.5.0."""

from pathlib import Path


class TestPyprojectVersion:
    def test_pyproject_version_is_050(self):
        pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
        content = pyproject.read_text()
        assert 'version = "0.5.0"' in content
