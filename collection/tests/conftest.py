"""Expose the collection fixtures to synthetic child interpreters."""

import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def child_module_path(monkeypatch: pytest.MonkeyPatch) -> None:
    tests = Path(__file__).resolve().parent
    paths = [str(tests.parent / "runtime"), str(tests)]
    if os.environ.get("PYTHONPATH"):
        paths.append(os.environ["PYTHONPATH"])
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join(paths))
