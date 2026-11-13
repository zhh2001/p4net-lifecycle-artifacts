"""Publish a complete file without replacing an existing result."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any


def publish(path: Path, value: dict[str, Any]) -> None:
    payload = json.dumps(value, sort_keys=True, allow_nan=False).encode() + b"\n"
    temporary = path.parent / ("." + path.name + "-" + uuid.uuid4().hex)
    linked = False
    identity = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
            identity = os.fstat(stream.fileno())
        os.link(temporary, path)
        linked = True
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except BaseException:
        if linked and identity is not None:
            current = path.lstat()
            if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                path.unlink()
        raise
    finally:
        temporary.unlink(missing_ok=True)


def pointer(path: Path) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("a published regular artifact is required")
    return {"path": str(path.resolve()), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
