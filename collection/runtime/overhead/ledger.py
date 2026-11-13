"""Append immutable, hash-linked campaign events under one process lock."""

from __future__ import annotations

import fcntl
import json
import os
import re
from pathlib import Path
from typing import Any, TextIO

from overhead.publication import pointer, publish
from overhead.wire import pairs


def read(path: Path) -> dict[str, Any]:
    pointer(path)
    value = json.loads(path.read_text(), object_pairs_hook=pairs, parse_constant=invalid_constant)
    if not isinstance(value, dict):
        raise ValueError("journal artifact must be an object")
    return value


def invalid_constant(value: str) -> Any:
    raise ValueError("nonfinite journal value: " + value)


def pinned(pin: dict[str, Any]) -> dict[str, Any]:
    if set(pin) != {"path", "sha256"} or not Path(pin["path"]).is_absolute():
        raise ValueError("journal pin fields differ")
    path = Path(pin["path"])
    if pointer(path) != pin:
        raise ValueError("journal artifact changed")
    result = read(path)
    if pointer(path) != pin:
        raise ValueError("journal artifact changed while reading")
    return result


class Ledger:
    def __init__(self, root: Path, binding: dict[str, str]):
        self.root, self.binding = root.absolute(), dict(binding)
        self.lock: TextIO | None = None
        self.events: list[tuple[dict[str, str], dict[str, Any]]] = []

    def __enter__(self) -> Ledger:
        if self.lock is not None or self.root.is_symlink():
            raise RuntimeError("journal requires an inactive real directory")
        pinned(self.binding)
        self.root.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(
            self.root / ".campaign.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
        )
        self.lock = os.fdopen(descriptor, "a+")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            path = self.root / "campaign.json"
            expected = {
                "schema_version": 1,
                "record_type": "diagnostic-overhead-campaign",
                "binding": self.binding,
            }
            if path.exists() or path.is_symlink():
                if read(path) != expected:
                    raise ValueError("journal belongs to another input binding")
            else:
                extra = [
                    p
                    for p in self.root.iterdir()
                    if p.name != ".campaign.lock" and not self.fragment(p, "campaign.json")
                ]
                if extra:
                    raise ValueError("unbound journal contains existing artifacts")
                publish(path, expected)
            for name in ("events", "attempts", "readiness"):
                directory = self.root / name
                if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
                    raise ValueError("journal subdirectories must be real directories")
                directory.mkdir(exist_ok=True)
            self.reload()
        except BaseException:
            self.__exit__()
            raise
        return self

    def __exit__(self, *args: Any) -> None:
        if self.lock is not None:
            self.lock.close()
            self.lock = None

    @staticmethod
    def fragment(path: Path, filename: str = r"[0-9]{6}\.json") -> bool:
        return (
            not path.is_symlink()
            and path.is_file()
            and re.fullmatch(r"\." + filename + r"-[0-9a-f]{32}", path.name) is not None
        )

    def active(self) -> None:
        if self.lock is None or self.lock.closed:
            raise RuntimeError("journal mutation requires its process lock")

    def reload(self, *, read_only: bool = False) -> None:
        if not read_only:
            self.active()
        paths = []
        for path in (self.root / "events").iterdir():
            if self.fragment(path):
                continue
            if (
                path.is_symlink()
                or not path.is_file()
                or re.fullmatch(r"[0-9]{6}\.json", path.name) is None
            ):
                raise ValueError("unknown ledger artifact")
            paths.append(path)
        self.events = []
        previous = None
        for number, path in enumerate(sorted(paths), 1):
            value = read(path)
            if (
                path.name != f"{number:06d}.json"
                or set(value)
                != {
                    "schema_version",
                    "record_type",
                    "binding",
                    "number",
                    "previous",
                    "kind",
                    "payload",
                }
                or type(value["schema_version"]) is not int
                or value["schema_version"] != 1
                or value["record_type"] != "diagnostic-overhead-event"
                or value["binding"] != self.binding
                or type(value["number"]) is not int
                or value["number"] != number
                or value["previous"] != previous
                or not isinstance(value["payload"], dict)
            ):
                raise ValueError("journal event chain differs")
            previous = pointer(path)
            self.events.append((previous, value))

    def append(self, kind: str, payload: dict[str, Any]) -> dict[str, str]:
        self.active()
        number = len(self.events) + 1
        value = {
            "schema_version": 1,
            "record_type": "diagnostic-overhead-event",
            "binding": self.binding,
            "number": number,
            "previous": None if not self.events else self.events[-1][0],
            "kind": kind,
            "payload": payload,
        }
        path = self.root / "events" / f"{number:06d}.json"
        publish(path, value)
        pin = pointer(path)
        self.events.append((pin, value))
        return pin
