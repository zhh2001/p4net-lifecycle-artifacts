"""Register a host process before a pipe acknowledgment permits its selected exec."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from overhead.ledger import pinned, read
from overhead.proc import ProcReader
from overhead.publication import pointer, publish


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--intent", required=True, type=Path)
    parser.add_argument("--barrier", required=True, type=int)
    args = parser.parse_args()
    intent = read(args.intent)
    scope = pinned(intent["scope"])
    reader = ProcReader()
    parent = reader.identity(os.getppid())
    if parent.as_dict() != scope["owner"] or intent["role"] not in {"guard", "outer"}:
        raise PermissionError("owned child parent differs from its registered scope")
    own = reader.identity(os.getpid())
    publish(
        args.intent.with_name(intent["role"] + ".json"),
        {
            "scope": intent["scope"],
            "role": intent["role"],
            "intent": pointer(args.intent),
            "parent": parent.as_dict(),
            "identity": own.as_dict(),
        },
    )
    with os.fdopen(args.barrier, "rb", buffering=0) as pipe:
        if pipe.read(1) != b"G":
            return
    for descriptor in read(args.intent).get("inherited_fds", []):
        os.set_inheritable(descriptor, True)
    os.execvpe(intent["executable"], intent["argv"], os.environ)


if __name__ == "__main__":
    main()
