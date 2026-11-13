"""Protocol-only subprocess fixture for recovery-runner unit checks."""

import argparse
from pathlib import Path

from harness.events import emit, serve_commands
from harness.spec import load

parser = argparse.ArgumentParser()
parser.add_argument("--manifest", type=Path, required=True)
args = parser.parse_args()
manifest = load(args.manifest)
if manifest.get("test_behavior") == "bad-json":
    print("{broken", flush=True)
else:
    emit(manifest, "starting")
    hosts = manifest["host_names"]
    checks = [{"src": hosts[i], "dst": hosts[i + 1], "ok": True} for i in range(0, len(hosts), 2)]
    checks += [{"src": c["dst"], "dst": c["src"], "ok": True} for c in checks[:]]
    emit(manifest, "ready", checks=checks)
    serve_commands(manifest, lambda: {"entries": 2})
    emit(manifest, "stopped")
