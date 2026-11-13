"""Native watchdog fixture that starts and deliberately never becomes ready."""

import argparse
import os
import time
from pathlib import Path

from harness.events import emit, identity
from harness.spec import load

parser = argparse.ArgumentParser()
parser.add_argument("--manifest", required=True, type=Path)
args = parser.parse_args()
manifest = load(args.manifest)
emit(manifest, "starting")
emit(manifest, "inventory", owned_processes=[identity(os.getpid())])
time.sleep(200)
