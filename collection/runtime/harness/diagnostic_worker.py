"""Enter a bound diagnostic worker inside the existing native enclosure."""

from __future__ import annotations

import argparse
from pathlib import Path

from harness.diagnostic_binding import execute


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    return execute(args.manifest)


if __name__ == "__main__":
    raise SystemExit(main())
