"""Command-line entry points for offline reproduction and figures."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analysis import reproduce


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser(
        "reproduce", help="recompute and check all primary intervals and tables"
    )
    analyze.add_argument("--data", type=Path, default=Path("data"))
    analyze.add_argument("--output", type=Path, default=Path("results"))
    analyze.add_argument(
        "--bootstrap", action="store_true", help="also recompute both 10,000-draw reference schemes"
    )
    plot = sub.add_parser("plot", help="render data figures with Times New Roman")
    plot.add_argument("--data", type=Path, default=Path("data"))
    plot.add_argument("--results", type=Path, default=Path("results"))
    plot.add_argument("--output", type=Path, default=Path("results/figures"))
    plot.add_argument("--font", type=Path)
    args = parser.parse_args()
    if args.command == "reproduce":
        print(json.dumps(reproduce(args.data, args.output, bootstrap=args.bootstrap), indent=2))
    else:
        from .plotting import render

        print(json.dumps(render(args.data, args.results, args.output, font=args.font), indent=2))


if __name__ == "__main__":
    main()
