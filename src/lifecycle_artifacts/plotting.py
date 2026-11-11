"""Render the data figures from task observations and recomputed effects."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

from .analysis import check_integrity, load_records, read, verify_expected, write
from .tables import find

TOOLS = ("p4net", "p4utils", "tutorial-components")
NAMES = {"p4net": "p4net", "p4utils": "P4-Utils", "tutorial-components": "Tutorial components"}
COLORS = {"p4net": "#0072B2", "p4utils": "#D55E00", "tutorial-components": "#009E73"}
SCALES = (1, 2, 4, 8, 16)


def quantile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    a, b = math.floor(position), math.ceil(position)
    return ordered[a] + (ordered[b] - ordered[a]) * (position - a)


def render(data: Path, results: Path, output: Path, *, font: Path | None = None) -> dict[str, Any]:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib import font_manager

    check_integrity(data)
    datasets = load_records(data)
    effects, outcomes = read(results / "comparisons.json"), read(results / "outcomes.json")
    verify_expected(data, effects, outcomes, bootstrap=False)
    if font is None:
        font = Path(font_manager.findfont("Times New Roman", fallback_to_default=False))
    if not font.is_file():
        raise ValueError("Times New Roman is required; pass --font with its font file")
    font_manager.fontManager.addfont(str(font))
    if font_manager.FontProperties(fname=str(font)).get_name() != "Times New Roman":
        raise ValueError("the selected font must be Times New Roman")
    matplotlib.rcParams.update(
        {
            "font.family": "Times New Roman",
            "font.size": 10,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "savefig.dpi": 300,
            "axes.spines.top": False,
            "axes.spines.right": False,
        }
    )
    output.mkdir(parents=True, exist_ok=True)
    plot_values: list[dict[str, Any]] = []
    names = []

    def save(figure: Any, name: str) -> None:
        for extension in ("pdf", "png"):
            figure.savefig(output / f"{name}.{extension}", bbox_inches="tight")
        plt.close(figure)
        names.append(name)

    def raw(ax: Any, metric: str, label: str, factor: float = 1) -> None:
        for tool in TOOLS:
            stats = []
            for n in SCALES:
                values = [
                    r["metrics"][metric] * factor
                    for r in datasets["formal"]
                    if r["condition"]["workload"] == "scale"
                    and r["condition"]["switches"] == n
                    and r["tool"] == tool
                ]
                stats.append([quantile(values, p) for p in (0.25, 0.5, 0.75)])
                plot_values.append(
                    {
                        "panel": metric,
                        "tool": tool,
                        "switches": n,
                        "n": len(values),
                        "q1": stats[-1][0],
                        "median": stats[-1][1],
                        "q3": stats[-1][2],
                    }
                )
            ax.plot(
                range(5),
                [s[1] for s in stats],
                "o-",
                color=COLORS[tool],
                label=NAMES[tool],
                markersize=4,
            )
            ax.fill_between(
                range(5),
                [s[0] for s in stats],
                [s[2] for s in stats],
                color=COLORS[tool],
                alpha=0.15,
            )
        ax.set_xticks(range(5), SCALES)
        ax.set_xlabel("Switches")
        ax.set_ylabel(label)
        ax.grid(axis="y", color="0.9", linewidth=0.6)

    fig, axes = plt.subplots(2, 2, figsize=(10.8, 7.3), constrained_layout=True)
    for col, metric in enumerate(("task_to_ready_ns", "stop_to_exit_ns")):
        raw(axes[0, col], metric, "Latency (s)", 1e-9)
        axes[0, col].set_title(
            "Launch to validated readiness" if col == 0 else "Stop request to worker exit"
        )
        ax = axes[1, col]
        for index, baseline in enumerate(TOOLS[1:]):
            rows = [
                find(
                    effects,
                    "formal",
                    metric,
                    {"workload": "scale", "switches": n},
                    ["p4net", baseline],
                )["primary"]
                for n in SCALES
            ]
            points = [r["point_estimate"] * 1e-9 for r in rows]
            ax.errorbar(
                [i + (-0.07 if index == 0 else 0.07) for i in range(5)],
                points,
                yerr=[
                    [(r["point_estimate"] - r["interval"]["lower"]) * 1e-9 for r in rows],
                    [(r["interval"]["upper"] - r["point_estimate"]) * 1e-9 for r in rows],
                ],
                fmt="o-",
                color=COLORS[baseline],
                capsize=3,
                label=f"p4net - {NAMES[baseline]}",
            )
        ax.set_xticks(range(5), SCALES)
        ax.set_xlabel("Switches")
        ax.set_ylabel("Median paired difference (s)")
        ax.axhline(0, color="0.4", linestyle="--", linewidth=0.8)
    axes[0, 0].legend(frameon=False, fontsize=9)
    axes[1, 0].legend(frameon=False, fontsize=9)
    save(fig, "scale-lifecycle")
    fig, axes = plt.subplots(2, 3, figsize=(12.0, 7.1), constrained_layout=True)
    for index, role in enumerate(("worker", "bmv2")):
        for col, (suffix, label, factor) in enumerate(
            (
                ("cpu_percent", "CPU (% of one core)", 1),
                ("rss_bytes", "RSS (MiB)", 1 / 2**20),
                ("pss_bytes", "PSS (MiB)", 1 / 2**20),
            )
        ):
            raw(axes[index, col], f"idle_{role}_{suffix}", label, factor)
            axes[index, col].set_title(
                f"{'Worker' if role == 'worker' else 'BMv2 total'} {label.split()[0]}"
            )
    axes[0, 0].legend(frameon=False, fontsize=9)
    save(fig, "scale-resources")
    faults = (
        "normal-control",
        "invalid-p4",
        "occupied-grpc",
        "sigint-startup",
        "kill-bmv2",
        "drop-control",
    )
    labels = (
        "Normal control",
        "Invalid P4",
        "Occupied port",
        "Startup SIGINT",
        "BMv2 termination",
        "Control interruption",
    )
    fig, axes = plt.subplots(2, 2, figsize=(11, 7.1), constrained_layout=True)
    for ax, key, title in zip(
        axes.flat,
        (
            "initial_ready",
            "initial_ordinary_cleanup_clean",
            "restart_ready",
            "restart_ordinary_cleanup_clean",
        ),
        (
            "Initial validated readiness",
            "Initial ordinary cleanup",
            "Restart validated readiness",
            "Restart ordinary cleanup",
        ),
        strict=True,
    ):
        matrix = [
            [
                next(g for g in outcomes if g["tool"] == tool and g["fault"] == fault)["counts"][
                    key
                ]
                for fault in faults
            ]
            for tool in TOOLS
        ]
        ax.imshow(matrix, vmin=0, vmax=30, cmap="Blues", aspect="auto")
        ax.set_xticks(range(6), labels, rotation=28, ha="right", fontsize=8)
        ax.set_yticks(range(3), [NAMES[t] for t in TOOLS], fontsize=9)
        ax.set_title(title)
        for i, row in enumerate(matrix):
            for j, count in enumerate(row):
                ax.text(
                    j,
                    i,
                    f"{count}/30",
                    ha="center",
                    va="center",
                    color="white" if count > 15 else "black",
                    fontsize=9,
                )
    save(fig, "fault-outcomes")
    births = read(data / "formal/process-birth.json")
    fig, axes = plt.subplots(1, 3, figsize=(12, 3.5), constrained_layout=True)
    for ax, key, title in zip(
        axes,
        ("worker_birth_to_first_bmv2_s", "bmv2_birth_span_s", "adjacent_bmv2_birth_gap_s"),
        ("Worker birth to first BMv2", "First to last BMv2 birth", "Median adjacent BMv2 gap"),
        strict=True,
    ):
        for tool in TOOLS:
            x, medians, lower, upper = [], [], [], []
            for n in SCALES:
                values = [
                    r[key]
                    for r in births
                    if r["tool"] == tool and r["switches"] == n and r[key] is not None
                ]
                if not values:
                    continue
                x.append(n)
                lower.append(quantile(values, 0.25))
                medians.append(quantile(values, 0.5))
                upper.append(quantile(values, 0.75))
                plot_values.append(
                    {
                        "panel": key,
                        "tool": tool,
                        "switches": n,
                        "n": len(values),
                        "median": medians[-1],
                        "q1": lower[-1],
                        "q3": upper[-1],
                    }
                )
            ax.plot(x, medians, "o-", label=NAMES[tool], color=COLORS[tool], markersize=4)
            ax.fill_between(x, lower, upper, color=COLORS[tool], alpha=0.15)
        ax.set_title(title)
        ax.set_xlabel("Switches")
        ax.set_ylabel("Seconds")
        ax.set_xticks(SCALES)
    axes[0].legend(frameon=False, fontsize=8)
    save(fig, "process-birth")
    # The calibration panels share original-unit effect boundaries with their tables.
    for campaign, metrics, levels in (
        (
            "observer",
            [
                ("observer_cpu_seconds", "Observer CPU (s)", 1),
                ("observer_pss_bytes", "Endpoint PSS (MiB)", 1 / 2**20),
            ],
            [["S", "T"]],
        ),
        (
            "diagnostic",
            [
                ("reference_body_wall_ns", "Reference-body wall (ms)", 1e-6),
                ("worker_ready_pss_bytes", "Ready PSS (MiB)", 1 / 2**20),
            ],
            [["stages", "native"], ["detail", "native"]],
        ),
    ):
        fig, axes = plt.subplots(2, 2, figsize=(10.5, 6.7), constrained_layout=True)
        for row_index, n in enumerate((1, 16)):
            for ax, (metric, label, factor) in zip(axes[row_index], metrics, strict=True):
                for index, pair in enumerate(levels):
                    selected = [
                        find(effects, campaign, metric, {"tool": t, "switches": n}, pair)["primary"]
                        for t in TOOLS
                    ]
                    ax.errorbar(
                        [i + (index - (len(levels) - 1) / 2) * 0.16 for i in range(3)],
                        [r["point_estimate"] * factor for r in selected],
                        yerr=[
                            [
                                (r["point_estimate"] - r["interval"]["lower"]) * factor
                                for r in selected
                            ],
                            [
                                (r["interval"]["upper"] - r["point_estimate"]) * factor
                                for r in selected
                            ],
                        ],
                        fmt="o",
                        capsize=3,
                        label=" - ".join(pair),
                    )
                ax.set_xticks(range(3), [NAMES[t] for t in TOOLS], fontsize=9)
                ax.set_title(f"{n} switch{'es' if n != 1 else ''}")
                ax.set_ylabel(label)
                ax.axhline(0, color="0.5", linestyle="--", linewidth=0.7)
        axes[0, 0].legend(frameon=False)
        save(fig, f"{campaign}-overhead")
    write(output / "plot-values.json", plot_values)
    return {
        "font": "Times New Roman",
        "figures": names,
        "formats": ["pdf", "png"],
        "source_values": len(plot_values),
    }
