"""Verify the frozen experiment population and independently derived outputs."""

from __future__ import annotations

import copy
import csv
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from lifecycle_artifacts import binomial_intervals, median_intervals
from lifecycle_artifacts.analysis import (
    check_integrity,
    comparison,
    exclusion,
    load_records,
    read,
    reproduce,
)

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"


@pytest.fixture(scope="module")
def records():
    return load_records(DATA)


@pytest.fixture(scope="module")
def reproduced(tmp_path_factory):
    output = tmp_path_factory.mktemp("reproduced")
    summary = reproduce(DATA, output)
    return output, summary


def test_complete_first_attempt_population(records):
    assert {key: len(value) for key, value in records.items()} == {
        "formal": 990,
        "observer": 270,
        "diagnostic": 360,
    }
    assert Counter(r["condition"]["workload"] for r in records["formal"]) == {
        "scale": 450,
        "fault": 540,
    }
    assert all({r["session"] for r in rows} == {1, 2, 3} for rows in records.values())
    assert all(r["attempt"] == 1 for rows in records.values() for r in rows)


def test_all_primary_intervals_and_outcomes_match(reproduced):
    output, summary = reproduced
    assert summary["comparisons"] == 1125
    assert summary["available_intervals"] == 814
    assert summary["formal_performance_eligible"] == 916
    assert summary["formal_performance_excluded"] == 74
    observed = read(output / "comparisons.json")
    expected = read(DATA / "expected-comparisons.json")
    assert Counter(r["campaign"] for r in observed) == {
        "formal": 693,
        "observer": 72,
        "diagnostic": 360,
    }
    assert [r["primary"] for r in observed] == [r["primary"] for r in expected]


def test_cleanup_and_restart_denominators(reproduced):
    output, _ = reproduced
    groups = [g for g in read(output / "outcomes.json") if g["workload"] == "fault"]
    assert sum(g["planned_units"] for g in groups) == 540
    assert (
        sum(g["counts"]["initial_ordinary_cleanup_clean"] for g in groups if g["tool"] == "p4net")
        == 180
    )
    assert sum(g["counts"]["restart_ready"] for g in groups) == 540
    assert sum(g["counts"]["restart_ordinary_cleanup_clean"] for g in groups) == 540
    assert (
        next(g for g in groups if g["tool"] == "p4utils" and g["fault"] == "drop-control")[
            "counts"
        ]["initial_ordinary_cleanup_clean"]
        == 0
    )
    assert (
        next(
            g
            for g in groups
            if g["tool"] == "tutorial-components" and g["fault"] == "sigint-startup"
        )["counts"]["initial_ordinary_cleanup_clean"]
        == 16
    )


def test_nine_tables_and_paper_units(reproduced):
    output, _ = reproduced
    assert len(list((output / "tables").glob("table-*.csv"))) == 9
    with (output / "tables/table-05-startup.csv").open() as stream:
        rows = list(csv.DictReader(stream))
    p4utils = next(r for r in rows if r["switches"] == "16" and r["baseline"] == "p4utils")
    tutorial = next(
        r for r in rows if r["switches"] == "16" and r["baseline"] == "tutorial-components"
    )
    assert round(float(p4utils["median"]), 3) == 2.150
    assert round(float(tutorial["median"]), 3) == -4.230
    with (output / "tables/table-09-diagnostic.csv").open() as stream:
        rows = list(csv.DictReader(stream))
    assert round(float(rows[0]["wall_ms_median"]), 1) == 400.8
    assert float(rows[0]["cpu_ms_median"]) == 150
    assert round(float(rows[0]["pss_mib_median"]), 2) == 13.08


@pytest.mark.parametrize(
    "key, value, reason",
    [
        ("ordinary_stop_timeout", True, "ordinary-stop-timeout"),
        ("restart_ordinary_stop_timeout", True, "ordinary-stop-timeout"),
        ("ordinary_cleanup_clean", False, "ordinary-cleanup-incomplete"),
        ("restart_ordinary_cleanup_clean", False, "ordinary-cleanup-incomplete"),
    ],
)
def test_both_cleanup_phases_gate_performance(records, key, value, reason):
    row = copy.deepcopy(next(r for r in records["formal"] if exclusion(r) is None))
    row["eligibility"][key] = value
    assert exclusion(row) == reason


def test_missing_metric_drops_only_its_pair(records):
    spec = next(
        s
        for s in read(ROOT / "protocol/comparisons.json")
        if s["campaign"] == "formal"
        and s["condition"]["workload"] == "scale"
        and s["metric"] == "task_to_ready_ns"
    )
    rows = copy.deepcopy(records["formal"])
    row = next(
        r for r in rows if r["condition"] == spec["condition"] and r["tool"] == spec["levels"][0]
    )
    del row["metrics"][spec["metric"]]
    result = comparison(rows, spec)
    assert result["primary"]["total_n"] == 29
    assert len(result["excluded"]) == 1
    assert result["excluded"][0]["reasons"][0]["reason"] == "missing-completed-metric"


def test_absent_startup_is_not_zero(records):
    spec = next(
        s
        for s in read(ROOT / "protocol/comparisons.json")
        if s["campaign"] == "formal"
        and s["condition"]["fault"] == "invalid-p4"
        and s["metric"] == "task_to_ready_ns"
    )
    result = comparison(records["formal"], spec)
    assert result["primary"]["point_estimate"] is None
    assert result["primary"]["interval"] is None
    assert result["primary"]["status"] == "unavailable"


@pytest.mark.parametrize("campaign", ["formal", "observer", "diagnostic"])
def test_supplementary_bootstrap_reference(records, campaign):
    frozen = next(
        c
        for c in read(DATA / "expected-comparisons.json")
        if c["campaign"] == campaign and c["primary"]["status"] == "ok"
    )
    spec = {k: v for k, v in frozen.items() if k not in ("primary", "bootstrap")}
    result = comparison(records[campaign], spec, bootstrap=True)
    assert result["bootstrap"] == frozen["bootstrap"]


@pytest.mark.parametrize(
    "per_session, bounds", [(10, {"lower": 10, "upper": 21}), (5, {"lower": 4, "upper": 12})]
)
def test_rank_bounds(per_session, bounds):
    result = median_intervals.rank_median(
        {s: list(range(per_session)) for s in (1, 2, 3)}, expected_sessions=[1, 2, 3]
    )
    assert result["rank_bounds"] == bounds
    assert result["coverage_lower_bound"] >= 0.95


def test_missing_session_retains_point_but_has_no_interval():
    result = median_intervals.rank_median(
        {1: list(range(15)), 2: list(range(15))}, expected_sessions=[1, 2, 3]
    )
    assert result["point_estimate"] == 7
    assert result["interval"] is None
    assert result["reason"] == "missing-session-data"


@pytest.mark.parametrize(
    "successes, lower, upper", [(30, 0.8842966917779722, 1.0), (0, 0.0, 0.11570330822202779)]
)
def test_exact_completion_extremes(successes, lower, upper):
    interval = binomial_intervals.exact_interval(successes, 30)["interval"]
    assert interval["lower"] == pytest.approx(lower, abs=1e-15)
    assert interval["upper"] == pytest.approx(upper, abs=1e-15)


def test_manifest_detects_changed_observations(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "records.json").write_text("changed")
    (data / "manifest.json").write_text(json.dumps({"sha256": {"data/records.json": "0" * 64}}))
    with pytest.raises(ValueError, match="content hash differs"):
        check_integrity(data)


def test_manifest_rejects_paths_outside_root(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "manifest.json").write_text(json.dumps({"sha256": {"../outside": "0" * 64}}))
    with pytest.raises(ValueError, match="escapes"):
        check_integrity(data)


def test_cli_from_another_directory(tmp_path):
    command = subprocess.run(
        [
            sys.executable,
            "-m",
            "lifecycle_artifacts",
            "reproduce",
            "--data",
            str(DATA),
            "--output",
            str(tmp_path / "out"),
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=True,
    )
    assert json.loads(command.stdout)["all_reference_comparisons_match"] is True


def test_manifest_uses_portable_relative_paths():
    manifest = read(DATA / "manifest.json")
    for name in manifest["sha256"]:
        path = Path(name)
        assert not path.is_absolute()
        assert ".." not in path.parts
