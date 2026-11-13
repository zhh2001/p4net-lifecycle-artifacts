"""Connect reviewed observer attempts to the calibrated native dispatcher."""

from __future__ import annotations

import copy
import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from harness import observer_dispatch, spec
from harness.campaign_executor import NativeBackend, _equal, _json, _resolve, _sha, _write_new
from harness.observer_campaign import (
    Attempt,
    entries_for,
    metadata_for,
    observation_metadata,
    required_gates,
)
from harness.observer_campaign_inputs import plan_from_binding, verify_binding

TREATMENTS = {
    "p4net": ("p4net310", "harness.worker"),
    "p4utils": ("p4utils310", "harness.worker_p4utils"),
    "tutorial-components": ("tutorial310", "harness.worker_tutorial"),
}


def _adapt(
    dispatch: Mapping[str, Any], metadata: Mapping[str, Any], *, artifacts: Path
) -> dict[str, Any]:
    from harness.observer_campaign_result import adapt_result

    return adapt_result(dispatch, metadata, artifacts=artifacts)


class NativeObserverBackend:
    """Require current input and environment checks before any native dispatch."""

    mode = "pilot"

    def __init__(self, *, base: Path) -> None:
        self.base = base.resolve()
        self.binding: dict[str, Any] | None = None
        self.output: Path | None = None
        self._native = NativeBackend(self.mode, base=self.base)

    def preflight(self, output: Path, binding: Mapping[str, Any]) -> None:
        """Check native dependencies and clear any preceding successful state first."""
        self.binding, self.output = None, None
        self._native.binding = None
        candidate = copy.deepcopy(dict(binding))
        verify_binding(candidate, base=self.base)
        if candidate["mode"] != self.mode:
            raise ValueError("native observer execution requires a pilot input binding")
        directory = output.resolve()
        if not _equal(_json(directory / "observer-binding.json"), candidate):
            raise ValueError("native observer output is bound to different inputs")
        self._native.preflight(directory, candidate["base_binding"])
        self.binding, self.output = candidate, directory

    def _claim(self, attempt: Attempt) -> dict[str, Any]:
        if self.binding is None or self.output is None:
            raise RuntimeError("native observer execution requires a successful preflight")
        if not _equal(_json(self.output / "observer-binding.json"), self.binding):
            raise ValueError("native observer journal binding changed after preflight")
        metadata = attempt.metadata
        plan = plan_from_binding(self.binding)
        entries = entries_for(plan)
        planned = metadata.get("planned_id")
        if not isinstance(planned, str) or planned not in entries:
            raise ValueError("native observer claim is outside its allocation")
        number, run_id = metadata.get("attempt_number"), metadata.get("run_id")
        if (
            type(number) is not int
            or number < 1
            or not isinstance(run_id, str)
            or not re.fullmatch(r"[a-f0-9]{32}", run_id)
        ):
            raise ValueError("native observer claim has an invalid attempt identity")
        phase, entry = entries[planned]
        expected = metadata_for(plan, self.binding, phase, entry, number, run_id)
        directory = self.output / "attempts" / planned / f"{number:04}"
        supplied = Path(os.path.abspath(attempt.directory))
        if supplied != directory or any(
            path.is_symlink() for path in (directory, directory.parent, directory.parent.parent)
        ):
            raise ValueError("native observer attempt is outside its owned journal")
        started = _json(directory / "started.json")
        if (
            not _equal(metadata, expected)
            or not _equal(started, attempt.started)
            or not _equal(started.get("entry"), entry)
            or started.get("record_type") != "observer-attempt-start"
            or type(started.get("schema_version")) is not int
            or started["schema_version"] != 1
            or started.get("mode") != self.mode
            or started.get("performance_samples") is not True
            or started.get("input_lock_sha256") != self.binding["input_lock_sha256"]
            or started.get("previous_attempt_id")
            != (None if number == 1 else f"{planned}--a{number - 1:04}")
        ):
            raise ValueError("native observer claim differs from its published identity")
        reviews = started.get("gate_reviews")
        gates = required_gates(plan, phase, entry)
        if not isinstance(reviews, list) or len(reviews) != len(gates):
            raise ValueError("native observer claim is missing reviewed stage permissions")
        for reference, gate in zip(reviews, gates, strict=True):
            if (
                not isinstance(reference, dict)
                or set(reference) != {"gate_id", "review_number", "sha256"}
                or reference.get("gate_id") != gate
                or type(reference.get("review_number")) is not int
                or reference["review_number"] < 1
            ):
                raise ValueError("native observer claim has an invalid gate reference")
            path = self.output / "gates" / gate / f"{reference['review_number']:04}.json"
            review = _json(path)
            if (
                reference.get("sha256") != _sha(path)
                or review.get("gate_id") != gate
                or review.get("review_number") != reference["review_number"]
                or review.get("qualified") is not True
                or review.get("input_lock_sha256") != self.binding["input_lock_sha256"]
            ):
                raise ValueError("native observer claim has changed stage permissions")
        if any(
            os.path.lexists(directory / name)
            for name in ("result.json", "measurement.json", "backend-result.json", "artifacts")
        ):
            raise FileExistsError(
                "native observer attempt already contains an outcome or artifacts"
            )
        return metadata

    def _worker(self, tool: str) -> tuple[Path, str]:
        assert self.binding is not None
        label, worker = TREATMENTS[tool]
        dependency_path = _resolve(
            self.binding["base_binding"]["dependency_manifest"]["path"], self.base
        )
        dependency = _json(dependency_path)
        environment_path = _resolve(dependency["environment_files"][label], dependency_path.parent)
        environment = _json(environment_path)
        if environment.get("version_info", [])[:3] != [3, 10, 20]:
            raise ValueError("worker Python version differs from the observer allocation")
        python = _resolve(environment["executable"], environment_path.parent)
        if (
            python.resolve()
            != _resolve(
                environment["interpreter_identity"]["path"], environment_path.parent
            ).resolve()
        ):
            raise ValueError("worker executable differs from its frozen interpreter")
        return python, worker

    def __call__(self, attempt: Attempt) -> Mapping[str, Any]:
        from harness.worker_components import verify_binding_components

        if self.binding is None:
            raise RuntimeError("native observer execution requires a successful preflight")
        verify_binding(self.binding, base=self.base)
        components = verify_binding_components(self.binding["base_binding"], base=self.base)
        self._native._tool_lookup(self.binding["base_binding"])
        metadata = self._claim(attempt)
        python, worker = self._worker(metadata["tool"])
        path = spec.create(
            attempt.artifacts,
            groups=metadata["switches"],
            source=self.base / "harness/workloads/l3.p4",
            configuration_profile=metadata["configuration_profile"],
        )
        manifest = spec.load(path)
        manifest["worker_components"] = components
        manifest["run_id"] = metadata["run_id"]
        if metadata["workload"] == "fault":
            manifest["episode_fault"] = metadata["fault"]
        path.write_text(json.dumps(manifest, indent=2, allow_nan=False) + "\n")
        configuration = {
            "mode": self.mode,
            "metadata": observation_metadata(metadata),
            "clock_domain": "observer-monotonic-ns-v1",
            **self.binding["measurement_defaults"],
            "observer_profile": metadata["observer_profile"],
            "attempt_id": metadata["attempt_id"],
        }
        try:
            dispatch = observer_dispatch.run_calibrated(
                path, python, worker, calibration=configuration, collection_authorized=True
            )
        except (KeyboardInterrupt, SystemExit):
            try:
                dispatch = _json(attempt.artifacts / "observer-dispatch.json")
                response = _adapt(dispatch, metadata, artifacts=attempt.artifacts)
                _write_new(attempt.directory / "backend-result.json", response)
            except Exception:
                # The original interruption remains authoritative when no
                # validated response can be retained for reconciliation.
                pass
            raise
        return _adapt(dispatch, metadata, artifacts=attempt.artifacts)
