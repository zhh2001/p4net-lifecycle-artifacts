"""Check explicit campaign configuration using only synthetic enclosure dispatch."""

import copy
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from harness import campaign_bridge, isolation, measure, resources


def configuration():
    return {
        "mode": "pilot",
        "clock_domain": "synthetic-campaign-session-1",
        "duration_ns": 10_000_000_000,
        "interval_ns": 100_000_000,
        "metadata": {
            "run_id": "0" * 32,
            "session": 1,
            "tool": "p4net",
            "python": "3.10.20",
            "input_lock_sha256": "a" * 64,
            "workload": "scale",
            "switches": 1,
            "configuration_profile": "matched-v1",
            "build_mode": "native-source-cold",
            "fault": None,
            "planned_case_id": "scale-s01-r01-n01-p4net",
            "source_identity": {"sha256": "b" * 64},
        },
    }


class ValidationTests(unittest.TestCase):
    def test_validation_does_not_read_clocks_or_resources_and_returns_a_deep_copy(self):
        original = configuration()
        with (
            patch.object(measure.time, "monotonic_ns", side_effect=AssertionError("clock")),
            patch.object(measure, "sample_window", side_effect=AssertionError("sampler")),
            patch.object(resources, "read_sample", side_effect=AssertionError("procfs")),
        ):
            result = campaign_bridge.validate_measurement(original)
        self.assertEqual(result, original)
        result["metadata"]["source_identity"]["sha256"] = "c" * 64
        self.assertEqual(original["metadata"]["source_identity"]["sha256"], "b" * 64)

    def test_configuration_requires_exactly_the_five_supported_fields(self):
        for key in configuration():
            with self.subTest(missing=key):
                value = configuration()
                del value[key]
                with self.assertRaises(ValueError):
                    campaign_bridge.validate_measurement(value)
        value = configuration()
        value["schema_version"] = 1
        with self.assertRaises(ValueError):
            campaign_bridge.validate_measurement(value)
        for value in (None, [], "pilot"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                campaign_bridge.validate_measurement(value)

    def test_modes_clock_domains_and_schedules_are_explicit_and_bounded(self):
        cases = [
            ("mode", "synthetic-validation"),
            ("mode", []),
            ("clock_domain", ""),
            ("clock_domain", " \t"),
            ("clock_domain", 1),
            ("duration_ns", True),
            ("duration_ns", 1.0),
            ("duration_ns", float("inf")),
            ("duration_ns", 0),
            ("duration_ns", 2**63),
            ("interval_ns", True),
            ("interval_ns", 0),
            ("interval_ns", -1),
            ("interval_ns", 10_000_000_001),
        ]
        for key, invalid in cases:
            with self.subTest(key=key, invalid=invalid):
                value = configuration()
                value[key] = invalid
                with self.assertRaises(ValueError):
                    campaign_bridge.validate_measurement(value)
        value = configuration()
        value.update(mode="formal", duration_ns=2**63 - 1, interval_ns=2**63 - 1)
        self.assertEqual(campaign_bridge.validate_measurement(value), value)

    def test_recorder_metadata_contract_and_finite_json_values_are_enforced(self):
        cases = [
            ("session", True),
            ("input_lock_sha256", "unfrozen"),
            ("configuration_profile", "native"),
            ("mode", "formal"),
            ("extra", float("nan")),
            ("extra", {"nested": float("inf")}),
            ("extra", object()),
        ]
        for key, invalid in cases:
            with self.subTest(key=key, invalid=invalid):
                value = configuration()
                value["metadata"][key] = invalid
                with self.assertRaises(ValueError):
                    campaign_bridge.validate_measurement(value)
        value = configuration()
        del value["metadata"]["tool"]
        with self.assertRaises(ValueError):
            campaign_bridge.validate_measurement(value)
        value["metadata"] = []
        with self.assertRaises(ValueError):
            campaign_bridge.validate_measurement(value)

    def test_manifest_binding_checks_parent_identity_scale_profile_fault_and_workload(self):
        manifest = {"run_id": "0" * 32, "groups": 1, "configuration_profile": "matched-v1"}
        value = configuration()
        self.assertEqual(campaign_bridge.validate_measurement(value, manifest), value)
        for field, invalid in (
            ("run_id", "1" * 32),
            ("switches", 2),
            ("fault", "normal-control"),
            ("workload", "fault"),
        ):
            with self.subTest(field=field):
                value = configuration()
                value["metadata"][field] = invalid
                with self.assertRaisesRegex(ValueError, "native manifest"):
                    campaign_bridge.validate_measurement(value, manifest)
        value = configuration()
        manifest["configuration_profile"] = "native"
        with self.assertRaisesRegex(ValueError, "native manifest"):
            campaign_bridge.validate_measurement(value, manifest)
        manifest.update(configuration_profile="matched-v1", episode_fault="normal-control")
        value["metadata"].update(workload="fault", fault="normal-control")
        self.assertEqual(campaign_bridge.validate_measurement(value, manifest), value)


class EnclosureDispatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / "trial"
        self.directory.mkdir()
        self.source = self.root / "source.p4"
        self.source.write_text("synthetic source fixture\n")
        self.path = self.directory / "manifest.json"
        self.manifest = {
            "schema_version": 1,
            "purpose": "functional-check",
            "run_id": "0" * 32,
            "prefix": "r000000",
            "groups": 1,
            "host_names": ["r000000a0", "r000000b0"],
            "switch_names": ["r000000s0"],
            "service_ports": [10001, 10002],
            "p4_source": str(self.source),
            "output_dir": str(self.directory),
            "configuration_profile": "matched-v1",
        }
        self.save_manifest()
        self.outer = {kind: f"{kind}:[1]" for kind in isolation.NAMESPACES}
        self.inner = {kind: f"{kind}:[2]" for kind in isolation.NAMESPACES}

    def save_manifest(self):
        self.path.write_text(json.dumps(self.manifest) + "\n")

    def test_command_round_trips_measurement_without_changing_the_default_command(self):
        value = configuration()
        with patch.object(isolation, "namespace_ids", return_value=self.outer):
            ordinary = isolation.isolated_command(self.path, Path("/venv/bin/python"), "worker")
            measured = isolation.isolated_command(
                self.path, Path("/venv/bin/python"), "worker", measurement=value
            )
        self.assertEqual(measured[:-2], ordinary)
        self.assertEqual(measured[-2], "--measurement")
        self.assertEqual(json.loads(measured[-1]), value)
        self.assertNotIn("--validate-boundaries", measured)
        self.assertIn("--kill-child=KILL", ordinary)

    def test_measurement_and_boundary_validation_reject_before_native_setup(self):
        value = configuration()
        with (
            patch.object(isolation, "require_private") as private,
            patch.object(isolation, "namespace_ids") as namespaces,
            patch.object(isolation.subprocess, "Popen") as popen,
        ):
            for function, arguments in (
                (isolation.inside, (self.path, Path(sys.executable), "worker", self.outer)),
                (isolation.isolated_command, (self.path, Path(sys.executable), "worker")),
                (isolation.run_isolated, (self.path, Path(sys.executable), "worker")),
            ):
                with self.subTest(function=function.__name__), self.assertRaises(ValueError):
                    function(*arguments, boundary_validation=True, measurement=value)
            private.assert_not_called()
            namespaces.assert_not_called()
            popen.assert_not_called()

    def test_invalid_binding_rejects_before_native_setup(self):
        value = configuration()
        value["metadata"]["run_id"] = "1" * 32
        with (
            patch.object(isolation, "require_private") as private,
            patch.object(isolation.subprocess, "Popen") as popen,
        ):
            for function, arguments in (
                (isolation.inside, (self.path, Path(sys.executable), "worker", self.outer)),
                (isolation.run_isolated, (self.path, Path(sys.executable), "worker")),
            ):
                with self.subTest(function=function.__name__), self.assertRaises(ValueError):
                    function(*arguments, measurement=value)
            private.assert_not_called()
            popen.assert_not_called()

    def test_inside_constructs_after_enclosure_checks_and_dispatches_task_or_episode(self):
        for fault in (None, "normal-control"):
            with self.subTest(fault=fault):
                self.check_inside_dispatch(fault)

    def check_inside_dispatch(self, fault):
        value = configuration()
        if fault is not None:
            self.manifest["episode_fault"] = fault
            value["metadata"].update(workload="fault", fault=fault)
        self.save_manifest()
        stages = []
        observation = Mock()

        def private(expected):
            self.assertEqual(expected, self.outer)
            stages.append("private")
            return self.inner

        def mounts():
            stages.append("mounts")
            return {}

        def factory(**kwargs):
            self.assertEqual(stages, ["private", "mounts"])
            self.assertEqual(kwargs, value)
            self.assertEqual(json.loads(isolation.os.environ["P4NET_STUDY_INNER_NS"]), self.inner)
            stages.append("observation")
            return observation

        with (
            patch.dict(isolation.os.environ),
            patch.object(isolation, "require_private", side_effect=private),
            patch.object(isolation, "prepare_mounts", side_effect=mounts),
            patch.object(isolation, "checked"),
            patch.object(isolation.subprocess, "check_output", return_value="1\n1\n1\n"),
            patch("harness.native_measurement.measured_observation", side_effect=factory),
            patch("harness.supervisor.run", return_value={"ok": False}) as task,
            patch("harness.episode.run_episode", return_value={"ok": False}) as episode,
            patch.object(measure, "sample_window", side_effect=AssertionError("sampler")),
            patch.object(isolation.subprocess, "Popen", side_effect=AssertionError("launch")),
            redirect_stdout(io.StringIO()),
        ):
            status = isolation.inside(
                self.path, Path(sys.executable), "worker", self.outer, measurement=value
            )
        self.assertEqual(status, 1)
        selected, unused = (task, episode) if fault is None else (episode, task)
        self.assertIs(selected.call_args.kwargs["observation"], observation)
        unused.assert_not_called()
        record = json.loads((self.root / "trial-isolation.json").read_text())
        self.assertEqual(record["mode"], "pilot")
        self.assertTrue(record["performance_samples"])

    def test_inside_keeps_default_and_boundary_validation_modes(self):
        for boundary_validation in (False, True):
            with (
                self.subTest(boundary_validation=boundary_validation),
                patch.dict(isolation.os.environ),
                patch.object(isolation, "require_private", return_value=self.inner),
                patch.object(isolation, "prepare_mounts", return_value={}),
                patch.object(isolation, "checked"),
                patch.object(isolation.subprocess, "check_output", return_value="1\n1\n1\n"),
                patch("harness.native_measurement.measured_observation") as measured,
                patch("harness.native_measurement.Observation") as bare,
                patch("harness.supervisor.run", return_value={"ok": True}) as task,
                patch.object(isolation.subprocess, "Popen", side_effect=AssertionError("launch")),
                redirect_stdout(io.StringIO()),
            ):
                status = isolation.inside(
                    self.path,
                    Path(sys.executable),
                    "worker",
                    self.outer,
                    boundary_validation=boundary_validation,
                )
                self.assertEqual(status, 0)
                measured.assert_not_called()
                if boundary_validation:
                    bare.assert_called_once_with()
                    self.assertIs(task.call_args.kwargs["observation"], bare.return_value)
                else:
                    bare.assert_not_called()
                    self.assertIsNone(task.call_args.kwargs["observation"])
                record = json.loads((self.root / "trial-isolation.json").read_text())
                self.assertEqual(record["mode"], "correctness-check")
                self.assertFalse(record["performance_samples"])

    def test_outer_launcher_forwards_configuration_and_retains_native_failure(self):
        value = configuration()
        native_result = {"ok": False, "error": {"type": "SyntheticFailure"}}
        (self.directory / "result.json").write_text(json.dumps(native_result))
        process = Mock()
        process.wait.return_value = 1
        with (
            patch.object(isolation, "namespace_ids", return_value=self.outer),
            patch.object(isolation.shutil, "which", return_value="/bin/true"),
            patch.object(isolation.subprocess, "Popen", return_value=process) as popen,
            patch.object(measure, "sample_window", side_effect=AssertionError("sampler")),
        ):
            result = isolation.run_isolated(
                self.path, Path(sys.executable), "worker", measurement=value
            )
        self.assertEqual(result, native_result)
        command = popen.call_args.args[0]
        self.assertEqual(json.loads(command[command.index("--measurement") + 1]), value)
        process.wait.assert_called_once_with(timeout=210)
        process.kill.assert_not_called()

    def test_watchdog_record_identifies_explicit_measurement_and_preserves_default(self):
        for measurement in (None, configuration()):
            with self.subTest(measured=measurement is not None):
                process = Mock(returncode=-9)
                process.wait.side_effect = [subprocess.TimeoutExpired("synthetic", 210), -9]
                with (
                    patch.object(isolation, "namespace_ids", return_value=self.outer),
                    patch.object(isolation.shutil, "which", return_value="/bin/true"),
                    patch.object(isolation.subprocess, "Popen", return_value=process),
                    self.assertRaises(TimeoutError),
                ):
                    isolation.run_isolated(
                        self.path, Path(sys.executable), "worker", measurement=measurement
                    )
                record = json.loads((self.directory / "outer-watchdog.json").read_text())
                self.assertEqual(record["performance_samples"], measurement is not None)
                if measurement is None:
                    self.assertNotIn("mode", record)
                else:
                    self.assertEqual(record["mode"], "pilot")
                self.assertFalse(record["inner_pid_numbers_consumed"])
                process.kill.assert_called_once_with()
                process.send_signal.assert_not_called()

    def test_cli_routes_explicit_measurement_to_both_entry_points(self):
        value = configuration()
        base = [
            "harness.isolation",
            "--manifest",
            str(self.path),
            "--python",
            sys.executable,
            "--measurement",
            json.dumps(value),
        ]
        for inner in (False, True):
            arguments = copy.deepcopy(base)
            if inner:
                arguments.extend(["--inside", "--outer-namespaces", json.dumps(self.outer)])
            with (
                self.subTest(inner=inner),
                patch.object(sys, "argv", arguments),
                patch.object(isolation, "inside", return_value=0) as inside,
                patch.object(isolation, "run_isolated", return_value={"ok": True}) as outer,
                redirect_stdout(io.StringIO()),
                self.assertRaises(SystemExit) as exit_context,
            ):
                isolation.main()
            self.assertEqual(exit_context.exception.code, 0)
            selected, unused = (inside, outer) if inner else (outer, inside)
            self.assertEqual(selected.call_args.kwargs["measurement"], value)
            unused.assert_not_called()


if __name__ == "__main__":
    unittest.main()
