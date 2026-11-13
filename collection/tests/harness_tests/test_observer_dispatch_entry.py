"""Exercise fresh-directory guards through real native entries and protocol workers."""

import fcntl
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from harness import episode, faults, measure, native_measurement, spec, supervisor
from harness import observer_dispatch as dispatch
from harness.resources import ProcessTarget

from harness_tests.test_episodes import clean
from harness_tests.test_measure import metadata

WORKERS = {
    "p4net": "harness.worker",
    "p4utils": "harness.worker_p4utils",
    "tutorial-components": "harness.worker_tutorial",
}
FIXTURE_WORKER = "harness_tests.fixtures.episode_worker"


class EntryVerified(Exception):
    """End the transport fixture after the actual native entry returns."""


def targets(manifest, worker, event):
    return [
        ProcessTarget(worker["pid"], worker["start_ticks"], "worker"),
        *[ProcessTarget(1_000_000 + i, i, "bmv2") for i in range(manifest["groups"])],
    ]


class DispatchEntryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)

    def create(self, name, *, groups=1, fault=None):
        path = spec.create(self.base / name, groups, configuration_profile="matched-v1")
        if fault is not None:
            manifest = spec.load(path)
            manifest["episode_fault"] = fault
            path.write_text(json.dumps(manifest))
        return path

    def configuration(self, path, *, tool="p4net", profile="B"):
        manifest = spec.load(path)
        values = metadata(manifest.get("episode_fault"))
        values.update(run_id=manifest["run_id"], tool=tool, switches=manifest["groups"])
        return {
            "mode": "pilot",
            "clock_domain": "directory-entry-fixture",
            "duration_ns": 10_000_000_000,
            "interval_ns": 100_000_000,
            "metadata": values,
            "observer_profile": profile,
            "attempt_id": "entry-fixture-1",
        }

    def assert_parent_controls_open(self, path):
        lock_path, log_path = dispatch.control_paths(path)
        self.assertEqual(lock_path.parent.resolve(), path.parent.parent.resolve())
        self.assertEqual(log_path.parent.resolve(), path.parent.parent.resolve())
        self.assertTrue(lock_path.is_file())
        self.assertTrue(log_path.is_file())
        with lock_path.open("a") as contender, self.assertRaises(BlockingIOError):
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        log_stat = log_path.stat()
        open_for_writing = False
        for descriptor in Path("/proc/self/fd").iterdir():
            try:
                fd = int(descriptor.name)
                descriptor_stat = os.fstat(fd)
                if (descriptor_stat.st_dev, descriptor_stat.st_ino) == (
                    log_stat.st_dev,
                    log_stat.st_ino,
                ):
                    open_for_writing |= (
                        fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE
                    ) != os.O_RDONLY
            except OSError:
                continue
        self.assertTrue(open_for_writing, "the dispatcher must still have its log open")

    def at_native_entry(self, path, callback, *, tool="p4net", profile="B"):
        checked = []

        def enter(candidate, python, worker, **kwargs):
            self.assertEqual(candidate, path.resolve())
            self.assertEqual(worker, WORKERS[tool])
            self.assertEqual(kwargs["observer_calibration"]["observer_profile"], profile)
            self.assert_parent_controls_open(candidate)
            callback(candidate)
            self.assert_parent_controls_open(candidate)
            checked.append(True)
            # The native entry has finished. No outer isolation process is needed.
            raise EntryVerified("native entry checked without calibration sampling")

        with (
            patch.object(dispatch.isolation, "environment_for", return_value=dict(os.environ)),
            patch.object(dispatch.isolation, "isolated_command", side_effect=enter) as command,
            patch.object(
                dispatch, "read_observer_cpu", side_effect=AssertionError("live CPU read")
            ) as cpu,
            patch.object(
                dispatch, "read_observer_memory", side_effect=AssertionError("live memory read")
            ) as memory,
            patch.object(measure, "sample_window", side_effect=AssertionError("live sampling")),
        ):
            result = dispatch.run_calibrated(
                path,
                Path(sys.executable),
                WORKERS[tool],
                calibration=self.configuration(path, tool=tool, profile=profile),
                collection_authorized=True,
            )
        self.assertEqual(checked, [True], result["error"])
        command.assert_called_once()
        cpu.assert_not_called()
        memory.assert_not_called()
        self.assertEqual(result["error"]["type"], "EntryVerified")
        self.assertIsNone(result["outer_pid"])
        self.assertIsNone(result["outer_launch_ns"])
        self.assertIsNone(result["outer_lifetime_ns"])
        return result

    def complete_native(self, path, *, fault=None):
        # Check the loader itself, then let the real entry run its own guard again.
        manifest = supervisor._load_manifest(path)
        self.assertEqual(Path(manifest["output_dir"]).resolve(), path.parent.resolve())
        self.assertEqual({item.name for item in path.parent.iterdir()}, {path.name})
        observer = native_measurement.Observation(select_targets=targets)
        if fault is None:
            result = supervisor.run(
                path,
                worker_command=[sys.executable, "-m", FIXTURE_WORKER, "--manifest", str(path)],
                ready_timeout=5,
                stop_timeout=5,
                audit_fn=clean,
                observation=observer,
            )
            self.assertTrue(result["ready"], result)
            self.assertEqual(len(result["checks"]), 2 * manifest["groups"])
            self.assertEqual(result["worker_returncode"], 0)
            self.assertTrue(result["cleanup"]["ordinary_after_clean"], result)
        else:
            with (
                patch.object(faults, "require_enclosure"),
                patch.object(episode.audit, "capture", side_effect=clean),
            ):
                result = episode.run_episode(
                    path, Path(sys.executable), FIXTURE_WORKER, observation=observer
                )
            self.assertTrue(result["framework_complete"], result)
            self.assertTrue(result["recovery_success"], result)
            for phase in ("initial", "restart"):
                self.assertEqual(len(result[phase]["checks"]), 2 * manifest["groups"])
                self.assertTrue(result[phase]["ordinary_cleanup_clean"], result)
                self.assertEqual(result[phase]["worker_returncode"], 0)
        self.assertTrue(result["ok"], result)
        self.assertFalse(result["performance_samples"])
        self.assertFalse(result["observation"]["performance_samples"])
        self.assertEqual(result["observation"]["issues"], [])
        self.assertNotIn("metrics", result["observation"])
        self.assertNotIn("resource_windows", result["observation"])

    def test_real_entries_accept_open_parent_controls_for_all_task_configurations(self):
        for tool in WORKERS:
            for profile in ("B", "T", "S"):
                for fault in (None, "normal-control"):
                    for groups in (1, 16):
                        with self.subTest(tool=tool, profile=profile, fault=fault, groups=groups):
                            path = self.create(
                                f"{tool}-{profile}-{fault}-{groups}", groups=groups, fault=fault
                            )
                            result = self.at_native_entry(
                                path,
                                lambda candidate, fault=fault: self.complete_native(
                                    candidate, fault=fault
                                ),
                                tool=tool,
                                profile=profile,
                            )
                            self.assertTrue(result["native_ok"], result)
                            self.assertEqual(
                                result["native_result_source"]["kind"], "ordinary-result"
                            )

    def add_record(self, directory, kind):
        path = directory / kind
        if kind == "unknown-directory":
            path.mkdir()
        elif kind == "dangling-link":
            path.symlink_to(directory / "missing-record")
        elif kind == "external-link":
            path.symlink_to(self.base / "outside-record")
        else:
            path.write_text("existing record\n")
        return path

    def assert_real_entries_reject(self, path):
        original = path.read_bytes()
        audit = Mock(side_effect=AssertionError("audit must follow the directory guard"))
        with (
            patch.object(faults, "require_enclosure"),
            patch.object(episode.audit, "capture", audit),
            patch.object(supervisor.subprocess, "Popen") as launch,
        ):
            with self.assertRaisesRegex(FileExistsError, "output_dir already contains"):
                supervisor._load_manifest(path)
            with self.assertRaisesRegex(FileExistsError, "output_dir already contains"):
                supervisor.run(path, audit_fn=audit)
            with self.assertRaisesRegex(FileExistsError, "episode directory already contains"):
                episode.run_episode(path, Path(sys.executable), FIXTURE_WORKER)
        launch.assert_not_called()
        audit.assert_not_called()
        self.assertEqual(path.read_bytes(), original)

    def test_real_entry_guards_reject_records_even_with_parent_controls_open(self):
        (self.base / "outside-record").write_text("external contents\n")
        for index, kind in enumerate(
            (
                ".observer-dispatch.lock",
                "observer-isolation.log",
                "unknown.json",
                "unknown-directory",
                "dangling-link",
                "external-link",
            )
        ):
            with self.subTest(kind=kind):
                path = self.create(f"stale-{index}", fault="normal-control")

                def reject(candidate, kind=kind):
                    record = self.add_record(candidate.parent, kind)
                    self.assert_real_entries_reject(candidate)
                    self.assertTrue(os.path.lexists(record))

                result = self.at_native_entry(path, reject)
                self.assertFalse(result["native_outcome_available"])
                self.assertIsNone(result["native_ok"])
        self.assertEqual((self.base / "outside-record").read_text(), "external contents\n")

    def test_parent_rejects_existing_inside_records_before_transport_or_worker(self):
        for index, kind in enumerate(
            (".observer-dispatch.lock", "observer-isolation.log", "unknown.json", "dangling-link")
        ):
            with self.subTest(kind=kind):
                path = self.create(f"existing-{index}", fault="normal-control")
                record = self.add_record(path.parent, kind)
                self.assert_real_entries_reject(path)
                with (
                    patch.object(dispatch.isolation, "environment_for") as environment,
                    patch.object(dispatch.isolation, "isolated_command") as command,
                    patch.object(dispatch.subprocess, "Popen") as launch,
                    self.assertRaises(FileExistsError),
                ):
                    dispatch.run_calibrated(
                        path,
                        Path(sys.executable),
                        WORKERS["p4net"],
                        calibration=self.configuration(path),
                        collection_authorized=True,
                    )
                environment.assert_not_called()
                command.assert_not_called()
                launch.assert_not_called()
                self.assertTrue(os.path.lexists(record))
                self.assertFalse(dispatch.control_paths(path)[1].exists())

    def test_relative_and_directory_alias_paths_reach_real_entries(self):
        for alias in (False, True):
            for fault in (None, "normal-control"):
                with self.subTest(alias=alias, fault=fault):
                    path = self.create(f"canonical-{alias}-{fault}", fault=fault)
                    if alias:
                        link = self.base / f"alias-{fault}"
                        link.symlink_to(path.parent, target_is_directory=True)
                        path = link / path.name
                    else:
                        path = Path(os.path.relpath(path))
                    result = self.at_native_entry(
                        path,
                        lambda candidate, fault=fault: self.complete_native(candidate, fault=fault),
                    )
                    self.assertTrue(result["native_ok"], result)


if __name__ == "__main__":
    unittest.main()
