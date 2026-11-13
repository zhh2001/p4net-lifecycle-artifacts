"""Check native campaign adapter gates with temporary files and mocked launches."""

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import campaign, campaign_executor, campaign_inputs, spec, worker_components

from harness_tests import test_campaign_executor as fixtures


class CampaignNativeAdapterTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.output = self.base / "output"
        self.proc = self.base / "proc-fixture"
        self.proc.mkdir()
        self.plan = campaign.generate(sessions=1, repetitions_per_session=1)
        self.plan_path = fixtures.write(self.base / "campaign.json", self.plan)
        source = fixtures.write(self.base / "harness/worker.py", {"fixture": "worker"})
        workload = fixtures.write(self.base / "harness/workloads/l3.p4", {"fixture": "P4"})
        launcher = fixtures.write(self.base / "harness/bin/simple_switch_grpc", {})
        self.sources = [source, workload, launcher]
        self.environments = {}
        for label in ("p4net310", "p4utils310", "tutorial310"):
            executable = fixtures.write(self.base / f"deps/{label}/bin/python", {})
            self.environments[label] = fixtures.write(
                self.base / f"deps/{label}/environment.json",
                {
                    "version_info": [3, 10, 20, "final", 0],
                    "executable": "bin/python",
                    "interpreter_identity": {"path": str(executable)},
                },
            )
        self.tool_paths = {
            name: fixtures.write(self.base / "tools" / name, {})
            for name in ("p4c", "simple_switch_grpc", "unshare")
        }
        fixtures.write(
            self.base / "deps/tools.json",
            {name: {"real_path": str(path)} for name, path in self.tool_paths.items()},
        )
        fixtures.write(self.base / "deps/mininet.json", {})
        artifact = fixtures.write(self.base / "fixture.whl", {})
        self.dependency = fixtures.write(
            self.base / "deps/manifest.json",
            {
                "environment_files": {
                    label: f"{label}/environment.json" for label in self.environments
                },
                "tools_file": "tools.json",
                "mininet_source_file": "mininet.json",
                "artifacts": {
                    "fixture": {"path": "../fixture.whl", "sha256": fixtures.digest(artifact)}
                },
            },
        )
        wrapper_python = fixtures.write(self.base / "tools/wrapper-python", {})
        component_root = self.base / "extracted-tutorial-utils"
        for name in worker_components.REQUIRED:
            fixtures.write(component_root / name, {})
        self.components = fixtures.write(
            self.base / "worker-components.json", worker_components.build_manifest(component_root)
        )
        self.control = fixtures.write(
            self.base / "control.json",
            {
                "campaign": {"path": "campaign.json", "sha256": fixtures.digest(self.plan_path)},
                "dependency_freeze": {
                    "path": "deps/manifest.json",
                    "sha256": fixtures.digest(self.dependency),
                },
                "sources": {
                    str(path.relative_to(self.base)): fixtures.digest(path) for path in self.sources
                },
                "wrapper_interpreter": {
                    "path": str(wrapper_python),
                    "sha256": fixtures.digest(wrapper_python),
                },
                "worker_components": {
                    "path": str(self.components),
                    "sha256": fixtures.digest(self.components),
                },
            },
        )
        self.binding = self.build()
        for name in (
            "subprocess.run",
            "subprocess.Popen",
            "socket.socket",
            "harness.measure.sample_window",
            "harness.measure.time.monotonic_ns",
            "harness.resources.read_sample",
        ):
            self.mock(name, side_effect=AssertionError(f"unexpected live operation: {name}"))
        self.launch = self.mock(
            "harness.isolation.run_isolated", side_effect=AssertionError("unexpected launch")
        )
        self.create = self.mock("harness.spec.create", side_effect=self.create_manifest)
        self.verify_environment = self.mock("harness.campaign_inputs.verify_native_environment")
        self.mock("harness.campaign_executor.os.geteuid", return_value=0)
        self.lookup = self.mock(
            "harness.campaign_executor.shutil.which",
            side_effect=lambda name: str(self.tool_paths[name]),
        )

        def redirected_path(value):
            return self.proc if value == "/proc" else Path(value)

        self.mock("harness.campaign_executor.Path", side_effect=redirected_path)

    def mock(self, target, **kwargs):
        patcher = patch(target, **kwargs)
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def build(self, mode="pilot"):
        return campaign_inputs.build_binding(
            self.plan_path,
            self.control,
            self.dependency,
            self.sources,
            mode=mode,
            base=self.base,
            duration_ns=2000,
            interval_ns=100,
        )

    def executor(self, binding=None):
        return campaign_executor.Campaign(self.output, binding or self.binding, base=self.base)

    def attempt(self, *, tool="p4net", phase="fault", fault="kill-bmv2"):
        entry = next(
            entry
            for entry in self.plan[phase + "_schedule"]
            if entry["tool"] == tool and (phase == "scale" or entry["fault"] == fault)
        )
        executor = self.executor()
        metadata = executor._metadata(phase, entry, 1, "a" * 32)
        directory = self.output / "attempts" / metadata["planned_id"] / "0001"
        directory.mkdir(parents=True)
        return campaign_executor.Attempt(directory, {"metadata": metadata})

    def create_manifest(self, output, groups, source, configuration_profile):
        self.assertFalse(output.exists())
        hosts, switches = spec.names("r000000", groups)
        return fixtures.write(
            output / "manifest.json",
            {
                "schema_version": 1,
                "purpose": "functional-check",
                "configuration_profile": configuration_profile,
                "run_id": "b" * 32,
                "prefix": "r000000",
                "groups": groups,
                "host_names": hosts,
                "switch_names": switches,
                "service_ports": list(range(20000, 20000 + 2 * groups)),
                "p4_source": str(source.resolve()),
                "source_sha256": fixtures.digest(source),
                "output_dir": str(output.resolve()),
            },
        )

    def prepared_backend(self, mode="pilot"):
        backend = campaign_executor.NativeBackend(mode, base=self.base)
        backend.preflight(self.output, self.binding)
        return backend

    def test_bound_interpreters_parent_episode_and_measurement_config_reach_isolation(self):
        for tool, label, worker in (
            ("p4net", "p4net310", "harness.worker"),
            ("p4utils", "p4utils310", "harness.worker_p4utils"),
            ("tutorial-components", "tutorial310", "harness.worker_tutorial"),
        ):
            with self.subTest(tool=tool):
                attempt = self.attempt(tool=tool)
                self.assertFalse(attempt.artifacts.exists())
                backend = self.prepared_backend()
                native_result = {"observation": {"fixture": tool}, "native_fixture": True}

                def isolated(
                    path,
                    python,
                    module,
                    *,
                    measurement,
                    expected_attempt=attempt,
                    expected_label=label,
                    expected_worker=worker,
                    retained=native_result,
                ):
                    manifest = spec.load(path)
                    self.assertEqual(manifest["run_id"], expected_attempt.metadata["run_id"])
                    self.assertEqual(manifest["episode_fault"], "kill-bmv2")
                    self.assertEqual(manifest["groups"], 4)
                    self.assertEqual(list(expected_attempt.artifacts.iterdir()), [path])
                    self.assertEqual(
                        python, self.environments[expected_label].parent / "bin/python"
                    )
                    self.assertEqual(module, expected_worker)
                    self.assertEqual(
                        measurement,
                        {
                            "mode": "pilot",
                            "metadata": expected_attempt.metadata,
                            "clock_domain": "observer-monotonic-ns-v1",
                            "duration_ns": 2000,
                            "interval_ns": 100,
                        },
                    )
                    self.assertEqual(len(measurement["metadata"]["planned_execution_ids"]), 2)
                    return retained

                self.launch.side_effect = isolated
                response = backend(attempt)
                self.assertEqual(response["measurement"], native_result["observation"])
                self.assertIs(response["native_result"], native_result)
                self.create.assert_called_with(
                    attempt.artifacts,
                    groups=4,
                    source=self.base / "harness/workloads/l3.p4",
                    configuration_profile="matched-v1",
                )
        self.assertEqual(self.launch.call_count, 3)
        self.assertEqual(self.verify_environment.call_count, 3)

    def test_scale_manifest_has_no_episode_fault_or_restart_execution(self):
        attempt = self.attempt(phase="scale")
        backend = self.prepared_backend()
        self.launch.side_effect = None
        self.launch.return_value = {"observation": {"fixture": "scale"}}
        backend(attempt)
        manifest = spec.load(attempt.artifacts / "manifest.json")
        self.assertNotIn("episode_fault", manifest)
        self.assertEqual(self.launch.call_args.kwargs["measurement"]["metadata"], attempt.metadata)
        self.assertEqual(attempt.metadata["planned_execution_ids"], [])

    def test_native_backend_requires_preflight_before_creating_artifacts(self):
        attempt = self.attempt()
        backend = campaign_executor.NativeBackend("pilot", base=self.base)
        with self.assertRaisesRegex(RuntimeError, "preflight"):
            backend(attempt)
        self.create.assert_not_called()
        self.launch.assert_not_called()
        self.assertFalse(attempt.artifacts.exists())

    def test_wrong_worker_python_version_prevents_isolation(self):
        attempt = self.attempt()
        environment = fixtures.read(self.environments["p4net310"])
        environment["version_info"] = [3, 11, 0]
        fixtures.write(self.environments["p4net310"], environment)
        self.binding = self.build()
        backend = self.prepared_backend()
        with self.assertRaisesRegex(ValueError, "Python version"):
            backend(attempt)
        self.launch.assert_not_called()

    def test_worker_executable_must_match_the_bound_interpreter_path(self):
        attempt = self.attempt()
        environment = fixtures.read(self.environments["p4net310"])
        environment["executable"] = "other/python"
        fixtures.write(self.environments["p4net310"], environment)
        self.binding = self.build()
        backend = self.prepared_backend()
        with self.assertRaisesRegex(ValueError, "pinned interpreter"):
            backend(attempt)
        self.launch.assert_not_called()

    def test_path_shadowing_rejects_batch_before_preparation_or_launch(self):
        backend = campaign_executor.NativeBackend("pilot", base=self.base)
        self.lookup.side_effect = lambda name: str(self.base / "shadow" / name)
        with self.assertRaisesRegex(ValueError, "tool lookup"):
            backend.preflight(self.output, self.binding)
        self.assertIsNone(backend.binding)
        self.create.assert_not_called()
        self.launch.assert_not_called()

    def test_path_is_checked_again_before_each_native_case(self):
        attempt = self.attempt()
        backend = self.prepared_backend()
        self.lookup.side_effect = lambda name: str(self.base / "shadow" / name)
        with self.assertRaisesRegex(ValueError, "tool lookup"):
            backend(attempt)
        self.create.assert_not_called()
        self.launch.assert_not_called()

    def test_existing_enclosure_in_fixture_proc_blocks_preflight(self):
        attempt = self.attempt()
        process = self.proc / "8123"
        process.mkdir()
        manifest = attempt.artifacts / "manifest.json"
        (process / "cmdline").write_bytes(b"unshare\0--manifest\0" + str(manifest).encode() + b"\0")
        backend = campaign_executor.NativeBackend("pilot", base=self.base)
        with self.assertRaisesRegex(RuntimeError, "still running"):
            backend.preflight(self.output, self.binding)
        self.assertIsNone(backend.binding)
        self.create.assert_not_called()
        self.launch.assert_not_called()

    def test_unrelated_or_disappearing_fixture_process_does_not_block_preflight(self):
        unrelated = self.proc / "123"
        unrelated.mkdir()
        (unrelated / "cmdline").write_bytes(b"unshare\0--manifest\0/unrelated/manifest.json\0")
        (self.proc / "456").mkdir()
        (self.proc / "self").mkdir()
        backend = self.prepared_backend()
        self.assertEqual(backend.binding, self.binding)
        self.launch.assert_not_called()

    def test_native_backend_rejects_synthetic_mode_and_synthetic_campaign_binding(self):
        with self.assertRaisesRegex(ValueError, "native-validation, pilot, or formal"):
            campaign_executor.NativeBackend("synthetic-validation", base=self.base)
        binding = self.build(mode="synthetic-validation")
        backend = campaign_executor.NativeBackend("pilot", base=self.base)
        with self.executor(binding) as executor, self.assertRaisesRegex(ValueError, "mode differs"):
            executor.run("scale", 1, backend, limit=1)
        self.verify_environment.assert_not_called()
        self.create.assert_not_called()
        self.launch.assert_not_called()
        self.assertEqual(list((self.output / "attempts").iterdir()), [])

    def test_formal_config_is_preserved_by_the_mocked_adapter(self):
        self.binding = self.build(mode="formal")
        attempt = self.attempt()
        backend = self.prepared_backend(mode="formal")
        self.launch.side_effect = None
        self.launch.return_value = {"observation": {"fixture": "formal"}}
        backend(attempt)
        self.assertEqual(self.launch.call_args.kwargs["measurement"]["mode"], "formal")


class CampaignOrphanTerminalTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.CampaignExecutorTests(methodName="runTest")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()

    def test_unclaimed_terminal_cannot_hide_backend_reference_or_outcome_files(self):
        fixture = self.fixture
        with fixture.executor() as executor:
            directory = fixture.directory()
            directory.mkdir(parents=True)
            executor.reconcile()
        result_path = directory / "result.json"
        original = fixtures.read(result_path)
        for hidden in ("backend_reference", "backend-result.json", "measurement.json"):
            with self.subTest(hidden=hidden):
                terminal = copy.deepcopy(original)
                if hidden == "backend_reference":
                    terminal["backend_result"] = {
                        "path": "backend-result.json",
                        "sha256": "f" * 64,
                    }
                else:
                    fixtures.write(directory / hidden, {"hidden": "outcome"})
                fixtures.write(result_path, terminal)
                before = {path.name: path.read_bytes() for path in directory.iterdir()}
                backend = fixtures.RecordingBackend()
                with (
                    fixture.executor() as executor,
                    self.assertRaisesRegex(ValueError, "unclaimed terminal"),
                ):
                    executor.run("scale", 1, backend, limit=1)
                self.assertEqual(backend.calls, [])
                self.assertEqual(
                    {path.name: path.read_bytes() for path in directory.iterdir()}, before
                )
                if hidden != "backend_reference":
                    (directory / hidden).unlink()
                fixtures.write(result_path, original)


if __name__ == "__main__":
    unittest.main()
