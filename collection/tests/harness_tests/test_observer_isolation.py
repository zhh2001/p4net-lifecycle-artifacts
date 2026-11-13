"""Check calibration descriptor ownership and native publication using mocked workers."""

import io
import json
import os
import socket
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout, suppress
from pathlib import Path
from unittest.mock import Mock, patch

from harness import isolation, spec

from harness_tests.test_measure import metadata


class CalibrationIsolationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.path = spec.create(self.base / "run", configuration_profile="matched-v1")
        self.manifest = spec.load(self.path)
        self.outer = {kind: f"{kind}:[1]" for kind in isolation.NAMESPACES}
        self.inner = {kind: f"{kind}:[2]" for kind in isolation.NAMESPACES}
        self.configuration = {
            "observer_profile": "S",
            "attempt_id": "attempt-1",
            "mode": "pilot",
            "clock_domain": "linux-monotonic",
            "duration_ns": 10_000_000_000,
            "interval_ns": 100_000_000,
            "metadata": {**metadata(), "run_id": self.manifest["run_id"]},
        }
        self.deadline = 1_000_000.0

    def descriptor(self):
        parent, child = socket.socketpair()
        self.addCleanup(parent.close)
        descriptor = child.detach()
        self.addCleanup(self.close_if_open, descriptor, os.fstat(descriptor).st_ino)
        os.set_inheritable(descriptor, True)
        return descriptor

    @staticmethod
    def close_if_open(descriptor, inode):
        with suppress(OSError):
            if os.fstat(descriptor).st_ino == inode:
                os.close(descriptor)

    def setup_patches(self, *, private=None):
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.dict(isolation.os.environ))
        stack.enter_context(
            patch.object(isolation, "require_private", side_effect=private, return_value=self.inner)
        )
        stack.enter_context(patch.object(isolation, "prepare_mounts", return_value={}))
        stack.enter_context(patch.object(isolation, "checked"))
        stack.enter_context(
            patch.object(isolation.subprocess, "check_output", return_value="1\n1\n1\n")
        )
        stack.enter_context(redirect_stdout(io.StringIO()))
        return stack

    def test_calibration_command_keeps_default_prefix_and_round_trips_reference_fields(self):
        with patch.object(isolation, "namespace_ids", return_value=self.outer):
            default = isolation.isolated_command(self.path, Path(sys.executable), "worker")
            calibrated = isolation.isolated_command(
                self.path,
                Path(sys.executable),
                "worker",
                observer_calibration=self.configuration,
                reference_fd=42,
                reference_deadline=self.deadline,
            )
        self.assertEqual(calibrated[:-6], default)
        self.assertEqual(json.loads(calibrated[-5]), self.configuration)
        self.assertEqual(
            calibrated[-4:], ["--reference-fd", "42", "--reference-deadline", "1000000.0"]
        )
        self.assertNotIn("--measurement", calibrated)
        self.assertNotIn("--validate-boundaries", calibrated)

    def test_reference_fields_are_required_together_before_namespace_or_socket_work(self):
        cases = (
            {"observer_calibration": self.configuration},
            {"reference_fd": 42},
            {"reference_deadline": self.deadline},
            {"observer_calibration": self.configuration, "reference_fd": 42},
            {"reference_fd": 42, "reference_deadline": self.deadline},
        )
        with (
            patch.object(isolation, "require_private") as private,
            patch.object(isolation, "namespace_ids") as namespaces,
            patch.object(isolation.socket, "socket") as connection,
        ):
            for case in cases:
                for function, arguments in (
                    (isolation.inside, (self.path, Path(sys.executable), "worker", self.outer)),
                    (isolation.isolated_command, (self.path, Path(sys.executable), "worker")),
                ):
                    with (
                        self.subTest(case=case, function=function.__name__),
                        self.assertRaises(ValueError),
                    ):
                        function(*arguments, **case)
            private.assert_not_called()
            namespaces.assert_not_called()
            connection.assert_not_called()

    def test_invalid_descriptor_deadline_and_observation_combinations_reject_before_setup(self):
        arguments = {
            "observer_calibration": self.configuration,
            "reference_fd": 42,
            "reference_deadline": self.deadline,
        }
        cases = (
            {"reference_fd": True},
            {"reference_fd": 2},
            {"reference_fd": -1},
            {"reference_deadline": True},
            {"reference_deadline": 0},
            {"reference_deadline": float("nan")},
            {"reference_deadline": float("inf")},
            {"boundary_validation": True},
            {"measurement": {}},
        )
        with (
            patch.object(isolation, "require_private") as private,
            patch.object(isolation.socket, "socket") as connection,
        ):
            for case in cases:
                with self.subTest(case=case), self.assertRaises(ValueError):
                    isolation.inside(
                        self.path,
                        Path(sys.executable),
                        "worker",
                        self.outer,
                        **{**arguments, **case},
                    )
            private.assert_not_called()
            connection.assert_not_called()

    def check_calibration_dispatch(self, profile, fault):
        self.configuration["observer_profile"] = profile
        if fault:
            self.manifest["episode_fault"] = fault
            self.path.write_text(json.dumps(self.manifest))
            self.configuration["metadata"].update(workload="fault", fault=fault)
        descriptor = self.descriptor()
        stages = []
        messages = []
        supplied = {}
        observer = Mock()
        channel = Mock()

        def private(_expected):
            self.assertFalse(os.get_inheritable(descriptor))
            stages.append("private")
            return self.inner

        def send(message):
            messages.append(message)
            if message["boundary"] == "ref_begin":
                stages.append("begin")
            if message["boundary"] == "ref_complete":
                self.assertTrue((self.path.parent / "result.json").is_file())
                self.assertTrue((self.path.parent / "observer-child-result.json").is_file())

        channel.send.side_effect = send
        channel.receive.side_effect = lambda: {
            **messages[-1],
            "record_type": "observer-reference-ack",
        }

        def factory(*args, **kwargs):
            self.assertEqual(stages, ["private", "begin"])
            self.assertEqual(args, (profile, self.configuration["metadata"]))
            self.assertEqual(kwargs["mode"], "pilot")
            self.assertEqual(kwargs["duration_ns"], 10_000_000_000)
            self.assertEqual(kwargs["interval_ns"], 100_000_000)
            self.assertIs(kwargs["clock_ns"], isolation.time.monotonic_ns)
            self.assertIs(kwargs["sleep"], isolation.time.sleep)
            supplied.update(kwargs)
            stages.append("constructed")
            return observer

        def task(*args, **kwargs):
            self.assertIs(kwargs["observation"], observer)
            self.assertEqual(stages[-1], "constructed")
            primary = self.path.parent / "measurement-primary.json"
            primary.write_text("{}\n")
            supplied["on_primary_published"](primary)
            return {"ok": False, "fixture": True}

        def run_child(path, reference, *, mode, build_observation, run_task):
            self.assertEqual(path.name, "observer-child-result.json")
            self.assertEqual(mode, "pilot")
            self.assertEqual(reference.binding["observer_profile"], profile)
            self.assertEqual(
                reference.namespaces, {kind: self.inner[kind] for kind in ("pid", "net", "mnt")}
            )
            reference.checkpoint("ref_begin")
            observation = build_observation(
                lambda _path: reference.checkpoint("ref_primary_published")
            )
            result = run_task(observation)
            path.write_text(json.dumps({"native_result": result}))
            reference.checkpoint("ref_complete")
            return {"native_result": result}

        self.setup_patches(private=private)
        with (
            patch(
                "harness.observer_dispatch.SocketChannel", return_value=channel
            ) as channel_factory,
            patch("harness.observer_profiles.profile_observation", side_effect=factory),
            patch("harness.observer_runtime.run_child", side_effect=run_child),
            patch("harness.supervisor.run", side_effect=task) as scale,
            patch("harness.episode.run_episode", side_effect=task) as episode,
            patch.object(
                isolation.subprocess, "Popen", side_effect=AssertionError("native launch")
            ),
        ):
            status = isolation.inside(
                self.path,
                Path(sys.executable),
                "worker",
                self.outer,
                observer_calibration=self.configuration,
                reference_fd=descriptor,
                reference_deadline=self.deadline,
            )
        self.assertEqual(status, 1)
        self.assertEqual(stages, ["private", "begin", "constructed"])
        selected, unused = (episode, scale) if fault else (scale, episode)
        selected.assert_called_once()
        unused.assert_not_called()
        self.assertEqual(
            [item["boundary"] for item in messages],
            ["ref_begin", "ref_primary_published", "ref_complete"],
        )
        self.assertEqual(channel_factory.call_args.kwargs, {"deadline": self.deadline})
        self.assertEqual(channel_factory.call_args.args[0].fileno(), -1)
        record = json.loads((self.base / "run-isolation.json").read_text())
        self.assertEqual(record["observer_profile"], profile)
        self.assertTrue(record["performance_samples"])
        self.assertFalse(json.loads((self.path.parent / "result.json").read_text())["ok"])
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_scale_path_constructs_each_profile_after_begin_and_preserves_native_failure(self):
        for profile in ("B", "T", "S"):
            with self.subTest(profile=profile):
                self.check_calibration_dispatch(profile, None)

    def test_episode_path_uses_calibrated_observation_and_publishes_before_complete(self):
        self.check_calibration_dispatch("S", "normal-control")

    def test_reference_socket_closes_when_private_namespace_validation_fails(self):
        descriptor = self.descriptor()
        with (
            patch.object(isolation, "require_private", side_effect=RuntimeError("not private")),
            self.assertRaisesRegex(RuntimeError, "not private"),
        ):
            isolation.inside(
                self.path,
                Path(sys.executable),
                "worker",
                self.outer,
                observer_calibration=self.configuration,
                reference_fd=descriptor,
                reference_deadline=self.deadline,
            )
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_reference_socket_closes_when_channel_construction_fails(self):
        descriptor = self.descriptor()
        self.setup_patches()
        with (
            patch("harness.observer_dispatch.SocketChannel", side_effect=TimeoutError("expired")),
            self.assertRaisesRegex(TimeoutError, "expired"),
        ):
            isolation.inside(
                self.path,
                Path(sys.executable),
                "worker",
                self.outer,
                observer_calibration=self.configuration,
                reference_fd=descriptor,
                reference_deadline=self.deadline,
            )
        with self.assertRaises(OSError):
            os.fstat(descriptor)
        self.assertFalse((self.path.parent / "result.json").exists())

    def test_begin_ack_failure_closes_descriptor_before_profile_or_worker_construction(self):
        descriptor = self.descriptor()
        self.setup_patches()
        channel = Mock()
        channel.receive.side_effect = EOFError("parent closed")
        with (
            patch("harness.observer_dispatch.SocketChannel", return_value=channel),
            patch("harness.observer_profiles.profile_observation") as factory,
            patch("harness.supervisor.run") as task,
            self.assertRaisesRegex(EOFError, "parent closed"),
        ):
            isolation.inside(
                self.path,
                Path(sys.executable),
                "worker",
                self.outer,
                observer_calibration=self.configuration,
                reference_fd=descriptor,
                reference_deadline=self.deadline,
            )
        factory.assert_not_called()
        task.assert_not_called()
        self.assertFalse((self.path.parent / "result.json").exists())
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_worker_exception_closes_reference_without_publishing_final_results(self):
        descriptor = self.descriptor()
        self.configuration["observer_profile"] = "B"
        self.setup_patches()
        channel, messages = Mock(), []
        channel.send.side_effect = messages.append
        channel.receive.side_effect = lambda: {
            **messages[-1],
            "record_type": "observer-reference-ack",
        }
        with (
            patch("harness.observer_dispatch.SocketChannel", return_value=channel),
            patch("harness.supervisor.run", side_effect=RuntimeError("worker exception")),
            patch.object(
                isolation.time, "monotonic_ns", side_effect=AssertionError("sampling clock")
            ),
            self.assertRaisesRegex(RuntimeError, "worker exception"),
        ):
            isolation.inside(
                self.path,
                Path(sys.executable),
                "worker",
                self.outer,
                observer_calibration=self.configuration,
                reference_fd=descriptor,
                reference_deadline=self.deadline,
            )
        self.assertEqual([message["boundary"] for message in messages], ["ref_begin"])
        self.assertFalse((self.path.parent / "result.json").exists())
        self.assertFalse((self.path.parent / "observer-child-result.json").exists())
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_environment_helper_preserves_native_launcher_settings_and_removes_ovs_options(self):
        with (
            patch.dict(isolation.os.environ, {"PATH": "/bin", "OVS_OPTION": "unsafe"}, clear=True),
            patch.object(isolation.shutil, "which", return_value="/bin/true"),
        ):
            environment = isolation.environment_for(self.manifest)
        self.assertNotIn("OVS_OPTION", environment)
        self.assertEqual(environment["P4NET_STUDY_RUN_DIR"], self.manifest["output_dir"])
        self.assertEqual(environment["P4NET_STUDY_BMV2_REAL"], "/usr/bin/true")
        self.assertEqual(environment["PYTHONPATH"], str(isolation.PAPER))
        self.assertEqual(environment["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"], "python")
        self.assertEqual(
            environment["PATH"], str(isolation.PAPER / "harness/bin") + os.pathsep + "/bin"
        )

    def test_calibration_cli_arguments_cannot_start_an_unacknowledged_outer_run(self):
        command = [
            "isolation",
            "--manifest",
            str(self.path),
            "--python",
            sys.executable,
            "--observer-calibration",
            json.dumps(self.configuration),
            "--reference-fd",
            "42",
            "--reference-deadline",
            str(self.deadline),
        ]
        with (
            patch.object(sys, "argv", command),
            patch.object(isolation, "run_isolated") as run,
            redirect_stdout(io.StringIO()),
            patch("sys.stderr", io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            isolation.main()
        self.assertEqual(raised.exception.code, 2)
        run.assert_not_called()
