"""Join injected profiles and reference endpoints without native sampling."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from harness import observer_runtime as runtime
from harness.observer_profiles import profile_observation
from harness.observer_reference import ChildReference, ObserverIdentity, ParentReference

from harness_tests.test_measure import Clock, metadata, observation
from harness_tests.test_observer_profiles import TARGETS


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.result = self.base / "child.json"
        self.primary = self.base / "primary.json"
        self.sidecar = self.base / "reference.json"
        self.terminal = self.base / "terminal.json"
        self.clock = Clock()
        self.log = []
        self.responses = []
        self.profile = "S"
        self.native_ok = True
        self.emit_primary = True
        self.identity = ObserverIdentity(
            1234, 10, {"pid": "pid:[1]", "net": "net:[2]", "mnt": "mnt:[3]"}
        )

    def reference(self):
        def cpu(identity):
            self.log.append("cpu")
            self.clock.now += 11
            return {
                "observer": identity.as_dict(),
                "user_ticks": self.clock.now // 10_000_000,
                "system_ticks": 0,
                "cpu_ticks": self.clock.now // 10_000_000,
            }

        def memory(identity):
            self.log.append("memory")
            self.assertTrue(self.result.is_file())
            self.clock.now += 5000
            return {"observer": identity.as_dict(), "rss_bytes": 4096, "pss_bytes": 2048}

        def acknowledge(message):
            self.log.append(message["boundary"])
            if message["boundary"] == "ref_primary_published":
                self.assertTrue(self.primary.is_file())
            if message["boundary"] == "ref_complete":
                self.assertTrue(self.result.is_file())
            self.responses.append(message)

        parent = ParentReference(
            self.identity,
            run_id="synthetic-run",
            attempt_id="attempt-1",
            profile=self.profile,
            clock_ns=self.clock,
            monitor_cpu_ns=lambda: self.clock.now // 10,
            clock_ticks=100,
            read_cpu=cpu,
            read_memory=memory,
            send_ack=acknowledge,
        )
        child = ChildReference(
            run_id="synthetic-run",
            attempt_id="attempt-1",
            profile=self.profile,
            namespaces=self.identity.namespaces,
            send=parent.handle,
            receive=lambda: self.responses.pop(0),
        )
        return child, parent

    def build(self, callback):
        self.assertEqual(self.log[-1], "ref_begin")
        self.log.append("construct")
        return profile_observation(
            self.profile,
            metadata(),
            mode="synthetic-validation",
            clock_domain="synthetic-clock",
            clock_ns=self.clock,
            sleep=self.clock.sleep,
            read=observation,
            select_targets=lambda *_: TARGETS,
            on_primary_published=callback,
        )

    def task(self, observer):
        self.log.append("task")
        manifest = {"run_id": "synthetic-run", "groups": 1, "configuration_profile": "matched-v1"}
        observer.bind(manifest)
        observer.mark("worker_launch")
        observer.received({"event": "ready"}, observed_ns=self.clock())
        observer.ready(manifest, {}, {})
        for boundary in (
            "stop_request",
            "stop_sent",
            "worker_exit",
            "ordinary_audit_start",
            "ordinary_audit_end",
        ):
            observer.mark(boundary)
        result = {"ok": self.native_ok, "run_id": "synthetic-run"}
        if self.emit_primary:
            observer.checkpoint(self.primary, result)
        self.clock.now += 77
        return result

    def run_child(self, child, **kwargs):
        return runtime.run_synthetic_child(
            self.result,
            child,
            build_observation=kwargs.get("build_observation", self.build),
            run_task=kwargs.get("run_task", self.task),
        )

    def assert_profile_publication(self, profile):
        self.profile = profile
        child_ref, parent = self.reference()
        original_publish = runtime._publish

        def publish(path, record):
            original_publish(path, record)
            self.clock.now += 500

        unexpected = Mock(side_effect=AssertionError("unexpected live operation"))
        with (
            patch("subprocess.Popen", unexpected),
            patch("time.monotonic_ns", unexpected),
            patch.object(runtime, "_publish", side_effect=publish),
        ):
            child = self.run_child(child_ref)
        unexpected.assert_not_called()
        frozen = self.result.read_bytes()
        terminal = runtime.publish_terminal(self.terminal, self.result, self.sidecar, parent)
        record = json.loads(self.sidecar.read_bytes())
        self.assertEqual(self.result.read_bytes(), frozen)
        self.assertEqual(record["child_result"]["sha256"], hashlib.sha256(frozen).hexdigest())
        self.assertTrue(child["native_result"]["ok"])
        self.assertEqual(terminal["reference_status"], "complete")
        self.assertFalse(terminal["performance_samples"])
        self.assertEqual(child_ref.index, 3)
        self.assertEqual(record["observer_body_wall_ns"], 10_000_000_577)
        self.assertLess(record["wall_end_ns"], self.clock.now)
        self.assertEqual(self.log[:4], ["cpu", "ref_begin", "construct", "task"])
        self.assertEqual(self.log[-3:], ["cpu", "memory", "ref_complete"])
        hold = child["profile_observation"]["holds"]["initial"]
        self.assertEqual(hold["requested_duration_ns"], 10_000_000_000)
        self.assertTrue(hold["complete"])

    def test_boundary_profile_publication(self):
        self.assert_profile_publication("B")

    def test_timestamp_profile_publication(self):
        self.assert_profile_publication("T")

    def test_sampled_profile_publication(self):
        self.assert_profile_publication("S")

    def test_native_failure_is_preserved_with_complete_reference(self):
        self.native_ok = False
        child, parent = self.reference()
        self.run_child(child)
        terminal = runtime.publish_terminal(self.terminal, self.result, self.sidecar, parent)
        self.assertFalse(terminal["native_ok"])
        self.assertEqual(terminal["reference_status"], "complete")

    def test_no_primary_produces_an_incomplete_reference_without_zero_endpoints(self):
        self.emit_primary = False
        child, parent = self.reference()
        result = self.run_child(child)
        terminal = runtime.publish_terminal(self.terminal, self.result, self.sidecar, parent)
        self.assertTrue(result["native_result"]["ok"])
        self.assertEqual(terminal["reference_status"], "incomplete")
        self.assertIsNone(terminal["reference_sidecar"])
        self.assertFalse(self.sidecar.exists())
        self.assertEqual(self.log.count("cpu"), 1)
        self.assertNotIn("memory", self.log)
        with self.assertRaises(ValueError):
            parent.record()

    def test_primary_write_failure_cannot_close_reference_endpoints(self):
        child, parent = self.reference()
        with patch("harness.measure.write_record", side_effect=OSError("disk full")):
            result = self.run_child(child)
        self.assertTrue(result["native_result"]["ok"])
        self.assertIsNone(result["primary_publication"])
        self.assertEqual(parent.index, 1)
        self.assertTrue(result["profile_observation"]["issues"])

    def test_primary_ack_failure_does_not_rewrite_native_success(self):
        child, parent = self.reference()
        original = child.receive

        def receive():
            result = original()
            if result["boundary"] == "ref_primary_published":
                raise EOFError("closed")
            return result

        child.receive = receive
        result = self.run_child(child)
        self.assertTrue(result["native_result"]["ok"])
        self.assertFalse(result["reference_primary_acknowledged"])
        self.assertEqual(parent.index, 2)
        self.assertTrue(child.failed)

    def test_final_publication_failure_does_not_send_complete(self):
        child, parent = self.reference()
        with (
            patch.object(runtime, "_publish", side_effect=OSError("disk full")),
            self.assertRaises(OSError),
        ):
            self.run_child(child)
        self.assertTrue(self.primary.is_file())
        self.assertEqual(parent.index, 2)
        self.assertNotIn("memory", self.log)

    def test_final_memory_probe_failure_retains_published_native_result(self):
        child, parent = self.reference()
        parent.read_memory = Mock(side_effect=ProcessLookupError("observer disappeared"))
        with self.assertRaises(ProcessLookupError):
            self.run_child(child)
        frozen = self.result.read_bytes()
        terminal = runtime.publish_terminal(self.terminal, self.result, self.sidecar, parent)
        self.assertTrue(terminal["native_ok"])
        self.assertTrue(terminal["reference_failed"])
        self.assertEqual(terminal["reference_status"], "incomplete")
        self.assertEqual(self.result.read_bytes(), frozen)
        self.assertFalse(self.sidecar.exists())

    def test_begin_failure_does_not_construct_or_run_an_observer(self):
        child, parent = self.reference()
        parent.read_cpu = Mock(side_effect=ProcessLookupError("observer disappeared"))
        build, task = Mock(), Mock()
        with self.assertRaises(ProcessLookupError):
            self.run_child(child, build_observation=build, run_task=task)
        build.assert_not_called()
        task.assert_not_called()
        self.assertFalse(self.result.exists())

    def test_preexisting_output_is_rejected_before_begin(self):
        child, parent = self.reference()
        self.result.write_text("preserve")
        with self.assertRaises(FileExistsError):
            self.run_child(child)
        self.assertEqual(parent.index, 0)
        self.assertEqual(self.log, [])
        self.assertEqual(self.result.read_text(), "preserve")

    def test_task_exception_does_not_invent_final_results(self):
        child, parent = self.reference()
        task = Mock(side_effect=RuntimeError("worker failed before returning"))
        with self.assertRaises(RuntimeError):
            self.run_child(child, run_task=task)
        self.assertEqual(parent.index, 1)
        self.assertFalse(self.result.exists())

    def test_profile_mismatch_is_rejected_before_task(self):
        child, parent = self.reference()
        self.profile = "B"
        task = Mock()
        with self.assertRaises(ValueError):
            self.run_child(child, run_task=task)
        task.assert_not_called()
        self.assertEqual(parent.index, 1)

    def test_live_profile_is_rejected_by_synthetic_coordinator(self):
        child, parent = self.reference()

        def build(callback):
            observer = self.build(callback)
            observer.mode = "pilot"
            return observer

        task = Mock()
        with self.assertRaises(ValueError):
            self.run_child(child, build_observation=build, run_task=task)
        task.assert_not_called()
        self.assertEqual(parent.index, 1)

    def test_terminal_rejects_another_attempt_without_publishing_sidecar(self):
        child, parent = self.reference()
        result = self.run_child(child)
        result["attempt_id"] = "different"
        self.result.write_text(json.dumps(result))
        with self.assertRaises(ValueError):
            runtime.publish_terminal(self.terminal, self.result, self.sidecar, parent)
        self.assertFalse(self.sidecar.exists())
        self.assertFalse(self.terminal.exists())

    def test_terminal_outputs_are_exclusive(self):
        child, parent = self.reference()
        self.run_child(child)
        runtime.publish_terminal(self.terminal, self.result, self.sidecar, parent)
        frozen = self.terminal.read_bytes(), self.sidecar.read_bytes()
        with self.assertRaises(FileExistsError):
            runtime.publish_terminal(self.terminal, self.result, self.sidecar, parent)
        self.assertEqual(frozen, (self.terminal.read_bytes(), self.sidecar.read_bytes()))

    def test_nonfinite_final_data_fail_before_creating_result(self):
        child, parent = self.reference()
        with self.assertRaises(ValueError):
            self.run_child(child, run_task=lambda _: {"ok": True, "bad": float("nan")})
        self.assertFalse(self.result.exists())
        self.assertEqual(parent.index, 1)

    def test_missing_native_outcome_cannot_publish_a_completed_reference(self):
        child, parent = self.reference()
        with self.assertRaisesRegex(ValueError, "boolean outcome"):
            self.run_child(child, run_task=lambda _: {})
        self.assertFalse(self.result.exists())
        self.assertEqual(parent.index, 1)
