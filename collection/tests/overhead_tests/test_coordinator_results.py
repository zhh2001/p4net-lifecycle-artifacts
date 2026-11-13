import json

from overhead.coordinator import Supervisor
from overhead.results import finalize
from overhead.wire import ChildReference

from .support import Fixture


class CoordinatorTests(Fixture):
    def complete(self):
        self.coordinator.run(self.execute)
        return finalize(
            self.parent, self.output, outer_span={"start_ns": 1, "end_ns": self.clock.now()}
        )

    def test_full_record_contains_all_endpoints_and_original_native_result(self):
        original = self.native.copy()
        receipt = self.complete()
        self.assertTrue(receipt["primary_performance_eligible"])
        self.assertTrue(receipt["measurement_complete"])
        self.assertEqual(receipt["native_result"], original)
        self.assertIn("outer_process_wall_ns", receipt["metrics"])
        self.assertIn("worker_cpu_end_ticks", receipt["metrics"])

    def test_common_prepare_runs_after_begin_acknowledgment(self):
        events = []
        self.coordinator.run(self.execute, prepare=lambda: events.append(list(self.parent.history)))
        self.assertEqual(events, [["ref_begin"]])

    def test_failed_begin_prevents_worker_dispatch(self):
        child = ChildReference(self.context, self.supervisor, lambda packet: None, lambda: {})
        supervisor = Supervisor(self.context, child, self.output)
        invoked = []
        with self.assertRaises(ValueError):
            supervisor.run(lambda o: invoked.append(True))
        self.assertEqual(invoked, [])

    def test_one_hold_uses_original_deadline_after_endpoint_probe_time(self):
        self.reader.delay = 200
        self.coordinator.run(self.execute)
        self.assertEqual(len(self.clock.sleeps), 1)
        self.assertLess(self.clock.sleeps[0], 0.000001)
        self.assertTrue(self.coordinator.hold["complete"])

    def test_overrun_does_not_add_another_hold(self):
        self.reader.delay = 2000
        self.coordinator.run(self.execute)
        self.assertEqual(self.clock.sleeps, [])
        self.assertGreater(self.coordinator.hold["extension_ns"], 0)

    def test_duplicate_ready_does_not_wait_again(self):
        def execute(o):
            result = self.execute(o)
            o.ready(self.worker)
            return result

        self.coordinator.run(execute)
        self.assertEqual(len(self.clock.sleeps), 1)
        self.assertTrue(self.coordinator.issues)

    def test_nonadvancing_hold_is_recorded_without_changing_native_return(self):
        self.coordinator.sleep = lambda seconds: None
        self.coordinator.clock = lambda: 2_000_000
        result = self.coordinator.run(self.execute)
        self.assertIs(result, self.native)
        self.assertFalse(self.coordinator.hold["complete"])

    def test_lost_ready_channel_still_executes_native_cleanup(self):
        def send(packet):
            if packet["boundary"] == "ref_ready":
                raise EOFError("lost ready ack")
            self.parent.handle(packet)

        self.child.send = send
        result = self.coordinator.run(self.execute)
        self.assertIs(result, self.native)
        self.assertIn("ordinary_audit_end", self.coordinator.markers)
        receipt = finalize(self.parent, self.output)
        self.assertEqual(receipt["native_result"], self.native)
        self.assertFalse(receipt["primary_performance_eligible"])

    def test_native_exception_identity_survives_failed_publication(self):
        error = RuntimeError("native")

        def execute(o):
            raise error

        def fail(*args):
            raise OSError("disk")

        self.coordinator.publisher = fail
        with self.assertRaises(RuntimeError) as caught:
            self.coordinator.run(execute)
        self.assertIs(caught.exception, error)

    def test_native_return_survives_unserializable_measurement(self):
        native = {"ok": True, "object": object()}
        result = self.coordinator.run(lambda o: native)
        self.assertIs(result, native)
        self.assertTrue(self.coordinator.issues)

    def test_missing_end_record_removes_only_its_cpu_metric(self):
        self.coordinator.run(self.execute)
        (self.output / "worker-cpu-end.json").unlink()
        receipt = finalize(self.parent, self.output)
        self.assertTrue(receipt["primary_performance_eligible"])
        self.assertFalse(receipt["measurement_complete"])
        self.assertNotIn("worker_cpu_end_ticks", receipt["metrics"])
        self.assertIn("startup_wall_ns", receipt["metrics"])

    def test_partial_memory_damage_does_not_remove_other_metrics(self):
        self.reader.partial_memory = True
        receipt = self.complete()
        self.assertTrue(receipt["primary_performance_eligible"])
        self.assertIn("worker_ready_rss_bytes", receipt["metrics"])
        self.assertNotIn("worker_ready_pss_bytes", receipt["metrics"])
        self.assertIn("worker_cpu_end_ticks", receipt["metrics"])

    def test_cleanup_failure_keeps_native_outcome_and_raw_metrics(self):
        self.native["cleanup"]["ordinary_after_clean"] = False
        receipt = self.complete()
        self.assertTrue(receipt["native_result"]["ok"])
        self.assertEqual(receipt["metrics"], {})
        self.assertIn("startup_wall_ns", receipt["raw_validated_metrics"])

    def test_child_hash_tampering_is_rejected(self):
        self.coordinator.run(self.execute)
        p = self.output / "child.json"
        p.write_text(p.read_text() + " ")
        receipt = finalize(self.parent, self.output)
        self.assertFalse(receipt["primary_performance_eligible"])
        self.assertTrue(any(i["metric"] == "publication" for i in receipt["issues"]))

    def test_worker_end_attempt_tampering_does_not_remove_wall_metrics(self):
        self.coordinator.run(self.execute)
        p = self.output / "worker-cpu-end.json"
        value = json.loads(p.read_text())
        value["context"]["attempt_id"] = "other"
        p.write_text(json.dumps(value))
        receipt = finalize(self.parent, self.output)
        self.assertTrue(receipt["primary_performance_eligible"])
        self.assertNotIn("worker_cpu_end_ticks", receipt["metrics"])

    def test_counter_rollback_at_worker_end_is_rejected(self):
        self.coordinator.run(self.execute)
        p = self.output / "worker-cpu-end.json"
        v = json.loads(p.read_text())
        v["cpu"].update(user_ticks=0, system_ticks=0, cpu_ticks=0)
        p.write_text(json.dumps(v))
        receipt = finalize(self.parent, self.output)
        self.assertNotIn("worker_cpu_end_ticks", receipt["metrics"])

    def test_repeated_result_publication_does_not_overwrite(self):
        self.complete()
        path = self.output / "reference-result.json"
        before = path.read_bytes()
        with self.assertRaises(FileExistsError):
            finalize(self.parent, self.output)
        self.assertEqual(path.read_bytes(), before)

    def test_unknown_or_duplicate_lifecycle_marker_is_reported(self):
        self.coordinator.mark("unknown")
        self.coordinator.mark("worker_launch")
        self.coordinator.mark("worker_launch")
        self.assertEqual(len(self.coordinator.issues), 2)


class AdditionalCoordinatorTests(Fixture):
    def test_default_ten_second_hold_is_checked_with_a_synthetic_clock(self):
        self.coordinator.hold_ns = 10_000_000_000
        self.coordinator.run(self.execute)
        self.assertEqual(self.coordinator.hold["requested_duration_ns"], 10_000_000_000)
        self.assertEqual(len(self.clock.sleeps), 1)
        self.assertTrue(self.coordinator.hold["complete"])

    def test_boolean_exit_code_does_not_become_a_completed_metric_pair(self):
        self.native["worker_returncode"] = False
        self.coordinator.run(self.execute)
        self.assertFalse(finalize(self.parent, self.output)["primary_performance_eligible"])

    def test_worker_end_read_before_readiness_is_rejected(self):
        self.coordinator.run(self.execute)
        p = self.output / "worker-cpu-end.json"
        v = json.loads(p.read_text())
        v["cpu"]["read_start_ns"] = 0
        v["cpu"]["read_end_ns"] = 1
        p.write_text(json.dumps(v))
        receipt = finalize(self.parent, self.output)
        self.assertNotIn("worker_cpu_end_ticks", receipt["metrics"])
