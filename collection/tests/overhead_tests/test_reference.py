import socket

from overhead.wire import Channel, ChildReference, decode, encode, message

from .support import Fixture


class WireTests(Fixture):
    def test_duplicate_keys_and_nonfinite_numbers_are_rejected(self):
        for data in (b'{"a":1,"a":2}\n', b'{"x":NaN}\n', b'{"x":1e999}\n', b'{"x":0.5}\n'):
            with self.assertRaises(ValueError):
                decode(data)

    def test_bounded_newline_and_object_frames(self):
        for data in (b"[]\n", b"{}", b"{}\n{}\n", b'{"x":"' + b"a" * 4096 + b'"}\n'):
            with self.assertRaises(ValueError):
                decode(data)

    def test_codec_round_trip(self):
        value = message(self.context, self.supervisor, "ref_begin", 1)
        self.assertEqual(decode(encode(value)), value)

    def test_fragmented_and_coalesced_socket_frames(self):
        left, right = socket.socketpair()
        with left, right:
            channel = Channel(right, 10, clock=lambda: 1)
            left.sendall(b'{"x":')
            left.sendall(b'1}\n{"x":2}\n')
            self.assertEqual(channel.receive(), {"x": 1})
            self.assertEqual(channel.receive(), {"x": 2})

    def test_deadline_and_eof_are_bounded(self):
        left, right = socket.socketpair()
        with left, right:
            with self.assertRaises(TimeoutError):
                Channel(left, 1, clock=lambda: 1).receive()
            right.close()
            with self.assertRaises(EOFError):
                Channel(left, 10, clock=lambda: 1).receive()

    def test_invalid_deadlines_and_clocks_are_rejected(self):
        left, right = socket.socketpair()
        with left, right:
            for deadline in (True, float("nan"), float("inf")):
                with self.assertRaises(ValueError):
                    Channel(left, deadline)
            with self.assertRaises(ValueError):
                Channel(left, 10, clock=lambda: False).remaining()

    def test_duplicate_and_out_of_order_checkpoints_are_rejected(self):
        self.child.checkpoint("ref_begin")
        with self.assertRaises(ValueError):
            self.child.checkpoint("ref_begin")
        self.assertTrue(self.child.failed)

    def test_cross_attempt_and_cross_profile_packets_are_rejected(self):
        for key, value in (("attempt_id", "other"), ("diagnostic_profile", "detail")):
            packet = message(self.context, self.supervisor, "ref_begin", 1)
            packet["context"][key] = value
            with self.assertRaises(ValueError):
                self.parent.handle(packet)
            self.parent.failed = False

    def test_boolean_sequence_and_version_are_rejected(self):
        for key in ("schema_version", "sequence"):
            packet = message(self.context, self.supervisor, "ref_begin", 1)
            packet[key] = True
            with self.assertRaises(ValueError):
                self.parent.handle(packet)
            self.parent.failed = False

    def test_false_flag_does_not_accept_zero(self):
        packet = message(self.context, self.supervisor, "ref_begin", 1)
        packet["context"]["performance_samples"] = 0
        with self.assertRaises(ValueError):
            self.parent.handle(packet)

    def test_ack_must_echo_the_exact_checkpoint(self):
        def receive():
            value = self.acks.pop(0)
            value["payload"] = {"different": True}
            return value

        child = ChildReference(self.context, self.supervisor, self.parent.handle, receive)
        with self.assertRaises(ValueError):
            child.checkpoint("ref_begin")

    def test_supervisor_identity_drift_is_rejected(self):
        packet = message(self.context, self.supervisor, "ref_begin", 1)
        packet["supervisor"]["boot_id"] = "other"
        with self.assertRaises(ValueError):
            self.parent.handle(packet)

    def test_publication_pointer_shape_is_checked(self):
        self.child.checkpoint("ref_begin")
        with self.assertRaises(ValueError):
            self.child.checkpoint(
                "ref_primary_published", {"primary": {"path": "x", "sha256": "bad"}}
            )


class ReferenceTests(Fixture):
    def test_probe_order_closes_wall_and_cpu_before_final_memory(self):
        self.coordinator.run(self.execute)
        calls = self.reader.calls
        self.assertLess(
            calls.index(("cpu", self.worker.pid)), calls.index(("memory", self.worker.pid))
        )
        end = self.parent.endpoints
        self.assertLess(end["body_end_ns"], end["supervisor_memory_end"]["read_start_ns"])
        self.assertEqual(self.parent.result()["metrics"]["supervisor_cpu_ticks"], 10)
        self.assertTrue(self.parent.result()["transport_complete"])

    def test_worker_cpu_failure_keeps_other_endpoints(self):
        self.reader.bad_cpu = self.worker.pid
        self.coordinator.run(lambda o: self.execute_without_end(o))
        result = self.parent.result()
        self.assertNotIn("worker_cpu_ready", result["endpoints"])
        self.assertIn("worker_memory_ready", result["endpoints"])
        self.assertIn("reference_body_wall_ns", result["metrics"])
        self.assertTrue(result["transport_complete"])

    def execute_without_end(self, observation):
        observation.mark("worker_launch")
        observation.ready(self.worker)
        observation.mark("stop_request")
        observation.mark("worker_exit")
        return self.native

    def test_worker_memory_failure_keeps_cpu_and_supervisor_memory(self):
        self.reader.bad_memory = self.worker.pid
        self.coordinator.run(self.execute)
        result = self.parent.result()
        self.assertIn("worker_cpu_ready", result["endpoints"])
        self.assertNotIn("worker_memory_ready", result["endpoints"])
        self.assertIn("supervisor_memory_end", result["endpoints"])

    def test_one_memory_field_failure_retains_the_other_field(self):
        self.reader.partial_memory = True
        self.coordinator.run(self.execute)
        endpoint = self.parent.result()["endpoints"]["worker_memory_ready"]
        self.assertIn("rss_bytes", endpoint)
        self.assertNotIn("pss_bytes", endpoint)

    def test_raw_zero_cpu_is_a_valid_observation(self):
        original = self.reader.cpu

        def zero(identity):
            value = original(identity)
            value.update(user_ticks=0, system_ticks=0, cpu_ticks=0)
            return value

        self.reader.cpu = zero
        self.coordinator.run(self.execute)
        self.assertEqual(self.parent.result()["metrics"]["supervisor_cpu_ticks"], 0)

    def test_missing_ready_checkpoint_can_close_a_failed_start(self):
        self.coordinator.run(lambda o: {"ok": False, "ready": False})
        self.assertEqual(
            self.parent.history, ["ref_begin", "ref_primary_published", "ref_complete"]
        )
        self.assertNotIn("worker_cpu_ready", self.parent.endpoints)

    def test_reference_result_is_a_detached_snapshot(self):
        self.coordinator.run(self.execute)
        result = self.parent.result()
        result["endpoints"].clear()
        self.assertTrue(self.parent.result()["endpoints"])

    def test_unknown_payload_fields_fail_reference(self):
        self.child.checkpoint("ref_begin")
        with self.assertRaises(ValueError):
            self.child.checkpoint(
                "ref_ready",
                {
                    "worker": self.worker.as_dict(),
                    "hold_anchor_ns": 0,
                    "hold_deadline_ns": 10,
                    "extra": True,
                },
            )

    def test_foreign_worker_is_not_used_for_resource_reads(self):
        self.child.checkpoint("ref_begin")
        value = self.worker.as_dict()
        value["start_ticks"] += 1
        with self.assertRaises(ProcessLookupError):
            self.child.checkpoint(
                "ref_ready", {"worker": value, "hold_anchor_ns": 0, "hold_deadline_ns": 1000}
            )


class AdditionalReferenceTests(Fixture):
    def test_ack_rejects_a_mutated_original_request(self):
        def send(packet):
            packet["context"]["attempt_id"] = "other"
            self.acks.append({**packet, "record_type": "diagnostic-reference-ack"})

        child = ChildReference(self.context, self.supervisor, send, lambda: self.acks.pop(0))
        with self.assertRaises(ValueError):
            child.checkpoint("ref_begin")

    def test_supervisor_counter_rollback_removes_only_its_cpu_metric(self):
        original = self.reader.cpu

        def cpu(identity):
            value = original(identity)
            if identity == self.supervisor and self.reader.counts[identity.pid] > 1:
                value.update(user_ticks=0, system_ticks=0, cpu_ticks=0)
            return value

        self.reader.cpu = cpu
        self.coordinator.run(self.execute)
        result = self.parent.result()
        self.assertNotIn("supervisor_cpu_ticks", result["metrics"])
        self.assertIn("reference_body_wall_ns", result["metrics"])

    def test_reference_own_cpu_failure_does_not_break_the_main_interval(self):
        self.parent.process_cpu = lambda: -1
        self.coordinator.run(self.execute)
        result = self.parent.result()
        self.assertNotIn("reference_own_cpu_ns", result["metrics"])
        self.assertTrue(result["transport_complete"])
        self.assertIn("reference_body_wall_ns", result["metrics"])
