"""Synthetic reference checkpoints, procfs identity, and publication tests."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import observer_reference as reference

NS = {"pid": "pid:[101]", "net": "net:[102]", "mnt": "mnt:[103]"}
OTHER = {"pid": "pid:[201]", "net": "net:[202]", "mnt": "mnt:[203]"}
BINDING = {"run_id": "run-a", "attempt_id": "attempt-a", "observer_profile": "S"}
IDENTITY = reference.ObserverIdentity(42, 700, NS)


def message(boundary, *, ack=False):
    return {
        "schema_version": 1,
        "record_type": "observer-reference-ack" if ack else "observer-reference-checkpoint",
        **BINDING,
        "boundary": boundary,
        "sequence": reference.BOUNDARIES.index(boundary),
        "namespaces": dict(NS),
    }


def stat(pid, parent, *, start=700, user=11, system=7, state="S"):
    fields = ["0"] * 20
    fields[0], fields[1] = state, str(parent)
    fields[11:15] = [str(user), str(system), "999999", "999999"]
    fields[19] = str(start)
    return f"{pid} (observer with ) name) " + " ".join(fields)


def process(root, pid, parent, *, namespaces=NS, namespace_pids=None, **kwargs):
    directory = root / str(pid)
    directory.mkdir(exist_ok=True)
    (directory / "stat").write_text(stat(pid, parent, **kwargs))
    (directory / "status").write_text("NSpid:\t" + (namespace_pids or f"{pid}\t1") + "\n")
    (directory / "smaps_rollup").write_text("Rss: 123 kB\nPss: 98 kB\n")
    ns = directory / "ns"
    ns.mkdir(exist_ok=True)
    for name, target in namespaces.items():
        path = ns / name
        if path.is_symlink():
            path.unlink()
        path.symlink_to(target)
    return directory


class ReferenceFixture:
    def __init__(self, **overrides):
        self.trace = []
        self.wall = 0
        self.monitor = 0
        self.cpu_calls = 0
        self.queue = []
        values = {
            "identity": IDENTITY,
            "run_id": BINDING["run_id"],
            "attempt_id": BINDING["attempt_id"],
            "profile": "S",
            "clock_ns": self.clock,
            "monitor_cpu_ns": self.monitor_clock,
            "clock_ticks": 100,
            "read_cpu": self.cpu,
            "read_memory": self.memory,
            "send_ack": self.ack,
        }
        values.update(overrides)
        self.parent = reference.ParentReference(**values)
        self.child = reference.ChildReference(
            run_id=BINDING["run_id"],
            attempt_id=BINDING["attempt_id"],
            profile="S",
            namespaces=NS,
            send=self.parent.handle,
            receive=lambda: self.queue.pop(0),
        )

    def clock(self):
        self.wall += 100
        self.trace.append(("wall", self.wall))
        return self.wall

    def monitor_clock(self):
        self.monitor += 10
        self.trace.append(("monitor", self.monitor))
        return self.monitor

    def cpu(self, identity):
        self.cpu_calls += 1
        self.trace.append(("cpu", self.cpu_calls))
        return {
            "observer": identity.as_dict(),
            "user_ticks": self.cpu_calls * 10,
            "system_ticks": self.cpu_calls,
            "cpu_ticks": self.cpu_calls * 11,
        }

    def memory(self, identity):
        self.trace.append(("memory", self.parent.wall_end))
        return {"observer": identity.as_dict(), "rss_bytes": 2000, "pss_bytes": 1000}

    def ack(self, value):
        self.trace.append(("ack", value["boundary"]))
        self.queue.append(copy.deepcopy(value))

    def complete(self):
        for boundary in reference.BOUNDARIES:
            self.child.checkpoint(boundary)
        return self.parent.record()


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        process(self.root, 20, 2, namespaces=OTHER, start=600)
        process(self.root, 30, 20, namespaces=OTHER, start=650, namespace_pids="30\t2")
        self.observer = process(self.root, 42, 30)

    def discover(self, **kwargs):
        return reference.discover_observer(20, NS, proc_root=self.root, **kwargs)

    def test_descendant_host_mapping_and_own_cpu_only(self):
        identity = self.discover(outer_start_ticks=600)
        self.assertEqual(identity, IDENTITY)
        self.assertEqual(
            reference.read_observer_cpu(identity, proc_root=self.root)["cpu_ticks"], 18
        )
        memory = reference.read_observer_memory(identity, proc_root=self.root)
        self.assertEqual((memory["rss_bytes"], memory["pss_bytes"]), (123 * 1024, 98 * 1024))
        self.assertIn("not peak", memory["scope"])
        with self.assertRaises(TypeError):
            identity.namespaces["pid"] = "pid:[0]"

    def test_unrelated_unreadable_namespace_does_not_block_mapping(self):
        other = process(self.root, 99, 2)
        for name in NS:
            (other / "ns" / name).unlink()
        self.assertEqual(self.discover(), IDENTITY)

    def test_foreign_tree_cannot_supply_observer(self):
        (self.observer / "stat").write_text(stat(42, 2))
        with self.assertRaisesRegex(ValueError, "unique observer"):
            self.discover()

    def test_ambiguous_candidate_is_rejected(self):
        process(self.root, 43, 20)
        with self.assertRaisesRegex(ValueError, "unique observer"):
            self.discover()

    def test_non_init_or_invalid_namespace_pid_mapping_is_rejected(self):
        for payload in ("42\t2", "1", "41\t1", "not-a-pid\t1", "42\t0\t1", "42\t1\nNSpid:\t42\t1"):
            with self.subTest(payload=payload):
                (self.observer / "status").write_text("NSpid:\t" + payload + "\n")
                with self.assertRaises(ValueError):
                    self.discover()

    def test_outer_and_observer_start_ticks_are_locked(self):
        with self.assertRaises(ProcessLookupError):
            self.discover(outer_start_ticks=601)
        for invalid in (-1, True, 600.0):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.discover(outer_start_ticks=invalid)
        (self.observer / "stat").write_text(stat(42, 30, start=701))
        for reader in (reference.read_observer_cpu, reference.read_observer_memory):
            with self.assertRaises(ProcessLookupError):
                reader(IDENTITY, proc_root=self.root)

    def test_namespace_change_and_exit_are_rejected(self):
        for state in ("Z", "X", "x"):
            with self.subTest(state=state):
                (self.observer / "stat").write_text(stat(42, 30, state=state))
                with self.assertRaises(ProcessLookupError):
                    reference.read_observer_cpu(IDENTITY, proc_root=self.root)
        (self.observer / "stat").write_text(stat(42, 30))
        (self.observer / "ns" / "net").unlink()
        (self.observer / "ns" / "net").symlink_to("net:[999]")
        with self.assertRaises(ProcessLookupError):
            reference.read_observer_memory(IDENTITY, proc_root=self.root)

    def test_mid_read_pid_reuse_and_cpu_decrease_are_rejected(self):
        original = reference._view
        calls = []

        def change_after_first(pid, root):
            value = original(pid, root)
            calls.append(pid)
            if len(calls) == 1:
                (self.observer / "stat").write_text(stat(42, 30, start=701))
            return value

        with (
            patch.object(reference, "_view", side_effect=change_after_first),
            self.assertRaises(ProcessLookupError),
        ):
            reference.read_observer_cpu(IDENTITY, proc_root=self.root)
        (self.observer / "stat").write_text(stat(42, 30))
        before = original(42, self.root)
        after = {**before, "user_ticks": 0}
        with (
            patch.object(reference, "_verify", side_effect=[before, after]),
            self.assertRaises(ValueError),
        ):
            reference.read_observer_cpu(IDENTITY, proc_root=self.root)

    def test_invalid_identity_and_namespace_shapes(self):
        for pid, ticks, namespaces in (
            (1, 0, NS),
            (True, 0, NS),
            (42, -1, NS),
            (42, 0, {}),
            (42, 0, {**NS, "net": "net:1"}),
        ):
            with (
                self.subTest(pid=pid, ticks=ticks, namespaces=namespaces),
                self.assertRaises(ValueError),
            ):
                reference.ObserverIdentity(pid, ticks, namespaces)


class ChannelTests(unittest.TestCase):
    def test_utf8_round_trip_and_binary_line_channel(self):
        payload = {"label": "接口", "value": 1}
        frame = reference.encode_message(payload)
        self.assertEqual(reference.decode_message(frame), payload)
        output = io.BytesIO()
        channel = reference.LineChannel(io.BytesIO(frame), output)
        self.assertEqual(channel.receive(), payload)
        channel.send(payload)
        self.assertEqual(output.getvalue(), frame)

    def test_exact_frame_limit_and_oversize(self):
        payload = {"x": "a" * (reference.MAX_FRAME_BYTES - 9)}
        frame = reference.encode_message(payload)
        self.assertEqual(len(frame), reference.MAX_FRAME_BYTES)
        self.assertEqual(reference.decode_message(frame), payload)
        with self.assertRaises(ValueError):
            reference.encode_message({"x": payload["x"] + "a"})
        with self.assertRaises(ValueError):
            reference.LineChannel(io.BytesIO(b"x" * 9000), io.BytesIO()).receive()

    def test_eof_partial_duplicate_nonfinite_and_invalid_frames(self):
        with self.assertRaises(EOFError):
            reference.LineChannel(io.BytesIO(), io.BytesIO()).receive()
        for frame in (
            b"{}",
            b"{}\n{}\n",
            b"[]\n",
            b'{"x":1,"x":2}\n',
            b'{"x":NaN}\n',
            b'"x"\n',
            b"\xff\n",
            b"}\n",
        ):
            with self.subTest(frame=frame), self.assertRaises(ValueError):
                reference.decode_message(frame)
        with self.assertRaises(ValueError):
            reference.encode_message({"value": float("inf")})

    def test_short_writes_are_errors(self):
        writer = unittest.mock.Mock()
        writer.write.return_value = 1
        with self.assertRaises(OSError):
            reference.LineChannel(io.BytesIO(), writer).send({"value": 1})
        writer.flush.assert_not_called()


class ProtocolTests(unittest.TestCase):
    def test_constructor_does_not_read_clocks_or_resources(self):
        fixture = ReferenceFixture()
        self.assertEqual(fixture.trace, [])
        with self.assertRaises(ValueError):
            fixture.parent.record()

    def test_three_boundaries_preserve_wall_cpu_memory_order(self):
        fixture = ReferenceFixture()
        record = fixture.complete()
        self.assertEqual(
            [event["boundary"] for event in record["reference_events"]], list(reference.BOUNDARIES)
        )
        trace = fixture.trace
        self.assertEqual(
            [name for name, _ in trace[:7]],
            ["wall", "monitor", "cpu", "wall", "wall", "ack", "wall"],
        )
        complete = next(index for index, item in enumerate(trace) if item == ("cpu", 2))
        self.assertEqual(trace[complete - 1], ("wall", record["wall_end_ns"]))
        memory = next(index for index, item in enumerate(trace) if item[0] == "memory")
        self.assertGreater(memory, complete)
        self.assertEqual(trace[memory][1], record["wall_end_ns"])
        self.assertEqual(record["observer_cpu_delta_ticks"], 11)
        self.assertEqual(record["observer_cpu_seconds"], 0.11)
        self.assertEqual(record["observer_cpu_resolution_seconds"], 0.01)
        self.assertEqual(
            record["observer_body_wall_ns"], record["wall_end_ns"] - record["wall_start_ns"]
        )
        self.assertFalse(record["reference_cost_subtracted"])
        self.assertFalse(record["performance_samples"])
        self.assertEqual(record["reference_process_cpu_ns"], 10)

    def test_pilot_performance_flag_and_quantized_zero_cpu(self):
        fixture = ReferenceFixture(
            mode="pilot",
            read_cpu=lambda identity: {
                "observer": identity.as_dict(),
                "user_ticks": 0,
                "system_ticks": 0,
                "cpu_ticks": 0,
            },
        )
        record = fixture.complete()
        self.assertTrue(record["performance_samples"])
        self.assertEqual(record["observer_cpu_delta_ticks"], 0)
        self.assertEqual(record["observer_cpu_resolution_seconds"], 0.01)

    def test_missing_primary_publication_cannot_complete(self):
        fixture = ReferenceFixture()
        fixture.child.checkpoint("ref_begin")
        with self.assertRaises(ValueError):
            fixture.child.checkpoint("ref_complete")
        self.assertTrue(fixture.child.failed)
        with self.assertRaises(ValueError):
            fixture.child.checkpoint("ref_primary_published")
        with self.assertRaises(ValueError):
            fixture.parent.record()

    def test_wrong_parent_identity_schema_or_order_poisons_attempt(self):
        for key, wrong in (
            ("attempt_id", "other"),
            ("run_id", "other"),
            ("observer_profile", "B"),
            ("sequence", True),
            ("schema_version", True),
            ("namespaces", OTHER),
            ("boundary", "ref_complete"),
            ("extra", 1),
        ):
            with self.subTest(key=key):
                fixture = ReferenceFixture()
                value = {**message("ref_begin"), key: wrong}
                with self.assertRaises(ValueError):
                    fixture.parent.handle(value)
                self.assertTrue(fixture.parent.failed)
                self.assertEqual(fixture.trace, [])
                with self.assertRaises(ValueError):
                    fixture.parent.handle(message("ref_begin"))

    def test_wrong_ack_and_eof_poison_child(self):
        for receive in (
            lambda: message("ref_primary_published", ack=True),
            lambda: (_ for _ in ()).throw(EOFError()),
        ):
            child = reference.ChildReference(
                run_id="run-a",
                attempt_id="attempt-a",
                profile="S",
                namespaces=NS,
                send=lambda value: None,
                receive=receive,
            )
            with self.assertRaises((ValueError, EOFError)):
                child.checkpoint("ref_begin")
            self.assertTrue(child.failed)

    def test_duplicate_after_complete_invalidates_reference(self):
        fixture = ReferenceFixture()
        fixture.complete()
        with self.assertRaises(ValueError):
            fixture.parent.handle(message("ref_complete"))
        self.assertTrue(fixture.parent.failed)
        with self.assertRaises(ValueError):
            fixture.parent.record()

    def test_cpu_identity_sum_or_counter_decrease_are_errors(self):
        bad = (
            {
                "observer": {**IDENTITY.as_dict(), "host_pid": 43},
                "user_ticks": 1,
                "system_ticks": 1,
                "cpu_ticks": 2,
            },
            {"observer": IDENTITY.as_dict(), "user_ticks": 1, "system_ticks": 1, "cpu_ticks": 3},
            {"observer": IDENTITY.as_dict(), "user_ticks": True, "system_ticks": 1, "cpu_ticks": 2},
        )
        for value in bad:
            with self.subTest(value=value):
                fixture = ReferenceFixture(read_cpu=lambda identity, value=value: value)
                with self.assertRaises(ValueError):
                    fixture.child.checkpoint("ref_begin")
                self.assertTrue(fixture.parent.failed)
        fixture = ReferenceFixture()
        fixture.child.checkpoint("ref_begin")
        fixture.child.checkpoint("ref_primary_published")
        fixture.parent.read_cpu = lambda identity: {
            "observer": identity.as_dict(),
            "user_ticks": 0,
            "system_ticks": 0,
            "cpu_ticks": 0,
        }
        with self.assertRaises(ValueError):
            fixture.child.checkpoint("ref_complete")
        with self.assertRaises(ValueError):
            fixture.parent.record()

    def test_clock_reversal_and_memory_failure_remain_unavailable(self):
        fixture = ReferenceFixture(clock_ns=iter((100, 99)).__next__)
        with self.assertRaises(ValueError):
            fixture.child.checkpoint("ref_begin")
        self.assertTrue(fixture.parent.failed)
        fixture = ReferenceFixture(
            read_memory=lambda identity: {
                "observer": identity.as_dict(),
                "rss_bytes": -1,
                "pss_bytes": 0,
            }
        )
        with self.assertRaises(ValueError):
            fixture.complete()
        with self.assertRaises(ValueError):
            fixture.parent.record()

    def test_invalid_constructor_inputs_fail_without_sampling(self):
        for invalid in (
            {"mode": "formal"},
            {"clock_ticks": True},
            {"clock_ns": None},
            {"identity": None},
            {"profile": "X"},
            {"run_id": ""},
            {"attempt_id": "bad\nvalue"},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                ReferenceFixture(**invalid)

    def test_sidecar_exclusive_hash_binding_and_unchanged_child(self):
        fixture = ReferenceFixture()
        fixture.complete()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child, sidecar = root / "child.json", root / "reference.json"
            envelope = {
                **BINDING,
                "schema_version": 1,
                "record_type": "observer-calibration-child-result",
                "mode": "synthetic-validation",
                "performance_samples": False,
                "native_result": {"ok": True},
            }
            child.write_text(json.dumps(envelope) + "\n")
            before = child.read_bytes()
            metadata = child.stat()
            record = fixture.parent.publish_sidecar(sidecar, child)
            self.assertEqual(record["child_result"]["sha256"], hashlib.sha256(before).hexdigest())
            self.assertEqual(child.read_bytes(), before)
            self.assertEqual(child.stat().st_mtime_ns, metadata.st_mtime_ns)
            self.assertEqual(json.loads(sidecar.read_text()), record)
            with self.assertRaises(FileExistsError):
                fixture.parent.publish_sidecar(sidecar, child)
            for key, wrong in (
                ("attempt_id", "another-attempt"),
                ("record_type", "native-result"),
                ("schema_version", True),
                ("schema_version", 2),
                ("mode", "pilot"),
                ("performance_samples", True),
                ("performance_samples", 0),
            ):
                with self.subTest(key=key, wrong=wrong):
                    child.write_text(json.dumps({**envelope, key: wrong}))
                    with self.assertRaises(ValueError):
                        fixture.parent.publish_sidecar(root / "foreign.json", child)
            link = root / "link.json"
            link.symlink_to(child)
            with self.assertRaises(ValueError):
                fixture.parent.publish_sidecar(root / "linked.json", link)
            self.assertFalse((root / "foreign.json").exists())


if __name__ == "__main__":
    unittest.main()
