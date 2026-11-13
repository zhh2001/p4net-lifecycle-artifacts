"""Retain complete child publications when a later durable write fails."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from harness import observer_runtime


class PublicationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.path = self.base / "record.json"

    def test_fsync_failure_before_link_does_not_publish_partial_json(self):
        with patch("os.fsync", side_effect=OSError("flush failed")), self.assertRaises(OSError):
            observer_runtime._publish(self.path, {"native_ok": True})
        self.assertEqual(list(self.base.iterdir()), [])

    def test_link_failure_cleans_up_pending_file(self):
        with patch("os.link", side_effect=OSError("link failed")), self.assertRaises(OSError):
            observer_runtime._publish(self.path, {"native_ok": True})
        self.assertEqual(list(self.base.iterdir()), [])

    def test_directory_fsync_failure_leaves_complete_published_record(self):
        original = os.fsync
        calls = []

        def fsync(descriptor):
            calls.append(descriptor)
            if len(calls) == 2:
                raise OSError("directory flush failed")
            original(descriptor)

        with patch("os.fsync", side_effect=fsync), self.assertRaises(OSError):
            observer_runtime._publish(self.path, {"native_ok": True})
        self.assertEqual(json.loads(self.path.read_bytes()), {"native_ok": True})
        self.assertEqual(list(self.base.iterdir()), [self.path])

    def test_existing_record_cannot_be_replaced(self):
        observer_runtime._publish(self.path, {"native_ok": False})
        original = self.path.read_bytes()
        with self.assertRaises(FileExistsError):
            observer_runtime._publish(self.path, {"native_ok": True})
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(list(self.base.iterdir()), [self.path])

    def test_nonfinite_payload_does_not_leave_a_pending_file(self):
        with self.assertRaises(ValueError):
            observer_runtime._publish(self.path, {"cost": float("inf")})
        self.assertEqual(list(self.base.iterdir()), [])

    def test_incomplete_terminal_rejects_boolean_schema(self):
        child = self.base / "child.json"
        binding = {"run_id": "run", "attempt_id": "attempt", "observer_profile": "B"}
        child.write_text(
            json.dumps(
                {
                    **binding,
                    "schema_version": True,
                    "record_type": "observer-calibration-child-result",
                    "mode": "synthetic-validation",
                    "performance_samples": False,
                    "native_result": {"ok": True},
                }
            )
        )
        reference = SimpleNamespace(
            mode="synthetic-validation", binding=binding, index=1, failed=False
        )
        with self.assertRaises(ValueError):
            observer_runtime.publish_terminal(
                self.path, child, self.base / "reference.json", reference
            )
        self.assertFalse(self.path.exists())

    def test_unknown_child_mode_fails_before_begin(self):
        reference = SimpleNamespace(checkpoint=lambda _: self.fail("unexpected checkpoint"))
        with self.assertRaises(ValueError):
            observer_runtime.run_child(
                self.path,
                reference,
                mode="formal",
                build_observation=lambda _: self.fail("unexpected construction"),
                run_task=lambda _: self.fail("unexpected worker"),
            )
