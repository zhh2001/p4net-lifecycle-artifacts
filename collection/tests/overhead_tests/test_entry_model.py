import hashlib
import json
import sys
from pathlib import Path
from unittest.mock import patch

from overhead.entry import Entry, run_entry
from overhead.model import Context, Identity
from overhead.publication import publish

from .support import Fixture


class ModelTests(Fixture):
    def test_context_round_trip(self):
        self.assertEqual(Context.from_dict(self.context.as_dict()), self.context)

    def test_native_pilot_is_rejected(self):
        with self.assertRaises(PermissionError):
            Context("r", "a", "p4net", "native", mode="pilot")

    def test_unknown_profiles_and_observers_are_rejected(self):
        for kw in ({"diagnostic_profile": "B"}, {"observer_profile": "S"}, {"tool": "other"}):
            values = {
                "run_id": "r",
                "attempt_id": "a",
                "tool": "p4net",
                "diagnostic_profile": "off",
                **kw,
            }
            with self.assertRaises(ValueError):
                Context(**values)

    def test_bad_context_fields_are_rejected(self):
        for value in ("", " ", "\n", "a" * 257):
            with self.assertRaises(ValueError):
                Context(value, "a", "p4net", "off")

    def test_false_is_not_interchangeable_with_zero(self):
        value = self.context.as_dict()
        value["performance_samples"] = 0
        with self.assertRaises(ValueError):
            Context.from_dict(value)

    def test_namespace_mapping_is_immutable(self):
        with self.assertRaises(TypeError):
            self.worker.namespaces["pid"] = "pid:[1]"

    def test_cross_domain_identity_uses_inner_pid_and_start_time(self):
        value = self.worker.as_dict()
        value["pid"] = 12345
        other = Identity.from_dict(value)
        self.assertTrue(other.same_process(self.worker))
        self.assertNotEqual(other, self.worker)

    def test_identity_booleans_are_rejected(self):
        value = self.worker.as_dict()
        value["start_ticks"] = False
        with self.assertRaises(ValueError):
            Identity.from_dict(value)


class EntryTests(Fixture):
    def invoke(self, fn, **kwargs):
        return run_entry(
            self.context,
            fn,
            self.output / "end.json",
            identity=self.worker,
            read_cpu=lambda: self.reader.cpu(self.worker),
            clock=self.clock.now,
            **kwargs,
        )

    def test_return_object_is_not_replaced(self):
        native = object()
        self.assertIs(self.invoke(lambda: native), native)
        self.assertEqual(
            json.loads((self.output / "end.json").read_text())["native_outcome"],
            {"status": "returned"},
        )

    def test_all_native_exception_identities_are_preserved(self):
        for index, error in enumerate((RuntimeError("native"), KeyboardInterrupt(), SystemExit(7))):
            path = self.output / f"end-{index}.json"

            def raise_error(error=error):
                raise error

            with self.assertRaises(type(error)) as caught:
                run_entry(
                    self.context,
                    raise_error,
                    path,
                    identity=self.worker,
                    read_cpu=lambda: self.reader.cpu(self.worker),
                    clock=self.clock.now,
                )
            self.assertIs(caught.exception, error)
            self.assertEqual(json.loads(path.read_text())["native_outcome"]["status"], "raised")

    def test_cpu_failure_does_not_replace_native_return(self):
        self.reader.bad_cpu = self.worker.pid
        issues = []
        self.assertEqual(self.invoke(lambda: 9, report_issue=issues.append), 9)
        self.assertEqual(len(issues), 1)
        self.assertFalse((self.output / "end.json").exists())

    def test_publication_failure_does_not_replace_native_exception(self):
        error = RuntimeError("native")
        issues = []

        def native():
            raise error

        def fail(*args):
            raise OSError("disk")

        with self.assertRaises(RuntimeError) as caught:
            self.invoke(native, publisher=fail, report_issue=issues.append)
        self.assertIs(caught.exception, error)
        self.assertTrue(issues)

    def test_measurement_keyboard_interrupt_does_not_mask_native(self):
        error = RuntimeError("native")

        def native():
            raise error

        def fail(*args):
            raise KeyboardInterrupt()

        with self.assertRaises(RuntimeError) as caught:
            self.invoke(native, publisher=fail, report_issue=lambda message: None)
        self.assertIs(caught.exception, error)

    def test_existing_record_is_preserved(self):
        path = self.output / "end.json"
        path.write_bytes(b"existing")
        self.assertEqual(self.invoke(lambda: 0, report_issue=lambda message: None), 0)
        self.assertEqual(path.read_bytes(), b"existing")

    def test_foreign_cpu_identity_is_rejected(self):
        cpu = self.reader.cpu(self.worker)
        cpu["identity"] = self.supervisor.as_dict()
        issues = []
        result = run_entry(
            self.context,
            lambda: 0,
            self.output / "end.json",
            identity=self.worker,
            read_cpu=lambda: cpu,
            report_issue=issues.append,
        )
        self.assertEqual(result, 0)
        self.assertTrue(issues)
        self.assertFalse((self.output / "end.json").exists())

    def test_own_end_record_publication_follows_cpu_read(self):
        events = []

        def cpu():
            events.append("cpu")
            return self.reader.cpu(self.worker)

        def writer(path, value):
            events.append("publish")
            publish(path, value)

        run_entry(
            self.context,
            lambda: events.append("native"),
            self.output / "end.json",
            identity=self.worker,
            read_cpu=cpu,
            publisher=writer,
            clock=self.clock.now,
        )
        self.assertEqual(events, ["native", "cpu", "publish"])

    def test_entry_origin_and_hash_are_checked(self):
        import overhead_fixtures

        source = Path(overhead_fixtures.__file__).with_name("native.py").resolve()
        Entry(
            "overhead_fixtures.native", source, hashlib.sha256(source.read_bytes()).hexdigest()
        ).verify()
        with self.assertRaises(ValueError):
            Entry("overhead_fixtures.native", source, "0" * 64).verify()
        with self.assertRaises(ImportError):
            Entry("overhead_fixtures.native", self.output / "other.py", "0" * 64).verify()

    def test_module_cli_preserves_argv_and_original_failure(self):
        import overhead_fixtures

        source = Path(overhead_fixtures.__file__).with_name("native.py").resolve()
        manifest = self.output / "manifest.json"
        manifest.write_text(json.dumps({"behavior": "raise"}))
        before = sys.argv
        with self.assertRaisesRegex(RuntimeError, "synthetic native failure"):
            Entry(
                "overhead_fixtures.native", source, hashlib.sha256(source.read_bytes()).hexdigest()
            ).invoke(["--manifest", str(manifest)])
        self.assertIs(sys.argv, before)

    def test_atomic_publication_never_replaces_an_existing_file(self):
        p = self.output / "result.json"
        publish(p, {"value": 1})
        with self.assertRaises(FileExistsError):
            publish(p, {"value": 2})
        self.assertEqual(json.loads(p.read_text()), {"value": 1})
        self.assertEqual(len(list(self.output.iterdir())), 1)

    def test_sync_failure_leaves_no_published_record(self):
        with (
            patch("overhead.publication.os.fsync", side_effect=OSError("sync")),
            self.assertRaises(OSError),
        ):
            publish(self.output / "bad.json", {"value": 1})
        self.assertEqual(list(self.output.iterdir()), [])


class PathPointerTests(Fixture):
    def test_relative_and_absolute_paths_bind_the_same_published_artifact(self):
        import os

        from overhead.publication import pointer
        from overhead.results import read_bound

        original = os.getcwd()
        try:
            os.chdir(self.output)
            path = Path("bound.json")
            publish(
                path,
                {
                    "schema_version": 1,
                    "record_type": "test-bound",
                    "context": self.context.as_dict(),
                },
            )
            self.assertEqual(pointer(path), pointer(path.absolute()))
            value = read_bound(path.absolute(), pointer(path), self.context, "test-bound")
            self.assertEqual(value["record_type"], "test-bound")
        finally:
            os.chdir(original)
