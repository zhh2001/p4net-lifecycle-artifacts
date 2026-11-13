"""Check retained input bindings using temporary files and synthetic metadata."""

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from base64 import urlsafe_b64encode
from pathlib import Path
from unittest.mock import patch

from harness import campaign_inputs


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n")
    return path


def rehash(binding):
    payload = {key: value for key, value in binding.items() if key != "input_lock_sha256"}
    binding["input_lock_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.plan = write(self.base / "plans" / "frozen.json", {"schedule": ["case-1"]})
        self.source = write(self.base / "harness" / "worker.py", {"source": "baseline"})
        self.workload = write(self.base / "harness" / "workloads" / "l3.p4", {"p4": "valid"})
        self.environment = write(self.base / "deps" / "tool" / "environment.json", {"python": 3})
        self.tools = write(self.base / "deps" / "tools.json", {"tools": []})
        self.mininet = write(self.base / "deps" / "mininet.json", {"files": []})
        self.artifact = write(self.base / "artifact.whl", {"package": "test"})
        self.dependency_data = {
            "environment_files": {"tool": "tool/environment.json"},
            "tools_file": "tools.json",
            "mininet_source_file": "mininet.json",
            "artifacts": {"tool": {"path": "../artifact.whl", "sha256": digest(self.artifact)}},
        }
        self.dependency = write(self.base / "deps" / "manifest.json", self.dependency_data)
        self.control_data = {
            "campaign": {"path": "plans/frozen.json", "sha256": digest(self.plan)},
            "dependency_freeze": {"path": "deps/manifest.json", "sha256": digest(self.dependency)},
            "sources": {
                "harness/worker.py": digest(self.source),
                "harness/workloads/l3.p4": digest(self.workload),
            },
        }
        self.control = write(self.base / "frozen-control.json", self.control_data)

    def build(self, **kwargs):
        options = {"mode": "synthetic-validation", "base": self.base}
        options.update(kwargs)
        return campaign_inputs.build_binding(
            self.plan, self.control, self.dependency, [self.source, self.workload], **options
        )

    def save_control(self):
        write(self.control, self.control_data)

    def save_dependency(self):
        write(self.dependency, self.dependency_data)
        self.control_data["dependency_freeze"]["sha256"] = digest(self.dependency)
        self.save_control()

    def test_binding_retains_primary_and_linked_files_without_native_operations(self):
        with patch("subprocess.run", side_effect=AssertionError("unexpected execution")):
            binding = self.build()
            campaign_inputs.verify_binding(binding, base=self.base)
        self.assertFalse(binding["performance_samples"])
        self.assertEqual(
            binding["plan"], {"path": "plans/frozen.json", "sha256": digest(self.plan)}
        )
        self.assertEqual(
            set(binding["locked_inputs"]),
            {"deps/tool/environment.json", "deps/tools.json", "deps/mininet.json", "artifact.whl"},
        )
        self.assertEqual(binding["historical_source_drift"], [])
        self.assertEqual(
            binding["measurement_defaults"],
            {"duration_ns": 10_000_000_000, "interval_ns": 100_000_000},
        )

    def test_frozen_plan_hash_and_path_are_enforced(self):
        write(self.plan, {"changed": True})
        with self.assertRaisesRegex(ValueError, "plan hash differs"):
            self.build()
        self.control_data["campaign"]["sha256"] = digest(self.plan)
        self.control_data["campaign"]["path"] = "somewhere-else.json"
        self.save_control()
        with self.assertRaisesRegex(ValueError, "plan path differs"):
            self.build()

    def test_explicit_plan_pin_accepts_a_new_plan_without_changing_control(self):
        original = self.control.read_bytes()
        self.plan = write(self.base / "plans" / "measurement.json", {"measurement": True})
        binding = self.build(plan_sha256=digest(self.plan))
        campaign_inputs.verify_binding(binding, base=self.base)
        self.assertEqual(self.control.read_bytes(), original)
        with self.assertRaisesRegex(ValueError, "plan hash differs"):
            self.build(plan_sha256="a" * 64)

    def test_dependency_pointer_hash_and_path_are_enforced(self):
        write(self.dependency, {"changed": True})
        with self.assertRaisesRegex(ValueError, "manifest hash differs"):
            self.build()
        self.control_data["dependency_freeze"]["sha256"] = digest(self.dependency)
        self.control_data["dependency_freeze"]["path"] = "other/manifest.json"
        self.save_control()
        with self.assertRaisesRegex(ValueError, "manifest path differs"):
            self.build()

    def test_historical_code_drift_is_informational_and_workload_drift_is_rejected(self):
        write(self.source, {"source": "updated"})
        binding = self.build()
        self.assertEqual(
            binding["historical_source_drift"],
            [
                {
                    "path": "harness/worker.py",
                    "expected_sha256": self.control_data["sources"]["harness/worker.py"],
                    "actual_sha256": digest(self.source),
                }
            ],
        )
        campaign_inputs.verify_binding(binding, base=self.base)
        write(self.workload, {"p4": "changed"})
        with self.assertRaisesRegex(ValueError, "P4 source hash differs"):
            self.build()

    def test_artifact_pin_is_enforced(self):
        write(self.artifact, {"package": "changed"})
        with self.assertRaisesRegex(ValueError, "artifact hash differs"):
            self.build()

    def test_every_linked_file_is_required(self):
        for path in (self.environment, self.tools, self.mininet, self.artifact):
            with self.subTest(path=path):
                original = path.read_bytes()
                path.unlink()
                with self.assertRaises(FileNotFoundError):
                    self.build()
                path.write_bytes(original)

    def test_resume_detects_primary_source_and_linked_file_changes(self):
        binding = self.build()
        paths = (
            self.plan,
            self.control,
            self.dependency,
            self.source,
            self.workload,
            self.environment,
            self.tools,
            self.mininet,
            self.artifact,
        )
        for path in paths:
            with self.subTest(path=path):
                original = path.read_bytes()
                path.write_bytes(original + b" ")
                with self.assertRaisesRegex(ValueError, "input file hash differs"):
                    campaign_inputs.verify_binding(binding, base=self.base)
                path.write_bytes(original)

    def test_resume_detects_self_hash_and_rehashed_link_removal(self):
        binding = self.build()
        changed = copy.deepcopy(binding)
        changed["measurement_defaults"]["duration_ns"] += 1
        with self.assertRaisesRegex(ValueError, "binding hash differs"):
            campaign_inputs.verify_binding(changed, base=self.base)
        changed = copy.deepcopy(binding)
        del changed["locked_inputs"]["deps/tools.json"]
        rehash(changed)
        with self.assertRaisesRegex(ValueError, "linked input contract"):
            campaign_inputs.verify_binding(changed, base=self.base)

    def test_output_path_does_not_enter_binding_and_source_order_is_stable(self):
        first = self.build()
        (self.base / "output-a").mkdir()
        second = campaign_inputs.build_binding(
            self.plan,
            self.control,
            self.dependency,
            [self.workload, self.source],
            mode="synthetic-validation",
            base=self.base,
        )
        self.assertEqual(first, second)
        self.assertNotIn(str(self.base), json.dumps(first))

    def test_external_absolute_inputs_and_lexical_normalization_are_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            external = write(Path(directory) / "external.py", {"source": "external"})
            binding = campaign_inputs.build_binding(
                self.plan.parent / ".." / "plans" / self.plan.name,
                self.control,
                self.dependency,
                [external],
                mode="synthetic-validation",
                base=self.base,
            )
            self.assertIn(str(external), binding["sources"])
            self.assertEqual(binding["plan"]["path"], "plans/frozen.json")
            campaign_inputs.verify_binding(binding, base=self.base)

    def test_modes_and_integer_schedules_are_bound_and_validated(self):
        original = self.build()
        for mode in ("synthetic-validation", "pilot", "formal"):
            binding = self.build(mode=mode, duration_ns=20, interval_ns=5)
            self.assertIs(binding["performance_samples"], mode != "synthetic-validation")
            self.assertNotEqual(original["input_lock_sha256"], binding["input_lock_sha256"])
            campaign_inputs.verify_binding(binding, base=self.base)
        for options in (
            {"mode": "incorrect"},
            {"duration_ns": 0},
            {"duration_ns": 1.0},
            {"interval_ns": True},
            {"interval_ns": 0},
            {"interval_ns": 20_000_000_000},
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.build(**options)

    def test_malformed_digests_and_metadata_are_rejected(self):
        for value in (None, "", "g" * 64, 4):
            self.control_data["dependency_freeze"]["sha256"] = value
            self.save_control()
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.build()
        self.control_data["dependency_freeze"]["sha256"] = digest(self.dependency)
        self.save_control()
        binding = self.build()
        for field in ("input_lock_sha256",):
            changed = copy.deepcopy(binding)
            changed[field] = "invalid"
            with self.assertRaises(ValueError):
                campaign_inputs.verify_binding(changed, base=self.base)
        for field, value in (("schema_version", True), ("performance_samples", 0)):
            changed = copy.deepcopy(binding)
            changed[field] = value
            rehash(changed)
            with self.assertRaises(ValueError):
                campaign_inputs.verify_binding(changed, base=self.base)

    def test_strict_json_rejects_nonfinite_values_and_duplicate_keys(self):
        for payload in ('{"sources":NaN}', '{"campaign":{},"campaign":{}}'):
            self.control.write_text(payload)
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.build()


class NativeEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "native"
        self.purelib = self.root / "env" / "lib" / "site-packages"
        self.package = write(self.purelib / "demo_pkg.py", {"package": "fixture"})
        self.info = self.purelib / "demo_pkg-1.0.dist-info"
        self.info.mkdir()
        (self.info / "METADATA").write_text(
            "Metadata-Version: 2.1\nName: Demo_Pkg\nVersion: 1.0\n\n"
        )
        self.record = self.info / "RECORD"
        rows = []
        for path in (self.package, self.info / "METADATA"):
            encoded = urlsafe_b64encode(hashlib.sha256(path.read_bytes()).digest()).rstrip(b"=")
            rows.append(
                f"{path.relative_to(self.purelib)},sha256={encoded.decode()},{path.stat().st_size}"
            )
        rows.append(f"{self.record.relative_to(self.purelib)},,")
        self.record.write_text("\n".join(rows) + "\n")
        self.python = write(self.root / "python", {"interpreter": "fixture"})
        self.interpreter = self.root / "env" / "bin" / "python"
        self.interpreter.parent.mkdir(parents=True)
        self.interpreter.symlink_to(self.python)
        self.library = write(self.root / "libpython.so", {"library": "fixture"})
        self.tool = write(self.root / "tool", {"tool": "fixture"})
        self.mininet = self.root / "mininet"
        self.mininet_source = write(self.mininet / "__init__.py", {"mininet": "fixture"})
        self.link = self.purelib / "mininet"
        self.link.symlink_to(self.mininet, target_is_directory=True)
        self.environment_data = {
            "executable": str(self.interpreter),
            "base_executable": str(self.interpreter),
            "interpreter_identity": self.identity(self.interpreter),
            "base_interpreter_identity": self.identity(self.interpreter),
            "python_library_identity": self.identity(self.library),
            "sysconfig_paths": {"purelib": str(self.purelib)},
            "distributions": [
                {
                    "name": "demo-pkg",
                    "version": "1.0",
                    "metadata_sha256": digest(self.info / "METADATA"),
                    "record_sha256": digest(self.record),
                    "recorded_files": 3,
                    "installation_root": str(self.purelib),
                }
            ],
            "mininet_package_link": {
                "path": str(self.link),
                "resolved_source": str(self.mininet),
                "is_symlink": True,
                "matches_frozen_system_source": True,
            },
        }
        self.environment = write(self.base / "fixture" / "environment.json", self.environment_data)
        self.tools = write(self.base / "tools.json", {"fixture-tool": self.identity(self.tool)})
        self.mininet_manifest = write(
            self.base / "mininet.json",
            {
                "source_root": str(self.mininet),
                "python_source_files": {"__init__.py": digest(self.mininet_source)},
            },
        )
        self.dependency = write(
            self.base / "manifest.json",
            {
                "environment_files": {"fixture": "fixture/environment.json"},
                "tools_file": "tools.json",
                "tools": ["fixture-tool"],
                "mininet_source_file": "mininet.json",
            },
        )

    def identity(self, path):
        return {
            "path": str(path),
            "real_path": str(path.resolve()),
            "sha256": digest(path),
            "size_bytes": path.stat().st_size,
        }

    def verify(self, labels=("fixture",), **kwargs):
        campaign_inputs.verify_native_environment(self.dependency, labels=labels, **kwargs)

    def build_binding(self):
        artifact = write(self.base / "artifact.whl", {"artifact": "fixture"})
        dependency = json.loads(self.dependency.read_text())
        dependency["artifacts"] = {"fixture": {"path": str(artifact), "sha256": digest(artifact)}}
        write(self.dependency, dependency)
        plan = write(self.base / "plan.json", {"plan": "fixture"})
        control = write(
            self.base / "control.json",
            {
                "campaign": {"path": "plan.json", "sha256": digest(plan)},
                "dependency_freeze": {"path": "manifest.json", "sha256": digest(self.dependency)},
            },
        )
        return campaign_inputs.build_binding(
            plan,
            control,
            self.dependency,
            [self.mininet_source],
            mode="synthetic-validation",
            base=self.base,
        )

    def add_legacy(self):
        legacy = self.purelib / "legacy.egg-info"
        legacy.mkdir()
        (legacy / "PKG-INFO").write_text("Metadata-Version: 1.0\nName: Legacy\nVersion: 0.1\n")
        (legacy / "SOURCES.txt").write_text(
            "legacy.py\nlegacy.egg-info/PKG-INFO\nlegacy.egg-info/SOURCES.txt\n"
        )
        source = write(self.purelib / "legacy.py", {"legacy": "fixture"})
        self.environment_data["distributions"].append(
            {
                "name": "legacy",
                "version": "0.1",
                "metadata_sha256": None,
                "record_sha256": None,
                "recorded_files": 3,
                "installation_root": str(self.purelib),
            }
        )
        self.save_environment()
        return source, legacy / "PKG-INFO", legacy / "SOURCES.txt"

    def save_environment(self):
        write(self.environment, self.environment_data)

    def test_preflight_reads_only_fixture_files_and_never_imports_package(self):
        with (
            patch("subprocess.run", side_effect=AssertionError("unexpected execution")),
            patch("subprocess.Popen", side_effect=AssertionError("unexpected process")),
        ):
            self.verify()
        self.assertNotIn("demo_pkg", sys.modules)

    def test_native_tool_interpreter_base_and_library_changes_are_rejected(self):
        for path in (self.tool, self.python, self.library):
            with self.subTest(path=path):
                original = path.read_bytes()
                path.write_bytes(original + b" ")
                with self.assertRaisesRegex(ValueError, "file hash differs"):
                    self.verify()
                path.write_bytes(original)
        self.environment_data["base_interpreter_identity"]["sha256"] = "a" * 64
        self.save_environment()
        with self.assertRaisesRegex(ValueError, "base_interpreter_identity file hash differs"):
            self.verify()

    def test_interpreter_symlink_retarget_is_rejected_even_with_same_content(self):
        other = self.root / "other-python"
        other.write_bytes(self.python.read_bytes())
        self.interpreter.unlink()
        self.interpreter.symlink_to(other)
        with self.assertRaisesRegex(ValueError, "resolved path differs"):
            self.verify()

    def test_mininet_source_change_extra_file_and_package_link_change_are_rejected(self):
        original = self.mininet_source.read_bytes()
        self.mininet_source.write_bytes(original + b" ")
        with self.assertRaisesRegex(ValueError, "Mininet source hash differs"):
            self.verify()
        self.mininet_source.write_bytes(original)
        extra = write(self.mininet / "extra.py", {"extra": True})
        with self.assertRaisesRegex(ValueError, "source file set differs"):
            self.verify()
        extra.unlink()
        other = self.root / "other-mininet"
        other.mkdir()
        self.link.unlink()
        self.link.symlink_to(other, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "package link differs"):
            self.verify()

    def test_installed_package_content_is_checked_against_record_hash(self):
        self.package.write_bytes(self.package.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "distribution file hash differs"):
            self.verify()

    def test_missing_record_hashed_file_is_rejected(self):
        self.package.unlink()
        with self.assertRaises((FileNotFoundError, ValueError)):
            self.verify()

    def test_metadata_and_record_drift_are_rejected(self):
        for path, error in ((self.info / "METADATA", "METADATA"), (self.record, "RECORD")):
            with self.subTest(path=path):
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                with self.assertRaisesRegex(ValueError, f"distribution {error} hash differs"):
                    self.verify()
                path.write_bytes(original)

    def test_missing_extra_and_duplicate_distributions_are_rejected(self):
        self.environment_data["distributions"] = []
        self.save_environment()
        with self.assertRaisesRegex(ValueError, "extra=\\['demo-pkg'\\]"):
            self.verify()
        self.environment_data["distributions"] = [{"name": "missing", "version": "1"}]
        self.save_environment()
        with self.assertRaisesRegex(ValueError, "missing=\\['missing'\\]"):
            self.verify()
        other = self.purelib / "duplicate-1.0.dist-info"
        other.mkdir()
        (other / "METADATA").write_text("Name: demo.pkg\nVersion: 1.0\n")
        with self.assertRaisesRegex(ValueError, "duplicate installed distribution"):
            self.verify()

    def test_distribution_version_and_installation_root_are_enforced(self):
        package = self.environment_data["distributions"][0]
        package["version"] = "2.0"
        self.save_environment()
        with self.assertRaisesRegex(ValueError, "version differs"):
            self.verify()
        package["version"] = "1.0"
        package["installation_root"] = str(self.root)
        self.save_environment()
        with self.assertRaisesRegex(ValueError, "installation root differs"):
            self.verify()

    def test_labels_are_required_known_and_distinct(self):
        for labels in ([], ["missing"], ["fixture", "fixture"], "fixture"):
            with self.subTest(labels=labels), self.assertRaises(ValueError):
                self.verify(labels)

    def test_legacy_files_require_explicit_effective_pins_and_reject_mutation(self):
        files = self.add_legacy()
        with self.assertRaisesRegex(ValueError, "insufficient file coverage"):
            self.verify()
        pins = {path.relative_to(self.base).as_posix(): digest(path) for path in files}
        self.verify(file_hashes=pins, base=self.base)
        missing = dict(pins)
        del missing[files[0].relative_to(self.base).as_posix()]
        with self.assertRaisesRegex(ValueError, "insufficient file coverage"):
            self.verify(file_hashes=missing, base=self.base)
        files[0].write_bytes(files[0].read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "unhashed distribution file differs"):
            self.verify(file_hashes=pins, base=self.base)

    def test_binding_snapshots_all_unhashed_files_and_resume_rejects_source_changes(self):
        files = self.add_legacy()
        binding = self.build_binding()
        for path in (*files, self.record):
            self.assertEqual(
                binding["locked_inputs"][path.relative_to(self.base).as_posix()], digest(path)
            )
        campaign_inputs.verify_binding(binding, base=self.base)
        self.verify(file_hashes=binding["locked_inputs"], base=self.base)
        files[0].write_bytes(files[0].read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "input file hash differs"):
            campaign_inputs.verify_binding(binding, base=self.base)
        with self.assertRaisesRegex(ValueError, "unhashed distribution file differs"):
            self.verify(file_hashes=binding["locked_inputs"], base=self.base)

    def test_missing_unhashed_distribution_file_prevents_binding(self):
        files = self.add_legacy()
        files[0].unlink()
        with self.assertRaises((FileNotFoundError, ValueError)):
            self.build_binding()

    def test_generated_caches_can_change_disappear_and_reappear_between_attempts(self):
        caches = [
            write(self.purelib / "demo_pkg.pyc", {"cache": "fixture"}),
            write(self.purelib / "demo_pkg.pyo", {"cache": "fixture"}),
            write(self.purelib / "__pycache__" / "demo_pkg.pyc", {"cache": "fixture"}),
            write(self.purelib / "__pycache__" / "other.bin", {"cache": "fixture"}),
        ]
        cache_rows = []
        for index, path in enumerate(caches):
            file_hash = ""
            if index == 0:
                encoded = urlsafe_b64encode(hashlib.sha256(path.read_bytes()).digest()).rstrip(b"=")
                file_hash = f"sha256={encoded.decode()}"
            cache_rows.append(f"{path.relative_to(self.purelib)},{file_hash},\n")
        self.record.write_text(self.record.read_text() + "".join(cache_rows))
        self.environment_data["distributions"][0]["record_sha256"] = digest(self.record)
        self.environment_data["distributions"][0]["recorded_files"] += len(caches)
        self.save_environment()
        binding = self.build_binding()
        for path in caches:
            self.assertNotIn(path.relative_to(self.base).as_posix(), binding["locked_inputs"])
            path.write_bytes(b"recreated cache")
        self.verify()
        campaign_inputs.verify_binding(binding, base=self.base)
        for path in caches:
            path.unlink()
        self.verify()
        campaign_inputs.verify_binding(binding, base=self.base)
        for path in caches:
            path.write_bytes(b"new cache")
        self.verify()
        campaign_inputs.verify_binding(binding, base=self.base)

    def test_legacy_installed_paths_and_historical_source_counts_use_distinct_roots(self):
        source, package_info, sources_file = self.add_legacy()
        legacy = package_info.parent
        sources_file.write_text(
            "COPYING\nREADME\nlegacy.py\nsetup.py\nlegacy.egg-info/PKG-INFO\n"
            "legacy.egg-info/SOURCES.txt\nlegacy.egg-info/dependency_links.txt\n"
            "legacy.egg-info/top_level.txt\n"
        )
        dependency_links = write(legacy / "dependency_links.txt", {"links": []})
        top_level = write(legacy / "top_level.txt", {"package": "legacy"})
        installed_file = legacy / "installed-files.txt"
        installed_file.write_text(
            "../__pycache__/legacy.cpython-310.pyc\n../legacy.py\nPKG-INFO\nSOURCES.txt\n"
            "dependency_links.txt\ntop_level.txt\n"
        )
        self.environment_data["distributions"][-1]["recorded_files"] = 8
        self.save_environment()
        binding = self.build_binding()
        required = (source, package_info, sources_file, dependency_links, top_level, installed_file)
        for path in required:
            self.assertEqual(
                binding["locked_inputs"][path.relative_to(self.base).as_posix()], digest(path)
            )
        self.verify(file_hashes=binding["locked_inputs"], base=self.base)
        campaign_inputs.verify_binding(binding, base=self.base)
        script = write(self.root / "bin" / "legacy-run", {"script": "fixture"})
        installed_file.write_text(installed_file.read_text() + "../../../../bin/legacy-run\n")
        binding = self.build_binding()
        self.assertEqual(
            binding["locked_inputs"][script.relative_to(self.base).as_posix()], digest(script)
        )
        self.verify(file_hashes=binding["locked_inputs"], base=self.base)
        source.unlink()
        with self.assertRaises(FileNotFoundError):
            self.build_binding()


if __name__ == "__main__":
    unittest.main()
