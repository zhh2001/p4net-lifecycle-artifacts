"""Exercise relocated worker inputs and pre-dispatch dependency failures."""

import copy
import hashlib
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from harness import campaign_inputs, isolation, worker_tutorial
from harness import worker_components as components

from harness_tests import test_campaign_native_adapter as adapters
from harness_tests import test_observer_campaign_native as observers


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data)
    return path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class WorkerComponentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "original-study/tutorial-utils"
        for name in components.REQUIRED | {"p4runtime_lib/helper.py", "p4runtime_lib/bmv2.py"}:
            write(self.root / name, "# pinned tutorial source\n")
        write(self.root / "README.md", "tutorial component data\n")
        self.value = components.build_manifest(self.root)
        self.manifest = self.base / "inputs/worker-components.json"
        self.pin = self.save(self.value)
        self.environ = patch.dict(os.environ, {}, clear=True)
        self.environ.start()
        self.addCleanup(self.environ.stop)
        self.modules = patch.dict(sys.modules)
        self.modules.start()
        self.addCleanup(self.modules.stop)
        for name in list(sys.modules):
            if name in {"p4_mininet", "p4runtime_switch", "netstat"} or name.startswith(
                "p4runtime_lib"
            ):
                del sys.modules[name]
        self.forbidden = Mock(side_effect=AssertionError("unexpected network or worker operation"))
        for name in ("subprocess.Popen", "subprocess.run", "socket.socket"):
            manager = patch(name, self.forbidden)
            manager.start()
            self.addCleanup(manager.stop)

    def tearDown(self):
        self.forbidden.assert_not_called()

    def save(self, value):
        write(self.manifest, json.dumps(value, sort_keys=True))
        return {"path": str(self.manifest), "sha256": sha(self.manifest)}

    def set_environment(self):
        os.environ[components.ENV_FILE] = self.pin["path"]
        os.environ[components.ENV_SHA256] = self.pin["sha256"]

    def test_complete_tree_includes_data_and_excludes_generated_cache(self):
        write(self.root / "__pycache__/ignored.pyc", "cache")
        write(self.root / "ignored.pyo", "cache")
        manifest = components.build_manifest(self.root)
        self.assertEqual(manifest, self.value)
        self.assertIn("README.md", manifest["tutorial_utils"]["files"])
        self.assertEqual(components.read_manifest(self.pin), manifest)

    def test_missing_component_directory_and_required_source_are_rejected(self):
        with self.assertRaises(FileNotFoundError):
            components.build_manifest(self.base / "absent")
        (self.root / "p4runtime_switch.py").unlink()
        with self.assertRaisesRegex(ValueError, "required tutorial"):
            components.read_manifest(self.pin)

    def test_changed_source_is_detected_with_unchanged_manifest(self):
        write(self.root / "p4_mininet.py", "changed source\n")
        with self.assertRaisesRegex(ValueError, "source hash"):
            components.read_manifest(self.pin)

    def test_deleted_data_file_is_detected(self):
        (self.root / "README.md").unlink()
        with self.assertRaisesRegex(ValueError, "file set"):
            components.read_manifest(self.pin)

    def test_untracked_source_shadowing_is_detected(self):
        write(self.root / "shadow.py", "untracked source\n")
        with self.assertRaisesRegex(ValueError, "file set"):
            components.read_manifest(self.pin)

    def test_component_symbolic_link_is_not_accepted_as_source(self):
        (self.root / "p4_mininet.py").unlink()
        (self.root / "p4_mininet.py").symlink_to(write(self.base / "other.py", "source"))
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            components.read_manifest(self.pin)

    def test_manifest_symbolic_link_and_changed_bytes_are_rejected(self):
        linked = self.base / "linked.json"
        linked.symlink_to(self.manifest)
        with self.assertRaisesRegex(ValueError, "symbolic links"):
            components.read_manifest({"path": str(linked), "sha256": self.pin["sha256"]})
        write(self.manifest, "{}")
        with self.assertRaisesRegex(ValueError, "frozen identity"):
            components.read_manifest(self.pin)

    def test_wrong_schema_revision_and_inventory_paths_are_rejected(self):
        for field, value in (("schema_version", True), ("record_type", "other")):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.value)
                changed[field] = value
                with self.assertRaises(ValueError):
                    components.read_manifest(self.save(changed))
        for name in ("../outside.py", "/absolute.py", "a//b.py", "__pycache__/module.pyc"):
            with self.subTest(name=name):
                changed = copy.deepcopy(self.value)
                changed["tutorial_utils"]["files"][name] = "0" * 64
                with self.assertRaises(ValueError):
                    components.read_manifest(self.save(changed))
        changed = copy.deepcopy(self.value)
        changed["tutorial_utils"]["revision"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "revision"):
            components.read_manifest(self.save(changed))

    def test_environment_cannot_supply_a_partial_pin(self):
        self.assertIsNone(components.from_environment())
        os.environ[components.ENV_FILE] = self.pin["path"]
        with self.assertRaises(ValueError):
            components.from_environment()

    def test_isolation_discards_ambient_component_pins_without_task_metadata(self):
        self.set_environment()
        os.environ["P4NET_STUDY_COMPONENTS_UNRELATED"] = "ambient"
        environment = isolation.environment_for({"configuration_profile": "native"})
        self.assertFalse(any(name.startswith("P4NET_STUDY_COMPONENTS") for name in environment))

    def test_isolation_uses_only_explicit_metadata_and_checks_entire_tree(self):
        self.set_environment()
        os.environ[components.ENV_FILE] = "/ambient/not-used.json"
        environment = isolation.environment_for(
            {"configuration_profile": "native", "worker_components": self.pin}
        )
        self.assertEqual(environment[components.ENV_FILE], self.pin["path"])
        self.assertEqual(environment[components.ENV_SHA256], self.pin["sha256"])
        write(self.root / "README.md", "changed data")
        with self.assertRaisesRegex(ValueError, "source hash"):
            isolation.environment_for({"worker_components": self.pin})

    def test_worker_detects_wrong_origin_before_importing_any_component(self):
        self.set_environment()
        foreign = types.ModuleType("p4_mininet")
        foreign.__file__ = str(write(self.base / "wrong/p4_mininet.py", "wrong source"))
        sys.modules["p4_mininet"] = foreign
        with (
            patch.object(worker_tutorial.importlib, "import_module") as imports,
            self.assertRaisesRegex(ValueError, "outside frozen"),
        ):
            worker_tutorial.load_components()
        imports.assert_not_called()

    def test_nested_cached_module_origin_is_also_checked(self):
        module = types.ModuleType("p4runtime_lib.helper")
        module.__file__ = str(write(self.base / "foreign/helper.py", "wrong"))
        sys.modules[module.__name__] = module
        with self.assertRaisesRegex(ValueError, "outside frozen"):
            components.verify_loaded_modules(self.value)

    def test_loaded_source_drift_is_rejected_even_without_full_inventory_rescan(self):
        module = types.ModuleType("p4_mininet")
        module.__file__ = str(self.root / "p4_mininet.py")
        sys.modules[module.__name__] = module
        write(Path(module.__file__), "changed after preflight")
        with self.assertRaisesRegex(ValueError, "source differs"):
            components.verify_loaded_modules(self.value)

    def test_relocated_worker_loads_pinned_components_instead_of_local_baselines(self):
        self.set_environment()
        attributes = {
            "mininet.net": "Mininet",
            "mininet.link": "TCLink",
            "p4_mininet": "P4Host",
            "p4runtime_switch": "P4RuntimeSwitch",
            "p4runtime_lib.helper": "P4InfoHelper",
            "p4runtime_lib.bmv2": "Bmv2SwitchConnection",
        }

        def import_module(name):
            module = types.ModuleType(name)
            if not name.startswith("mininet."):
                module.__file__ = str(self.root / (name.replace(".", "/") + ".py"))
                sys.modules[name] = module
            setattr(module, attributes[name], object())
            return module

        with (
            patch.object(worker_tutorial, "BASE", self.base / "relocated-capsule/no-baselines"),
            patch.object(worker_tutorial.importlib, "import_module", side_effect=import_module),
            patch.object(sys, "path", list(sys.path)),
        ):
            loaded = worker_tutorial.load_components()
            self.assertEqual(len(loaded), 6)
            self.assertEqual(sys.path[0], str(self.root))


class NativeComponentGateTests(unittest.TestCase):
    def setUp(self):
        self.fixture = adapters.CampaignNativeAdapterTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_binding_locks_manifest_and_every_component_file(self):
        fixture = self.fixture
        pin = fixture.binding["worker_components"]
        self.assertEqual(pin["path"], "worker-components.json")
        self.assertEqual(fixture.binding["locked_inputs"][pin["path"]], pin["sha256"])
        manifest = json.loads(fixture.components.read_text())
        for name, digest in manifest["tutorial_utils"]["files"].items():
            self.assertEqual(
                fixture.binding["locked_inputs"]["extracted-tutorial-utils/" + name], digest
            )
        campaign_inputs.verify_binding(fixture.binding, base=fixture.base)

    def test_component_contract_cannot_be_omitted_from_locked_inputs(self):
        fixture = self.fixture
        changed = copy.deepcopy(fixture.binding)
        del changed["locked_inputs"]["extracted-tutorial-utils/netstat.py"]
        with self.assertRaisesRegex(ValueError, "outside the frozen input"):
            components.verify_binding_components(changed, base=fixture.base)

    def test_native_preflight_without_explicit_component_pin_cannot_check_environment(self):
        fixture = self.fixture
        control = json.loads(fixture.control.read_text())
        del control["worker_components"]
        fixture.control.write_text(json.dumps(control))
        binding = fixture.build()
        backend = adapters.campaign_executor.NativeBackend("pilot", base=fixture.base)
        with self.assertRaisesRegex(ValueError, "requires explicit"):
            backend.preflight(fixture.output, binding)
        fixture.verify_environment.assert_not_called()
        fixture.launch.assert_not_called()
        self.assertFalse(fixture.output.exists())

    def test_deleted_extracted_directory_fails_before_environment_or_campaign_claim(self):
        fixture = self.fixture
        shutil.rmtree(fixture.base / "extracted-tutorial-utils")
        backend = adapters.campaign_executor.NativeBackend("pilot", base=fixture.base)
        with self.assertRaises((ValueError, FileNotFoundError)):
            backend.preflight(fixture.output, fixture.binding)
        fixture.verify_environment.assert_not_called()
        fixture.launch.assert_not_called()
        self.assertFalse(fixture.output.exists())

    def test_component_drift_after_preflight_fails_before_manifest_or_worker_creation(self):
        fixture = self.fixture
        backend = fixture.prepared_backend()
        attempt = fixture.attempt()
        write(fixture.base / "extracted-tutorial-utils/netstat.py", "changed")
        with self.assertRaisesRegex(ValueError, "source hash"):
            backend(attempt)
        fixture.create.assert_not_called()
        fixture.launch.assert_not_called()
        self.assertFalse(attempt.artifacts.exists())

    def test_native_task_manifest_propagates_the_same_component_pin_for_every_tool(self):
        fixture = self.fixture
        backend = fixture.prepared_backend()
        fixture.launch.side_effect = None
        fixture.launch.return_value = {"observation": {}, "fixture": True}
        for tool in ("p4net", "p4utils", "tutorial-components"):
            with self.subTest(tool=tool):
                attempt = fixture.attempt(tool=tool)
                backend(attempt)
                manifest = json.loads((attempt.artifacts / "manifest.json").read_text())
                self.assertEqual(
                    manifest["worker_components"],
                    {
                        "path": str(fixture.components),
                        "sha256": sha(fixture.components),
                    },
                )


class ObserverComponentGateTests(unittest.TestCase):
    def test_observer_dispatch_keeps_the_same_pin_and_rejects_dependency_drift(self):
        fixture = observers.ObserverNativeTests(methodName="runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.prepare()
        first = fixture.attempt(tool="tutorial-components")
        fixture.backend(first)
        manifest = json.loads((first.artifacts / "manifest.json").read_text())
        self.assertEqual(
            manifest["worker_components"],
            {
                "path": str(fixture.fixture.components),
                "sha256": sha(fixture.fixture.components),
            },
        )
        second = fixture.attempt(tool="p4net")
        write(fixture.base / "extracted-tutorial-utils/netstat.py", "changed after preflight")
        with self.assertRaises(ValueError):
            fixture.backend(second)
        self.assertFalse(second.artifacts.exists())
        self.assertEqual(fixture.launch.call_count, 1)


if __name__ == "__main__":
    unittest.main()
