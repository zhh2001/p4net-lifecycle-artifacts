"""Check complete observer bindings and self-contained historical allocations."""

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from harness import observer_calibration_plan
from harness import observer_campaign_inputs as inputs

from harness_tests import test_campaign_inputs as fixtures


class ObserverBindingTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.BindingTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.base = self.fixture.base
        self.plan = self.fixture.plan
        self.allocation = observer_calibration_plan.generate(scope="qualification-only")
        self.save_plan()
        self.core = fixtures.write(
            self.base / "harness" / "observer_campaign_inputs.py", {"source": "observer fixture"}
        )
        self.inventory = [self.fixture.source, self.core]
        self.runtime = patch.object(inputs, "runtime_sources", side_effect=lambda: self.inventory)
        self.runtime.start()
        self.addCleanup(self.runtime.stop)

    def save_plan(self):
        fixtures.write(self.plan, self.allocation)
        self.pin_plan()

    def pin_plan(self):
        self.fixture.control_data["campaign"] = {
            "path": str(self.plan.relative_to(self.base)),
            "sha256": fixtures.digest(self.plan),
        }
        self.fixture.save_control()

    def build(self, **kwargs):
        options = {"mode": "synthetic-validation", "base": self.base}
        options.update(kwargs)
        return inputs.build_binding(
            self.plan,
            self.fixture.control,
            self.fixture.dependency,
            [self.fixture.workload],
            **options,
        )

    def rehash(self, binding, *, inner=False):
        if inner:
            fixtures.rehash(binding["base_binding"])
        fixtures.rehash(binding)

    def test_complete_inventory_and_profiles_share_one_binding_without_native_operations(self):
        unexpected = Mock(side_effect=AssertionError("unexpected native operation"))
        with (
            patch("subprocess.Popen", unexpected),
            patch("subprocess.run", unexpected),
            patch("time.monotonic_ns", unexpected),
            patch("time.sleep", unexpected),
            patch("harness.resources.read_sample", unexpected),
        ):
            binding = self.build()
            inputs.verify_binding(binding, base=self.base)
        unexpected.assert_not_called()
        self.assertEqual([row["profile"] for row in binding["profiles"]], ["B", "T", "S"])
        self.assertNotIn("observer_profile", binding)
        self.assertEqual(
            binding["runtime_sources"], ["harness/observer_campaign_inputs.py", "harness/worker.py"]
        )
        self.assertEqual(
            set(binding["base_binding"]["sources"]),
            {
                "harness/observer_campaign_inputs.py",
                "harness/worker.py",
                "harness/workloads/l3.p4",
            },
        )
        self.assertFalse(binding["collection_authorized"])
        self.assertFalse(binding["performance_samples"])
        self.assertEqual(inputs.plan_from_binding(binding), self.allocation)

    def test_full_confirmed_plan_retains_270_calibration_and_nine_qualification_units(self):
        self.allocation = observer_calibration_plan.generate()
        self.save_plan()
        binding = self.build()
        plan = inputs.plan_from_binding(binding)
        self.assertEqual(len(plan["calibration_schedule"]), 270)
        self.assertEqual(len(plan["qualification_schedule"]), 9)
        self.assertFalse(plan["runtime_ready"])
        self.assertFalse(plan["collection_authorized"])
        self.assertEqual(binding["measurement_defaults"], inputs.DEFAULTS)

    def test_exact_utf8_plan_bytes_survive_whitespace_and_newline_formatting(self):
        raw = (json.dumps(self.allocation, indent=4) + "\n").replace("\n", "\r\n").encode()
        self.plan.write_bytes(raw)
        self.pin_plan()
        binding = self.build()
        self.assertEqual(binding["plan_content"].encode(), raw)
        self.assertEqual(binding["plan"]["sha256"], hashlib.sha256(raw).hexdigest())
        inputs.verify_binding(binding, base=self.base)

    def test_retained_analysis_survives_original_file_removal_and_runtime_evolution(self):
        binding = self.build()
        self.plan.unlink()
        self.core.write_text("updated runtime")
        self.inventory.append(fixtures.write(self.base / "harness" / "new.py", {"new": True}))
        with (
            patch.object(Path, "read_bytes", side_effect=AssertionError("unexpected file read")),
            patch.object(Path, "read_text", side_effect=AssertionError("unexpected file read")),
            patch.object(inputs, "runtime_sources", side_effect=AssertionError("runtime lookup")),
        ):
            inputs.validate_binding(binding, base=self.base)
            retained = inputs.plan_from_binding(binding)
        self.assertEqual(retained, self.allocation)
        with self.assertRaisesRegex(ValueError, "runtime inventory differs"):
            inputs.verify_binding(binding, base=self.base)

    def test_current_runtime_content_and_inventory_changes_reject_execution(self):
        binding = self.build()
        original = self.core.read_bytes()
        self.core.write_bytes(original + b"\n")
        with self.assertRaisesRegex(ValueError, "input file hash differs"):
            inputs.verify_binding(binding, base=self.base)
        self.core.write_bytes(original)
        self.inventory.append(fixtures.write(self.base / "harness" / "new.py", {"new": True}))
        with self.assertRaisesRegex(ValueError, "runtime inventory differs"):
            inputs.verify_binding(binding, base=self.base)

    def test_rehashed_core_removal_is_rejected_by_live_inventory(self):
        binding = self.build()
        del binding["base_binding"]["sources"]["harness/observer_campaign_inputs.py"]
        binding["runtime_sources"].remove("harness/observer_campaign_inputs.py")
        self.rehash(binding, inner=True)
        inputs.validate_binding(binding, base=self.base)
        with self.assertRaisesRegex(ValueError, "runtime inventory differs"):
            inputs.verify_binding(binding, base=self.base)

    def test_pilot_binding_is_distinct_but_never_grants_collection_authorization(self):
        synthetic = self.build()
        pilot = self.build(mode="pilot")
        self.assertTrue(pilot["performance_samples"])
        self.assertFalse(pilot["collection_authorized"])
        self.assertNotEqual(synthetic["input_lock_sha256"], pilot["input_lock_sha256"])
        inputs.verify_binding(pilot, base=self.base)
        for mode in ("formal", "native-validation", "offline-planning", None, True):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.build(mode=mode)

    def test_explicit_observer_pin_does_not_change_formal_control_pointer(self):
        original_control = self.fixture.control.read_bytes()
        self.plan = fixtures.write(self.base / "plans" / "observer.json", self.allocation)
        binding = self.build(plan_sha256=fixtures.digest(self.plan))
        self.assertEqual(self.fixture.control.read_bytes(), original_control)
        inputs.verify_binding(binding, base=self.base)
        with self.assertRaises(ValueError):
            self.build()
        with self.assertRaisesRegex(ValueError, "plan hash differs"):
            self.build(plan_sha256="a" * 64)

    def test_plan_generation_and_retained_byte_pins_are_independently_checked(self):
        binding = self.build()
        changed = copy.deepcopy(binding)
        changed["plan_content"] += "\n"
        self.rehash(changed)
        with self.assertRaisesRegex(ValueError, "retained observer plan bytes differ"):
            inputs.validate_binding(changed, base=self.base)
        self.allocation["collection_authorized"] = True
        self.save_plan()
        with self.assertRaisesRegex(ValueError, "deterministic allocation"):
            self.build()

    def test_rehashed_profile_schedule_and_outer_inner_mode_drift_are_rejected(self):
        original = self.build()
        variants = []
        profile = copy.deepcopy(original)
        profile["profiles"][0]["internal_recorder"] = True
        variants.append(profile)
        schedule = copy.deepcopy(original)
        schedule["measurement_defaults"]["duration_ns"] = 20_000_000_000
        variants.append(schedule)
        inner_mode = copy.deepcopy(original)
        inner_mode["base_binding"].update(mode="pilot", performance_samples=True)
        fixtures.rehash(inner_mode["base_binding"])
        variants.append(inner_mode)
        inner_schedule = copy.deepcopy(original)
        inner_schedule["base_binding"]["measurement_defaults"]["interval_ns"] = 50_000_000
        fixtures.rehash(inner_schedule["base_binding"])
        variants.append(inner_schedule)
        for value in variants:
            self.rehash(value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                inputs.validate_binding(value, base=self.base)

    def test_exact_fields_strict_booleans_and_schema_are_enforced(self):
        original = self.build()
        for field, value in (
            ("schema_version", True),
            ("performance_samples", 0),
            ("collection_authorized", True),
            ("collection_authorized", 0),
            ("record_type", "campaign-input-binding"),
            ("plan_content", b"{}"),
            ("plan_content", None),
            ("base_binding", []),
        ):
            changed = copy.deepcopy(original)
            changed[field] = value
            if not isinstance(value, bytes):
                self.rehash(changed)
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                inputs.validate_binding(changed, base=self.base)
        changed = copy.deepcopy(original)
        changed["extra"] = True
        self.rehash(changed)
        with self.assertRaises(ValueError):
            inputs.validate_binding(changed, base=self.base)
        for field in original:
            changed = copy.deepcopy(original)
            del changed[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                inputs.validate_binding(changed, base=self.base)

    def test_inventory_must_be_sorted_distinct_and_bound(self):
        original = self.build()
        for inventory in (
            [],
            list(reversed(original["runtime_sources"])),
            original["runtime_sources"] * 2,
            ["missing.py"],
            ["harness/workloads/l3.p4"],
            [1],
            "harness/worker.py",
        ):
            changed = copy.deepcopy(original)
            changed["runtime_sources"] = inventory
            self.rehash(changed)
            with self.subTest(inventory=inventory), self.assertRaises(ValueError):
                inputs.validate_binding(changed, base=self.base)

    def test_nonfinite_and_duplicate_plan_fields_are_rejected(self):
        original = self.plan.read_bytes()
        for content in (b'{"x":NaN}', b'{"seed":1,"seed":2}', b"\xff"):
            self.plan.write_bytes(content)
            with self.subTest(content=content), self.assertRaises(ValueError):
                self.build()
        self.plan.write_bytes(original)
        binding = self.build()
        binding["base_binding"]["unexpected"] = float("nan")
        with self.assertRaises(ValueError):
            inputs.validate_binding(binding, base=self.base)

    def test_default_runtime_inventory_contains_current_observer_modules(self):
        self.runtime.stop()
        paths = inputs.runtime_sources()
        self.assertEqual(paths, sorted(paths))
        self.assertIn(Path(inputs.__file__).resolve(), paths)
        self.assertIn("observer_dispatch.py", {path.name for path in paths})

    def test_default_sources_bind_the_automatic_inventory_and_stable_order(self):
        original = self.build()
        reversed_inventory = list(reversed(self.inventory))
        with patch.object(inputs, "runtime_sources", return_value=reversed_inventory):
            reordered = self.build()
        self.assertEqual(original, reordered)
        default = inputs.build_binding(
            self.plan,
            self.fixture.control,
            self.fixture.dependency,
            mode="synthetic-validation",
            base=self.base,
        )
        self.assertEqual(set(default["base_binding"]["sources"]), set(default["runtime_sources"]))
        for value in ("worker.py", Path("worker.py"), None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                inputs.build_binding(
                    self.plan,
                    self.fixture.control,
                    self.fixture.dependency,
                    value,
                    mode="synthetic-validation",
                    base=self.base,
                )

    def test_retained_plan_accessor_rejects_missing_pin_or_nonobject_binding(self):
        binding = self.build()
        for changed in (None, {}, {**binding, "plan": None}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                inputs.plan_from_binding(changed)
        with tempfile.TemporaryDirectory() as absent:
            inputs.validate_binding(binding, base=Path(absent) / "does-not-exist")
