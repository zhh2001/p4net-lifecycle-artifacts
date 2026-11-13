"""Check manifest safety and forwarding-task construction without root."""

import json
import tempfile
import unittest
from pathlib import Path

from harness import spec
from harness.worker import build


class ManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = spec.create(Path(self.temp.name) / "trial")
        self.manifest = spec.load(self.path)

    def test_rejects_duplicate_ports_before_network_creation(self) -> None:
        self.manifest["service_ports"] = [12345, 12345]
        with self.assertRaisesRegex(ValueError, "distinct"):
            spec.validate(self.manifest)

    def test_rejects_foreign_names_and_relative_paths(self) -> None:
        self.manifest["host_names"] = ["unrelated", "host"]
        with self.assertRaisesRegex(ValueError, "resource names"):
            spec.validate(self.manifest)
        self.manifest = spec.load(self.path)
        self.manifest["output_dir"] = "relative"
        with self.assertRaisesRegex(ValueError, "absolute"):
            spec.validate(self.manifest)

    def test_trial_directory_cannot_be_reused(self) -> None:
        with self.assertRaises(FileExistsError):
            spec.create(self.path.parent)

    def test_manifest_cannot_point_at_another_directory(self) -> None:
        self.manifest["output_dir"] = str(self.path.parent / "other")
        self.path.write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(ValueError, "own output"):
            spec.load(self.path)

    def test_scale_sixteen_has_valid_interfaces_and_task_pairs(self) -> None:
        path = spec.create(Path(self.temp.name) / "sixteen", groups=16)
        manifest = spec.load(path)
        topo = build(manifest)
        self.assertEqual(len(topo.hosts), 32)
        self.assertEqual(len(topo.switches), 16)
        self.assertTrue(
            all(len(ep.iface_name.encode()) <= 15 for link in topo.links for ep in (link.a, link.b))
        )
        rows = spec.task_rows(manifest)
        self.assertEqual(len(rows), 32)
        self.assertEqual(len({row["ip"] for row in rows}), 32)
        self.assertEqual(rows[0]["peer"], rows[1]["host"])
        self.assertEqual(rows[1]["peer"], rows[0]["host"])

    def test_schema_and_scale_are_strict(self) -> None:
        for field, value in (
            ("schema_version", 2),
            ("groups", True),
            ("groups", 17),
            ("purpose", "benchmark"),
        ):
            manifest = dict(self.manifest, **{field: value})
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                spec.validate(manifest)


if __name__ == "__main__":
    unittest.main()
