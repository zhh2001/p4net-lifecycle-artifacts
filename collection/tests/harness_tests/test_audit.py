"""Ownership and parsing checks for independent resource auditing."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from harness import audit


def process(pid: int, parent: int = 1, **values: object) -> dict[str, object]:
    return {
        "pid": pid,
        "ppid": parent,
        "start_ticks": pid * 100,
        "state": "S",
        "name": "worker",
        "cmdline": ["python", "worker.py"],
        "netns": "net:[1]",
        **values,
    }


class ProcessOwnershipTests(unittest.TestCase):
    def test_stat_parser_preserves_spaces_and_parentheses(self) -> None:
        fields = ["S", "5"] + ["0"] * 17 + ["12345"] + ["0"] * 4
        result = audit.parse_process_stat("23 (name (with) spaces)) " + " ".join(fields))
        self.assertEqual(result["pid"], 23)
        self.assertEqual(result["name"], "name (with) spaces)")
        self.assertEqual(result["ppid"], 5)
        self.assertEqual(result["start_ticks"], 12345)

    def test_worker_identity_and_descendants_survive_unmarked_arguments(self) -> None:
        processes = {10: process(10), 20: process(20), 21: process(21, 20)}
        manifest = {"prefix": "r123abc", "worker_identity": {"pid": 20, "start_ticks": 2000}}
        owned = audit.select_owned_processes(processes, manifest, set(), 10)
        self.assertEqual([record["pid"] for record in owned], [20, 21])
        self.assertEqual(owned[1]["ownership"], ["worker_descendant"])

    def test_marker_candidate_does_not_make_descendants_trusted(self) -> None:
        processes = {
            10: process(10),
            20: process(20, cmdline=["tail", "/tmp/r123abc/worker.log"]),
            21: process(21, 20),
        }
        owned = audit.select_owned_processes(processes, {"prefix": "r123abc"}, set(), 10)
        self.assertEqual(owned[0]["ownership"], ["run_marker"])
        self.assertEqual(owned[1]["ownership"], ["candidate_descendant"])

    def test_registered_identity_descendants_have_independent_trust(self) -> None:
        processes = {10: process(10), 20: process(20), 21: process(21, 20)}
        manifest = {"prefix": "r123abc", "owned_processes": [{"pid": 20, "start_ticks": 2000}]}
        owned = audit.select_owned_processes(processes, manifest, set(), 10)
        self.assertEqual(owned[1]["ownership"], ["trusted_descendant"])

    def test_older_process_is_not_descendant_of_reused_parent(self) -> None:
        processes = {10: process(10), 20: process(20, start_ticks=4000), 21: process(21, 20)}
        manifest = {"prefix": "r123abc", "worker_identity": {"pid": 20, "start_ticks": 4000}}
        owned = audit.select_owned_processes(processes, manifest, set(), 10)
        self.assertEqual([record["pid"] for record in owned], [20])

    def test_reused_pid_is_not_the_registered_process(self) -> None:
        processes = {10: process(10), 20: process(20, start_ticks=9999)}
        manifest = {"prefix": "r123abc", "owned_processes": [{"pid": 20, "start_ticks": 2000}]}
        self.assertEqual(audit.select_owned_processes(processes, manifest, set(), 10), [])

    def test_ancestor_markers_do_not_capture_supervisor(self) -> None:
        processes = {
            9: process(9, cmdline=["python", "r123abc/config.json"]),
            10: process(10, 9),
            20: process(20, cmdline=["simple_switch_grpc", "-i", "1@r123abcs0-eth1"]),
        }
        owned = audit.select_owned_processes(processes, {"prefix": "r123abc"}, set(), 10)
        self.assertEqual([record["pid"] for record in owned], [20])

    def test_saved_namespace_identity_finds_unmarked_orphan(self) -> None:
        processes = {10: process(10), 55: process(55, netns="net:[900]")}
        manifest = {"prefix": "r123abc"}
        owned = audit.select_owned_processes(processes, manifest, {"net:[900]"}, 10)
        self.assertEqual([record["pid"] for record in owned], [55])
        self.assertEqual(owned[0]["ownership"], ["owned_network_namespace"])

    def test_external_blocker_identity_is_excluded(self) -> None:
        processes = {10: process(10), 55: process(55, cmdline=["listener", "r123abc"])}
        manifest = {
            "prefix": "r123abc",
            "excluded_processes": [{"pid": 55, "start_ticks": 5500}],
        }
        self.assertEqual(audit.select_owned_processes(processes, manifest, set(), 10), [])


class ListenerTests(unittest.TestCase):
    def test_proc_tcp_uses_state_and_inode_instead_of_port_alone(self) -> None:
        text = (
            "sl local_address rem_address st tx_queue rx_queue tr tm retr uid inode\n"
            "0: 0100007F:C353 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 845\n"
            "1: 0100007F:C353 00000000:0000 01 00000000:00000000 00:00000000 00000000 0 0 846\n"
        )
        entries = audit.parse_tcp_listeners(text, "ipv4")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["local_port"], 50003)
        self.assertEqual(entries[0]["socket_inode"], 845)

    def test_incomplete_tcp_table_is_not_treated_as_empty(self) -> None:
        with self.assertRaises(ValueError):
            audit.parse_tcp_listeners("header\n0: broken\n", "ipv4")

    def test_unowned_listener_on_same_service_port_is_not_reported(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            proc = root / "20"
            (proc / "fd").mkdir(parents=True)
            (proc / "net").mkdir()
            (proc / "stat").write_text(
                "20 (worker) " + " ".join(["S", "1"] + ["0"] * 17 + ["2000"])
            )
            (proc / "fd/4").symlink_to("socket:[845]")
            (proc / "net/tcp").write_text(
                "header\n"
                "0: 0100007F:C353 00000000:0000 0A 0:0 00:0 0 0 0 845\n"
                "1: 0100007F:C353 00000000:0000 0A 0:0 00:0 0 0 0 846\n"
            )
            (proc / "net/tcp6").write_text("header\n")
            errors: list[dict[str, str]] = []
            with patch.object(audit, "PROC", root):
                entries = audit._owned_listeners([process(20)], errors)
        self.assertEqual([entry["socket_inode"] for entry in entries], [845])
        self.assertEqual(errors, [])


class CaptureTests(unittest.TestCase):
    def test_deleted_named_namespace_is_reported_by_saved_identity(self) -> None:
        processes = {10: process(10), 55: process(55, netns="net:[900]")}
        manifest = {"prefix": "r123abc", "namespace_ids": ["net:[900]"]}
        with (
            patch.object(audit.os, "getpid", return_value=10),
            patch.object(audit, "_named_namespaces", return_value=[]),
            patch.object(audit, "_read_processes", return_value=processes),
            patch.object(audit, "_link_inventory", return_value=[]),
            patch.object(audit, "_owned_listeners", return_value=[]),
            patch.object(audit, "_namespace_fd_holders", return_value={}),
        ):
            snapshot = audit.capture(manifest)
        self.assertEqual(
            snapshot["namespaces"], [{"name": None, "netns": "net:[900]", "holder_pids": [55]}]
        )
        self.assertFalse(audit.is_clean(snapshot))

    def test_unmounted_namespace_descriptor_is_preserved_without_claiming_owner(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            proc = root / "55"
            (proc / "fd").mkdir(parents=True)
            (proc / "stat").write_text(
                "55 (holder) " + " ".join(["S", "1"] + ["0"] * 17 + ["5500"])
            )
            (proc / "fd/7").symlink_to("net:[900]")
            errors: list[dict[str, str]] = []
            original_stat = Path.stat

            def namespace_stat(path: Path, **kwargs: object) -> object:
                if path == root / "self/ns/net":
                    return SimpleNamespace(st_dev=4, st_ino=1)
                if path == proc / "fd/7":
                    return SimpleNamespace(st_dev=4, st_ino=900)
                return original_stat(path, **kwargs)

            with (
                patch.object(audit, "PROC", root),
                patch.object(Path, "stat", new=namespace_stat),
            ):
                holders = audit._namespace_fd_holders({55: process(55)}, {"net:[900]"}, errors)
        self.assertEqual(holders, {"net:[900]": [{"pid": 55, "start_ticks": 5500}]})
        self.assertEqual(errors, [])

    def test_namespace_mount_path_descriptor_uses_nsfs_object_identity(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            proc = root / "55"
            (proc / "fd").mkdir(parents=True)
            (proc / "stat").write_text(
                "55 (holder) " + " ".join(["S", "1"] + ["0"] * 17 + ["5500"])
            )
            (proc / "fd/7").symlink_to("/var/run/netns/removed-name (deleted)")
            errors: list[dict[str, str]] = []
            original_stat = Path.stat

            def namespace_stat(path: Path, **kwargs: object) -> object:
                if path == root / "self/ns/net":
                    return SimpleNamespace(st_dev=4, st_ino=1)
                if path == proc / "fd/7":
                    return SimpleNamespace(st_dev=4, st_ino=900)
                return original_stat(path, **kwargs)

            with (
                patch.object(audit, "PROC", root),
                patch.object(Path, "stat", new=namespace_stat),
            ):
                holders = audit._namespace_fd_holders({55: process(55)}, {"net:[900]"}, errors)
        self.assertEqual(holders, {"net:[900]": [{"pid": 55, "start_ticks": 5500}]})
        self.assertEqual(errors, [])

    def test_matching_inode_on_another_filesystem_is_not_a_namespace_holder(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            proc = root / "55"
            (proc / "fd").mkdir(parents=True)
            (proc / "stat").write_text(
                "55 (holder) " + " ".join(["S", "1"] + ["0"] * 17 + ["5500"])
            )
            (proc / "fd/7").symlink_to("/tmp/ordinary-file")
            errors: list[dict[str, str]] = []
            original_stat = Path.stat

            def namespace_stat(path: Path, **kwargs: object) -> object:
                if path == root / "self/ns/net":
                    return SimpleNamespace(st_dev=4, st_ino=1)
                if path == proc / "fd/7":
                    return SimpleNamespace(st_dev=77, st_ino=900)
                return original_stat(path, **kwargs)

            with (
                patch.object(audit, "PROC", root),
                patch.object(Path, "stat", new=namespace_stat),
            ):
                holders = audit._namespace_fd_holders({55: process(55)}, {"net:[900]"}, errors)
        self.assertEqual(holders, {})
        self.assertEqual(errors, [])

    def test_command_failure_produces_uncertain_audit(self) -> None:
        with patch.object(audit.subprocess, "run", side_effect=PermissionError("denied")):
            errors: list[dict[str, str]] = []
            self.assertIsNone(audit._command(["ip", "netns", "list"], errors))
        self.assertEqual(len(errors), 1)
        snapshot = {key: [] for key in audit.RESOURCE_KEYS}
        snapshot["snapshot_errors"] = errors
        self.assertFalse(audit.is_clean(snapshot))

    def test_missing_audit_fields_do_not_mean_clean(self) -> None:
        self.assertFalse(audit.is_clean({}))
        self.assertTrue(
            audit.is_clean({key: [] for key in (*audit.RESOURCE_KEYS, "snapshot_errors")})
        )


class RootInterfaceComparisonTests(unittest.TestCase):
    def snapshot(self, links: list[dict[str, object]]) -> dict[str, object]:
        return {
            **{key: [] for key in (*audit.RESOURCE_KEYS, "snapshot_errors")},
            "prefix": "r123abc",
            "root_interface_inventory": links,
        }

    def test_unprefixed_added_temporary_link_is_uncertain(self) -> None:
        before = self.snapshot([{"ifindex": 1, "ifname": "lo"}])
        after = self.snapshot([{"ifindex": 1, "ifname": "lo"}, {"ifindex": 8, "ifname": "tmpabc"}])
        result = audit.compare_root_interfaces(before, after)
        self.assertFalse(audit.is_clean(result))
        self.assertEqual(
            result["snapshot_errors"][0]["changes"],
            [{"ifindex": 8, "before": None, "after": "tmpabc"}],
        )
        self.assertEqual(after["snapshot_errors"], [])

    def test_unrelated_removed_and_renamed_links_are_uncertain(self) -> None:
        before = self.snapshot(
            [{"ifindex": 2, "ifname": "eth0"}, {"ifindex": 3, "ifname": "veth3"}]
        )
        after = self.snapshot([{"ifindex": 2, "ifname": "renamed"}])
        changes = audit.compare_root_interfaces(before, after)["snapshot_errors"][0]["changes"]
        self.assertEqual(
            changes,
            [
                {"ifindex": 2, "before": "eth0", "after": "renamed"},
                {"ifindex": 3, "before": "veth3", "after": None},
            ],
        )

    def test_run_prefixed_links_remain_owned_residuals(self) -> None:
        before = self.snapshot([])
        link = {"ifindex": 8, "ifname": "r123abcs0-eth1"}
        after = self.snapshot([link])
        after["interfaces"] = [{**link, "namespace": "root"}]
        result = audit.compare_root_interfaces(before, after)
        self.assertEqual(result["snapshot_errors"], [])
        self.assertFalse(audit.is_clean(result))

    def test_lightweight_fake_snapshots_are_unchanged(self) -> None:
        after = {key: [] for key in (*audit.RESOURCE_KEYS, "snapshot_errors")}
        self.assertIs(audit.compare_root_interfaces({}, after), after)


if __name__ == "__main__":
    unittest.main()
