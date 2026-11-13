"""Qualify native artifact conversion using synthetic clocks and retained JSON."""

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import observer_campaign_result as adapter
from harness.observer_calibration_plan import generate
from harness.observer_campaign import metadata_for, observation_metadata
from harness.observer_profiles import profile_observation
from harness.observer_reference import ChildReference, ObserverIdentity, ParentReference
from harness.observer_runtime import _publish, publish_terminal, run_child
from harness.resources import ProcessTarget

from harness_tests.test_measure import Clock, observation
from harness_tests.test_measure import metadata as base_metadata


def metadata(*, profile="S", tool="p4net", fault=None, switches=1):
    return {
        **base_metadata(fault),
        "observer_profile": profile,
        "tool": tool,
        "switches": switches,
        "attempt_id": "planned--a0001",
    }


def make_fixture(artifacts, values, *, cpu_delta=1):
    """Create an ephemeral pilot-contract fixture with no live task or resource read."""
    artifacts.mkdir(parents=True, exist_ok=True)
    clock = Clock()
    identity = ObserverIdentity(2345, 100, {"pid": "pid:[9]", "net": "net:[8]", "mnt": "mnt:[7]"})
    responses, calls = [], []

    def cpu(observer):
        calls.append("cpu")
        ticks = 10 if len(calls) == 1 else 10 + cpu_delta
        return {
            "observer": observer.as_dict(),
            "user_ticks": ticks,
            "system_ticks": 0,
            "cpu_ticks": ticks,
        }

    parent = ParentReference(
        identity,
        run_id=values["run_id"],
        attempt_id=values["attempt_id"],
        profile=values["observer_profile"],
        mode="pilot",
        clock_ns=clock,
        monitor_cpu_ns=lambda: 0,
        clock_ticks=100,
        read_cpu=cpu,
        read_memory=lambda observer: {
            "observer": observer.as_dict(),
            "rss_bytes": 4096,
            "pss_bytes": 2048,
        },
        send_ack=responses.append,
    )
    child = ChildReference(
        run_id=values["run_id"],
        attempt_id=values["attempt_id"],
        profile=values["observer_profile"],
        namespaces=identity.namespaces,
        send=parent.handle,
        receive=lambda: responses.pop(0),
    )
    native = {
        "schema_version": 1,
        "run_id": values["run_id"],
        "ok": True,
        "mode": "correctness-check" if values["observer_profile"] == "B" else "pilot",
        "performance_samples": values["observer_profile"] != "B",
        "pid_namespace": "pid:[9]",
        "ready": True,
        "checks": [{"src": "h1", "dst": "h2", "ok": True}, {"src": "h2", "dst": "h1", "ok": True}],
        "worker_returncode": 0,
        "cleanup": {"ordinary_after_clean": True, "after_clean": True, "rescue_attempted": False},
    }
    episode = values["workload"] == "fault"
    phases = ("initial", "restart") if episode else ("initial",)
    if episode:
        task = {
            "ready": True,
            "checks": native["checks"],
            "worker_returncode": 0,
            "stopped": True,
            "ordinary_cleanup_clean": True,
            "ordinary_stop_timeout": False,
        }
        native.update(
            fault="normal-control",
            framework_complete=True,
            recovery_success=True,
            primary_outcome_saved_before_safety=True,
            safety_after_clean=True,
            safety_actions=[],
            fixture_safety_errors=[],
            initial=copy.deepcopy(task),
            restart=copy.deepcopy(task),
        )
    manifest = {
        "run_id": values["run_id"],
        "groups": values["switches"],
        "configuration_profile": "matched-v1",
    }
    if episode:
        manifest["episode_fault"] = "normal-control"

    def targets(*_):
        offset = 1000 if clock.now >= adapter.DURATION_NS else 0
        return (
            ProcessTarget(100 + offset, 1, "worker"),
            *(
                ProcessTarget(101 + offset + index, 2 + index, "bmv2")
                for index in range(values["switches"])
            ),
        )

    def build(callback):
        return profile_observation(
            values["observer_profile"],
            observation_metadata(values),
            mode="pilot",
            clock_domain="synthetic-clock",
            clock_ns=clock,
            sleep=clock.sleep,
            read=observation,
            select_targets=targets,
            on_primary_published=callback,
        )

    def execute(observer):
        observer.bind(manifest)
        for phase in phases:
            observer.mark("worker_launch", phase=phase, observed_ns=clock())
            observer.received({"event": "ready"}, phase=phase, observed_ns=clock())
            observer.ready(manifest, {}, {}, phase=phase)
            for boundary in (
                "stop_request",
                "stop_sent",
                "worker_exit",
                "ordinary_audit_start",
                "ordinary_audit_end",
            ):
                observer.mark(boundary, phase=phase, observed_ns=clock())
        observer.checkpoint(artifacts / "measurement-primary.json", native)
        native["observation"] = observer.finish(native)
        assert not observer.issues, observer.issues
        _publish(artifacts / "result.json", native)
        return native

    with patch("harness.faults.require_enclosure"):
        envelope = run_child(
            artifacts / "observer-child-result.json",
            child,
            mode="pilot",
            build_observation=build,
            run_task=execute,
        )
    terminal = publish_terminal(
        artifacts / "observer-calibration-result.json",
        artifacts / "observer-child-result.json",
        artifacts / "observer-reference.json",
        parent,
    )
    binding = {key: values[key] for key in ("run_id", "attempt_id", "observer_profile")}

    def reference(name):
        return {
            "path": str(artifacts / name),
            "sha256": hashlib.sha256((artifacts / name).read_bytes()).hexdigest(),
        }

    dispatch = {
        "schema_version": 1,
        "record_type": "observer-calibration-dispatch-record",
        **binding,
        "mode": "pilot",
        "performance_samples": True,
        "dispatch_status": "completed",
        "native_outcome_available": True,
        "native_ok": True,
        "native_result_source": {
            "kind": "child-envelope",
            **reference("observer-child-result.json"),
        },
        "child_result": reference("observer-child-result.json"),
        "calibration_terminal": reference("observer-calibration-result.json"),
        "cleanup_issues": [],
        "publication_error": None,
        "error": None,
        "outer_pid": 2344,
        "outer_returncode": 0,
        "inner_pid_numbers_consumed": False,
    }
    _publish(artifacts / "observer-dispatch.json", dispatch)
    return {
        "dispatch": dispatch,
        "child": envelope,
        "native": native,
        "terminal": terminal,
        "reference": json.loads((artifacts / "observer-reference.json").read_text()),
    }


def republish_fixture(artifacts, fixture):
    """Refresh downstream hashes after a deliberate fixture mutation."""

    def write(name, value):
        (artifacts / name).write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")

    def ref(name):
        return {
            "path": str(artifacts / name),
            "sha256": hashlib.sha256((artifacts / name).read_bytes()).hexdigest(),
        }

    fixture["child"]["native_result"] = fixture["native"]
    write("result.json", fixture["native"])
    write("observer-child-result.json", fixture["child"])
    fixture["reference"]["child_result"] = ref("observer-child-result.json")
    fixture["terminal"]["child_result"] = ref("observer-child-result.json")
    write("observer-reference.json", fixture["reference"])
    fixture["terminal"]["reference_sidecar"] = ref("observer-reference.json")
    write("observer-calibration-result.json", fixture["terminal"])
    fixture["dispatch"]["native_result_source"] = {
        "kind": "child-envelope",
        **ref("observer-child-result.json"),
    }
    fixture["dispatch"]["child_result"] = ref("observer-child-result.json")
    fixture["dispatch"]["calibration_terminal"] = ref("observer-calibration-result.json")
    fixture["terminal"]["native_ok"] = fixture["native"]["ok"]
    fixture["dispatch"]["native_ok"] = fixture["native"]["ok"]
    write("observer-calibration-result.json", fixture["terminal"])
    fixture["dispatch"]["calibration_terminal"] = ref("observer-calibration-result.json")
    write("observer-dispatch.json", fixture["dispatch"])


class ResultTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.artifacts = Path(temporary.name) / "artifacts"
        self.values = metadata()
        self.fixture = make_fixture(self.artifacts, self.values)

    def adapt(self):
        return adapter.adapt_result(self.fixture["dispatch"], self.values, artifacts=self.artifacts)

    def mutate(self, key, operation):
        operation(self.fixture[key])
        republish_fixture(self.artifacts, self.fixture)

    def test_all_tools_profiles_and_normal_control_qualify(self):
        for tool in ("p4net", "p4utils", "tutorial-components"):
            for profile in ("B", "T", "S"):
                for fault in (None, "normal-control"):
                    with (
                        self.subTest(tool=tool, profile=profile, fault=fault),
                        tempfile.TemporaryDirectory() as temporary,
                    ):
                        values = metadata(tool=tool, profile=profile, fault=fault)
                        artifacts = Path(temporary)
                        fixture = make_fixture(artifacts, values)
                        result = adapter.adapt_result(
                            fixture["dispatch"], values, artifacts=artifacts
                        )
                        self.assertTrue(result["measurement"]["qualified"], result["measurement"])
                        self.assertEqual(
                            result["measurement"]["metrics"],
                            {
                                "observer_body_wall_ns": 20_000_000_000
                                if fault
                                else 10_000_000_000,
                                "observer_cpu_seconds": 0.01,
                                "observer_rss_bytes": 4096,
                                "observer_pss_bytes": 2048,
                            },
                        )

    def test_zero_cpu_ticks_remain_a_valid_quantized_observation(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary)
            fixture = make_fixture(artifacts, self.values, cpu_delta=0)
            result = adapter.adapt_result(fixture["dispatch"], self.values, artifacts=artifacts)
        self.assertEqual(result["measurement"]["metrics"]["observer_cpu_seconds"], 0)
        self.assertTrue(result["measurement"]["qualified"])

    def test_bad_cpu_scalar_only_removes_cpu_metric(self):
        self.mutate("reference", lambda value: value.update(observer_cpu_seconds=42))
        result = self.adapt()["measurement"]
        self.assertEqual(result["status"], "completed")
        self.assertFalse(result["qualified"])
        self.assertNotIn("observer_cpu_seconds", result["metrics"])
        self.assertIn("observer_body_wall_ns", result["metrics"])
        self.assertIn("observer_rss_bytes", result["metrics"])

    def test_bad_wall_or_rss_keeps_other_valid_metrics(self):
        self.mutate("reference", lambda value: value.update(observer_body_wall_ns=1))
        self.fixture["reference"]["observer_memory_endpoint"]["rss_bytes"] = -1
        republish_fixture(self.artifacts, self.fixture)
        result = self.adapt()["measurement"]
        self.assertNotIn("observer_body_wall_ns", result["metrics"])
        self.assertNotIn("observer_rss_bytes", result["metrics"])
        self.assertEqual(result["metrics"]["observer_pss_bytes"], 2048)
        self.assertEqual(result["metrics"]["observer_cpu_seconds"], 0.01)

    def test_counter_decrease_or_identity_change_rejects_cpu_metric(self):
        endpoint = self.fixture["reference"]["observer_cpu_end"]
        endpoint.update(user_ticks=9, cpu_ticks=9)
        republish_fixture(self.artifacts, self.fixture)
        self.assertNotIn("observer_cpu_seconds", self.adapt()["measurement"]["metrics"])
        endpoint.update(user_ticks=11, cpu_ticks=11)
        endpoint["observer"]["host_pid"] += 1
        republish_fixture(self.artifacts, self.fixture)
        self.assertNotIn("observer_cpu_seconds", self.adapt()["measurement"]["metrics"])

    def test_missing_pointer_or_wrong_sha_drops_all_reference_metrics(self):
        for pointer in (
            None,
            {"path": str(self.artifacts / "observer-child-result.json"), "sha256": "0" * 64},
        ):
            with self.subTest(pointer=pointer):
                self.fixture["dispatch"]["child_result"] = pointer
                (self.artifacts / "observer-dispatch.json").write_text(
                    json.dumps(self.fixture["dispatch"])
                )
                result = self.adapt()["measurement"]
                self.assertEqual(result["status"], "completed")
                self.assertEqual(result["metrics"], {})
                self.assertEqual(result["reference_status"], "incomplete")

    def test_foreign_or_outside_reference_does_not_authorize_metrics(self):
        self.fixture["dispatch"]["calibration_terminal"]["path"] = str(
            self.artifacts.parent / "outside.json"
        )
        (self.artifacts / "observer-dispatch.json").write_text(json.dumps(self.fixture["dispatch"]))
        result = self.adapt()["measurement"]
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["metrics"], {})

    def test_dispatch_payload_difference_and_wrong_run_are_ineligible(self):
        self.fixture["dispatch"]["dispatch_status"] = "timeout"
        self.assertFalse(self.adapt()["measurement"]["qualified"])
        self.fixture["dispatch"]["run_id"] = "foreign"
        (self.artifacts / "observer-dispatch.json").write_text(json.dumps(self.fixture["dispatch"]))
        result = self.adapt()["measurement"]
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["metrics"], {})

    def test_missing_envelope_retains_ordinary_success_and_no_metrics(self):
        (self.artifacts / "observer-child-result.json").unlink()
        self.fixture["dispatch"].update(
            dispatch_status="failed", child_result=None, calibration_terminal=None
        )
        self.fixture["dispatch"]["native_result_source"] = {
            "kind": "ordinary-result",
            "path": str(self.artifacts / "result.json"),
            "sha256": hashlib.sha256((self.artifacts / "result.json").read_bytes()).hexdigest(),
        }
        (self.artifacts / "observer-dispatch.json").write_text(json.dumps(self.fixture["dispatch"]))
        result = self.adapt()
        self.assertTrue(result["native_result"]["ok"])
        self.assertEqual(result["measurement"]["status"], "completed")
        self.assertEqual(result["measurement"]["metrics"], {})

    def test_unknown_native_timeout_is_not_replaced_by_success(self):
        for name in ("result.json", "observer-child-result.json"):
            (self.artifacts / name).unlink()
        self.fixture["dispatch"].update(
            native_outcome_available=False,
            native_ok=None,
            native_result_source=None,
            dispatch_status="timeout",
            child_result=None,
            calibration_terminal=None,
        )
        (self.artifacts / "observer-dispatch.json").write_text(json.dumps(self.fixture["dispatch"]))
        result = self.adapt()
        self.assertEqual(result["measurement"]["status"], "timeout")
        self.assertNotIn("ok", result["native_result"])
        self.assertEqual(result["measurement"]["metrics"], {})

    def test_incomplete_window_and_rescue_do_not_rewrite_native_success(self):
        window = self.fixture["native"]["observation"]["resource_windows"]["initial"]
        window["complete"] = False
        self.fixture["native"]["cleanup"]["rescue_attempted"] = True
        republish_fixture(self.artifacts, self.fixture)
        result = self.adapt()["measurement"]
        self.assertEqual(result["status"], "completed")
        self.assertFalse(result["qualified"])
        self.assertEqual(result["reference_status"], "complete")
        self.assertFalse(result["treatment_valid"])
        self.assertEqual(result["metrics"], {})
        self.assertEqual(set(result["reference_metrics"]), set(adapter.REFERENCE_METRICS))

    def test_missing_hold_and_invalid_target_make_qualification_unavailable(self):
        self.fixture["child"]["profile_observation"]["holds"].clear()
        republish_fixture(self.artifacts, self.fixture)
        self.assertFalse(self.adapt()["measurement"]["qualified"])

    def test_missing_scheduled_endpoint_is_ineligible(self):
        self.fixture["native"]["observation"]["resource_windows"]["initial"]["rounds"].pop()
        republish_fixture(self.artifacts, self.fixture)
        self.assertFalse(self.adapt()["measurement"]["qualified"])

    def test_reference_probe_order_and_pid_namespace_bind_all_metrics(self):
        self.fixture["reference"]["reference_events"][2]["memory_probe_start_ns"] = 0
        republish_fixture(self.artifacts, self.fixture)
        self.assertEqual(self.adapt()["measurement"]["metrics"], {})
        self.fixture["reference"]["reference_events"][2]["memory_probe_start_ns"] = 10_000_000_000
        self.fixture["native"]["pid_namespace"] = "pid:[10]"
        republish_fixture(self.artifacts, self.fixture)
        self.assertEqual(self.adapt()["measurement"]["metrics"], {})

    def test_non_dict_events_and_duplicate_json_are_rejected(self):
        self.mutate("reference", lambda value: value.update(reference_events=[None, None, None]))
        self.assertEqual(self.adapt()["measurement"]["metrics"], {})
        path = self.artifacts / "observer-dispatch.json"
        path.write_text('{"schema_version":1,"schema_version":1}')
        self.assertFalse(self.adapt()["measurement"]["qualified"])

    def test_inputs_and_existing_artifact_bytes_are_unchanged(self):
        before = {
            path.name: (path.read_bytes(), path.stat().st_mtime_ns)
            for path in self.artifacts.iterdir()
        }
        values, dispatch = copy.deepcopy(self.values), copy.deepcopy(self.fixture["dispatch"])
        self.assertTrue(self.adapt()["measurement"]["qualified"])
        self.assertEqual(self.values, values)
        self.assertEqual(self.fixture["dispatch"], dispatch)
        self.assertEqual(
            before,
            {
                path.name: (path.read_bytes(), path.stat().st_mtime_ns)
                for path in self.artifacts.iterdir()
            },
        )

    def test_primary_observation_requires_its_original_boundaries_and_identity(self):
        path = self.artifacts / "measurement-primary.json"
        primary = json.loads(path.read_text())
        primary["native_observation"]["boundaries"].append(
            {"phase": "initial", "boundary": "safety_start"}
        )
        path.write_text(json.dumps(primary))
        self.fixture["child"]["primary_publication"]["sha256"] = hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        republish_fixture(self.artifacts, self.fixture)
        result = self.adapt()["measurement"]
        self.assertEqual(result["status"], "completed")
        self.assertFalse(result["qualified"])
        self.assertTrue(any("safety escalation" in issue for issue in result["measurement_issues"]))

    def test_window_endpoints_cannot_be_faked_by_only_claiming_101_rounds(self):
        window = self.fixture["native"]["observation"]["resource_windows"]["initial"]
        for sample in window["rounds"][-1]:
            sample["sample_start_ns"] -= 1
        republish_fixture(self.artifacts, self.fixture)
        self.assertFalse(self.adapt()["measurement"]["qualified"])

    def test_normal_control_recovery_failure_retains_only_reference_diagnostics(self):
        values = metadata(fault="normal-control")
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary)
            fixture = make_fixture(artifacts, values)
            fixture["native"]["recovery_success"] = False
            republish_fixture(artifacts, fixture)
            result = adapter.adapt_result(fixture["dispatch"], values, artifacts=artifacts)[
                "measurement"
            ]
        self.assertEqual(result["status"], "completed")
        self.assertFalse(result["treatment_valid"])
        self.assertFalse(result["qualified"])
        self.assertEqual(result["metrics"], {})
        self.assertEqual(set(result["reference_metrics"]), set(adapter.REFERENCE_METRICS))

    def test_outer_timeout_does_not_relabel_an_already_published_native_failure(self):
        self.fixture["native"].update(
            ok=False, error={"type": "NativeFailure", "message": "failed"}
        )
        self.fixture["dispatch"]["dispatch_status"] = "timeout"
        republish_fixture(self.artifacts, self.fixture)
        result = self.adapt()["measurement"]
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["qualified"])
        self.assertEqual(result["metrics"], {})

    def test_qualification_claim_session_zero_is_retained_outside_the_recorder(self):
        plan = generate()
        values = metadata_for(
            plan,
            {"input_lock_sha256": "a" * 64},
            "qualification",
            plan["qualification_schedule"][0],
            1,
            "1" * 32,
        )
        self.assertEqual(values["session"], 0)
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary)
            fixture = make_fixture(artifacts, values)
            inner = fixture["native"]["observation"]
            self.assertEqual(inner["session"], 1)
            self.assertEqual(inner["campaign_session"], 0)
            result = adapter.adapt_result(fixture["dispatch"], values, artifacts=artifacts)[
                "measurement"
            ]
        self.assertTrue(result["qualified"], result["measurement_issues"])
        self.assertEqual(result["session"], 0)
        self.assertEqual(result["phase"], "qualification")
        self.assertEqual(values["session"], 0)

    def test_pre_mapped_fixture_metadata_is_not_mapped_twice(self):
        values = {**self.values, "phase": "qualification", "session": 0}
        mapped = observation_metadata(values)
        self.assertEqual(observation_metadata(mapped), mapped)
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary)
            fixture = make_fixture(artifacts, mapped)
            result = adapter.adapt_result(fixture["dispatch"], values, artifacts=artifacts)[
                "measurement"
            ]
        self.assertTrue(result["qualified"], result["measurement_issues"])
        self.assertEqual(result["session"], 0)
