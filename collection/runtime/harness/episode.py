"""Observe an initial task and valid restart without replacing native recovery."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import signal
import subprocess
import time
import uuid
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from harness import audit, faults, supervisor
from harness.native_measurement import Observation

FAULTS = {
    "normal-control",
    "invalid-p4",
    "occupied-grpc",
    "sigint-startup",
    "kill-bmv2",
    "drop-control",
}


def signatures(snapshot: dict[str, Any]) -> dict[str, set[str]]:
    def token(value: Any) -> str:
        return json.dumps(value, sort_keys=True)

    return {
        "processes": {token([p["pid"], p["start_ticks"]]) for p in snapshot["processes"]},
        "namespaces": {token(n.get("netns")) for n in snapshot["namespaces"]},
        "interfaces": {
            token([i.get("namespace"), i.get("ifindex"), i.get("ifname")])
            for i in snapshot["interfaces"]
        },
        "listeners": {
            token([x.get("socket_inode"), x.get("local_port"), x.get("netns")])
            for x in snapshot["listeners"]
        },
    }


def allowed_restart(snapshot: dict[str, Any], ledger: dict[str, set[str]]) -> bool:
    return not snapshot["snapshot_errors"] and all(
        values <= ledger[key] for key, values in signatures(snapshot).items()
    )


class Episode:
    def __init__(
        self,
        manifest: dict[str, Any],
        excluded_children: set[int] | None = None,
        observation: Observation | None = None,
    ) -> None:
        self.observation = observation
        self.manifest = copy.deepcopy(manifest)
        self.manifest["owned_processes"] = []
        self.manifest["namespace_ids"] = []
        self.directory = Path(manifest["output_dir"])
        self.ledger: dict[str, set[str]] = {key: set() for key in audit.RESOURCE_KEYS}
        self.workers: set[int] = set(excluded_children or ())
        self.init_reaped: list[int] = []
        self.before = audit.capture(self.manifest)

    def snapshot(self) -> dict[str, Any]:
        # PID-namespace init reaps only adopted, exited children. Worker Popen
        # objects retain responsibility for their own direct child identities.
        for path in Path("/proc").iterdir():
            if not path.name.isdecimal() or int(path.name) in self.workers:
                continue
            try:
                value = audit.parse_process_stat((path / "stat").read_text())
                if (
                    value["state"] == "Z"
                    and value["ppid"] == os.getpid()
                    and os.waitpid(value["pid"], os.WNOHANG)[0]
                ):
                    self.init_reaped.append(value["pid"])
            except (FileNotFoundError, ProcessLookupError, ChildProcessError):
                continue
        state = supervisor._compare_final_interfaces(self.before, audit.capture(self.manifest))
        supervisor._remember_snapshot(self.manifest, state)
        for key, values in signatures(state).items():
            self.ledger[key].update(values)
        return state

    def child_manifest(self, role: str, source: Path) -> Path:
        directory = self.directory / role
        directory.mkdir()
        child = {
            key: value
            for key, value in self.manifest.items()
            if key not in {"owned_processes", "namespace_ids", "worker_identity", "episode_fault"}
        }
        child.update(
            run_id=uuid.uuid4().hex,
            output_dir=str(directory),
            p4_source=str(source),
            source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        )
        path = directory / "manifest.json"
        supervisor.write_json(path, child)
        return path


class Attempt:
    def __init__(self, episode: Episode, path: Path, python: Path, module: str) -> None:
        self.episode = episode
        self.manifest = json.loads(path.read_text())
        self.directory = path.parent
        self.phase = path.parent.name
        self.observation = episode.observation
        self.events = (self.directory / "events.jsonl").open("w")
        self.log = (self.directory / "worker.log").open("wb")
        env = {**os.environ, "P4NET_STUDY_RUN_DIR": str(self.directory)}
        self.observe("worker_launch")
        self.proc = subprocess.Popen(
            [str(python), "-m", module, "--manifest", str(path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.log,
            env=env,
            cwd=Path(__file__).resolve().parents[1],
            start_new_session=True,
            bufsize=0,
        )
        episode.workers.add(self.proc.pid)
        identity = supervisor.process_identity(self.proc.pid)
        if identity is None:
            raise RuntimeError("worker exited before identity registration")
        episode.manifest["worker_identity"] = identity
        episode.manifest["owned_processes"].append(identity)
        self.identity = identity
        assert self.proc.stdout is not None
        self.reader = supervisor.EventReader(
            self.proc.stdout,
            clock_ns=self.observation.clock_ns if self.observation is not None else None,
        )
        self.result: dict[str, Any] = {
            "ready": False,
            "checks": [],
            "error": None,
            "errors": [],
            "worker_returncode": None,
            "stopped": False,
            "ordinary_stop_timeout": False,
            "worker_identity": identity,
            "pid_namespace": os.readlink("/proc/self/ns/pid"),
            "outer_network_namespace": os.readlink("/proc/self/ns/net"),
        }
        self.started = False

    def observe(self, name: str) -> None:
        observation = getattr(self, "observation", None)
        if observation is not None:
            observation.mark(name, phase=self.phase)

    def exited(self) -> bool:
        if self.proc.poll() is None:
            return False
        self.observe("worker_exit")
        return True

    def intervene(self, action: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        self.observe("intervention_start")
        try:
            result = action()
        except Exception:
            self.observe("intervention_failed")
            raise
        self.observe("intervention_applied")
        return result

    def record(self, event: dict[str, Any]) -> None:
        self.events.write(
            json.dumps({"recorded_at": datetime.now().astimezone().isoformat(), "payload": event})
            + "\n"
        )
        self.events.flush()

    def consume(self, deadline: float) -> dict[str, Any] | None:
        event = self.reader.read(deadline)
        if event is None:
            return None
        observation = getattr(self, "observation", None)
        if observation is not None:
            observation.received(event, phase=self.phase, observed_ns=self.reader.last_received_ns)
        self.record(event)
        kind = event.get("event")
        if kind == "probe":
            if event.get("schema_version") != 1 or event.get("run_id") != self.manifest["run_id"]:
                raise supervisor.ProtocolError("probe identifies another worker")
            return event
        kind = supervisor.validate_event(event, self.manifest["run_id"])
        supervisor._remember_event(self.episode.manifest, event, self.proc.pid)
        if kind == "starting":
            if self.started:
                raise supervisor.ProtocolError("duplicate starting event")
            self.started = True
        elif not self.started:
            raise supervisor.ProtocolError("worker event precedes starting")
        if kind == "ready":
            if self.result["ready"]:
                raise supervisor.ProtocolError("duplicate ready event")
            self.result["checks"] = supervisor.validate_task_ready(event, self.manifest)
            self.result["ready"] = True
            if observation is not None:
                observation.ready(self.manifest, self.identity, event, phase=self.phase)
        elif kind == "error":
            self.result["errors"].append(event)
            if self.result["error"] is None:
                self.result["error"] = event
        elif kind == "stopped":
            self.result["stopped"] = True
        return event

    def wait_ready(self, *, interrupt: bool = False) -> dict[str, Any] | None:
        deadline = time.monotonic() + 90
        delivered = None
        while not self.exited():
            try:
                event = self.consume(min(deadline, time.monotonic() + 0.03))
            except TimeoutError:
                event = {}
            if (
                self.result["ready"]
                or self.result["error"]
                or self.result["stopped"]
                or event is None
            ):
                break
            state = self.episode.snapshot()
            if interrupt and delivered is None and faults.owned_veth_present(state, self.manifest):
                self.drain_pending()
                if self.result["ready"] or self.result["error"] or self.result["stopped"]:
                    break
                # Resource availability, rather than a fixed delay, determines delivery.
                delivered = self.intervene(
                    lambda: faults.signal_verified(self.identity, signal.SIGINT)
                )
                self.record({"event": "injection", **delivered})
            if time.monotonic() >= deadline:
                self.result["error"] = {"event": "startup-timeout"}
                break
        return delivered

    def drain_pending(self) -> None:
        while b"\n" in self.reader.buffer or self.reader.eof or self.reader.selector.select(0):
            try:
                if self.consume(time.monotonic() + 0.001) is None:
                    return
            except TimeoutError:
                return

    def probe(self, name: str) -> dict[str, Any]:
        self.send({"command": "probe", "request_id": name})
        deadline = time.monotonic() + 6
        while self.proc.poll() is None:
            event = self.consume(deadline)
            if event is None:
                break
            if event.get("event") == "probe":
                if event.get("request_id") != name or type(event.get("ok")) is not bool:
                    raise supervisor.ProtocolError("probe response does not match request")
                return event
        raise RuntimeError("worker exited before answering the bounded probe")

    def send(self, command: dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write((json.dumps(command) + "\n").encode())
        self.proc.stdin.flush()

    def finish(self, timeout: float = 10) -> dict[str, Any]:
        actions: list[dict[str, Any]] = []
        live = not self.exited()
        if live:
            self.observe("stop_request")
        supervisor._request_stop(self.proc, actions)
        if live:
            delivered = any(item["action"] == "request_stop" for item in actions)
            self.observe("stop_sent" if delivered else "stop_failed")
        self.wait_exit(timeout)
        self.result["ordinary_stop_timeout"] = self.proc.poll() is None
        self.result["worker_returncode"] = self.proc.poll()
        self.observe("ordinary_audit_start")
        raw = self.episode.snapshot()
        self.observe("ordinary_audit_end")
        supervisor.write_json(self.directory / "inventory-ordinary-after.json", raw)
        self.result["ordinary_cleanup_clean"] = audit.is_clean(raw)
        self.result["stop_actions"] = actions
        self.save()
        return raw

    def wait_exit(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while not self.exited() and time.monotonic() < deadline:
            try:
                if self.consume(min(deadline, time.monotonic() + 0.05)) is None:
                    self.proc.wait(timeout=max(0.001, deadline - time.monotonic()))
            except (TimeoutError, subprocess.TimeoutExpired):
                continue
        if self.exited():
            # A fast exit can leave final events buffered in the pipe.
            while True:
                try:
                    if self.consume(time.monotonic() + 0.05) is None:
                        break
                except TimeoutError:
                    break

    def save(self) -> None:
        supervisor.write_json(self.directory / "result.json", self.result)

    def close(self) -> None:
        self.reader.close()
        for stream in (self.proc.stdin, self.proc.stdout):
            if stream is not None and not stream.closed:
                stream.close()
        self.events.close()
        self.log.close()


def run_episode(
    path: Path,
    python: Path,
    module: str,
    *,
    excluded_children: set[int] | None = None,
    observation: Observation | None = None,
) -> dict[str, Any]:
    faults.require_enclosure()
    if any(item.name != path.name for item in path.parent.iterdir()):
        raise FileExistsError("episode directory already contains records")
    manifest = json.loads(path.read_text())
    if observation is not None:
        observation.bind(manifest)
    fault = manifest["episode_fault"]
    if fault not in FAULTS:
        raise ValueError("unsupported episode fault")
    episode = Episode(manifest, excluded_children, observation)
    supervisor.write_json(episode.directory / "inventory-before.json", episode.before)
    if not audit.is_clean(episode.before):
        raise RuntimeError("episode initial environment is not clean")
    result: dict[str, Any] = {
        "schema_version": 1,
        "run_id": manifest["run_id"],
        "mode": "correctness-episode",
        "performance_samples": False,
        "fault": fault,
        "ok": False,
        "framework_complete": False,
        "injection_delivered": False,
        "recovery_success": False,
        "initial": None,
        "restart": None,
        "primary_outcome_saved_before_safety": False,
    }
    if observation is not None and observation.recorder is not None:
        result["mode"] = observation.recorder.mode
        result["performance_samples"] = observation.performance_samples
    source = Path(manifest["p4_source"])
    attempts: list[Attempt] = []
    listener = None
    blocker = None
    try:
        if fault == "invalid-p4":
            initial_source = faults.invalid_source(episode.directory / "invalid.p4")
            result["injection_delivered"] = True
        else:
            initial_source = source
        if fault == "occupied-grpc":
            listener = faults.OwnedListener(manifest["service_ports"][0])
            listener.start()
            result["listener_before"] = listener.verify()
            result["injection_delivered"] = True
        if observation is not None and fault in {"invalid-p4", "occupied-grpc"}:
            observation.mark("condition_ready")
        initial = Attempt(
            episode, episode.child_manifest("initial", initial_source), python, module
        )
        attempts.append(initial)
        signal_action = initial.wait_ready(interrupt=fault == "sigint-startup")
        if signal_action is not None:
            result["injection"] = signal_action
            result["injection_delivered"] = True
        if fault in {"kill-bmv2", "drop-control", "normal-control"}:
            if not initial.result["ready"]:
                raise RuntimeError("post-ready fault did not reach a valid task")
            result["baseline_probe"] = initial.probe("baseline")
            if not result["baseline_probe"]["ok"]:
                raise RuntimeError("healthy existing-connection probe failed")
            ready = episode.snapshot()
            supervisor.write_json(episode.directory / "inventory-ready.json", ready)
            if fault == "kill-bmv2":
                identity = faults.identify_first_switch(ready, manifest)
                result["injection"] = initial.intervene(
                    lambda: faults.signal_verified(identity, signal.SIGKILL)
                )
                result["process_exit"] = faults.confirm_exit(identity)
                initial.observe("exit_confirmed")
                result["injection_delivered"] = True
            elif fault == "drop-control":
                blocker = faults.EndpointBlocker(manifest, ready)
                result["injection"] = initial.intervene(blocker.install)
                result["injection_delivered"] = True
            else:
                result["injection_delivered"] = True
            if fault != "normal-control":
                result["detection_probe"] = initial.probe("after-fault")
        initial.finish()
        result["initial"] = initial.result
        ledger = copy.deepcopy(episode.ledger)
        if listener is not None:
            result["listener_after_ordinary_teardown"] = listener.verify()
            listener.release()
        if blocker is not None:
            blocker.release()
        result["fixture_release_after_original_audit"] = True
        if initial.proc.poll() is None:
            initial.wait_exit(5)
        after_fixture = episode.snapshot()
        supervisor.write_json(
            episode.directory / "inventory-after-fixture-release.json", after_fixture
        )
        result["post_fixture_worker_returncode"] = initial.proc.poll()
        pre_restart = supervisor._compare_final_interfaces(
            episode.before, audit.capture(episode.manifest)
        )
        supervisor.write_json(episode.directory / "inventory-before-restart.json", pre_restart)
        if initial.proc.poll() is None:
            result["restart"] = {"blocked": "initial-worker-still-running"}
        elif not allowed_restart(pre_restart, ledger):
            result["restart"] = {"blocked": "unregistered-or-uncertain-preexisting-resources"}
        else:
            restart = Attempt(episode, episode.child_manifest("restart", source), python, module)
            attempts.append(restart)
            restart.wait_ready()
            restart.finish()
            result["restart"] = restart.result
            result["recovery_success"] = bool(
                restart.result["ready"]
                and restart.result["stopped"]
                and restart.result["worker_returncode"] == 0
                and restart.result["ordinary_cleanup_clean"]
            )
        result["framework_complete"] = True
        result["condition_established"] = bool(result["injection_delivered"])
        result["ok"] = result["condition_established"]
        if fault == "normal-control":
            result["injection_delivered"] = False
        if fault in {"kill-bmv2", "drop-control"}:
            result["ok"] = result["ok"] and result["detection_probe"]["ok"] is False
    except BaseException as exc:
        result["framework_error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        for index, attempt in enumerate(attempts):
            if "ordinary_cleanup_clean" not in attempt.result:
                try:
                    attempt.finish()
                except Exception as exc:
                    attempt.result["snapshot_error"] = str(exc)
            if index == 0:
                result["initial"] = attempt.result
        supervisor.write_json(
            episode.directory / "inventory-emergency-before-safety.json", episode.snapshot()
        )
        # Save the primary observation before fixture rescue or forceful process cleanup.
        result["primary_outcome_saved_before_safety"] = True
        supervisor.write_json(episode.directory / "primary-outcome.json", result)
        if observation is not None:
            observation.checkpoint(episode.directory / "measurement-primary.json", result)
            observation.mark("safety_start")
        fixture_errors = []
        for fixture in (listener, blocker):
            if fixture is not None:
                try:
                    fixture.release()
                except Exception as exc:
                    fixture_errors.append({"type": type(exc).__name__, "message": str(exc)})
        result["fixture_safety_errors"] = fixture_errors
        safety: list[dict[str, Any]] = []
        for attempt in attempts:
            if attempt.proc.poll() is None:
                supervisor._stop_worker(
                    attempt.proc,
                    {**episode.manifest, "worker_identity": attempt.identity},
                    1,
                    safety,
                )
        leftover = episode.snapshot()
        supervisor.write_json(episode.directory / "inventory-before-safety-rescue.json", leftover)
        if not audit.is_clean(leftover):
            safety.extend(supervisor._rescue(episode.manifest, leftover))
        final = episode.snapshot()
        supervisor.write_json(episode.directory / "inventory-after-safety.json", final)
        result["safety_actions"] = safety
        result["safety_after_clean"] = audit.is_clean(final)
        result["init_reaped_orphans"] = episode.init_reaped
        for attempt in attempts:
            attempt.close()
        if observation is not None:
            observation.mark("safety_end")
            result["observation"] = observation.finish(result)
        supervisor.write_json(episode.directory / "result.json", result)
    return result
