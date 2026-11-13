"""Run a complete supervisor inside private Linux resource namespaces."""

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from harness.campaign_bridge import validate_measurement
from harness.spec import load

PAPER = Path(__file__).resolve().parents[1]
NAMESPACES = ("net", "mnt", "pid", "ipc", "uts")


def namespace_ids() -> dict[str, str]:
    return {kind: os.readlink(f"/proc/self/ns/{kind}") for kind in NAMESPACES}


def checked(argv: list[str]) -> None:
    subprocess.run(argv, check=True, capture_output=True, text=True, timeout=15)


def require_private(expected: dict[str, str]) -> dict[str, str]:
    current = namespace_ids()
    if os.getpid() != 1 or set(expected) != set(NAMESPACES):
        raise RuntimeError("isolation setup requires the new PID namespace's init process")
    if any(current[kind] == expected[kind] for kind in NAMESPACES):
        raise RuntimeError("refusing mount changes without all private namespaces")
    return current


def prepare_mounts() -> dict[str, Any]:
    checked(["mount", "--make-rprivate", "/"])
    private = []
    for target, mode in (("/tmp", "1777"), ("/var/tmp", "1777"), ("/run", "0755")):
        checked(["mount", "-t", "tmpfs", "-o", f"mode={mode},nosuid,nodev", "tmpfs", target])
        private.append(target)
    # sysfs must reflect this network namespace, and remain read-only.
    checked(["mount", "-t", "sysfs", "-o", "ro,nosuid,nodev,noexec", "sysfs", "/sys"])
    for target in ("/proc/sys/vm", "/proc/sys/kernel", "/proc/sys/fs"):
        checked(["mount", "--bind", target, target])
        checked(["mount", "-o", "remount,bind,ro", target])
    ssh = Path.home() / ".ssh"
    if ssh.is_dir():
        checked(["mount", "-t", "tmpfs", "-o", "mode=0700,nosuid,nodev", "tmpfs", str(ssh)])
        private.append(str(ssh))
    checked(["ip", "link", "set", "lo", "up"])
    interfaces = json.loads(subprocess.check_output(["ip", "-j", "link", "show"], text=True))
    sys_interfaces = sorted(path.name for path in Path("/sys/class/net").iterdir())
    if {link["ifname"] for link in interfaces} != {"lo"} or sys_interfaces != ["lo"]:
        raise RuntimeError("new network/sysfs view contains unexpected interfaces")
    return {
        "private_mounts": private,
        "initial_interfaces": interfaces,
        "sysfs_interfaces": sys_interfaces,
        "global_sysctls_read_only": True,
    }


def _reference_arguments(
    calibration: Mapping[str, Any] | None,
    reference_fd: int | None,
    reference_deadline: float | None,
) -> None:
    present = (calibration is not None, reference_fd is not None, reference_deadline is not None)
    if any(present) and not all(present):
        raise ValueError("observer calibration requires its reference descriptor and deadline")
    if calibration is not None:
        if type(reference_fd) is not int or reference_fd < 3:
            raise ValueError("reference descriptor must be an integer of at least three")
        if (
            reference_deadline is None
            or type(reference_deadline) not in (int, float)
            or not math.isfinite(reference_deadline)
            or reference_deadline <= 0
        ):
            raise ValueError("reference deadline must be finite and positive")


def inside(
    path: Path,
    python: Path,
    worker: str,
    expected: dict[str, str],
    guards: bool = False,
    boundary_validation: bool = False,
    *,
    measurement: Mapping[str, Any] | None = None,
    observer_calibration: Mapping[str, Any] | None = None,
    reference_fd: int | None = None,
    reference_deadline: float | None = None,
) -> int:
    manifest = load(path)
    _reference_arguments(observer_calibration, reference_fd, reference_deadline)
    if observer_calibration is not None:
        if measurement is not None or boundary_validation:
            raise ValueError("observer calibration cannot be combined with other observations")
        from harness.observer_config import validate_calibration

        observer_calibration = validate_calibration(observer_calibration, manifest)
    if measurement is not None:
        if boundary_validation:
            raise ValueError("measurement and boundary validation are mutually exclusive")
        measurement = validate_measurement(measurement, manifest)
    with ExitStack() as resources:
        connection = None
        if observer_calibration is not None:
            connection = resources.enter_context(socket.socket(fileno=reference_fd))
            connection.set_inheritable(False)
        return _inside_task(
            path,
            python,
            worker,
            expected,
            guards,
            boundary_validation,
            manifest=manifest,
            measurement=measurement,
            observer_calibration=observer_calibration,
            reference_socket=connection,
            reference_deadline=reference_deadline,
        )


def _inside_task(
    path: Path,
    python: Path,
    worker: str,
    expected: dict[str, str],
    guards: bool,
    boundary_validation: bool,
    *,
    manifest: Mapping[str, Any],
    measurement: Mapping[str, Any] | None,
    observer_calibration: Mapping[str, Any] | None,
    reference_socket: socket.socket | None,
    reference_deadline: float | None,
) -> int:
    private_ids = require_private(expected)
    mounts = prepare_mounts()
    os.environ["P4NET_STUDY_INNER_NS"] = json.dumps(private_ids)
    if manifest.get("configuration_profile", "native") == "matched-v1":
        keys = [f"net.ipv6.conf.{scope}.disable_ipv6" for scope in ("all", "default", "lo")]
        checked(["sysctl", "-w", *[key + "=1" for key in keys]])
        values = subprocess.check_output(["sysctl", "-n", *keys], text=True).splitlines()
        if values != ["1", "1", "1"]:
            raise RuntimeError("matched outer IPv6 settings did not take effect")
        mounts["outer_ipv6_disabled"] = True
    record = {
        "mode": (
            observer_calibration["mode"]
            if observer_calibration is not None
            else measurement["mode"]
            if measurement is not None
            else "correctness-check"
        ),
        "performance_samples": (
            observer_calibration["mode"] in {"pilot", "formal"}
            if observer_calibration is not None
            else measurement is not None
        ),
        "outer_namespaces": expected,
        "inner_namespaces": private_ids,
        "inner_pid": os.getpid(),
        **mounts,
    }
    if observer_calibration is not None:
        record["observer_profile"] = observer_calibration["observer_profile"]
    report = path.parent.parent / f"{path.parent.name}-isolation.json"
    report.write_text(json.dumps(record, indent=2) + "\n")
    from harness.supervisor import run

    def execute(observation: Any) -> dict[str, Any]:
        sentinel_path = Path("/tmp") / f"research-{manifest['run_id']}.log"
        sentinel = None
        if guards:
            sentinel_path.write_text("inner namespace fixture\n")
            sentinel = subprocess.Popen(["mininet:isolated-guard", "200"], executable="/bin/sleep")
        try:
            if "episode_fault" in manifest:
                from harness.episode import run_episode

                result = run_episode(
                    path,
                    python,
                    worker,
                    excluded_children={sentinel.pid} if sentinel is not None else None,
                    observation=observation,
                )
            else:
                result = run(
                    path,
                    ready_timeout=120,
                    stop_timeout=30,
                    worker_command=[str(python), "-m", worker, "--manifest", str(path)],
                    observation=observation,
                )
            if sentinel is not None:
                record["inner_log_sentinel_remaining"] = sentinel_path.exists()
                record["inner_process_sentinel_running"] = sentinel.poll() is None
                report.write_text(json.dumps(record, indent=2) + "\n")
        finally:
            if sentinel is not None:
                if sentinel.poll() is None:
                    sentinel.terminate()
                sentinel.wait(timeout=5)
        result["pid_namespace"] = private_ids["pid"]
        result["isolation_record"] = str(report)
        (path.parent / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result), flush=True)
        return result

    if observer_calibration is not None:
        from harness.observer_dispatch import SocketChannel
        from harness.observer_profiles import profile_observation
        from harness.observer_reference import ChildReference
        from harness.observer_runtime import run_child

        assert reference_socket is not None and reference_deadline is not None
        channel = SocketChannel(reference_socket, deadline=reference_deadline)
        reference = ChildReference(
            run_id=manifest["run_id"],
            attempt_id=observer_calibration["attempt_id"],
            profile=observer_calibration["observer_profile"],
            namespaces={kind: private_ids[kind] for kind in ("pid", "net", "mnt")},
            send=channel.send,
            receive=channel.receive,
        )

        def build(callback: Callable[[Path], None]) -> Any:
            return profile_observation(
                observer_calibration["observer_profile"],
                observer_calibration["metadata"],
                mode=observer_calibration["mode"],
                clock_domain=observer_calibration["clock_domain"],
                clock_ns=time.monotonic_ns,
                sleep=time.sleep,
                duration_ns=observer_calibration["duration_ns"],
                interval_ns=observer_calibration["interval_ns"],
                clock_ticks=os.sysconf("SC_CLK_TCK"),
                on_primary_published=callback,
            )

        envelope = run_child(
            path.parent / "observer-child-result.json",
            reference,
            mode=observer_calibration["mode"],
            build_observation=build,
            run_task=execute,
        )
        return 0 if envelope["native_result"]["ok"] else 1

    observation = None
    if measurement is not None:
        from harness.native_measurement import measured_observation

        observation = measured_observation(**measurement)
    elif boundary_validation:
        from harness.native_measurement import Observation

        observation = Observation()

    result = execute(observation)
    return 0 if result["ok"] else 1


def isolated_command(
    path: Path,
    python: Path,
    worker: str,
    guards: bool = False,
    boundary_validation: bool = False,
    *,
    measurement: Mapping[str, Any] | None = None,
    observer_calibration: Mapping[str, Any] | None = None,
    reference_fd: int | None = None,
    reference_deadline: float | None = None,
) -> list[str]:
    _reference_arguments(observer_calibration, reference_fd, reference_deadline)
    if observer_calibration is not None:
        if measurement is not None or boundary_validation:
            raise ValueError("observer calibration cannot be combined with other observations")
        from harness.observer_config import validate_calibration

        observer_calibration = validate_calibration(observer_calibration, load(path))
    if measurement is not None:
        if boundary_validation:
            raise ValueError("measurement and boundary validation are mutually exclusive")
        measurement = validate_measurement(measurement)
    command = [
        "unshare",
        "--net",
        "--pid",
        "--mount",
        "--ipc",
        "--uts",
        "--fork",
        "--mount-proc",
        "--kill-child=KILL",
        sys.executable,
        "-m",
        "harness.isolation",
        "--inside",
        "--manifest",
        str(path),
        "--python",
        str(python),
        "--worker",
        worker,
        "--outer-namespaces",
        json.dumps(namespace_ids()),
    ]
    if guards:
        command.append("--verify-guards")
    if boundary_validation:
        command.append("--validate-boundaries")
    if measurement is not None:
        command.extend(["--measurement", json.dumps(measurement, allow_nan=False)])
    if observer_calibration is not None:
        command.extend(
            [
                "--observer-calibration",
                json.dumps(observer_calibration, allow_nan=False),
                "--reference-fd",
                str(reference_fd),
                "--reference-deadline",
                str(reference_deadline),
            ]
        )
    return command


def environment_for(manifest: Mapping[str, Any]) -> dict[str, str]:
    """Build the shared native worker environment without launching a process."""
    from harness import worker_components

    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("OVS_", "P4NET_STUDY_COMPONENTS"))
    }
    if "worker_components" in manifest:
        component_pin = manifest["worker_components"]
        worker_components.read_manifest(component_pin)
        env[worker_components.ENV_FILE] = component_pin["path"]
        env[worker_components.ENV_SHA256] = component_pin["sha256"]
    env["PYTHONPATH"] = str(PAPER)
    env["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"
    if manifest.get("configuration_profile", "native") == "matched-v1":
        real = shutil.which("simple_switch_grpc", path=env.get("PATH"))
        wrapper = PAPER / "harness/bin/simple_switch_grpc"
        if real is None or not wrapper.is_file():
            raise RuntimeError("matched BMv2 launcher or real executable is missing")
        env["P4NET_STUDY_BMV2_REAL"] = str(Path(real).resolve())
        env["P4NET_STUDY_RUN_DIR"] = manifest["output_dir"]
        env["PATH"] = str(wrapper.parent) + os.pathsep + env.get("PATH", "")
    return env


def run_isolated(
    path: Path,
    python: Path,
    worker: str,
    *,
    timeout: float | None = None,
    guards: bool = False,
    boundary_validation: bool = False,
    measurement: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    path = path.absolute()
    manifest = load(path)
    if measurement is not None:
        if boundary_validation:
            raise ValueError("measurement and boundary validation are mutually exclusive")
        measurement = validate_measurement(measurement, manifest)
    from harness.supervisor import _positive_timeout

    timeout = _positive_timeout(
        (360 if "episode_fault" in manifest else 210) if timeout is None else timeout,
        "outer watchdog",
    )
    env = environment_for(manifest)
    log_path = path.parent.parent / f"{path.parent.name}-isolation.log"
    with log_path.open("w") as log:
        proc = subprocess.Popen(
            isolated_command(
                path,
                python.absolute(),
                worker,
                guards,
                boundary_validation,
                measurement=measurement,
            ),
            cwd=PAPER,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            # Only the outer Popen identity is used here. Inner PID numbers
            # never authorize a host signal. unshare kills its PID-namespace init.
            proc.kill()
            proc.wait(timeout=10)
            (path.parent / "outer-watchdog.json").write_text(
                json.dumps(
                    {
                        "error": "outer-watchdog-expired",
                        **({"mode": measurement["mode"]} if measurement is not None else {}),
                        "performance_samples": measurement is not None,
                        "worker_container_returncode": proc.returncode,
                        "primary_outcome_available": (
                            path.parent / "primary-outcome.json"
                        ).exists(),
                        "inner_pid_numbers_consumed": False,
                    },
                    indent=2,
                )
                + "\n"
            )
            raise TimeoutError(f"isolated task exceeded watchdog; inspect {log_path}") from None
        except BaseException:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
            raise
    result_path = path.parent / "result.json"
    if not result_path.is_file():
        raise RuntimeError(f"isolation setup failed with exit {code}; inspect {log_path}")
    result: dict[str, Any] = json.loads(result_path.read_text())
    if code != (0 if result.get("ok") else 1):
        raise RuntimeError(f"isolated task exit disagrees with its record: {code}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--python", required=True, type=Path)
    parser.add_argument("--worker", default="harness.worker")
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--outer-namespaces")
    parser.add_argument("--verify-guards", action="store_true")
    parser.add_argument("--validate-boundaries", action="store_true")
    parser.add_argument("--measurement", type=json.loads)
    parser.add_argument("--observer-calibration", type=json.loads)
    parser.add_argument("--reference-fd", type=int)
    parser.add_argument("--reference-deadline", type=float)
    args = parser.parse_args()
    if not args.inside and any(
        value is not None
        for value in (args.observer_calibration, args.reference_fd, args.reference_deadline)
    ):
        parser.error("observer calibration requires the acknowledged native dispatcher")
    if args.inside:
        raise SystemExit(
            inside(
                args.manifest,
                args.python,
                args.worker,
                json.loads(args.outer_namespaces),
                args.verify_guards,
                args.validate_boundaries,
                measurement=args.measurement,
                observer_calibration=args.observer_calibration,
                reference_fd=args.reference_fd,
                reference_deadline=args.reference_deadline,
            )
        )
    result = run_isolated(
        args.manifest,
        args.python,
        args.worker,
        guards=args.verify_guards,
        boundary_validation=args.validate_boundaries,
        measurement=args.measurement,
    )
    print(json.dumps(result))
    raise SystemExit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
