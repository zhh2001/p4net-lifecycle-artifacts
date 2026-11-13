"""Normalize recorded BMv2 launch options before replacing the wrapper process."""

from __future__ import annotations

import contextlib
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

DEFAULT_BINARY = "/usr/local/bin/simple_switch_grpc"
POLICY = {
    "log_console": True,
    "log_level": "info",
    "log_flush": False,
    "pcap": False,
    "nanolog": False,
    "grpc_bind_host": "127.0.0.1",
}
QUERIES = {"-h", "--help", "-v", "--version", "--json-version"}
ALIASES = {"-i": "--interface", "-L": "--log-level"}
CORE_VALUES = {
    "--interface",
    "--use-files",
    "--packet-in",
    "--thrift-port",
    "--device-id",
    "--nanolog",
    "--log-file",
    "--log-level",
    "--notifications-addr",
    "--restore-state",
    "--dump-packet-data",
    "--max-port-count",
}
CORE_FLAGS = {"--log-console", "--log-flush", "--no-p4"}
POLICY_OPTIONS = {
    "--nanolog",
    "--pcap",
    "--log-file",
    "--log-level",
    "--log-console",
    "--log-flush",
}
TARGET_VALUES = {
    "--load-modules",
    "--grpc-server-addr",
    "--grpc-server-cacert",
    "--grpc-server-cert",
    "--grpc-server-key",
    "--cpu-port",
    "--drop-port",
    "--dp-grpc-server-addr",
    "--priority-queues",
}
TARGET_FLAGS = {"--disable-swap", "--grpc-server-ssl", "--grpc-server-with-client-auth"}
LOG_LEVELS = {"trace", "debug", "info", "warn", "error", "off"}


class ArgumentError(ValueError):
    """An option is unknown, misplaced, incomplete, or conflicting."""


def _option(token: str) -> tuple[str, str | None]:
    if token.startswith("--") and "=" in token:
        option, value = token.split("=", 1)
        return option, value
    for short in ("-i", "-L"):
        if token.startswith(short) and len(token) > len(short):
            return ALIASES[short], token[len(short) :]
    return ALIASES.get(token, token), None


def _value(argv: list[str], index: int, option: str, attached: str | None) -> tuple[str, int]:
    if attached is not None:
        if not attached:
            raise ArgumentError(f"{option} requires a nonempty value")
        return attached, index + 1
    if index + 1 == len(argv) or argv[index + 1].startswith("-"):
        raise ArgumentError(f"{option} requires a value")
    return argv[index + 1], index + 2


def _core(argv: list[str]) -> tuple[list[str], str | None]:
    retained: list[str] = []
    positionals: list[str] = []
    seen: set[str] = set()
    ports: set[int] = set()
    interfaces: set[str] = set()
    index = 0
    while index < len(argv):
        start = index
        token = argv[index]
        if not token.startswith("-"):
            positionals.append(token)
            index += 1
            continue
        option, attached = _option(token)
        if option not in CORE_VALUES | CORE_FLAGS | {"--pcap"}:
            raise ArgumentError(f"unknown or misplaced BMv2 core option: {token}")
        if option in seen and option != "--interface":
            raise ArgumentError(f"duplicate BMv2 core option: {option}")
        seen.add(option)
        if option == "--pcap":
            index += 1
            if attached is None and index < len(argv) and not argv[index].startswith("-"):
                index += 1
        elif option in CORE_FLAGS:
            if attached is not None:
                raise ArgumentError(f"{option} does not take a value")
            index += 1
        else:
            value, index = _value(argv, index, option, attached)
            if option == "--log-level" and value not in LOG_LEVELS:
                raise ArgumentError(f"unsupported BMv2 log level: {value}")
            if option == "--interface":
                port, separator, interface = value.partition("@")
                if not separator or not port.isascii() or not port.isdecimal() or not interface:
                    raise ArgumentError("interface must have the form port@interface")
                if int(port) in ports or interface in interfaces:
                    raise ArgumentError("duplicate BMv2 interface port or name")
                ports.add(int(port))
                interfaces.add(interface)
        if option not in POLICY_OPTIONS:
            retained.extend(argv[start:index])
    if "--log-console" in seen and "--log-file" in seen:
        raise ArgumentError("--log-console and --log-file are mutually exclusive")
    if "--no-p4" in seen:
        if positionals:
            raise ArgumentError("--no-p4 conflicts with a JSON configuration path")
        return retained, None
    if len(positionals) != 1 or not positionals[0]:
        raise ArgumentError("exactly one JSON configuration path is required")
    return retained, positionals[0]


def _target(argv: list[str]) -> list[str]:
    seen: set[str] = set()
    retained = []
    index = 0
    while index < len(argv):
        start = index
        option, attached = _option(argv[index])
        if option not in TARGET_VALUES | TARGET_FLAGS:
            raise ArgumentError(f"unknown or misplaced BMv2 target option: {argv[index]}")
        if option in seen:
            raise ArgumentError(f"duplicate BMv2 target option: {option}")
        seen.add(option)
        if option in TARGET_FLAGS:
            if attached is not None:
                raise ArgumentError(f"{option} does not take a value")
            index += 1
        else:
            value_text, index = _value(argv, index, option, attached)
            if option == "--grpc-server-addr":
                host, separator, port = value_text.rpartition(":")
                if (
                    not separator
                    or host not in {"0.0.0.0", "127.0.0.1"}
                    or not port.isascii()
                    or not port.isdecimal()
                    or not 1024 <= int(port) <= 65535
                ):
                    raise ArgumentError(
                        "matched gRPC endpoint requires an allocated local IPv4 port"
                    )
                retained.extend(["--grpc-server-addr", f"127.0.0.1:{int(port)}"])
                continue
        retained.extend(argv[start:index])
    return retained


def normalize(argv: Sequence[str]) -> list[str]:
    """Return normalized arguments, excluding the executable path."""
    args = list(argv)
    if any(not isinstance(value, str) or "\0" in value for value in args):
        raise ArgumentError("arguments must be strings without NUL bytes")
    if len(args) == 1 and args[0] in QUERIES:
        return args
    if args.count("--") > 1:
        raise ArgumentError("only one core/target separator is supported")
    separator = args.index("--") if "--" in args else len(args)
    core, config = _core(args[:separator])
    target = args[separator + 1 :] if separator < len(args) else []
    target = _target(target)
    effective = [*core, "--log-console", "-L", "info"]
    if config is not None:
        effective.append(config)
    if separator < len(args):
        effective.extend(["--", *target])
    return effective


def _write(path: Path, record: dict[str, Any]) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(record, indent=2, allow_nan=False) + "\n")
    temporary.replace(path)


def run(argv: Sequence[str], environ: Mapping[str, str] | None = None) -> int:
    """Record the command and exec the real switch with inherited streams."""
    env = dict(os.environ if environ is None else environ)
    path: Path | None = None
    record: dict[str, Any] = {
        "schema_version": 1,
        "mode": "normalized-bmv2-launch",
        "pid": os.getpid(),
        "requested_program": sys.argv[0],
        "requested_argv": list(argv),
        "effective_argv": None,
        "policy": dict(POLICY),
        "query": len(argv) == 1 and argv[0] in QUERIES,
    }
    try:
        directory = Path(env.get("P4NET_STUDY_RUN_DIR", ""))
        if not directory.is_absolute() or not directory.is_dir():
            raise ArgumentError(
                "P4NET_STUDY_RUN_DIR must name an existing absolute trial directory"
            )
        records = directory / "bmv2-launches"
        records.mkdir(exist_ok=True)
        path = records / f"launch-{os.getpid()}.json"
        if path.exists():
            raise FileExistsError(f"launch record already exists: {path}")
        binary = env.get("P4NET_STUDY_BMV2_REAL", DEFAULT_BINARY)
        if not Path(binary).is_absolute():
            raise ArgumentError("P4NET_STUDY_BMV2_REAL must be an absolute path")
        if Path(binary).resolve() == Path(sys.argv[0]).resolve():
            raise ArgumentError("real BMv2 executable resolves to the wrapper")
        record["effective_argv"] = [binary, *normalize(argv)]
        record["status"] = "prepared"
        _write(path, record)
    except (OSError, ValueError) as exc:
        record["status"] = "rejected"
        record["error"] = {"type": type(exc).__name__, "message": str(exc)}
        if path is not None and not path.exists():
            with contextlib.suppress(OSError):
                _write(path, record)
        print(f"BMv2 launch rejected: {exc}", file=sys.stderr)
        return 2
    try:
        os.execve(binary, record["effective_argv"], env)
    except OSError as exc:
        record["status"] = "exec_failed"
        record["error"] = {"type": type(exc).__name__, "errno": exc.errno, "message": str(exc)}
        _write(path, record)
        print(f"BMv2 exec failed: {exc}", file=sys.stderr)
        return 127 if exc.errno == 2 else 126


def main() -> None:
    raise SystemExit(run(sys.argv[1:]))


if __name__ == "__main__":
    main()
