import tempfile
import unittest
from collections import Counter
from pathlib import Path

from overhead.coordinator import Supervisor
from overhead.entry import run_entry
from overhead.model import NAMESPACES, Context, Identity
from overhead.reference import ParentReference
from overhead.wire import ChildReference


class Clock:
    def __init__(self):
        self.value = 1_000_000
        self.sleeps = []

    def now(self):
        self.value += 10
        return self.value

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.value += int(seconds * 1_000_000_000)


class Reader:
    def __init__(self, clock, supervisor, worker):
        self.clock, self.supervisor, self.worker = clock, supervisor, worker
        self.calls = []
        self.counts = Counter()
        self.bad_cpu = None
        self.bad_memory = None
        self.partial_memory = False
        self.delay = 0

    def verify(self, identity):
        if identity not in (self.supervisor, self.worker):
            raise ProcessLookupError("identity changed")

    def resolve_child(self, supervisor, worker):
        self.verify(supervisor)
        if not worker.same_process(self.worker):
            raise ProcessLookupError("wrong worker")
        return self.worker

    def cpu(self, identity):
        self.calls.append(("cpu", identity.pid))
        self.counts[identity.pid] += 1
        if self.bad_cpu == identity.pid:
            raise OSError("CPU unavailable")
        n = self.counts[identity.pid] * 10
        start = self.clock.now()
        return {
            "identity": identity.as_dict(),
            "user_ticks": n,
            "system_ticks": 2,
            "cpu_ticks": n + 2,
            "clock_ticks": 100,
            "read_start_ns": start,
            "read_end_ns": self.clock.now(),
        }

    def memory(self, identity):
        self.calls.append(("memory", identity.pid))
        self.clock.value += self.delay
        if self.bad_memory == identity.pid:
            raise OSError("memory unavailable")
        start = self.clock.now()
        result = {
            "identity": identity.as_dict(),
            "rss_bytes": 4096,
            "pss_bytes": 2048,
            "read_start_ns": start,
            "read_end_ns": self.clock.now(),
        }
        if self.partial_memory:
            result.pop("pss_bytes")
            result["unavailable_fields"] = {"pss_bytes": "invalid Pss"}
        return result


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name)
        self.context = Context("run-1", "attempt-1", "p4net", "off")
        ns = {name: f"{name}:[{100 + i}]" for i, name in enumerate(NAMESPACES)}
        self.supervisor = Identity(1000, 1000, 10, "boot", ns)
        self.worker = Identity(1001, 1001, 11, "boot", ns)
        self.clock = Clock()
        self.reader = Reader(self.clock, self.supervisor, self.worker)
        self.acks = []
        self.parent = ParentReference(
            self.context,
            self.supervisor,
            self.acks.append,
            reader=self.reader,
            clock=self.clock.now,
            process_cpu=self.clock.now,
        )
        self.child = ChildReference(
            self.context, self.supervisor, self.parent.handle, lambda: self.acks.pop(0)
        )
        self.coordinator = Supervisor(
            self.context,
            self.child,
            self.output,
            hold_ns=1000,
            clock=self.clock.now,
            sleep=self.clock.sleep,
        )
        self.native = {
            "ok": True,
            "ready": True,
            "worker_returncode": 0,
            "cleanup": {"ordinary_after_clean": True, "rescue_attempted": False},
        }

    def execute(self, observation):
        observation.mark("worker_launch")
        observation.ready(self.worker)
        observation.mark("stop_request")
        run_entry(
            self.context,
            lambda: 0,
            self.output / "worker-cpu-end.json",
            identity=self.worker,
            read_cpu=lambda: self.reader.cpu(self.worker),
            clock=self.clock.now,
        )
        observation.mark("worker_exit")
        observation.mark("ordinary_audit_end")
        return self.native
