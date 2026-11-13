"""Install reversible, source-pinned hooks at native module import boundaries."""

from __future__ import annotations

import functools
import hashlib
import importlib.abc
import inspect
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

from diagnostic.trace import Trace


@dataclass(frozen=True)
class Hook:
    module: str
    owner: str
    member: str
    stage: str
    source: str
    sha256: str
    level: str = "stages"
    kind: str = "span"


class Loader(importlib.abc.Loader):
    def __init__(self, original: Any, session: Session) -> None:
        self.original, self.session = original, session

    def create_module(self, spec: Any) -> Any:
        create = getattr(self.original, "create_module", None)
        return create(spec) if create else None

    def exec_module(self, module: ModuleType) -> None:
        self.session.verify_module(module)
        self.original.exec_module(module)
        self.session.patch(module)


class Session(importlib.abc.MetaPathFinder):
    def __init__(self, trace: Trace, hooks: Sequence[Hook]) -> None:
        self.trace = trace
        self.hooks = tuple(hooks)
        if any(
            h.level not in {"stages", "detail"} or h.kind not in {"span", "event"} for h in hooks
        ):
            raise ValueError("invalid diagnostic hook")
        keys = [(h.module, h.owner, h.member) for h in hooks]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate diagnostic hook target")
        self._changes: list[tuple[Any, str, Any, Any]] = []
        self._installed: set[Hook] = set()
        self._enabled = False
        self._used = False
        self._sources: dict[str, tuple[Path, str]] = {}
        for hook in hooks:
            identity = (Path(hook.source), hook.sha256)
            if hook.module in self._sources and self._sources[hook.module] != identity:
                raise ValueError("one module has conflicting diagnostic source identities")
            self._sources[hook.module] = identity

    def _selected(self, hook: Hook) -> bool:
        return self.trace.profile == "detail" or (
            self.trace.profile == "stages" and hook.level == "stages"
        )

    def verify_sources(self) -> None:
        for path, digest in set(self._sources.values()):
            if not path.is_absolute() or not path.is_file():
                raise ValueError(f"diagnostic source is unavailable: {path}")
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError(f"diagnostic source changed: {path}")

    def __enter__(self) -> Session:
        if self._used:
            raise RuntimeError("diagnostic sessions are single-use")
        if any(isinstance(finder, Session) for finder in sys.meta_path):
            raise RuntimeError("a diagnostic import session is already active")
        self.verify_sources()
        self._used = True
        self._enabled = True
        try:
            for name in sorted({h.module for h in self.hooks}):
                if name in sys.modules:
                    self.patch(sys.modules[name])
            sys.meta_path.insert(0, self)
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> Any:
        selected = [h for h in self.hooks if h.module == fullname]
        if not selected:
            return None
        for finder in tuple(sys.meta_path):
            if finder is self:
                continue
            find = getattr(finder, "find_spec", None)
            spec = find(fullname, path, target) if find else None
            if spec is not None:
                if spec.loader is None or not hasattr(spec.loader, "exec_module"):
                    raise ImportError(f"diagnostic module has no executable loader: {fullname}")
                origin = Path(spec.origin).resolve() if spec.origin else None
                if any(origin != Path(h.source).resolve() for h in selected):
                    raise ImportError(
                        f"diagnostic module resolved outside pinned source: {fullname}"
                    )
                spec.loader = Loader(spec.loader, self)
                return spec
        return None

    def _wrap(self, original: Callable[..., Any], hook: Hook) -> Callable[..., Any]:
        if inspect.iscoroutinefunction(original) or inspect.isgeneratorfunction(original):
            raise TypeError("diagnostic hook requires a synchronous ordinary function")

        @functools.wraps(original)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            if not self._enabled:
                return original(*args, **kwargs)
            if hook.kind == "event":
                result = original(*args, **kwargs)
                event = args[1] if len(args) > 1 else kwargs.get("event")
                if isinstance(event, str):
                    self.trace.checkpoint(f"worker.{event}")
                return result
            with self.trace.span(hook.stage):
                return original(*args, **kwargs)

        return wrapped

    def verify_module(self, module: ModuleType) -> None:
        path, digest = self._sources[module.__name__]
        origin = getattr(module, "__file__", None)
        if not origin or Path(origin).resolve() != path.resolve():
            raise ImportError(f"diagnostic module identity differs: {module.__name__}")
        if hashlib.sha256(Path(origin).read_bytes()).hexdigest() != digest:
            raise ImportError(f"diagnostic module bytes changed: {module.__name__}")

    def patch(self, module: ModuleType) -> None:
        self.verify_module(module)
        for hook in self.hooks:
            if (
                hook.module != module.__name__
                or hook in self._installed
                or not self._selected(hook)
            ):
                continue
            owner: Any = module
            for part in hook.owner.split(".") if hook.owner else ():
                owner = getattr(owner, part)
            raw = inspect.getattr_static(owner, hook.member)
            if isinstance(raw, (staticmethod, classmethod)):
                raise TypeError("descriptor hooks require an explicit adapter")
            if not callable(raw):
                raise TypeError("diagnostic target is not callable")
            original = getattr(owner, hook.member)
            wrapper = self._wrap(original, hook)
            setattr(owner, hook.member, wrapper)
            self._changes.append((owner, hook.member, original, wrapper))
            self._installed.add(hook)

    def coverage(self) -> list[dict[str, Any]]:
        return [
            {
                "module": h.module,
                "owner": h.owner,
                "member": h.member,
                "stage": h.stage,
                "selected": self._selected(h),
                "installed": h in self._installed,
            }
            for h in self.hooks
        ]

    def __exit__(self, *args: Any) -> None:
        self._enabled = False
        if self in sys.meta_path:
            sys.meta_path.remove(self)
        for owner, member, original, wrapper in reversed(self._changes):
            if getattr(owner, member) is wrapper:
                setattr(owner, member, original)
            else:
                self.trace.errors.append(f"hook restoration conflict: {member}")
        self._changes.clear()
