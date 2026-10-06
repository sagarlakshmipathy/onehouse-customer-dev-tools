"""Core framework: check registration, result model, and the base validator.

A source plugin subclasses ``SourceValidator`` and marks methods with ``@check``.
The runner collects every marked method across the class hierarchy, groups them
by layer (network -> infra -> database), and runs them in definition order.
All checks are read-only. No check may write to the source database.
"""
from __future__ import annotations

import argparse
import dataclasses
import enum
import getpass
import itertools
import os
import socket
import time
from typing import Any, Callable, Iterable

LAYERS = ("network", "infra", "database")
_counter = itertools.count()


class Status(str, enum.Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"


@dataclasses.dataclass
class Result:
    status: Status
    message: str
    fix: str | None = None
    details: list[str] = dataclasses.field(default_factory=list)


def ok(msg: str, details: Iterable[str] = ()) -> Result:
    return Result(Status.PASS, msg, details=list(details))


def warn(msg: str, fix: str | None = None, details: Iterable[str] = ()) -> Result:
    return Result(Status.WARN, msg, fix, list(details))


def fail(msg: str, fix: str | None = None, details: Iterable[str] = ()) -> Result:
    return Result(Status.FAIL, msg, fix, list(details))


def skip(msg: str) -> Result:
    return Result(Status.SKIP, msg)


class Skip(Exception):
    """Raise inside a check to mark it SKIP with the given reason."""


@dataclasses.dataclass
class CheckSpec:
    id: str
    title: str
    layer: str
    order: int
    func: Callable[["SourceValidator"], Result]


@dataclasses.dataclass
class CheckOutcome:
    id: str
    title: str
    layer: str
    result: Result
    seconds: float

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["result"]["status"] = self.result.status.value
        return d


def check(id: str, title: str, layer: str = "database"):
    """Register a validator method as a prerequisite check."""
    if layer not in LAYERS:
        raise ValueError(f"unknown layer {layer!r}")

    def deco(fn):
        fn._check = (id, title, layer, next(_counter))
        return fn

    return deco


def csv_list(value: str | None) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def plural(items: list, noun: str) -> str:
    """'1 table' / '3 tables'. Use it where no verb has to agree with the count."""
    return f"{len(items)} {noun}{'' if len(items) == 1 else 's'}"


def preview(items: list[str], limit: int = 15) -> list[str]:
    if len(items) <= limit:
        return items
    return items[:limit] + [f"... and {len(items) - limit} more"]


class SourceValidator:
    """Base class for one CDC source type (postgres, mysql, oracle, ...)."""

    name: str = ""
    label: str = ""
    docs_url: str = ""
    default_port: int = 0
    supported_clouds: tuple[str, ...] = ("aws", "gcp")
    driver_hint: str = ""

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.conn = None
        self.connect_error: str | None = None

    # ---- plugin hooks -------------------------------------------------
    @classmethod
    def add_arguments(cls, parser: argparse.ArgumentParser) -> None:
        """Add source-specific CLI flags."""

    def connect(self):
        """Return a DB-API connection. Raise on failure."""
        raise NotImplementedError

    # ---- helpers for plugins -----------------------------------------
    @property
    def port(self) -> int:
        return self.args.port or self.default_port

    def password(self) -> str:
        if self.args.password is not None:
            return self.args.password
        env = os.environ.get("CDC_DB_PASSWORD")
        if env is not None:
            return env
        return getpass.getpass(f"Password for {self.args.user}@{self.args.host}: ")

    def query(self, sql: str, params: Any = None) -> list[tuple]:
        cur = self.conn.cursor()
        try:
            if params is None:
                cur.execute(sql)
            else:
                cur.execute(sql, params)
            return list(cur.fetchall()) if cur.description else []
        finally:
            cur.close()

    def scalar(self, sql: str, params: Any = None):
        rows = self.query(sql, params)
        return rows[0][0] if rows else None

    def require_conn(self) -> None:
        if self.conn is None:
            raise Skip(f"no database connection ({self.connect_error or 'not attempted'})")

    # ---- built-in checks shared by every source -----------------------
    @check("network.tcp", "TCP reachability from this machine", layer="network")
    def check_tcp(self) -> Result:
        start = time.monotonic()
        try:
            with socket.create_connection((self.args.host, self.port), timeout=self.args.connect_timeout):
                ms = (time.monotonic() - start) * 1000
            return ok(f"{self.args.host}:{self.port} accepts TCP connections ({ms:.0f} ms)",
                      ["This proves reachability from the machine that runs this script, "
                       "not from the Onehouse cluster. The infra layer checks the cluster path."])
        except OSError as e:
            return fail(f"cannot open TCP to {self.args.host}:{self.port}: {e}",
                        "Run the script from a host inside the database network, or open a tunnel.")

    @check("database.connect", "Log in as the CDC user", layer="database")
    def check_connect(self) -> Result:
        try:
            self.conn = self.connect()
        except ImportError as e:
            self.connect_error = f"driver missing: {e}"
            return fail(self.connect_error, f"pip install {self.driver_hint}")
        except Exception as e:  # noqa: BLE001 - driver errors vary by vendor
            self.connect_error = str(e).strip().splitlines()[0] if str(e).strip() else type(e).__name__
            return fail(f"login as {self.args.user!r} failed: {self.connect_error}",
                        "Check the host, port, database name, user, and password.")
        return ok(f"logged in as {self.args.user!r}")

    # ---- runner -------------------------------------------------------
    @classmethod
    def specs(cls) -> list[CheckSpec]:
        seen: dict[str, CheckSpec] = {}
        for klass in reversed(cls.__mro__):
            for attr, fn in vars(klass).items():
                meta = getattr(fn, "_check", None)
                if meta:
                    cid, title, layer, order = meta
                    seen[attr] = CheckSpec(cid, title, layer, order, fn)
        return sorted(seen.values(), key=lambda s: (LAYERS.index(s.layer), s.order))

    def run(self, layers: Iterable[str], only: list[str] | None = None,
            on_result: Callable[[CheckOutcome], None] | None = None) -> list[CheckOutcome]:
        layers = set(layers)
        selected = [s for s in self.specs() if s.layer in layers and
                    (not only or any(s.id == o or s.id.startswith(o + ".") or s.layer == o for o in only))]
        # Database checks need the login check, even when --only filters it out.
        if any(s.layer == "database" for s in selected) and not any(s.id == "database.connect" for s in selected):
            selected.insert(next(i for i, s in enumerate(selected) if s.layer == "database"),
                            next(s for s in self.specs() if s.id == "database.connect"))
        outcomes = []
        for spec in selected:
            start = time.monotonic()
            try:
                if spec.layer == "database" and spec.id != "database.connect":
                    self.require_conn()
                result = spec.func(self)
            except Skip as e:
                result = skip(str(e))
            except Exception as e:  # noqa: BLE001 - one bad check must not stop the run
                msg = str(e).strip().splitlines()[0] if str(e).strip() else type(e).__name__
                result = Result(Status.ERROR, f"{type(e).__name__}: {msg}")
                self._rollback()
            outcome = CheckOutcome(spec.id, spec.title, spec.layer, result, time.monotonic() - start)
            outcomes.append(outcome)
            if on_result:
                on_result(outcome)
        self.close()
        return outcomes

    def _rollback(self) -> None:
        # Postgres aborts the transaction after any error; reset so later checks still run.
        if self.conn is not None:
            try:
                self.conn.rollback()
            except Exception:  # noqa: BLE001
                pass

    def close(self) -> None:
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:  # noqa: BLE001
                pass
            self.conn = None
