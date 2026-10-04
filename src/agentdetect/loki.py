"""Minimal Loki client for the lab: push API ingestion and instant LogQL queries.

The Loki half of the dual-engine replay. It mirrors the Splunk client's shape:
events go in tagged with a per-run marker, and every query is confined to that
marker. Two things differ from Splunk, and both are deliberate:

* The run marker is a stream label (``ad_run``), because a Loki query must open
  with a stream selector. A label per replay is a cardinality anti-pattern in
  production; here each stream lives for one throwaway replay.
* Events are rebased so the trace ends "now", with every inter-arrival gap
  preserved. Splunk takes a backdated fixture as-is. Loki's default limits
  reject any line more than a week old, and with that limit lifted the lab
  accepted the July-dated events and then returned nothing for them. The
  behavioral rules only measure gaps, so shifting the whole trace loses nothing.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import requests

# Every rule (converted Sigma or native .logql) addresses its streams with this
# exact selector, so a rule file is deployable as written. The client swaps it
# for the run-scoped selector at replay time.
SELECTOR = '{job="agentdetect"}'

# How far back a converted Sigma match looks. Fixture traces span under three
# minutes; native rules carry their own range.
SIGMA_WINDOW = "15m"

_RUN_RE = re.compile(r"\A[0-9a-f]{32}\Z")
_NS_PER_MS = 1_000_000
# The rebased trace ends this far behind the wall clock, and queries evaluate
# this far past its last event, so the final event is always inside the range.
_TAIL_NS = 2_000_000_000


class LokiError(RuntimeError):
    """Loki was unreachable or returned something we cannot use."""


@dataclass(frozen=True, slots=True)
class LokiConfig:
    url: str = field(default_factory=lambda: os.environ.get("AD_LOKI_URL", "http://localhost:3100"))
    # Basic auth is only needed for a hosted Loki (Grafana Cloud); the lab has none.
    user: str = field(default_factory=lambda: os.environ.get("AD_LOKI_USER", ""))
    token: str = field(default_factory=lambda: os.environ.get("AD_LOKI_TOKEN", ""))
    timeout: int = 60


def _epoch_ns(timestamp: Any) -> int:
    if not isinstance(timestamp, str):
        raise LokiError(f"event timestamp {timestamp!r} is not a string")
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LokiError(f"event timestamp {timestamp!r} is not ISO-8601") from exc
    return round(parsed.timestamp() * 1000) * _NS_PER_MS


def scope(logql: str, run: str) -> str:
    """Confine a rule to one replay by narrowing its stream selector."""
    if not _RUN_RE.match(run):
        raise LokiError(f"invalid run token {run!r}")
    if SELECTOR not in logql:
        raise LokiError(f"rule does not address {SELECTOR}; it cannot be scoped to a run")
    return logql.replace(SELECTOR, f'{{job="agentdetect", ad_run="{run}"}}')


class LokiClient:
    def __init__(self, config: LokiConfig | None = None) -> None:
        self.config = config or LokiConfig()
        self._session = requests.Session()
        if self.config.user:
            self._session.auth = (self.config.user, self.config.token)

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        url = f"{self.config.url.rstrip('/')}{path}"
        try:
            return self._session.request(
                method, url, timeout=self.config.timeout, allow_redirects=False, **kwargs
            )
        except requests.RequestException as exc:
            raise LokiError(f"{method} {url} failed: {exc}") from exc

    def wait_ready(self, attempts: int = 40, delay: float = 3.0) -> None:
        for _ in range(attempts):
            try:
                if self._request("GET", "/ready").status_code == 200:
                    return
            except LokiError:
                pass
            time.sleep(delay)
        raise LokiError(f"Loki not ready after {attempts} attempts")

    def post_events(self, events: list[dict[str, Any]], run: str) -> int:
        """Push one fixture as a single stream; return the query evaluation time (ns)."""
        if not _RUN_RE.match(run):
            raise LokiError(f"invalid run token {run!r}")
        if not events:
            raise LokiError("refusing to push an empty fixture")
        stamps = [_epoch_ns(event.get("timestamp")) for event in events]
        shift = time.time_ns() - _TAIL_NS - max(stamps)
        values = [
            [str(stamp + shift), json.dumps(event)]
            for stamp, event in zip(stamps, events, strict=True)
        ]
        resp = self._request(
            "POST",
            "/loki/api/v1/push",
            json={"streams": [{"stream": {"job": "agentdetect", "ad_run": run}, "values": values}]},
        )
        if resp.status_code != 204:
            raise LokiError(f"push returned {resp.status_code}: {resp.text[:200]}")
        return max(stamps) + shift + _TAIL_NS

    def query(self, logql: str, at_ns: int) -> list[dict[str, Any]]:
        """Run an instant metric query and return its result vector."""
        resp = self._request(
            "GET", "/loki/api/v1/query", params={"query": logql, "time": str(at_ns)}
        )
        if resp.status_code != 200:
            raise LokiError(f"query returned {resp.status_code}: {resp.text[:300]}")
        try:
            data = resp.json()["data"]
        except (ValueError, KeyError, TypeError) as exc:
            raise LokiError(f"unexpected query response: {resp.text[:200]}") from exc
        if data.get("resultType") != "vector" or not isinstance(data.get("result"), list):
            raise LokiError(f"expected an instant vector, got {data.get('resultType')!r}")
        return [row for row in data["result"] if isinstance(row, dict)]

    def fires_native(self, run: str, logql: str, at_ns: int) -> bool:
        """A native rule is a thresholded metric query: any surviving series is a hit."""
        return len(self.query(scope(logql, run), at_ns)) > 0

    def fires_sigma(self, run: str, logql: str, at_ns: int) -> bool:
        """A converted Sigma rule is a log query; count its matching lines."""
        counted = f"sum(count_over_time({scope(logql, run)} [{SIGMA_WINDOW}]))"
        return len(self.query(counted, at_ns)) > 0

    def count(self, run: str, at_ns: int) -> int:
        rows = self.query(f"sum(count_over_time({scope(SELECTOR, run)} [{SIGMA_WINDOW}]))", at_ns)
        if not rows:
            return 0  # count_over_time yields no series until a line is queryable
        try:
            return int(float(rows[0]["value"][1]))
        except (KeyError, IndexError, ValueError, TypeError) as exc:
            raise LokiError(f"unexpected count result {rows[0]!r}") from exc

    def wait_for_count(
        self, run: str, expected: int, at_ns: int, timeout: float = 60.0, poll: float = 0.5
    ) -> None:
        """Block until every pushed line is queryable; raise rather than guess."""
        deadline = time.monotonic() + timeout
        seen = 0
        while time.monotonic() < deadline:
            seen = self.count(run, at_ns)
            if seen >= expected:
                return
            time.sleep(poll)
        raise LokiError(
            f"only {seen}/{expected} lines for run {run} became queryable within {timeout:.0f}s"
        )
