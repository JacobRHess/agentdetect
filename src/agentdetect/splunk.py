"""Minimal Splunk client for the lab: HEC event posting and REST search, no SDK.

Adapted from the purpleloop / clouddetect harness. It targets the local lab
Splunk, whose certificate is self-signed, so TLS verification is off by default
and is turned on with AD_SPLUNK_VERIFY=true for a trusted endpoint. Every call
maps a transport failure to a SplunkError so the harness reports it cleanly
rather than leaking a requests exception.
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
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_DEV_HEC_TOKEN = "00000000-0000-0000-0000-000000000000"  # noqa: S105  # nosec B105

# The per-ingestion isolation marker is always a uuid4 hex string. Enforcing the
# shape at the query boundary keeps it from ever carrying SPL metacharacters, so
# the f-string interpolation below cannot be turned into anything else.
_RUN_RE = re.compile(r"\A[0-9a-f]{32}\Z")


class SplunkError(RuntimeError):
    """Splunk was unreachable or returned something we cannot use."""


@dataclass(frozen=True, slots=True)
class SplunkConfig:
    host: str = field(default_factory=lambda: os.environ.get("AD_SPLUNK_HOST", "localhost"))
    hec_port: int = field(default_factory=lambda: int(os.environ.get("AD_HEC_PORT", "8088")))
    api_port: int = field(default_factory=lambda: int(os.environ.get("AD_API_PORT", "8089")))
    username: str = "admin"
    password: str = field(default_factory=lambda: os.environ.get("AD_SPLUNK_PASSWORD", "changeme"))
    hec_token: str = _DEV_HEC_TOKEN
    index: str = "agentdetect"
    sourcetype: str = "agent:telemetry"
    timeout: int = 60
    verify: bool = field(
        default_factory=lambda: (
            os.environ.get("AD_SPLUNK_VERIFY", "").lower() in ("1", "true", "yes")
        )
    )


class SplunkClient:
    def __init__(self, config: SplunkConfig | None = None) -> None:
        self.config = config or SplunkConfig()
        self._session = requests.Session()
        self._session.verify = self.config.verify

    def _api(self, path: str) -> str:
        return f"https://{self.config.host}:{self.config.api_port}{path}"

    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        """Issue a request, mapping any transport failure to SplunkError.

        `allow_redirects=False` on every call: these requests carry the HEC
        token or basic-auth credentials and must never be bounced to another
        host.
        """
        try:
            return self._session.request(
                method, url, timeout=self.config.timeout, allow_redirects=False, **kwargs
            )
        except requests.RequestException as exc:
            raise SplunkError(f"{method} {url} failed: {exc}") from exc

    def wait_ready(self, attempts: int = 40, delay: float = 5.0) -> None:
        for _ in range(attempts):
            try:
                resp = self._request(
                    "GET",
                    self._api("/services/server/info"),
                    auth=(self.config.username, self.config.password),
                    params={"output_mode": "json"},
                )
                if resp.status_code == 200:
                    return
            except SplunkError:
                pass
            time.sleep(delay)
        raise SplunkError(f"Splunk not ready after {attempts} attempts")

    def post_events(self, events: list[dict[str, Any]], run: str) -> int:
        """Send events to HEC, tagging each with a per-run marker for isolation.

        Each event's own ``timestamp`` becomes the Splunk ``_time`` so the
        behavioral searches measure the real inter-arrival gaps in the trace,
        not the wall-clock instant the fixture was ingested.
        """
        if not events:
            return 0
        if not _RUN_RE.match(run):
            raise SplunkError(f"invalid run token {run!r}")
        url = f"https://{self.config.host}:{self.config.hec_port}/services/collector/event"
        lines: list[str] = []
        for event in events:
            tagged = {**event, "ad_run": run}
            envelope: dict[str, Any] = {
                "event": tagged,
                "index": self.config.index,
                "sourcetype": self.config.sourcetype,
            }
            ts = self._epoch(event.get("timestamp"))
            if ts is not None:
                envelope["time"] = ts
            lines.append(json.dumps(envelope))
        resp = self._request(
            "POST",
            url,
            headers={"Authorization": f"Splunk {self.config.hec_token}"},
            data="\n".join(lines),
        )
        if resp.status_code != 200:
            raise SplunkError(f"HEC returned {resp.status_code}: {resp.text[:200]}")
        return len(events)

    @staticmethod
    def _epoch(timestamp: Any) -> float | None:
        """Parse an ISO-8601 UTC timestamp to epoch seconds, or None if absent."""
        if not isinstance(timestamp, str):
            return None
        try:
            return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None

    # The window spans well past both directions on purpose. A fixture's events
    # carry their own timestamps, and some are dated on (or slightly ahead of)
    # the day a replay runs; with `latest=now` those future-of-wall-clock events
    # fall outside the range and the detection silently misses. Isolation comes
    # from the per-run `ad_run` marker, not the time bounds, so widening the
    # window is free and removes the dependence on when the clock says it is.
    def search(
        self, spl: str, earliest: str = "-10y", latest: str = "+10y"
    ) -> list[dict[str, Any]]:
        query = spl.strip()
        if not query.startswith("|") and not query.lower().startswith("search"):
            query = f"search {query}"
        resp = self._request(
            "POST",
            self._api("/services/search/jobs"),
            auth=(self.config.username, self.config.password),
            data={
                "search": query,
                "earliest_time": earliest,
                "latest_time": latest,
                "exec_mode": "oneshot",
                "output_mode": "json",
                "count": 0,
            },
        )
        if resp.status_code != 200:
            raise SplunkError(f"search returned {resp.status_code}: {resp.text[:200]}")
        try:
            payload = resp.json()
        except ValueError as exc:
            raise SplunkError(f"search results were not JSON: {exc}") from exc
        rows = payload.get("results", []) if isinstance(payload, dict) else []
        return [row for row in rows if isinstance(row, dict)]

    def _scope(self, run: str) -> str:
        """The index + run predicate every per-run search is confined to."""
        if not _RUN_RE.match(run):
            raise SplunkError(f"invalid run token {run!r}")
        return f'index={self.config.index} ad_run="{run}"'

    def search_sigma(self, run: str, spl: str) -> list[dict[str, Any]]:
        """Run a Sigma-converted match expression confined to one ingestion run."""
        return self.search(f"search {self._scope(run)} ({spl})")

    def search_native(self, run: str, spl: str) -> list[dict[str, Any]]:
        """Run a native SPL search (leading filter + aggregation pipes) for one run.

        The search leads with field filters and then pipes through
        `stats | where ...`, so the run scope is prepended to that leading filter
        rather than wrapped in parentheses.
        """
        return self.search(f"search {self._scope(run)} {spl}")

    def count(self, run: str) -> int:
        # `| stats count` always returns exactly one row; an empty result means
        # the search itself failed, which the caller must not read as "0 events".
        rows = self.search(f"search {self._scope(run)} | stats count")
        if not rows:
            raise SplunkError(f"count search for run {run} returned no rows")
        try:
            return int(rows[0]["count"])
        except (KeyError, ValueError, TypeError) as exc:
            raise SplunkError(f"unexpected count result {rows[0]!r}") from exc

    def wait_for_count(
        self, run: str, expected: int, timeout: float = 180.0, poll: float = 3.0
    ) -> None:
        """Block until at least `expected` events for this run are searchable.

        HEC accepts events before they are indexed, so the engine calls this
        before running a detection. Raising on timeout is the whole point: a
        silent return would let a slow or stuck index look exactly like a
        detection that did not fire, turning a real miss into a false verdict.
        """
        deadline = time.monotonic() + timeout
        seen = 0
        while time.monotonic() < deadline:
            seen = self.count(run)
            if seen >= expected:
                return
            time.sleep(poll)
        raise SplunkError(
            f"only {seen}/{expected} events for run {run} became searchable "
            f"within {timeout:.0f}s; the index did not catch up"
        )
