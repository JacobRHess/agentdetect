"""Replay one fixture's telemetry through Splunk and report whether a detection fired.

One boundary: ``Engine.replay(detection, events) -> bool``. Did this detection's
search match this trace? A Sigma rule is converted to SPL and run as a match
expression; a native ``.spl`` rule is run as-is. Either way the search is
confined to a per-replay marker so it only ever sees this one fixture's events.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Protocol

from agentdetect import sigma
from agentdetect.manifest import Detection, RuleKind
from agentdetect.splunk import SplunkClient


class EngineError(RuntimeError):
    """The engine could not run, or returned something we cannot interpret."""


def load_events(path: Path) -> list[dict[str, Any]]:
    """Read a fixture file as a JSON array of event objects."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list) or not all(isinstance(e, dict) for e in raw):
        raise EngineError(f"{path.name}: fixture must be a JSON array of event objects")
    return raw


class Engine(Protocol):
    """Anything that can replay a fixture against a detection and report a hit."""

    name: str

    def wait_ready(self) -> None: ...

    def replay(self, detection: Detection, events: list[dict[str, Any]]) -> bool: ...


class SplunkEngine:
    name = "splunk"

    def __init__(self, client: SplunkClient | None = None) -> None:
        self.client = client or SplunkClient()

    def wait_ready(self) -> None:
        self.client.wait_ready()

    def replay(self, detection: Detection, events: list[dict[str, Any]]) -> bool:
        run = uuid.uuid4().hex
        rule_text = detection.rule.read_text(encoding="utf-8")
        self.client.post_events(events, run=run)
        # HEC accepts before indexing finishes; wait until the run's events are
        # searchable so a slow index never looks like a detection miss.
        self.client.wait_for_count(run, expected=len(events))
        if detection.kind is RuleKind.SPL:
            return len(self.client.search_native(run, rule_text)) > 0
        return len(self.client.search_sigma(run, sigma.to_spl(rule_text))) > 0
