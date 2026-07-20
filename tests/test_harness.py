"""The verdict logic, exercised with a stub engine (no live Splunk needed)."""

from __future__ import annotations

from typing import Any

from agentdetect.harness import evaluate
from agentdetect.manifest import Detection, Expect, load


class _StubEngine:
    """An engine whose firing decision we dictate, to test verdict polarity."""

    name = "stub"

    def __init__(self, *, fires: bool) -> None:
        self._fires = fires

    def wait_ready(self) -> None:  # pragma: no cover - trivial
        pass

    def replay(self, detection: Detection, events: list[dict[str, Any]]) -> bool:
        return self._fires


def _first() -> Detection:
    return load()[0]


def test_alert_fixture_passes_when_it_fires() -> None:
    det = _first()
    alert = next(fx for fx in det.fixtures if fx.expect is Expect.ALERT)
    verdict = evaluate(det, alert, _StubEngine(fires=True))
    assert verdict.passed
    assert "fired" in verdict.detail


def test_alert_fixture_fails_when_silent() -> None:
    det = _first()
    alert = next(fx for fx in det.fixtures if fx.expect is Expect.ALERT)
    verdict = evaluate(det, alert, _StubEngine(fires=False))
    assert not verdict.passed
    assert "did NOT fire" in verdict.detail


def test_clean_fixture_passes_when_silent() -> None:
    det = _first()
    clean = next(fx for fx in det.fixtures if fx.expect is Expect.CLEAN)
    verdict = evaluate(det, clean, _StubEngine(fires=False))
    assert verdict.passed
    assert "silent" in verdict.detail


def test_clean_fixture_fails_when_it_fires() -> None:
    det = _first()
    clean = next(fx for fx in det.fixtures if fx.expect is Expect.CLEAN)
    verdict = evaluate(det, clean, _StubEngine(fires=True))
    assert not verdict.passed
    assert "must not alert" in verdict.detail
