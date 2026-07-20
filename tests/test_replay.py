"""Replay every fixture through a real Splunk.

This is the half of the suite that needs infrastructure: a live Splunk (the lab,
or the CI validate job). It is marked ``replay`` and deselected by the default
``pytest`` run, so the offline gate stays fast.

Each detection's attack fixture must fire the rule and its benign fixture must
stay silent. A parametrized id reads like ``agent_loop_interleave.alert`` so a
failure names the exact fixture that broke.
"""

from __future__ import annotations

import pytest

from agentdetect.engine import SplunkEngine
from agentdetect.harness import evaluate
from agentdetect.manifest import Detection, Fixture, load

_ENGINE = SplunkEngine()

_CASES = [pytest.param(det, fx, id=fx.events.stem) for det in load() for fx in det.fixtures]


@pytest.fixture(scope="session", autouse=True)
def _engine_ready() -> None:
    _ENGINE.wait_ready()


@pytest.mark.replay
@pytest.mark.parametrize(("detection", "fixture"), _CASES)
def test_fixture_behaves_as_declared(detection: Detection, fixture: Fixture) -> None:
    verdict = evaluate(detection, fixture, _ENGINE)
    assert verdict.passed, (
        f"{detection.id}: {fixture.name} {verdict.detail} (fired={verdict.fired})"
    )
