"""Replay every fixture through a real Splunk and a real Loki.

This is the half of the suite that needs infrastructure: live engines (the lab,
or the CI validate job). It is marked ``replay`` and deselected by the default
``pytest`` run, so the offline gate stays fast.

Each detection's attack fixture must fire the rule and its benign fixture must
stay silent, on both engines, unless the manifest declares that an engine
diverges on that fixture. A parametrized id reads like
``loki:agent_loop_interleave.alert`` so a failure names the exact cell that broke.
"""

from __future__ import annotations

import pytest

from agentdetect.engine import Engine, by_name
from agentdetect.harness import evaluate
from agentdetect.manifest import ENGINES, Detection, Fixture, load

_ENGINES = {name: by_name(name) for name in ENGINES}

_CASES = [
    pytest.param(name, det, fx, id=f"{name}:{fx.events.stem}")
    for name in ENGINES
    for det in load()
    for fx in det.fixtures
]


@pytest.fixture(scope="session", autouse=True)
def _engines_ready() -> None:
    for engine in _ENGINES.values():
        engine.wait_ready()


@pytest.mark.replay
@pytest.mark.parametrize(("engine_name", "detection", "fixture"), _CASES)
def test_fixture_behaves_as_declared(
    engine_name: str, detection: Detection, fixture: Fixture
) -> None:
    engine: Engine = _ENGINES[engine_name]
    verdict = evaluate(detection, fixture, engine)
    assert verdict.passed, (
        f"{detection.id} on {engine_name}: {fixture.name} {verdict.detail} (fired={verdict.fired})"
    )
