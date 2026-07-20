"""Turn one (detection, fixture) pair into a verdict.

The contract is strict:

* An ``alert`` fixture must make the detection fire. A detection that stays quiet
  on its own attack sample is broken.
* A ``clean`` fixture must not make it fire. This is the half people skip, and it
  is the half that catches a detection that "works" only because it matches
  everything - or, here, one that flags any process that ever talks to a model
  API rather than the agent loop that acts on the host between calls.
"""

from __future__ import annotations

from dataclasses import dataclass

from agentdetect.engine import Engine, load_events
from agentdetect.manifest import Detection, Expect, Fixture


@dataclass(frozen=True, slots=True)
class Verdict:
    detection_id: str
    engine: str
    fixture: str
    expect: Expect
    fired: bool
    passed: bool

    @property
    def detail(self) -> str:
        if self.expect is Expect.ALERT:
            return (
                "fired on its attack sample as required"
                if self.passed
                else "did NOT fire on its attack sample"
            )
        return (
            "stayed silent on the benign sample"
            if self.passed
            else "fired on a benign sample that must not alert"
        )


def evaluate(detection: Detection, fixture: Fixture, engine: Engine) -> Verdict:
    events = load_events(fixture.events)
    fired = engine.replay(detection, events)
    passed = fired if fixture.expect is Expect.ALERT else not fired
    return Verdict(
        detection_id=detection.id,
        engine=engine.name,
        fixture=fixture.name,
        expect=fixture.expect,
        fired=fired,
        passed=passed,
    )
