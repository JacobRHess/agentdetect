"""The manifest loads, and every detection is well-formed by construction."""

from __future__ import annotations

from agentdetect.manifest import Expect, RuleKind, load


def test_manifest_loads_ten_detections() -> None:
    detections = load()
    assert len(detections) == 10
    assert len({d.id for d in detections}) == 10


def test_every_detection_has_one_alert_and_one_clean_fixture() -> None:
    for det in load():
        expects = {fx.expect for fx in det.fixtures}
        assert Expect.ALERT in expects
        assert Expect.CLEAN in expects


def test_rule_kind_matches_extension() -> None:
    for det in load():
        if det.rule.suffix == ".spl":
            assert det.kind is RuleKind.SPL
        else:
            assert det.kind is RuleKind.SIGMA


def test_every_rule_and_fixture_file_exists() -> None:
    for det in load():
        assert det.rule.is_file()
        for fx in det.fixtures:
            assert fx.events.is_file()


def test_every_detection_maps_to_attack() -> None:
    for det in load():
        assert det.attack, f"{det.id} has no ATT&CK technique"
        assert all(t.startswith("T") for t in det.attack)


def test_native_rules_have_a_logql_port_and_sigma_rules_do_not() -> None:
    for det in load():
        if det.kind is RuleKind.SPL:
            assert det.logql is not None
            assert det.logql.suffix == ".logql"
        else:
            assert det.logql is None


def test_declared_divergences_are_loki_only_and_benign() -> None:
    diverging = [(det.id, fx) for det in load() for fx in det.fixtures if fx.diverges]
    assert {det_id for det_id, _ in diverging} == {"agent-command-cadence", "agent-retry-storm"}
    for _, fx in diverging:
        assert fx.diverges == frozenset({"loki"})
        assert fx.expect is Expect.CLEAN
