"""The Grafana lab content is generated from the manifest and cannot drift from it."""

from __future__ import annotations

from pathlib import Path

from agentdetect import grafana
from agentdetect.cli import main
from agentdetect.manifest import REPO_ROOT, load

_RULES = REPO_ROOT / "lab" / "grafana" / "provisioning" / "alerting" / "agentdetect.yml"
_BOARD = REPO_ROOT / "lab" / "grafana" / "dashboards" / "agentdetect.json"


def test_committed_alert_rules_match_the_manifest() -> None:
    assert _RULES.read_text(encoding="utf-8") == grafana.render_alert_rules()


def test_committed_dashboard_matches_the_manifest() -> None:
    assert _BOARD.read_text(encoding="utf-8") == grafana.render_dashboard()


def test_one_alert_rule_per_detection_on_the_lab_datasource() -> None:
    rules = grafana.alert_rules()["groups"][0]["rules"]
    assert [r["uid"] for r in rules] == [f"ad-{d.id}" for d in load()]
    for rule in rules:
        query = rule["data"][0]
        assert query["datasourceUid"] == grafana.DATASOURCE_UID
        assert '{job="agentdetect"}' in query["model"]["expr"]
        assert "#" not in query["model"]["expr"]
        assert rule["noDataState"] == "OK"


def test_firing_sessions_wraps_both_rule_kinds_per_session() -> None:
    for det in load():
        assert grafana.firing_sessions(det).startswith("count by (session) (")


def test_cycles_panel_drops_only_the_threshold() -> None:
    panel = next(p for p in grafana.dashboard()["panels"] if p["type"] == "bargauge")
    expr = panel["targets"][0]["expr"]
    assert "rate_counter" in expr
    assert ">=" not in expr


def test_grafana_command_writes_both_files(tmp_path: Path) -> None:
    assert main(["grafana", "--out-dir", str(tmp_path)]) == 0
    written = tmp_path / "provisioning" / "alerting" / "agentdetect.yml"
    assert written.read_text(encoding="utf-8") == grafana.render_alert_rules()
    board = tmp_path / "dashboards" / "agentdetect.json"
    assert board.read_text(encoding="utf-8") == grafana.render_dashboard()
