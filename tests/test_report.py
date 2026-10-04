"""The HTML report renders deterministically and escapes its inputs."""

from __future__ import annotations

from agentdetect.manifest import load
from agentdetect.report import CellResult, render


def test_render_is_deterministic() -> None:
    detections = load()
    results = {
        (det.id, fx.name): CellResult(True, "ok") for det in detections for fx in det.fixtures
    }
    assert render(detections, results) == render(detections, results)


def test_render_counts_pass_and_fail() -> None:
    detections = load()
    results = {}
    for det in detections:
        for i, fx in enumerate(det.fixtures):
            results[det.id, fx.name] = CellResult(i == 0, "detail")
    html = render(detections, results)
    assert "validation report" in html
    assert "PASS" in html
    assert "FAIL" in html


def test_unevaluated_cells_render_na() -> None:
    detections = load()
    html = render(detections, {})
    assert "n/a" in html


def test_no_raw_html_injection() -> None:
    detections = load()
    results = {
        (det.id, fx.name): CellResult(False, "<script>alert(1)</script>")
        for det in detections
        for fx in det.fixtures
    }
    html = render(detections, results)
    assert "<script>alert(1)</script>" not in html


def test_loki_report_names_the_engine_and_the_logql_rules() -> None:
    html = render(load(), {}, engine="loki")
    assert "replayed through Loki" in html
    assert "agent_loop_interleave.logql" in html
    assert "agent_loop_interleave.spl" not in html


def test_declared_divergence_renders_as_gap_not_pass() -> None:
    detections = load()
    results = {
        (det.id, fx.name): CellResult(True, "detail", diverges=bool(fx.diverges))
        for det in detections
        for fx in det.fixtures
    }
    html = render(detections, results, engine="loki")
    assert html.count(">GAP<") == 2
