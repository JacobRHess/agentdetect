"""Every Sigma rule converts to exactly one search per engine; garbage is rejected."""

from __future__ import annotations

import pytest

from agentdetect import sigma
from agentdetect.manifest import RuleKind, load


@pytest.mark.parametrize(
    "detection",
    [d for d in load() if d.kind is RuleKind.SIGMA],
    ids=lambda d: d.id,
)
def test_sigma_rules_convert_to_one_spl(detection) -> None:
    spl = sigma.to_spl(detection.rule.read_text(encoding="utf-8"))
    assert spl
    assert "\n" not in spl  # exactly one search expression


def test_non_sigma_text_raises() -> None:
    with pytest.raises(sigma.ConversionError, match="did not parse"):
        sigma.to_spl("this is not a sigma rule")


def test_llm_egress_matches_model_hosts() -> None:
    det = next(d for d in load() if d.id == "llm-api-egress")
    spl = sigma.to_spl(det.rule.read_text(encoding="utf-8"))
    assert "api.anthropic.com" in spl
    assert "dest_host" in spl


@pytest.mark.parametrize(
    "detection",
    [d for d in load() if d.kind is RuleKind.SIGMA],
    ids=lambda d: d.id,
)
def test_sigma_rules_convert_to_one_logql(detection) -> None:
    logql = sigma.to_logql(detection.rule.read_text(encoding="utf-8"))
    # The telemetry is JSON. The backend's default logfmt parser would extract
    # no fields from it and the rule would silently match nothing.
    assert logql.startswith('{job="agentdetect"} | json | ')
    assert "logfmt" not in logql


def test_non_sigma_text_raises_for_logql() -> None:
    with pytest.raises(sigma.ConversionError, match="did not parse"):
        sigma.to_logql("this is not a sigma rule")
