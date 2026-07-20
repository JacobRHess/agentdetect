"""The offline CLI subcommands: list, validate, convert."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdetect.cli import _check_spl, main
from agentdetect.manifest import Detection, RuleKind


def test_list(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["list"]) == 0
    out = capsys.readouterr().out
    assert "agent-loop-interleave" in out
    assert "[sigma]" in out
    assert "[spl " in out


def test_validate(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["validate"]) == 0
    out = capsys.readouterr().out
    assert "10/10 rules are well-formed" in out


def test_convert_sigma(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["convert", "llm-api-egress"]) == 0
    assert "dest_host" in capsys.readouterr().out


def test_convert_spl(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["convert", "agent-command-cadence"]) == 0
    assert "streamstats" in capsys.readouterr().out


def test_convert_unknown_id() -> None:
    assert main(["convert", "does-not-exist"]) == 2


def test_attack_markdown(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["attack"]) == 0
    assert "ATT&CK coverage" in capsys.readouterr().out


def test_attack_layer_written(tmp_path: Path) -> None:
    out = tmp_path / "layer.json"
    assert main(["attack", "--layer", str(out)]) == 0
    assert '"techniqueID"' in out.read_text(encoding="utf-8")


def test_emulate_list(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["emulate", "--list"]) == 0
    assert "recon-and-loot" in capsys.readouterr().out


def test_emulate_requires_objective() -> None:
    assert main(["emulate"]) == 2


def _detection_with_rule(rule: Path) -> Detection:
    return Detection(id="x", title="x", rule=rule, kind=RuleKind.SPL, attack=(), fixtures=())


def test_check_spl_rejects_empty(tmp_path: Path) -> None:
    rule = tmp_path / "empty.spl"
    rule.write_text("   \n", encoding="utf-8")
    with pytest.raises(Exception, match="empty"):
        _check_spl(_detection_with_rule(rule))


def test_check_spl_rejects_leading_pipe(tmp_path: Path) -> None:
    rule = tmp_path / "pipe.spl"
    rule.write_text("| stats count", encoding="utf-8")
    with pytest.raises(Exception, match="lead with a filter"):
        _check_spl(_detection_with_rule(rule))


def test_check_spl_rejects_unbalanced_parens(tmp_path: Path) -> None:
    rule = tmp_path / "paren.spl"
    rule.write_text("event_type=process_creation (a AND b", encoding="utf-8")
    with pytest.raises(Exception, match="unbalanced"):
        _check_spl(_detection_with_rule(rule))
