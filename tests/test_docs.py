"""The generated ATT&CK docs match the committed copies and name every technique."""

from __future__ import annotations

import json

import pytest

from agentdetect import attackdoc
from agentdetect.manifest import REPO_ROOT, load


def test_every_technique_has_a_name() -> None:
    used = {t for det in load() for t in det.attack}
    for technique in used:
        assert technique in attackdoc.TECHNIQUE_NAMES, f"{technique} has no name"


def test_attack_md_is_not_stale() -> None:
    committed = (REPO_ROOT / "docs" / "ATTACK.md").read_text(encoding="utf-8")
    assert committed == attackdoc.render_markdown(), "docs/ATTACK.md drifted; regenerate it"


def test_attack_layer_is_not_stale() -> None:
    committed = json.loads((REPO_ROOT / "docs" / "attack-layer.json").read_text(encoding="utf-8"))
    assert committed == attackdoc.render_layer(), "docs/attack-layer.json drifted; regenerate it"


def test_missing_technique_name_fails_loudly(monkeypatch: pytest.MonkeyPatch) -> None:
    used = next(t for det in load() for t in det.attack)
    trimmed = {k: v for k, v in attackdoc.TECHNIQUE_NAMES.items() if k != used}
    monkeypatch.setattr(attackdoc, "TECHNIQUE_NAMES", trimmed)
    with pytest.raises(ValueError, match="no ATT&CK name on file"):
        attackdoc.render_markdown()
