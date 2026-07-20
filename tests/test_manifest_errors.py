"""Malformed manifests fail loudly instead of shipping a broken detection."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdetect.manifest import ManifestError, load


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "detections.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="not found"):
        load(tmp_path / "nope.yaml")


def test_root_must_be_mapping(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="mapping"):
        load(_write(tmp_path, "- a\n- b\n"))


def test_no_detections(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="at least one detection"):
        load(_write(tmp_path, "detections: []\n"))


def test_unknown_rule_extension(tmp_path: Path) -> None:
    body = (
        "detections:\n"
        "  - id: x\n"
        "    title: x\n"
        "    rule: README.md\n"
        "    fixtures:\n"
        "      - {events: README.md, expect: alert}\n"
        "      - {events: README.md, expect: clean}\n"
    )
    with pytest.raises(ManifestError, match=r"Sigma rule or a \.spl"):
        load(_write(tmp_path, body))


def test_path_escaping_repo_is_rejected(tmp_path: Path) -> None:
    body = (
        "detections:\n"
        "  - id: x\n"
        "    title: x\n"
        "    rule: ../../etc/passwd\n"
        "    fixtures:\n"
        "      - {events: README.md, expect: alert}\n"
    )
    with pytest.raises(ManifestError, match=r"escapes|does not exist"):
        load(_write(tmp_path, body))


def test_needs_both_alert_and_clean(tmp_path: Path) -> None:
    body = (
        "detections:\n"
        "  - id: x\n"
        "    title: x\n"
        "    rule: detections.yaml\n"
        "    fixtures:\n"
        "      - {events: README.md, expect: alert}\n"
    )
    with pytest.raises(ManifestError, match=r"alert.*clean|clean"):
        load(_write(tmp_path, body))
