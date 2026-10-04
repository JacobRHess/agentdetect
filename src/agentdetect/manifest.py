"""Load and validate detections.yaml, the single source of truth.

The engine, the CLI, the test suite and the ATT&CK doc are all driven by this
file. Adding a detection means adding an entry here plus a rule and two fixtures
(one attack, one benign) - nothing else.

A detection's rule is one of two kinds, chosen by file extension:

- ``.yml`` / ``.yaml`` - a portable **Sigma** rule, converted to SPL at replay
  time. Used for the field-match detections (an outbound call to a model API, a
  read of a credential file, a wiped shell history).
- ``.spl`` - a **native Splunk** search. Used for the behavioral detections that
  are statistical, not field-match: an agent's command cadence, the call/act
  interleave of an agent loop, error-driven retry storms. These do not compress
  into portable Sigma without lying about what they measure, so they are written
  as the search a detection engineer would actually deploy.

Both kinds run on two engines. A Sigma rule is converted for each. A native rule
names its hand-written Loki port with ``logql:``. Where a port is knowingly
weaker than the SPL original, the fixture that exposes the gap lists the engine
under ``diverges:``; that engine must then give the *opposite* answer, so the
gap is pinned by a test instead of described in prose.

Every path in the manifest is confined to the repository root: it must be
relative, must not climb out with ``..``, and must point at a file that exists.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "detections.yaml"


class ManifestError(ValueError):
    """The manifest is malformed or references something that does not exist."""


class Expect(Enum):
    ALERT = "alert"
    CLEAN = "clean"


class RuleKind(Enum):
    SIGMA = "sigma"
    SPL = "spl"


ENGINES = ("splunk", "loki")


@dataclass(frozen=True, slots=True)
class Fixture:
    events: Path
    expect: Expect
    diverges: frozenset[str] = frozenset()

    @property
    def name(self) -> str:
        return self.events.name


@dataclass(frozen=True, slots=True)
class Detection:
    id: str
    title: str
    rule: Path
    kind: RuleKind
    logql: Path | None
    attack: tuple[str, ...]
    fixtures: tuple[Fixture, ...]


def _confine(raw: str, *, field: str, ctx: str) -> Path:
    """Resolve a manifest-relative path, refusing anything outside the repo."""
    candidate = (REPO_ROOT / raw).resolve()
    try:
        candidate.relative_to(REPO_ROOT)
    except ValueError as exc:
        raise ManifestError(f"{ctx}: {field} {raw!r} escapes the repository root") from exc
    if not candidate.is_file():
        raise ManifestError(f"{ctx}: {field} {raw!r} does not exist")
    return candidate


def _require(mapping: dict[str, Any], key: str, ctx: str) -> Any:
    if key not in mapping:
        raise ManifestError(f"{ctx}: missing required key {key!r}")
    return mapping[key]


def _rule_kind(rule: Path, ctx: str) -> RuleKind:
    suffix = rule.suffix.lower()
    if suffix in (".yml", ".yaml"):
        return RuleKind.SIGMA
    if suffix == ".spl":
        return RuleKind.SPL
    raise ManifestError(f"{ctx}: rule must be a .yml/.yaml Sigma rule or a .spl search")


def _parse_fixture(raw: dict[str, Any], ctx: str) -> Fixture:
    events = _confine(str(_require(raw, "events", ctx)), field="events", ctx=ctx)
    try:
        expect = Expect(str(_require(raw, "expect", ctx)))
    except ValueError as exc:
        raise ManifestError(f"{ctx}: expect must be 'alert' or 'clean'") from exc
    diverges_raw = raw.get("diverges", [])
    if not isinstance(diverges_raw, list) or not set(diverges_raw) <= set(ENGINES):
        raise ManifestError(f"{ctx}: diverges must be a list drawn from {list(ENGINES)}")
    return Fixture(events=events, expect=expect, diverges=frozenset(diverges_raw))


def _parse_logql(raw: dict[str, Any], kind: RuleKind, ctx: str) -> Path | None:
    """A native rule must name its Loki port; a Sigma rule is converted instead."""
    if kind is RuleKind.SIGMA:
        if "logql" in raw:
            raise ManifestError(f"{ctx}: a Sigma rule is converted to LogQL, drop 'logql'")
        return None
    logql = _confine(str(_require(raw, "logql", ctx)), field="logql", ctx=ctx)
    if logql.suffix.lower() != ".logql":
        raise ManifestError(f"{ctx}: logql must be a .logql query")
    return logql


def _parse_detection(raw: dict[str, Any]) -> Detection:
    det_id = str(_require(raw, "id", "detection"))
    ctx = f"detection {det_id!r}"

    rule = _confine(str(_require(raw, "rule", ctx)), field="rule", ctx=ctx)
    kind = _rule_kind(rule, ctx)
    logql = _parse_logql(raw, kind, ctx)
    attack = tuple(str(t) for t in raw.get("attack", []))

    fixtures_raw = _require(raw, "fixtures", ctx)
    if not isinstance(fixtures_raw, list) or not fixtures_raw:
        raise ManifestError(f"{ctx}: fixtures must be a non-empty list")
    fixtures = tuple(_parse_fixture(f, ctx) for f in fixtures_raw)

    expects = {f.expect for f in fixtures}
    if Expect.ALERT not in expects or Expect.CLEAN not in expects:
        raise ManifestError(f"{ctx}: needs at least one 'alert' and one 'clean' fixture")

    return Detection(
        id=det_id,
        title=str(_require(raw, "title", ctx)),
        rule=rule,
        kind=kind,
        logql=logql,
        attack=attack,
        fixtures=fixtures,
    )


def load(path: Path = MANIFEST_PATH) -> tuple[Detection, ...]:
    """Parse and validate the manifest, returning every detection."""
    if not path.is_file():
        raise ManifestError(f"manifest not found at {path}")
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise ManifestError("manifest root must be a mapping")
    detections_raw = doc.get("detections")
    if not isinstance(detections_raw, list) or not detections_raw:
        raise ManifestError("manifest must list at least one detection")

    detections = tuple(_parse_detection(d) for d in detections_raw)

    seen: set[str] = set()
    for det in detections:
        if det.id in seen:
            raise ManifestError(f"duplicate detection id {det.id!r}")
        seen.add(det.id)
    return detections
