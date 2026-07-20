"""Generate the ATT&CK coverage doc and Navigator layer from the manifest.

The mapping in the docs is generated, not hand-maintained. ``python -m
agentdetect.attackdoc`` prints docs/ATTACK.md; CI diffs the result against the
committed copy on every push, so the table cannot drift away from the manifest.
The same data renders an ATT&CK Navigator layer (``--layer``) you can drop onto
the Enterprise matrix.
"""

from __future__ import annotations

import json
from pathlib import Path

from agentdetect.manifest import RuleKind, load

# ATT&CK has no public name lookup we want to vendor, so the names used in the
# table live next to the techniques the pack actually claims. Adding a detection
# that uses a new technique adds a line here, or generation fails loudly rather
# than shipping a blank cell.
TECHNIQUE_NAMES = {
    "T1016": "System Network Configuration Discovery",
    "T1033": "System Owner/User Discovery",
    "T1041": "Exfiltration Over C2 Channel",
    "T1057": "Process Discovery",
    "T1059": "Command and Scripting Interpreter",
    "T1069": "Permission Groups Discovery",
    "T1070.003": "Indicator Removal: Clear Command History",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1082": "System Information Discovery",
    "T1102": "Web Service",
    "T1518": "Software Discovery",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1552.005": "Unsecured Credentials: Cloud Instance Metadata API",
    "T1562.003": "Impair Defenses: Impair Command History Logging",
    "T1567": "Exfiltration Over Web Service",
}

_COVERED_COLOR = "#8957e5"


def _check_names() -> None:
    missing = sorted({t for det in load() for t in det.attack if t not in TECHNIQUE_NAMES})
    if missing:
        raise ValueError(
            f"no ATT&CK name on file for {missing}; add them to TECHNIQUE_NAMES "
            f"so the doc cannot ship a blank cell"
        )


def render_markdown() -> str:
    _check_names()
    lines = [
        "# ATT&CK coverage",
        "",
        "Generated from `detections.yaml`. Regenerate after manifest changes:",
        "",
        "```bash",
        "uv run python -m agentdetect.attackdoc > docs/ATTACK.md",
        "```",
        "",
        "| Technique | Name | Detection | Rule |",
        "|-----------|------|-----------|------|",
    ]
    for det in load():
        kind = "sigma" if det.kind is RuleKind.SIGMA else "spl"
        for technique in det.attack:
            lines.append(f"| {technique} | {TECHNIQUE_NAMES[technique]} | {det.id} | {kind} |")
    return "\n".join(lines) + "\n"


def render_layer() -> dict[str, object]:
    _check_names()
    by_technique: dict[str, list[str]] = {}
    for det in load():
        for technique in det.attack:
            by_technique.setdefault(technique, []).append(det.id)
    techniques = [
        {
            "techniqueID": tid,
            "score": len(dets),
            "color": _COVERED_COLOR,
            "comment": ", ".join(sorted(dets)),
            "enabled": True,
        }
        for tid, dets in sorted(by_technique.items())
    ]
    return {
        "name": "agentdetect coverage",
        "description": "Detections for autonomous LLM-agent tradecraft, proven against Splunk.",
        "domain": "enterprise-attack",
        "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", _COVERED_COLOR], "minValue": 0, "maxValue": 3},
        "legendItems": [{"label": "covered by an agentdetect detection", "color": _COVERED_COLOR}],
        "hideDisabled": False,
    }


def write_layer(path: Path) -> None:
    """Write the ATT&CK Navigator layer JSON to `path`."""
    path.write_text(json.dumps(render_layer(), indent=2) + "\n", encoding="utf-8")


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="agentdetect.attackdoc")
    parser.add_argument("--layer", type=Path, help="write the Navigator layer JSON here")
    args = parser.parse_args()
    if args.layer is not None:
        write_layer(args.layer)
        return 0
    print(render_markdown(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
