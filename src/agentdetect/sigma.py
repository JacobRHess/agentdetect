"""Convert one Sigma rule into the Splunk search it runs.

The field-match detections are authored as Sigma so the logic is portable and
reads as standard detection content. This module converts a rule to SPL; the
engine scopes that SPL to a private per-replay marker before running it, so the
converter only ever emits match logic, never an index or a time range.

The behavioral detections are *not* Sigma - they are native ``.spl`` searches
that measure timing and cadence, which Sigma cannot express honestly. Those
never pass through here; see ``manifest.RuleKind`` and the engine.
"""

from __future__ import annotations

from functools import cache

from sigma.backends.splunk import SplunkBackend  # type: ignore[attr-defined]
from sigma.collection import SigmaCollection


class ConversionError(ValueError):
    """A Sigma rule could not be converted to a Splunk search."""


def _collection(rule_text: str) -> SigmaCollection:
    try:
        return SigmaCollection.from_yaml(rule_text)
    except Exception as exc:  # pySigma raises a family of parse errors
        raise ConversionError(f"rule did not parse as Sigma: {exc}") from exc


@cache
def to_spl(rule_text: str) -> str:
    """Convert a Sigma rule to a Splunk SPL search expression (no index selector)."""
    queries = SplunkBackend().convert(_collection(rule_text))
    if not queries:
        raise ConversionError("splunk backend produced no query")
    if len(queries) > 1:
        raise ConversionError(
            f"splunk backend produced {len(queries)} queries; "
            "an agentdetect Sigma rule must convert to exactly one"
        )
    return str(queries[0])
