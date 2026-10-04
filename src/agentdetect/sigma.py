"""Convert one Sigma rule into the search each engine runs.

The field-match detections are authored as Sigma so the logic is portable and
reads as standard detection content. This module converts a rule to SPL and to
LogQL; the engine scopes the result to a private per-replay marker before
running it, so the converter never emits an index, a run, or a time range.

The behavioral detections are *not* Sigma - they are native ``.spl`` searches
(and hand-ported ``.logql`` queries) that measure timing and cadence, which
Sigma cannot express honestly. Those never pass through here; see
``manifest.RuleKind`` and the engine.
"""

from __future__ import annotations

from functools import cache

from sigma.backends.loki import LogQLBackend
from sigma.backends.splunk import SplunkBackend  # type: ignore[attr-defined]
from sigma.collection import SigmaCollection
from sigma.pipelines.loki.loki import LokiCustomAttributes, SetCustomAttributeTransformation
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

from agentdetect.loki import SELECTOR


class ConversionError(ValueError):
    """A Sigma rule could not be converted to an engine query."""


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


def _loki_pipeline() -> ProcessingPipeline:
    """Tell the Loki backend what the telemetry actually looks like.

    Left alone, the backend selects every stream and parses lines as logfmt.
    The telemetry is JSON, so a logfmt query extracts no fields and matches
    nothing: every attack fixture would stay silent while every benign fixture
    "passed". The parser and the selector are set explicitly instead.
    """
    return ProcessingPipeline(
        name="agentdetect JSON telemetry",
        priority=20,
        items=[
            ProcessingItem(
                identifier="agentdetect_json_parser",
                transformation=SetCustomAttributeTransformation(
                    attribute=LokiCustomAttributes.PARSER.value, value="json"
                ),
            ),
            ProcessingItem(
                identifier="agentdetect_stream_selector",
                transformation=SetCustomAttributeTransformation(
                    attribute=LokiCustomAttributes.LOGSOURCE_SELECTION.value, value=SELECTOR
                ),
            ),
        ],
    )


@cache
def to_logql(rule_text: str) -> str:
    """Convert a Sigma rule to a LogQL log query over the agentdetect stream."""
    queries = LogQLBackend(processing_pipeline=_loki_pipeline()).convert(_collection(rule_text))
    if not queries:
        raise ConversionError("loki backend produced no query")
    if len(queries) > 1:
        raise ConversionError(
            f"loki backend produced {len(queries)} queries; "
            "an agentdetect Sigma rule must convert to exactly one"
        )
    return str(queries[0])
