"""The normalized telemetry schema every fixture is written in.

agentdetect does not invent an exotic log source. It models the two events any
Linux EDR, auditd pipeline, or Sysmon-for-Linux install already emits:

- ``process_creation`` - a command executed on the host (image, command line,
  controlling tty, exit code once the process lifecycle is joined).
- ``network_connection`` - an outbound socket a process opened (destination host
  and port, bytes moved, and the client user agent when a TLS-inspecting proxy
  can see it).

Keeping the schema to what a real sensor produces is the whole point: the
detections in this repo run on telemetry a SOC already has, so the novelty is in
what the rules *look for* (an autonomous agent's operating rhythm), not in some
bespoke feed nobody collects.

Every event carries a ``session`` - the identifier a sensor assigns to one
continuous operator session on the host (a shell session, a service's request
context). The behavioral detections group by it: an agent loop is a single
session that talks to a model and acts on the host in the same breath.

This module is the contract. ``validate_events`` is run over every fixture in
the test suite, so a malformed trace fails loudly instead of silently never
matching a rule.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

EVENT_TYPES = ("process_creation", "network_connection")

# Fields shared by every event regardless of type.
_COMMON: dict[str, type] = {
    "timestamp": str,
    "event_type": str,
    "host": str,
    "session": str,
    "user": str,
    "pid": int,
}

_PROCESS: dict[str, type] = {
    "image": str,
    "command_line": str,
}

_NETWORK: dict[str, type] = {
    "image": str,
    "dest_host": str,
    "dest_port": int,
}


class SchemaError(ValueError):
    """A telemetry event does not conform to the agentdetect schema."""


def _check_shape(event: dict[str, Any], required: dict[str, type], ctx: str) -> None:
    for field, typ in required.items():
        if field not in event:
            raise SchemaError(f"{ctx}: missing required field {field!r}")
        value = event[field]
        # bool is an int subclass; a port or pid that is True/False is a bug.
        if typ is int and isinstance(value, bool):
            raise SchemaError(f"{ctx}: field {field!r} must be {typ.__name__}, got bool")
        if not isinstance(value, typ):
            raise SchemaError(
                f"{ctx}: field {field!r} must be {typ.__name__}, got {type(value).__name__}"
            )


def _check_timestamp(value: str, ctx: str) -> None:
    """The timestamp must parse as ISO-8601 UTC.

    The behavioral searches read each event's timestamp as its Splunk _time and
    measure inter-arrival gaps from it. A timestamp that does not parse would be
    dropped and the event indexed at ingest time instead, silently breaking the
    cadence, interleave, and retry timing - a false pass, not a loud failure. So
    it is a schema error, caught here.
    """
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SchemaError(f"{ctx}: timestamp {value!r} is not ISO-8601") from exc


def validate_event(event: Any, ctx: str = "event") -> None:
    """Validate a single event, raising SchemaError with context on any problem."""
    if not isinstance(event, dict):
        raise SchemaError(f"{ctx}: event must be a JSON object")
    _check_shape(event, _COMMON, ctx)
    _check_timestamp(event["timestamp"], ctx)

    event_type = event["event_type"]
    if event_type not in EVENT_TYPES:
        raise SchemaError(f"{ctx}: event_type must be one of {EVENT_TYPES}, got {event_type!r}")

    if event_type == "process_creation":
        _check_shape(event, _PROCESS, ctx)
        # exit_code is optional (creation may precede termination) but if present
        # it must be an int so the retry-loop detection can compare it.
        if "exit_code" in event and (
            isinstance(event["exit_code"], bool) or not isinstance(event["exit_code"], int)
        ):
            raise SchemaError(f"{ctx}: exit_code must be an int")
    else:
        _check_shape(event, _NETWORK, ctx)
        for optional, typ in (("bytes_out", int), ("bytes_in", int)):
            if optional in event and (
                isinstance(event[optional], bool) or not isinstance(event[optional], typ)
            ):
                raise SchemaError(f"{ctx}: {optional} must be an int")


def validate_events(events: Any, ctx: str = "fixture") -> None:
    """Validate a fixture: a non-empty JSON array of well-formed events."""
    if not isinstance(events, list) or not events:
        raise SchemaError(f"{ctx}: must be a non-empty JSON array of events")
    for i, event in enumerate(events):
        validate_event(event, ctx=f"{ctx}[{i}]")
