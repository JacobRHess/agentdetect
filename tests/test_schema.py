"""The telemetry schema, and proof every committed fixture conforms to it."""

from __future__ import annotations

import json

import pytest

from agentdetect.manifest import load
from agentdetect.schema import SchemaError, validate_event, validate_events

_FIXTURES = [fx.events for det in load() for fx in det.fixtures]


@pytest.mark.parametrize("path", _FIXTURES, ids=lambda p: p.name)
def test_every_fixture_conforms_to_schema(path) -> None:
    events = json.loads(path.read_text(encoding="utf-8"))
    validate_events(events, ctx=path.name)


def test_process_event_ok() -> None:
    validate_event(
        {
            "timestamp": "2026-07-07T00:00:00.000Z",
            "event_type": "process_creation",
            "host": "h",
            "session": "s",
            "user": "u",
            "pid": 1,
            "image": "/bin/sh",
            "command_line": "sh -c id",
        }
    )


def test_network_event_ok() -> None:
    validate_event(
        {
            "timestamp": "2026-07-07T00:00:00.000Z",
            "event_type": "network_connection",
            "host": "h",
            "session": "s",
            "user": "u",
            "pid": 1,
            "image": "/bin/curl",
            "dest_host": "example.com",
            "dest_port": 443,
        }
    )


def test_missing_common_field() -> None:
    with pytest.raises(SchemaError, match="session"):
        validate_event(
            {
                "timestamp": "t",
                "event_type": "process_creation",
                "host": "h",
                "user": "u",
                "pid": 1,
                "image": "/bin/sh",
                "command_line": "id",
            }
        )


def test_unknown_event_type() -> None:
    with pytest.raises(SchemaError, match="event_type"):
        validate_event(
            {
                "timestamp": "2026-07-07T00:00:00.000Z",
                "event_type": "file_write",
                "host": "h",
                "session": "s",
                "user": "u",
                "pid": 1,
            }
        )


def test_bool_is_not_an_int_port() -> None:
    with pytest.raises(SchemaError, match="dest_port"):
        validate_event(
            {
                "timestamp": "2026-07-07T00:00:00.000Z",
                "event_type": "network_connection",
                "host": "h",
                "session": "s",
                "user": "u",
                "pid": 1,
                "image": "/bin/curl",
                "dest_host": "x",
                "dest_port": True,
            }
        )


def test_bad_exit_code_type() -> None:
    with pytest.raises(SchemaError, match="exit_code"):
        validate_event(
            {
                "timestamp": "2026-07-07T00:00:00.000Z",
                "event_type": "process_creation",
                "host": "h",
                "session": "s",
                "user": "u",
                "pid": 1,
                "image": "/bin/sh",
                "command_line": "id",
                "exit_code": "zero",
            }
        )


def test_empty_fixture_rejected() -> None:
    with pytest.raises(SchemaError, match="non-empty"):
        validate_events([])


def test_unparseable_timestamp_rejected() -> None:
    with pytest.raises(SchemaError, match="ISO-8601"):
        validate_event(
            {
                "timestamp": "last tuesday",
                "event_type": "process_creation",
                "host": "h",
                "session": "s",
                "user": "u",
                "pid": 1,
                "image": "/bin/sh",
                "command_line": "id",
            }
        )
