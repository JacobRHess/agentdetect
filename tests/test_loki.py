"""The offline half of the Loki client: run scoping and timestamp handling."""

from __future__ import annotations

import pytest

from agentdetect.loki import SELECTOR, LokiError, _epoch_ns, scope

_RUN = "0123456789abcdef0123456789abcdef"


def test_scope_narrows_every_selector() -> None:
    logql = f"sum(count_over_time({SELECTOR} [5m])) - sum(count_over_time({SELECTOR} [1m]))"
    scoped = scope(logql, _RUN)
    assert SELECTOR not in scoped
    assert scoped.count('ad_run="' + _RUN + '"') == 2


def test_scope_rejects_a_run_that_is_not_a_uuid_hex() -> None:
    with pytest.raises(LokiError, match="invalid run token"):
        scope(SELECTOR, 'x"} or {job=~".+')


def test_scope_rejects_a_rule_it_cannot_confine() -> None:
    with pytest.raises(LokiError, match="cannot be scoped"):
        scope('sum(count_over_time({job=~".+"} [5m]))', _RUN)


def test_epoch_ns_keeps_millisecond_gaps() -> None:
    first = _epoch_ns("2026-07-07T16:00:00.000Z")
    second = _epoch_ns("2026-07-07T16:00:03.200Z")
    assert second - first == 3_200_000_000


@pytest.mark.parametrize("bad", [None, 1783432931, "yesterday"])
def test_epoch_ns_rejects_unusable_timestamps(bad: object) -> None:
    with pytest.raises(LokiError, match="timestamp"):
        _epoch_ns(bad)
