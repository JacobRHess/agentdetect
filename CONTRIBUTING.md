# Contributing

Thanks for looking. agentdetect is small on purpose: one manifest, one rule and
two fixtures per detection, and a harness that proves each rule fires on its
attack trace and stays silent on its benign one.

## Adding a detection

1. Write the rule under `rules/` - a `.yml` Sigma rule for a field match, or a
   `.spl` native Splunk search for a behavioral/statistical one. A native rule
   must lead with a filter (not a pipe) so the engine's per-run scope binds,
   and needs a `.logql` port beside it that selects `{job="agentdetect"}`. If
   the port cannot match the SPL, add a benign fixture that lands in the gap
   and mark it `diverges: [loki]` rather than leaving the difference untested.
2. Add two fixtures under `fixtures/`: `<name>.alert.json` (must fire) and
   `<name>.benign.json` (must stay silent). The benign fixture should be the
   deliberate near-miss for that rule - the case that separates a real detection
   from one that matches everything.
3. Register it in `detections.yaml` with its ATT&CK technique(s).
4. If the rule uses a new technique, add its name to `TECHNIQUE_NAMES` in
   `src/agentdetect/attackdoc.py`.

## Before you push

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run pytest -q --cov                 # offline gate
uv run python -m agentdetect.attackdoc > docs/ATTACK.md
uv run agentdetect attack --layer docs/attack-layer.json
```

Then prove it end to end against the real engine:

```bash
docker compose -f lab/docker-compose.yml up -d
uv run pytest -m replay -v
```

Every fixture is validated against the telemetry schema
(`src/agentdetect/schema.py`), so a malformed trace fails the suite rather than
silently never matching.
