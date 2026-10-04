# agentdetect

Detections for when the intruder is an autonomous LLM agent, shipped with the
telemetry that proves they fire.

The threat model everyone is quietly preparing for: the operator inside your
network is not a person and not a script, but a language model driving a shell
through a tool-use loop. It enumerates the host in seconds, reads exactly the
files that matter, adapts to every error, and treats a public model API as its
command channel. agentdetect is a small pack of detections tuned to that
operator's *rhythm* rather than to any one payload, each one shipped with two
traces - an attack sample that must fire it and a benign sample that must not -
and CI replays both through a real Splunk and a real Grafana Loki on every push.

## Why this is different from "block the LLM API"

A model API on an allowlist is not a detection. The interesting signal is not
that a host talked to `api.anthropic.com`; it is that the same session talked to
a model *and acted on the host between calls*, over and over, at a tempo no human
types at and no script pauses for. agentdetect separates the two:

- **Anchors** (Sigma) - the cheap, spoofable signals: traffic to a model API, an
  SDK user agent, a credential file read, a hit on the instance metadata service.
  Useful, brittle, and deliberately labelled as such.
- **Behavioral flagships** (native SPL, hand-ported to LogQL) - the signals that survive when the
  adversary vendors the SDK, spoofs the user agent, or rotates infrastructure,
  because they key on how an agent *operates*:
  - **agent-loop-interleave** - model call, host action, model call, host action,
    repeated in one session. The signature of a tool-use loop, and the one thing
    a benign AI feature never does (it calls the model; it does not then run
    `cat /etc/passwd`).
  - **agent-command-cadence** - non-interactive command bursts spaced by
    inference-latency gaps: faster and more regular than a human, far slower than
    a shell script.
  - **agent-retry-storm** - the same tool re-run with a tweak within seconds of
    each failure, again and again. Machine self-correction, not a human giving up.
  - **recon-breadth-burst** - one session sweeping six or more distinct discovery
    categories inside two minutes, because a model already knows every path.
  - **sensitive-read-llm-exfil** - a credential read followed by a large POST to a
    model API. Exfiltration wearing a prompt as a costume.

## Telemetry, not science fiction

Every fixture is written in one small schema (`src/agentdetect/schema.py`) that
models exactly two events any Linux EDR, auditd pipeline, or Sysmon-for-Linux
install already emits: `process_creation` and `network_connection`. Nothing here
needs a feed you do not already collect. The novelty is in what the rules look
for, not in the data.

```
                 detections.yaml  (single source of truth)
                        │
          ┌─────────────┴─────────────┐
     rules/**/*.yml           rules/**/*.spl + *.logql
       (Sigma)                (native, one per engine)
          │                             │
   Sigma → SPL, LogQL              run as-is
          └─────────────┬─────────────┘
            Splunk and Loki (CI services)
        ingest this fixture's events, run the search
                        │
            alert trace → must fire
            benign trace → must stay silent
```

## Two engines: Splunk and Loki

Every detection runs on both engines. The five Sigma rules are converted for
each. The five behavioral rules were written in SPL first, and three of them
lean on `streamstats` to compare each event with the one before it, which LogQL
has no direct equivalent for. Each has a hand-written LogQL port next to it. I am
newer to LogQL than to SPL, and the ports say how faithful they are:

| Detection | LogQL port | What it took, or what it loses |
| --- | --- | --- |
| sensitive-read-llm-exfil | exact | Event times unwrapped as values, so "exfil after read, within 180 s" is plain arithmetic. |
| agent-loop-interleave | matches SPL on every sequence tested | `rate_counter` over a 0/1 series. Its counter-reset correction counts model-call → command steps, standing in for `streamstats`. |
| recon-breadth-burst | close | The 120 s bound becomes the query range (a sliding window) instead of a per-session span. |
| agent-retry-storm | approximate | Sees that a failed executable was run again, but not how soon or what ran in between. |
| agent-command-cadence | approximate | Knows the mean gap between commands, not each gap, so it cannot tell a steady cadence from bursts and pauses. |

The two approximate ports are not left as a footnote. Each has a benign fixture
built to land in the gap (a backup job retrying on a 30 s backoff, a staged
deploy that pauses between bursts). Splunk stays silent on both, Loki fires on
both, and the manifest marks those two cells `diverges: [loki]`. A declared
divergence is tested as strictly as any other cell: if a better port closes the
gap, CI fails until the declaration is removed. If you know a LogQL way to get
at per-event gaps, I would like to hear it.

Two things about replaying into Loki that were not obvious to me going in:

- The pySigma Loki backend parses lines as logfmt unless told otherwise. This
  telemetry is JSON, so the default conversion extracted no fields and matched
  nothing. Every benign fixture "passed" while every attack fixture was missed.
  `sigma.to_logql` sets the JSON parser and the stream selector explicitly.
- Fixtures are dated the day they were written. Splunk indexes them as-is. Loki
  rejects lines more than a week old by default, so the Loki engine shifts each
  trace to end at the current time and keeps every gap between events intact.

## The live loop: fixtures generated by a real agent

The attack fixtures in this repo are hand-authored so CI is free and
deterministic. But the point of the project is that they do not have to be.
`agentdetect emulate` hands an objective to a real Claude agent, gives it a
single `run_shell` tool wired into a throwaway Docker container stocked with
**synthetic** honeypot data (fake cloud keys, a fake metadata service, decoy SSH
keys), and records every tool call and its timing into the same schema. The
attacker is not scripted; an autonomous model decides what to run, and its actual
operating rhythm becomes the trace the detections are tested against.

This path needs an Anthropic API key and Docker, runs only against the sandbox,
and is never exercised in CI. See [docs/LIVE-LOOP.md](docs/LIVE-LOOP.md) for the
safety model.

```bash
uv sync --extra emulate
export ANTHROPIC_API_KEY=...
agentdetect emulate --list
agentdetect emulate recon-and-loot --out trace.json
```

## Coverage

Ten detections across the agent kill chain, every technique tagged to MITRE
ATT&CK. The full, always-current list is [docs/ATTACK.md](docs/ATTACK.md),
generated from the manifest, not hand-edited, and diffed in CI so it cannot
drift.

## Running it

```bash
uv sync --extra dev
uv run agentdetect list              # every detection, rule kind, ATT&CK mapping
uv run agentdetect validate          # every rule is well-formed (offline gate)
uv run agentdetect convert agent-loop-interleave   # see the SPL a detection runs
uv run agentdetect convert agent-loop-interleave --engine loki   # and the LogQL
docker compose -f lab/docker-compose.yml up -d     # local Splunk + Loki
uv run pytest -m replay              # replay every fixture through both engines
uv run agentdetect report --out report.html
uv run agentdetect report --engine loki --out report-loki.html
```

## Layout

```
detections.yaml          single source of truth: id, rule, ATT&CK, fixtures
rules/process/           Sigma rules over process_creation events
rules/network/           Sigma rules over network_connection events
rules/correlation/       native searches for the behavioral detections (.spl + .logql)
fixtures/                attack + benign traces, at least one pair per detection
src/agentdetect/         schema, manifest, Sigma converter, Splunk + Loki clients, CLI
emulate/                 the sandbox container + honeypot for the live agent loop
lab/                     docker-compose for a local Splunk and Loki
docs/                    generated ATT&CK coverage + the live-loop runbook
```

## License

MIT. See [LICENSE](LICENSE).
