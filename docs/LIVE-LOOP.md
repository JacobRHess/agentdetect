# The live loop: generating traces with a real agent

The fixtures committed to this repo are hand-authored so CI is free and
deterministic. But the premise of the project is that they don't have to be. The
`emulate` command hands an objective to a real Claude agent and records what it
actually does against a disposable sandbox, in the same schema the detections
read. The attacker isn't scripted; a model decides what to run, and its real
operating rhythm (the tempo, the error-driven retries, the breadth of
enumeration) becomes the trace.

## What it does

```
agentdetect emulate <objective>
        │
        ├─ builds emulate/Dockerfile → a throwaway container seeded with
        │  synthetic honeypot data (fake cloud keys, a decoy SSH key, a token)
        │
        ├─ gives the agent one tool, run_shell, wired into that container
        │
        └─ runs the agent loop, recording:
             • each shell command  → a process_creation event (real exit code,
               real timestamp); a curl/wget also emits its network_connection
             • each model round-trip → a network_connection to api.anthropic.com
               (the agent loop's command channel; the interleave signature)
```

The output is a JSON trace you can drop straight into `fixtures/` and replay
through the same detections that CI runs.

## Why the model API calls are in the trace

On a host being driven by an autonomous agent, the model API *is* the command
channel. The agent reads output, calls the model, and acts on the host, over
and over. Recording each model round-trip as an outbound connection isn't a
fiction added for effect; it's the literal control-plane traffic, and it's what
`agent-loop-interleave` keys on. Strip it out and you've hidden the single most
distinctive thing about an agent operator.

## Running it

```bash
uv sync --extra emulate
export ANTHROPIC_API_KEY=...            # your key; billed to you
agentdetect emulate --list             # available objectives
agentdetect emulate recon-and-loot --out fixtures/emulated.alert.json
```

Objectives:

| Objective | What the agent is told to do |
|---|---|
| `recon-and-loot` | Profile the host, hunt for credentials, stage them under /tmp |
| `privilege-hunt` | Enumerate for local privilege-escalation footholds |
| `benign-ops` | Cut a release and tidy up (a negative trace) |

## Safety model

This runs a language model against a shell. That is contained by design:

- The agent only ever touches a throwaway Docker container built from
  `emulate/Dockerfile`. Nothing on your host is exposed to it.
- The container holds **synthetic honeypot data only**. Every credential under
  `emulate/honeypot/` is fake and marked as such, so there is nothing real to
  find or exfiltrate. The sandbox also runs with no network access, no Linux
  capabilities, and hard memory and process caps.
- The loop is opt-in (`--extra emulate`), needs your own `ANTHROPIC_API_KEY`,
  and is **never** run in CI.

This is defensive tradecraft: the whole point is to see what an agent operator's
telemetry looks like so a SOC can detect it. Do not point `emulate` at anything
other than the provided sandbox.
