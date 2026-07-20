# Security

## Scope

agentdetect is a detection-engineering project. It ships detection rules (Sigma
and native Splunk searches), synthetic telemetry fixtures, and a harness that
replays those fixtures through Splunk. It does not run in production and does not
handle real data; every fixture in this repo is hand-authored or generated in a
lab, never captured from a real host or tenant.

## The emulation loop

`agentdetect emulate` drives a real Claude agent through attacker-style
objectives to generate attack traces. This is defensive tradecraft - the point
is to capture what an autonomous agent's activity looks like so it can be
detected - and it is contained by design:

- The agent operates only inside a throwaway Docker container built from
  `emulate/Dockerfile`. That container runs with no network access
  (`--network none`), all Linux capabilities dropped (`--cap-drop ALL`), no new
  privileges, and hard memory and process-count caps, so a command the agent
  runs cannot reach the network or exhaust the host.
- The container is seeded with **synthetic honeypot data only**: fake cloud
  keys, a decoy SSH key, and a planted token, all clearly marked as non-real.
  There is nothing real for the agent to reach or exfiltrate.
- The loop needs an `ANTHROPIC_API_KEY`, is opt-in (`uv sync --extra emulate`),
  and is **never** run in CI.

Do not point the emulation loop at anything other than the provided sandbox.

## Reporting

Found something wrong with a detection (a false positive, a trivial bypass, a
mislabeled ATT&CK technique) or with the harness itself? Open an issue, or for
anything sensitive email the address in the repo profile.

## Handling of credentials

- The local lab (`lab/docker-compose.yml`) and the CI `validate` job use a
  throwaway, in-repo development password and a well-known HEC token for Splunk.
  They are not secrets; they guard an ephemeral container that never leaves the
  runner.
- The honeypot credentials under `emulate/honeypot/` are fake by construction.

## Known advisories

- **CVE-2025-69872** (diskcache) is tolerated in CI. diskcache is pulled
  transitively by pySigma; there is no fixed release. pySigma in this repo only
  ever converts the repo's own trusted Sigma rules, so no untrusted input
  reaches diskcache and the vulnerable path is unreachable. The `pip-audit` step
  in `.github/workflows/ci.yml` ignores it explicitly; drop the ignore when a
  fixed diskcache ships.
