# platform-ci

Firewall telemetry generator. No application code.

## What this repo demos

Keeps a steady stream of Socket Firewall events flowing into the `contoso`
org so the Events page is never empty when a demo opens it.
`firewall-traffic.yml` runs every 3 hours and produces both allows and
blocks, so the page shows a realistic mix rather than a wall of red.

No always-on infrastructure. `sfw` runs in wrapper mode inside the job.

## Blocked packages are discovered, never hardcoded

`scripts/pick-blocked-packages.sh` queries the threat feed each run. Two
filters matter:

- `threatType` must be exactly `malware`. `possible_malware` only **warns**,
  it does not block, so it produces an allow event and a confusing demo.
- Versions ending `-security` are npm's own replacement stubs. They resolve
  but are not the malicious artifact.

It then checks the version is still live on npm. If npm has removed it, the
install fails at resolution with a generic "no matching version found" and
Socket never gets to speak.

## The freshness check is the point

`scripts/verify-events.sh` fails the job if no recent firewall event exists.
Without it, a wrong token env var yields zero events and a silent green
checkmark, which is how a demo surface rots unnoticed.

Verified against org `contoso` on 2026-09-15:

- Endpoint is `GET /v0/orgs/{org}/events`. `/firewall/events` returns 404.
- Rows are under `items`, not `results`.
- The feed mixes two different things. `eventCategory=external` with an
  `artifactPurl` is a real firewall package decision.
  `eventCategory=api-analytics` with no purl is API call analytics, including
  the firewall's own calls and any `curl` you run. The script filters on
  `artifactPurl` so API noise cannot make the check pass.
- `clientAction` values are `error`, `warn`, `monitor`. There is no `block`
  value; a block surfaces as `error`.

## Required secrets

- `SOCKET_SECURITY_API_TOKEN`
