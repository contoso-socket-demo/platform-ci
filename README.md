# platform-ci

Firewall telemetry generator. No application code.

## What this repo demos

Keeps a steady stream of Socket Firewall events flowing into the `contoso`
org so the Events page is never empty when a demo opens it. Runs every 3
hours and produces both allows and blocks.

## Service mode, not `sfw npm install`

Wrapper mode was built first and **does not work for this purpose.** It
blocks correctly (npm gets a 403, the Socket reason prints) but produces
**zero org telemetry**. Verified by searching the events API for the exact
packages a wrapper-mode CI run had just installed and finding none.

Service mode reports. Confirmed locally 2026-09-15:

| Package | clientAction |
|---|---|
| `process-lhpm@1.1.79` | error (blocked) |
| `process-tailwind@1.1.99` | error (blocked) |
| `lodash@4.17.21` | monitor (allowed) |

## Three things that break it

**TLS is mandatory.** A plain-HTTP client hop breaks public upstreams in
registry mode: npm relays the canonical `https` Location unrewritten, and
PyPI hard-403s "SSL is required". `forward_for_domain: false` does not fix
it. Hence the throwaway CA in `scripts/make-certs.sh`.

**The container must publish `443:443`.** The firewall rewrites tarball URLs
to the `path_routing` domain and drops the port while doing it. On a high
port the client is handed `https://packages.contoso.internal/...` and every
download fails. Verified locally.

**`path_routing.domain` must be exactly one hostname.** Two or more
whitespace-separated names produce a rewritten Location with an embedded
space, and every npm metadata rewrite comes out corrupt.

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
