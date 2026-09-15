#!/usr/bin/env bash
# Fail the job unless the packages THIS RUN touched show up as firewall
# events. Passed a list of "name@version" on stdin.
#
# An earlier version only checked "is the newest event recent", which passed
# on pre-existing events from an unrelated local demo while this run had in
# fact produced nothing. Matching specific purls is the only honest check.
#
# Verified against org contoso 2026-09-15:
#   GET /v0/orgs/{org}/events  ->  { endCursor, items: [...], meta }
#   NOT /firewall/events (404). Rows under "items", not "results".
#
# The feed mixes two kinds of row:
#   eventCategory=external      + artifactPurl set -> firewall decision
#   eventCategory=api-analytics + no artifactPurl  -> API call analytics,
#                                                     including your own curl
# So filter on artifactPurl or API noise makes this pass for free.
#
# clientAction is error | warn | monitor | ignore. There is no "block".
set -euo pipefail
: "${SOCKET_SECURITY_API_TOKEN:?SOCKET_SECURITY_API_TOKEN must be set}"
ORG="${SOCKET_ORG:-contoso}"
EXPECT_FILE="${1:?usage: verify-events.sh <file-with-name@version-lines>}"

sleep "${EVENT_SETTLE_SECONDS:-25}"

code=$(curl -s -o /tmp/events.json -w '%{http_code}' \
  -u "${SOCKET_SECURITY_API_TOKEN}:" \
  "https://api.socket.dev/v0/orgs/${ORG}/events?per_page=100")
[ "$code" = "200" ] || { echo "events API HTTP $code" >&2; head -c 400 /tmp/events.json >&2; exit 1; }

python3 - "$EXPECT_FILE" <<'PY'
import collections, json, sys

expect = [l.strip() for l in open(sys.argv[1]) if l.strip()]
rows = [r for r in json.load(open("/tmp/events.json")).get("items") or []
        if r.get("artifactPurl")]

print(f"firewall package-decision events in feed: {len(rows)}")
print("  clientAction mix:", dict(collections.Counter(r.get("clientAction") for r in rows)))

purls = {r["artifactPurl"] for r in rows}
missing = []
for spec in expect:
    name, _, ver = spec.rpartition("@")
    want = f"pkg:npm/{name}@{ver}"
    hit = any(p == want for p in purls)
    print(f"  {'FOUND  ' if hit else 'MISSING'}  {want}")
    if not hit:
        missing.append(want)

if missing:
    sys.exit(f"FAIL: {len(missing)} of {len(expect)} expected purls produced no event")
print(f"OK: all {len(expect)} expected purls produced firewall events")
PY
