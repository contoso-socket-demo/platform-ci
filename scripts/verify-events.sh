#!/usr/bin/env bash
# Verify that the packages just installed produced firewall events.
#
# CALL THIS ONCE PER TRAFFIC PHASE, not once at the end.
#
# The events endpoint returns only the newest ~100 rows and ignores every
# cursor parameter tried on GET (cursor, page_cursor, after, startAfter all
# return the same first page). A single npm install of express plus pg emits
# ~70 `ignore` events for the transitive tree, so one phase floods the whole
# window. Verifying everything at the end reported the allow packages as
# MISSING when they had in fact been recorded and simply paginated out.
#
# Verified against org contoso 2026-09-15:
#   GET /v0/orgs/{org}/events -> { endCursor, items: [...], meta }
#   NOT /firewall/events (404). Rows under "items", not "results".
#
# Rows with an artifactPurl are firewall package decisions. Rows with
# eventCategory=api-analytics and no purl are API call analytics, including
# this script's own curl, so filtering on artifactPurl is required.
#
# clientAction is error | warn | monitor | ignore. There is no "block":
# a block surfaces as error.
set -euo pipefail
: "${SOCKET_SECURITY_API_TOKEN:?SOCKET_SECURITY_API_TOKEN must be set}"
ORG="${SOCKET_ORG:-contoso}"
LABEL="${1:?usage: verify-events.sh <label> <expected-file>}"
EXPECT_FILE="${2:?usage: verify-events.sh <label> <expected-file>}"

sleep "${EVENT_SETTLE_SECONDS:-25}"

code=$(curl -s -o /tmp/events.json -w '%{http_code}' \
  -u "${SOCKET_SECURITY_API_TOKEN}:" \
  "https://api.socket.dev/v0/orgs/${ORG}/events?per_page=100")
[ "$code" = "200" ] || { echo "events API HTTP $code" >&2; head -c 400 /tmp/events.json >&2; exit 1; }

LABEL="$LABEL" python3 - "$EXPECT_FILE" <<'PY'
import collections, json, os, sys

label = os.environ["LABEL"]
expect = [l.strip() for l in open(sys.argv[1]) if l.strip()]
rows = [r for r in json.load(open("/tmp/events.json")).get("items") or []
        if r.get("artifactPurl")]

ts = [r.get("eventCreatedAt") for r in rows if r.get("eventCreatedAt")]
print(f"[{label}] firewall events in newest window: {len(rows)}")
if ts:
    print(f"  window spans {min(ts)} .. {max(ts)}")
print("  clientAction mix:", dict(collections.Counter(r.get("clientAction") for r in rows)))

purls = {r["artifactPurl"] for r in rows}
missing = []
for spec in expect:
    name, _, ver = spec.rpartition("@")
    want = f"pkg:npm/{name}@{ver}"
    hit = want in purls
    print(f"  {'FOUND  ' if hit else 'MISSING'}  {want}")
    if not hit:
        missing.append(want)

if missing:
    sys.exit(f"[{label}] FAIL: {len(missing)} of {len(expect)} expected purls "
             f"produced no event in the newest window")
print(f"[{label}] OK: all {len(expect)} expected purls produced firewall events")
PY
