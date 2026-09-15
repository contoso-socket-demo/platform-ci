#!/usr/bin/env bash
# Fail the job loudly if the firewall run produced no FRESH package-decision
# telemetry. Without this, a wrong token env var yields zero real events and
# a silent green checkmark, which is how a demo surface rots unnoticed.
#
# Verified against org contoso 2026-09-15:
#   GET /v0/orgs/{org}/events  ->  { endCursor, items: [...], meta }
#   NOT /firewall/events (404). Rows are under "items", not "results".
#
# CRITICAL: the events feed mixes two very different things.
#   eventCategory=external       + artifactPurl set  -> a real firewall
#                                                       package decision
#   eventCategory=api-analytics  + no artifactPurl   -> API call analytics,
#                                                       including the
#                                                       firewall's own calls
#                                                       and any curl you run
# Counting the second kind makes this check pass with zero firewall traffic,
# so we filter on artifactPurl.
#
# clientAction values in practice: error | warn | monitor. There is no
# "block" value; a block surfaces as clientAction=error.
set -euo pipefail
: "${SOCKET_SECURITY_API_TOKEN:?SOCKET_SECURITY_API_TOKEN must be set}"
ORG="${SOCKET_ORG:-contoso}"
MAX_AGE_MIN="${MAX_AGE_MIN:-45}"

code=$(curl -s -o /tmp/events.json -w '%{http_code}' \
  -u "${SOCKET_SECURITY_API_TOKEN}:" \
  "https://api.socket.dev/v0/orgs/${ORG}/events?per_page=100")

if [ "$code" != "200" ]; then
  echo "events API returned HTTP ${code}:" >&2
  head -c 400 /tmp/events.json >&2; echo >&2
  exit 1
fi

MAX_AGE_MIN="$MAX_AGE_MIN" python3 - <<'PY'
import collections, datetime, json, os, sys

max_age = int(os.environ["MAX_AGE_MIN"])
allrows = json.load(open("/tmp/events.json")).get("items") or []

# Only rows carrying an artifactPurl are package decisions made by the firewall.
rows = [r for r in allrows if r.get("artifactPurl")]
print(f"events returned: {len(allrows)}  (firewall package decisions: {len(rows)})")
if not rows:
    sys.exit("FAIL: no firewall package-decision events -- telemetry is not flowing")

def parsed(r):
    ts = r.get("eventCreatedAt") or ""
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.datetime.strptime(ts[:19], fmt)
        except ValueError:
            continue
    return None

print("  clientAction mix:", dict(collections.Counter(r.get("clientAction") for r in rows)))
print("  sample purls:")
for r in rows[:4]:
    print(f"    {r.get('clientAction')}  {r.get('artifactPurl')}")

stamped = [t for t in (parsed(r) for r in rows) if t]
if not stamped:
    sys.exit("FAIL: no parseable eventCreatedAt on any firewall row")

newest = max(stamped)
age = (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - newest).total_seconds() / 60
print(f"  newest firewall event: {newest} UTC ({age:.0f} min old)")

if age > max_age:
    sys.exit(f"FAIL: newest firewall event is {age:.0f} min old, over the {max_age} min budget")
print("OK: fresh firewall telemetry present")
PY
