#!/usr/bin/env bash
# Emit "name@version" lines for npm packages Socket confirms as MALWARE and
# that npm still serves. Both conditions matter:
#
#   * threatType must be exactly "malware". "possible_malware" only WARNS,
#     it does not block, so it produces an allow event and a confusing demo.
#   * versions ending "-security" are npm's own replacement stubs. They
#     resolve but are not the malicious artifact.
#
# If npm has removed a version, the install fails at resolution with a
# generic "no matching version found" and Socket never gets to speak.
set -euo pipefail
: "${SOCKET_SECURITY_API_TOKEN:?SOCKET_SECURITY_API_TOKEN must be set}"
WANT="${1:-4}"

python3 - "$WANT" <<'PY'
import base64, json, os, sys, urllib.error, urllib.parse, urllib.request

want = int(sys.argv[1])
tok = os.environ["SOCKET_SECURITY_API_TOKEN"]
auth = base64.b64encode((tok + ":").encode()).decode()

def api(path):
    req = urllib.request.Request(
        "https://api.socket.dev" + path,
        headers={"Authorization": "Basic " + auth},
    )
    return json.loads(urllib.request.urlopen(req, timeout=60).read().decode())

rows = []
for page in range(1, 5):
    qs = urllib.parse.urlencode(
        {"type": "npm", "per_page": 100, "page": page, "filter": "mal"}
    )
    try:
        rows += api(f"/v0/threat-feed?{qs}").get("results") or []
    except urllib.error.HTTPError as e:
        sys.exit(f"threat-feed HTTP {e.code}: {e.read().decode()[:200]}")

def live_on_npm(name, ver):
    url = f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}/{ver}"
    try:
        with urllib.request.urlopen(url, timeout=20) as r:
            return r.status == 200
    except Exception:
        return False

seen, out = set(), []
for r in rows:
    if r.get("threatType") != "malware":
        continue
    purl = (r.get("purl") or "").split("?")[0]
    if not purl.startswith("pkg:npm/"):
        continue
    rest = purl[len("pkg:npm/"):]
    if "@" not in rest:
        continue
    name, _, ver = rest.rpartition("@")
    name = urllib.parse.unquote(name)
    if not ver or ver.endswith("-security") or (name, ver) in seen:
        continue
    seen.add((name, ver))
    if live_on_npm(name, ver):
        out.append(f"{name}@{ver}")
    if len(out) >= want:
        break

if not out:
    sys.exit("no live confirmed-malware npm packages found in the first 400 feed rows")
print("\n".join(out))
PY
