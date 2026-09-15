#!/usr/bin/env bash
# Generate a throwaway CA plus a server cert for the firewall hostname.
#
# Real TLS is REQUIRED here, not a convenience. A plain-HTTP client hop
# breaks public upstreams in registry mode: npm relays the canonical https
# Location unrewritten and PyPI hard-403s "SSL is required". Setting
# forward_for_domain: false does NOT fix it. Live-validated.
set -euo pipefail
HOST="${1:-packages.contoso.internal}"
OUT="${2:-certs}"
mkdir -p "$OUT"

openssl genrsa -out "$OUT/ca.key" 2048 2>/dev/null
openssl req -x509 -new -nodes -key "$OUT/ca.key" -sha256 -days 3650 \
  -subj "/CN=Contoso Demo CA" -out "$OUT/ca.pem" 2>/dev/null

openssl genrsa -out "$OUT/privkey.pem" 2048 2>/dev/null
openssl req -new -key "$OUT/privkey.pem" -subj "/CN=$HOST" -out "$OUT/srv.csr" 2>/dev/null
printf 'subjectAltName=DNS:%s\n' "$HOST" > "$OUT/san.ext"
openssl x509 -req -in "$OUT/srv.csr" -CA "$OUT/ca.pem" -CAkey "$OUT/ca.key" \
  -CAcreateserial -out "$OUT/fullchain.pem" -days 3650 -sha256 \
  -extfile "$OUT/san.ext" 2>/dev/null

# A cert without the SAN is silently rejected by modern clients, so assert it.
openssl x509 -in "$OUT/fullchain.pem" -noout -ext subjectAltName \
  | grep -q "DNS:$HOST" || { echo "SAN for $HOST missing from cert" >&2; exit 1; }
echo "certs ready in $OUT (SAN DNS:$HOST)"
