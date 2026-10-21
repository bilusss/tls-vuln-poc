#!/usr/bin/env bash
# Generate a tiny PKI shared by the PoCs:
#   ca.crt / ca.key      - our own Certificate Authority ("CA-A")
#   ca2.crt / ca2.key    - a SECOND, independent CA ("CA-B") - used by the nginx lab
#                          as a DIFFERENT trust anchor for a different vhost, to show
#                          a cert valid under CA-A getting wrongly accepted by a vhost
#                          that only trusts CA-B, via TLS session resumption.
#   server.crt/.key      - server cert, SAN covers public.local + secure.local + localhost
#   client.crt/.key      - client cert signed by our CA (CA-A) (for the nginx mTLS demo)
#   untrusted.crt/.key    - self-signed cert NOT signed by our CA (for the Traefik MITM demo)
#
# Everything is throwaway lab material. Do not reuse outside this testbed.
set -euo pipefail

OUT="${1:-$(cd "$(dirname "$0")" && pwd)/certs}"
mkdir -p "$OUT"
cd "$OUT"

echo "[*] Writing certs into: $OUT"

# --- Our CA ------------------------------------------------------------------
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout ca.key -out ca.crt \
  -subj "/CN=TLS-PoC Lab CA" 2>/dev/null

# --- A second, independent CA (CA-B) ----------------------------------------
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout ca2.key -out ca2.crt \
  -subj "/CN=TLS-PoC Lab CA-2" 2>/dev/null

# --- Server cert (signed by CA), SAN = the two vhosts + localhost ------------
openssl req -newkey rsa:2048 -nodes \
  -keyout server.key -out server.csr \
  -subj "/CN=public.local" 2>/dev/null

cat > server.ext <<'EOF'
subjectAltName = DNS:public.local, DNS:secure.local, DNS:localhost, IP:127.0.0.1
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 365 -extfile server.ext -out server.crt 2>/dev/null

# --- Client cert (signed by CA) ---------------------------------------------
openssl req -newkey rsa:2048 -nodes \
  -keyout client.key -out client.csr \
  -subj "/CN=legit-client" 2>/dev/null
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 365 -out client.crt 2>/dev/null

# --- Untrusted self-signed cert (NOT signed by our CA) ----------------------
# Used as a rogue backend cert in the Traefik verification-bypass demo.
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout untrusted.key -out untrusted.crt \
  -subj "/CN=rogue-backend" \
  -addext "subjectAltName=DNS:backend.local" 2>/dev/null

rm -f server.csr client.csr server.ext *.srl

echo "[*] Done:"
ls -1 "$OUT"
