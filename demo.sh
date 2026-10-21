#!/usr/bin/env bash
# Runs all three TLS CVE PoCs end to end: brings each environment up (if not
# already running) and fires the attack script against both the vulnerable
# and the patched build. Safe to re-run; everything is idempotent.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"

banner() {
  echo
  echo "#################################################################"
  echo "# $1"
  echo "#################################################################"
}

# ---------------------------------------------------------------------------
banner "CVE-2025-23419 - nginx client-cert bypass via TLS session resumption"
cd "$ROOT/cve-2025-23419-nginx"
[ -d certs ] || ../common/gen-certs.sh "$PWD/certs"
docker compose up -d
sleep 2
echo "--- vulnerable (nginx 1.27.3, port 8443) ---"
./run-poc.sh 8443
echo "--- patched (nginx 1.27.4, port 9443) ---"
./run-poc.sh 9443

# ---------------------------------------------------------------------------
banner "CVE-2024-37309 - CrateDB CPU DoS via client-initiated TLS renegotiation"
cd "$ROOT/cve-2024-37309-cratedb"
if [ ! -f certs/keystore.jks ]; then
  ../common/gen-certs.sh "$PWD/certs"
  openssl pkcs12 -export -in certs/server.crt -inkey certs/server.key -certfile certs/ca.crt \
    -name cratedb -out certs/keystore.p12 -passout pass:changeit
  keytool -importkeystore -srckeystore certs/keystore.p12 -srcstoretype PKCS12 -srcstorepass changeit \
    -destkeystore certs/keystore.jks -deststoretype JKS -deststorepass changeit -destkeypass changeit -noprompt
fi
docker compose up -d
sleep 5
echo "--- vulnerable (CrateDB 5.7.1, port 4200) ---"
./run-poc.sh cve-37309-vuln 4200
echo "--- patched (CrateDB 5.7.2, port 4201) ---"
./run-poc.sh cve-37309-patched 4201

# ---------------------------------------------------------------------------
banner "CVE-2025-66491 - Traefik backend cert verification silently disabled"
cd "$ROOT/cve-2025-66491-traefik"
./run-poc.sh

banner "All three PoCs done."
