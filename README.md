# TLS Vulnerabilities PoC

Secure Communications Systems 2026-27. Piotr Pacyna. Łukasz Bilski, Mateusz Wątor,
Przemysław Bryzek.

Reproduces three recent, already patched TLS CVEs: one vulnerable and one patched
instance of each, side by side, fully in Docker on `127.0.0.1`. Nothing touches an
external network.

| CVE | Software | What it allows | Fixed in |
|---|---|---|---|
| CVE-2025-23419 | nginx | client-cert auth bypass via TLS session resumption | 1.27.4 / 1.26.3 |
| CVE-2024-37309 | CrateDB | CPU DoS via client-initiated TLS renegotiation | 5.7.2 |
| CVE-2025-66491 | Traefik | inverted `proxy-ssl-verify` leaves backend cert check disabled (MITM) | 3.6.3 |

See `STATUS.md` for the current build/debug status of each lab.

## Requirements
- Docker + Docker Compose
- OpenSSL CLI
- `keytool` / `java` (JDK, needed once to build CrateDB's Java keystore)
- `k3d` (only for the Traefik lab, `brew install k3d`)

## Quick start (per CVE)

Each `cve-*/` directory is self-contained: generate certs, then `docker compose up`.

### CVE-2025-23419, nginx
```bash
cd cve-2025-23419-nginx
../common/gen-certs.sh "$PWD/certs"
docker compose up -d
./run-poc.sh 8443   # against the vulnerable build (nginx 1.27.3)
./run-poc.sh 9443   # against the patched build (nginx 1.27.4)
```

### CVE-2024-37309, CrateDB
```bash
cd cve-2024-37309-cratedb
../common/gen-certs.sh "$PWD/certs"
openssl pkcs12 -export -in certs/server.crt -inkey certs/server.key -certfile certs/ca.crt \
  -name cratedb -out certs/keystore.p12 -passout pass:changeit
keytool -importkeystore -srckeystore certs/keystore.p12 -srcstoretype PKCS12 -srcstorepass changeit \
  -destkeystore certs/keystore.jks -deststoretype JKS -deststorepass changeit -destkeypass changeit -noprompt
docker compose up -d
# vulnerable node:  https://127.0.0.1:4200
# patched node:     https://127.0.0.1:4201
```

### CVE-2025-66491, Traefik
Not built yet. Needs a local k3d cluster. See `STATUS.md`.

## Why this is safe to share / run anywhere
Every container binds only to `127.0.0.1`, so nothing is reachable from the network.
All three CVEs are old, public, and already patched upstream, so this reproduces known,
published behaviour for a university course rather than a novel exploit. Certificates
are throwaway lab material generated locally by `common/gen-certs.sh` and are not
committed to git (see `.gitignore`); each clone regenerates its own.
