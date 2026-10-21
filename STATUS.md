# Status projektu: TLS Vulnerabilities PoC (Meeting #1)

Pierwsza konsultacja (Proof of Concept): 2026-10-21. Prezentacja gotowa:
`docs/TLS-Vulnerabilities-Meeting-1-PoC.pptx` (8 slajdów, treść OK,
patrz "Uwaga do slajdów" poniżej).

Trzy CVE do zademonstrowania w Dockerze, wersja podatna vs. załatana, oba na 127.0.0.1:

| CVE | Produkt | Co umożliwia | Fix |
|---|---|---|---|
| CVE-2025-23419 | nginx | bypass auth. certyfikatem klienta przez wznowienie sesji TLS | 1.27.4 / 1.26.3 |
| CVE-2024-37309 | CrateDB | DoS (CPU) przez client-initiated renegotiation TLS | 5.7.2 |
| CVE-2025-66491 | Traefik | odwrócona logika proxy-ssl-verify, wyłączona weryfikacja certu backendu (MITM) | 3.6.3 |

## Uwaga do slajdów
Slajd 7 (Traefik) podaje CVSS "do 8.2". Zweryfikowane źródła (NVD, GitHub Advisory
GHSA-7vww-mvcr-x6vj) podają CVSS 5.9. Do poprawienia w prezentacji przed spotkaniem.

## Środowisko (zweryfikowane 2026-10-21)
- macOS, Docker 29.8.1 + Compose v5.5.1, OK, daemon działa.
- OpenSSL 3.6.4, OK. Java/keytool, OK (potrzebne do keystore dla CrateDB).
- `k3d`: brak, trzeba doinstalować przed robieniem labu Traefik (`brew install k3d`).
- kubectl v1.36.1 jest.
- macOS nie ma `timeout` z coreutils. W skryptach używamy przenośnego zamiennika:
  `perl -e 'alarm shift; exec @ARGV' N cmd...`.
- Wolne miejsce na dysku: ok. 35 GB w momencie startu.

## Struktura repo
```
~/tls-vuln-poc/
  demo.sh                           odpala wszystkie trzy PoC jedną komendą
  common/gen-certs.sh               generator mini-PKI (CA, server, client, untrusted certy)
  cve-2025-23419-nginx/
    nginx.conf                      config z dwoma vhostami na jednym porcie
    docker-compose.yml              nginx:1.27.3 (vuln, port 8443) + nginx:1.27.4 (patched, port 9443)
    certs/                          wygenerowane przez gen-certs.sh, nie commitowane do git
    run-poc.sh                      skrypt atakujący (openssl s_client)
  cve-2024-37309-cratedb/
    crate.yml                       konfiguracja TLS na porcie 4200 (HTTP)
    docker-compose.yml              crate:5.7.1 (vuln, port 4200) + crate:5.7.2 (patched, port 4201)
    certs/                          jak wyżej, plus keystore.jks (nie commitowany)
    run-poc.sh                      pętla renegocjacji + pomiar CPU kontenera
  cve-2025-66491-traefik/
    manifests/                      namespace, backend HTTPS, RBAC, 2x Traefik, IngressClass+Ingress
    certs/                          jak wyżej
    run-poc.sh                      tworzy/reużywa klaster k3d, apply, port-forward, curl na obie wersje
```

## Status per CVE

### 1. CVE-2025-23419 (nginx): działa end to end, bypass odtworzony

Root cause znaleziony przez czytanie realnego kodu nginx (nie zgadywanie):
`ngx_http_process_request()` w `src/http/ngx_http_request.c` czyta
`SSL_get_peer_certificate(c->ssl->connection)`. Na WZNOWIONEJ (abbreviated TLSv1.3)
sesji żaden nowy Certificate message nie jest wymieniany — OpenSSL po stronie serwera
po prostu zwraca certyfikat i wynik weryfikacji **zcache'owany z oryginalnego,
pełnego handshake'u**. Nginx nie re-weryfikuje tego certu wobec CA listy nowo
wybranego (po SNI) server blocku.

Pierwsza wersja configu (public.local bez wymogu certu wcale) była ślepym zaułkiem:
`SSL_get_peer_certificate` zwracał po prostu NULL (zawsze, bo nic nie było do
zcache'owania), więc oba build'y (podatny i załatany) dawały identyczny wynik
(`400 No required SSL certificate was sent`) — to NIE testowało rzeczywistego bugu.

Właściwy scenariusz wymaga DWÓCH różnych CA:
- `public.local` (named vhost): `ssl_client_certificate ca.crt` (CA-A).
- `secure.local` (default_server): `ssl_client_certificate ca2.crt` (CA-B, INNE CA).
- Atakujący ma cert podpisany przez CA-A (`client.crt`/`client.key`).

Atak: zaloguj się normalnie na `public.local` certem CA-A (sukces, bo CA-A tam
zaufane), zapisz sesję, wznów ją żądając `secure.local` BEZ podawania żadnego certu.

Wynik:
- Podatna (1.27.3): `SECURE reached ... verify=SUCCESS` — cert zaufany tylko przez
  CA-A został zaakceptowany na vhoście, który ufa wyłącznie CA-B. Bypass potwierdzony.
- Załatana (1.27.4): `tlsv1 alert access denied` (SSL alert 49) — to dosłownie
  `SSL_AD_ACCESS_DENIED` z fix commitu nginx (hash `13935cf`, "SNI: added restriction
  for TLSv1.3 cross-SNI session resumption"), `New, TLSv1.3` (nie `Reused`, czyli
  handshake faktycznie odrzucony na poziomie TLS, nie HTTP).

Fix dodaje w `ngx_http_ssl_servername()`: jeśli `ssl_verify_client` jest włączone dla
server blocku wybranego przez SNI, nginx porównuje hostname zapisany w wznawianej
sesji (`SSL_SESSION_get0_hostname()`) z aktualnie żądanym SNI, i przy niezgodności
odrzuca handshake. Zablokowane dawno, błędne podejścia po drodze (TLSv1.2 zamiast
TLSv1.3, resume bez SNI, jeden-CA scenariusz) opisane w historii commitów repo, nie
trzeba ich powtarzać.

```bash
cd ~/tls-vuln-poc/cve-2025-23419-nginx
docker compose up -d
./run-poc.sh 8443   # podatna: STEP 4 -> "SECURE reached ... verify=SUCCESS"
./run-poc.sh 9443   # załatana: STEP 4 -> "tlsv1 alert access denied"
```

### 2. CVE-2024-37309 (CrateDB): działa end to end, efekt widoczny na CPU

Zbudowane i przetestowane. Keystore JKS zrobiony z naszego PKI (openssl pkcs12 +
keytool), zamontowany do obu kontenerów przez `crate.yml` (`ssl.http.enabled: true`).
Ważna poprawka: oba kontenery potrzebują `-Cnetwork.host=0.0.0.0` w `docker-compose.yml`
(komenda startowa), bo CrateDB domyślnie wiąże się tylko na `127.0.0.1`/`::1` wewnątrz
kontenera (ustawienie Elasticsearch-owe "_local_"), co z userland-proxy Dockera na
macOS powodowało, że handshake TLS nigdy się nie kończył (serwer zrywał połączenie po
ClientHello, bez żadnego ServerHello, bez logu po stronie serwera).

`run-poc.sh [container] [port]` otwiera jedną sesję TLS 1.2 (z flagami
`-legacy_renegotiation -legacy_server_connect`, bo nowoczesny OpenSSL domyślnie
odmawia inicjować renegocjację bez tych flag) i strzela 100 renegocjacjami w pętli,
mierząc CPU kontenera przez `docker stats` co sekundę.

Zmierzone wyniki:
- `cve-37309-vuln` (5.7.1, port 4200): 100/100 renegocjacji przyjęte, CPU
  skacze z ~0.5% do 17-38% w trakcie ataku.
- `cve-37309-patched` (5.7.2, port 4201): serwer odrzuca pierwszą renegocjację
  alertem `handshake failure`, CPU zostaje płaskie (~0.3-1%).

Czysty, przekonujący kontrast przed/po.

### 3. CVE-2025-66491 (Traefik): działa end to end

Klaster k3d (`tls-poc`, bez wbudowanego Traefika z k3s, `--k3s-arg
"--disable=traefik@server:0"`). Manifesty w `manifests/`:
- Namespace `tls-poc`.
- Backend HTTPS: nginx z certyfikatem `untrusted.crt`/`untrusted.key` (self-signed,
  NIE podpisany naszym CA, dokładnie rogue-backend do tego scenariusza).
- RBAC (ServiceAccount + ClusterRole + ClusterRoleBinding) do watchowania
  Ingress/Service/Secret itd.
- Dwa Deploymenty Traefika: `traefik-vuln` (image `traefik:v3.6.2`) i
  `traefik-patched` (image `traefik:v3.6.4` — `v3.6.3` zniknęło z Docker Hub, ale
  3.6.4 ma ten sam fix). Oba z flagami
  `--experimental.kubernetesingressnginx=true --providers.kubernetesingressnginx=true
  --providers.kubernetesingressnginx.ingressclass=nginx`.
- IngressClass `nginx` + Ingress z adnotacjami
  `nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"` i
  `nginx.ingress.kubernetes.io/proxy-ssl-verify: "on"`.

`run-poc.sh` tworzy klaster (albo reużywa istniejący), aplikuje manifesty,
portforwarduje obie wersje Traefika i strzela curlem z `Host: backend.local`.

Zmierzone wyniki:
- Vulnerable (3.6.2): `200 OK`, treść backendu dostaje się przez, czyli
  weryfikacja certu faktycznie wyłączona mimo `proxy-ssl-verify: "on"`.
- Patched (3.6.4): `500 Internal Server Error`, w logach Traefika
  `tls: failed to verify certificate: x509: ...` — realna weryfikacja certyfikatu
  faktycznie zachodzi i odrzuca rogue backend.

Bug w kodzie Traefika potwierdzony z commita naprawczego (`pkg/provider/kubernetes/
ingress-nginx/kubernetes.go`, linia z `InsecureSkipVerify: strings.ToLower(...) ==
"on"` — dosłownie odwrócona logika).

## Jedna komenda na wszystko
```bash
cd ~/tls-vuln-poc
./demo.sh
```
Stawia (albo reużywa) wszystkie środowiska i odpala wszystkie trzy PoC po kolei,
z czytelnymi nagłówkami. Bezpieczne do wielokrotnego odpalania.

## Następne kroki, w kolejności
Wszystkie trzy PoC działają end to end (podatna przechodzi, załatana blokuje).
Zostało: zrobić screenshoty/output z każdego demo na potrzeby raportu.

## Decyzja użytkownika z 2026-10-21
Zapytany, jak kontynuować przy zablokowanym PoC nginx, użytkownik wybrał dalsze
debugowanie dokładnego bypassu, czyli nie przechodzić na razie do CrateDB/Traefik i
nie akceptować wersji "wskaźnikowej" jak publiczny skaner. Potem, pod presją czasu
(spotkanie o 17:45), priorytet przesunięto na to, żeby wszystkie trzy środowiska
stały i akceptowały TLS, bo to jest wymóg na Meeting #1 (slajd 8); pełne odtworzenie
exploitu zostaje na Meeting #2.
