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

### 1. CVE-2025-23419 (nginx): środowisko działa, dokładny bypass jeszcze nie odtworzony

Infrastruktura działa: `docker compose up -d` w `cve-2025-23419-nginx/` stawia oba
kontenery (`cve-23419-vuln` na 8443, `cve-23419-patched` na 9443), oba przyjmują TLS.

Aktualna konfiguracja `nginx.conf` (druga wersja, poprawiona pod realne preconditions
z advisory, ale bypass mimo to jeszcze nie przechodzi):
- `secure.local` to default_server, `ssl_verify_client on` (wymaga certu klienta).
- `public.local` to zwykły named vhost, bez wymogu certu.
- `ssl_protocols TLSv1.3;` jest wymagane: advisory nginx mówi wyraźnie, że bug dotyczy
  TLSv1.3, nie TLSv1.2. Pierwsza wersja configu używała TLSv1.2 i to był błąd.
- `ssl_session_tickets on;` plus `ssl_session_cache shared:SSL:10m;`.

Dokładny mechanizm bugu, zweryfikowany z realnego fix commitu nginx (hash 13935cf,
"SNI: added restriction for TLSv1.3 cross-SNI session resumption"):
- Fix dodaje w `ngx_http_ssl_servername()` sprawdzenie: jeśli `ssl_verify_client` jest
  włączone dla server blocku wybranego przez SNI, nginx odczytuje hostname zapisany
  w wznawianej sesji (`SSL_SESSION_get0_hostname()`), i jeśli różni się od aktualnie
  żądanego SNI, handshake jest odrzucany (`handshake_rejected=1`, `SSL_AD_ACCESS_DENIED`).
- W wersji przed fixem to porównanie nie istnieje, więc teoretycznie nic nie blokuje
  wznowienia sesji otwartej pod SNI=public.local (bez certu) z nowym żądaniem o
  SNI=secure.local (z certem).
- Precondition z Red Hat / GitHub advisory GHSA-84xh-pwc6-7g4g: default server musi
  wymagać client-cert auth, stąd `secure.local` jako default_server w configu.
- Ważny szczegół z komentarza w commicie: przy TLSv1.3 OpenSSL wznawia sesję w domyślnym
  kontekście SSL przed wywołaniem callbacka SNI, czyli resumption dzieje się przed
  wyborem kontekstu po SNI.

Co już wypróbowane i nie zadziałało (ciągle 400 lub 421, na obu wersjach):
1. Pierwsza, błędna wersja configu: TLSv1.2, `public.local` jako default_server bez
   certu, `secure.local` jako named vhost z certem, resume z `-servername secure.local`.
   Wynik: `421 Misdirected Request` na obu wersjach. To inny, starszy mechanizm nginx,
   ochrona przed HTTP/2 connection coalescing z 2016, niezwiązany z tym CVE (zmiana
   changeset 6556 autorstwa Valentina Bartenev, "closes #848").
2. Po poprawce (TLSv1.3, `secure.local` jako default_server z certem, `public.local`
   jako named bez certu): resume bez SNI (`-servername` całkiem pominięte). Wynik:
   `400 No required SSL certificate was sent` na wersji podatnej (8443). Bez SNI nginx
   i tak wymusza weryfikację certu na default_server, prawdopodobnie bo bez SNI nie
   wywołuje się callback `ngx_http_ssl_servername`, więc używany jest domyślny SSL_CTX,
   który już ma `verify_client on` ustawione na starcie dla tego listen socketu.
3. Resume z explicit `-servername secure.local` (różne od oryginalnego SNI=public.local
   użytego przy tworzeniu sesji). Wynik: też `400 No required SSL certificate was sent`,
   na wersji podatnej (8443). Czyli nawet w scenariuszu teoretycznie dokładnie
   odpowiadającym opisowi z fix commitu, bypass nie udał się przez plain
   `openssl s_client -sess_in/-sess_out`.

Hipoteza czemu (3) nie działa, do zweryfikowania w następnej sesji:
- Możliwe, że `ssl_verify_client on` razem z `SSL_VERIFY_FAIL_IF_NO_PEER_CERT` w
  OpenSSL wymusza błąd "no peer cert" na poziomie post-handshake niezależnie od tego,
  czy nginx-owy bug w SNI routing pozwolił requestowi przejść. Czyli błąd 400 może być
  generowany przez samo OpenSSL/nginx na podstawie faktycznej nieobecności certu
  klienta w handshake, a nie przez dodatkowy check z fix commitu. W takim razie realny
  bypass wymagałby czegoś subtelniejszego niż `s_client -sess_in`, na przykład:
  - `ssl_verify_client optional` plus własny check w `location`
    (`if ($ssl_client_verify != SUCCESS) return 403;`), żeby zobaczyć różnicę między
    "handshake succeeded mimo braku certu" i "HTTP layer check go złapał";
  - TLS 1.3 session ticket (PSK) resumption z explicit `early_data` / 0-RTT, bo to
    może iść inną ścieżką kodu;
  - sprawdzenie dokładnej wersji OpenSSL w obrazie (`docker exec cve-23419-vuln
    nginx -V`), bo obraz bazowy może mieć OpenSSL już spatchowany niezależnie od
    wersji nginx;
  - mini-klient TLS w Pythonie (moduł `ssl`, `SSLContext.wrap_socket` z `session=`
    z poprzedniego połączenia) zamiast `openssl s_client`, bo s_client może się
    zachowywać nietypowo przy 0-RTT/PSK;
  - sprawdzenie logów nginx podczas ataku (`docker logs cve-23419-vuln`), żeby
    zobaczyć na jakim etapie żądanie zostaje odrzucone.
- Publiczne repo PoC `harley-ghostie/safe-check-CVE-2025-23419` okazało się
  heurystycznym skanerem (sprawdza Server header, obecność mTLS i tak dalej), nie
  realnym exploitem. Nie dało konkretnej recepty na sam atak.

Komenda do podniesienia środowiska od zera:
```bash
cd ~/tls-vuln-poc/cve-2025-23419-nginx
docker compose up -d
./run-poc.sh 8443   # atak na podatną wersję
./run-poc.sh 9443   # to samo na załatanej, powinno się nie udać
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
1. Dokończyć CVE-2025-23419: zdebugować dlaczego bypass się nie reprodukuje mimo
   configu zgodnego z preconditions (patrz hipotezy wyżej). To jedyny z trzech,
   który jeszcze nie daje efektu "podatna = przechodzi, załatana = blokuje".
2. Zrobić screenshoty/output z każdego demo na potrzeby raportu.

## Decyzja użytkownika z 2026-10-21
Zapytany, jak kontynuować przy zablokowanym PoC nginx, użytkownik wybrał dalsze
debugowanie dokładnego bypassu, czyli nie przechodzić na razie do CrateDB/Traefik i
nie akceptować wersji "wskaźnikowej" jak publiczny skaner. Potem, pod presją czasu
(spotkanie o 17:45), priorytet przesunięto na to, żeby wszystkie trzy środowiska
stały i akceptowały TLS, bo to jest wymóg na Meeting #1 (slajd 8); pełne odtworzenie
exploitu zostaje na Meeting #2.
