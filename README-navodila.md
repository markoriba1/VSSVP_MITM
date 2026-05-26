# MITM Chat Demo — Diffie-Hellman (faze 1–7)

## Datoteke
```
dh.py                  Kriptografski primitivi
server.py              Strežnik (faze 1–7)
client.py              Odjemalec (faze 1–7)
mitm.py                MITM proxy (faze 1–7)
issue_client_cert.py   Izda certifikat odjemalcu (mTLS)
```

## Namestitev
```bash
pip install cryptography
```

## Splošen vzorec (velja za VSE faze)

```
Alice (port 9000) ──────────────────────→ Strežnik
Bob   (port 9001) ──→ MITM ──→ (9000) ──→ Strežnik
```

- Strežnik posluša na **obeh** portih (9000 in 9001)
- Alice se poveže direktno na 9000
- Bob se poveže na 9001 — misli da je strežnik, a je MITM
- MITM posreduje Bobov promet na pravi strežnik (9000)

---

## FAZA 1 — Plaintext (napad deluje)

```bash
python3 server.py --phase 1 --port 9000 --extra-ports 9001
python3 mitm.py   --phase 1 --listen-port 9001 --server-port 9000
python3 client.py --name Alice --phase 1 --port 9000
python3 client.py --name Bob   --phase 1 --port 9001
```

MITM vidi vsa Bobova sporočila v plaintext.

---

## FAZA 2 — DH + HMAC (napad še deluje)

```bash
python3 server.py --phase 2 --port 9000 --extra-ports 9001
python3 mitm.py   --phase 2 --listen-port 9001 --server-port 9000
python3 client.py --name Alice --phase 2 --port 9000 --long-term-key longterm.key
python3 client.py --name Bob   --phase 2 --port 9001 --long-term-key longterm.key
```

MITM pozna long_term_key → ustvari veljavne HMAC-e → bere šifrirano.

---

## FAZA 3 — DH + CA certifikat (MITM blokiran)

```bash
python3 server.py --phase 3 --port 9000 --extra-ports 9001
python3 mitm.py   --phase 3 --listen-port 9001 --server-port 9000
python3 client.py --name Alice --phase 3 --port 9000 --ca ca_public.pem
python3 client.py --name Bob   --phase 3 --port 9001 --ca ca_public.pem
```

Bob preveri certifikat → MITM ne more ponarediti CA podpisa → zavrnjen.

---

## FAZA 4 — PFS (MITM blokiran + pretekle seje varne)

```bash
python3 server.py --phase 4 --port 9000 --extra-ports 9001
python3 mitm.py   --phase 4 --listen-port 9001 --server-port 9000
python3 client.py --name Alice --phase 4 --port 9000 --ca ca_public.pem
python3 client.py --name Bob   --phase 4 --port 9001 --ca ca_public.pem
```

Vsaka seja ima unikaten efemerni ključ ki se zavrže — pretekle seje varne.

---

## FAZA 5 — mTLS (MITM blokiran + odjemalec preverjen)

```bash
# 1. PRVIČ — generiraj CA ključe
python3 server.py --phase 5 --port 9000 --extra-ports 9001
# ustavi z Ctrl+C

# 2. Izda certifikate (samo enkrat)
python3 issue_client_cert.py --name Alice
python3 issue_client_cert.py --name Bob

# 3. Od zdaj naprej — strežnik vedno naloži isti CA ključ
python3 server.py --phase 5 --port 9000 --extra-ports 9001
python3 client.py --name Alice --phase 5 --port 9000 --ca ca_public.pem
python3 client.py --name Bob   --phase 5 --port 9001 --ca ca_public.pem
```

Strežnik preveri certifikat odjemalca — brez veljavnega certifikata zavrnjen.

---

## FAZA 6 — Anti-replay (MITM blokiran + replay zaščita)

```bash
python3 server.py --phase 6 --port 9000 --extra-ports 9001
python3 mitm.py   --phase 6 --listen-port 9001 --server-port 9000
python3 client.py --name Alice --phase 6 --port 9000 --ca ca_public.pem
python3 client.py --name Bob   --phase 6 --port 9001 --ca ca_public.pem
```

Vsak paket ima nonce + seq + timestamp — duplikati zavrnjeni.

---

## FAZA 7 — Vse skupaj

```bash
python3 server.py --phase 7 --port 9000 --extra-ports 9001
python3 issue_client_cert.py --name Alice
python3 issue_client_cert.py --name Bob
python3 mitm.py   --phase 7 --listen-port 9001 --server-port 9000
python3 client.py --name Alice --phase 7 --port 9000 --ca ca_public.pem
python3 client.py --name Bob   --phase 7 --port 9001 --ca ca_public.pem
```

---

## Primerjalna tabela

| Faza | DH | Overjanje | PFS | mTLS | Anti-replay | MITM |
|------|----|-----------|-----|------|-------------|------|
| 1    | —  | —         | —   | —    | —           | deluje |
| 2    | ✓  | HMAC      | —   | —    | —           | deluje |
| 3    | ✓  | CA cert   | —   | —    | —           | blokiran |
| 4    | ✓  | CA cert   | ✓   | —    | —           | blokiran |
| 5    | ✓  | CA cert   | —   | ✓    | —           | blokiran |
| 6    | ✓  | CA cert   | —   | —    | ✓           | blokiran |
| 7    | ✓  | CA cert   | ✓   | ✓    | ✓           | blokiran |

## Opomba — fazi 1 in 2 brez MITM

Če hočeš videti normalno komunikacijo brez napadalca:
```bash
python3 server.py --phase 1 --port 9000
python3 client.py --name Alice --phase 1 --port 9000
python3 client.py --name Bob   --phase 1 --port 9000
```