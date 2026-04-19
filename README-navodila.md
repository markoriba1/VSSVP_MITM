# MITM Chat Demo — Diffie-Hellman, vse faze (1–7)

## Datoteke
```
dh.py                  Skupni kriptografski primitivi
server.py              Strežnik (faze 1–7)
client.py              Odjemalec (faze 1–7)
mitm.py                MITM proxy (faze 1–7)
issue_client_cert.py   Izda certifikat odjemalcu (za mTLS)
```

## Namestitev
```bash
pip install cryptography
```

---

## FAZA 1 — Osnoven DH, brez overjanja

**Ranljivost:** MITM zamenja javne ključe. Alice in Bob imata skupno skrivnost
z napadalcem, ne med seboj. Napad je transparenten — žrtvi tega ne opazita.

```bash
python3 server.py --phase 1                              # T1
python3 mitm.py   --phase 1                              # T2
python3 client.py --name Alice --phase 1 --port 9001    # T3
python3 client.py --name Bob   --phase 1 --port 9001    # T4
```

---

## FAZA 2 — DH + HMAC podpis ključev

**Razlaga:** HMAC dokazuje *integriteto* (sporočilo ni bilo spremenjeno),
ne *identitete* (kdo je ključ ustvaril). Ker MITM pozna skupni `long_term_key`,
ustvari veljavne HMAC-e za lastne ključe. To je "key distribution problem" —
rešitev so certifikati (CA).

```bash
python3 server.py --phase 2                              # T1 (generira longterm.key)
python3 mitm.py   --phase 2                              # T2 (naloži longterm.key)
python3 client.py --name Alice --phase 2 --port 9001    # T3
```

---

## FAZA 3 — DH + CA certifikat

**Zaščita:** Strežnik ima CA-podpisan certifikat. Odjemalec preveri podpis —
MITM ne more ponarediti certifikata brez CA privatnega ključa.

```bash
python3 server.py --phase 3                              # T1 (generira ca_public.pem)
python3 mitm.py   --phase 3                              # T2 (bo blokiran)
python3 client.py --name Alice --phase 3 --port 9001 --ca ca_public.pem  # T3 → ZAVRNJEN
python3 client.py --name Alice --phase 3 --port 9000 --ca ca_public.pem  # T3 → DELUJE
```

---

## FAZA 4 — PFS (Perfect Forward Secrecy)

**Razlaga:** Strežnik generira nov DH ključ za VSAKO sejo. Ključ se po
koncu seje zavrže. Posledica: če napadalec pozneje ukrade strežnikov ključ,
ne more dešifrirati posnetih preteklih sej.

**Pomembno:** PFS ne pomaga pri aktivnem MITM napadu — certifikat ga blokira
v obeh fazah (3 in 4). PFS ščiti pred *pasivnim* napadalcem ki snema promet
in pozneje pridobi ključe.

```bash
python3 server.py --phase 4                              # T1
python3 mitm.py   --phase 4                              # T2 (blokiran — certifikat)
python3 client.py --name Alice --phase 4 --port 9000 --ca ca_public.pem
```

Opazuj v T1: "Efemerni zasebni ključ ZAVRŽEN" po vsaki seji.

---

## FAZA 5 — mTLS (vzajemna avtentikacija)

**Razlaga:** Normalno samo odjemalec preveri strežnikov certifikat.
Pri mTLS strežnik prav tako preveri *odjemalčev* certifikat.
Odjemalec brez veljavnega certifikata je zavrnjen.

```bash
python3 server.py --phase 5                              # T1

# Izda certifikata za Alice in Bob
python3 issue_client_cert.py --name Alice
python3 issue_client_cert.py --name Bob

python3 mitm.py   --phase 5                              # T2 (blokiran)
python3 client.py --name Alice --phase 5 --port 9000 --ca ca_public.pem  # T3 ✓
python3 client.py --name Bob   --phase 5 --port 9000 --ca ca_public.pem  # T4 ✓
```

---

## FAZA 6 — Nonce + sekvenčna zaščita (anti-replay)

**Razlaga:** Brez zaščite bi napadalec lahko:
1. Posnel šifriran paket "Nakaži 1000€"
2. Ga poslal 10x → 10x nakazilo

Zaščita: vsak paket ima unikatni nonce + sekvenčno številko + timestamp.
Strežnik zavrne vsak duplikat ali paket izven okna.

```bash
python3 server.py --phase 6                              # T1
python3 client.py --name Alice --phase 6 --port 9000 --ca ca_public.pem
```

V dh.py si oglej `ReplayGuard.check()` — tam se zgodijo vse tri preveritve.

---

## FAZA 7 — Vse skupaj

```bash
python3 server.py --phase 7                              # T1
python3 issue_client_cert.py --name Alice
python3 issue_client_cert.py --name Bob
python3 client.py --name Alice --phase 7 --port 9000 --ca ca_public.pem
python3 client.py --name Bob   --phase 7 --port 9000 --ca ca_public.pem
```

---

## Primerjalna tabela

| Faza | DH | Overjanje | PFS | mTLS | Anti-replay | MITM |
|------|----|-----------|-----|------|-------------|------|
| 1    | ✓  | —         | —   | —    | —           | ✓ deluje |
| 2    | ✓  | HMAC      | —   | —    | —           | ✓ deluje (key distribution) |
| 3    | ✓  | CA cert   | —   | —    | —           | ✗ blokiran |
| 4    | ✓  | CA cert   | ✓   | —    | —           | ✗ blokiran + PFS zaščita |
| 5    | ✓  | CA cert   | —   | ✓    | —           | ✗ blokiran + identiteta odjemalca |
| 6    | ✓  | CA cert   | —   | —    | ✓           | ✗ blokiran + replay zaščita |
| 7    | ✓  | CA cert   | ✓   | ✓    | ✓           | ✗ blokiran na vsakem koraku |
