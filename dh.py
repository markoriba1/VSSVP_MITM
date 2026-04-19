"""
dh.py — Diffie-Hellman primitivi za vse faze (1–7)

Faze:
  1  Osnoven DH, brez overjanja          → MITM zamenja ključe, bere vse
  2  DH + HMAC podpis ključev            → zakaj to ne zadostuje?
  3  DH + CA certifikat                  → overjanje identitete
  4  PFS — efemerni ključi               → pretekle seje varne tudi po vdoru
  5  mTLS — vzajemna avtentikacija       → strežnik preveri odjemalca
  6  Nonce + sekvenčna zaščita           → preprečuje replay napade
  7  Vse skupaj                          → celovita zaščita

Opomba o kriptografiji:
  - DH izmenjava:   za vzpostavitev skupne skrivnosti
  - RSA podpisi:    samo za podpisovanje certifikatov (ne za šifriranje!)
  - HKDF:           za derivacijo ključev iz DH skrivnosti
  - HMAC-SHA256:    za overjanje sporočil in ključev
  - XOR + nonce:    poenostavljeno šifriranje za demo (v praksi AES-GCM)
"""
import os, hmac as _hmac, hashlib, json, time, struct
from cryptography.hazmat.primitives.asymmetric.dh import generate_parameters
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ═══════════════════════════════════════════════════════════════════════════════
# DH PARAMETRI — skupni za vse procese
# ═══════════════════════════════════════════════════════════════════════════════
_PARAMS_FILE = os.path.join(os.path.dirname(__file__), "dh_params.pem")

def _load_or_generate_params():
    from cryptography.hazmat.primitives.serialization import (
        Encoding, ParameterFormat, load_pem_parameters
    )
    if os.path.exists(_PARAMS_FILE):
        with open(_PARAMS_FILE, "rb") as f:
            params = load_pem_parameters(f.read(), backend=default_backend())
        print(f"[DH] Parametri naloženi iz {_PARAMS_FILE}")
        return params
    print("[DH] Generiram parametre (g, p) ... ", end="", flush=True)
    params = generate_parameters(generator=2, key_size=512, backend=default_backend())
    pem = params.parameter_bytes(
        serialization.Encoding.PEM,
        serialization.ParameterFormat.PKCS3
    )
    with open(_PARAMS_FILE, "wb") as f:
        f.write(pem)
    print(f"OK  → {_PARAMS_FILE}")
    return params

DH_PARAMS = _load_or_generate_params()

# ═══════════════════════════════════════════════════════════════════════════════
# OSNOVE: ključi, skupna skrivnost
# ═══════════════════════════════════════════════════════════════════════════════

def new_keypair():
    """
    Generiraj nov DH ključ par (zasebni, javni).

    V fazah 1–3 strežnik generira en par ob zagonu in ga uporablja za vse seje.
    V fazi 4 (PFS) se kliče za VSAKO sejo posebej — ključi se po koncu zavržejo.
    """
    priv = DH_PARAMS.generate_private_key()
    return priv, priv.public_key()

def pub_to_bytes(pub_key) -> bytes:
    return pub_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

def pub_from_bytes(data: bytes):
    return serialization.load_pem_public_key(data, backend=default_backend())

def compute_shared_secret(my_priv, their_pub, salt: bytes = None) -> bytes:
    """
    Izračunaj skupno skrivnost in jo deriviraj v 32-bajtni ključ (HKDF).

    HKDF (Hash-based Key Derivation Function) je pomemben korak:
    - Surovi DH izhod ni enakomerno porazdeljen → ni direktno uporaben kot ključ
    - HKDF "razpne" entropijo v kriptografsko varen ključ
    - Salt naredi derivacijo odvisno od seje (faza 6: nonce kot salt)
    """
    raw = my_priv.exchange(their_pub)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"mitm-chat-demo",
        backend=default_backend()
    ).derive(raw)

# ═══════════════════════════════════════════════════════════════════════════════
# ŠIFRIRANJE (poenostavljeno za demo)
# ═══════════════════════════════════════════════════════════════════════════════

def encrypt(key: bytes, plaintext: str, seq: int = None) -> str:
    """
    XOR šifriranje z naključnim nonce.

    V produkciji bi uporabili AES-GCM ki zagotavlja:
    - zaupnost (encryption)
    - integriteto (authentication tag)
    - zaščito pred replay (nonce/IV)

    seq (sequence number) je vključen v nonce za fazu 6.
    """
    nonce = os.urandom(12)
    if seq is not None:
        # Vključi sekvenčno številko v prvih 4 bajtih nonce
        nonce = struct.pack(">I", seq) + nonce[4:]
    pt  = plaintext.encode()
    pad = (nonce * (len(pt) // len(nonce) + 1))[:len(pt)]
    ct  = bytes(a ^ b for a, b in zip(pt, pad))
    return (nonce + ct).hex()

def decrypt(key: bytes, ciphertext_hex: str) -> tuple:
    """Vrne (plaintext, seq_or_None)."""
    raw   = bytes.fromhex(ciphertext_hex)
    nonce = raw[:12]
    ct    = raw[12:]
    pad   = (nonce * (len(ct) // len(nonce) + 1))[:len(ct)]
    pt    = bytes(a ^ b for a, b in zip(ct, pad)).decode()
    seq   = struct.unpack(">I", nonce[:4])[0]
    return pt, seq

# ═══════════════════════════════════════════════════════════════════════════════
# FAZA 2: HMAC podpis javnih ključev
# ═══════════════════════════════════════════════════════════════════════════════

def make_hmac(key: bytes, data: str) -> str:
    """
    HMAC-SHA256 — overi da sporočilo ni bilo spremenjeno.

    Problem pri fazi 2: HMAC ključ mora biti vnaprej izmenjan po varnem kanalu.
    Če ga izmenjamo po istem kanalu kot DH ključe → MITM ga prestrezе in
    ustvari veljavne HMAC-e za lastne ključe.

    To je "key distribution problem" — rešitev so certifikati (faza 3).
    """
    return _hmac.new(key, data.encode(), hashlib.sha256).hexdigest()

def verify_hmac(key: bytes, data: str, tag: str) -> bool:
    expected = make_hmac(key, data)
    return _hmac.compare_digest(expected, tag)

def sign_pub_key(long_term_key: bytes, pub_bytes: bytes, identity: str) -> str:
    """
    Faza 2: podpiši javni ključ z dolgoročnim skupnim ključem.

    Zakaj to še vedno ni dovolj:
    - Dolgoročni ključ morata Alice in Bob vnaprej izmenjati — toda kako?
    - Če ga izmenjata prek istega omrežja → MITM ga prestrezе
    - Potrebujemo zaupanja vredno tretjo stranko → CA (faza 3)
    """
    payload = f"{identity}::{pub_bytes.hex()}"
    return make_hmac(long_term_key, payload)

def verify_pub_key(long_term_key: bytes, pub_bytes: bytes, identity: str, sig: str) -> bool:
    payload = f"{identity}::{pub_bytes.hex()}"
    return verify_hmac(long_term_key, payload, sig)

# ═══════════════════════════════════════════════════════════════════════════════
# FAZA 3 + 5: CA in certifikati
# ═══════════════════════════════════════════════════════════════════════════════

class CA:
    """
    Certifikatna agencija — zaupanja vredna tretja stranka.

    Vloga CA:
    - Ima dolgoročni RSA ključ par
    - Njen javni ključ je "všit" v odjemalce (certificate pinning)
    - Podpisuje certifikate: "ta DH javni ključ PRIPADA tej identiteti"
    - Napadalec brez CA privatnega ključa ne more ustvariti veljavnega certifikata

    V fazi 3: strežnik ima CA-podpisan certifikat
    V fazi 5 (mTLS): tudi odjemalci imajo CA-podpisane certifikate
    """
    def __init__(self):
        self._key = rsa.generate_private_key(65537, 2048, default_backend())
        self.public_key = self._key.public_key()

    def sign(self, identity: str, dh_pub_bytes: bytes) -> dict:
        """
        Podpiši certifikat.

        Certifikat vsebuje:
        - identity: kdo je lastnik (npr. "ChatServer", "Alice")
        - dh_pub:   DH javni ključ lastnika
        - sig:      CA podpis nad (identity || dh_pub)

        Napadalec ne more ponarediti sig ker nima CA privatnega ključa.
        """
        payload = f"{identity}::{dh_pub_bytes.hex()}".encode()
        sig = self._key.sign(payload, PKCS1v15(), hashes.SHA256())
        return {
            "identity": identity,
            "dh_pub":   dh_pub_bytes.hex(),
            "sig":      sig.hex()
        }

    def verify(self, cert: dict) -> bool:
        payload = f"{cert['identity']}::{cert['dh_pub']}".encode()
        try:
            self.public_key.verify(
                bytes.fromhex(cert["sig"]), payload, PKCS1v15(), hashes.SHA256()
            )
            return True
        except:
            return False

    def pub_pem(self) -> bytes:
        return self.public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

class CAVerifier:
    """
    Odjemalčeva stran CA — samo javni ključ.

    Odjemalec ima "všit" (pinned) CA javni ključ:
    - Sprejme SAMO certifikate podpisane s tem CA
    - Lažen CA bi moral biti nameščen na odjemalčev sistem (zahteva malware/fizičen dostop)
    """
    def __init__(self, pub_pem: bytes):
        self._pub = serialization.load_pem_public_key(pub_pem, default_backend())

    def verify(self, cert: dict) -> bool:
        payload = f"{cert['identity']}::{cert['dh_pub']}".encode()
        try:
            self._pub.verify(
                bytes.fromhex(cert["sig"]), payload, PKCS1v15(), hashes.SHA256()
            )
            return True
        except:
            return False

def ca_from_pub_pem(pem: bytes) -> CAVerifier:
    return CAVerifier(pem)

# ═══════════════════════════════════════════════════════════════════════════════
# FAZA 6: NONCE + SEKVENČNA ZAŠČITA (replay prevention)
# ═══════════════════════════════════════════════════════════════════════════════

class ReplayGuard:
    """
    Zaščita pred replay napadi.

    Replay napad: napadalec posname šifrirane pakete in jih pozneje
    ponovno pošlje — npr. posname "Nakaži 1000€" in ga pošlje 10x.

    Zaščita:
    1. Nonce: vsak paket ima unikatni naključni nonce → isti paket dvakrat = zavrnjen
    2. Sekvenčna številka: paketi morajo prihajati v vrstnem redu
    3. Timestamp: paket starejši od okna (npr. 30s) je zavrnjen

    V produkciji TLS 1.3 uporablja sekvenčne številke + AEAD za zaščito pred replay.
    """
    def __init__(self, window_seconds: int = 30):
        self._seen_nonces: set = set()
        self._expected_seq: int = 0
        self._window = window_seconds
        self._lock = __import__('threading').Lock()

    def check(self, nonce: str, seq: int, timestamp: float) -> tuple[bool, str]:
        """
        Preveri paket. Vrne (ok, razlog_zavrnitve).
        """
        now = time.time()

        # 1. Preveri timestamp (zaščita pred zamrznjenimi replay napadi)
        age = now - timestamp
        if age > self._window:
            return False, f"Paket prestar: {age:.1f}s > {self._window}s okno"
        if age < -5:  # malo tolerance za uro
            return False, f"Paket iz prihodnosti: {age:.1f}s"

        with self._lock:
            # 2. Preveri nonce (zaščita pred enakim paketom)
            if nonce in self._seen_nonces:
                return False, f"Duplikat nonce — replay napad!"
            self._seen_nonces.add(nonce)

            # 3. Preveri sekvenčno številko
            if seq < self._expected_seq:
                return False, f"Sekvenčna številka {seq} < pričakovana {self._expected_seq}"
            self._expected_seq = seq + 1

        return True, "OK"

    def make_packet(self, key: bytes, text: str, seq: int) -> dict:
        """Ustvari zaščiten paket z nonce, seq in timestamp."""
        nonce     = os.urandom(16).hex()
        timestamp = time.time()
        ct        = encrypt(key, text, seq)
        # HMAC nad (nonce || seq || timestamp || ciphertext)
        mac_data  = f"{nonce}:{seq}:{timestamp:.3f}:{ct}"
        mac       = make_hmac(key, mac_data)
        return {
            "type":      "msg",
            "ct":        ct,
            "nonce":     nonce,
            "seq":       seq,
            "ts":        timestamp,
            "mac":       mac,
            "encrypted": True,
            "protected": True
        }

    def open_packet(self, key: bytes, pkt: dict) -> tuple[str, str]:
        """
        Odpri in preveri zaščiten paket.
        Vrne (plaintext, napaka_ali_None).
        """
        nonce = pkt["nonce"]
        seq   = pkt["seq"]
        ts    = pkt["ts"]
        ct    = pkt["ct"]
        mac   = pkt["mac"]

        # 1. Preveri HMAC (integriteta)
        mac_data = f"{nonce}:{seq}:{ts:.3f}:{ct}"
        if not verify_hmac(key, mac_data, mac):
            return None, "HMAC napaka — paket je bil spremenjen!"

        # 2. Preveri replay
        ok, reason = self.check(nonce, seq, ts)
        if not ok:
            return None, reason

        # 3. Dešifriraj
        try:
            plain, _ = decrypt(key, ct)
            return plain, None
        except Exception as e:
            return None, f"Napaka dešifriranja: {e}"
