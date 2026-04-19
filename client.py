"""
client.py — Chat odjemalec za vse faze (1–7)

Poženi:
  Faza 1:  python3 client.py --name Alice --phase 1
  Faza 2:  python3 client.py --name Alice --phase 2 --long-term-key longterm.key
  Faza 3:  python3 client.py --name Alice --phase 3 --ca ca_public.pem
  Faza 4:  python3 client.py --name Alice --phase 4 --ca ca_public.pem
  Faza 5:  python3 client.py --name Alice --phase 5 --ca ca_public.pem
           (strežnik mora imeti Alicin certifikat — zahteva --client-cert)
  Faza 6:  python3 client.py --name Alice --phase 6 --ca ca_public.pem
  Faza 7:  python3 client.py --name Alice --phase 7 --ca ca_public.pem
"""
import socket, threading, json, argparse, sys, time, os
sys.path.insert(0, os.path.dirname(__file__))
import dh as DH

R = "\033[0m"
def col(c, t): return f"\033[{c}m{t}{R}"
SYS  = lambda t: col(90, t)
RECV = lambda t: col(94, t)
ME   = lambda t: col(92, t)
WARN = lambda t: col(91, t)
OK   = lambda t: col(92, t)
PFS  = lambda t: col(95, t)

PHASE_DESC = {
    1: "Osnoven DH, brez overjanja         ← MITM deluje",
    2: "DH + HMAC podpis ključev           ← MITM še deluje!",
    3: "DH + CA certifikat                 ← MITM blokiran",
    4: "PFS — efemerni ključi              ← pretekle seje varne",
    5: "mTLS — vzajemna avtentikacija      ← strežnik te preveri",
    6: "Nonce + sekvenčna zaščita          ← replay blokiran",
    7: "Vse skupaj                         ← celovita zaščita",
}

class ChatClient:
    def __init__(self, name, host, port, phase,
                 ca_pem=None, long_term_key=None, client_cert=None):
        self.name           = name
        self.host           = host
        self.port           = port
        self.phase          = phase
        self.ca_pem         = ca_pem
        self.long_term_key  = long_term_key
        self.client_cert    = client_cert   # za mTLS (faza 5, 7)
        self.sock           = None
        self.key            = None
        self.guard          = None
        self.seq            = 0
        self.running        = False

        # DH ključ par
        self.my_priv, self.my_pub = DH.new_keypair()
        self.my_pub_bytes = DH.pub_to_bytes(self.my_pub)

    # ── Handshake po fazah ────────────────────────────────────────────────────

    def _hs_phase1(self):
        """Faza 1: samo JOIN."""
        self._send_raw({"type": "join", "name": self.name})

    def _hs_phase2(self):
        """
        Faza 2: DH + HMAC podpis javnih ključev.

        RAZLAGA RANLJIVOSTI:
        MITM prestrezе dh_hello in zamenja dh_pub z lastnim.
        Ker MITM pozna long_term_key (ga je prestrezel ali uganil),
        ustvari veljaven HMAC za lastni ključ.
        → Odjemalec misli da je HMAC veljaven ker long_term_key drži.
        → MITM je vmes.

        ZAKAJ HMAC NE REŠI PROBLEMA:
        HMAC dokazuje da sporočilo ni bilo MODIFICIRANO,
        ne dokazuje KDO ga je poslal — to zahteva asimetrično kriptografijo (CA).
        """
        print(SYS("  [HMAC] Podpisujem javni ključ z dolgoročnim ključem..."))
        sig = DH.sign_pub_key(self.long_term_key, self.my_pub_bytes, self.name)
        self._send_raw({
            "type":   "dh_hello_hmac",
            "name":   self.name,
            "dh_pub": self.my_pub_bytes.hex(),
            "sig":    sig
        })

        reply = json.loads(self._recv_line())
        assert reply["type"] == "dh_reply_hmac"

        # Preveri HMAC strežnikovega ključa
        srv_pub_bytes = bytes.fromhex(reply["dh_pub"])
        if not DH.verify_pub_key(self.long_term_key, srv_pub_bytes, "ChatServer", reply["sig"]):
            raise Exception("HMAC strežnikovega ključa ni veljaven!")
        print(SYS("  [HMAC] Strežnikov podpis ključa veljaven"))

        srv_pub  = DH.pub_from_bytes(srv_pub_bytes)
        self.key = DH.compute_shared_secret(self.my_priv, srv_pub)
        print(SYS(f"  [DH] Skupna skrivnost: {self.key.hex()[:16]}...\n"))

    def _hs_phase3_plus(self):
        """
        Faza 3, 4, 5, 6, 7: DH + CA certifikat.

        Faza 4 (PFS): strežnik pošlje EFEMERNI ključ (nov za to sejo).
                      Odjemalec to vidi v certifikatu — vsaka seja drugačen ključ.

        Faza 5 (mTLS): strežnik zahteva odjemalčev certifikat.
                       Odjemalec pošlje client_cert.

        Faza 6 (replay): po handshaku aktivira ReplayGuard.
        """
        print(SYS("  [DH] Pošiljam javni ključ strežniku..."))
        self._send_raw({
            "type":   "dh_hello",
            "name":   self.name,
            "dh_pub": self.my_pub_bytes.hex()
        })

        reply = json.loads(self._recv_line())
        assert reply["type"] == "dh_reply"

        # Preveri certifikat strežnika
        cert = reply.get("cert")
        if not cert:
            raise Exception("Strežnik ni poslal certifikata!")

        verifier = DH.ca_from_pub_pem(self.ca_pem)
        print(SYS(f"  [CA] Preverjam certifikat za '{cert['identity']}'..."))
        if not verifier.verify(cert):
            raise Exception(
                "CERTIFIKAT NI VELJAVEN!\n"
                "  Možen MITM — napadalec ne more ponarediti CA podpisa.\n"
                "  Prekinjam brez pošiljanja podatkov."
            )

        # Preveri da certifikat vsebuje TA ključ (ne podtaknjenega)
        if cert["dh_pub"] != reply["dh_pub"]:
            raise Exception("DH ključ se ne ujema s certifikatom — MITM!")

        print(OK(f"  [CA] ✓ Certifikat veljaven"))

        if self.phase == 4:
            print(PFS("  [PFS] Strežnik je poslal EFEMERNI ključ za to sejo"))
            print(PFS("       → Če napadalec pozneje ukrade statični ključ, ta seja ostane varna"))

        # mTLS: pošlji odjemalčev certifikat če strežnik zahteva
        if reply.get("require_client_cert"):
            if not self.client_cert:
                raise Exception("Strežnik zahteva mTLS certifikat, a ga nimamo!")
            print(SYS("  [mTLS] Strežnik zahteva moj certifikat — pošiljam..."))
            self._send_raw({"type": "client_cert", "cert": self.client_cert})
            print(OK("  [mTLS] ✓ Certifikat poslan"))

        srv_pub  = DH.pub_from_bytes(bytes.fromhex(reply["dh_pub"]))
        self.key = DH.compute_shared_secret(self.my_priv, srv_pub)
        print(SYS(f"  [DH] Skupna skrivnost: {self.key.hex()[:16]}...\n"))

        # Replay guard (fazi 6 in 7)
        if self.phase in (6, 7):
            self.guard = DH.ReplayGuard()
            print(SYS("  [Replay] Zaščita pred replay napadi aktivna"))

    def _handshake(self):
        if self.phase == 1:   self._hs_phase1()
        elif self.phase == 2: self._hs_phase2()
        else:                 self._hs_phase3_plus()

    # ── Pošiljanje / sprejemanje ──────────────────────────────────────────────

    def _send_raw(self, obj):
        self.sock.sendall((json.dumps(obj) + "\n").encode())

    def _recv_line(self) -> str:
        buf = ""
        while "\n" not in buf:
            buf += self.sock.recv(4096).decode()
        return buf.split("\n")[0]

    def send_msg(self, text):
        if self.guard and self.key:
            # Faza 6/7: zaščiten paket
            pkt = self.guard.make_packet(self.key, text, self.seq)
            self.seq += 1
            self._send_raw(pkt)
        elif self.key:
            self._send_raw({
                "type":      "msg",
                "text":      DH.encrypt(self.key, text),
                "encrypted": True
            })
        else:
            self._send_raw({"type": "msg", "text": text})

    def recv_loop(self):
        buf = ""
        while self.running:
            try:
                chunk = self.sock.recv(4096).decode()
                if not chunk: break
                buf += chunk
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    if not line.strip(): continue
                    pkt = json.loads(line)

                    if pkt["type"] == "sys":
                        print(SYS(f"\n  *** {pkt['text']} ***"))
                    elif pkt["type"] == "error":
                        print(WARN(f"\n  [!] Strežnik: {pkt['text']}"))
                    elif pkt["type"] == "msg":
                        text = pkt["text"]
                        if pkt.get("encrypted") and self.key:
                            try: text, _ = DH.decrypt(self.key, text)
                            except: pass
                        ts = pkt.get("ts", "")
                        print(RECV(f"\n  [{ts}] {pkt['from']}: {text}"))

                    print(ME(f"  {self.name}> "), end="", flush=True)
            except: break

    # ── Zagon ─────────────────────────────────────────────────────────────────

    def run(self):
        print(f"""
  ╔══════════════════════════════════════════════════╗
  ║  CHAT ODJEMALEC  —  {self.name:<20}      ║
  ║  Faza {self.phase}: {PHASE_DESC[self.phase]:<42} ║
  ╚══════════════════════════════════════════════════╝
  Povezujem se na {self.host}:{self.port}...
""")
        self.sock = socket.socket()
        try:
            self.sock.connect((self.host, self.port))
        except Exception as e:
            print(WARN(f"  [!] Ne morem se povezati: {e}")); sys.exit(1)

        try:
            self._handshake()
        except Exception as e:
            print(WARN(f"\n  [!] Varnostna napaka: {e}"))
            self.sock.close(); sys.exit(1)

        self.running = True
        threading.Thread(target=self.recv_loop, daemon=True).start()
        time.sleep(0.3)
        print(ME(f"  {self.name}> "), end="", flush=True)

        try:
            while self.running:
                line = input()
                if line.strip() == "/quit":
                    self._send_raw({"type": "quit"}); break
                if line.strip():
                    self.send_msg(line.strip())
                    print(ME(f"  {self.name}> "), end="", flush=True)
        except (KeyboardInterrupt, EOFError): pass

        self.running = False
        self.sock.close()
        print(SYS("\n  [odjavljen]"))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--name",            required=True)
    ap.add_argument("--host",            default="127.0.0.1")
    ap.add_argument("--port",            type=int, default=9000)
    ap.add_argument("--phase",           type=int, default=1, choices=range(1, 8))
    ap.add_argument("--ca",              default="ca_public.pem")
    ap.add_argument("--long-term-key",   default="longterm.key")
    ap.add_argument("--register-cert",   action="store_true",
                    help="Registriraj se pri CA in pridobi certifikat (za mTLS)")
    args = ap.parse_args()

    ca_pem        = None
    long_term_key = None
    client_cert   = None

    if args.phase in (3, 4, 5, 6, 7):
        if not os.path.exists(args.ca):
            print(WARN(f"[!] CA ključ '{args.ca}' ne obstaja. Najprej poženi strežnik."))
            sys.exit(1)
        with open(args.ca, "rb") as f:
            ca_pem = f.read()

    if args.phase == 2:
        if not os.path.exists(args.long_term_key):
            print(WARN(f"[!] Dolgoročni ključ '{args.long_term_key}' ne obstaja."))
            sys.exit(1)
        with open(args.long_term_key, "rb") as f:
            long_term_key = f.read()

    if args.phase in (5, 7):
        # Za mTLS: ustvari odjemalčev certifikat
        # V praksi bi CA odjemalcu izdala certifikat po preverjanju identitete
        # Tu simuliramo: odjemalec ima CA javni ključ in strežnik mu izda certifikat
        cert_file = f"{args.name.lower()}_cert.json"
        if os.path.exists(cert_file):
            import json as _json
            with open(cert_file) as f:
                client_cert = _json.load(f)
            print(SYS(f"  [mTLS] Naložen certifikat iz '{cert_file}'"))
        else:
            print(WARN(f"  [mTLS] Certifikat '{cert_file}' ne obstaja."))
            print(WARN(f"         Poženi: python3 issue_client_cert.py --name {args.name}"))
            sys.exit(1)

    ChatClient(args.name, args.host, args.port, args.phase,
               ca_pem, long_term_key, client_cert).run()
