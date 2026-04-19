"""
mitm.py — MITM proxy za vse faze (1–7)
Poženi: python3 mitm.py --phase <N> [--listen-port 9001] [--server-port 9000]

Prikazuje:
  Faza 1: bere plaintext
  Faza 2: prestrezе HMAC ključ in ponaredi podpise (zakaj HMAC ne zadostuje)
  Faza 3: blokiran — ne more ponarediti CA certifikata
  Faza 4: blokiran — PFS ga ne "odblokira", samo omeji škodo pri vdoru
  Faza 5: blokiran — ne more pridobiti odjemalčevega certifikata
  Faza 6: poskusi replay napad — blokiran z nonce/seq zaščito
  Faza 7: vse zaščite hkrati — blokiran na vsakem koraku
"""
import socket, threading, json, argparse, sys, os, time
from datetime import datetime
sys.path.insert(0, os.path.dirname(__file__))
import dh as DH

R = "\033[0m"
def col(c, t): return f"\033[{c}m{t}{R}"
INTERCEPT = lambda t: col(91, t)
BLOCKED   = lambda t: col(92, t)
WARN_C    = lambda t: col(93, t)
SYS_C     = lambda t: col(96, t)

class MITMProxy:
    def __init__(self, listen_host, listen_port, server_host, server_port, phase,
                 long_term_key=None):
        self.listen_host   = listen_host
        self.listen_port   = listen_port
        self.server_host   = server_host
        self.server_port   = server_port
        self.phase         = phase
        self.long_term_key = long_term_key  # za fazo 2
        self.intercepted   = []
        self.lock          = threading.Lock()

    def _ts(self): return datetime.now().strftime("%H:%M:%S")

    def _log(self, title, lines, color=INTERCEPT):
        ts = self._ts()
        print(color(f"\n  ╔══ [{ts}] {title}"))
        for l in lines:
            print(color(f"  ║  {l}"))
        print(color(f"  ╚{'═'*44}"))

    def _recv_line(self, sock) -> str:
        buf = ""
        while "\n" not in buf:
            c = sock.recv(4096).decode()
            if not c: raise ConnectionError()
            buf += c
        return buf.split("\n")[0]

    def _send(self, sock, obj):
        sock.sendall((json.dumps(obj) + "\n").encode())

    # ── Faza 1: plaintext ────────────────────────────────────────────────────
    def _handle_phase1(self, csock, ssock):
        name_ref = ["?"]
        def pipe(src, dst, direction):
            buf = ""
            while True:
                try:
                    chunk = src.recv(4096).decode()
                    if not chunk: break
                    buf += chunk
                    while "\n" in buf:
                        line, buf = buf.split("\n", 1)
                        if not line.strip(): continue
                        pkt = json.loads(line)
                        if pkt.get("type") == "join":
                            name_ref[0] = pkt.get("name", "?")
                        if pkt.get("type") == "msg" and direction == "C→S":
                            self._log("PRESTREZENO", [
                                f"Od: {name_ref[0]}",
                                f"Sporočilo: {pkt['text']}"
                            ])
                            with self.lock: self.intercepted.append(pkt['text'])
                        dst.sendall((line + "\n").encode())
                except: break
            try: src.close()
            except: pass
            try: dst.close()
            except: pass
        t1 = threading.Thread(target=pipe, args=(csock, ssock, "C→S"), daemon=True)
        t2 = threading.Thread(target=pipe, args=(ssock, csock, "S→C"), daemon=True)
        t1.start(); t2.start(); t1.join(); t2.join()

    # ── Faza 2: HMAC zamenjava ────────────────────────────────────────────────
    def _handle_phase2(self, csock, ssock):
        """
        MITM v fazi 2:

        Ker MITM pozna long_term_key (ga je prestrezel pri inicializaciji
        ali ga je pridobil drugače), lahko ustvari veljavne HMAC-e za
        lastne javne ključe.

        To razkrije temeljno slabost HMAC pristopa:
        HMAC dokazuje INTEGRITETO (sporočilo ni bilo spremenjeno),
        ne dokazuje IDENTITETE (kdo je ključ ustvaril).
        Za identiteto potrebujemo asimetrično kriptografijo → CA.
        """
        if not self.long_term_key:
            self._log("FAZA 2 MITM", ["Nimam long_term_key — posredujem brez prestrezanja"], WARN_C)
            self._plain_pipe(csock, ssock); return

        line = self._recv_line(csock)
        pkt  = json.loads(line)
        name = pkt.get("name", "?")

        self._log("DH HELLO + HMAC prestrezeno", [
            f"Od: {name}",
            f"Odjemalčev pub: {pkt['dh_pub'][:32]}...",
            f"HMAC podpis:    {pkt['sig'][:32]}...",
            f"Imam long_term_key → ustvarim lasten HMAC!",
        ])

        # Generiraj MITM ključ in podpiši z long_term_key
        mitm_priv_c, mitm_pub_c = DH.new_keypair()
        mitm_pub_c_bytes = DH.pub_to_bytes(mitm_pub_c)
        mitm_sig_c = DH.sign_pub_key(self.long_term_key, mitm_pub_c_bytes, name)

        client_pub = DH.pub_from_bytes(bytes.fromhex(pkt["dh_pub"]))

        # Pošlji strežniku MITM ključ z veljavnim HMAC
        self._send(ssock, {
            "type":   "dh_hello_hmac",
            "name":   name,
            "dh_pub": mitm_pub_c_bytes.hex(),
            "sig":    mitm_sig_c   # VELJAVEN HMAC za MITM ključ!
        })

        line2 = self._recv_line(ssock)
        reply = json.loads(line2)
        srv_pub = DH.pub_from_bytes(bytes.fromhex(reply["dh_pub"]))

        mitm_priv_s, mitm_pub_s = DH.new_keypair()
        mitm_pub_s_bytes = DH.pub_to_bytes(mitm_pub_s)
        mitm_sig_s = DH.sign_pub_key(self.long_term_key, mitm_pub_s_bytes, "ChatServer")

        self._send(csock, {
            "type":   "dh_reply_hmac",
            "dh_pub": mitm_pub_s_bytes.hex(),
            "sig":    mitm_sig_s
        })

        key_c = DH.compute_shared_secret(mitm_priv_s, client_pub)
        key_s = DH.compute_shared_secret(mitm_priv_c, srv_pub)

        self._log("HMAC NAPAD USPEŠEN", [
            f"Obe strani imata veljavne HMAC podpise!",
            f"Skupna skrivnost z odjemalcem: {key_c.hex()[:16]}...",
            f"Skupna skrivnost s strežnikom: {key_s.hex()[:16]}...",
            f"HMAC ne dokazuje IDENTITETE — samo integriteto!",
        ])

        self._dh_pipe(csock, ssock, key_c, key_s, name)

    # ── Faze 3–7: certifikat blokira ─────────────────────────────────────────
    def _handle_cert_phases(self, csock, ssock):
        """
        Za faze 3–7: MITM poskusi zamenjati DH ključe.
        Ker nima CA privatnega ključa, ne more ustvariti veljavnega certifikata.
        Odjemalec zavrne lažen certifikat.
        """
        line = self._recv_line(csock)
        pkt  = json.loads(line)
        name = pkt.get("name", "?")

        self._log(f"DH HELLO prestrezeno (faza {self.phase})", [
            f"Od: {name}",
            "Zamenjujem javni ključ z MITM ključem...",
        ])

        mitm_priv, mitm_pub = DH.new_keypair()
        mitm_pub_bytes = DH.pub_to_bytes(mitm_pub)

        self._send(ssock, {"type": "dh_hello", "name": name, "dh_pub": mitm_pub_bytes.hex()})
        line2 = self._recv_line(ssock)
        reply = json.loads(line2)

        self._log("Poskus ponarejanja certifikata", [
            f"Strežnik poslal certifikat: {bool(reply.get('cert'))}",
            f"Ustvarjam lažen certifikat za MITM ključ...",
            f"Podpis: 'deadbeef...' (ponarejen — nimam CA privatnega ključa!)",
        ])

        fake_cert = {
            "identity": "ChatServer",
            "dh_pub":   mitm_pub_bytes.hex(),
            "sig":      "deadbeef" * 64
        }

        self._send(csock, {
            "type":                "dh_reply",
            "dh_pub":              mitm_pub_bytes.hex(),
            "cert":                fake_cert,
            "require_client_cert": reply.get("require_client_cert", False)
        })

        phase_notes = {
            3: "CA podpis blokira napad.",
            4: "PFS ne pomaga MITM-u — certifikat ga še vedno blokira.",
            5: "mTLS: tudi brez certifikata napadalec ne more mimo CA preverjanja.",
            6: "Replay zaščita je za PO handshaku — certifikat blokira že prej.",
            7: "Vse zaščite — blokiran na prvem koraku (CA certifikat).",
        }

        print(BLOCKED(f"""
  ╔══════════════════════════════════════════════╗
  ║  NAPAD BLOKIRAN  —  Faza {self.phase}                   ║
  ║  {phase_notes.get(self.phase,''):<44} ║
  ╚══════════════════════════════════════════════╝"""))

        try:
            data = csock.recv(1024)
            if not data:
                print(BLOCKED("  ✓ Odjemalec zaprl zvezo — ni poslal nobenih podatkov."))
        except: pass
        try: csock.close()
        except: pass
        try: ssock.close()
        except: pass

    # ── Faza 6: replay napad demo ─────────────────────────────────────────────
    def _replay_demo(self, csock, ssock):
        """
        Posebna demonstracija replay napada:
        MITM posname en paket in ga poskusi poslati dvakrat.
        Strežnik zavrne duplikat (nonce je bil že viden).

        Opomba: to je samo za ilustracijo — faza 6 ima certifikat,
        torej MITM že pade pri handshaku. Ta demo se izvede samo
        pri direktni povezavi (brez certifikata) za prikaz replay zaščite.
        """
        self._log("REPLAY NAPAD DEMO", [
            "Snemam prvi paket...",
            "Ga bom poslal dvakrat — drugi mora biti zavrnjen.",
        ], WARN_C)

        recorded = None
        def pipe_record(src, dst, record=False):
            nonlocal recorded
            buf = ""
            count = 0
            while True:
                try:
                    chunk = src.recv(4096).decode()
                    if not chunk: break
                    buf += chunk
                    while "\n" in buf:
                        line, buf = buf.split("\n", 1)
                        if not line.strip(): continue
                        pkt = json.loads(line)
                        dst.sendall((line + "\n").encode())
                        if record and pkt.get("protected") and recorded is None:
                            recorded = line
                            count += 1
                            print(WARN_C(f"\n  [REPLAY] Posnel paket #{count}: {line[:60]}..."))
                            # Pošlji isti paket še enkrat
                            time.sleep(0.5)
                            print(WARN_C(f"  [REPLAY] Pošiljam duplikat..."))
                            dst.sendall((line + "\n").encode())
                except: break
        t1 = threading.Thread(target=pipe_record, args=(csock, ssock, True), daemon=True)
        t2 = threading.Thread(target=pipe_record, args=(ssock, csock, False), daemon=True)
        t1.start(); t2.start(); t1.join(); t2.join()

    # ── Pomočne funkcije ──────────────────────────────────────────────────────
    def _dh_pipe(self, csock, ssock, key_c, key_s, name):
        """Posreduj in dešifriraj DH šifriran promet."""
        def pipe(src, dst, kd, ke, dir):
            buf = ""
            while True:
                try:
                    chunk = src.recv(4096).decode()
                    if not chunk: break
                    buf += chunk
                    while "\n" in buf:
                        line, buf = buf.split("\n", 1)
                        if not line.strip(): continue
                        pkt = json.loads(line)
                        if pkt.get("type") == "msg" and pkt.get("encrypted"):
                            try:
                                plain, _ = DH.decrypt(kd, pkt["text"])
                                self._log(f"DEŠIFRIRANO ({dir})", [f"{name}: {plain}"])
                                with self.lock: self.intercepted.append(f"{name}: {plain}")
                                pkt["text"] = DH.encrypt(ke, plain)
                            except: pass
                        dst.sendall((json.dumps(pkt) + "\n").encode())
                except: break
            try: src.close()
            except: pass
            try: dst.close()
            except: pass
        t1 = threading.Thread(target=pipe, args=(csock, ssock, key_c, key_s, "C→S"), daemon=True)
        t2 = threading.Thread(target=pipe, args=(ssock, csock, key_s, key_c, "S→C"), daemon=True)
        t1.start(); t2.start(); t1.join(); t2.join()

    def _plain_pipe(self, csock, ssock):
        def pipe(src, dst):
            while True:
                try:
                    d = src.recv(4096)
                    if not d: break
                    dst.sendall(d)
                except: break
        t1 = threading.Thread(target=pipe, args=(csock, ssock), daemon=True)
        t2 = threading.Thread(target=pipe, args=(ssock, csock), daemon=True)
        t1.start(); t2.start(); t1.join(); t2.join()

    # ── Glavi handler ─────────────────────────────────────────────────────────
    def handle(self, csock, addr):
        print(SYS_C(f"\n  [MITM] Nova žrtev: {addr[0]}:{addr[1]}"))
        ssock = socket.socket()
        try:
            ssock.connect((self.server_host, self.server_port))
        except Exception as e:
            print(col(91, f"  [MITM] Ne morem do strežnika: {e}"))
            csock.close(); return

        p = self.phase
        if p == 1:   self._handle_phase1(csock, ssock)
        elif p == 2: self._handle_phase2(csock, ssock)
        else:        self._handle_cert_phases(csock, ssock)

    def print_summary(self):
        with self.lock:
            if not self.intercepted: return
            print(INTERCEPT("\n  ══ PRESTREZENA SPOROČILA ══"))
            for m in self.intercepted:
                print(INTERCEPT(f"  ★ {m}"))

    def run(self):
        desc = {
            1: "Plaintext — bere vse",
            2: "HMAC zamenjava — bere šifrirano",
            3: "Certifikat — BLOKIRAN",
            4: "PFS + certifikat — BLOKIRAN",
            5: "mTLS — BLOKIRAN",
            6: "Replay — BLOKIRAN pri handshaku",
            7: "Vse skupaj — BLOKIRAN",
        }
        print(f"""
  ╔══════════════════════════════════════════════╗
  ║              MITM PROXY                      ║
  ║  Faza {self.phase}: {desc.get(self.phase,''):<37} ║
  ╠══════════════════════════════════════════════╣
  ║  Poslušam:    {self.listen_host}:{self.listen_port:<28} ║
  ║  Posredujem:  {self.server_host}:{self.server_port:<28} ║
  ╚══════════════════════════════════════════════╝
  Odjemalci → port {self.listen_port}
  Ctrl+C za povzetek.
""")
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.listen_host, self.listen_port))
        srv.listen(10)
        try:
            while True:
                conn, addr = srv.accept()
                threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            self.print_summary()
            print(SYS_C("\n  [MITM] Ugašam..."))

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--phase",        type=int, default=1, choices=range(1, 8))
    ap.add_argument("--listen-port",  type=int, default=9001)
    ap.add_argument("--server-port",  type=int, default=9000)
    ap.add_argument("--host",         default="127.0.0.1")
    ap.add_argument("--long-term-key",default="longterm.key",
                    help="Za fazo 2 — mora biti ista datoteka kot pri strežniku/odjemalcih")
    args = ap.parse_args()

    long_term_key = None
    if args.phase == 2 and os.path.exists(args.long_term_key):
        with open(args.long_term_key, "rb") as f:
            long_term_key = f.read()
        print(f"[MITM] Naložil long_term_key iz '{args.long_term_key}'")

    MITMProxy(args.host, args.listen_port, args.host, args.server_port,
              args.phase, long_term_key).run()
