"""
server.py — Chat strežnik za vse faze (1–7)

Poženi: python3 server.py --phase <N> [--port 9000]

Faze:
  1  Osnoven DH, brez overjanja
  2  DH + HMAC podpis ključev (pokaže zakaj ni dovolj)
  3  DH + CA certifikat
  4  PFS — efemerni ključi na sejo
  5  mTLS — vzajemna avtentikacija (strežnik preveri odjemalca)
  6  Nonce + sekvenčna zaščita (anti-replay)
  7  Vse skupaj
"""
import socket, threading, json, argparse, sys, os, time
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))
import dh as DH

R = "\033[0m"
def col(c, t): return f"\033[{c}m{t}{R}"
SYS  = lambda t: col(96, t)
MSG  = lambda t: col(37, t)
WARN = lambda t: col(91, t)
OK   = lambda t: col(92, t)
PFS  = lambda t: col(95, t)   # vijolična za PFS

PHASE_DESC = {
    1: "Osnoven DH, brez overjanja",
    2: "DH + HMAC podpis ključev",
    3: "DH + CA certifikat",
    4: "PFS — efemerni ključi",
    5: "mTLS — vzajemna avtentikacija",
    6: "Nonce + sekvenčna zaščita",
    7: "Vse skupaj (3 + 4 + 5 + 6)",
}

class ChatServer:
    def __init__(self, host, port, phase, ca=None, long_term_key=None):
        self.host           = host
        self.port           = port
        self.phase          = phase
        self.ca             = ca                  # CA instanca (faze 3,5,7)
        self.long_term_key  = long_term_key        # HMAC ključ (faza 2)
        self.clients        = {}                   # sock → {name, key, guard}
        self.lock           = threading.Lock()

        # Statični DH ključ (faze 1–3) — ISTI za vse seje
        # To je ranljivost ki jo PFS (faza 4) odpravi!
        self.static_priv, self.static_pub = DH.new_keypair()
        self.static_pub_bytes = DH.pub_to_bytes(self.static_pub)

        # CA certifikat za statični ključ (faza 3)
        self.static_cert = ca.sign("ChatServer", self.static_pub_bytes) if ca else None

    # ── Pošiljanje ────────────────────────────────────────────────────────────

    def _send(self, sock, obj, key=None, guard=None, seq_ref=None):
        """Pošlji paket, opcijsko šifriran in zaščiten."""
        if key and obj.get("type") == "msg":
            if guard and seq_ref is not None:
                # Faza 6/7: zaščiten paket z nonce + seq
                pkt = guard.make_packet(key, obj["text"], seq_ref[0])
                seq_ref[0] += 1
                pkt["from"] = obj.get("from", "")
                pkt["ts_str"] = obj.get("ts", "")
            else:
                pkt = dict(obj)
                pkt["text"]      = DH.encrypt(key, obj["text"])
                pkt["encrypted"] = True
        else:
            pkt = obj
        try:
            sock.sendall((json.dumps(pkt) + "\n").encode())
        except:
            pass

    def broadcast(self, msg, exclude=None):
        dead = []
        with self.lock:
            items = list(self.clients.items())
        for sock, info in items:
            if sock is exclude: continue
            try:
                self._send(sock, msg, info.get("key"),
                           info.get("guard"), info.get("seq_ref"))
            except:
                dead.append(sock)
        for s in dead: self._remove(s)

    def _remove(self, sock):
        with self.lock:
            info = self.clients.pop(sock, None)
        if info:
            self.broadcast({"type": "sys", "text": f"{info['name']} je zapustil chat."})
        try: sock.close()
        except: pass

    def _recv_line(self, sock) -> str:
        buf = ""
        while "\n" not in buf:
            c = sock.recv(4096).decode()
            if not c: raise ConnectionError("Prekinjena zveza")
            buf += c
        return buf.split("\n")[0]

    # ── Handshake po fazah ────────────────────────────────────────────────────

    def _hs_phase1(self, sock):
        """Faza 1: samo JOIN, brez kriptografije."""
        pkt = json.loads(self._recv_line(sock))
        assert pkt["type"] == "join"
        return pkt["name"], None, None, None

    def _hs_phase2(self, sock):
        """
        Faza 2: DH izmenjava + HMAC podpis javnih ključev.

        POSTOPEK:
          1. Odjemalec pošlje: dh_pub + HMAC(long_term_key, dh_pub)
          2. Strežnik preveri HMAC
          3. Strežnik pošlje: svoj dh_pub + HMAC(long_term_key, dh_pub)
          4. Odjemalec preveri HMAC

        PROBLEM:
          - long_term_key morata imeti oba vnaprej
          - Če ga izmenjata prek omrežja → MITM ga prestrezе in ponaredi HMAC-e
          - Rešitev: CA (faza 3) ki je zaupanja vredna tretja stranka
        """
        pkt  = json.loads(self._recv_line(sock))
        assert pkt["type"] == "dh_hello_hmac"
        name = pkt["name"]
        client_pub_bytes = bytes.fromhex(pkt["dh_pub"])

        # Preveri HMAC odjemalčevega ključa
        if not DH.verify_pub_key(self.long_term_key, client_pub_bytes, name, pkt["sig"]):
            raise Exception(f"HMAC odjemalčevega ključa ni veljaven!")
        print(SYS(f"  [HMAC] Podpis ključa za {name} veljaven"))

        client_pub = DH.pub_from_bytes(client_pub_bytes)

        # Pošlji strežnikov ključ + HMAC
        srv_sig = DH.sign_pub_key(self.long_term_key, self.static_pub_bytes, "ChatServer")
        sock.sendall((json.dumps({
            "type":   "dh_reply_hmac",
            "dh_pub": self.static_pub_bytes.hex(),
            "sig":    srv_sig
        }) + "\n").encode())

        key = DH.compute_shared_secret(self.static_priv, client_pub)
        print(SYS(f"  [DH] Skupna skrivnost z {name}: {key.hex()[:16]}..."))
        return name, key, None, None

    def _hs_phase3(self, sock, use_ephemeral=False, require_client_cert=False):
        """
        Faza 3 (+ 4 + 5 + 7): DH + CA certifikat.

        use_ephemeral=True  → faza 4 (PFS): generiraj nov ključ za to sejo
        require_client_cert → faza 5 (mTLS): zahtevaj certifikat od odjemalca
        """
        pkt  = json.loads(self._recv_line(sock))
        assert pkt["type"] == "dh_hello", f"Pričakoval dh_hello, dobil {pkt.get('type')}"
        name           = pkt["name"]
        client_pub_bytes = bytes.fromhex(pkt["dh_pub"])
        client_pub     = DH.pub_from_bytes(client_pub_bytes)

        # ── PFS: generiraj EFEMERNI ključ za to sejo ──────────────────────────
        if use_ephemeral:
            session_priv, session_pub = DH.new_keypair()
            session_pub_bytes = DH.pub_to_bytes(session_pub)
            # CA podpiše efemerni ključ (v praksi: "server signature" nad eph. ključem)
            session_cert = self.ca.sign("ChatServer", session_pub_bytes)
            print(PFS(f"  [PFS] Generiran EFEMERNI ključ za sejo z {name}"))
            print(PFS(f"  [PFS] Ključ: {session_pub_bytes.hex()[:32]}..."))
        else:
            session_priv     = self.static_priv
            session_pub_bytes = self.static_pub_bytes
            session_cert     = self.static_cert

        # ── mTLS: zahtevaj certifikat od odjemalca ───────────────────────────
        reply = {
            "type":               "dh_reply",
            "dh_pub":             session_pub_bytes.hex(),
            "cert":               session_cert,
            "require_client_cert": require_client_cert
        }
        sock.sendall((json.dumps(reply) + "\n").encode())

        # ── mTLS: prejmi in preveri odjemalčev certifikat ────────────────────
        client_cert_verified = False
        if require_client_cert:
            pkt2 = json.loads(self._recv_line(sock))
            if pkt2.get("type") != "client_cert":
                raise Exception("Odjemalec ni poslal certifikata (mTLS zahteva)!")
            client_cert = pkt2["cert"]
            if not self.ca.verify(client_cert):
                # Zavrni odjemalca brez CA certifikata
                sock.sendall((json.dumps({
                    "type": "error",
                    "text": "Tvoj certifikat ni veljaven — zavrnjen!"
                }) + "\n").encode())
                raise Exception(f"Odjemalec {name} nima veljavnega certifikata!")
            if client_cert["identity"] != name:
                raise Exception(f"Certifikat je za '{client_cert['identity']}', ne '{name}'!")
            print(OK(f"  [mTLS] ✓ Odjemalčev certifikat za '{name}' veljaven"))
            client_cert_verified = True

        key = DH.compute_shared_secret(session_priv, client_pub)
        label = "PFS efemerni" if use_ephemeral else "statični"
        print(SYS(f"  [DH] {label} ključ — skupna skrivnost z {name}: {key.hex()[:16]}..."))

        if use_ephemeral:
            # Po izračunu skupne skrivnosti efemerni zasebni ključ zavržemo
            del session_priv
            print(PFS(f"  [PFS] Efemerni zasebni ključ ZAVRŽEN — pretekle seje varne"))

        return name, key, None, None

    def _handshake(self, sock):
        """Dispatcher za vse faze."""
        p = self.phase
        if p == 1: return self._hs_phase1(sock)
        if p == 2: return self._hs_phase2(sock)
        if p == 3: return self._hs_phase3(sock)
        if p == 4: return self._hs_phase3(sock, use_ephemeral=True)
        if p == 5: return self._hs_phase3(sock, require_client_cert=True)
        if p == 6: return self._hs_phase3(sock)   # replay zaščita pride v handle()
        if p == 7: return self._hs_phase3(sock, use_ephemeral=True, require_client_cert=True)

    # ── Obdelava odjemalca ────────────────────────────────────────────────────

    def handle(self, sock, addr):
        try:
            name, key, _, __ = self._handshake(sock)
        except Exception as e:
            print(WARN(f"  [!] Handshake napaka ({addr}): {e}"))
            sock.close(); return

        ts = datetime.now().strftime("%H:%M:%S")
        print(SYS(f"  [{ts}] + {name} ({addr[0]}:{addr[1]})"))

        # Replay guard (fazi 6 in 7)
        guard   = DH.ReplayGuard() if self.phase in (6, 7) else None
        seq_ref = [0]

        with self.lock:
            self.clients[sock] = {
                "name":    name,
                "key":     key,
                "guard":   guard,
                "seq_ref": seq_ref
            }

        self.broadcast({"type": "sys", "text": f"{name} se je pridružil!"}, exclude=sock)
        self._send(sock, {"type": "sys", "text": f"Dobrodošel, {name}!"}, key)

        buf = ""
        while True:
            try:
                chunk = sock.recv(4096).decode()
                if not chunk: break
                buf += chunk
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    if not line.strip(): continue
                    pkt = json.loads(line)

                    if pkt.get("type") in ("msg", "protected_msg"):
                        # Dešifriraj
                        if pkt.get("protected") and guard:
                            text, err = guard.open_packet(key, pkt)
                            if err:
                                print(WARN(f"  [!] Replay/integriteta napaka od {name}: {err}"))
                                self._send(sock, {"type": "error", "text": f"Paket zavrnjen: {err}"}, key)
                                continue
                        elif pkt.get("encrypted") and key:
                            try:
                                text, _ = DH.decrypt(key, pkt["text"])
                            except:
                                text = pkt["text"]
                        else:
                            text = pkt.get("text", "")

                        ts2 = datetime.now().strftime("%H:%M:%S")
                        print(MSG(f"  [{ts2}] {name}: {text}"))
                        self.broadcast(
                            {"type": "msg", "from": name, "text": text, "ts": ts2},
                            exclude=sock
                        )
                    elif pkt.get("type") == "quit":
                        raise ConnectionError("quit")
            except: break

        self._remove(sock)

    def _listen_on(self, port, open_sockets):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, port))
        srv.listen(10)
        srv.settimeout(1.0)
        open_sockets.append(srv)
        while not self._stop:
            try:
                conn, addr = srv.accept()
                threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def run(self, extra_ports=None):
        """
        extra_ports: dodatni porti na katerih strežnik posluša.
        Npr. server.run(extra_ports=[9001]) → Alice na 9000, Bob na 9001 (skozi MITM).
        Oba odjemalca komunicirata z istim strežnikom — MITM je med njima neviden.
        """
        import signal
        self._stop = False
        ports = [self.port] + (extra_ports or [])
        ports_str = " in ".join(str(p) for p in ports)

        print(f"""
╔═════════════════════════════════════════════════╗
║     CHAT STRŒŽNIK  —  Faza {self.phase}                    ║
║  {PHASE_DESC[self.phase]:<46} ║
╚═════════════════════════════════════════════════╝
  Posluša na portih: {ports_str}
  Ustavi z: Ctrl+C
""")
        open_sockets = []

        def shutdown(sig=None, frame=None):
            print(SYS("\n  [SYS] Ugašam strežnik..."))
            self._stop = True
            for s in open_sockets:
                try: s.close()
                except: pass
            sys.exit(0)

        signal.signal(signal.SIGINT,  shutdown)
        signal.signal(signal.SIGTERM, shutdown)
        if hasattr(signal, "SIGBREAK"):
            signal.signal(signal.SIGBREAK, shutdown)

        threads = []
        for p in ports:
            t = threading.Thread(target=self._listen_on, args=(p, open_sockets), daemon=True)
            t.start()
            threads.append(t)
            print(SYS(f"  [SYS] Poslušam na portu {p}"))

        try:
            for t in threads:
                t.join()
        except (KeyboardInterrupt, SystemExit):
            shutdown()

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host",         default="0.0.0.0")
    ap.add_argument("--port",         type=int, default=9000)
    ap.add_argument("--extra-ports",  type=int, nargs="+", default=[],
                    help="Dodatni porti (npr. --extra-ports 9001 9002)")
    ap.add_argument("--phase",        type=int, default=1, choices=range(1, 8))
    ap.add_argument("--ca-pub-out",   default="ca_public.pem")
    ap.add_argument("--long-term-key",default="longterm.key")
    args = ap.parse_args()

    ca = None
    long_term_key = None

    if args.phase in (3, 4, 5, 6, 7):
        ca_priv_path = "ca_private.pem"
        if os.path.exists(ca_priv_path):
            # Naloži obstoječ CA ključ — certifikati iz issue_client_cert.py ostanejo veljavni
            with open(ca_priv_path, "rb") as f:
                ca = DH.CA(priv_pem=f.read())
            print(f"[CA] Naložen obstoječ CA ključ iz '{ca_priv_path}'")
            print(f"[CA] Certifikati iz prejšnjih zagonov so še veljavni\n")
        else:
            # Generiraj nov CA ključ (prvi zagon)
            print("[CA] Generiram nov CA ključ...")
            ca = DH.CA()
            with open(args.ca_pub_out, "wb") as f:
                f.write(ca.pub_pem())
            print(f"[CA] Javni ključ  → '{args.ca_pub_out}'")
            with open(ca_priv_path, "wb") as f:
                f.write(ca.priv_pem())
            print(f"[CA] Zasebni ključ → '{ca_priv_path}'  (za issue_client_cert.py)\n")

    if args.phase == 2:
        # Generiraj dolgoročni skupni ključ (v praksi bi bil vnaprej izmenjan)
        long_term_key = os.urandom(32)
        with open(args.long_term_key, "wb") as f:
            f.write(long_term_key)
        print(f"[HMAC] Dolgoročni ključ → '{args.long_term_key}'")
        print(f"[HMAC] Kopiraj to datoteko k odjemalcem!\n")

    ChatServer(args.host, args.port, args.phase, ca, long_term_key).run(extra_ports=args.extra_ports)
