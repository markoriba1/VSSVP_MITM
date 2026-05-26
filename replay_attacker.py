"""
replay_attacker.py — Demonstracija replay napada

Scenarij:
  Pasivni napadalec snema promet med Alice in strežnikom.
  Ko Alice pošlje sporočilo, napadalec isti paket pošlje še N-krat.

Poženi:
  Faza 5 (brez replay zaščite — napadi uspejo):
    python3 replay_attacker.py --phase 5 --port 9000 --ca ca_public.pem --name Eve

  Faza 6 (z replay zaščito — napadi blokirani):
    python3 replay_attacker.py --phase 6 --port 9000 --ca ca_public.pem --name Eve

Potek:
  1. Eve se poveže na strežnik kot legitimen odjemalec
  2. Počaka da Alice pošlje sporočilo (posname ga iz strežnikovega broadcast-a)
  3. Pošlje isti šifriran paket 3x zapored
  4. Pokaže ali strežnik sprejme ali zavrne duplikate

Opomba:
  V resničnem scenariju napadalec ne bi bil prijavljen kot odjemalec —
  ampak bi pakete prestrezal na omrežni ravni (npr. z Wiresharkom).
  Ker nimamo pravega omrežja, simuliramo z legitimno prijavo ki snema
  in ponovno pošilja pakete.
"""
import socket, threading, json, argparse, sys, os, time
sys.path.insert(0, os.path.dirname(__file__))
import dh as DH

R = "\033[0m"
def col(c, t): return f"\033[{c}m{t}{R}"
ATK  = lambda t: col(91, t)   # rdeča — napadalec
SYS  = lambda t: col(90, t)   # siva
OK   = lambda t: col(92, t)   # zelena — blokiran
WARN = lambda t: col(93, t)   # rumena — uspel napad

class ReplayAttacker:
    def __init__(self, host, port, phase, ca_pem, replays=3, delay=0.5):
        self.host     = host
        self.port     = port
        self.phase    = phase
        self.ca_pem   = ca_pem
        self.replays  = replays   # kolikokrat pošlji isti paket
        self.delay    = delay     # sekunde med replay paketi
        self.sock     = None
        self.key      = None
        self.running  = False
        self.recorded = None      # posneti paket

        self.my_priv, self.my_pub = DH.new_keypair()
        self.my_pub_bytes = DH.pub_to_bytes(self.my_pub)

    def _send_raw(self, obj):
        self.sock.sendall((json.dumps(obj) + "\n").encode())

    def _recv_line(self) -> str:
        buf = ""
        while "\n" not in buf:
            buf += self.sock.recv(4096).decode()
        return buf.split("\n")[0]

    def _handshake(self):
        """
        Vzpostavi legitimno sejo — Eve je prijavljena kot navaden odjemalec.
        Za faze 5 in 7 (mTLS) Eve nima certifikata, zato se poveže na
        strežnik brez mTLS zahteve — strežnik pri replay demo ne zahteva
        certifikata od vseh odjemalcev, samo preveri replay pakete.
        """
        self._send_raw({
            "type":   "dh_hello",
            "name":   "Eve",
            "dh_pub": self.my_pub_bytes.hex()
        })

        reply = json.loads(self._recv_line())
        assert reply["type"] == "dh_reply"

        # Preveri certifikat strežnika
        cert = reply.get("cert")
        if cert:
            verifier = DH.ca_from_pub_pem(self.ca_pem)
            if not verifier.verify(cert):
                raise Exception("Certifikat strežnika ni veljaven!")

        # Če strežnik zahteva mTLS — Eve nima certifikata
        # Pošlji prazen odgovor da strežnik ne čaka
        if reply.get("require_client_cert"):
            print(SYS("  [Eve] Strežnik zahteva mTLS — Eve nima certifikata, pošiljem brez..."))
            # Ustvari lažen certifikat ki ga strežnik zavrne ali preskoči
            self._send_raw({"type": "client_cert", "cert": {
                "identity": "Eve", "dh_pub": self.my_pub_bytes.hex(), "sig": "00"*256
            }})
            # Preberi morebitno napako
            self.sock.settimeout(0.5)
            try:
                resp = self.sock.recv(4096).decode()
                for line in resp.split("\n"):
                    if line.strip():
                        try:
                            pkt = json.loads(line)
                            if pkt.get("type") == "error":
                                print(WARN(f"  [strežnik] {pkt['text']}"))
                                print(SYS("  [Eve] mTLS zavrnjena — nadaljujem brez mTLS za replay demo"))
                        except: pass
            except: pass
            finally:
                self.sock.settimeout(None)

        srv_pub  = DH.pub_from_bytes(bytes.fromhex(reply["dh_pub"]))
        self.key = DH.compute_shared_secret(self.my_priv, srv_pub)
        print(SYS(f"  [Eve] Prijavljena — skupna skrivnost: {self.key.hex()[:16]}..."))

    def _recv_loop(self):
        """
        Posluša broadcast sporočila od strežnika.
        Ko pride sporočilo od Alice, ga posname za replay.
        """
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

                    if pkt.get("type") == "sys":
                        print(SYS(f"\n  [strežnik] {pkt['text']}"))

                    elif pkt.get("type") == "msg":
                        # Prejeli smo sporočilo od Alice — dešifriraj in prikaži
                        text = pkt["text"]
                        if pkt.get("encrypted") and self.key:
                            try: text, _ = DH.decrypt(self.key, text)
                            except: pass

                        print(ATK(f"\n  [Eve] Prejela broadcast od {pkt['from']}: '{text}'"))

                    elif pkt.get("type") == "error":
                        print(OK(f"\n  [strežnik] ZAVRNIL: {pkt['text']}"))

            except: break

    def _read_response(self):
        """Preberi odgovor strežnika (error ali tišina) z kratkim timeoutom."""
        self.sock.settimeout(0.4)
        try:
            buf = ""
            while True:
                chunk = self.sock.recv(4096).decode()
                if not chunk: break
                buf += chunk
                if "\n" in buf:
                    for line in buf.split("\n"):
                        if not line.strip(): continue
                        try:
                            pkt = json.loads(line)
                            if pkt.get("type") == "error":
                                print(OK(f"  → strežnik ZAVRNIL: {pkt['text']}"))
                            elif pkt.get("type") == "sys":
                                print(SYS(f"  → strežnik: {pkt['text']}"))
                        except: pass
                    break
        except socket.timeout:
            pass  # ni odgovora = paket tiho sprejet
        except: pass
        finally:
            self.sock.settimeout(None)

    def _do_replay(self, raw_packet: str):
        """
        Pošlje isti raw paket večkrat in po vsakem prebere odgovor strežnika.
        """
        print(ATK(f"\n  ╔══════════════════════════════════════════════╗"))
        print(ATK(f"  ║  REPLAY NAPAD                                ║"))
        print(ATK(f"  ║  Pošiljam isti paket {self.replays}x zapored           ║"))
        print(ATK(f"  ╚══════════════════════════════════════════════╝"))
        print(ATK(f"  Paket: {raw_packet[:70]}..."))

        for i in range(self.replays):
            time.sleep(self.delay)
            try:
                self.sock.sendall((raw_packet + "\n").encode())
                print(ATK(f"\n  [{i+1}/{self.replays}] Poslan replay paket"))
                self._read_response()
            except OSError as e:
                # WinError 10053 = zveza prekinjena s strani strežnika
                # To se zgodi ko strežnik zapre sejo po handshake napaki
                print(WARN(f"  [{i+1}/{self.replays}] Strežnik zaprl zvezo"))
                print(SYS(  "  Razlog: mTLS zahteva ali handshake napaka"))
                break
            except Exception as e:
                print(WARN(f"  [{i+1}/{self.replays}] Napaka: {e}"))
                break

        time.sleep(0.3)

    def run(self):
        print(f"""
  ╔══════════════════════════════════════════════╗
  ║  REPLAY NAPADALEC  —  Eve                    ║
  ║  Faza {self.phase}: {'replay zaščita AKTIVNA' if self.phase >= 6 else 'replay zaščita NI aktivna'}{'          ' if self.phase >= 6 else '     '}  ║
  ╚══════════════════════════════════════════════╝
  Povežem se na {self.host}:{self.port} kot 'Eve'
  Počakam na Alicino sporočilo, potem pošljem replay...
""")
        self.sock = socket.socket()
        try:
            self.sock.connect((self.host, self.port))
        except Exception as e:
            print(col(91, f"  [!] Ne morem se povezati: {e}")); sys.exit(1)

        try:
            self._handshake()
        except Exception as e:
            print(col(91, f"  [!] Handshake napaka: {e}")); sys.exit(1)

        self.running = True

        # Recv loop v threadu
        threading.Thread(target=self._recv_loop, daemon=True).start()

        print(SYS("  [Eve] Čakam na Alicino sporočilo da ga posnamem..."))
        print(SYS("  [Eve] (Alice mora biti prijavljena in poslati sporočilo)\n"))

        # Počakaj na vhod — ko Alice pošlje sporočilo, ga Eve posname
        # iz recv_loop in ga tu posredujemo za replay
        # Ker Eve prejme samo broadcast (ne Alicinih raw paketov),
        # simuliramo da Eve pozna strukturo paketa in ga rekonstruira

        try:
            while self.running:
                cmd = input(SYS("  Eve> "))

                if cmd.strip() == "/quit":
                    break

                elif cmd.strip().startswith("/replay "):
                    # Ročno določi sporočilo za replay
                    msg = cmd.strip()[8:]
                    if self.key:
                        # Ustvari paket kot bi ga poslala Alice (faza 5 — brez zaščite)
                        if self.phase < 6:
                            fake_pkt = json.dumps({
                                "type":      "msg",
                                "text":      DH.encrypt(self.key, msg),
                                "encrypted": True
                            })
                        else:
                            # Faza 6 — Eve ne more ustvariti veljavnega paketa
                            # ker ne pozna Alicinega nonce/seq/HMAC ključa
                            # Simuliramo da je Eve nekako prebrala Alicin paket
                            guard = DH.ReplayGuard()
                            fake_pkt = json.dumps(guard.make_packet(self.key, msg, 0))

                        print(ATK(f"  [Eve] Ustvarila paket: {fake_pkt[:60]}..."))
                        self._do_replay(fake_pkt)
                    else:
                        print(SYS("  [!] Ni ključa"))

                elif cmd.strip() == "/help":
                    print(SYS("""
  Ukazi:
    /replay <sporocilo>   Ustvari in pošlji replay paket
    /quit                 Izhod

  Primer:
    /replay Nakaži 100€
"""))
                else:
                    # Normalno sporočilo
                    if self.key:
                        if self.phase >= 6:
                            guard = DH.ReplayGuard()
                            pkt = guard.make_packet(self.key, cmd.strip(), 0)
                        else:
                            pkt = {
                                "type":      "msg",
                                "text":      DH.encrypt(self.key, cmd.strip()),
                                "encrypted": True
                            }
                        self._send_raw(pkt)
                    else:
                        self._send_raw({"type": "msg", "text": cmd.strip()})

        except (KeyboardInterrupt, EOFError):
            pass

        self.running = False
        self._send_raw({"type": "quit"})
        self.sock.close()
        print(SYS("\n  [Eve] Odjavljena"))

        # Povzetek
        print(f"""
  ╔══════════════════════════════════════════════╗
  ║  POVZETEK                                    ║
  ║                                              ║
  ║  Faza {self.phase} replay zaščita:                      ║""")
        if self.phase < 6:
            print(WARN(f"  ║  NI aktivna — replay napadi USPEJO          ║"))
            print(WARN(f"  ║  Strežnik sprejme vsak paket brez preverjanja║"))
        else:
            print(OK(  f"  ║  AKTIVNA — duplikat nonce → zavrnjen        ║"))
            print(OK(  f"  ║  Vsak paket ima unikaten nonce+seq+ts        ║"))
        print(f"  ╚══════════════════════════════════════════════╝")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host",    default="127.0.0.1")
    ap.add_argument("--port",    type=int, default=9000)
    ap.add_argument("--phase",   type=int, default=5, choices=[5, 6, 7])
    ap.add_argument("--ca",      default="ca_public.pem")
    ap.add_argument("--replays", type=int, default=3,
                    help="Kolikokrat ponovi isti paket (privzeto: 3)")
    ap.add_argument("--delay",   type=float, default=0.5,
                    help="Sekunde med replay paketi (privzeto: 0.5)")
    args = ap.parse_args()

    if not os.path.exists(args.ca):
        print(f"[!] CA ključ '{args.ca}' ne obstaja.")
        sys.exit(1)

    with open(args.ca, "rb") as f:
        ca_pem = f.read()

    ReplayAttacker(args.host, args.port, args.phase, ca_pem,
                   args.replays, args.delay).run()
