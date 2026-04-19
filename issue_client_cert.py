"""
issue_client_cert.py — Izda odjemalčev certifikat za mTLS (faza 5, 7)

Poženi PRED odjemalcem:
  python3 issue_client_cert.py --name Alice
  python3 issue_client_cert.py --name Bob

Predpogoj: strežnik mora biti že zagnan z --phase 5 ali 7,
           da obstaja ca_public.pem (CA javni ključ).

V praksi bi CA preverila identiteto odjemalca preden mu izda certifikat
(npr. z email verifikacijo, osebnim dokumentom, ipd.).
"""
import argparse, os, sys, json
sys.path.insert(0, os.path.dirname(__file__))
import dh as DH
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives import hashes

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name",   required=True, help="Ime odjemalca (npr. Alice)")
    ap.add_argument("--ca-key", default="ca_private.pem",
                    help="CA privatni ključ (mora biti na strežniku)")
    ap.add_argument("--ca-pub", default="ca_public.pem")
    args = ap.parse_args()

    # Preveri da CA ključ obstaja
    if not os.path.exists(args.ca_key):
        # Simuliraj: v demo okolju CA privatni ključ shranimo ob zagonu strežnika
        print(f"[!] CA privatni ključ '{args.ca_key}' ne obstaja.")
        print(f"    V produkciji bi CA ključ bil samo na CA strežniku.")
        print(f"    Za demo: poženi strežnik z --phase 5, nato ta skript.")
        sys.exit(1)

    print(f"[CA] Izdajam certifikat za '{args.name}'...")

    # Generiraj odjemalčev DH ključ par
    client_priv, client_pub = DH.new_keypair()
    client_pub_bytes = DH.pub_to_bytes(client_pub)

    # Naloži CA privatni ključ
    with open(args.ca_key, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    # Podpiši certifikat
    payload = f"{args.name}::{client_pub_bytes.hex()}".encode()
    sig = ca_key.sign(payload, PKCS1v15(), hashes.SHA256())

    cert = {
        "identity": args.name,
        "dh_pub":   client_pub_bytes.hex(),
        "sig":      sig.hex()
    }

    # Shrani certifikat
    cert_file = f"{args.name.lower()}_cert.json"
    with open(cert_file, "w") as f:
        json.dump(cert, f)

    # Shrani tudi zasebni ključ (za DH izmenjavo v odjemalcu)
    priv_file = f"{args.name.lower()}_priv.pem"
    with open(priv_file, "wb") as f:
        f.write(client_priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))

    print(f"  ✓ Certifikat → '{cert_file}'")
    print(f"  ✓ Zasebni ključ → '{priv_file}'")
    print(f"""
  Odjemalec se identificira strežniku z:
    python3 client.py --name {args.name} --phase 5 --ca {args.ca_pub}

  Strežnik bo preveril certifikat in dovolil/zavrnil dostop.
""")

if __name__ == "__main__":
    main()
