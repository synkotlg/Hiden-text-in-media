#!/usr/bin/env python3
#& by @synko & hashref sec

import os, sys, time, json, secrets, struct, subprocess, argparse

def ensure(pkg):
    try:
        __import__(pkg)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

ensure("cryptography")

from cryptography.hazmat.primitives.ciphers.aead import AESGCM ; from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC ; from cryptography.hazmat.primitives import hashes

SALT = b"xplat-hidden-salt"
ITER = 300_000
MAGIC = b"HTX2"
FOOTER_SIZE = 26

def anti_debug():
    if sys.gettrace():
        sys.exit("[-] Debugger détecté")
    if os.name == "posix":
        try:
            import ctypes
            if ctypes.CDLL(None).ptrace(0, 0, None, None) == -1:
                sys.exit("[-] ptrace détecté")
        except:
            pass
    for v in ("PYTHONINSPECT", "PYTHONDEBUG"):
        if os.getenv(v):
            sys.exit("[-] Environnement suspect")

def now():
    return int(time.time())

def gen_key():
    return secrets.token_urlsafe(32)

def derive_key(pwd: str) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=SALT,iterations=ITER,)
    return kdf.derive(pwd.encode())

def remove_block(file):
    with open(file, "rb") as f:
        f.seek(-FOOTER_SIZE, os.SEEK_END)
        footer = f.read(FOOTER_SIZE)
        blob_size = struct.unpack(">I", footer[22:26])[0]
        f.seek(-(FOOTER_SIZE + blob_size), os.SEEK_END)
        cut = f.tell()
    with open(file, "rb") as f:
        data = f.read(cut)
    with open(file, "wb") as f:
        f.write(data)

def add_text(text, file, key=None, ttl=None, max_reads=0,destroy_on_fail=False, corrupt_after_read=False):
    text = text.replace("\\n", "\n")
    if not key:
        key = gen_key()
        print(f"[KEY] {key}")
    expire = now() + int(ttl) if ttl else 0
    max_reads = int(max_reads) if max_reads else 0
    reads = 0
    payload = json.dumps({"text": text}).encode()
    aes = AESGCM(derive_key(key))
    nonce = secrets.token_bytes(12)
    enc = aes.encrypt(nonce, payload, None)
    blob = nonce + enc
    footer = (MAGIC +
        struct.pack(">B", destroy_on_fail) +
        struct.pack(">B", corrupt_after_read) +
        struct.pack(">Q", expire) +
        struct.pack(">I", max_reads) +
        struct.pack(">I", reads) +
        struct.pack(">I", len(blob)))
    with open(file, "ab") as f:
        f.write(blob + footer)
    print("[+] Message caché")
    input("Entrée pour quitter (copie la clé)")

def read_text(file, key):
    anti_debug()
    with open(file, "rb") as f:
        f.seek(-FOOTER_SIZE, os.SEEK_END)
        footer = f.read(FOOTER_SIZE)
        if footer[:4] != MAGIC:
            print("[-] Aucun message")
            input("Entrée pour quitter")
            return
        destroy_on_fail = bool(footer[4])
        corrupt_after_read = bool(footer[5])
        expire = struct.unpack(">Q", footer[6:14])[0]
        max_reads = struct.unpack(">I", footer[14:18])[0]
        reads = struct.unpack(">I", footer[18:22])[0]
        blob_size = struct.unpack(">I", footer[22:26])[0]
        f.seek(-(FOOTER_SIZE + blob_size), os.SEEK_END)
        blob = f.read(blob_size)
    aes = AESGCM(derive_key(key))
    nonce, enc = blob[:12], blob[12:]
    try: payload = json.loads(aes.decrypt(nonce, enc, None))
    except:
        print("[-] Mauvaise clé")
        input("Entrée pour quitter")
        if destroy_on_fail:
            print("[!] Auto-destruction")
            input("Entrée pour quitter")
            remove_block(file)
        return
    if expire and now() > expire:
        print("[-] Message expiré → supprimé")
        remove_block(file)
        input("Entrée pour quitter")
        return
    reads += 1
    if max_reads and reads > max_reads:
        print("[-] Limite atteinte → supprimé")
        remove_block(file)
        input("Entrée pour quitter")
        return
    print("\n===== MESSAGE =====")
    print(payload["text"])
    print("===================")
    remove_block(file)
    footer = (MAGIC +
        struct.pack(">B", destroy_on_fail) +
        struct.pack(">B", corrupt_after_read) +
        struct.pack(">Q", expire) +
        struct.pack(">I", max_reads) +
        struct.pack(">I", reads) +
        struct.pack(">I", blob_size))
    with open(file, "ab") as f:
        f.write(blob + footer)
    if corrupt_after_read:
        with open(file, "r+b") as f:
            f.seek(0)
            f.write(secrets.token_bytes(1024))

def check_text(file):
    try:
        with open(file, "rb") as f:
            f.seek(-FOOTER_SIZE, os.SEEK_END)
            footer = f.read(FOOTER_SIZE)

        if footer[:4] != MAGIC:
            print("[-] Aucun message caché")
            input("Entrée pour quitter")
            return
        expire = struct.unpack(">Q", footer[6:14])[0]
        max_reads = struct.unpack(">I", footer[14:18])[0]
        reads = struct.unpack(">I", footer[18:22])[0]
        size = struct.unpack(">I", footer[22:26])[0]
        print("[+] Message détecté")
        print(f"    Taille     : {size} octets")
        print(f"    Lectures   : {reads}/{max_reads or '∞'}")
        print(f"    Expiration : {time.ctime(expire) if expire else '∞'}")
    except: print("[-] Impossible de lire le fichier")

def main():
    p = argparse.ArgumentParser(description="Hidden Text XPlat")
    sub = p.add_subparsers(dest="cmd")
    a = sub.add_parser("add")
    a.add_argument("text")
    a.add_argument("file")
    a.add_argument("-k", "--key")
    a.add_argument("-t", "--ttl")
    a.add_argument("-r", "--reads")
    a.add_argument("--destroy-on-fail", action="store_true")
    a.add_argument("--corrupt-after-read", action="store_true")
    r = sub.add_parser("read")
    r.add_argument("file")
    r.add_argument("-k", "--key", required=True)
    c = sub.add_parser("check")
    c.add_argument("file")
    args = p.parse_args()
    if args.cmd == "add":
        add_text(args.text, args.file, args.key, args.ttl,
                 args.reads, args.destroy_on_fail, args.corrupt_after_read)
    elif args.cmd == "read":
        read_text(args.file, args.key)
    elif args.cmd == "check":
        check_text(args.file)
    else:
        p.print_help()

if __name__ == "__main__":
    main()
