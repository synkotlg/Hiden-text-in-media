import os, sys, time, json, secrets, struct, subprocess

def ensure(pkg):
    try:
        __import__(pkg)
    except ImportError: subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

ensure("cryptography")

from cryptography.hazmat.primitives.ciphers.aead import AESGCM ; from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC ; from cryptography.hazmat.primitives import hashes

SALT = b"xplat-hidden-salt"
ITER = 300_000

def anti_debug():
    if sys.gettrace():
        print("[-] Debugger détecté")
        sys.exit(1)
    if os.name == "posix":
        try:
            import ctypes
            if ctypes.CDLL(None).ptrace(0, 0, None, None) == -1:
                print("[-] ptrace détecté")
                sys.exit(1)
        except:
            pass
    for v in ("PYTHONINSPECT", "PYTHONDEBUG"):
        if os.getenv(v):
            print("[-] Environnement suspect")
            sys.exit(1)

def derive_key(pwd):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=SALT,iterations=ITER,)
    return kdf.derive(pwd.encode())

def gen_key():
    return secrets.token_urlsafe(32)

def now():
    return int(time.time())

def fragment(data, n):
    size = len(data) // n
    return [data[i*size:(i+1)*size] for i in range(n-1)] + [data[(n-1)*size:]]

def add_text(text,file,pwd=None,ttl=None,max_reads=None,destroy_on_fail=False,corrupt_after_read=False):
    text = text.replace("\\n", "\n")
    if not pwd:
        pwd = gen_key()
        print(f"[KEY] {pwd}")
    meta = {
        "expire": now() + int(ttl) if ttl else None,
        "max_reads": int(max_reads) if max_reads else None,
        "reads": 0,
        "destroy_on_fail": destroy_on_fail,
        "corrupt_after_read": corrupt_after_read}
    payload = json.dumps({"meta": meta, "text": text}).encode()
    chunks = fragment(payload, secrets.randbelow(4) + 3)
    aes = AESGCM(derive_key(pwd))
    out = b""
    for c in chunks:
        pad_len = secrets.randbelow(128)
        pad = secrets.token_bytes(pad_len)
        nonce = secrets.token_bytes(12)
        enc = aes.encrypt(nonce, c, None)
        block = struct.pack(">B", pad_len) + pad + nonce + enc
        out += block + struct.pack(">I", len(block))
    footer = b"HTX1" + struct.pack(">I", len(out))
    with open(file, "ab") as f:
        f.write(out + footer)
    print("[+] Message caché")
    try: input("Appuie sur Entrée pour quitter...")
    except: pass

def remove_block(file):
    with open(file, "rb") as f:
        data = f.read()
    pos = len(data)
    while pos > 4:
        size = struct.unpack(">I", data[pos-4:pos])[0]
        pos = pos - 4 - size
        if pos < 0: break
    with open(file, "wb") as f:
        f.write(data[:pos])

def read_text(file, pwd):
    anti_debug()
    with open(file, "rb") as f:
        f.seek(-8, os.SEEK_END)
        if f.read(4) != b"HTX1":
            print("[-] Aucun message trouvé")
            try: input("Appuie sur Entrée pour quitter...")
            except: pass
            return
        size = struct.unpack(">I", f.read(4))[0]
        f.seek(-(8 + size), os.SEEK_END)
        data = f.read(size)
    parts = []
    pos = len(data)
    aes = AESGCM(derive_key(pwd))
    while pos > 0:
        block_size = struct.unpack(">I", data[pos-4:pos])[0]
        block = data[pos-4-block_size:pos-4]
        pos -= 4 + block_size
        try:
            pad_len = block[0]
            nonce = block[1 + pad_len : 13 + pad_len]
            enc = block[13 + pad_len :]
            parts.append(aes.decrypt(nonce, enc, None))
        except: continue
    if not parts:
        print("[-] Mauvaise clé")
        try: input("Appuie sur Entrée pour quitter...")
        except: pass
        return
    payload = json.loads(b"".join(reversed(parts)))
    meta = payload["meta"]
    if meta["expire"] and now() > meta["expire"]:
        print("[-] Message expiré → supprimé")
        remove_block(file)
        try: input("Appuie sur Entrée pour quitter...")
        except: pass
        return
    meta["reads"] += 1
    if meta["max_reads"] and meta["reads"] > meta["max_reads"]:
        print("[-] Limite de lecture atteinte → supprimé")
        remove_block(file)
        try: input("Appuie sur Entrée pour quitter...")
        except: pass
        return
    print("\n===== MESSAGE =====")
    print(payload["text"])
    print("===================\n")
    if meta["corrupt_after_read"]:
        with open(file, "r+b") as f:
            f.seek(0)
            f.write(secrets.token_bytes(1024))
        print("[!] Média corrompu")
        try: input("Appuie sur Entrée pour quitter...")
        except: pass

def help():
    print("""
Usage :
  -text add "texte" to fichier
        [-k clé]
        [-t secondes]
        [-r lectures]
        [--destroy-on-fail]
        [--corrupt-after-read]

  -text read fichier -k clé

Options :
  -k  clé de chiffrement
  -t  durée avant expiration (secondes)
  -r  nombre max de lectures
  --destroy-on-fail     supprime si clé fausse
  --corrupt-after-read détruit le média
""")

def main():
    a = sys.argv[1:]
    try:
        if a[1] == "add":
            add_text(
                a[2],
                a[4],
                a[a.index("-k")+1] if "-k" in a else None,
                a[a.index("-t")+1] if "-t" in a else None,
                a[a.index("-r")+1] if "-r" in a else None,
                "--destroy-on-fail" in a,
                "--corrupt-after-read" in a,)
        elif a[1] == "read":
            read_text(a[2], a[4])
        else:
            help()
    except:
        help()

if __name__ == "__main__":
    main()