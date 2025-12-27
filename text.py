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

def add_text(text, file, pwd=None, ttl=None, max_reads=None,destroy_on_fail=False, corrupt_after_read=False):
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
    key = derive_key(pwd)
    aes = AESGCM(key)
    out = b""
    for c in chunks:
        nonce = secrets.token_bytes(12)
        enc = nonce + aes.encrypt(nonce, c, None)
        pad = secrets.token_bytes(secrets.randbelow(128))
        block = pad + enc
        out += block + struct.pack(">I", len(block))
    with open(file, "ab") as f: f.write(out)
    print("[+] Message caché")

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
    with open(file, "rb") as f: data = f.read()
    pos = len(data)
    parts = []
    while pos > 4:
        size = struct.unpack(">I", data[pos-4:pos])[0]
        start = pos - 4 - size
        block = data[start:pos-4]
        pos = start
        for i in range(len(block)):
            try:
                raw = block[i:]
                nonce = raw[:12]
                enc = raw[12:]
                aes = AESGCM(derive_key(pwd))
                parts.append(aes.decrypt(nonce, enc, None))
                break
            except: continue
    if not parts:
        print("[-] Mauvaise clé")
        return
    payload = json.loads(b"".join(reversed(parts)))
    meta = payload["meta"]
    if meta["expire"] and now() > meta["expire"]:
        print("[-] Message expiré")
        remove_block(file)
        return
    meta["reads"] += 1
    if meta["max_reads"] and meta["reads"] > meta["max_reads"]:
        print("[-] Limite atteinte")
        remove_block(file)
        return
    print("\n===== MESSAGE =====")
    print(payload["text"])
    print("===================\n")
    if meta["corrupt_after_read"]:
        with open(file, "r+b") as f:
            f.seek(0)
            f.write(secrets.token_bytes(1024))
        print("[!] Média corrompu")

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
