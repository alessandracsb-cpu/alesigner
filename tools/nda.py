#!/usr/bin/env python3
"""Criptografa (e descriptografa) os cases sob NDA do portfólio.

Uso:
  NDA_PASSWORD='...' python3 tools/nda.py encrypt   # private/  -> assets/nda/
  NDA_PASSWORD='...' python3 tools/nda.py decrypt   # assets/nda/ -> private/  (para editar)

Fonte em texto puro (nunca vai para o Git): private/case-<slug>.html e os arquivos
em private/<pasta>/. Saída pública: assets/nda/*.bin (AES-256-GCM, chave PBKDF2-SHA256).
No HTML do case, referências a "assets/os/..." e "demo/..." viram atributos data-nda-*,
resolvidos no navegador depois que a senha é digitada.
"""
import base64, json, mimetypes, os, re, secrets, sys
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ROOT = Path(__file__).resolve().parent.parent
PRIV = ROOT / 'private'
OUT = ROOT / 'assets' / 'nda'
ITER = 310_000

# Quais cases são protegidos e quais pastas privadas cada um usa.
CASES = {
    'wos': ['os', 'demo'],
    'cupons': [],
}


def key_from(password: str, salt: bytes) -> bytes:
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(password.encode())


def seal(key: bytes, data: bytes) -> bytes:
    iv = secrets.token_bytes(12)
    return iv + AESGCM(key).encrypt(iv, data, None)


def unseal(key: bytes, blob: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:12], blob[12:], None)


def password() -> str:
    pw = os.environ.get('NDA_PASSWORD', '')
    if not pw:
        sys.exit('Defina NDA_PASSWORD.')
    return pw


def encrypt():
    pw = password()
    OUT.mkdir(parents=True, exist_ok=True)
    for f in OUT.glob('*.bin'):
        f.unlink()
    salt = secrets.token_bytes(16)
    (OUT / 'salt.txt').write_text(base64.b64encode(salt).decode())
    key = key_from(pw, salt)
    index = {}
    for slug, folders in CASES.items():
        html = (PRIV / f'case-{slug}.html').read_text()
        html = re.sub(r'\b(src|href)="(?:assets/)?((?:os|demo)/[^"]+)"', r'data-nda-\1="\2"', html)
        assets = {}
        for folder in folders:
            for f in sorted((PRIV / folder).glob('*')):
                name = f'{folder}/{f.name}'
                fname = secrets.token_hex(8) + '.bin'
                (OUT / fname).write_bytes(seal(key, f.read_bytes()))
                mime = mimetypes.guess_type(f.name)[0] or 'application/octet-stream'
                assets[name] = [fname, mime]
        payload = json.dumps({'html': html, 'assets': assets}).encode()
        fname = f'case-{slug}.bin'
        (OUT / fname).write_bytes(seal(key, payload))
        index[slug] = fname
        print(f'{slug}: {len(assets)} arquivos protegidos')
    (OUT / 'index.json').write_text(json.dumps({'iter': ITER, 'cases': index}))


def decrypt():
    pw = password()
    salt = base64.b64decode((OUT / 'salt.txt').read_text())
    key = key_from(pw, salt)
    index = json.loads((OUT / 'index.json').read_text())['cases']
    for slug, fname in index.items():
        data = json.loads(unseal(key, (OUT / fname).read_bytes()))
        html = re.sub(r'data-nda-(src|href)="(os/[^"]+)"', r'\1="assets/\2"', data['html'])
        html = re.sub(r'data-nda-(src|href)="(demo/[^"]+)"', r'\1="\2"', html)
        PRIV.mkdir(exist_ok=True)
        (PRIV / f'case-{slug}.html').write_text(html)
        for name, (f, _) in data['assets'].items():
            dest = PRIV / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(unseal(key, (OUT / f).read_bytes()))
        print(f'{slug}: restaurado em private/')


if __name__ == '__main__':
    {'encrypt': encrypt, 'decrypt': decrypt}.get(sys.argv[1] if len(sys.argv) > 1 else '', lambda: sys.exit(__doc__))()
