#!/usr/bin/env python3
"""
transfer manage — keys and uploads.

Usage:
  python manage.py code-add <label> [CODE[#SECRET]] [--max SIZE]   new key; prints CODE#SECRET once
  python manage.py code-max <code> <SIZE|none>                     set or remove a key's size limit
  python manage.py code-rename <code> <label>                      change a key's label
  python manage.py code-list                                       keys, uses and space used
  python manage.py code-del <code>                                 revoke a key
  python manage.py uploads                                         list all uploads
  python manage.py delete <uuid>                                   delete an upload
  python manage.py decrypt [out-dir] [uuid]                        decrypt a key's uploads (prompts for CODE#SECRET)

SIZE is 500M, 2G, 1.5T or plain bytes (1024-based).
"""

import base64
import json
import os
import secrets
import shutil
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from getpass import getpass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'transfer.db')
UPLOADS_DIR = os.path.join(BASE_DIR, 'uploads')
METADATA_DIR = os.path.join(BASE_DIR, 'metadata')

# Mirrors static/e2e.js: chunk size, HKDF salt/info and the AAD strings.
E2E_CHUNK = 50 * 1024 * 1024
E2E_OVERHEAD = 12 + 16  # iv + GCM tag


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def all_meta():
    """Every upload's metadata, oldest first, with the old single-file shape normalized."""
    metas = []
    for fname in os.listdir(METADATA_DIR):
        with open(os.path.join(METADATA_DIR, fname)) as f:
            m = json.load(f)
        if 'files' not in m:
            m['files'] = [{'filename': m['filename'], 'size': m['size']}]
        metas.append(m)
    return sorted(metas, key=lambda m: m.get('uploaded_at', ''))


def parse_size(text):
    units = {'K': 1024, 'M': 1024**2, 'G': 1024**3, 'T': 1024**4}
    text = text.strip().upper().removesuffix('B')
    if text and text[-1] in units:
        return int(float(text[:-1]) * units[text[-1]])
    return int(text)


def fmt_limit(max_bytes):
    return _fmt_size(max_bytes) if max_bytes is not None else 'no limit'


def cmd_code_add(*args):
    args = list(args)
    max_bytes = None
    if '--max' in args:
        i = args.index('--max')
        max_bytes = parse_size(args[i + 1])
        del args[i:i + 2]
    label = args[0]
    code, _, secret = (args[1] if len(args) > 1 else '').partition('#')
    code = code or uuid.uuid4().hex[:16].upper()
    if len(secret) < 16:
        secret = secrets.token_urlsafe(16)
    with get_db() as db:
        db.execute(
            'INSERT INTO auth_codes (code, label, created_at, uses, max_bytes) VALUES (?, ?, ?, 0, ?)',
            (code, label, datetime.now(timezone.utc).isoformat(), max_bytes)
        )
    print(f'  Key  : {code}#{secret}')
    print(f'  Label: {label}')
    print(f'  Max  : {fmt_limit(max_bytes)}')
    print(f'  Login: https://transfer.lyr4.net/files/{code}#{secret}')
    print('  The part after # is not stored anywhere. Save the full key now:')
    print('  without it, files uploaded with this key cannot be decrypted.')


def cmd_code_max(code, size):
    max_bytes = None if size.lower() == 'none' else parse_size(size)
    with get_db() as db:
        found = db.execute('UPDATE auth_codes SET max_bytes = ? WHERE code = ?', (max_bytes, code)).rowcount
    print(f'  Code : {code}\n  Max  : {fmt_limit(max_bytes)}' if found else f'Not found: {code}')


def cmd_code_rename(code, label):
    with get_db() as db:
        found = db.execute('UPDATE auth_codes SET label = ? WHERE code = ?', (label, code)).rowcount
    print(f'  Code : {code}\n  Label: {label}' if found else f'Not found: {code}')


def cmd_code_list():
    with get_db() as db:
        rows = db.execute('SELECT * FROM auth_codes ORDER BY created_at').fetchall()
    if not rows:
        print('No auth codes.')
        return
    used = {}
    for m in all_meta():
        used[m.get('auth_code')] = used.get(m.get('auth_code'), 0) + sum(f['size'] for f in m['files'])
    print(f"{'CODE':<20}  {'LABEL':<20}  {'USES':>4}  {'USED / MAX':<22}  CREATED")
    print('-' * 95)
    for row in rows:
        usage = f"{_fmt_size(used.get(row['code'], 0))} / {fmt_limit(row['max_bytes'])}"
        print(f"{row['code']:<20}  {row['label']:<20}  {row['uses']:>4}  {usage:<22}  {row['created_at'][:19]}")


def cmd_code_del(code):
    with get_db() as db:
        found = db.execute('DELETE FROM auth_codes WHERE code = ?', (code,)).rowcount
    print(f'Revoked: {code}' if found else f'Not found: {code}')


def cmd_uploads():
    metas = all_meta()
    if not metas:
        print('No uploads.')
        return
    print(f"{'UUID':<36}  {'FILES':>5}  {'SIZE':>10}  UPLOADED")
    print('-' * 75)
    for m in metas:
        size = _fmt_size(sum(f['size'] for f in m['files']))
        print(f"{m['uuid']:<36}  {len(m['files']):>5}  {size:>10}  {m.get('uploaded_at', '')[:19]}")


def cmd_delete(file_uuid):
    meta_path = os.path.join(METADATA_DIR, f'{file_uuid}.json')
    upload_dir = os.path.join(UPLOADS_DIR, file_uuid)
    removed = False
    if os.path.exists(meta_path):
        os.remove(meta_path)
        removed = True
    if os.path.exists(upload_dir):
        shutil.rmtree(upload_dir)
        removed = True
    print(f'Deleted: {file_uuid}' if removed else f'Not found: {file_uuid}')


def upload_cipher(secret, upload_id):
    raw = HKDF(algorithm=hashes.SHA256(), length=32, salt=b'transfer.lyr4.net v1',
               info=f'upload:{upload_id}'.encode()).derive(secret.encode())
    return AESGCM(raw)


def unseal(aes, sealed, aad):
    return aes.decrypt(sealed[:12], sealed[12:], aad.encode())


def decrypt_file(aes, src, dest_dir, f):
    idx = f['index']
    name_enc = base64.urlsafe_b64decode(f['name_enc'] + '=' * (-len(f['name_enc']) % 4))
    name = os.path.basename(unseal(aes, name_enc, f'name:{idx}').decode()) or f'file{idx}'
    size = os.path.getsize(src)
    stride = E2E_CHUNK + E2E_OVERHEAD
    total = max(1, -(-size // stride))
    os.makedirs(dest_dir, exist_ok=True)
    with open(src, 'rb') as inp, open(os.path.join(dest_dir, name), 'wb') as out:
        for ci in range(total):
            out.write(unseal(aes, inp.read(stride), f'{idx}:{ci}:{total}'))
    print(f'  {dest_dir}/{name}  ({_fmt_size(size - total * E2E_OVERHEAD)})')


def cmd_decrypt(out_dir='decrypted', only_uuid=None):
    code, _, secret = getpass('Full key (CODE#SECRET): ').strip().partition('#')
    if not secret:
        print('That key has no #SECRET part; nothing can be decrypted without it.')
        return
    metas = [m for m in all_meta()
             if m.get('auth_code') == code and m.get('encrypted') and only_uuid in (None, m['uuid'])]
    if not metas:
        print(f'No encrypted uploads for {code}.')
        return
    for m in metas:
        aes = upload_cipher(secret, m['uuid'])
        dest_dir = os.path.join(out_dir, f"{m['uploaded_at'][:10]}_{m['uuid'][:8]}")
        try:
            for f in m['files']:
                decrypt_file(aes, os.path.join(UPLOADS_DIR, m['uuid'], f['filename']), dest_dir, f)
        except InvalidTag:
            print(f"  {m['uuid']}: the secret does not open this upload (wrong secret, or the file was altered)")


def _fmt_size(size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f'{size:.1f} {unit}'
        size /= 1024
    return f'{size:.1f} TB'


COMMANDS = {
    'code-add': cmd_code_add,
    'code-max': cmd_code_max,
    'code-rename': cmd_code_rename,
    'code-list': cmd_code_list,
    'code-del': cmd_code_del,
    'uploads': cmd_uploads,
    'delete': cmd_delete,
    'decrypt': cmd_decrypt,
}

if __name__ == '__main__':
    args = sys.argv[1:]
    if not args or args[0] not in COMMANDS:
        print(__doc__)
        sys.exit(1)
    COMMANDS[args[0]](*args[1:])
