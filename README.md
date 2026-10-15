![transfer.lyr4.net](static/banner.jpg)

# transfer

A small file drop at `https://transfer.lyr4.net`. People with an upload key send
files; each upload gets a link to share. The upload page encrypts files in the
browser, so the server and anything in between (Cloudflare) hold ciphertext. Uploads
made before encryption, or sent to the API without it, are stored as sent.

## Keys

A key looks like `CODE#SECRET`.

- **CODE** is the login. The server stores it and checks it on every request. It
  controls uploading, the **My uploads** list and the key's size limit.
- **SECRET** never leaves the browser. Everything after `#` in a URL is not sent in
  requests, and the pages only ever send CODE. SECRET is not stored anywhere: lose it
  and the files uploaded with it cannot be decrypted.

## Pages

| Path | What it does |
|---|---|
| `/upload` | Enter `CODE#SECRET`, pick files, upload. Shows progress, speed and time left, and can be cancelled. Ends on **My uploads**, logging in with that key if needed. |
| `/files` | **My uploads**: log in with `CODE#SECRET`; lists uploads with decrypted names, space used against the key's limit, and login history. |
| `/files/CODE#SECRET` | Logs straight in. |
| `/<upload-id>#<upload-key>` | Share page: decrypts the names and downloads the files. |
| `/dl/<upload-id>/<file>` | The stored (encrypted) file, fetched by the share page. Kept under its own prefix so a Cloudflare challenge can cover every page while leaving downloads alone. |

## Encryption

All of it is in `static/e2e.js`; `manage.py decrypt` mirrors it in Python.

- Per-upload key: HKDF-SHA256 over SECRET, salt `transfer.lyr4.net v1`, info
  `upload:<upload-id>`, 32 bytes. A share link carries this key, so it opens that one
  upload and never reveals SECRET.
- Files are sent in 16 MB chunks, four at a time; each upload records its chunk size,
  and uploads made before this recorded none and used 50 MB. Each chunk is AES-256-GCM
  with a random 12-byte IV, stored as `iv || ciphertext || tag`. The additional data is
  `<file-index>:<chunk-index>:<chunk-count>`, so chunks cannot be reordered, swapped
  between files or truncated without decryption failing.
- File names are sealed the same way with additional data `name:<file-index>` and
  kept base64url-encoded in the metadata. On disk the files are named `f0`, `f1`, ….
- Downloads fetch each chunk with a Range request and decrypt it. Chrome writes
  straight to disk through the save-file picker; other browsers assemble the file in
  memory.

What it does not cover: the server delivers the page's JavaScript, so a party able to
rewrite that code in transit could make it leak the key. It also does not hide sizes,
upload times or which CODE made an upload.

## Managing keys and uploads

Run on the server, from this directory, with the app's virtualenv:

```
python manage.py code-add <label> [CODE[#SECRET]] [--max SIZE]   new key; prints CODE#SECRET once
python manage.py code-max <code> <SIZE|none>                     set or remove a key's size limit
python manage.py code-rename <code> <label>                      change a key's label
python manage.py code-list                                       keys, uses and space used
python manage.py code-del <code>                                 revoke a key
python manage.py uploads                                         list all uploads
python manage.py delete <uuid>                                   delete an upload
python manage.py decrypt [out-dir] [uuid]                        decrypt a key's uploads locally
```

SIZE is `500M`, `2G`, `1.5T` or plain bytes, 1024-based. `decrypt` prompts for the
full `CODE#SECRET` without echoing it and writes to `out-dir/<date>_<upload-id>/`.

A size limit counts everything uploaded with the key plus the upload in progress; an
upload that would go over is stopped and its partial data deleted.

The server writes each chunk straight into its file at the offset the browser gives,
so chunks can arrive in any order. Finalize checks every chunk arrived. A failed
chunk is retried three times; a cancelled or failed upload is deleted, and anything
unfinished and untouched for a day is swept away on the next finish or cancel.

## Running it

Flask behind gunicorn, as a systemd user service (`transfer.service` in this
directory):

```
gunicorn -w 2 --worker-class gthread --threads 8 -b 0.0.0.0:5001 --timeout 120 --access-logfile - app:app
```

Python dependencies: `flask` and `gunicorn` for the app, `cryptography` for
`manage.py`.

Public traffic arrives through a Cloudflare tunnel. The app uses Cloudflare's
`CF-Connecting-IP` header for login history and only sets its session cookie over
HTTPS.

## Files

| Path | |
|---|---|
| `app.py` | The web app. |
| `manage.py` | Key and upload management, and local decryption. |
| `static/e2e.js` | Browser-side encryption, shared by every page. |
| `static/` images | `favicon.ico`, `icon-512.png`, `apple-touch-icon.png`; `banner.jpg` (this README), `og.jpg` (1280×640 project image and link preview) and `page-bg.jpg` (page background behind a semi-opaque content panel; its edges match `--page` in `base.html`). |
| `templates/` | Pages. |
| `tests/e2e_roundtrip.mjs` | Round trip against a running server: `node tests/e2e_roundtrip.mjs http://127.0.0.1:5001 'CODE#SECRET'`. Run it from this directory with a throwaway key; it leaves one upload behind to delete. |
| `tests/browser_upload.mjs` | Drives a real headless Chrome through the upload page with a throwaway key: `node tests/browser_upload.mjs http://localhost:5001 'CODE#SECRET' [--no-login]`. Checks it lands on My uploads with the name decrypted. |

Created at runtime and kept out of git: `transfer.db` (keys and login history),
`secret_key` (signs the session cookie), `uploads/`, `metadata/` and `staging/`.

## License

MIT. See `LICENSE`; reuse is free as long as the copyright notice comes along.
