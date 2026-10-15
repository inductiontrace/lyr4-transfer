import os
import uuid
import json
import shutil
import sqlite3
from datetime import datetime, timezone
from flask import Flask, request, render_template, abort, send_from_directory, url_for, jsonify, session, redirect
from werkzeug.utils import secure_filename

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOADS_DIR = os.path.join(BASE_DIR, 'uploads')
METADATA_DIR = os.path.join(BASE_DIR, 'metadata')
STAGING_DIR = os.path.join(BASE_DIR, 'staging')
DB_PATH = os.path.join(BASE_DIR, 'transfer.db')
SECRET_KEY_PATH = os.path.join(BASE_DIR, 'secret_key')


def load_secret_key():
    """Read the session signing key, creating it once; both workers race here."""
    if not os.path.exists(SECRET_KEY_PATH):
        tmp = f'{SECRET_KEY_PATH}.{os.getpid()}'
        with open(tmp, 'w') as f:
            f.write(os.urandom(32).hex())
        os.chmod(tmp, 0o600)
        try:
            os.link(tmp, SECRET_KEY_PATH)
        except FileExistsError:
            pass
        os.unlink(tmp)
    with open(SECRET_KEY_PATH) as f:
        return f.read().strip()


app.secret_key = load_secret_key()
app.config['SESSION_COOKIE_SECURE'] = True

# Each chunk is ≤50 MB; allow a little headroom
app.config['MAX_CONTENT_LENGTH'] = 60 * 1024 * 1024  # 60 MB per request

for d in (UPLOADS_DIR, METADATA_DIR, STAGING_DIR):
    os.makedirs(d, exist_ok=True)


# ─── DB ──────────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as db:
        db.execute('''
            CREATE TABLE IF NOT EXISTS auth_codes (
                code        TEXT PRIMARY KEY,
                label       TEXT,
                created_at  TEXT,
                uses        INTEGER DEFAULT 0,
                max_bytes   INTEGER
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS logins (
                code  TEXT,
                at    TEXT,
                ip    TEXT
            )
        ''')


def record_login(code):
    """Store this login; returns its timestamp so the page can mark it."""
    ip = request.headers.get('CF-Connecting-IP', request.remote_addr)
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute('INSERT INTO logins (code, at, ip) VALUES (?, ?, ?)', (code, now, ip))
    return now


def login_history(code):
    with get_db() as db:
        return db.execute(
            'SELECT at, ip FROM logins WHERE code = ? ORDER BY at DESC', (code,)
        ).fetchall()


def check_auth_code(code):
    """Validate code — no side effects."""
    with get_db() as db:
        return db.execute(
            'SELECT 1 FROM auth_codes WHERE code = ?', (code,)
        ).fetchone() is not None


def consume_auth_code(code):
    """Validate and increment use count. Call once per completed upload."""
    with get_db() as db:
        return db.execute('UPDATE auth_codes SET uses = uses + 1 WHERE code = ?', (code,)).rowcount > 0


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    abort(404)


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(app.static_folder, 'favicon.ico')


@app.route('/upload', methods=['GET'])
def upload_form():
    return render_template('upload.html', auth_code=_session_code())


@app.route('/files/<code>')
def login(code):
    """Log in with /files/CODE#SECRET. The redirect carries #SECRET along
    (browsers keep the fragment when Location has none); the server never sees it."""
    if not check_auth_code(code):
        return render_template('files.html', uploads=None, error='Invalid upload key'), 403
    session['auth_code'] = code
    session['login_at'] = record_login(code)
    return redirect(url_for('my_files'))


@app.route('/files')
def my_files():
    """The upload key is the login; list everything uploaded with it."""
    code = _session_code()
    if not code:
        return render_template('files.html', uploads=None, error=None)
    uploads = _uploads_for(code)
    key = _key_row(code)
    return render_template('files.html', uploads=uploads, label=key['label'],
                           used=_committed_bytes(uploads), max_bytes=key['max_bytes'],
                           logins=login_history(code), login_at=session.get('login_at'), error=None)


@app.route('/files/logout', methods=['POST'])
def logout():
    session.pop('auth_code', None)
    session.pop('login_at', None)
    return redirect(url_for('my_files'))


@app.route('/upload/chunk', methods=['POST'])
def upload_chunk():
    """Accept a single chunk of a file within a multi-file upload session."""
    auth_code   = request.form.get('auth_code', '').strip()
    upload_id   = request.form.get('upload_id', '').strip()
    filename    = request.form.get('filename', '').strip()

    try:
        uuid.UUID(upload_id)
    except ValueError:
        return jsonify({'error': 'Invalid upload session'}), 400

    # The indexes become path components, so only plain integers get through
    try:
        file_index  = int(request.form.get('file_index', '0'))
        chunk_index = int(request.form.get('chunk_index', '0'))
        chunk_total = int(request.form.get('chunk_total', '1'))
    except ValueError:
        return jsonify({'error': 'Invalid chunk position'}), 400
    if file_index < 0 or not 0 <= chunk_index < chunk_total:
        return jsonify({'error': 'Invalid chunk position'}), 400

    # Validate auth on every chunk (no increment yet — charged on completion)
    if not check_auth_code(auth_code):
        return jsonify({'error': 'Invalid upload key'}), 403

    chunk_file = request.files.get('chunk')
    if not chunk_file:
        return jsonify({'error': 'No chunk data'}), 400

    # Save chunk to staging/<upload_id>_<file_index>/chunk_NNNNNN
    staging_dir = os.path.join(STAGING_DIR, f'{upload_id}_{file_index}')
    os.makedirs(staging_dir, exist_ok=True)
    chunk_file.save(os.path.join(staging_dir, f'chunk_{chunk_index:06d}'))

    max_bytes = _key_row(auth_code)['max_bytes']
    if max_bytes is not None:
        committed = _committed_bytes(_uploads_for(auth_code))
        if committed + _session_bytes(upload_id) > max_bytes:
            _discard_session(upload_id)
            return jsonify({'error': f"This upload would go over the key's {_fmt_size(max_bytes)} "
                                     f"limit ({_fmt_size(committed)} already used)."}), 413

    # Not the last chunk — ack and continue
    if chunk_index < chunk_total - 1:
        return jsonify({'done': False, 'received': chunk_index})

    # ── Last chunk: assemble file into uploads/<upload_id>/<filename> ─────────
    safe_filename = secure_filename(filename)
    if not safe_filename:
        shutil.rmtree(staging_dir, ignore_errors=True)
        return jsonify({'error': 'Invalid filename'}), 400

    upload_dir = os.path.join(UPLOADS_DIR, upload_id)
    os.makedirs(upload_dir, exist_ok=True)

    # Deduplicate filenames within the same upload session
    final_path = os.path.join(upload_dir, safe_filename)
    if os.path.exists(final_path):
        name, ext = os.path.splitext(safe_filename)
        counter = 1
        while os.path.exists(final_path):
            safe_filename = f'{name}_{counter}{ext}'
            final_path = os.path.join(upload_dir, safe_filename)
            counter += 1

    try:
        with open(final_path, 'wb') as out:
            for i in range(chunk_total):
                cp = os.path.join(staging_dir, f'chunk_{i:06d}')
                with open(cp, 'rb') as cf:
                    shutil.copyfileobj(cf, out)
    except Exception as e:
        return jsonify({'error': f'Assembly failed: {e}'}), 500
    finally:
        shutil.rmtree(staging_dir, ignore_errors=True)

    size = os.path.getsize(final_path)
    return jsonify({'done': True, 'filename': safe_filename, 'size': size})


@app.route('/upload/finalize', methods=['POST'])
def upload_finalize():
    """Finalize a multi-file upload session by writing its metadata. The browser
    builds the share link itself, since only it holds the key that goes after '#'."""
    auth_code = request.json.get('auth_code', '').strip()
    upload_id = request.json.get('upload_id', '').strip()
    files     = request.json.get('files', [])

    try:
        uuid.UUID(upload_id)
    except ValueError:
        return jsonify({'error': 'Invalid upload session'}), 400

    if not consume_auth_code(auth_code):
        return jsonify({'error': 'Invalid upload key'}), 403

    upload_dir = os.path.join(UPLOADS_DIR, upload_id)
    if not os.path.isdir(upload_dir):
        return jsonify({'error': 'No files found for this session'}), 400

    # Sizes come from disk, not the browser, so the key's size limit can't be understated
    for f in files:
        name = f.get('filename', '')
        path = os.path.join(upload_dir, name)
        if not name or secure_filename(name) != name or not os.path.isfile(path):
            return jsonify({'error': 'Unknown file in upload'}), 400
        f['size'] = os.path.getsize(path)

    meta = {
        'uuid': upload_id,
        'files': files,
        'uploaded_at': datetime.now(timezone.utc).isoformat(),
        'auth_code': auth_code,
        'encrypted': bool(request.json.get('encrypted')),
    }
    with open(os.path.join(METADATA_DIR, f'{upload_id}.json'), 'w') as f:
        json.dump(meta, f, indent=2)
    return jsonify({'done': True})


@app.route('/<file_uuid>')
def file_landing(file_uuid):
    meta = _load_meta(file_uuid)
    return render_template('landing.html', meta=meta, file_uuid=file_uuid)


@app.route('/dl/<file_uuid>/<filename>')
def file_download(file_uuid, filename):
    meta = _load_meta(file_uuid)
    valid_names = {f['filename'] for f in meta['files']}
    if filename not in valid_names:
        abort(404)
    upload_dir = os.path.join(UPLOADS_DIR, file_uuid)
    return send_from_directory(upload_dir, filename, as_attachment=True)


# ─── Error handlers ──────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'Chunk too large. Maximum chunk size is 50 MB.'}), 413


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _session_code():
    """The logged-in key, dropped if it has been revoked since login."""
    code = session.get('auth_code')
    if code and not check_auth_code(code):
        session.pop('auth_code', None)
        return None
    return code


def _key_row(code):
    with get_db() as db:
        return db.execute('SELECT label, max_bytes FROM auth_codes WHERE code = ?', (code,)).fetchone()


def _committed_bytes(uploads):
    return sum(f.get('size', 0) for m in uploads for f in m['files'])


def _dir_bytes(path):
    return sum(os.path.getsize(os.path.join(root, f))
               for root, _, files in os.walk(path) for f in files)


def _session_dirs(upload_id):
    """Everything an unfinished upload has written: assembled files and staged chunks."""
    dirs = [os.path.join(UPLOADS_DIR, upload_id)]
    dirs += [os.path.join(STAGING_DIR, d) for d in os.listdir(STAGING_DIR)
             if d.startswith(f'{upload_id}_')]
    return dirs


def _session_bytes(upload_id):
    return sum(_dir_bytes(d) for d in _session_dirs(upload_id))


def _discard_session(upload_id):
    for d in _session_dirs(upload_id):
        shutil.rmtree(d, ignore_errors=True)


def _uploads_for(code):
    uploads = []
    for fname in os.listdir(METADATA_DIR):
        if not fname.endswith('.json'):
            continue
        meta = _load_meta(fname[:-5])
        if meta.get('auth_code') == code:
            uploads.append(meta)
    uploads.sort(key=lambda m: m['uploaded_at'], reverse=True)
    return uploads


def _load_meta(file_uuid):
    try:
        uuid.UUID(file_uuid)
    except ValueError:
        abort(404)
    meta_path = os.path.join(METADATA_DIR, f'{file_uuid}.json')
    if not os.path.exists(meta_path):
        abort(404)
    with open(meta_path) as f:
        meta = json.load(f)
    # Normalize legacy single-file metadata
    if 'files' not in meta:
        meta['files'] = [{'filename': meta['filename'], 'size': meta['size']}]
    return meta


def _fmt_size(size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f'{size:.1f} {unit}'
        size /= 1024
    return f'{size:.1f} TB'


app.jinja_env.filters['fmt_size'] = _fmt_size


# ─── Init ────────────────────────────────────────────────────────────────────

init_db()

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5001)
