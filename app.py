"""
Personal Diary — VULNERABLE version
====================================
⚠️  FOR EDUCATIONAL PURPOSES ONLY ⚠️
This application intentionally contains security vulnerabilities.
DO NOT deploy to production or expose to the internet.

Run:
    python init_db.py   (first time only)
    python app.py
"""
import os
import sqlite3
from datetime import datetime
from flask import (
    Flask, render_template, request, session,
    redirect, url_for, flash, send_from_directory,
)
from flask_swagger_ui import get_swaggerui_blueprint
from api import api as api_blueprint
from config import DB_PATH, UPLOAD_FOLDER

app = Flask(__name__)

# ── API Blueprint ────────────────────────────────────────────────────────────
app.register_blueprint(api_blueprint)

# ── Swagger UI ───────────────────────────────────────────────────────────────
swaggerui_bp = get_swaggerui_blueprint(
    '/api/docs',
    '/static/swagger.yaml',
    config={
        'app_name':              'Personal Diary — Security Lab API',
        'deepLinking':           True,
        'displayRequestDuration': True,
        'tryItOutEnabled':       True,
        'defaultModelsExpandDepth': 2,
        'defaultModelExpandDepth':  2,
    },
)
app.register_blueprint(swaggerui_bp)

# ─────────────────────────────────────────────────────────────────────────────
# VULNERABILITY #1: Weak, hardcoded secret key
# A short predictable key lets an attacker forge Flask session cookies with
# tools like flask-unsign, giving them arbitrary session values (e.g. is_admin=True).
# ─────────────────────────────────────────────────────────────────────────────
app.secret_key = "secret123"

# ─────────────────────────────────────────────────────────────────────────────
# VULNERABILITY #2: Insecure session cookie configuration
# HttpOnly=False → JavaScript can read the session cookie (XSS → session theft).
# SameSite=None  → cross-site requests carry the cookie (CSRF-friendly).
# Secure=False   → cookie sent over plain HTTP (eavesdropping possible).
# ─────────────────────────────────────────────────────────────────────────────
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['SESSION_COOKIE_SECURE']   = False
app.config['SESSION_COOKIE_SAMESITE'] = None

app.config['UPLOAD_FOLDER']      = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB


# ── Database helper ──────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def parse_dt(value):
    """Convert SQLite datetime string to Python datetime."""
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return value
    return value


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        email    = request.form.get('email', '').strip()

        conn = get_db()
        cur  = conn.cursor()
        try:
            # ─────────────────────────────────────────────────────────────────
            # VULNERABILITY #3: SQL Injection
            # User-supplied values are interpolated directly into the query
            # string.  An attacker can inject arbitrary SQL.
            # ─────────────────────────────────────────────────────────────────
            # VULNERABILITY #4: Plaintext password storage
            # Passwords are stored as-is — a DB dump immediately reveals them.
            # ─────────────────────────────────────────────────────────────────
            query = (
                f"INSERT INTO users (username, password, email) "
                f"VALUES ('{username}', '{password}', '{email}')"
            )
            cur.execute(query)
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.rollback()
            flash('Username or email already taken.', 'error')
        except Exception as e:
            conn.rollback()
            # VULNERABILITY: detailed DB error exposed to the user
            flash(f'Database error: {e}', 'error')
        finally:
            cur.close()
            conn.close()

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        conn = get_db()
        cur  = conn.cursor()
        try:
            # ─────────────────────────────────────────────────────────────────
            # VULNERABILITY #3 (continued): SQL Injection in login
            # Classic bypass: username = ' OR '1'='1'--
            # VULNERABILITY #4 (continued): password compared as plaintext
            # ─────────────────────────────────────────────────────────────────
            query = (
                f"SELECT id, username, is_admin FROM users "
                f"WHERE username='{username}' AND password='{password}'"
            )
            cur.execute(query)
            user = cur.fetchone()
        finally:
            cur.close()
            conn.close()

        if user:
            # VULNERABILITY #2 (continued): session not regenerated after login
            # (session fixation — attacker can pre-set a session ID)
            session['user_id']  = user[0]
            session['username'] = user[1]
            session['is_admin'] = user[2]
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "SELECT id, title, mood, created_at FROM notes "
        "WHERE user_id = ? ORDER BY created_at DESC",
        (session['user_id'],),
    )
    rows  = cur.fetchall()
    cur.close()
    conn.close()

    notes = [(r[0], r[1], r[2], parse_dt(r[3])) for r in rows]
    return render_template('dashboard.html', notes=notes)


@app.route('/note/create', methods=['GET', 'POST'])
def create_note():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title   = request.form.get('title', '').strip()
        content = request.form.get('content', '')
        mood    = request.form.get('mood', 'neutral')
        now     = datetime.now().isoformat(timespec='seconds')

        conn = get_db()
        cur  = conn.cursor()
        try:
            # ─────────────────────────────────────────────────────────────────
            # VULNERABILITY #3 (continued): SQL Injection in note creation
            # Content with quotes or SQL syntax can break or hijack the query.
            # ─────────────────────────────────────────────────────────────────
            query = (
                f"INSERT INTO notes (user_id, title, content, mood, created_at) "
                f"VALUES ({session['user_id']}, '{title}', '{content}', '{mood}', '{now}')"
            )
            cur.execute(query)
            note_id = cur.lastrowid
            conn.commit()
            flash('Entry created!', 'success')
            return redirect(url_for('view_note', note_id=note_id))
        except Exception as e:
            conn.rollback()
            flash(f'Error saving note: {e}', 'error')
        finally:
            cur.close()
            conn.close()

    return render_template('note_create.html')


@app.route('/note/<int:note_id>')
def view_note(note_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    cur  = conn.cursor()
    # ─────────────────────────────────────────────────────────────────────────
    # VULNERABILITY #5: IDOR — Insecure Direct Object Reference
    # Any logged-in user can read ANY note by changing the note_id in the URL.
    # There is no check that note_id belongs to session['user_id'].
    # ─────────────────────────────────────────────────────────────────────────
    cur.execute(
        "SELECT id, title, content, mood, created_at, user_id FROM notes WHERE id = ?",
        (note_id,),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        flash('Note not found.', 'error')
        return redirect(url_for('dashboard'))

    note = (row[0], row[1], row[2], row[3], parse_dt(row[4]), row[5])
    return render_template('note_view.html', note=note)


@app.route('/note/<int:note_id>/delete', methods=['POST'])
def delete_note(note_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    cur  = conn.cursor()
    # ─────────────────────────────────────────────────────────────────────────
    # VULNERABILITY #5 (continued): IDOR — any user can delete any note
    # ─────────────────────────────────────────────────────────────────────────
    cur.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    conn.commit()
    cur.close()
    conn.close()

    flash('Entry deleted.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    cur  = conn.cursor()

    if request.method == 'POST':
        file = request.files.get('avatar')
        if file and file.filename:
            # ─────────────────────────────────────────────────────────────────
            # VULNERABILITY #6: Unrestricted File Upload
            # No validation of MIME type or file extension.
            # Attacker can upload .py / .exe / .html files.
            # VULNERABILITY #6b: Path Traversal
            # Filename not sanitised — e.g. "../../app.py" overwrites source.
            # ─────────────────────────────────────────────────────────────────
            filename  = file.filename  # raw, unsanitised
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(save_path)
            cur.execute(
                "UPDATE users SET avatar = ? WHERE id = ?",
                (filename, session['user_id']),
            )
            conn.commit()
            flash('Profile picture updated!', 'success')

    cur.execute(
        "SELECT id, username, email, avatar, created_at FROM users WHERE id = ?",
        (session['user_id'],),
    )
    row  = cur.fetchone()
    cur.close()
    conn.close()

    user = (row[0], row[1], row[2], row[3], parse_dt(row[4]))
    return render_template('profile.html', user=user)


@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    # VULNERABILITY: serves any file from uploads dir, including scripts
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/admin')
def admin():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # ─────────────────────────────────────────────────────────────────────────
    # VULNERABILITY #7: Broken Access Control via forged session
    # is_admin is read from the Flask session cookie, which is signed with the
    # weak secret key (#1).  An attacker who forges the session can set
    # is_admin=True and gain full admin access without a real admin account.
    # ─────────────────────────────────────────────────────────────────────────
    if not session.get('is_admin'):
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))

    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT id, username, email, is_admin, created_at FROM users ORDER BY id")
    users = [(r[0], r[1], r[2], r[3], parse_dt(r[4])) for r in cur.fetchall()]

    cur.execute(
        "SELECT n.id, n.title, u.username, n.created_at "
        "FROM notes n JOIN users u ON n.user_id = u.id ORDER BY n.created_at DESC"
    )
    all_notes = [(r[0], r[1], r[2], parse_dt(r[3])) for r in cur.fetchall()]
    cur.close()
    conn.close()

    return render_template('admin.html', users=users, all_notes=all_notes)


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))

    conn = get_db()
    cur  = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    cur.close()
    conn.close()

    flash('User deleted.', 'success')
    return redirect(url_for('admin'))


if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    # VULNERABILITY: debug=True exposes interactive debugger
    app.run(debug=True, host='0.0.0.0', port=5000)
