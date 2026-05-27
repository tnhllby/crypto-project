"""
Personal Diary — FIXED (secure) version
=========================================
All vulnerabilities from the 'vulnerable' branch have been remediated.
FIXED comments explain what changed and why.

Run:
    python init_db.py   (first time only)
    python app.py
"""
import os
import sqlite3
import secrets
from datetime import datetime
from markupsafe import Markup, escape

from flask import (
    Flask, render_template, request, session,
    redirect, url_for, flash, send_from_directory,
)
from flask_swagger_ui import get_swaggerui_blueprint
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

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
        'app_name':               'Personal Diary — Security Lab API (Fixed)',
        'deepLinking':            True,
        'displayRequestDuration': True,
        'tryItOutEnabled':        True,
        'defaultModelsExpandDepth': 2,
        'defaultModelExpandDepth':  2,
    },
)
app.register_blueprint(swaggerui_bp)

# ─────────────────────────────────────────────────────────────────────────────
# FIXED #1: Strong random secret key loaded from environment variable.
# Falls back to a random 32-byte hex string for local development only.
# In production: export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
# ─────────────────────────────────────────────────────────────────────────────
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# ─────────────────────────────────────────────────────────────────────────────
# FIXED #2: Secure session cookie attributes.
# HttpOnly=True  → JavaScript cannot access the session cookie.
# SameSite='Lax' → Cookie not sent on cross-site requests (CSRF mitigation).
# Secure=False   → Set to True when running over HTTPS in production.
# ─────────────────────────────────────────────────────────────────────────────
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE']   = False   # Change to True behind HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

app.config['UPLOAD_FOLDER']      = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024   # 4 MB limit

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}


# ── Custom Jinja2 filter ─────────────────────────────────────────────────────

@app.template_filter('nl2br')
def nl2br_filter(text: str) -> Markup:
    """FIXED #7: Escape HTML then convert newlines to <br> — safe formatted output."""
    return Markup(escape(text).replace('\n', '<br>\n'))


# ── Helpers ──────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def allowed_file(filename: str) -> bool:
    """FIXED #6: Return True only for whitelisted image extensions."""
    return (
        '.' in filename
        and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    )


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

        if not username or not password or not email:
            flash('All fields are required.', 'error')
            return render_template('register.html')

        conn = get_db()
        cur  = conn.cursor()
        try:
            # FIXED #3: Parameterized query — no SQL injection possible.
            # FIXED #4: Password hashed with bcrypt before storage.
            cur.execute(
                "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), email),
            )
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.rollback()
            flash('Username or email already taken.', 'error')
        except Exception:
            conn.rollback()
            # FIXED: Generic error — no internal details exposed to client.
            flash('Registration failed. Please try again.', 'error')
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
            # FIXED #3: Parameterized query for login lookup.
            cur.execute(
                "SELECT id, username, password, is_admin FROM users WHERE username = ?",
                (username,),
            )
            user = cur.fetchone()
        finally:
            cur.close()
            conn.close()

        # FIXED #4: Compare with bcrypt hash — never plaintext.
        if user and check_password_hash(user[2], password):
            # FIXED #2: Regenerate session to prevent session fixation.
            session.clear()
            session['user_id']  = user[0]
            session['username'] = user[1]
            session['is_admin'] = user[3]
            return redirect(url_for('dashboard'))
        else:
            # Generic message — do not reveal whether username exists.
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
    # FIXED #3: Parameterized query.
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

        valid_moods = {'happy', 'sad', 'neutral', 'excited', 'anxious', 'calm'}
        if mood not in valid_moods:
            mood = 'neutral'

        if not title:
            flash('Title is required.', 'error')
            return render_template('note_create.html')

        now  = datetime.now().isoformat(timespec='seconds')
        conn = get_db()
        cur  = conn.cursor()
        try:
            # FIXED #3: Parameterized query — user input never touches SQL structure.
            cur.execute(
                "INSERT INTO notes (user_id, title, content, mood, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (session['user_id'], title, content, mood, now),
            )
            note_id = cur.lastrowid
            conn.commit()
            flash('Entry created!', 'success')
            return redirect(url_for('view_note', note_id=note_id))
        except Exception:
            conn.rollback()
            flash('Error saving note. Please try again.', 'error')
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
    # FIXED #5: Query includes user_id — ensures only the owner can view their note.
    cur.execute(
        "SELECT id, title, content, mood, created_at, user_id FROM notes "
        "WHERE id = ? AND user_id = ?",
        (note_id, session['user_id']),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        # Return 404-like — do not reveal whether note exists for another user.
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
    # FIXED #5: user_id condition prevents deleting another user's notes.
    cur.execute(
        "DELETE FROM notes WHERE id = ? AND user_id = ?",
        (note_id, session['user_id']),
    )
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
            # FIXED #6a: Reject files with disallowed extensions.
            if not allowed_file(file.filename):
                flash('Only image files are allowed (png, jpg, jpeg, gif, webp).', 'error')
                cur.close()
                conn.close()
                return redirect(url_for('profile'))

            # FIXED #6b: secure_filename strips path separators and dangerous characters.
            filename = secure_filename(file.filename)
            if not filename:
                flash('Invalid filename.', 'error')
                cur.close()
                conn.close()
                return redirect(url_for('profile'))

            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            # FIXED #3: Parameterized update.
            cur.execute(
                "UPDATE users SET avatar = ? WHERE id = ?",
                (filename, session['user_id']),
            )
            conn.commit()
            flash('Profile picture updated!', 'success')

    # FIXED #3: Parameterized select.
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
    # FIXED #6: send_from_directory prevents directory traversal.
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/admin')
def admin():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # FIXED #7 (Access Control): Re-verify is_admin from the database on every
    # admin request — do not rely solely on the session value.
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT is_admin FROM users WHERE id = ?", (session['user_id'],))
    row = cur.fetchone()

    if not row or not row[0]:
        cur.close()
        conn.close()
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))

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
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # FIXED: Re-verify admin status from DB before destructive action.
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT is_admin FROM users WHERE id = ?", (session['user_id'],))
    row = cur.fetchone()
    if not row or not row[0]:
        cur.close()
        conn.close()
        return redirect(url_for('login'))

    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    cur.close()
    conn.close()

    flash('User deleted.', 'success')
    return redirect(url_for('admin'))


if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    # FIXED: debug=False in production.
    debug_mode = os.environ.get('DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode, host='127.0.0.1', port=5000)
