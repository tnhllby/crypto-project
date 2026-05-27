"""
REST API Blueprint — FIXED (secure) version
=============================================
All vulnerabilities from the vulnerable branch have been remediated.
FIXED comments explain what changed and why.
"""
import sqlite3
from datetime import datetime
from functools import wraps
from flask import Blueprint, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from config import DB_PATH

api = Blueprint('api', __name__, url_prefix='/api')

ALLOWED_MOODS = {'happy', 'sad', 'neutral', 'excited', 'anxious', 'calm'}


# ── Helpers ──────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def parse_dt(value):
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value).isoformat()
        except ValueError:
            return value
    return str(value) if value else None


def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required. POST /api/auth/login first.'}), 401
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """FIXED #7: Re-verify admin status from DB on every sensitive request."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("SELECT is_admin FROM users WHERE id = ?", (session['user_id'],))
        row = cur.fetchone()
        cur.close()
        conn.close()
        if not row or not row[0]:
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated


# ── Auth ─────────────────────────────────────────────────────────────────────

@api.route('/auth/login', methods=['POST'])
def api_login():
    data     = request.get_json(force=True) or {}
    username = str(data.get('username', '')).strip()
    password = str(data.get('password', ''))

    if not username or not password:
        return jsonify({'error': 'username and password are required'}), 400

    conn = get_db()
    cur  = conn.cursor()
    try:
        # FIXED #3: Parameterized query — SQL injection not possible.
        cur.execute(
            "SELECT id, username, password, is_admin FROM users WHERE username = ?",
            (username,),
        )
        user = cur.fetchone()
    finally:
        cur.close()
        conn.close()

    # FIXED #4: Compare against bcrypt hash, never plaintext.
    if user and check_password_hash(user[2], password):
        # FIXED #2: Clear session before setting new values (session fixation prevention).
        session.clear()
        session['user_id']  = user[0]
        session['username'] = user[1]
        session['is_admin'] = user[3]
        return jsonify({
            'message': 'Login successful',
            'user': {
                'id':       user[0],
                'username': user[1],
                'is_admin': bool(user[3]),
            }
        })
    # FIXED: Generic error — do not reveal whether username exists.
    return jsonify({'error': 'Invalid username or password'}), 401


@api.route('/auth/register', methods=['POST'])
def api_register():
    data     = request.get_json(force=True) or {}
    username = str(data.get('username', '')).strip()
    password = str(data.get('password', ''))
    email    = str(data.get('email', '')).strip()

    if not username or not password or not email:
        return jsonify({'error': 'username, password and email are required'}), 400

    conn = get_db()
    cur  = conn.cursor()
    try:
        # FIXED #3: Parameterized query.
        # FIXED #4: Password hashed with bcrypt before storage.
        cur.execute(
            "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), email),
        )
        conn.commit()
        return jsonify({'message': 'Registration successful'}), 201
    except sqlite3.IntegrityError:
        conn.rollback()
        return jsonify({'error': 'Username or email already taken'}), 409
    except Exception:
        conn.rollback()
        # FIXED: Generic error — no internal DB details exposed.
        return jsonify({'error': 'Registration failed. Please try again.'}), 500
    finally:
        cur.close()
        conn.close()


@api.route('/auth/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'})


@api.route('/auth/me', methods=['GET'])
@auth_required
def api_me():
    return jsonify({
        'user_id':  session['user_id'],
        'username': session['username'],
        'is_admin': bool(session.get('is_admin', False)),
    })


# ── Notes ─────────────────────────────────────────────────────────────────────

@api.route('/notes', methods=['GET'])
@auth_required
def api_get_notes():
    conn = get_db()
    cur  = conn.cursor()
    # FIXED #3: Parameterized query.
    cur.execute(
        "SELECT id, title, mood, created_at FROM notes "
        "WHERE user_id = ? ORDER BY created_at DESC",
        (session['user_id'],),
    )
    notes = [
        {'id': r[0], 'title': r[1], 'mood': r[2], 'created_at': parse_dt(r[3])}
        for r in cur.fetchall()
    ]
    cur.close()
    conn.close()
    return jsonify(notes)


@api.route('/notes', methods=['POST'])
@auth_required
def api_create_note():
    data    = request.get_json(force=True) or {}
    title   = str(data.get('title', '')).strip()
    content = str(data.get('content', ''))
    mood    = str(data.get('mood', 'neutral'))

    if not title:
        return jsonify({'error': 'title is required'}), 400

    # FIXED: Validate mood against a whitelist.
    if mood not in ALLOWED_MOODS:
        mood = 'neutral'

    now  = datetime.now().isoformat(timespec='seconds')
    conn = get_db()
    cur  = conn.cursor()
    try:
        # FIXED #3: All fields as parameterized placeholders.
        cur.execute(
            "INSERT INTO notes (user_id, title, content, mood, created_at) VALUES (?, ?, ?, ?, ?)",
            (session['user_id'], title, content, mood, now),
        )
        note_id = cur.lastrowid
        conn.commit()
        return jsonify({'message': 'Note created', 'note_id': note_id}), 201
    except Exception:
        conn.rollback()
        return jsonify({'error': 'Failed to create note. Please try again.'}), 500
    finally:
        cur.close()
        conn.close()


@api.route('/notes/<int:note_id>', methods=['GET'])
@auth_required
def api_get_note(note_id):
    conn = get_db()
    cur  = conn.cursor()
    # FIXED #5: user_id included in WHERE clause — IDOR prevented.
    cur.execute(
        "SELECT id, title, content, mood, created_at FROM notes "
        "WHERE id = ? AND user_id = ?",
        (note_id, session['user_id']),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        # FIXED: Return 404 regardless of whether note exists for another user.
        return jsonify({'error': 'Note not found'}), 404

    return jsonify({
        'id':         row[0],
        'title':      row[1],
        'content':    row[2],
        'mood':       row[3],
        'created_at': parse_dt(row[4]),
        # FIXED: user_id not exposed in API response.
    })


@api.route('/notes/<int:note_id>', methods=['DELETE'])
@auth_required
def api_delete_note(note_id):
    conn = get_db()
    cur  = conn.cursor()
    # FIXED #5: user_id in WHERE prevents deleting another user's notes.
    cur.execute(
        "DELETE FROM notes WHERE id = ? AND user_id = ?",
        (note_id, session['user_id']),
    )
    deleted = cur.rowcount
    conn.commit()
    cur.close()
    conn.close()

    if deleted == 0:
        return jsonify({'error': 'Note not found'}), 404
    return jsonify({'message': f'Note {note_id} deleted'})


# ── Admin ─────────────────────────────────────────────────────────────────────

@api.route('/admin/users', methods=['GET'])
@admin_required
def api_admin_users():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "SELECT id, username, email, is_admin, created_at FROM users ORDER BY id"
    )
    # FIXED #4 + API security: password field is NOT returned in the response.
    users = [
        {
            'id':         r[0],
            'username':   r[1],
            'email':      r[2],
            'is_admin':   bool(r[3]),
            'created_at': parse_dt(r[4]),
        }
        for r in cur.fetchall()
    ]
    cur.close()
    conn.close()
    return jsonify(users)


@api.route('/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def api_delete_user(user_id):
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    deleted = cur.rowcount
    conn.commit()
    cur.close()
    conn.close()

    if deleted == 0:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'message': f'User {user_id} deleted'})


@api.route('/admin/notes', methods=['GET'])
@admin_required
def api_admin_notes():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "SELECT n.id, n.title, n.mood, u.username, n.created_at "
        "FROM notes n JOIN users u ON n.user_id = u.id ORDER BY n.created_at DESC"
    )
    # FIXED: content not included to avoid leaking sensitive data in list view.
    notes = [
        {
            'id': r[0], 'title': r[1], 'mood': r[2],
            'author': r[3], 'created_at': parse_dt(r[4]),
        }
        for r in cur.fetchall()
    ]
    cur.close()
    conn.close()
    return jsonify(notes)
