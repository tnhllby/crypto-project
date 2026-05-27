"""
REST API Blueprint — VULNERABLE version
=========================================
JSON API that mirrors the web interface with the same security flaws.
Swagger UI is available at /api/docs

⚠️ FOR EDUCATIONAL PURPOSES ONLY
"""
import sqlite3
from datetime import datetime
from functools import wraps
from flask import Blueprint, request, jsonify, session
from config import DB_PATH

api = Blueprint('api', __name__, url_prefix='/api')


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


# ── Auth ─────────────────────────────────────────────────────────────────────

@api.route('/auth/login', methods=['POST'])
def api_login():
    """
    Войти в аккаунт.
    ---
    tags:
      - auth
    """
    data     = request.get_json(force=True) or {}
    username = str(data.get('username', '')).strip()
    password = str(data.get('password', ''))

    if not username or not password:
        return jsonify({'error': 'username and password are required'}), 400

    conn = get_db()
    cur  = conn.cursor()
    try:
        # ─────────────────────────────────────────────────────────────────────
        # VULNERABILITY #3: SQL Injection
        # username и password вставляются напрямую в строку запроса.
        # Bypass: username = "admin'--"  (пароль не важен)
        # ─────────────────────────────────────────────────────────────────────
        # VULNERABILITY #4: пароль сравнивается в открытом виде
        # ─────────────────────────────────────────────────────────────────────
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
        session['user_id']  = user[0]
        session['username'] = user[1]
        session['is_admin'] = user[2]
        return jsonify({
            'message':  'Login successful',
            'user': {
                'id':       user[0],
                'username': user[1],
                'is_admin': bool(user[2]),
            }
        })
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
        # ─────────────────────────────────────────────────────────────────────
        # VULNERABILITY #3: SQL Injection в регистрации
        # VULNERABILITY #4: пароль хранится в открытом виде
        # ─────────────────────────────────────────────────────────────────────
        query = (
            f"INSERT INTO users (username, password, email) "
            f"VALUES ('{username}', '{password}', '{email}')"
        )
        cur.execute(query)
        conn.commit()
        return jsonify({'message': 'Registration successful'}), 201
    except sqlite3.IntegrityError:
        conn.rollback()
        return jsonify({'error': 'Username or email already taken'}), 409
    except Exception as e:
        conn.rollback()
        # VULNERABILITY: детали ошибки раскрываются клиенту
        return jsonify({'error': str(e)}), 500
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
    now     = datetime.now().isoformat(timespec='seconds')

    if not title:
        return jsonify({'error': 'title is required'}), 400

    conn = get_db()
    cur  = conn.cursor()
    try:
        # ─────────────────────────────────────────────────────────────────────
        # VULNERABILITY #3: SQL Injection в title / content / mood
        # ─────────────────────────────────────────────────────────────────────
        query = (
            f"INSERT INTO notes (user_id, title, content, mood, created_at) "
            f"VALUES ({session['user_id']}, '{title}', '{content}', '{mood}', '{now}')"
        )
        cur.execute(query)
        note_id = cur.lastrowid
        conn.commit()
        return jsonify({'message': 'Note created', 'note_id': note_id}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()


@api.route('/notes/<int:note_id>', methods=['GET'])
@auth_required
def api_get_note(note_id):
    conn = get_db()
    cur  = conn.cursor()
    # ─────────────────────────────────────────────────────────────────────────
    # VULNERABILITY #5: IDOR
    # Запрос не содержит user_id — любой авторизованный пользователь может
    # прочитать любую заметку, просто изменив note_id в URL.
    # ─────────────────────────────────────────────────────────────────────────
    cur.execute(
        "SELECT id, title, content, mood, created_at, user_id FROM notes WHERE id = ?",
        (note_id,),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        return jsonify({'error': 'Note not found'}), 404

    return jsonify({
        'id':         row[0],
        'title':      row[1],
        'content':    row[2],
        'mood':       row[3],
        'created_at': parse_dt(row[4]),
        'user_id':    row[5],   # видно чужой user_id — утечка информации
    })


@api.route('/notes/<int:note_id>', methods=['DELETE'])
@auth_required
def api_delete_note(note_id):
    conn = get_db()
    cur  = conn.cursor()
    # ─────────────────────────────────────────────────────────────────────────
    # VULNERABILITY #5: IDOR — удаление чужих заметок без проверки владельца
    # ─────────────────────────────────────────────────────────────────────────
    cur.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    deleted = cur.rowcount
    conn.commit()
    cur.close()
    conn.close()

    if deleted == 0:
        return jsonify({'error': 'Note not found'}), 404
    return jsonify({'message': f'Note {note_id} deleted'})


# ── Admin ─────────────────────────────────────────────────────────────────────

@api.route('/admin/users', methods=['GET'])
@auth_required
def api_admin_users():
    # ─────────────────────────────────────────────────────────────────────────
    # VULNERABILITY #7: Broken Access Control
    # Проверка только по значению в сессии (cookie).
    # При слабом секретном ключе (#1) сессию можно подделать.
    # ─────────────────────────────────────────────────────────────────────────
    if not session.get('is_admin'):
        return jsonify({'error': 'Admin access required'}), 403

    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "SELECT id, username, email, password, is_admin, created_at FROM users ORDER BY id"
    )
    # VULNERABILITY: возвращаем поле password (plaintext) в API-ответе
    users = [
        {
            'id':         r[0],
            'username':   r[1],
            'email':      r[2],
            'password':   r[3],   # открытый пароль в ответе!
            'is_admin':   bool(r[4]),
            'created_at': parse_dt(r[5]),
        }
        for r in cur.fetchall()
    ]
    cur.close()
    conn.close()
    return jsonify(users)


@api.route('/admin/users/<int:user_id>', methods=['DELETE'])
@auth_required
def api_delete_user(user_id):
    if not session.get('is_admin'):
        return jsonify({'error': 'Admin access required'}), 403

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
@auth_required
def api_admin_notes():
    if not session.get('is_admin'):
        return jsonify({'error': 'Admin access required'}), 403

    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "SELECT n.id, n.title, n.content, n.mood, u.username, n.created_at "
        "FROM notes n JOIN users u ON n.user_id = u.id ORDER BY n.created_at DESC"
    )
    notes = [
        {
            'id': r[0], 'title': r[1], 'content': r[2],
            'mood': r[3], 'author': r[4], 'created_at': parse_dt(r[5]),
        }
        for r in cur.fetchall()
    ]
    cur.close()
    conn.close()
    return jsonify(notes)
