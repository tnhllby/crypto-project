"""
Database initializer — vulnerable version.
Run once before starting the app: python init_db.py
"""
import sqlite3
from config import DB_PATH


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()
    cur.execute("PRAGMA foreign_keys = ON")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT UNIQUE NOT NULL,
            -- VULNERABILITY: password stored as plain text — no hashing
            password   TEXT NOT NULL,
            email      TEXT UNIQUE NOT NULL,
            is_admin   INTEGER DEFAULT 0,
            avatar     TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
            title      TEXT NOT NULL,
            content    TEXT,
            mood       TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)

    # VULNERABILITY: Admin created with plaintext password stored in DB
    cur.execute("SELECT 1 FROM users WHERE username = 'admin'")
    if not cur.fetchone():
        cur.execute(
            "INSERT INTO users (username, password, email, is_admin) VALUES ('admin', 'admin123', 'admin@diary.local', 1)"
        )
        print("[+] Created default admin  |  username: admin  |  password: admin123")

    cur.execute("SELECT 1 FROM users WHERE username = 'alice'")
    if not cur.fetchone():
        cur.execute(
            "INSERT INTO users (username, password, email) VALUES ('alice', 'alice123', 'alice@diary.local')"
        )
        print("[+] Created demo user      |  username: alice  |  password: alice123")

    conn.commit()
    cur.close()
    conn.close()
    print("[+] Database initialized successfully!")


if __name__ == '__main__':
    init_db()
