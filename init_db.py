"""
Database initializer — FIXED (secure) version.
Run once before starting the app: python init_db.py
"""
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from werkzeug.security import generate_password_hash
from config import DB_CONFIG


def init_db():
    # Step 1: Connect to default 'postgres' DB to create our database
    admin_cfg = {**DB_CONFIG, 'database': 'postgres'}
    conn = psycopg2.connect(**admin_cfg)
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()

    cur.execute("SELECT 1 FROM pg_catalog.pg_database WHERE datname = %s", (DB_CONFIG['database'],))
    if not cur.fetchone():
        cur.execute(f"CREATE DATABASE {DB_CONFIG['database']}")
        print(f"[+] Created database '{DB_CONFIG['database']}'")
    else:
        print(f"[~] Database '{DB_CONFIG['database']}' already exists")

    cur.close()
    conn.close()

    # Step 2: Connect to our database and create tables
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         SERIAL PRIMARY KEY,
            username   VARCHAR(50)  UNIQUE NOT NULL,
            -- FIXED: password column stores bcrypt hash, not plaintext
            password   VARCHAR(255) NOT NULL,
            email      VARCHAR(100) UNIQUE NOT NULL,
            is_admin   BOOLEAN DEFAULT FALSE,
            avatar     VARCHAR(255),
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id         SERIAL PRIMARY KEY,
            user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
            title      VARCHAR(200) NOT NULL,
            content    TEXT,
            mood       VARCHAR(50),
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)

    # FIXED: Passwords are hashed with bcrypt before storage
    cur.execute("SELECT 1 FROM users WHERE username = 'admin'")
    if not cur.fetchone():
        cur.execute(
            "INSERT INTO users (username, password, email, is_admin) VALUES (%s, %s, %s, %s)",
            ('admin', generate_password_hash('admin123'), 'admin@diary.local', True),
        )
        print("[+] Created default admin user  →  username: admin  |  password: admin123")

    cur.execute("SELECT 1 FROM users WHERE username = 'alice'")
    if not cur.fetchone():
        cur.execute(
            "INSERT INTO users (username, password, email) VALUES (%s, %s, %s)",
            ('alice', generate_password_hash('alice123'), 'alice@diary.local'),
        )
        print("[+] Created demo user  →  username: alice  |  password: alice123")

    conn.commit()
    cur.close()
    conn.close()
    print("[+] Database initialized successfully!")


if __name__ == '__main__':
    init_db()
