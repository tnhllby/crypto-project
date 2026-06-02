# 📔 Personal Diary — Security Training Lab

> ⚠️ **EDUCATIONAL USE ONLY** — This application is intentionally insecure.
> Run it **only locally** on a machine you control. Never expose it to the internet.

A lightweight web application built with Flask + SQLite, designed for hands-on
web application security training. It ships in two branches: a **vulnerable** version
for attack practice and a **fixed** version demonstrating secure coding patterns.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Branch Differences](#branch-differences)
3. [Vulnerabilities Overview](#vulnerabilities-overview-vulnerable-branch)
4. [Project Structure](#project-structure)
5. [Warning](#warning)

---

## Quick Start

### Prerequisites

| Requirement | Minimum version |
|-------------|----------------|
| Python      | 3.10+          |

### 1. Clone and choose a branch

```bash
# Vulnerable version (for attack practice)
git checkout vulnerable

# Secure version (to study fixes)
git checkout fixed
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Initialize the database

```bash
python init_db.py
```

This creates the `diary.db` SQLite file, sets up tables, and seeds default accounts.

**Default accounts (vulnerable branch):**

| Username | Password | Role  |
|----------|----------|-------|
| admin    | admin123 | Admin |
| alice    | alice123 | User  |

### 4. Start the application

```bash
python app.py
```

Open **http://localhost:5000** in your browser.

---

## Branch Differences

| Feature | `vulnerable` branch | `fixed` branch |
|---------|--------------------|-----------------|
| Secret key | `"secret123"` (hardcoded, weak) | Random 32-byte hex from `secrets` module |
| Password storage | Plaintext in database | `werkzeug.security` bcrypt hashing |
| Login query | Raw f-string (SQL injectable) | Parameterized `?` placeholders |
| Note queries | Raw f-string (SQL injectable) | Parameterized `?` placeholders |
| File upload | No type/name validation | Extension whitelist + `secure_filename` |
| Note ownership | No check (IDOR) | `user_id` verified before access |
| Admin check | From session cookie only | Re-verified against database |
| XSS | `\| safe` filter (renders HTML) | Auto-escaping + `nl2br` custom filter |
| Session cookies | `HttpOnly=False`, `SameSite=None` | `HttpOnly=True`, `SameSite=Lax` |
| Error messages | Raw DB errors shown to user | Generic messages, details logged server-side |

---

## Vulnerabilities Overview (vulnerable branch)

Documented at a high level — see `ATTACK_OVERVIEW.md` for details.

| # | Category | Location |
|---|----------|----------|
| 1 | Weak secret key / session forgery | `app.py` — `app.secret_key` |
| 2 | Insecure session cookies | `app.py` — cookie config |
| 3 | SQL Injection | `app.py` — login, register, create_note |
| 4 | Plaintext password storage | `app.py` — register; `init_db.py` |
| 5 | IDOR / Broken Access Control | `app.py` — view_note, delete_note |
| 6 | Unrestricted file upload + path traversal | `app.py` — profile upload |
| 7 | Stored XSS | `templates/note_view.html` |

---

## Project Structure

```
crypto-project/
├── app.py                Main Flask application
├── api.py                REST API Blueprint (JSON endpoints)
├── init_db.py            Database setup script (run once)
├── config.py             App configuration (paths)
├── requirements.txt      Python dependencies
├── diary.db              SQLite database (created by init_db.py)
├── static/
│   ├── css/style.css
│   ├── js/main.js
│   └── uploads/          Uploaded avatars
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── note_create.html
│   ├── note_view.html
│   ├── profile.html
│   └── admin.html
├── README.md
├── ATTACK_OVERVIEW.md
└── PENTEST_LAB_GUIDE.md  Step-by-step exploitation guide
```

---

## Warning

This lab contains deliberate security flaws including SQL injection, XSS, and
unrestricted file upload. It is designed for **local use only** by security
students and professionals. Do not run it on a shared server, expose it to the
internet, or use it to store real personal information.
