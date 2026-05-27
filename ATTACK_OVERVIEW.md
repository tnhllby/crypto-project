# Attack Overview — Personal Diary Lab

> This document describes vulnerabilities present in the **`vulnerable` branch**
> at a high level. It does not contain working exploit payloads or step-by-step
> attack instructions. Its purpose is to help security learners understand *what*
> to look for and *why* each flaw matters.

---

## Vulnerability Map

| ID | OWASP Category | Severity | Location in code |
|----|---------------|----------|-----------------|
| V1 | A07 — Identification & Auth Failures | High | `app.py` secret key |
| V2 | A07 — Identification & Auth Failures | Medium | `app.py` cookie config |
| V3 | A03 — Injection | Critical | `app.py` login / register / create_note |
| V4 | A02 — Cryptographic Failures | High | `app.py` register, `init_db.py` |
| V5 | A01 — Broken Access Control | High | `app.py` view_note / delete_note |
| V6 | A04 — Insecure Design (File Upload) | High | `app.py` profile upload |
| V7 | A03 — Injection (XSS) | High | `templates/note_view.html` |

---

## V1 — Weak Hardcoded Secret Key

**What it is:** Flask signs session cookies with `app.secret_key`. The application
uses the literal string `"secret123"`.

**Risk:** Anyone who knows (or guesses) the secret key can craft a valid session
cookie with arbitrary values — for example, setting `is_admin` to `True` without
ever having admin credentials. Tools exist that can brute-force short secret keys
from a captured cookie.

**How to detect:** Review `app.py` for `app.secret_key`. If it is a short,
hardcoded string it is almost certainly insufficient. Tools such as `flask-unsign`
can test keys offline against a captured session cookie.

**Correct fix:** Generate a cryptographically random key at startup
(`secrets.token_hex(32)`) and load it from an environment variable or secrets
manager, never from source code.

---

## V2 — Insecure Session Cookie Flags

**What it is:** Three cookie security attributes are deliberately misconfigured:

| Attribute | Vulnerable value | Effect |
|-----------|-----------------|--------|
| `HttpOnly` | `False` | JavaScript can read the cookie |
| `Secure` | `False` | Cookie sent over plain HTTP |
| `SameSite` | `None` | Cookie included in cross-site requests |

**Risk:** With `HttpOnly=False`, an XSS payload (see V7) can exfiltrate the
session cookie. With `SameSite=None`, CSRF attacks become easier to carry out.

**How to detect:** Inspect cookies in browser DevTools → Application → Cookies.
Look for the absence of `HttpOnly` and `SameSite` flags on the session cookie.

**Correct fix:** Set `HttpOnly=True`, `SameSite='Lax'`, and `Secure=True` (when
running over HTTPS).

---

## V3 — SQL Injection

**What it is:** User-supplied strings are concatenated directly into SQL queries
using Python f-strings. This affects the login, registration, and note-creation
endpoints.

**Risk:** An attacker can manipulate the SQL query structure to:
- Bypass authentication (login without valid credentials)
- Extract data from any table in the database
- Modify or delete arbitrary records
- In some configurations, execute operating-system commands

**How to detect:** Look for f-string SQL queries such as
`f"SELECT … WHERE username='{username}'"`. Static analysis tools (bandit, semgrep)
flag these patterns. Dynamic testing involves sending SQL metacharacters and
observing whether the application behaviour changes or an error is returned.

**Correct fix:** Use parameterized queries with `%s` placeholders — the database
driver handles escaping, making injection structurally impossible.

---

## V4 — Plaintext Password Storage

**What it is:** Passwords are stored as-is in the `password` column of the `users`
table. No hashing or salting is applied.

**Risk:** If the database is compromised (via SQL injection, a backup leak, or
direct access), all user passwords are immediately readable. Because users often
reuse passwords, this enables credential stuffing attacks against other services.

**How to detect:** Dump the `users` table and inspect the `password` column. If
the values look human-readable rather than fixed-length random-looking hashes,
passwords are not hashed.

**Correct fix:** Use an adaptive hashing algorithm with a per-user salt
(`werkzeug.security.generate_password_hash` / `check_password_hash`, or
`bcrypt`, `argon2-cffi`). Never store or compare raw passwords.

---

## V5 — IDOR / Broken Access Control

**What it is:** The endpoints `/note/<id>` and `/note/<id>/delete` fetch or
delete a note by its database ID without verifying that the note belongs to the
currently logged-in user.

**Risk:** Any authenticated user can read or permanently delete any other user's
diary entries simply by changing the numeric ID in the URL. This is one of the
most common real-world vulnerabilities (OWASP #1).

**How to detect:** Log in as user A, create a note, and note its ID (e.g. `/note/3`).
Log in as user B and navigate to `/note/3`. If the note is visible, the IDOR
exists. Automated scanners (Burp Suite Intruder) can enumerate IDs systematically.

**Correct fix:** Add a `WHERE id = %s AND user_id = %s` condition and supply both
the note ID and the session user ID. Return 403 or 404 if the record is not found.

---

## V6 — Unrestricted File Upload & Path Traversal

**What it is:** The profile avatar upload endpoint saves files using the
client-supplied filename without any validation of:
- File extension or MIME type
- Filename safety (directory separators, null bytes)

**Risk (file type):** Uploading a `.py`, `.html`, or script file and then
requesting it via `/uploads/<filename>` can serve arbitrary content. Depending
on server configuration this can lead to code execution.

**Risk (path traversal):** A filename such as `../../config.py` may resolve to
a path outside the uploads directory, allowing an attacker to overwrite arbitrary
files on the server — including the application source code itself.

**How to detect:** Attempt to upload a non-image file. Inspect whether the server
rejects it based on content type or extension. Tools like Burp Suite can modify
the `Content-Type` header and filename in transit.

**Correct fix:**
1. Whitelist allowed extensions (`{'png', 'jpg', 'jpeg', 'gif', 'webp'}`).
2. Verify the MIME type server-side (e.g. using `python-magic`).
3. Sanitize the filename with `werkzeug.utils.secure_filename`.
4. Store uploads outside the web root and serve them through a controlled route,
   or use a dedicated object storage service.

---

## V7 — Stored Cross-Site Scripting (XSS)

**What it is:** Note content is stored in the database and later rendered in
`note_view.html` using the Jinja2 `| safe` filter, which disables the default
HTML auto-escaping.

**Risk:** An attacker creates a note whose content contains an HTML/JavaScript
payload. When any user (including an admin) views that note, the script executes
in their browser with the victim's session context. Combined with V2
(`HttpOnly=False`), the script can silently exfiltrate the victim's session
cookie, enabling account takeover.

**How to detect:** Create a note with HTML content (e.g. a bold tag). If it
renders as formatted HTML rather than literal text, the application does not
escape output. Automated scanners (OWASP ZAP, Burp Suite) include XSS detection.

**Correct fix:** Remove the `| safe` filter. Jinja2 auto-escapes HTML by default
when auto-escaping is enabled for the template. If formatted output is needed,
use a library such as `bleach` to allow only a specific safe subset of tags.

---

## General Remediation Principles

1. **Never trust user input** — validate type, length, and format at every boundary.
2. **Use parameterized queries** — never build SQL strings from user data.
3. **Hash passwords** — use a modern adaptive algorithm with salt.
4. **Protect session cookies** — `HttpOnly`, `SameSite`, `Secure`.
5. **Use a strong secret key** — generated randomly, stored outside source code.
6. **Enforce authorization on every request** — "logged in" ≠ "authorized".
7. **Validate file uploads server-side** — client hints are bypassed trivially.
8. **Escape output** — treat all user-supplied data as untrusted when rendering HTML.
