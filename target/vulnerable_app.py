"""
Deliberately-VULNERABLE target app  (FOR LEARNING / OWNED-TARGET TESTING ONLY)
==============================================================================

This Flask app contains INTENTIONAL vulnerabilities so the scanner has real
flaws to detect. NEVER deploy this anywhere public. Run it locally only:

    python target/vulnerable_app.py      # serves on http://127.0.0.1:8000

Each endpoint is annotated with the OWASP Top 10 category it demonstrates.
"""

import sqlite3
import os
from flask import Flask, request, jsonify, Response

app = Flask(__name__)
DB = "/tmp/webscanner_target.db"


def init_db():
    if os.path.exists(DB):
        os.remove(DB)
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)")
    c.executemany(
        "INSERT INTO users VALUES (?,?,?,?)",
        [
            (1, "alice", "alicepass", "alice@example.com"),
            (2, "bob", "bobpass", "bob@example.com"),
            (3, "admin", "admin123", "admin@example.com"),
        ],
    )
    conn.commit()
    conn.close()


def db():
    return sqlite3.connect(DB)


# ---------------------------------------------------------------------------
# VULN 1 — SQL Injection (OWASP A03). User input concatenated into the query.
#   Exploit: /login?username=admin'--&password=anything   (auth bypass)
# ---------------------------------------------------------------------------
@app.route("/login")
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    conn = db()
    c = conn.cursor()
    query = f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        c.execute(query)
        row = c.fetchone()
    except Exception as e:
        # Verbose error leaks that injection reached the SQL engine (A05 too).
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()
    if row:
        return jsonify({"status": "authenticated", "user": row[1]})
    return jsonify({"status": "invalid credentials"}), 401


# ---------------------------------------------------------------------------
# VULN 2 — Reflected XSS (OWASP A03). Input reflected into HTML unescaped.
#   Exploit: /search?q=<script>alert(1)</script>
# ---------------------------------------------------------------------------
@app.route("/search")
def search():
    q = request.args.get("q", "")
    # DANGER: user input placed directly into HTML with no encoding.
    html = f"<html><body><h1>Results for: {q}</h1></body></html>"
    return Response(html, mimetype="text/html")


# ---------------------------------------------------------------------------
# VULN 3 — Broken Access Control / IDOR (OWASP A01). Any id is readable;
# no check that the caller owns the record. Leaks other users' data.
#   Exploit: /account/1 , /account/2 , /account/3  -> everyone's email
# ---------------------------------------------------------------------------
@app.route("/account/<int:user_id>")
def account(user_id):
    conn = db()
    c = conn.cursor()
    c.execute("SELECT id, username, email FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    # No authorization check — returns whoever you ask for.
    return jsonify({"id": row[0], "username": row[1], "email": row[2]})


@app.route("/")
def home():
    # Intentionally NO security headers set anywhere (VULN 4 — OWASP A05).
    return jsonify({"app": "vulnerable-target", "endpoints": ["/login", "/search", "/account/<id>"]})


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=8000)
