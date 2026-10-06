# app_securisee.py
# SECURE VERSION: same routes, same templates, but with active protections.
# [SECURE] Prepared statements, Jinja2 autoescape, CSP, strict validation.

import os
import platform
import re
import sqlite3
import subprocess
import ipaddress
import traceback
from functools import wraps
from pathlib import Path

import bleach
from flask import (
    Flask, request, render_template, redirect, url_for,
    session, send_file, abort, make_response,
    flash,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

from config import (
    TEMPLATES_DIR, STATIC_DIR, UPLOAD_FOLDER,
    DB_SECURE_PATH, PORT_SECURE,
)

app = Flask(
    __name__,
    template_folder=str(TEMPLATES_DIR),
    static_folder=str(STATIC_DIR),
)
app.secret_key = os.urandom(32).hex()   # [SECURE] random key at each startup

# [SECURE] Hardened cookies
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,   # True only behind HTTPS
)

# [SECURE] Rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)


# -------------------------------------------------------------
# Helpers
# -------------------------------------------------------------
def db():
    """Open a raw sqlite3 connection to the secure database."""
    con = sqlite3.connect(DB_SECURE_PATH)
    con.row_factory = sqlite3.Row
    return con


def ping_cmd_args(ip: str) -> list:
    """[PORTABLE] Return the argument list for ping (shell=False)."""
    if platform.system() == "Windows":
        return ["ping", "-n", "1", ip]
    return ["ping", "-c", "1", ip]


USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


def clean_html(text: str) -> str:
    """[SECURE] Bleach sanitization: no tag allowed."""
    return bleach.clean(text or "", tags=[], attributes={}, strip=True)


# -------------------------------------------------------------
# Authentication guard
# -------------------------------------------------------------
# Endpoints that do NOT require a logged-in user
PUBLIC_ENDPOINTS = {"login", "static", "logout"}


@app.before_request
def require_login_everywhere():
    """Protect every route by default.

    Any new route is protected automatically. Only the endpoints listed in
    PUBLIC_ENDPOINTS are reachable without a session.
    """
    # Allow static files and public endpoints
    if request.endpoint in PUBLIC_ENDPOINTS:
        return None
    # Allow 404 (no endpoint matched)
    if request.endpoint is None:
        return None
    # Not logged in -> redirect to /login with the original destination
    if not session.get("user"):
        flash("Veuillez vous connecter pour accéder à cette page.", "warning")
        return redirect(url_for("login", next=request.path))
    return None


# -------------------------------------------------------------
# Root + Dashboard
# -------------------------------------------------------------
@app.route("/")
def root():
    """Entry point: redirect to /dashboard if logged in, else to /login."""
    if session.get("user"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    """Home page shown to authenticated users."""
    return render_template(
        "dashboard.html",
        port=PORT_SECURE,
        version="SÉCURISÉE",
        mode="secure",
    )


# --- LOGIN ---------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5/minute")
def login():
    error = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")

        # [SECURE] Strict validation + prepared statement
        if not USERNAME_RE.match(u):
            error = "Identifiants invalides"
        else:
            con = db()
            row = con.execute(
                "SELECT * FROM users WHERE username = ?", (u,)
            ).fetchone()
            con.close()

            # [SECURE] Accept hashed OR plain password (both work in the lab)
            stored_hash = None
            stored_plain = None
            if row:
                keys = row.keys()
                stored_hash = row["password_hash"] if "password_hash" in keys else None
                stored_plain = row["password"] if "password" in keys else None

            password_ok = False
            if row and stored_hash:
                password_ok = check_password_hash(stored_hash, p)
            elif row and stored_plain is not None:
                password_ok = (stored_plain == p)

            if password_ok:
                session["user"] = row["username"]
                if "role" in row.keys():
                    session["role"] = row["role"]
                flash(f"Bienvenue, {row['username']} !", "success")

                # Send the user back to where they wanted to go, or dashboard
                next_url = (
                    request.form.get("next")
                    or request.args.get("next")
                    or url_for("dashboard")
                )
                return redirect(next_url)

            error = "Identifiants invalides"

    return render_template(
        "login.html",
        error=error,
        port=PORT_SECURE,
        mode="secure",
    )


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------
@app.route("/logout")
def logout():
    """Clear the session and redirect to the login page."""
    session.clear()
    flash("Vous avez été déconnecté.", "success")
    return redirect(url_for("login"))


# --- SEARCH --------------------------------------------------
@app.route("/search")
def search():
    q = request.args.get("q", "")
    results = []
    if q:
        # [SECURE] Prepared statement -> no SQLi
        con = db()
        results = con.execute(
            "SELECT id, title, content FROM articles WHERE title LIKE ?",
            (f"%{q}%",),
        ).fetchall()
        con.close()
    # [SECURE] Jinja2 escapes {{ q }} automatically in the template
    return render_template(
        "search.html",
        q=q,
        results=results,
        port=PORT_SECURE,
        mode="secure",
    )


# --- USER ----------------------------------------------------
@app.route("/user")
def user():
    uid_raw = request.args.get("id", "1")
    # [SECURE] Strict int() -> rejects any injection
    try:
        uid = int(uid_raw)
    except (TypeError, ValueError):
        abort(400, "id invalide")
    con = db()
    row = con.execute(
        "SELECT id, username, bio FROM users WHERE id = ?", (uid,)
    ).fetchone()
    con.close()
    if not row:
        abort(404)
    return render_template(
        "profile.html",
        user=dict(row),
        port=PORT_SECURE,
        mode="secure",
    )


# --- PROFILE -------------------------------------------------
@app.route("/profile", methods=["GET", "POST"])
def profile():
    username = session.get("user", "admin")
    if request.method == "POST":
        pseudo = request.form.get("pseudo", username)
        bio    = request.form.get("bio", "")
        # [SECURE] Validation + HTML sanitization
        if not USERNAME_RE.match(pseudo):
            pseudo = username
        bio_clean = clean_html(bio)
        con = db()
        con.execute(
            "UPDATE users SET username = ?, bio = ? WHERE username = ?",
            (pseudo, bio_clean, username),
        )
        con.commit()
        con.close()
        session["user"] = pseudo
        username = pseudo
    con = db()
    row = con.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    con.close()
    return render_template(
        "profile.html",
        user=dict(row) if row else {},
        port=PORT_SECURE,
        mode="secure",
    )


# --- PING ----------------------------------------------------
@app.route("/ping", methods=["GET", "POST"])
def ping():
    output = None
    ip = ""
    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        # [SECURE] ipaddress validation (IPv4 and IPv6 accepted)
        try:
            ipaddress.ip_address(ip)
            valid = True
        except ValueError:
            valid = False
        if not valid:
            output = "[Erreur] Adresse IP invalide."
        else:
            try:
                # [SECURE] shell=False + arg list + timeout
                output = subprocess.check_output(
                    ping_cmd_args(ip),
                    shell=False,
                    stderr=subprocess.STDOUT,
                    timeout=5,
                ).decode(errors="replace")
            except subprocess.CalledProcessError as e:
                output = e.output.decode(errors="replace")
            except subprocess.TimeoutExpired:
                output = "[Erreur] Délai dépassé."
            except Exception as e:
                output = f"[Erreur] {e}"
    return render_template(
        "ping.html",
        output=output,
        ip=ip,
        port=PORT_SECURE,
        mode="secure",
    )


# --- FILES ---------------------------------------------------
@app.route("/files")
def files():
    name = request.args.get("name", "")
    if not name:
        try:
            listing = sorted(os.listdir(UPLOAD_FOLDER))
        except Exception:
            listing = []
        return render_template(
            "files.html",
            listing=listing,
            port=PORT_SECURE,
            mode="secure",
        )

    # [SECURE] Multiple filters
    if any(bad in name.lower() for bad in ("..", "/", "\\", "%2e", "%2f", "%5c")):
        abort(403, "Nom de fichier interdit")

    safe = secure_filename(name)
    if not safe:
        abort(403, "Nom de fichier invalide")

    base = Path(UPLOAD_FOLDER).resolve()
    target = (base / safe).resolve()
    # [SECURE] Ensure the resolved path stays inside UPLOAD_FOLDER
    if not str(target).startswith(str(base) + os.sep) and target != base:
        abort(403, "Accès refusé")
    if not target.is_file():
        abort(404)
    return send_file(str(target))


# -------------------------------------------------------------
# Security headers
# -------------------------------------------------------------
@app.after_request
def security_headers(resp):
    # [SECURE] Strict CSP + browser protections
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; object-src 'none'; base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-XSS-Protection"] = "1; mode=block"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


# ---------------------------------------------------------------------------
# Articles CRUD - SECURE version (parameterized queries + escaping)
# ---------------------------------------------------------------------------
def _articles_db():
    """Open a raw sqlite3 connection to the articles database."""
    con = sqlite3.connect(DB_SECURE_PATH)
    con.row_factory = sqlite3.Row
    return con


@app.route("/articles")
def articles_list():
    """List all articles."""
    con = _articles_db()
    rows = con.execute("SELECT * FROM articles").fetchall()
    con.close()
    return render_template(
        "articles_list.html",
        articles=rows,
        port=PORT_SECURE,
        mode="secure",
    )


@app.route("/articles/new", methods=["GET", "POST"])
def articles_new():
    """Create a new article."""
    if request.method == "POST":
        title   = request.form.get("title", "")
        content = request.form.get("content", "")
        # [SECURE] parameterized query
        con = _articles_db()
        con.execute(
            "INSERT INTO articles (title, content) VALUES (?, ?)",
            (title, content),
        )
        con.commit()
        con.close()
        flash("Article créé.", "success")
        return redirect(url_for("articles_list"))
    return render_template(
        "article_form.html",
        article=None,
        port=PORT_SECURE,
        mode="secure",
    )


@app.route("/articles/<int:id>")
def articles_detail(id):
    """Show one article (id validated by Flask as int)."""
    con = _articles_db()
    row = con.execute("SELECT * FROM articles WHERE id=?", (id,)).fetchone()
    con.close()
    if not row:
        abort(404)
    return render_template(
        "article_detail.html",
        article=row,
        port=PORT_SECURE,
        mode="secure",
    )


@app.route("/articles/<int:id>/edit", methods=["GET", "POST"])
def articles_edit(id):
    """Edit an existing article."""
    con = _articles_db()
    if request.method == "POST":
        title   = request.form.get("title", "")
        content = request.form.get("content", "")
        con.execute(
            "UPDATE articles SET title=?, content=? WHERE id=?",
            (title, content, id),
        )
        con.commit()
        con.close()
        flash("Article modifié.", "success")
        return redirect(url_for("articles_list"))
    row = con.execute("SELECT * FROM articles WHERE id=?", (id,)).fetchone()
    con.close()
    if not row:
        abort(404)
    return render_template(
        "article_form.html",
        article=row,
        port=PORT_SECURE,
        mode="secure",
    )


@app.route("/articles/<int:id>/delete", methods=["POST"])
def articles_delete(id):
    """Delete an article."""
    con = _articles_db()
    con.execute("DELETE FROM articles WHERE id=?", (id,))
    con.commit()
    con.close()
    flash("Article supprimé.", "success")
    return redirect(url_for("articles_list"))


# -------------------------------------------------------------
# Error handlers
# -------------------------------------------------------------
@app.errorhandler(403)
def _403(e):
    return "403 — Accès refusé", 403


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=PORT_SECURE,
        threaded=True,
        use_reloader=False,
        debug=False,
    )