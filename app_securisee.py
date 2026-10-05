# app_securisee.py
# Version SÉCURISÉE : mêmes routes, mêmes templates, mais protections actives.
# [SECURE] Requêtes préparées, échappement Jinja2, CSP, validation stricte.

import os
import platform
import re
import sqlite3
import subprocess
import ipaddress
from pathlib import Path

import bleach
from flask import (
    Flask, request, render_template, redirect, url_for,
    session, send_file, abort, make_response
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

from config import (
    TEMPLATES_DIR, STATIC_DIR, UPLOAD_FOLDER,
    DB_SECURE_PATH, PORT_SECURE
)

app = Flask(
    __name__,
    template_folder=str(TEMPLATES_DIR),
    static_folder=str(STATIC_DIR),
)
app.secret_key = os.urandom(32).hex()   # [SECURE] clé aléatoire à chaque démarrage

# [SECURE] Cookies durcis
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,   # True seulement si HTTPS
)

# [SECURE] Rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────
def db():
    con = sqlite3.connect(DB_SECURE_PATH)
    con.row_factory = sqlite3.Row
    return con


def ping_cmd_args(ip: str) -> list:
    """[PORTABLE] Retourne la liste d'arguments (shell=False)."""
    if platform.system() == "Windows":
        return ["ping", "-n", "1", ip]
    return ["ping", "-c", "1", ip]


USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


def clean_html(text: str) -> str:
    """[SECURE] Nettoyage bleach : aucune balise autorisée."""
    return bleach.clean(text or "", tags=[], attributes={}, strip=True)


# ─────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html", port=PORT_SECURE, version="SÉCURISÉE")


# ─── LOGIN ───────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5/minute")
def login():
    error = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        # [SECURE] Validation stricte + requête préparée
        if not USERNAME_RE.match(u):
            error = "Identifiants invalides"
        else:
            con = db()
            row = con.execute(
                "SELECT * FROM users WHERE username = ?", (u,)
            ).fetchone()
            con.close()
            # [SECURE] Vérification du hash
            if row and check_password_hash(row["password_hash"], p):
                session["user"] = row["username"]
                session["role"] = row["role"]
                return redirect(url_for("profile"))
            error = "Identifiants invalides"
    return render_template("login.html", error=error, port=PORT_SECURE)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ─── SEARCH ──────────────────────────────────────────────────
@app.route("/search")
def search():
    q = request.args.get("q", "")
    results = []
    if q:
        # [SECURE] Requête préparée → pas de SQLi
        con = db()
        results = con.execute(
            "SELECT id, title, content FROM articles WHERE title LIKE ?",
            (f"%{q}%",),
        ).fetchall()
        con.close()
    # [SECURE] Jinja2 échappe automatiquement {{ q }} dans le template
    return render_template("search.html", q=q, results=results, port=PORT_SECURE)


# ─── USER ────────────────────────────────────────────────────
@app.route("/user")
def user():
    uid_raw = request.args.get("id", "1")
    # [SECURE] int() strict → rejette toute injection
    try:
        uid = int(uid_raw)
    except (TypeError, ValueError):
        abort(400, "id invalide")
    con = db()
    row = con.execute(
        "SELECT id, username, bio, role FROM users WHERE id = ?", (uid,)
    ).fetchone()
    con.close()
    if not row:
        abort(404)
    return render_template("profile.html", user=dict(row), port=PORT_SECURE)


# ─── PROFILE ─────────────────────────────────────────────────
@app.route("/profile", methods=["GET", "POST"])
def profile():
    username = session.get("user", "admin")
    if request.method == "POST":
        pseudo = request.form.get("pseudo", username)
        bio    = request.form.get("bio", "")
        # [SECURE] Validation + nettoyage HTML
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
    row = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    con.close()
    return render_template("profile.html", user=dict(row) if row else {}, port=PORT_SECURE)


# ─── PING ────────────────────────────────────────────────────
@app.route("/ping", methods=["GET", "POST"])
def ping():
    output = None
    ip = ""
    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        # [SECURE] Validation par ipaddress (accepte IPv4 et IPv6)
        try:
            ipaddress.ip_address(ip)
            valid = True
        except ValueError:
            valid = False
        if not valid:
            output = "[Erreur] Adresse IP invalide."
        else:
            try:
                # [SECURE] shell=False + liste d'arguments + timeout
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
    return render_template("ping.html", output=output, ip=ip, port=PORT_SECURE)


# ─── FILES ───────────────────────────────────────────────────
@app.route("/files")
def files():
    name = request.args.get("name", "")
    if not name:
        try:
            listing = sorted(os.listdir(UPLOAD_FOLDER))
        except Exception:
            listing = []
        return render_template("files.html", listing=listing, port=PORT_SECURE)

    # [SECURE] Filtres multiples
    if any(bad in name.lower() for bad in ("..", "/", "\\", "%2e", "%2f", "%5c")):
        abort(403, "Nom de fichier interdit")

    safe = secure_filename(name)
    if not safe:
        abort(403, "Nom de fichier invalide")

    base = Path(UPLOAD_FOLDER).resolve()
    target = (base / safe).resolve()
    # [SECURE] Vérification que la cible reste dans UPLOAD_FOLDER
    if not str(target).startswith(str(base) + os.sep) and target != base:
        abort(403, "Accès refusé")
    if not target.is_file():
        abort(404)
    return send_file(str(target))


# ─────────────────────────────────────────────────────────────
# En-têtes de sécurité
# ─────────────────────────────────────────────────────────────
@app.after_request
def security_headers(resp):
    # [SECURE] CSP stricte + protections navigateur
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


@app.errorhandler(403)
def _403(e):
    return "403 — Accès refusé", 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT_SECURE,
            threaded=True, use_reloader=False, debug=False)
