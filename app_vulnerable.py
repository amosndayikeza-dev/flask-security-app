# app_vulnerable.py
# ⚠️ USAGE STRICTEMENT PÉDAGOGIQUE — ENVIRONNEMENT ISOLÉ UNIQUEMENT.
# Cette application contient des vulnérabilités volontaires
# (XSS, SQLi, CmdI, Path Traversal) destinées à un TP universitaire.
# NE JAMAIS déployer sur Internet ni sur une machine de production.

import os
import platform
import sqlite3
import subprocess
import traceback
from pathlib import Path

from flask import (
    Flask, request, render_template, render_template_string,
    redirect, url_for, session, send_file, abort, make_response
)

from config import (
    TEMPLATES_DIR, STATIC_DIR, UPLOAD_FOLDER,
    DB_VULN_PATH, PORT_VULN
)

app = Flask(
    __name__,
    template_folder=str(TEMPLATES_DIR),
    static_folder=str(STATIC_DIR),
)
app.secret_key = "clef-vulnerable-pour-tp"   # [VULN] clé faible et publique


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────
def db():
    con = sqlite3.connect(DB_VULN_PATH)
    con.row_factory = sqlite3.Row
    return con


def ping_cmd(ip: str) -> str:
    """[PORTABLE] Choisit la bonne commande ping selon l'OS."""
    if platform.system() == "Windows":
        return f"ping -n 1 {ip}"
    return f"ping -c 1 {ip}"


# ─────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html", port=PORT_VULN, version="VULNÉRABLE")


# ─── LOGIN (SQLi) ────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        # [VULN] Concaténation directe → injection SQL triviale
        query = f"SELECT * FROM users WHERE username='{u}' AND password='{p}'"
        try:
            con = db()
            row = con.execute(query).fetchone()
            con.close()
            if row:
                session["user"] = row["username"]
                session["role"] = row["role"]
                return redirect(url_for("profile"))
            error = "Identifiants invalides"
        except Exception:
            # [VULN] Traceback brut exposé
            error = "<pre>" + traceback.format_exc() + "</pre>"
    return render_template("login.html", error=error, port=PORT_VULN)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ─── SEARCH (SQLi + XSS réfléchi) ────────────────────────────
@app.route("/search")
def search():
    q = request.args.get("q", "")
    results = []
    if q:
        # [VULN] Concaténation SQL
        query = f"SELECT id, title, content FROM articles WHERE title LIKE '%{q}%'"
        try:
            con = db()
            results = con.execute(query).fetchall()
            con.close()
        except Exception:
            results = []
    # [VULN] XSS réfléchi : la query est réinjectée SANS échappement
    return render_template("search.html", q=q, results=results, port=PORT_VULN)


# ─── USER (SQLi via id) ──────────────────────────────────────
@app.route("/user")
def user():
    uid = request.args.get("id", "1")
    # [VULN] id concaténé directement
    query = f"SELECT id, username, bio, role FROM users WHERE id={uid}"
    try:
        con = db()
        row = con.execute(query).fetchone()
        con.close()
        if not row:
            return "Utilisateur introuvable", 404
        return render_template("profile.html", user=dict(row), port=PORT_VULN)
    except Exception:
        # [VULN] Fuite d'info via traceback
        return "<pre>" + traceback.format_exc() + "</pre>", 500


# ─── PROFILE (XSS stocké) ────────────────────────────────────
@app.route("/profile", methods=["GET", "POST"])
def profile():
    # utilisateur "connecté" par défaut = admin (simplification TP)
    username = session.get("user", "admin")
    if request.method == "POST":
        pseudo = request.form.get("pseudo", username)
        bio    = request.form.get("bio", "")
        con = db()
        # [VULN] concaténation (l'utilisateur peut aussi injecter du SQL ici)
        con.execute(
            f"UPDATE users SET username='{pseudo}', bio='{bio}' WHERE username='{username}'"
        )
        con.commit()
        con.close()
        session["user"] = pseudo
        username = pseudo
    con = db()
    row = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    con.close()
    return render_template("profile.html", user=dict(row) if row else {}, port=PORT_VULN)


# ─── PING (Command Injection) ────────────────────────────────
@app.route("/ping", methods=["GET", "POST"])
def ping():
    output = None
    ip = ""
    if request.method == "POST":
        ip = request.form.get("ip", "")
        if ip:
            cmd = ping_cmd(ip)      # [PORTABLE] ping -c 1 / ping -n 1
            try:
                # [VULN] shell=True + concaténation → RCE
                output = subprocess.check_output(
                    cmd, shell=True, stderr=subprocess.STDOUT, timeout=10
                ).decode(errors="replace")
            except subprocess.CalledProcessError as e:
                output = e.output.decode(errors="replace")
            except Exception as e:
                output = str(e)
    return render_template("ping.html", output=output, ip=ip, port=PORT_VULN)


# ─── FILES (Directory Traversal) ─────────────────────────────
@app.route("/files")
def files():
    name = request.args.get("name", "")
    if not name:
        # Liste le dossier uploads
        try:
            listing = sorted(os.listdir(UPLOAD_FOLDER))
        except Exception:
            listing = []
        return render_template("files.html", listing=listing, port=PORT_VULN)

    # [VULN] Aucune normalisation, aucun contrôle → traversal libre
    target = os.path.join(str(UPLOAD_FOLDER), name)
    if not os.path.exists(target):
        return f"Fichier introuvable : {target}", 404
    return send_file(target)


# ─────────────────────────────────────────────────────────────
# En-têtes : AUCUN durcissement (pas de CSP, pas de X-Frame-Options)
# ─────────────────────────────────────────────────────────────
@app.after_request
def no_headers(resp):
    # [VULN] Volontairement aucune protection
    return resp


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT_VULN,
            threaded=True, use_reloader=False, debug=False)
