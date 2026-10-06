# app_vulnerable.py
# WARNING: STRICTLY FOR PEDAGOGICAL USE - ISOLATED ENVIRONMENT ONLY.
# This application contains intentional vulnerabilities
# (XSS, SQLi, CmdI, Path Traversal) designed for a university lab.
# NEVER deploy on the Internet or on a production machine.

import os
import platform
import sqlite3
import subprocess
import traceback
from pathlib import Path

from flask import (
    Flask, request, render_template, render_template_string,
    redirect, url_for, session, send_file, abort, make_response,
    flash,                                       # <-- FIX: needed by logout + CRUD
)

from config import (
    TEMPLATES_DIR, STATIC_DIR, UPLOAD_FOLDER,
    DB_VULN_PATH, PORT_VULN,
)

app = Flask(
    __name__,
    template_folder=str(TEMPLATES_DIR),
    static_folder=str(STATIC_DIR),
)
app.secret_key = "clef-vulnerable-pour-tp"   # [VULN] weak and public key


# -------------------------------------------------------------
# Helpers
# -------------------------------------------------------------
def db():
    """Open a raw sqlite3 connection to the main app database."""
    con = sqlite3.connect(DB_VULN_PATH)
    con.row_factory = sqlite3.Row
    return con


def ping_cmd(ip: str) -> str:
    """[PORTABLE] Pick the right ping command depending on the OS."""
    if platform.system() == "Windows":
        return f"ping -n 1 {ip}"
    return f"ping -c 1 {ip}"


# -------------------------------------------------------------
# Routes
# -------------------------------------------------------------
@app.route("/")
def index():
    return render_template(
        "index.html",
        port=PORT_VULN,
        version="VULNÉRABLE",
        mode="vulnerable",
    )


# --- LOGIN (SQLi) --------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        # [VULN] Direct concatenation -> trivial SQL injection
        query = f"SELECT * FROM users WHERE username='{u}' AND password='{p}'"
        try:
            con = db()
            row = con.execute(query).fetchone()
            con.close()
            if row:
                session["user"] = row["username"]
                session["role"] = row["role"] if "role" in row.keys() else None
                return redirect(url_for("profile"))
            error = "Identifiants invalides"
        except Exception:
            # [VULN] Raw traceback exposed to the client
            error = "<pre>" + traceback.format_exc() + "</pre>"
    return render_template("login.html", error=error, port=PORT_VULN, mode="vulnerable")


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------
@app.route("/logout")
def logout():
    """Clear the session and redirect to the home page."""
    session.clear()
    flash("Vous avez été déconnecté.", "success")
    return redirect(url_for("index"))


# --- SEARCH (SQLi + reflected XSS) ---------------------------
@app.route("/search")
def search():
    q = request.args.get("q", "")
    results = []
    if q:
        # [VULN] String concatenation
        query = f"SELECT id, title, content FROM articles WHERE title LIKE '%{q}%'"
        try:
            con = db()
            results = con.execute(query).fetchall()
            con.close()
        except Exception:
            results = []
    # [VULN] Reflected XSS: query re-injected WITHOUT escaping
    return render_template("search.html", q=q, results=results, port=PORT_VULN, mode="vulnerable")


# --- USER (SQLi via id) --------------------------------------
@app.route("/user")
def user():
    uid = request.args.get("id", "1")
    # [VULN] id concatenated directly
    query = f"SELECT id, username, bio FROM users WHERE id={uid}"
    try:
        con = db()
        row = con.execute(query).fetchone()
        con.close()
        if not row:
            return "Utilisateur introuvable", 404
        return render_template("profile.html", user=dict(row), port=PORT_VULN, mode="vulnerable")
    except Exception:
        # [VULN] Info leak via traceback
        return "<pre>" + traceback.format_exc() + "</pre>", 500


# --- PROFILE (stored XSS) ------------------------------------
@app.route("/profile", methods=["GET", "POST"])
def profile():
    # Default "logged in" user = admin (lab simplification)
    username = session.get("user", "admin")
    if request.method == "POST":
        pseudo = request.form.get("pseudo", username)
        bio    = request.form.get("bio", "")
        con = db()
        # [VULN] Concatenation (user can also inject SQL here)
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
    return render_template("profile.html", user=dict(row) if row else {}, port=PORT_VULN, mode="vulnerable")


# --- PING (Command Injection) --------------------------------
@app.route("/ping", methods=["GET", "POST"])
def ping():
    output = None
    ip = ""
    if request.method == "POST":
        ip = request.form.get("ip", "")
        if ip:
            cmd = ping_cmd(ip)      # [PORTABLE] ping -c 1 / ping -n 1
            try:
                # [VULN] shell=True + concatenation -> RCE
                output = subprocess.check_output(
                    cmd, shell=True, stderr=subprocess.STDOUT, timeout=10
                ).decode(errors="replace")
            except subprocess.CalledProcessError as e:
                output = e.output.decode(errors="replace")
            except Exception as e:
                output = str(e)
    return render_template("ping.html", output=output, ip=ip, port=PORT_VULN, mode="vulnerable")


# --- FILES (Directory Traversal) -----------------------------
@app.route("/files")
def files():
    name = request.args.get("name", "")
    if not name:
        try:
            listing = sorted(os.listdir(UPLOAD_FOLDER))
        except Exception:
            listing = []
        return render_template("files.html", listing=listing, port=PORT_VULN, mode="vulnerable")

    # [VULN] No normalization, no check -> free traversal
    target = os.path.join(str(UPLOAD_FOLDER), name)
    if not os.path.exists(target):
        return f"Fichier introuvable : {target}", 404
    return send_file(target)


# ---------------------------------------------------------------------------
# Articles CRUD - VULNERABLE version (string concatenation + raw HTML)
# ---------------------------------------------------------------------------
def _articles_db():
    """Open a raw sqlite3 connection to the articles database."""
    # FIX: use the correct config constant (was DB_PATH, undefined)
    con = sqlite3.connect(DB_VULN_PATH)
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
        port=PORT_VULN,
        mode="vulnerable",
    )


@app.route("/articles/new", methods=["GET", "POST"])
def articles_new():
    """Create a new article."""
    if request.method == "POST":
        title   = request.form.get("title", "")
        content = request.form.get("content", "")   # FIX: table column is 'content'
        # [VULN] string concatenation -> SQL injection possible
        con = _articles_db()
        con.execute(
            f"INSERT INTO articles (title, content) VALUES ('{title}', '{content}')"
        )
        con.commit()
        con.close()
        flash("Article créé.", "success")
        return redirect(url_for("articles_list"))
    return render_template(
        "article_form.html",
        article=None,
        port=PORT_VULN,
        mode="vulnerable",
    )


@app.route("/articles/<id>")
def articles_detail(id):
    """Show one article. [VULN] id is concatenated directly."""
    con = _articles_db()
    row = con.execute(f"SELECT * FROM articles WHERE id={id}").fetchone()
    con.close()
    if not row:
        abort(404)
    # [VULN] raw HTML rendered so stored XSS fires
    return render_template(
        "article_detail.html",
        article=row,
        port=PORT_VULN,
        mode="vulnerable",
    )


@app.route("/articles/<id>/edit", methods=["GET", "POST"])
def articles_edit(id):
    """Edit an existing article."""
    con = _articles_db()
    if request.method == "POST":
        title   = request.form.get("title", "")
        content = request.form.get("content", "")   # FIX: 'content' not 'body'
        con.execute(
            f"UPDATE articles SET title='{title}', content='{content}' WHERE id={id}"
        )
        con.commit()
        con.close()
        flash("Article modifié.", "success")
        return redirect(url_for("articles_list"))
    row = con.execute(f"SELECT * FROM articles WHERE id={id}").fetchone()
    con.close()
    if not row:
        abort(404)
    return render_template(
        "article_form.html",
        article=row,
        port=PORT_VULN,
        mode="vulnerable",
    )


@app.route("/articles/<id>/delete", methods=["POST"])
def articles_delete(id):
    """Delete an article."""
    con = _articles_db()
    con.execute(f"DELETE FROM articles WHERE id={id}")
    con.commit()
    con.close()
    flash("Article supprimé.", "success")
    return redirect(url_for("articles_list"))


# -------------------------------------------------------------
# Headers: NO hardening at all (no CSP, no X-Frame-Options)
# -------------------------------------------------------------
@app.after_request
def no_headers(resp):
    # [VULN] Intentionally no protection
    return resp


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=PORT_VULN,
        threaded=True,
        use_reloader=False,
        debug=False,
    )