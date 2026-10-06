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
    flash,
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

# Force template reload during development
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0


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
# Authentication guard
# -------------------------------------------------------------
# Endpoints reachable without a session.
# NOTE: /login is public so students can still test SQL injection on the form.
PUBLIC_ENDPOINTS = {"login", "static"}


@app.before_request
def require_login():
    """[VULN] Same login guard as the secure app, but auth is still SQLi-prone."""
    if request.endpoint in PUBLIC_ENDPOINTS:
        return None
    if request.endpoint is None:      # 404
        return None
    if not session.get("user"):
        flash("Veuillez vous connecter pour accéder à cette page.", "warning")
        return redirect(url_for("login", next=request.path))
    return None


# -------------------------------------------------------------
# Root + Dashboard
# -------------------------------------------------------------
@app.route("/")
def root():
    """Entry point: redirect to /dashboard if logged, else to /login."""
    if session.get("user"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    """Home page shown to authenticated users."""
    return render_template(
        "dashboard.html",
        port=PORT_VULN,
        version="VULNÉRABLE",
        mode="vulnerable",
    )


# --- LOGIN (SQLi) --------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    """[VULN] SQL injection on the login form is intentional."""
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
                flash(f"Bienvenue, {row['username']} !", "success")
                # Send the user back to where they wanted to go, or dashboard
                next_url = (
                    request.form.get("next")
                    or request.args.get("next")
                    or url_for("dashboard")
                )
                return redirect(next_url)
            error = "Identifiants invalides"
        except Exception:
            # [VULN] Raw traceback exposed to the client
            error = "<pre>" + traceback.format_exc() + "</pre>"
    return render_template(
        "login.html",
        error=error,
        port=PORT_VULN,
        mode="vulnerable",
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
    return render_template(
        "search.html",
        q=q,
        results=results,
        port=PORT_VULN,
        mode="vulnerable",
    )


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
        return render_template(
            "profile.html",
            user=dict(row),
            port=PORT_VULN,
            mode="vulnerable",
        )
    except Exception:
        # [VULN] Info leak via traceback
        return "<pre>" + traceback.format_exc() + "</pre>", 500


# --- PROFILE (stored XSS) ------------------------------------
@app.route("/profile", methods=["GET", "POST"])
def profile():
    # Current user comes from the session (login required by before_request)
    username = session.get("user")
    if not username:
        flash("Veuillez vous connecter.", "warning")
        return redirect(url_for("login"))

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
    return render_template(
        "profile.html",
        user=dict(row) if row else {},
        port=PORT_VULN,
        mode="vulnerable",
    )


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
    return render_template(
        "ping.html",
        output=output,
        ip=ip,
        port=PORT_VULN,
        mode="vulnerable",
    )


# --- FILES (Directory Traversal) -----------------------------
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
            port=PORT_VULN,
            mode="vulnerable",
        )

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
        content = request.form.get("content", "")
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
        content = request.form.get("content", "")
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