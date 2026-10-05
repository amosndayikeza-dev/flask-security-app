# database/init_db.py
# [PORTABLE] Utilise pathlib pour créer les deux bases.

import sqlite3
import sys
from pathlib import Path

# Permet d'exécuter le script depuis n'importe quel cwd
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import DB_VULN_PATH, DB_SECURE_PATH

from werkzeug.security import generate_password_hash


USERS = [
    # (id, username, password, bio, role)
    (1, "admin", "admin",        "Administrateur du site", "admin"),
    (2, "alice", "secret",       "Bio d'Alice <b>test</b>", "user"),
    (3, "bob",   "password123",  "Bio de Bob",              "user"),
]

ARTICLES = [
    (1, "Bienvenue", "Premier article du TP sécurité"),
    (2, "Flask", "Framework web Python léger"),
]


def _create_vulnerable(db_path: Path) -> None:
    """Base VULNÉRABLE : mots de passe en CLAIR."""
    if db_path.exists():
        db_path.unlink()
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,   -- [VULN] clair
            bio TEXT,
            role TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE articles (
            id INTEGER PRIMARY KEY,
            title TEXT,
            content TEXT
        )
    """)
    cur.executemany(
        "INSERT INTO users (id, username, password, bio, role) VALUES (?,?,?,?,?)",
        USERS,
    )
    cur.executemany(
        "INSERT INTO articles (id, title, content) VALUES (?,?,?)",
        ARTICLES,
    )
    con.commit()
    con.close()
    print(f"[OK] Base VULNÉRABLE créée : {db_path}")


def _create_secure(db_path: Path) -> None:
    """Base SÉCURISÉE : mots de passe hashés."""
    if db_path.exists():
        db_path.unlink()
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,   -- [SECURE]
            bio TEXT,
            role TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE articles (
            id INTEGER PRIMARY KEY,
            title TEXT,
            content TEXT
        )
    """)
    for uid, uname, upwd, bio, role in USERS:
        cur.execute(
            "INSERT INTO users (id, username, password_hash, bio, role) VALUES (?,?,?,?,?)",
            (uid, uname, generate_password_hash(upwd), bio, role),
        )
    cur.executemany(
        "INSERT INTO articles (id, title, content) VALUES (?,?,?)",
        ARTICLES,
    )
    con.commit()
    con.close()
    print(f"[OK] Base SÉCURISÉE créée : {db_path}")


if __name__ == "__main__":
    _create_vulnerable(DB_VULN_PATH)
    _create_secure(DB_SECURE_PATH)
    print("Initialisation terminée.")
