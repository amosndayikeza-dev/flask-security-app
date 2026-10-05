# config.py
# [PORTABLE] Tous les chemins sont calculés via pathlib → fonctionne
# sur Arch Linux ET Windows sans modification.

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Dossiers
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR    = BASE_DIR / "static"
UPLOAD_FOLDER = BASE_DIR / "uploads"
DATABASE_DIR  = BASE_DIR / "database"

# Base de données SQLite
DB_VULN_PATH   = DATABASE_DIR / "vulnerable.db"
DB_SECURE_PATH = DATABASE_DIR / "secure.db"

# Création runtime (idempotent)
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
DATABASE_DIR.mkdir(parents=True, exist_ok=True)

# Ports
PORT_VULN   = 5000
PORT_SECURE = 5001
