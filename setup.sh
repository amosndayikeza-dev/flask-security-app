#!/bin/bash
set -e
python -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python database/init_db.py
echo "[OK] Environnement prêt. Lancez : ./run.sh"
