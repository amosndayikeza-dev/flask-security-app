$ErrorActionPreference = "Stop"
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
python database\init_db.py
Write-Host "[OK] Environnement pret. Lancez : .\run.ps1"
