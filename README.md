# TP Sécurité — Flask Vulnérable vs Sécurisé

> ⚠️ **Usage strictement pédagogique** — environnement isolé (localhost).
> Ne jamais exposer ces applications sur un réseau public.

## 📌 Objectif

Comparer le comportement de **4 familles d'attaques** sur la **même
application Flask** exposée en deux versions :

| Port | Version    | Protection |
|------|------------|-----------|
| 5000 | Vulnérable | ❌ Aucune  |
| 5001 | Sécurisée  | ✅ Complètes |

## 🗂️ Routes communes

| Route               | Vulnérabilité testée | Outil      |
|---------------------|----------------------|------------|
| `/login` (POST)     | Injection SQL        | SQLMap     |
| `/search?q=`        | SQLi + XSS réfléchi  | SQLMap, XSStrike |
| `/user?id=`         | Injection SQL        | SQLMap     |
| `/profile` (POST)   | XSS stocké           | XSStrike   |
| `/ping` (POST)      | Command Injection    | Commix     |
| `/files?name=`      | Path Traversal       | DotDotPwn  |

## 🚀 Installation

### Sur Arch Linux (Étudiant A)

```bash
# Dépendances système (outils pentest)
sudo pacman -S sqlmap python python-pip base-devel
yay -S xsstrike commix dotdotpwn   # ou via git fallback

# Environnement projet
cd flask_tp_securite
chmod +x setup.sh run.sh
./setup.sh
./run.sh
```

### Sur Windows 11 (Étudiant B)

```powershell
# Prérequis : Python 3.10+ installé via winget
winget install Python.Python.3.12

# Outils pentest : WSL2 fortement conseillé
wsl --install -d Ubuntu

# Environnement projet (PowerShell)
cd flask_tp_securite
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned   # une seule fois
.\setup.ps1
.\run.ps1
```

L'application est accessible sur :
- http://127.0.0.1:5000 → VULNÉRABLE
- http://127.0.0.1:5001 → SÉCURISÉE

## 🧪 Scénarios d'attaque

### 1. XSS avec XSStrike

```bash
# Port 5000 (VULNÉRABLE)
xsstrike -u "http://localhost:5000/search?q=test"
# → Payload réfléchi trouvé → exploit réussi

# Port 5001 (SÉCURISÉE)
xsstrike -u "http://localhost:5001/search?q=test"
# → "0 payload found" — échappement Jinja2 + CSP + bleach
```

### 2. SQL Injection avec SQLMap

```bash
# Port 5000 (VULNÉRABLE)
sqlmap -u "http://localhost:5000/user?id=1" --batch --dbs
# → "Parameter: id (GET) — boolean-based blind"
# → Dump possible de toute la base

# Port 5001 (SÉCURISÉE)
sqlmap -u "http://localhost:5001/user?id=1" --batch --level=5 --risk=3
# → "not injectable" — requêtes préparées + int() strict
```

### 3. Command Injection avec Commix

```bash
# Port 5000
commix --url="http://localhost:5000/ping" --data="ip=127.0.0.1" --batch
# → Shell obtenu (os_shell)

# Port 5001
commix --url="http://localhost:5001/ping" --data="ip=127.0.0.1" --batch
# → "no injection point detected" — ipaddress + shell=False
```

### 4. Path Traversal avec DotDotPwn

```bash
# Port 5000
dotdotpwn -m http-url \
  -u "http://localhost:5000/files?name=TRAVERSAL" \
  -k "root:" -d 6 -f pentest/wordlist_traversal.txt
# → Vulnérabilité trouvée, /etc/passwd lisible

# Port 5001
dotdotpwn -m http-url \
  -u "http://localhost:5001/files?name=TRAVERSAL" \
  -k "root:" -d 6 -f pentest/wordlist_traversal.txt
# → "0 vulnerability found"
```

## 🔬 Analyse — pourquoi ça marche / pourquoi c'est bloqué

### XSS

| Aspect | Vulnérable | Sécurisée |
|---|---|---|
| Rendu du paramètre `q` | `{{ q | safe }}` | `{{ q }}` (échappement auto) |
| Champ `bio` en base | HTML brut conservé | `bleach.clean()` strip tout |
| En-têtes | aucun | CSP `default-src 'self'` |
| Cookies | par défaut | `HttpOnly`, `SameSite=Lax` |

**Heuristique XSStrike :** il envoie des payloads uniques, détecte la
réflexion **brute** dans le HTML retourné, analyse le **contexte**
(entre `<script>`, dans un attribut, etc.) et génère des payloads
adaptés. Dès que `<` est échappé en `&lt;`, la détection échoue.

### SQL Injection

| Aspect | Vulnérable | Sécurisée |
|---|---|---|
| Requête | f-string concaténée | `?` paramétrée |
| `id` | concaténé | `int()` + ValueError → 400 |
| Erreurs | traceback SQLite brut | message générique |
| Rate limit | non | 5/min via Flask-Limiter |
| Mots de passe | clair | hash Werkzeug |

**Heuristiques SQLMap :**
- **Boolean-based blind** : compare le contenu de la réponse entre `AND 1=1` et `AND 1=2`.
- **Time-based blind** : injecte `SLEEP(5)` et mesure la latence.
- **Error-based** : force une erreur SQL et lit le message.
Sur la version sécurisée, aucun de ces signaux n'apparaît.

### Command Injection

| Aspect | Vulnérable | Sécurisée |
|---|---|---|
| Appel | `shell=True` + concat | `subprocess.run([...], shell=False)` |
| Validation | aucune | `ipaddress.ip_address()` |
| Timeout | 10s | 5s |

**Heuristique Commix :** envoie `; id`, `&& id`, `| id`, backticks,
`$()`, `%0a id`, puis cherche la signature de sortie de commande
(uid, gid) ou mesure le timing (`sleep`). Avec une liste blanche stricte
d'IP, aucune injection ne passe.

### Path Traversal

| Aspect | Vulnérable | Sécurisée |
|---|---|---|
| Chemin | `os.path.join(UPLOAD, name)` | `secure_filename()` + `Path.resolve()` |
| Contrôle | aucun | filtre `..`, `/`, `\`, `%2e` + préfixe |
| Err | 404 | 403 |

**Heuristique DotDotPwn :** fuzzing par **profondeur** (`-d N`) et par
**encodage** (URL, double URL, UTF-8 overlong, `%c0%af`).
La vérification `str(target).startswith(str(base))` après
`Path.resolve()` **normalise** ces encodages → toutes les tentatives
retombent dans `UPLOAD_FOLDER` et sont rejetées.

## 🛠️ Dépannage

| Problème | Solution |
|---|---|
| **Port 5000/5001 déjà utilisé** | `ss -tlnp \| grep 500` (Arch) / `netstat -ano \| findstr :500` (Win) puis tuer le PID. Modifier `PORT_VULN`/`PORT_SECURE` dans `config.py`. |
| **Antivirus Windows bloque les payloads** | Ajouter une exception pour `venv\`, les dépôts clonés et le dossier du projet. Couper temporairement la protection temps réel pendant les tests. |
| **`Set-ExecutionPolicy` bloque `run.ps1`** | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` (une seule fois). |
| **DotDotPwn introuvable sous Windows** | Utiliser **WSL2** obligatoirement (dépendance Perl). Voir `pentest/commands_windows.md`. |
| **`PermissionError` sur `uploads/`** | Arch : `chmod 755 uploads`. Windows : vérifier que l'utilisateur a les droits en écriture sur le dossier projet. |
| **Flask ne recharge pas après modif** | Normal : `use_reloader=False`. Relancer `run_both.py` manuellement. |
| **`sqlite3.OperationalError: no such table`** | Relancer `python database/init_db.py`. |
| **XSStrike ne se lance pas (Python 3.12)** | Utiliser WSL2 ou un venv Python 3.10 pour XSStrike. |

## 👥 Répartition du travail (binôme)

| Étudiant | OS | Rôle principal |
|---|---|---|
| **A** | Arch Linux | Setup Arch + tests **SQLMap** et **DotDotPwn** ; vérifie que `ping -c 1` fonctionne ; documente `commands_arch.md`. |
| **B** | Windows 11 (WSL2) | Setup Windows + tests **XSStrike** et **Commix** ; vérifie que `ping -n 1` fonctionne ; documente `commands_windows.md`. |
| **Commun** | — | Rédaction du README, captures d'écran, analyse comparative 5000 vs 5001, soutenance. |

Chacun teste l'application sur **son** OS pour prouver la portabilité,
puis les deux comparent leurs résultats (idéalement avec un git push /
pull pour partager les captures).

## 📄 Licence

Projet universitaire — usage strictement pédagogique en environnement
isolé. Toute utilisation sur une cible réelle sans autorisation est
illégale.
