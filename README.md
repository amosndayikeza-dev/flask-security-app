# Security Lab — Vulnerable Flask vs Secure Flask

> ⚠️ **Strictly for educational use** — isolated environment (localhost).
> Never expose these applications on a public network.

## 📌 Objective

Compare the behavior of **4 families of attacks** against the **same
Flask application** exposed in two versions:

| Port | Version   | Protection |
|------|-----------|------------|
| 5000 | Vulnerable | ❌ None     |
| 5001 | Secure     | ✅ Complete |

## 🗂️ Common Routes

| Route               | Vulnerability tested    | Tool      |
|---------------------|-------------------------|-----------|
| `/login` (POST)     | SQL Injection           | SQLMap     |
| `/search?q=`        | SQLi + Reflected XSS    | SQLMap, XSStrike |
| `/user?id=`         | SQL Injection           | SQLMap     |
| `/profile` (POST)   | Stored XSS              | XSStrike   |
| `/ping` (POST)      | Command Injection       | Commix     |
| `/files?name=`      | Path Traversal          | DotDotPwn  |

## 🚀 Installation

### On Arch Linux (Student A)

```bash
# System dependencies (pentest tools)
sudo pacman -S sqlmap python python-pip base-devel
yay -S xsstrike commix dotdotpwn   # or via git fallback

# Project environment
cd flask_tp_securite
chmod +x setup.sh run.sh
./setup.sh
./run.sh
```

### On Windows 11 (Student B)

```powershell
# Prerequisite: Python 3.10+ installed via winget
winget install Python.Python.3.12

# Pentest tools: WSL2 strongly recommended
wsl --install -d Ubuntu

# Project environment (PowerShell)
cd flask_tp_securite
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned   # once only
.\setup.ps1
.\run.ps1
```

The application is available at:
- http://127.0.0.1:5000 → VULNERABLE
- http://127.0.0.1:5001 → SECURE

## 🧪 Attack Scenarios

### 1. XSS with XSStrike

```bash
# Port 5000 (VULNERABLE)
xsstrike -u "http://localhost:5000/search?q=test"
# → Reflected payload found → exploit successful

# Port 5001 (SECURE)
xsstrike -u "http://localhost:5001/search?q=test"
# → "0 payload found" — Jinja2 escaping + CSP + bleach
```

### 2. SQL Injection with SQLMap

```bash
# Port 5000 (VULNERABLE)
sqlmap -u "http://localhost:5000/user?id=1" --batch --dbs
# → "Parameter: id (GET) — boolean-based blind"
# → Full database dump possible

# Port 5001 (SECURE)
sqlmap -u "http://localhost:5001/user?id=1" --batch --level=5 --risk=3
# → "not injectable" — prepared statements + strict int()
```

### 3. Command Injection with Commix

```bash
# Port 5000
commix --url="http://localhost:5000/ping" --data="ip=127.0.0.1" --batch
# → Shell obtained (os_shell)

# Port 5001
commix --url="http://localhost:5001/ping" --data="ip=127.0.0.1" --batch
# → "no injection point detected" — ipaddress + shell=False
```

### 4. Path Traversal with DotDotPwn

```bash
# Port 5000
dotdotpwn -m http-url \
  -u "http://localhost:5000/files?name=TRAVERSAL" \
  -k "root:" -d 6 -f pentest/wordlist_traversal.txt
# → Vulnerability found, /etc/passwd readable

# Port 5001
dotdotpwn -m http-url \
  -u "http://localhost:5001/files?name=TRAVERSAL" \
  -k "root:" -d 6 -f pentest/wordlist_traversal.txt
# → "0 vulnerability found"
```

## 🔬 Analysis — why it works / why it's blocked

### XSS

| Aspect | Vulnerable | Secure |
|---|---|---|
| Rendering of `q` parameter | `{{ q | safe }}` | `{{ q }}` (auto-escape) |
| `bio` field in database | Raw HTML preserved | `bleach.clean()` strips everything |
| Headers | none | CSP `default-src 'self'` |
| Cookies | default | `HttpOnly`, `SameSite=Lax` |

**XSStrike heuristic:** it sends unique payloads, detects **raw**
reflection in the returned HTML, analyzes the **context**
(inside `<script>`, inside an attribute, etc.) and generates adapted
payloads. As soon as `<` is escaped to `&lt;`, detection fails.

### SQL Injection

| Aspect | Vulnerable | Secure |
|---|---|---|
| Query | concatenated f-string | parameterized `?` |
| `id` | concatenated | `int()` + ValueError → 400 |
| Errors | raw SQLite traceback | generic message |
| Rate limit | none | 5/min via Flask-Limiter |
| Passwords | plaintext | Werkzeug hash |

**SQLMap heuristics:**
- **Boolean-based blind:** compares response content between `AND 1=1` and `AND 1=2`.
- **Time-based blind:** injects `SLEEP(5)` and measures latency.
- **Error-based:** forces an SQL error and reads the message.
On the secure version, none of these signals appear.

### Command Injection

| Aspect | Vulnerable | Secure |
|---|---|---|
| Call | `shell=True` + concatenation | `subprocess.run([...], shell=False)` |
| Validation | none | `ipaddress.ip_address()` |
| Timeout | 10s | 5s |

**Commix heuristic:** sends `; id`, `&& id`, `| id`, backticks,
`$()`, `%0a id`, then looks for command output signatures
(uid, gid) or measures timing (`sleep`). With a strict IP whitelist,
no injection gets through.

### Path Traversal

| Aspect | Vulnerable | Secure |
|---|---|---|
| Path | `os.path.join(UPLOAD, name)` | `secure_filename()` + `Path.resolve()` |
| Control | none | filter `..`, `/`, `\`, `%2e` + prefix check |
| Error | 404 | 403 |

**DotDotPwn heuristic:** fuzzing by **depth** (`-d N`) and by
**encoding** (URL, double URL, UTF-8 overlong, `%c0%af`).
The `str(target).startswith(str(base))` check after
`Path.resolve()` **normalizes** these encodings → all attempts
fall back into `UPLOAD_FOLDER` and are rejected.

## 🛠️ Troubleshooting

| Issue | Solution |
|---|---|
| **Port 5000/5001 already in use** | `ss -tlnp \| grep 500` (Arch) / `netstat -ano \| findstr :500` (Win), then kill the PID. Change `PORT_VULN`/`PORT_SECURE` in `config.py`. |
| **Windows antivirus blocks payloads** | Add an exception for `venv\`, the cloned repos, and the project folder. Temporarily disable real-time protection during tests. |
| **`Set-ExecutionPolicy` blocks `run.ps1`** | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` (once only). |
| **DotDotPwn not found on Windows** | Use **WSL2** (Perl dependency). See `pentest/commands_windows.md`. |
| **`PermissionError` on `uploads/`** | Arch: `chmod 755 uploads`. Windows: ensure the user has write permission on the project folder. |
| **Flask does not reload after edits** | Normal: `use_reloader=False`. Restart `run_both.py` manually. |
| **`sqlite3.OperationalError: no such table`** | Re-run `python database/init_db.py`. |
| **XSStrike won't launch (Python 3.12)** | Use WSL2 or a Python 3.10 venv for XSStrike. |

## 👥 Task Distribution (pair)

| Student | OS | Main role |
|---|---|---|
| **A** | Arch Linux | Arch setup + **SQLMap** and **DotDotPwn** tests; verifies `ping -c 1` works; documents `commands_arch.md`. |
| **B** | Windows 11 (WSL2) | Windows setup + **XSStrike** and **Commix** tests; verifies `ping -n 1` works; documents `commands_windows.md`. |
| **Shared** | — | README writing, screenshots, comparative analysis 5000 vs 5001, presentation. |

Each tests the application on **their own** OS to prove portability,
then both compare results (ideally with a git push / pull to share
the screenshots).

## 📄 License

University project — strictly for educational use in an isolated
environment. Any use on a real target without authorization is
illegal.
