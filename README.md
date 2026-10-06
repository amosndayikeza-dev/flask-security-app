# 🔐 Security Lab — Vulnerable Flask vs Secure Flask

> ⚠️ **Educational use only** — all tests are performed locally on `localhost`.

## 🎯 Objective

Compare the same Flask application in two versions:

| Port   | Version       | Goal                        |
| ------ | ------------- | --------------------------- |
| `5000` | 🔴 Vulnerable | Demonstrate security flaws  |
| `5001` | 🟢 Secure     | Verify security protections |

---

## 🧪 Vulnerabilities & Tools

| Vulnerability        | Route                        | Tool          |
| -------------------- | ---------------------------- | ------------- |
| 💉 SQL Injection     | `/login`, `/user`, `/search` | **SQLMap**    |
| 🕷️ XSS              | `/search`, `/profile`        | **XSStrike**  |
| 💻 Command Injection | `/ping`                      | **Commix**    |
| 📁 Path Traversal    | `/files`                     | **DotDotPwn** |

---

## 🛠️ Pentesting Tools

### 💉 SQLMap — SQL Injection

**SQLMap** automatically detects and tests **SQL Injection** vulnerabilities in HTTP parameters.

Example:

```bash
sqlmap -u "http://127.0.0.1:5000/user?id=1" --batch
```

🔴 **Port 5000 — Vulnerable**

SQLMap confirmed that the `id` parameter is injectable.

Detected techniques included:

* Boolean-based blind SQL Injection
* Time-based blind SQL Injection
* UNION-based SQL Injection

🟢 **Port 5001 — Secure**

The `id` parameter is protected using input validation and parameterized SQL queries.

---

### 🕷️ XSStrike — Cross-Site Scripting

**XSStrike** is specialized in detecting **XSS (Cross-Site Scripting)** vulnerabilities.

It tests whether user-controlled input is reflected into the HTML without proper escaping.

Example:

```bash
./pentest_fixed/xsstrike.sh http://127.0.0.1:5000
```

🔴 **Port 5000 — Vulnerable**

The `/search?q=` parameter can be reflected without HTML escaping.

The vulnerable template uses:

```jinja2
{{ q|safe }}
```

🟢 **Port 5001 — Secure**

Jinja2 automatic HTML escaping is enabled:

```jinja2
{{ q }}
```

This prevents injected HTML/JavaScript from being interpreted by the browser.

---

### 💻 Commix — Command Injection

**Commix** detects **OS Command Injection** vulnerabilities.

Example:

```bash
./pentest_fixed/commix.sh http://127.0.0.1:5000
```

🔴 **Port 5000 — Vulnerable**

Commix confirmed:

```text
POST parameter 'ip' appears to be injectable
POST parameter 'ip' is vulnerable
```

It identified several injection techniques:

* Classic command injection
* Boolean-based blind injection
* Time-based blind injection
* File-based blind injection

The vulnerability comes from executing a command using user-controlled input with:

```python
shell=True
```

🟢 **Port 5001 — Secure**

The secure version:

```python
subprocess.run([...], shell=False)
```

and validates the IP address before execution.

---

### 📁 DotDotPwn — Path Traversal

**DotDotPwn** is designed to detect **Path Traversal** vulnerabilities.

Target:

```text
/files?name=...
```

🔴 **Port 5000 — Vulnerable**

Traversal sequences such as:

```text
../../../../etc/passwd
```

can access files outside the intended directory.

🟢 **Port 5001 — Secure**

The secure version uses:

* `secure_filename()`
* `Path.resolve()`
* Path validation
* Directory boundary checks

This prevents access outside the allowed directory.

---

## 🔬 Vulnerable vs Secure

| Area     | 🔴 Vulnerable            | 🟢 Secure                  |
| -------- | ------------------------ | -------------------------- |
| SQL      | String concatenation     | Parameterized queries      |
| XSS      | Raw HTML rendering       | Jinja2 escaping            |
| Commands | `shell=True`             | `shell=False`              |
| Input    | Weak validation          | Strict validation          |
| Files    | Direct path construction | Resolved & validated paths |

---

## 🚀 Running the Lab

Start both applications:

```bash
python run_both.py
```

Then open:

```text
🔴 http://127.0.0.1:5000 → Vulnerable
🟢 http://127.0.0.1:5001 → Secure
```

Default lab credentials:

```text
Username: admin
Password: admin
```

---

## 📌 Main Result

The lab demonstrates the complete security workflow:

```text
🔎 Identify the vulnerability
        ↓
🧪 Test it with a pentesting tool
        ↓
💥 Confirm the vulnerability
        ↓
🔧 Apply a security fix
        ↓
🛡️ Test the secure version
```

The main objective is to connect the **vulnerable code**, the **observed attack**, and the **corresponding security fix**.

---

## ⚠️ Disclaimer

This project is intended **strictly for educational purposes** in an isolated local environment.

Do not use these techniques against systems without explicit authorization.
