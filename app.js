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

// LIST FILES
app.get("/files", (req, res) => {
  const user = req.query.user;
  if (!user) return res.json([]);

  const dir = path.join(__dirname, "uploads", user);
  if (!fs.existsSync(dir)) return res.json([]);

  res.json(fs.readdirSync(dir));
});

// DELETE FILE
app.post("/delete", (req, res) => {
  const { username, filename } = req.body;
  if (!username || !filename)
    return res.status(400).json({ error: "Missing data" });

  const filePath = path.join(__dirname, "uploads", username, filename);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

  res.json({ success: true });
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
