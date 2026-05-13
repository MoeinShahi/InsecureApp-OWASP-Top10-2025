// database.js — SQLite setup for FileCloud
// INTENTIONAL VULN: passwords stored as bcrypt hashes but user_id is sequential
// (predictable), enabling IDOR attacks via JWT payload manipulation.

const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const path = require("path");

const db = new Database(path.join(__dirname, "filecloud.db"));

// ── Schema ──────────────────────────────────────────────────────────────────

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT UNIQUE NOT NULL,
    password  TEXT NOT NULL,
    role      TEXT NOT NULL DEFAULT 'user',
    email     TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS sessions (
    session_id  TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL,
    created_at  TEXT DEFAULT (datetime('now')),
    expires_at  TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS activity_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER,
    username   TEXT,
    action     TEXT,
    ip         TEXT,
    ts         TEXT DEFAULT (datetime('now'))
  );
`);

// ── Seed default users ───────────────────────────────────────────────────────
// INTENTIONAL VULN: default credentials (admin/admin, alice/alice, bob/bob)
// These are documented in README as Default Credentials vulnerability.

const seedUsers = [
  { username: "alice", password: "alice",   role: "user",  email: "alice@filecloud.io" },
  { username: "bob",   password: "bob",     role: "user",  email: "bob@filecloud.io"   },
  { username: "admin", password: "admin",   role: "admin", email: "admin@filecloud.io" },
];

const insertUser = db.prepare(
  "INSERT OR IGNORE INTO users (username, password, role, email) VALUES (?, ?, ?, ?)"
);

for (const u of seedUsers) {
  const hash = bcrypt.hashSync(u.password, 10);
  insertUser.run(u.username, hash, u.role, u.email);
}

// ── Helper functions ─────────────────────────────────────────────────────────

function getUserByUsername(username) {
  return db.prepare("SELECT * FROM users WHERE username = ?").get(username);
}

function getUserById(id) {
  return db.prepare("SELECT * FROM users WHERE id = ?").get(id);
}

function getAllUsers() {
  return db.prepare("SELECT id, username, role, email, created_at FROM users").all();
}

function createUser(username, password, role, email) {
  const hash = bcrypt.hashSync(password, 10);
  return db.prepare(
    "INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)"
  ).run(username, hash, role || "user", email || "");
}

function deleteUser(username) {
  return db.prepare("DELETE FROM users WHERE username = ?").run(username);
}

function logActivity(userId, username, action, ip) {
  db.prepare(
    "INSERT INTO activity_log (user_id, username, action, ip) VALUES (?, ?, ?, ?)"
  ).run(userId || null, username || "anonymous", action, ip || "");
}

function getActivityLog() {
  return db.prepare(
    "SELECT * FROM activity_log ORDER BY ts DESC LIMIT 100"
  ).all();
}

module.exports = {
  db,
  getUserByUsername,
  getUserById,
  getAllUsers,
  createUser,
  deleteUser,
  logActivity,
  getActivityLog,
};
