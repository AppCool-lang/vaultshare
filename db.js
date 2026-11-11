/**
 * VaultShare — Base de données SQLite (better-sqlite3)
 * Schéma : users, files, pairings, email_codes
 */
const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'vaultshare.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT DEFAULT '',
  verified INTEGER DEFAULT 0,
  banned INTEGER DEFAULT 0,
  provider TEXT DEFAULT 'email',
  provider_sub TEXT DEFAULT '',
  device_fingerprint TEXT DEFAULT '',
  ip TEXT DEFAULT '',
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS email_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  code TEXT NOT NULL,
  type TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  name TEXT NOT NULL,
  size INTEGER NOT NULL,
  path TEXT NOT NULL,
  status TEXT DEFAULT 'scanning',
  scan_result TEXT DEFAULT '',
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS pairings (
  code TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_files_user ON files(user_id);
CREATE INDEX IF NOT EXISTS idx_users_device ON users(device_fingerprint);
`);

module.exports = db;
