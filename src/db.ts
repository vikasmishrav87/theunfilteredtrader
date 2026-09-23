import { DatabaseSync } from 'node:sqlite'
import path from 'path'
import fs from 'fs'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

import os from 'os'

// Ensure data directory exists (use writable /tmp directory on Vercel serverless)
const isVercel = Boolean(process.env.VERCEL)
const dataDir = isVercel ? os.tmpdir() : path.join(process.cwd(), 'data')
if (!fs.existsSync(dataDir)) {
  try {
    fs.mkdirSync(dataDir, { recursive: true })
  } catch {}
}

const dbPath = path.join(dataDir, 'tradershub.db')
export const db = new DatabaseSync(dbPath)

// Initialize schema with strict constraints and indexes
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    google_sub TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    email_verified INTEGER NOT NULL DEFAULT 0,
    name TEXT,
    picture TEXT,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_login_at TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_users_google_sub ON users(google_sub);
  CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

  CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    sess TEXT NOT NULL,
    expired_at INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_sessions_expired_at ON sessions(expired_at);

  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    user_id INTEGER,
    ip_address TEXT,
    user_agent TEXT,
    details TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
  );

  CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
  CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
`)

export interface UserRecord {
  id: number
  google_sub: string
  email: string
  email_verified: number
  name: string | null
  picture: string | null
  role: string
  created_at: string
  updated_at: string
  last_login_at: string | null
}

// Prepared Statements for high performance and complete SQL injection immunity
const upsertUserStmt = db.prepare(`
  INSERT INTO users (google_sub, email, email_verified, name, picture, role, last_login_at, updated_at)
  VALUES (?, ?, ?, ?, ?, 'user', datetime('now'), datetime('now'))
  ON CONFLICT(google_sub) DO UPDATE SET
    email = excluded.email,
    email_verified = excluded.email_verified,
    name = excluded.name,
    picture = excluded.picture,
    last_login_at = datetime('now'),
    updated_at = datetime('now')
  RETURNING *
`)

const getUserByIdStmt = db.prepare(`
  SELECT id, google_sub, email, email_verified, name, picture, role, created_at, updated_at, last_login_at
  FROM users WHERE id = ?
`)

const getUserByGoogleSubStmt = db.prepare(`
  SELECT id, google_sub, email, email_verified, name, picture, role, created_at, updated_at, last_login_at
  FROM users WHERE google_sub = ?
`)

const logAuditEventStmt = db.prepare(`
  INSERT INTO audit_logs (event_type, user_id, ip_address, user_agent, details)
  VALUES (?, ?, ?, ?, ?)
`)

/**
 * Upsert Google User - uses Google `sub` as stable immutable identifier
 */
export function upsertGoogleUser(
  googleSub: string,
  email: string,
  emailVerified: boolean,
  name?: string | null,
  picture?: string | null
): UserRecord {
  const result = upsertUserStmt.get(
    googleSub,
    email,
    emailVerified ? 1 : 0,
    name || null,
    picture || null
  ) as unknown as UserRecord
  return result
}

/**
 * Fetch user by internal database ID
 */
export function getUserById(id: number): UserRecord | null {
  const row = getUserByIdStmt.get(id) as unknown as UserRecord | undefined
  return row || null
}

/**
 * Fetch user by Google sub claim
 */
export function getUserByGoogleSub(googleSub: string): UserRecord | null {
  const row = getUserByGoogleSubStmt.get(googleSub) as unknown as UserRecord | undefined
  return row || null
}

/**
 * Audit log recording without sensitive token or password exposure
 */
export function logSecurityEvent(
  eventType: string,
  userId: number | null,
  ipAddress: string,
  userAgent: string,
  details: Record<string, unknown>
): void {
  try {
    // Sanitize details to guarantee no secrets/tokens are logged
    const safeDetails = { ...details }
    delete safeDetails.client_secret
    delete safeDetails.password
    delete safeDetails.token
    delete safeDetails.id_token
    delete safeDetails.access_token

    logAuditEventStmt.run(
      eventType,
      userId,
      ipAddress || 'unknown',
      userAgent ? userAgent.substring(0, 255) : 'unknown',
      JSON.stringify(safeDetails)
    )
  } catch (err) {
    console.error('Failed to write security audit log:', err)
  }
}
