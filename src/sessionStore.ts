import session from 'express-session'
import { db } from './db.js'

interface SessionRow {
  sid: string
  sess: string
  expired_at: number
}

const getSessionStmt = db.prepare('SELECT sess, expired_at FROM sessions WHERE sid = ?')
const setSessionStmt = db.prepare(`
  INSERT INTO sessions (sid, sess, expired_at)
  VALUES (?, ?, ?)
  ON CONFLICT(sid) DO UPDATE SET
    sess = excluded.sess,
    expired_at = excluded.expired_at
`)
const destroySessionStmt = db.prepare('DELETE FROM sessions WHERE sid = ?')
const touchSessionStmt = db.prepare('UPDATE sessions SET expired_at = ? WHERE sid = ?')
const clearExpiredStmt = db.prepare('DELETE FROM sessions WHERE expired_at < ?')

export class SqliteSessionStore extends session.Store {
  private cleanupInterval: NodeJS.Timeout

  constructor() {
    super()
    // Run cleanup every 15 minutes
    this.cleanupInterval = setInterval(() => {
      this.clearExpired()
    }, 15 * 60 * 1000)
    // Don't keep the process alive solely for session cleanup
    this.cleanupInterval.unref()
  }

  get(sid: string, callback: (err?: any, sessionData?: session.SessionData | null) => void): void {
    try {
      const now = Date.now()
      const row = getSessionStmt.get(sid) as unknown as SessionRow | undefined

      if (!row) {
        return callback(null, null)
      }

      if (row.expired_at < now) {
        // Session expired, remove it
        destroySessionStmt.run(sid)
        return callback(null, null)
      }

      const sessionData = JSON.parse(row.sess) as session.SessionData
      return callback(null, sessionData)
    } catch (err) {
      return callback(err)
    }
  }

  set(sid: string, sessionData: session.SessionData, callback?: (err?: any) => void): void {
    try {
      let maxAge = 24 * 60 * 60 * 1000 // default 24h
      if (sessionData.cookie && sessionData.cookie.expires) {
        maxAge = new Date(sessionData.cookie.expires).getTime() - Date.now()
      } else if (sessionData.cookie && sessionData.cookie.maxAge) {
        maxAge = sessionData.cookie.maxAge
      }

      const expiredAt = Date.now() + Math.max(maxAge, 1000)
      const sessJson = JSON.stringify(sessionData)

      setSessionStmt.run(sid, sessJson, expiredAt)
      if (callback) callback(null)
    } catch (err) {
      if (callback) callback(err)
    }
  }

  destroy(sid: string, callback?: (err?: any) => void): void {
    try {
      destroySessionStmt.run(sid)
      if (callback) callback(null)
    } catch (err) {
      if (callback) callback(err)
    }
  }

  touch(sid: string, sessionData: session.SessionData, callback?: (err?: any) => void): void {
    try {
      let maxAge = 24 * 60 * 60 * 1000
      if (sessionData.cookie && sessionData.cookie.expires) {
        maxAge = new Date(sessionData.cookie.expires).getTime() - Date.now()
      } else if (sessionData.cookie && sessionData.cookie.maxAge) {
        maxAge = sessionData.cookie.maxAge
      }

      const expiredAt = Date.now() + Math.max(maxAge, 1000)
      touchSessionStmt.run(expiredAt, sid)
      if (callback) callback(null)
    } catch (err) {
      if (callback) callback(err)
    }
  }

  clearExpired(): void {
    try {
      clearExpiredStmt.run(Date.now())
    } catch (err) {
      console.error('Session expiration cleanup error:', err)
    }
  }
}
