import 'dotenv/config'
import express, { Request, Response, NextFunction } from 'express'
import path from 'path'
import { fileURLToPath } from 'url'
import session from 'express-session'
import cookieParser from 'cookie-parser'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
import authRouter, { handleLogout } from './auth.js'
import { SqliteSessionStore } from './sessionStore.js'
import { requireAuthApi, requireAuthPage, requireAdmin, verifyCsrfOrigin } from './middleware.js'
import { db, getUserById, logSecurityEvent } from './db.js'

import fs from 'fs'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const publicDir = fs.existsSync(path.join(process.cwd(), 'public'))
  ? path.join(process.cwd(), 'public')
  : path.join(__dirname, '..', 'public')

const app = express()
const isProd = process.env.NODE_ENV === 'production'

// Trust proxy if deployed behind Vercel or reverse proxy
app.set('trust proxy', 1)

// ==========================================
// 1. SECURITY HEADERS (Helmet)
// ==========================================
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'", // Needed for inline scripts on existing marketing pages
          'https://accounts.google.com',
          'https://apis.google.com'
        ],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          'https://fonts.googleapis.com',
          'https://accounts.google.com'
        ],
        fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
        imgSrc: [
          "'self'",
          'data:',
          'https://lh3.googleusercontent.com', // Google profile photos
          'https://*.googleusercontent.com'
        ],
        connectSrc: [
          "'self'",
          'https://accounts.google.com'
        ],
        frameSrc: [
          "'self'",
          'https://accounts.google.com' // Google One-Tap and iframe auth
        ],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'", 'https://accounts.google.com'],
        frameAncestors: ["'none'"]
      }
    },
    crossOriginEmbedderPolicy: false, // Allow Google OAuth popups
    crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    xContentTypeOptions: true,
    xFrameOptions: { action: 'deny' }
  })
)

// ==========================================
// 2. RATE LIMITING
// ==========================================
// Global limiter: 200 requests per minute
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
})
app.use(globalLimiter)

// Sensitive auth limiter: 30 requests per 15 minutes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts, please try again in 15 minutes.' }
})

// ==========================================
// 3. BODY PARSING & COOKIES
// ==========================================
app.use(express.json({ limit: '100kb' }))
app.use(express.urlencoded({ extended: false, limit: '100kb' }))
app.use(cookieParser())

// ==========================================
// 4. SESSION SECURITY
// ==========================================
const sessionSecret = process.env.SESSION_SECRET
if (!sessionSecret || sessionSecret.length < 32) {
  console.warn('WARNING: SESSION_SECRET is missing or has low entropy (<32 characters). Set a strong secret in .env.')
}

const cookieName = isProd ? '__Host-sid' : 'sid'

app.use(
  session({
    name: cookieName,
    secret: sessionSecret || 'fallback-dev-secret-do-not-use-in-production-12345678',
    store: new SqliteSessionStore(),
    resave: false,
    saveUninitialized: false,
    rolling: true, // Inactivity timeout refresh
    cookie: {
      httpOnly: true, // Inaccessible to JavaScript (XSS defense)
      secure: isProd, // Requires HTTPS in production
      sameSite: 'lax', // CSRF defense
      maxAge: 24 * 60 * 60 * 1000, // 24-hour absolute session duration
      path: '/'
    }
  })
)

// ==========================================
// 5. CSRF DEFENSE FOR STATE-CHANGING APIs
// ==========================================
app.use('/api', verifyCsrfOrigin)

// ==========================================
// 6. AUTHENTICATION ROUTES
// ==========================================
app.use('/auth', authLimiter, authRouter)
app.use('/api/auth', authLimiter, authRouter)

// ==========================================
// 7. USER & PROFILE APIs (Protected)
// ==========================================
/**
 * GET /api/me
 * Returns the currently authenticated user's profile from server session.
 */
app.get('/api/me', requireAuthApi, (req: Request, res: Response) => {
  const user = req.user!
  res.json({
    authenticated: true,
    user: {
      id: user.id,
      email: user.email,
      email_verified: Boolean(user.email_verified),
      name: user.name,
      picture: user.picture,
      role: user.role,
      created_at: user.created_at,
      last_login_at: user.last_login_at
    }
  })
})

/**
 * PUT /api/user/profile
 * Allows updating user name only. Prevents mass assignment and role escalation.
 */
app.put('/api/user/profile', requireAuthApi, (req: Request, res: Response) => {
  const user = req.user!
  const { name } = req.body

  if (name !== undefined && (typeof name !== 'string' || name.length > 100)) {
    return res.status(400).json({ error: 'Invalid name parameter' })
  }

  // Update profile with parameterized statement
  const updateStmt = db.prepare(`
    UPDATE users SET name = ?, updated_at = datetime('now') WHERE id = ?
  `)
  updateStmt.run(name || user.name, user.id)

  const updatedUser = getUserById(user.id)
  res.json({
    success: true,
    user: {
      id: updatedUser!.id,
      email: updatedUser!.email,
      name: updatedUser!.name,
      picture: updatedUser!.picture,
      role: updatedUser!.role
    }
  })
})

/**
 * GET /api/admin/audit-logs
 * Admin-only endpoint to inspect security audit trail.
 */
app.get('/api/admin/audit-logs', requireAuthApi, requireAdmin, (req: Request, res: Response) => {
  const logsStmt = db.prepare(`
    SELECT id, event_type, user_id, ip_address, user_agent, details, created_at
    FROM audit_logs
    ORDER BY id DESC
    LIMIT 100
  `)
  const logs = logsStmt.all()
  res.json({ success: true, logs })
})

// ==========================================
// 8. STATIC ASSETS & PUBLIC PAGES
// ==========================================
app.use(express.static(publicDir))

// Sign-in page
app.get('/signin', (req: Request, res: Response) => {
  if (req.session.userId) {
    return res.redirect('/dashboard')
  }
  res.sendFile(path.join(publicDir, 'signin.html'))
})

app.get('/login', (req: Request, res: Response) => {
  res.redirect('/signin')
})

// Protected Dashboard page (Server-side route protection)
app.get('/dashboard', requireAuthPage, (req: Request, res: Response) => {
  res.sendFile(path.join(publicDir, 'dashboard.html'))
})

// Home route
app.get('/', (req: Request, res: Response) => {
  res.sendFile(path.join(publicDir, 'index.html'))
})

// Dedicated marketing pages
const dedicatedPages = [
  'about',
  'vip',
  'brokers',
  'syllabus',
  'premium',
  'indian-market',
  'fibonacci-group',
  'courses',
  'mentorship',
  'prop-firms',
  'reviews',
  'chat',
  'feedback',
  'contact'
]

dedicatedPages.forEach(page => {
  app.get(`/${page}`, (req: Request, res: Response) => {
    res.sendFile(path.join(publicDir, `${page}.html`))
  })
})

// Aliases
app.get('/paid', (req: Request, res: Response) => {
  res.sendFile(path.join(publicDir, 'premium.html'))
})
app.get('/ai-chat', (req: Request, res: Response) => {
  res.sendFile(path.join(publicDir, 'chat.html'))
})
app.get('/suggestions', (req: Request, res: Response) => {
  res.sendFile(path.join(publicDir, 'feedback.html'))
})

// Health check
app.get('/healthz', (req: Request, res: Response) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() })
})

// ==========================================
// 9. CENTRALIZED SAFE ERROR HANDLER
// ==========================================
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error('Unhandled Server Error:', err)

  logSecurityEvent('UNHANDLED_SERVER_ERROR', req.session?.userId || null, req.ip || '', req.headers['user-agent'] || '', {
    message: err.message || 'Unknown error'
  })

  // Never expose stack traces or internal filesystem paths to clients
  res.status(500).json({
    error: 'Internal Server Error',
    message: 'An unexpected error occurred. Please try again later.'
  })
})

// Start server if executed directly
const PORT = process.env.PORT || 3000
const isMainModule = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])
if (isMainModule && process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    console.log(`[Traders Hub] Server running securely on port ${PORT}`)
  })
}

export default app
