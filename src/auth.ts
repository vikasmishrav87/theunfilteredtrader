import { Request, Response, NextFunction, Router } from 'express'
import { OAuth2Client } from 'google-auth-library'
import crypto from 'node:crypto'
import {
  upsertGoogleUser,
  getUserById,
  logSecurityEvent,
  UserRecord
} from './db.js'

// Extend Express SessionData to include our custom session fields
declare module 'express-session' {
  interface SessionData {
    userId?: number
    oauthState?: string
    oauthReturnTo?: string
  }
}

const router = Router()

// Validate environment variables on startup
const clientId = process.env.GOOGLE_CLIENT_ID
const clientSecret = process.env.GOOGLE_CLIENT_SECRET
const callbackUrl = process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback'

if (!clientId || !clientSecret) {
  console.warn('WARNING: GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET not configured. Google Sign-In will be disabled until set.')
}

export const googleClient = new OAuth2Client(clientId, clientSecret, callbackUrl)

/**
 * 1. GET /auth/google
 * Initiates the Google OAuth 2.0 Authorization Code flow with CSRF state protection.
 */
router.get('/google', (req: Request, res: Response) => {
  if (!clientId || !clientSecret) {
    return res.status(500).json({ error: 'OAuth provider credentials not configured' })
  }

  // Generate cryptographically random 256-bit state parameter for OAuth CSRF defense
  const state = crypto.randomBytes(32).toString('hex')
  req.session.oauthState = state

  // Store returnTo path if provided safely (prevent open redirect)
  const returnTo = typeof req.query.returnTo === 'string' && req.query.returnTo.startsWith('/')
    ? req.query.returnTo
    : '/dashboard'
  req.session.oauthReturnTo = returnTo

  // Construct official Google authorization URL
  const authorizeUrl = googleClient.generateAuthUrl({
    access_type: 'online',
    scope: ['openid', 'email', 'profile'],
    state,
    prompt: 'select_account',
    redirect_uri: callbackUrl
  })

  res.redirect(authorizeUrl)
})

/**
 * 2. GET /auth/google/callback
 * Handles the OAuth 2.0 authorization code exchange and cryptographic ID token verification.
 */
router.get('/google/callback', async (req: Request, res: Response) => {
  const ip = req.ip || req.socket.remoteAddress || 'unknown'
  const userAgent = req.headers['user-agent'] || 'unknown'

  try {
    const { code, state, error } = req.query

    if (error) {
      logSecurityEvent('OAUTH_ERROR_RETURNED', null, ip, userAgent, { error: String(error) })
      return res.redirect('/signin?error=oauth_cancelled')
    }

    if (!code || typeof code !== 'string') {
      logSecurityEvent('OAUTH_MISSING_CODE', null, ip, userAgent, {})
      return res.status(400).redirect('/signin?error=invalid_request')
    }

    // CSRF Check: Validate state parameter matches session state
    if (!state || typeof state !== 'string' || !req.session.oauthState || state !== req.session.oauthState) {
      logSecurityEvent('OAUTH_CSRF_STATE_MISMATCH', null, ip, userAgent, {
        providedState: state,
        expectedState: req.session.oauthState
      })
      delete req.session.oauthState
      return res.status(403).redirect('/signin?error=csrf_validation_failed')
    }

    // Clear state once validated to prevent replay
    delete req.session.oauthState
    const targetUrl = req.session.oauthReturnTo || '/dashboard'
    delete req.session.oauthReturnTo

    // Server-to-server exchange: code for tokens
    const { tokens } = await googleClient.getToken({
      code,
      redirect_uri: callbackUrl
    })

    if (!tokens.id_token) {
      logSecurityEvent('OAUTH_MISSING_ID_TOKEN', null, ip, userAgent, {})
      return res.status(400).redirect('/signin?error=no_id_token')
    }

    // Cryptographically verify ID Token using google-auth-library
    const ticket = await googleClient.verifyIdToken({
      idToken: tokens.id_token,
      audience: clientId
    })

    const payload = ticket.getPayload()
    if (!payload) {
      logSecurityEvent('OAUTH_INVALID_PAYLOAD', null, ip, userAgent, {})
      return res.status(400).redirect('/signin?error=invalid_token')
    }

    // Strict validation of Google Claims
    const { sub, email, email_verified, name, picture, iss } = payload

    // 1. Validate Issuer
    const validIssuers = ['accounts.google.com', 'https://accounts.google.com']
    if (!iss || !validIssuers.includes(iss)) {
      logSecurityEvent('OAUTH_INVALID_ISSUER', null, ip, userAgent, { iss })
      return res.status(400).redirect('/signin?error=invalid_issuer')
    }

    // 2. Validate Subject (sub claim) as stable account identifier
    if (!sub || typeof sub !== 'string' || sub.trim() === '') {
      logSecurityEvent('OAUTH_MISSING_SUB', null, ip, userAgent, {})
      return res.status(400).redirect('/signin?error=missing_subject')
    }

    // 3. Validate Email and Email Verification
    if (!email || !email_verified) {
      logSecurityEvent('OAUTH_UNVERIFIED_EMAIL', null, ip, userAgent, { email, email_verified })
      return res.status(400).redirect('/signin?error=email_not_verified')
    }

    // Upsert into backend database (stable Google sub used as unique key)
    const user = upsertGoogleUser(sub, email, email_verified, name, picture)

    // Session Rotation (prevention of session fixation attacks)
    req.session.regenerate((err) => {
      if (err) {
        console.error('Session rotation failed:', err)
        return res.status(500).redirect('/signin?error=session_error')
      }

      // Set server-managed authenticated identity
      req.session.userId = user.id

      logSecurityEvent('LOGIN_SUCCESS', user.id, ip, userAgent, {
        method: 'oauth_code',
        email: user.email
      })

      // Redirect safely to intended dashboard
      res.redirect(targetUrl)
    })
  } catch (err: any) {
    console.error('OAuth Callback Error:', err.message || err)
    logSecurityEvent('LOGIN_FAILED', null, ip, userAgent, { error: err.message })
    res.status(500).redirect('/signin?error=authentication_failed')
  }
})

/**
 * 3. POST /api/auth/google/verify
 * Server-side verification for Google One-Tap / Google Sign-In Button ID tokens.
 */
router.post('/google/verify', async (req: Request, res: Response) => {
  const ip = req.ip || req.socket.remoteAddress || 'unknown'
  const userAgent = req.headers['user-agent'] || 'unknown'

  try {
    const { credential, id_token } = req.body
    const token = credential || id_token

    if (!token || typeof token !== 'string') {
      return res.status(400).json({ error: 'Missing or malformed token' })
    }

    // Cryptographic verification with google-auth-library
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: clientId
    })

    const payload = ticket.getPayload()
    if (!payload) {
      return res.status(401).json({ error: 'Token payload missing' })
    }

    const { sub, email, email_verified, name, picture, iss } = payload

    const validIssuers = ['accounts.google.com', 'https://accounts.google.com']
    if (!iss || !validIssuers.includes(iss)) {
      logSecurityEvent('TOKEN_INVALID_ISSUER', null, ip, userAgent, { iss })
      return res.status(401).json({ error: 'Invalid token issuer' })
    }

    if (!sub || typeof sub !== 'string') {
      logSecurityEvent('TOKEN_MISSING_SUB', null, ip, userAgent, {})
      return res.status(401).json({ error: 'Invalid subject claim' })
    }

    if (!email || !email_verified) {
      logSecurityEvent('TOKEN_UNVERIFIED_EMAIL', null, ip, userAgent, { email })
      return res.status(403).json({ error: 'Verified email required' })
    }

    // Store in backend SQLite
    const user = upsertGoogleUser(sub, email, email_verified, name, picture)

    // Rotate session to prevent session fixation
    req.session.regenerate((err) => {
      if (err) {
        return res.status(500).json({ error: 'Session creation failed' })
      }

      req.session.userId = user.id

      logSecurityEvent('LOGIN_SUCCESS', user.id, ip, userAgent, {
        method: 'id_token_direct',
        email: user.email
      })

      return res.status(200).json({
        success: true,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          picture: user.picture,
          role: user.role
        }
      })
    })
  } catch (err: any) {
    console.error('ID Token Verification Error:', err.message || err)
    logSecurityEvent('LOGIN_FAILED', null, ip, userAgent, { error: err.message })
    return res.status(401).json({ error: 'Invalid or expired authentication token' })
  }
})

/**
 * 4. GET /auth/logout and POST /api/auth/logout
 * Server-side session revocation: Destroys session in DB, clears cookie, logs event.
 */
export const handleLogout = (req: Request, res: Response) => {
  const userId = req.session.userId || null
  const ip = req.ip || req.socket.remoteAddress || 'unknown'
  const userAgent = req.headers['user-agent'] || 'unknown'

  if (userId) {
    logSecurityEvent('LOGOUT', userId, ip, userAgent, {})
  }

  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error destroying session:', err)
    }

    // Clear session cookie with matching security parameters
    const cookieName = process.env.NODE_ENV === 'production' ? '__Host-sid' : 'sid'
    res.clearCookie(cookieName, {
      path: '/',
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax'
    })

    if (req.xhr || req.headers.accept?.includes('application/json')) {
      return res.status(200).json({ success: true, message: 'Logged out successfully' })
    }
    return res.redirect('/signin?logged_out=1')
  })
}

router.get('/logout', handleLogout)
router.post('/logout', handleLogout)

export default router
