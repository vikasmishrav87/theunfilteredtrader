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

export function getOAuthClient(req?: Request) {
  const currentClientId = process.env.GOOGLE_CLIENT_ID
  const currentClientSecret = process.env.GOOGLE_CLIENT_SECRET

  let dynamicCallback = process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback'
  if (req && !process.env.GOOGLE_CALLBACK_URL) {
    const proto = (req.headers['x-forwarded-proto'] as string) || req.protocol || 'https'
    const host = (req.headers['x-forwarded-host'] as string) || req.headers.host
    if (host) {
      dynamicCallback = `${proto}://${host}/auth/google/callback`
    }
  }

  return {
    clientId: currentClientId,
    clientSecret: currentClientSecret,
    callbackUrl: dynamicCallback,
    client: new OAuth2Client(currentClientId, currentClientSecret, dynamicCallback)
  }
}

function createSignedState(returnTo: string = '/dashboard'): string {
  const secret = process.env.SESSION_SECRET || 'state-signing-fallback-secret-at-least-32-chars'
  const nonce = crypto.randomBytes(16).toString('hex')
  const ts = Date.now()
  const payload = Buffer.from(JSON.stringify({ nonce, returnTo, ts })).toString('base64url')
  const sig = crypto.createHmac('sha256', secret).update(payload).digest('base64url')
  return `${payload}.${sig}`
}

function verifySignedState(stateStr: string): { valid: boolean; returnTo: string } {
  try {
    const parts = stateStr.split('.')
    if (parts.length !== 2) return { valid: false, returnTo: '/dashboard' }
    const [payload, sig] = parts
    const secret = process.env.SESSION_SECRET || 'state-signing-fallback-secret-at-least-32-chars'
    const expectedSig = crypto.createHmac('sha256', secret).update(payload).digest('base64url')

    const sigBuf = Buffer.from(sig)
    const expectedBuf = Buffer.from(expectedSig)
    if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
      return { valid: false, returnTo: '/dashboard' }
    }

    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'))
    // Expire state after 15 minutes
    if (Date.now() - data.ts > 15 * 60 * 1000) {
      return { valid: false, returnTo: '/dashboard' }
    }
    const safeReturnTo = typeof data.returnTo === 'string' && data.returnTo.startsWith('/')
      ? data.returnTo
      : '/dashboard'
    return { valid: true, returnTo: safeReturnTo }
  } catch {
    return { valid: false, returnTo: '/dashboard' }
  }
}

/**
 * 1. GET /auth/google
 * Initiates the Google OAuth 2.0 Authorization Code flow with CSRF state protection.
 */
router.get('/google', (req: Request, res: Response) => {
  const { clientId, clientSecret, callbackUrl, client } = getOAuthClient(req)

  if (!clientId || !clientSecret) {
    return res.status(500).json({ error: 'OAuth provider credentials not configured' })
  }

  // Store returnTo path if provided safely (prevent open redirect)
  const returnTo = typeof req.query.returnTo === 'string' && req.query.returnTo.startsWith('/')
    ? req.query.returnTo
    : '/dashboard'

  // Generate cryptographically signed HMAC state parameter for OAuth CSRF defense
  const state = createSignedState(returnTo)
  req.session.oauthState = state
  req.session.oauthReturnTo = returnTo

  // Explicit session save before redirect to prevent serverless race conditions
  req.session.save(() => {
    // Construct official Google authorization URL
    const authorizeUrl = client.generateAuthUrl({
      access_type: 'online',
      scope: ['openid', 'email', 'profile'],
      state,
      prompt: 'select_account',
      redirect_uri: callbackUrl
    })

    res.redirect(authorizeUrl)
  })
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

    // CSRF Check: Validate state parameter (HMAC signed or session state match)
    let isValidState = false
    let targetUrl = '/dashboard'

    if (state && typeof state === 'string') {
      // 1. Try HMAC cryptographic signature (stateless / serverless proof)
      const hmacResult = verifySignedState(state)
      if (hmacResult.valid) {
        isValidState = true
        targetUrl = hmacResult.returnTo
      }
      // 2. Fallback to session check if matching
      if (!isValidState && req.session.oauthState && req.session.oauthState === state) {
        isValidState = true
        targetUrl = req.session.oauthReturnTo || '/dashboard'
      }
    }

    if (!isValidState) {
      logSecurityEvent('OAUTH_CSRF_STATE_MISMATCH', null, ip, userAgent, {
        providedState: state,
        expectedState: req.session.oauthState
      })
      delete req.session.oauthState
      return res.status(403).redirect('/signin?error=csrf_validation_failed')
    }

    // Clear state once validated to prevent replay
    delete req.session.oauthState
    delete req.session.oauthReturnTo

    // Server-to-server exchange: code for tokens
    const { clientId, client, callbackUrl } = getOAuthClient(req)
    const { tokens } = await client.getToken({
      code,
      redirect_uri: callbackUrl
    })

    if (!tokens.id_token) {
      logSecurityEvent('OAUTH_MISSING_ID_TOKEN', null, ip, userAgent, {})
      return res.status(400).redirect('/signin?error=no_id_token')
    }

    // Cryptographically verify ID Token using google-auth-library
    const ticket = await client.verifyIdToken({
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

      // Persist session before redirect
      req.session.save(() => {
        res.redirect(targetUrl)
      })
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
    const { clientId, client } = getOAuthClient(req)
    const ticket = await client.verifyIdToken({
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
