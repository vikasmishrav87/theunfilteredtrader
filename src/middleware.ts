import { Request, Response, NextFunction } from 'express'
import { getUserById, logSecurityEvent, UserRecord } from './db.js'

// Extend Express Request to include authenticated user
declare global {
  namespace Express {
    interface Request {
      user?: UserRecord
    }
  }
}

/**
 * Server-side authentication guard for API endpoints.
 * Treats the backend as the security boundary.
 */
export function requireAuthApi(req: Request, res: Response, next: NextFunction): void {
  const userId = req.session.userId

  if (!userId) {
    res.status(401).json({
      error: 'Unauthorized',
      message: 'Authentication required. Please sign in.'
    })
    return
  }

  const user = getUserById(userId)
  if (!user) {
    // Stale or revoked user session
    req.session.destroy(() => {})
    res.status(401).json({
      error: 'Unauthorized',
      message: 'User account not found or revoked.'
    })
    return
  }

  req.user = user
  next()
}

/**
 * Server-side authentication guard for page routes.
 * Redirects unauthenticated browser requests to /signin.
 */
export function requireAuthPage(req: Request, res: Response, next: NextFunction): void {
  const userId = req.session.userId

  if (!userId) {
    const returnUrl = encodeURIComponent(req.originalUrl || '/dashboard')
    res.redirect(`/signin?returnTo=${returnUrl}`)
    return
  }

  const user = getUserById(userId)
  if (!user) {
    req.session.destroy(() => {})
    res.redirect('/signin')
    return
  }

  req.user = user
  next()
}

/**
 * Server-side role guard: requires 'admin' privilege derived strictly from DB.
 * Never trusts role values from client headers or body.
 */
export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  if (!req.user || req.user.role !== 'admin') {
    const ip = req.ip || req.socket.remoteAddress || 'unknown'
    const userAgent = req.headers['user-agent'] || 'unknown'

    logSecurityEvent('UNAUTHORIZED_ADMIN_ACCESS_ATTEMPT', req.user?.id || null, ip, userAgent, {
      path: req.originalUrl,
      attemptedRole: req.user?.role || 'anonymous'
    })

    res.status(403).json({
      error: 'Forbidden',
      message: 'Administrative privileges required.'
    })
    return
  }
  next()
}

/**
 * CSRF Protection for state-changing HTTP methods.
 * Verifies Origin or Referer header matches the application host.
 */
export function verifyCsrfOrigin(req: Request, res: Response, next: NextFunction): void {
  const safeMethods = ['GET', 'HEAD', 'OPTIONS']
  if (safeMethods.includes(req.method)) {
    return next()
  }

  const origin = req.headers['origin']
  const referer = req.headers['referer']
  const host = req.headers['host']

  if (!host) {
    res.status(400).json({ error: 'Missing Host header' })
    return
  }

  // Check Origin header if present
  if (origin) {
    try {
      const originUrl = new URL(origin)
      if (originUrl.host !== host) {
        logSecurityEvent('CSRF_ORIGIN_MISMATCH', req.user?.id || null, req.ip || '', req.headers['user-agent'] || '', {
          origin,
          host
        })
        res.status(403).json({ error: 'CSRF validation failed: Origin mismatch' })
        return
      }
    } catch {
      res.status(400).json({ error: 'Malformed Origin header' })
      return
    }
  } else if (referer) {
    // Fall back to Referer header
    try {
      const refererUrl = new URL(referer)
      if (refererUrl.host !== host) {
        logSecurityEvent('CSRF_REFERER_MISMATCH', req.user?.id || null, req.ip || '', req.headers['user-agent'] || '', {
          referer,
          host
        })
        res.status(403).json({ error: 'CSRF validation failed: Referer mismatch' })
        return
      }
    } catch {
      res.status(400).json({ error: 'Malformed Referer header' })
      return
    }
  }

  next()
}
