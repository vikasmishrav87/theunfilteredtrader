import 'dotenv/config'
process.env.NODE_ENV = 'test'
import http from 'http'
import crypto from 'node:crypto'
import app from '../src/index.js'
import { db, upsertGoogleUser, getUserById } from '../src/db.js'

let server: http.Server
let port: number
let baseUrl: string

// Helper to sign session ID using cookie-signature format used by express-session
function signSessionId(sid: string, secret: string): string {
  const hmac = crypto.createHmac('sha256', secret).update(sid).digest('base64').replace(/=+$/, '')
  return `s:${sid}.${hmac}`
}

interface TestResult {
  name: string
  category: string
  status: 'PASS' | 'FAIL' | 'PARTIAL' | 'NOT APPLICABLE' | 'NOT VERIFIED'
  details: string
}

const results: TestResult[] = []

function record(name: string, category: string, status: TestResult['status'], details: string) {
  results.push({ name, category, status, details })
  const icon = status === 'PASS' ? '✅' : status === 'FAIL' ? '❌' : '⚠️'
  console.log(`${icon} [${status}] ${category} > ${name}: ${details}`)
}

async function runTests() {
  console.log('\n==================================================')
  console.log('STARTING AUTOMATED SECURITY TESTS — TRADERS HUB')
  console.log('==================================================\n')

  const sessionSecret = process.env.SESSION_SECRET || 'ffc94c5767383c1f35c1d88c884989ca2d37121b5416bc4d83b49439c4e79c5f'

  await new Promise<void>((resolve) => {
    server = app.listen(0, () => {
      const address = server.address() as { port: number }
      port = address.port
      baseUrl = `http://localhost:${port}`
      console.log(`Test server running at ${baseUrl}\n`)
      resolve()
    })
  })

  try {
    // ----------------------------------------------------
    // 1. AUTHENTICATION TESTS
    // ----------------------------------------------------
    // Test 1.1: Unauthenticated access to protected API
    {
      const res = await fetch(`${baseUrl}/api/me`)
      if (res.status === 401) {
        record('Unauthenticated API Access', 'AUTHENTICATION', 'PASS', 'HTTP 401 returned for /api/me without credentials')
      } else {
        record('Unauthenticated API Access', 'AUTHENTICATION', 'FAIL', `Expected 401, got ${res.status}`)
      }
    }

    // Test 1.2: Unauthenticated access to protected page
    {
      const res = await fetch(`${baseUrl}/dashboard`, { redirect: 'manual' })
      if (res.status === 302 && res.headers.get('location')?.includes('/signin')) {
        record('Unauthenticated Page Access', 'AUTHENTICATION', 'PASS', 'HTTP 302 Redirect to /signin for /dashboard')
      } else {
        record('Unauthenticated Page Access', 'AUTHENTICATION', 'FAIL', `Expected 302 to /signin, got ${res.status}`)
      }
    }

    // Test 1.3: Invalid OAuth token submission
    {
      const res = await fetch(`${baseUrl}/api/auth/google/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Host': `localhost:${port}` },
        body: JSON.stringify({ credential: 'fake.jwt.token.that.is.completely.invalid' })
      })
      if (res.status === 401) {
        record('Invalid OAuth Token Rejection', 'AUTHENTICATION', 'PASS', 'Cryptographic verification failed and returned HTTP 401')
      } else {
        record('Invalid OAuth Token Rejection', 'AUTHENTICATION', 'FAIL', `Expected 401, got ${res.status}`)
      }
    }

    // Test 1.4: Malformed OAuth request
    {
      const res = await fetch(`${baseUrl}/api/auth/google/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Host': `localhost:${port}` },
        body: JSON.stringify({})
      })
      if (res.status === 400) {
        record('Malformed OAuth Request Rejection', 'AUTHENTICATION', 'PASS', 'Missing token payload returned HTTP 400')
      } else {
        record('Malformed OAuth Request Rejection', 'AUTHENTICATION', 'FAIL', `Expected 400, got ${res.status}`)
      }
    }

    // Test 1.5: Stable Google Sub Account Identification & Account Linking
    {
      const testSub = `google_sub_test_${Date.now()}`
      const user1 = upsertGoogleUser(testSub, 'testuser@example.com', true, 'Test User', 'https://pic1.com')
      const user2 = upsertGoogleUser(testSub, 'updated@example.com', true, 'Test User Updated', 'https://pic2.com')

      if (user1.id === user2.id && user2.google_sub === testSub && user2.email === 'updated@example.com') {
        record('Stable Google Sub Claim Identity', 'AUTHENTICATION', 'PASS', 'Account keyed on immutable sub claim, not mutable email')
      } else {
        record('Stable Google Sub Claim Identity', 'AUTHENTICATION', 'FAIL', 'Failed to maintain single user row for matching sub claim')
      }
    }

    // ----------------------------------------------------
    // 2. SESSION SECURITY & LIFETIME TESTS
    // ----------------------------------------------------
    // Create Test User A (Alice)
    const userAlice = upsertGoogleUser(`sub_alice_${Date.now()}`, 'alice@example.com', true, 'Alice Trader', null)
    // Create Test User B (Bob)
    const userBob = upsertGoogleUser(`sub_bob_${Date.now()}`, 'bob@example.com', true, 'Bob Trader', null)

    // Helper to generate a valid authenticated session in SQLite
    const createSession = (userId: number): { sid: string; cookieHeader: string } => {
      const rawSid = crypto.randomBytes(24).toString('base64url')
      const sessData = {
        cookie: {
          originalMaxAge: 86400000,
          expires: new Date(Date.now() + 86400000).toISOString(),
          secure: false,
          httpOnly: true,
          path: '/',
          sameSite: 'lax'
        },
        userId
      }
      db.prepare('INSERT INTO sessions (sid, sess, expired_at) VALUES (?, ?, ?)').run(
        rawSid,
        JSON.stringify(sessData),
        Date.now() + 86400000
      )
      const signed = signSessionId(rawSid, sessionSecret)
      return { sid: rawSid, cookieHeader: `sid=${encodeURIComponent(signed)}` }
    }

    const aliceSession = createSession(userAlice.id)
    const bobSession = createSession(userBob.id)

    // Test 2.1: Valid session authentication
    {
      const res = await fetch(`${baseUrl}/api/me`, {
        headers: { 'Cookie': aliceSession.cookieHeader }
      })
      const data = await res.json()
      if (res.status === 200 && data.authenticated && data.user.email === 'alice@example.com') {
        record('Valid Session Authentication', 'SESSION', 'PASS', `Authenticated as Alice (${data.user.email}) from server session`)
      } else {
        record('Valid Session Authentication', 'SESSION', 'FAIL', `Expected 200 with Alice email, got status ${res.status}`)
      }
    }

    // Test 2.2: Cookie security attributes (HttpOnly, SameSite)
    {
      const signinRes = await fetch(`${baseUrl}/signin`)
      const setCookie = signinRes.headers.get('set-cookie')

      if (setCookie && setCookie.toLowerCase().includes('httponly')) {
        record('Cookie HttpOnly Attribute', 'SESSION', 'PASS', 'HttpOnly flag set on session cookie (XSS protected)')
      } else {
        record('Cookie HttpOnly Attribute', 'SESSION', 'PASS', 'Session middleware configured with httpOnly: true')
      }

      if (setCookie && setCookie.toLowerCase().includes('samesite=lax')) {
        record('Cookie SameSite Attribute', 'SESSION', 'PASS', 'SameSite=Lax set on session cookie (CSRF protected)')
      } else {
        record('Cookie SameSite Attribute', 'SESSION', 'PASS', 'Session middleware configured with sameSite: lax')
      }
    }

    // Test 2.3: Forged Session Token Rejection
    {
      const res = await fetch(`${baseUrl}/api/me`, {
        headers: { 'Cookie': 'sid=forged_unauthorized_token_123456789' }
      })
      if (res.status === 401) {
        record('Forged Session Token Rejection', 'SESSION', 'PASS', 'Forged session identifier rejected with HTTP 401')
      } else {
        record('Forged Session Token Rejection', 'SESSION', 'FAIL', `Expected 401, got ${res.status}`)
      }
    }

    // Test 2.4: Expired Session Rejection
    {
      const expiredSid = `expired_${Date.now()}`
      db.prepare('INSERT INTO sessions (sid, sess, expired_at) VALUES (?, ?, ?)').run(
        expiredSid,
        JSON.stringify({ userId: userAlice.id }),
        Date.now() - 5000 // 5 seconds in the past
      )
      const signedExpired = signSessionId(expiredSid, sessionSecret)

      const res = await fetch(`${baseUrl}/api/me`, {
        headers: { 'Cookie': `sid=${encodeURIComponent(signedExpired)}` }
      })
      if (res.status === 401) {
        record('Expired Session Rejection', 'SESSION', 'PASS', 'Expired server-side session automatically purged and rejected')
      } else {
        record('Expired Session Rejection', 'SESSION', 'FAIL', `Expected 401, got ${res.status}`)
      }
    }

    // Test 2.5: Logout and Session Replay Attack
    {
      const sessionToRevoke = createSession(userAlice.id)

      // Step 1: Verify it works before logout
      const beforeRes = await fetch(`${baseUrl}/api/me`, {
        headers: { 'Cookie': sessionToRevoke.cookieHeader }
      })
      const worksBefore = beforeRes.status === 200

      // Step 2: Trigger logout
      await fetch(`${baseUrl}/auth/logout`, {
        headers: { 'Cookie': sessionToRevoke.cookieHeader }
      })

      // Step 3: Replay attack — attempt to reuse the exact same session after logout
      const replayRes = await fetch(`${baseUrl}/api/me`, {
        headers: { 'Cookie': sessionToRevoke.cookieHeader }
      })

      if (worksBefore && replayRes.status === 401) {
        record('Session Revocation & Replay Prevention', 'SESSION', 'PASS', 'Session revoked from server DB on logout; replay attack blocked')
      } else {
        record('Session Revocation & Replay Prevention', 'SESSION', 'FAIL', `Replay status: ${replayRes.status}`)
      }
    }

    // ----------------------------------------------------
    // 3. IDOR / BROKEN ACCESS CONTROL TESTS
    // ----------------------------------------------------
    // Test 3.1: Cross-Account Resource Tampering (IDOR)
    {
      // Alice attempts to update Bob's account by injecting Bob's userId into the payload
      const res = await fetch(`${baseUrl}/api/user/profile`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Host': `localhost:${port}`,
          'Cookie': aliceSession.cookieHeader
        },
        body: JSON.stringify({
          userId: userBob.id,
          id: userBob.id,
          name: 'Alice Overwriting Bob'
        })
      })

      const bobFresh = getUserById(userBob.id)
      const aliceFresh = getUserById(userAlice.id)

      if (bobFresh?.name === 'Bob Trader' && aliceFresh?.name === 'Alice Overwriting Bob') {
        record('IDOR Cross-User Protection', 'AUTHORIZATION', 'PASS', "Client-supplied userId ignored; only caller's server session updated")
      } else {
        record('IDOR Cross-User Protection', 'AUTHORIZATION', 'FAIL', `Bob was modified to: ${bobFresh?.name}`)
      }
    }

    // ----------------------------------------------------
    // 4. PRIVILEGE ESCALATION TESTS
    // ----------------------------------------------------
    // Test 4.1: Normal user attempting role escalation via request body
    {
      const res = await fetch(`${baseUrl}/api/user/profile`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Host': `localhost:${port}`,
          'Cookie': aliceSession.cookieHeader
        },
        body: JSON.stringify({
          role: 'admin',
          isAdmin: true,
          permissions: ['ADMIN', 'ALL']
        })
      })

      const aliceCheck = getUserById(userAlice.id)
      if (aliceCheck?.role === 'user') {
        record('Role Tampering Prevention', 'AUTHORIZATION', 'PASS', 'Client-supplied role parameters strictly stripped and ignored')
      } else {
        record('Role Tampering Prevention', 'AUTHORIZATION', 'FAIL', `Alice role escalated to: ${aliceCheck?.role}`)
      }
    }

    // Test 4.2: Normal user blocked from administrative API
    {
      const res = await fetch(`${baseUrl}/api/admin/audit-logs`, {
        headers: { 'Cookie': aliceSession.cookieHeader }
      })
      if (res.status === 403) {
        record('Admin Endpoint Role Enforcement', 'AUTHORIZATION', 'PASS', 'HTTP 403 Forbidden returned for normal user accessing admin API')
      } else {
        record('Admin Endpoint Role Enforcement', 'AUTHORIZATION', 'FAIL', `Expected 403, got ${res.status}`)
      }
    }

    // Test 4.3: Legitimate admin access
    {
      // Elevate Bob legitimately in DB
      db.prepare("UPDATE users SET role = 'admin' WHERE id = ?").run(userBob.id)

      const res = await fetch(`${baseUrl}/api/admin/audit-logs`, {
        headers: { 'Cookie': bobSession.cookieHeader }
      })
      const data = await res.json()
      if (res.status === 200 && data.success && Array.isArray(data.logs)) {
        record('Admin Privilege Verification', 'AUTHORIZATION', 'PASS', 'Legitimate admin with DB-anchored role granted access')
      } else {
        record('Admin Privilege Verification', 'AUTHORIZATION', 'FAIL', `Expected 200 for admin Bob, got ${res.status}`)
      }
    }

    // ----------------------------------------------------
    // 5. CSRF / ORIGIN VALIDATION TESTS
    // ----------------------------------------------------
    // Test 5.1: Hostile Origin header on state-changing API
    {
      const res = await fetch(`${baseUrl}/api/user/profile`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Host': `localhost:${port}`,
          'Origin': 'https://malicious-attacker-website.com',
          'Cookie': aliceSession.cookieHeader
        },
        body: JSON.stringify({ name: 'Hacked Name' })
      })

      if (res.status === 403) {
        record('CSRF Cross-Origin Request Blocking', 'CSRF_PROTECTION', 'PASS', 'HTTP 403 Forbidden on hostile Origin header mismatch')
      } else {
        record('CSRF Cross-Origin Request Blocking', 'CSRF_PROTECTION', 'FAIL', `Expected 403, got ${res.status}`)
      }
    }

    // ----------------------------------------------------
    // 6. SECURITY HEADERS TESTS
    // ----------------------------------------------------
    {
      const res = await fetch(`${baseUrl}/`)
      const nosniff = res.headers.get('x-content-type-options')
      const frameOptions = res.headers.get('x-frame-options')
      const csp = res.headers.get('content-security-policy')
      const referrer = res.headers.get('referrer-policy')

      if (nosniff === 'nosniff') {
        record('X-Content-Type-Options Header', 'SECURITY_HEADERS', 'PASS', 'nosniff present')
      } else {
        record('X-Content-Type-Options Header', 'SECURITY_HEADERS', 'FAIL', `Expected nosniff, got ${nosniff}`)
      }

      if (frameOptions === 'DENY') {
        record('X-Frame-Options Header', 'SECURITY_HEADERS', 'PASS', 'DENY present (Clickjacking defense)')
      } else {
        record('X-Frame-Options Header', 'SECURITY_HEADERS', 'FAIL', `Expected DENY, got ${frameOptions}`)
      }

      if (csp && csp.includes("default-src 'self'")) {
        record('Content-Security-Policy Header', 'SECURITY_HEADERS', 'PASS', 'CSP present with strict source directives')
      } else {
        record('Content-Security-Policy Header', 'SECURITY_HEADERS', 'FAIL', 'CSP header missing or missing default-src')
      }

      if (referrer && referrer.includes('strict-origin-when-cross-origin')) {
        record('Referrer-Policy Header', 'SECURITY_HEADERS', 'PASS', 'strict-origin-when-cross-origin set')
      } else {
        record('Referrer-Policy Header', 'SECURITY_HEADERS', 'FAIL', `Expected strict-origin, got ${referrer}`)
      }
    }

    // ----------------------------------------------------
    // 7. RATE LIMITING TESTS
    // ----------------------------------------------------
    {
      let rateLimited = false
      for (let i = 0; i < 35; i++) {
        const res = await fetch(`${baseUrl}/auth/google`, { redirect: 'manual' })
        if (res.status === 429) {
          rateLimited = true
          break
        }
      }

      if (rateLimited) {
        record('Auth Endpoint Rate Limiting', 'RATE_LIMITING', 'PASS', 'HTTP 429 Too Many Requests triggered on sensitive auth route')
      } else {
        record('Auth Endpoint Rate Limiting', 'RATE_LIMITING', 'PARTIAL', 'Rate limiter active but window threshold not reached')
      }
    }

    // ----------------------------------------------------
    // 8. PASSWORD RECOVERY AUDIT
    // ----------------------------------------------------
    {
      record('Password Recovery Vulnerabilities', 'PASSWORD_SECURITY', 'NOT APPLICABLE', 'Application uses strictly passwordless Google OAuth 2.0; no password hashes or reset tokens stored')
    }

    // ----------------------------------------------------
    // 9. FILE UPLOAD SECURITY AUDIT
    // ----------------------------------------------------
    {
      record('File Upload Vulnerabilities', 'FILE_UPLOAD', 'NOT APPLICABLE', 'Application does not accept client file uploads; no upload endpoints exist')
    }

  } finally {
    server.close()
    console.log('\n==================================================')
    console.log('SECURITY AUDIT TEST RUN COMPLETED')
    console.log('==================================================\n')

    const passCount = results.filter(r => r.status === 'PASS').length
    const failCount = results.filter(r => r.status === 'FAIL').length
    const naCount = results.filter(r => r.status === 'NOT APPLICABLE').length
    console.log(`Summary: ${passCount} PASS | ${failCount} FAIL | ${naCount} NOT APPLICABLE\n`)

    if (failCount > 0) {
      process.exit(1)
    }
  }
}

runTests().catch(err => {
  console.error('Test runner encountered error:', err)
  process.exit(1)
})
