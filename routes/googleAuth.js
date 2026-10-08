/**
 * KinyaBot — Google OAuth 2.0 / OpenID Connect (authorization-code flow)
 * ─────────────────────────────────────────────────────────────────────
 * Replaces the old Firebase popup flow. The BACKEND controls the whole
 * flow; the Client Secret never leaves the server.
 *
 *   GET  /api/auth/google            start: redirect the browser to Google
 *   GET  /api/auth/google/callback   Google redirects here with ?code&state
 *   POST /api/auth/google/exchange   SPA swaps a one-time code for the
 *                                    normal KinyaBot JWT + user payload
 *
 * Flow
 *   1. /api/auth/google creates state + PKCE verifier + OIDC nonce, stores
 *      them in a short-lived, signed, HttpOnly cookie (bound to THIS
 *      browser → login-CSRF protection) and redirects to Google.
 *   2. /callback validates state (constant-time) against the cookie,
 *      exchanges the code (with the PKCE verifier) for tokens, verifies the
 *      ID token (signature, audience, expiry, nonce) and requires a
 *      verified Google email.
 *   3. The KinyaBot user is found by google_id, else by e-mail (the Google
 *      identity is LINKED to the existing account — plan, chats, usage,
 *      settings are untouched), else created.
 *   4. The browser is redirected to the SPA with a 60-second, single-use
 *      code. The SPA POSTs it to /exchange and receives the SAME
 *      `{ token, user }` payload as the e-mail/password login. The JWT is
 *      therefore never placed in a URL, history entry or server log.
 *
 * Nothing sensitive (client secret, auth codes, tokens) is ever logged.
 */
const express = require('express');
const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');

const STATE_COOKIE = 'kb_g_oauth';
const STATE_TTL_MS = 10 * 60 * 1000;   // user has 10 min to finish Google's screen
const CODE_TTL_MS = 60 * 1000;         // one-time SPA exchange code lifetime

/** Short machine codes → the SPA maps them to friendly messages. */
const ERR = {
  CANCELLED: 'cancelled',
  NOT_CONFIGURED: 'not_configured',
  STATE: 'state_invalid',
  CODE_EXPIRED: 'code_expired',
  CONFIG: 'config_error',
  VERIFY: 'verify_failed',
  NO_EMAIL: 'no_email',
  EMAIL_UNVERIFIED: 'email_unverified',
  SUSPENDED: 'account_suspended',
  LINK_CONFLICT: 'link_conflict',
  MAINTENANCE: 'maintenance',
  GOOGLE: 'google_unavailable',
  SERVER: 'server_error'
};

function parseCookies(header) {
  const out = {};
  String(header || '').split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i < 0) return;
    const k = part.slice(0, i).trim();
    if (k) { try { out[k] = decodeURIComponent(part.slice(i + 1).trim()); } catch { /* ignore bad cookie */ } }
  });
  return out;
}

function safeEqual(a, b) {
  const x = Buffer.from(String(a || ''));
  const y = Buffer.from(String(b || ''));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

const b64url = (buf) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/** Only same-app, relative paths are accepted as post-login targets. */
function safeRedirectPath(p) {
  if (typeof p !== 'string') return '/';
  if (!p.startsWith('/') || p.startsWith('//') || p.includes('\\') || /[\r\n]/.test(p)) return '/';
  return p.slice(0, 300);
}

module.exports = function createGoogleAuthRouter(deps) {
  const {
    User, UserPlan, jwt, JWT_SECRET, bcrypt,
    allowedOrigins, normalizeOrigin, isMaintenance, sysLog, logActivity
  } = deps;

  const router = express.Router();

  const clientId = process.env.GOOGLE_CLIENT_ID || '';
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET || '';
  const callbackUrl = process.env.GOOGLE_CALLBACK_URL || '';
  const configured = !!(clientId && clientSecret && callbackUrl);
  const secureCookie = callbackUrl.startsWith('https://');

  if (!configured) {
    console.warn('[Google OAuth] GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_CALLBACK_URL not set — "Continue with Google" is disabled.');
  }

  const oauthClient = configured ? new OAuth2Client({ clientId, clientSecret, redirectUri: callbackUrl }) : null;

  /* One-time SPA exchange codes (in-memory, single-use, 60 s).
     NOTE: single backend instance assumed (Render free/starter). If the
     backend is ever scaled to several instances, move this to MongoDB/Redis. */
  const pendingLogins = new Map();
  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of pendingLogins) if (v.exp <= now) pendingLogins.delete(k);
  }, 30 * 1000);
  if (sweep.unref) sweep.unref();

  /** Where to send the browser back to: the origin that started the flow if it
      is an allowed KinyaBot origin, otherwise FRONTEND_URL. */
  function resolveFrontendOrigin(candidate) {
    const c = normalizeOrigin(candidate);
    if (c && allowedOrigins.includes(c)) return c;
    return normalizeOrigin(process.env.FRONTEND_URL) || 'https://www.kinyabotai.online';
  }

  /** The chat SPA is mounted under /chat/ (vite base) on the website. */
  function spaUrl(origin, spaPath, params) {
    const u = new URL(`${origin}/chat${spaPath}`);
    Object.entries(params || {}).forEach(([k, v]) => { if (v != null && v !== '') u.searchParams.set(k, v); });
    return u.toString();
  }

  function clearStateCookie(res) {
    res.clearCookie(STATE_COOKIE, { path: '/api/auth/google', httpOnly: true, secure: secureCookie, sameSite: 'lax' });
  }

  function fail(res, ctx, code) {
    clearStateCookie(res);
    const origin = resolveFrontendOrigin(ctx && ctx.origin);
    const page = ctx && ctx.from === 'register' ? '/register' : '/login';
    res.set('Cache-Control', 'no-store');
    return res.redirect(302, spaUrl(origin, page, { google_error: code }));
  }

  /* ── 1. START ─────────────────────────────────────────────────── */
  router.get('/', (req, res) => {
    const origin = resolveFrontendOrigin(req.query.origin);
    const from = req.query.from === 'register' ? 'register' : 'login';
    const ctx = { origin, from };
    if (!configured) return fail(res, ctx, ERR.NOT_CONFIGURED);

    const state = b64url(crypto.randomBytes(32));
    const nonce = b64url(crypto.randomBytes(32));
    const verifier = b64url(crypto.randomBytes(48));
    const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());

    const signed = jwt.sign(
      { state, nonce, verifier, origin, from, redirect: safeRedirectPath(req.query.redirect) },
      JWT_SECRET,
      { expiresIn: Math.floor(STATE_TTL_MS / 1000) }
    );
    res.cookie(STATE_COOKIE, signed, {
      httpOnly: true,
      secure: secureCookie,
      sameSite: 'lax',          // sent on the top-level redirect back from Google
      path: '/api/auth/google',
      maxAge: STATE_TTL_MS
    });

    const url = oauthClient.generateAuthUrl({
      access_type: 'online',
      response_type: 'code',
      scope: ['openid', 'email', 'profile'],
      state,
      nonce,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      prompt: 'select_account',
      include_granted_scopes: false
    });
    res.set('Cache-Control', 'no-store');
    return res.redirect(302, url);
  });

  /* ── 2. CALLBACK ──────────────────────────────────────────────── */
  router.get('/callback', async (req, res) => {
    let ctx = null;
    try {
      // Recover the signed flow context (also proves this browser started the flow)
      const raw = parseCookies(req.headers.cookie)[STATE_COOKIE];
      if (raw) {
        try { ctx = jwt.verify(raw, JWT_SECRET); } catch { ctx = null; }
      }
      if (!ctx) return fail(res, null, ERR.STATE);
      if (!configured) return fail(res, ctx, ERR.NOT_CONFIGURED);

      // User pressed "Cancel" / denied consent on Google's screen
      if (req.query.error) {
        return fail(res, ctx, req.query.error === 'access_denied' ? ERR.CANCELLED : ERR.GOOGLE);
      }
      if (!req.query.code || !req.query.state || !safeEqual(req.query.state, ctx.state)) {
        return fail(res, ctx, ERR.STATE);
      }

      // Exchange the authorization code (PKCE verifier proves we started it)
      let tokens;
      try {
        ({ tokens } = await oauthClient.getToken({ code: String(req.query.code), codeVerifier: ctx.verifier }));
      } catch (err) {
        const g = String(err?.response?.data?.error || '');
        console.error('[Google OAuth] token exchange failed:', g || err?.code || 'unknown'); // never log codes/tokens
        if (g === 'invalid_grant') return fail(res, ctx, ERR.CODE_EXPIRED);
        if (g === 'invalid_client' || g === 'redirect_uri_mismatch' || g === 'unauthorized_client') return fail(res, ctx, ERR.CONFIG);
        return fail(res, ctx, ERR.GOOGLE);
      }
      if (!tokens?.id_token) return fail(res, ctx, ERR.VERIFY);

      // Verify the OpenID Connect ID token (signature, issuer, audience, expiry)
      let payload;
      try {
        const ticket = await oauthClient.verifyIdToken({ idToken: tokens.id_token, audience: clientId });
        payload = ticket.getPayload();
      } catch (err) {
        console.error('[Google OAuth] ID token verification failed');
        return fail(res, ctx, ERR.VERIFY);
      }
      if (!payload || !payload.sub || !safeEqual(payload.nonce, ctx.nonce)) return fail(res, ctx, ERR.VERIFY);
      if (!payload.email) return fail(res, ctx, ERR.NO_EMAIL);
      if (payload.email_verified !== true) return fail(res, ctx, ERR.EMAIL_UNVERIFIED);

      const email = String(payload.email).toLowerCase();
      const googleId = String(payload.sub);
      const picture = payload.picture || null;

      if (isMaintenance()) return fail(res, ctx, ERR.MAINTENANCE);

      /* Find → link → create (single KinyaBot user system, no duplicates) */
      let user = await User.findOne({ google_id: googleId });
      if (!user) {
        user = await User.findOne({ email });
        if (user) {
          if (user.google_id && user.google_id !== googleId) return fail(res, ctx, ERR.LINK_CONFLICT);
          user.google_id = googleId;                      // LINK to the existing account
          await sysLog('info', 'auth', `Google account linked: ${user.username}`, null, user._id);
        }
      }

      if (user) {
        if (user.is_banned) return fail(res, ctx, ERR.SUSPENDED);
        user.last_login = new Date();
        if (picture && !user.avatar_url) user.avatar_url = picture;  // never overwrite a user-chosen avatar
        user.email_verified = true;                                  // Google verified this address
        await user.save();
        logActivity('login', { username: user.username, user_id: user._id.toString() });
      } else {
        const username = await uniqueUsername(User, payload.name || email.split('@')[0], googleId);
        const hash = await bcrypt.hash(crypto.randomBytes(24).toString('hex'), 12); // unusable random password
        user = await User.create({
          username, email, password_hash: hash, avatar_url: picture,
          email_verified: true, google_id: googleId, last_login: new Date()
        });
        await sysLog('info', 'auth', `Registered via Google: ${username}`, null, user._id);
        logActivity('register', { username, user_id: user._id.toString() });
      }

      // Hand the SPA a single-use code (NOT the JWT)
      const code = b64url(crypto.randomBytes(32));
      pendingLogins.set(code, { userId: user._id.toString(), exp: Date.now() + CODE_TTL_MS });

      clearStateCookie(res);
      res.set('Cache-Control', 'no-store');
      return res.redirect(302, spaUrl(resolveFrontendOrigin(ctx.origin), '/auth/google/callback', {
        code, redirect: ctx.redirect && ctx.redirect !== '/' ? ctx.redirect : ''
      }));
    } catch (err) {
      console.error('[Google OAuth] callback error:', err?.name || 'Error');
      return fail(res, ctx, err?.code === 11000 ? ERR.LINK_CONFLICT : ERR.SERVER);
    }
  });

  /* ── 3. EXCHANGE ──────────────────────────────────────────────── */
  router.post('/exchange', async (req, res) => {
    try {
      const code = String(req.body?.code || '');
      const entry = pendingLogins.get(code);
      pendingLogins.delete(code);                         // single use, always
      if (!code || !entry || entry.exp <= Date.now()) {
        return res.status(400).json({ error: 'Your Google sign-in expired. Please try again.' });
      }
      const user = await User.findById(entry.userId);
      if (!user) return res.status(400).json({ error: 'Account not found. Please try again.' });
      if (user.is_banned) return res.status(403).json({ error: 'Account suspended. Please contact support.' });

      const planDoc = await UserPlan.findOne({ user_id: user._id }).select('plan status').lean();
      const token = jwt.sign({ id: user._id.toString(), username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
      res.set('Cache-Control', 'no-store');
      return res.json({
        token,
        user: {
          id: user._id.toString(), username: user.username, email: user.email, avatar_url: user.avatar_url,
          onboarded: user.onboarded, profession: user.profession, email_verified: user.email_verified,
          plan: planDoc?.plan || 'free'
        }
      });
    } catch {
      return res.status(500).json({ error: 'Google sign-in failed. Please try again.' });
    }
  });

  return router;
};

async function uniqueUsername(User, rawName, googleId) {
  let base = String(rawName || 'user').replace(/[^\p{L}\p{N}_. -]/gu, '').trim().replace(/\s+/g, ' ').slice(0, 30);
  if (base.length < 3) base = `user_${googleId.slice(-5)}`;
  if (!(await User.exists({ username: base }))) return base;
  for (let i = 0; i < 5; i++) {
    const cand = `${base.slice(0, 24)}_${crypto.randomBytes(3).toString('hex')}`;
    if (!(await User.exists({ username: cand }))) return cand;
  }
  return `user_${crypto.randomBytes(5).toString('hex')}`;
}
