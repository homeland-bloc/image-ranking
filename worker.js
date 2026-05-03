/**
 * Peony Proxy Worker
 * Sits between your GitHub Pages app and Supabase.
 * Uses Firebase Auth (Third-Party Auth) for identity — no service role key.
 *
 * Environment variables (set in Cloudflare dashboard):
 *   SUPABASE_URL             = https://tbduuuzwbiidjgztupfp.supabase.co
 *   SUPABASE_ANON_KEY        = <anon key>
 *   DISCORD_CLIENT_SECRET    = <secret>
 *   FIREBASE_SERVICE_ACCOUNT = <service account JSON string>
 *   FIREBASE_PROJECT_ID      = peony-fire
 *   ADMIN_DISCORD_ID         = 719271552247529571
 */

const ALLOWED_ORIGIN = 'https://bicipikay.github.io';
const DISCORD_CLIENT_ID = '1442282566810861568';

const WRITE_METHODS = new Set(['POST', 'PATCH', 'PUT', 'DELETE']);

// Tables that require admin verification for DELETE
const ADMIN_SENSITIVE_TABLES = new Set([
  'contests', 'images', 'votes', 'users',
  'mergers', 'extracts', 'pinned_items'
]);

export default {
  async fetch(request, env) {
    try {
      if (request.method === 'OPTIONS') {
        return corsResponse(null, 204);
      }

      const url = new URL(request.url);
      // Normalize: collapse double slashes, lowercase
      const path = url.pathname.replace(/\/\/+/g, '/').toLowerCase();

      if (path === '/discord-token') return handleDiscordToken(request, env);
      if (path === '/discord-refresh') return handleDiscordRefresh(request, env);

      if (!env.SUPABASE_URL || !env.SUPABASE_ANON_KEY) {
        return corsResponse({ error: 'Worker misconfigured' }, 500);
      }

      if (path.startsWith('/rest/v1/') || path.startsWith('/storage/v1/')) {
        return handleSupabaseProxy(request, url, path, env);
      }

      return corsResponse({ error: 'Forbidden' }, 403);
    } catch (err) {
      console.error('Unhandled worker error:', err);
      return corsResponse({ error: 'Internal server error' }, 500);
    }
  }
};

// ── Discord token exchange ────────────────────────────────────────────────────
async function handleDiscordToken(request, env) {
  if (request.method !== 'POST') return corsResponse({ error: 'Method not allowed' }, 405);
  if (!env.DISCORD_CLIENT_SECRET) return corsResponse({ error: 'Worker misconfigured' }, 500);
  if (!env.FIREBASE_SERVICE_ACCOUNT) return corsResponse({ error: 'Worker misconfigured' }, 500);

  let body;
  try { body = await request.json(); }
  catch { return corsResponse({ error: 'Invalid JSON body' }, 400); }

  const { code, code_verifier, redirect_uri } = body;
  if (!code || !code_verifier || !redirect_uri) {
    return corsResponse({ error: 'Missing required fields: code, code_verifier, redirect_uri' }, 400);
  }

  // Exchange authorization code with Discord
  const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: DISCORD_CLIENT_ID,
      client_secret: env.DISCORD_CLIENT_SECRET,
      grant_type: 'authorization_code',
      code,
      redirect_uri,
      code_verifier
    })
  });

  const tokens = await tokenRes.json();
  if (!tokenRes.ok) {
    console.error('Discord token exchange failed:', tokens);
    return corsResponse({ error: 'Token exchange failed' }, tokenRes.status);
  }

  // Verify the Discord user
  const discordUser = await fetchDiscordUser(tokens.access_token);
  if (!discordUser) {
    return corsResponse({ error: 'Failed to verify Discord user' }, 401);
  }

  // Mint Firebase custom token (UID = Discord ID)
  let serviceAccount;
  try {
    serviceAccount = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
  } catch {
    console.error('Failed to parse FIREBASE_SERVICE_ACCOUNT');
    return corsResponse({ error: 'Worker misconfigured' }, 500);
  }

  const firebaseToken = await mintFirebaseCustomToken(serviceAccount, discordUser.id);

  return corsResponse({
    firebase_token: firebaseToken,
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    expires_in: tokens.expires_in,
    discord_user: {
      id: discordUser.id,
      username: discordUser.global_name || discordUser.username,
      avatar: discordUser.avatar
    }
  }, 200);
}

// ── Discord token refresh ─────────────────────────────────────────────────────
async function handleDiscordRefresh(request, env) {
  if (request.method !== 'POST') return corsResponse({ error: 'Method not allowed' }, 405);
  if (!env.DISCORD_CLIENT_SECRET) return corsResponse({ error: 'Worker misconfigured' }, 500);

  let body;
  try { body = await request.json(); }
  catch { return corsResponse({ error: 'Invalid JSON body' }, 400); }

  const { refresh_token } = body;
  if (!refresh_token) return corsResponse({ error: 'Missing required field: refresh_token' }, 400);

  const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: DISCORD_CLIENT_ID,
      client_secret: env.DISCORD_CLIENT_SECRET,
      grant_type: 'refresh_token',
      refresh_token
    })
  });

  const tokens = await tokenRes.json();
  if (!tokenRes.ok) {
    console.error('Discord token refresh failed:', tokens);
    return corsResponse({ error: 'Token refresh failed' }, tokenRes.status);
  }

  return corsResponse({
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    expires_in: tokens.expires_in
  }, 200);
}

// ── Supabase proxy ────────────────────────────────────────────────────────────
async function handleSupabaseProxy(request, url, normalizedPath, env) {
  const method = request.method;

  // Derive table name from normalized path (lowercase already)
  const segment = normalizedPath.startsWith('/rest/v1/')
    ? normalizedPath.slice('/rest/v1/'.length)
    : normalizedPath.slice('/storage/v1/'.length);
  const table = segment.split('?')[0].split('/')[0];

  const authHeader = request.headers.get('Authorization');
  let firebaseUid = null;

  if (WRITE_METHODS.has(method)) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return corsResponse({ error: 'Authentication required' }, 401);
    }

    const payload = decodeJwtPayload(authHeader.slice(7));
    if (!payload || !payload.sub) {
      return corsResponse({ error: 'Invalid token' }, 401);
    }
    firebaseUid = payload.sub;
    // Log the extracted UID server-side (Cloudflare tail logs) for debugging.
    // This is never returned to the client.
    console.error(`[auth] uid=${firebaseUid} method=${method} table=${table}`);

    // DELETE on sensitive tables requires admin verification
    if (method === 'DELETE' && ADMIN_SENSITIVE_TABLES.has(table)) {
      const isAdmin = await verifyAdmin(request, env);
      if (!isAdmin) {
        console.warn(`Unauthorized DELETE on ${table} by uid=${firebaseUid}`);
        return corsResponse({ error: 'Forbidden' }, 403);
      }
    }

    // Sanitize ownership fields on mutations
    if (method === 'POST' || method === 'PATCH' || method === 'PUT') {
      const cloned = request.clone();
      try {
        const bodyJson = await request.json();
        const sanitised = sanitiseBody(bodyJson, firebaseUid);
        request = new Request(request.url, {
          method,
          headers: request.headers,
          body: JSON.stringify(sanitised)
        });
      } catch {
        // Non-JSON body (e.g. storage uploads) — restore clone
        request = cloned;
      }
    }
  }

  // Forward to Supabase with anon key; pass Firebase token if present so RLS can
  // enforce ownership. For GET requests without a token, omit Authorization so
  // Supabase treats the request as anon role rather than an invalid token.
  const supabaseUrl = `${env.SUPABASE_URL}${url.pathname}${url.search}`;
  const headers = new Headers();
  headers.set('apikey', env.SUPABASE_ANON_KEY);
  if (authHeader) headers.set('Authorization', authHeader);

  // Forward safe passthrough headers
  for (const h of ['Content-Type', 'Prefer', 'X-Upsert', 'Range']) {
    const val = request.headers.get(h);
    if (val) headers.set(h, val);
  }

  const supabaseResp = await fetch(new Request(supabaseUrl, {
    method,
    headers,
    body: WRITE_METHODS.has(method) ? request.body : undefined
  }));

  const responseBody = await supabaseResp.text();
  return corsResponse(
    responseBody,
    supabaseResp.status,
    supabaseResp.headers.get('Content-Type') || 'application/json'
  );
}

// ── Admin verification ────────────────────────────────────────────────────────
async function verifyAdmin(request, env) {
  const discordToken = request.headers.get('X-Discord-Token');
  if (!discordToken) return false;

  const discordUser = await fetchDiscordUser(discordToken);
  if (!discordUser || discordUser.id !== env.ADMIN_DISCORD_ID) return false;

  try {
    const res = await fetch(
      `${env.SUPABASE_URL}/rest/v1/users?id=eq.${discordUser.id}&select=is_admin`,
      { headers: { apikey: env.SUPABASE_ANON_KEY, Authorization: `Bearer ${env.SUPABASE_ANON_KEY}` } }
    );
    if (!res.ok) return false;
    const rows = await res.json();
    return rows.length > 0 && rows[0].is_admin === true;
  } catch {
    return false;
  }
}

// ── Verify a Discord access token and return the user object ─────────────────
async function fetchDiscordUser(token) {
  try {
    const res = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!res.ok) return null;
    const data = await res.json();
    if (!data.id || !/^\d+$/.test(data.id)) return null;
    return data;
  } catch {
    return null;
  }
}

// ── Prevent ownership field spoofing ─────────────────────────────────────────
function sanitiseBody(body, firebaseUid) {
  // Array bodies (e.g. bulk inserts) — sanitise each element individually so the
  // array structure is preserved when forwarded to Supabase.
  if (Array.isArray(body)) {
    return body.map(item => sanitiseBody(item, firebaseUid));
  }
  // 'id' (primary key on users and other tables) is intentionally absent from
  // this list — it must never be overwritten by the sanitiser.
  const userFields = ['user_id', 'created_by', 'voted_by'];
  const patched = { ...body };
  for (const field of userFields) {
    if (field in patched && patched[field] !== firebaseUid) {
      console.warn(`Body sanitisation: ${field} overwritten with verified uid`);
      patched[field] = firebaseUid;
    }
  }
  return patched;
}

// ── JWT payload decoder (no signature verification — Supabase handles that) ──
function decodeJwtPayload(token) {
  try {
    const [, payloadB64] = token.split('.');
    const padded = payloadB64.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(padded));
  } catch {
    return null;
  }
}

// ── Firebase custom token minting ─────────────────────────────────────────────
async function mintFirebaseCustomToken(serviceAccount, uid) {
  const now = Math.floor(Date.now() / 1000);
  const headerB64 = base64UrlEncodeStr(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payloadB64 = base64UrlEncodeStr(JSON.stringify({
    iss: serviceAccount.client_email,
    sub: serviceAccount.client_email,
    aud: 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit',
    iat: now,
    exp: now + 3600,
    uid
  }));

  const signingInput = `${headerB64}.${payloadB64}`;
  const cryptoKey = await crypto.subtle.importKey(
    'pkcs8',
    pemToBinary(serviceAccount.private_key),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const sigBytes = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    cryptoKey,
    new TextEncoder().encode(signingInput)
  );

  return `${signingInput}.${base64UrlEncodeBuffer(sigBytes)}`;
}

function base64UrlEncodeStr(str) {
  return base64UrlEncodeBuffer(new TextEncoder().encode(str).buffer);
}

function base64UrlEncodeBuffer(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function pemToBinary(pem) {
  const base64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, '')
    .replace(/-----END PRIVATE KEY-----/g, '')
    .replace(/\s+/g, '');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

// ── CORS helper ───────────────────────────────────────────────────────────────
function corsResponse(body, status, contentType = 'application/json') {
  const headers = {
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, apikey, X-Discord-Token, Prefer, X-Upsert, Cache-Control, Pragma, Expires, Range',
    'Access-Control-Max-Age': '86400',
    'Content-Type': contentType
  };

  const responseBody =
    body === null ? null :
    typeof body === 'string' ? body :
    JSON.stringify(body);

  return new Response(responseBody, { status, headers });
}
