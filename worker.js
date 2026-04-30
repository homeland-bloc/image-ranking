/**
 * Peony Proxy Worker
 * Sits between your GitHub Pages app and Supabase.
 * Verifies Discord tokens before forwarding any write operation.
 *
 * Environment variables to set in Cloudflare dashboard:
 *   SUPABASE_URL          = https://tbduuuzwbiidjgztupfp.supabase.co
 *   SUPABASE_SERVICE_KEY  = <your service role key>  ← keep this secret!
 *   ADMIN_DISCORD_ID      = 719271552247529571
 */

const ALLOWED_ORIGIN = 'https://bicipikay.github.io'; // your GitHub Pages origin

// Tables that are read-only for everyone (no auth required for GET)
const PUBLIC_READ_TABLES = new Set([
  'contests', 'images', 'votes', 'users',
  'mergers', 'extracts', 'pinned_items'
]);

// Tables that require auth even for reads
const PROTECTED_TABLES = new Set([]);

// HTTP methods that mutate data — always require a verified Discord token
const WRITE_METHODS = new Set(['POST', 'PATCH', 'PUT', 'DELETE']);

export default {
  async fetch(request, env) {
    try {
      // ── CORS preflight ────────────────────────────────────────────────────
      if (request.method === 'OPTIONS') {
        return corsResponse(null, 204);
      }

      const url = new URL(request.url);

      // ── Discord OAuth routes (no Supabase env needed) ─────────────────────
      if (url.pathname === '/discord-token') {
        return handleDiscordToken(request, env);
      }
      if (url.pathname === '/discord-refresh') {
        return handleDiscordRefresh(request, env);
      }

      // Fail fast with a clear message if required env vars are missing
      if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_KEY) {
        return corsResponse({ error: 'Worker misconfigured: missing SUPABASE_URL or SUPABASE_SERVICE_KEY' }, 500);
      }

      // ── Route: /discord-verify  (called on login to validate token) ───────
      if (url.pathname === '/discord-verify') {
        return handleDiscordVerify(request, env);
      }

      // ── Route: /rest/v1/* (proxy to Supabase REST) ────────────────────────
      if (url.pathname.startsWith('/rest/v1/')) {
        return handleSupabaseProxy(request, url, env);
      }

      // ── Route: /storage/v1/* (proxy to Supabase Storage) ─────────────────
      if (url.pathname.startsWith('/storage/v1/')) {
        return handleSupabaseProxy(request, url, env);
      }

      return corsResponse({ error: 'Not found' }, 404);
    } catch (err) {
      // Surface the real error with CORS headers so the browser can read it
      console.error('Unhandled worker error:', err);
      return corsResponse({ error: err.message || String(err) }, 500);
    }
  }
};

// ── Discord verification endpoint ────────────────────────────────────────────
async function handleDiscordVerify(request, env) {
  if (request.method !== 'POST') {
    return corsResponse({ error: 'Method not allowed' }, 405);
  }

  const discordToken = request.headers.get('X-Discord-Token');
  if (!discordToken) {
    return corsResponse({ error: 'Missing Discord token' }, 401);
  }

  const user = await fetchDiscordUser(discordToken);
  if (!user) {
    return corsResponse({ error: 'Invalid Discord token' }, 401);
  }

  return corsResponse({
    id: user.id,
    username: user.username,
    avatar: user.avatar,
    isAdmin: user.id === env.ADMIN_DISCORD_ID
  }, 200);
}

// ── Discord token exchange (authorization code → tokens) ─────────────────────
async function handleDiscordToken(request, env) {
  if (request.method !== 'POST') {
    return corsResponse({ error: 'Method not allowed' }, 405);
  }
  if (!env.DISCORD_CLIENT_SECRET) {
    return corsResponse({ error: 'Worker misconfigured: missing DISCORD_CLIENT_SECRET' }, 500);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return corsResponse({ error: 'Invalid JSON body' }, 400);
  }

  const { code, code_verifier, redirect_uri } = body;
  if (!code || !code_verifier || !redirect_uri) {
    return corsResponse({ error: 'Missing required fields: code, code_verifier, redirect_uri' }, 400);
  }

  const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: '1442282566810861568',
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
    return corsResponse({ error: 'Token exchange failed', details: tokens }, tokenRes.status);
  }

  return corsResponse({
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    expires_in: tokens.expires_in
  }, 200);
}

// ── Discord token refresh ─────────────────────────────────────────────────────
async function handleDiscordRefresh(request, env) {
  if (request.method !== 'POST') {
    return corsResponse({ error: 'Method not allowed' }, 405);
  }
  if (!env.DISCORD_CLIENT_SECRET) {
    return corsResponse({ error: 'Worker misconfigured: missing DISCORD_CLIENT_SECRET' }, 500);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return corsResponse({ error: 'Invalid JSON body' }, 400);
  }

  const { refresh_token } = body;
  if (!refresh_token) {
    return corsResponse({ error: 'Missing required field: refresh_token' }, 400);
  }

  const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: '1442282566810861568',
      client_secret: env.DISCORD_CLIENT_SECRET,
      grant_type: 'refresh_token',
      refresh_token
    })
  });

  const tokens = await tokenRes.json();
  if (!tokenRes.ok) {
    console.error('Discord token refresh failed:', tokens);
    return corsResponse({ error: 'Token refresh failed', details: tokens }, tokenRes.status);
  }

  return corsResponse({
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    expires_in: tokens.expires_in
  }, 200);
}

// ── Supabase proxy ────────────────────────────────────────────────────────────
async function handleSupabaseProxy(request, url, env) {
  const method = request.method;

  // Identify which table is being accessed from the URL path
  // e.g. /rest/v1/contests?... → "contests"
  const pathParts = url.pathname.replace('/rest/v1/', '').split('?')[0].split('/');
  const table = pathParts[0];

  // ── Auth check for write operations ──────────────────────────────────────
  if (WRITE_METHODS.has(method)) {
    const discordToken = request.headers.get('X-Discord-Token');
    if (!discordToken) {
      return corsResponse({ error: 'Authentication required' }, 401);
    }

    const user = await fetchDiscordUser(discordToken);
    if (!user) {
      return corsResponse({ error: 'Invalid Discord token' }, 401);
    }

    // ── Extra guard: DELETE on core tables requires admin ─────────────────
    const sensitiveTables = new Set(['contests', 'images', 'votes']);
    if (method === 'DELETE' && sensitiveTables.has(table)) {
      if (user.id !== env.ADMIN_DISCORD_ID) {
        return corsResponse({ error: 'Admin only' }, 403);
      }
    }

    // ── Inject the verified user ID into the request body for writes ──────
    // This prevents clients from spoofing `created_by` or `user_id` fields.
    if (['POST', 'PATCH', 'PUT'].includes(method)) {
      try {
        const body = await request.json();
        const sanitisedBody = sanitiseBody(table, body, user.id);
        request = new Request(request, {
          body: JSON.stringify(sanitisedBody),
          headers: request.headers
        });
      } catch (_) {
        // Non-JSON body (e.g. storage uploads) — pass through untouched
      }
    }
  }

  // ── Forward to Supabase ───────────────────────────────────────────────────
  const supabaseUrl = `${env.SUPABASE_URL}${url.pathname}${url.search}`;

  const headers = new Headers(request.headers);
  headers.set('apikey', env.SUPABASE_SERVICE_KEY);
  headers.set('Authorization', `Bearer ${env.SUPABASE_SERVICE_KEY}`);
  // Remove the Discord token before forwarding — Supabase doesn't need it
  headers.delete('X-Discord-Token');

  const supabaseRequest = new Request(supabaseUrl, {
    method,
    headers,
    body: WRITE_METHODS.has(method) ? request.body : undefined
  });

  const supabaseResponse = await fetch(supabaseRequest);

  // Return the Supabase response with CORS headers added
  const responseBody = await supabaseResponse.text();
  return corsResponse(
    responseBody,
    supabaseResponse.status,
    supabaseResponse.headers.get('Content-Type') || 'application/json'
  );
}

// ── Verify a Discord access token and return the user object ─────────────────
async function fetchDiscordUser(token) {
  try {
    const res = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!res.ok) return null;
    const data = await res.json();
    // Basic sanity check — Discord IDs are snowflakes (numeric strings)
    if (!data.id || !/^\d+$/.test(data.id)) return null;
    return data;
  } catch {
    return null;
  }
}

// ── Prevent body spoofing on write operations ─────────────────────────────────
// Forces `user_id` / `created_by` / `voted_by` to match the verified user.
function sanitiseBody(table, body, verifiedUserId) {
  const userFields = ['user_id', 'created_by', 'voted_by'];
  const patched = { ...body };

  for (const field of userFields) {
    if (field in patched) {
      if (patched[field] !== verifiedUserId) {
        console.warn(`Spoofing attempt: ${field} was ${patched[field]}, overwriting with ${verifiedUserId}`);
      }
      patched[field] = verifiedUserId; // always enforce
    }
  }

  return patched;
}

// ── CORS helper ───────────────────────────────────────────────────────────────
function corsResponse(body, status, contentType = 'application/json') {
  const headers = {
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, apikey, X-Discord-Token, Prefer, X-Upsert, Cache-Control, Pragma',
    'Access-Control-Max-Age': '86400',
    'Content-Type': contentType
  };

  const responseBody =
    body === null
      ? null
      : typeof body === 'string'
      ? body
      : JSON.stringify(body);

  return new Response(responseBody, { status, headers });
}