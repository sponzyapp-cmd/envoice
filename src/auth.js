// Envoice — auth primitives (HMAC sessions, PBKDF2 passwords, cookies).
// Session model mirrors the Sigma worker: the token is an HMAC-SHA256 over a
// raw random id, but verification always resolves against live DB state
// (row existence + expiry + session_version) so revocation is immediate.

const encoder = new TextEncoder();

export const SESSION_COOKIE = 'envoice_sid';
export const SESSION_TTL_DAYS = 30;
export const SESSION_ID_CHARS = 128;
const PBKDF2_ITERATIONS = 100000;

// ── base64url ────────────────────────────────────────────────────────────────

export function b64url(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64url(str) {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (str.length % 4)) % 4);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// ── ids ──────────────────────────────────────────────────────────────────────

// 96 random bytes -> base64url -> exactly 128 characters.
export function newSessionId() {
  return b64url(crypto.getRandomValues(new Uint8Array(96)));
}

export function publicId(prefix) {
  return `${prefix}_${b64url(crypto.getRandomValues(new Uint8Array(18)))}`;
}

// ── digests ──────────────────────────────────────────────────────────────────

export async function sha256Hex(input) {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(input));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function hmacSign(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
  return b64url(new Uint8Array(sig));
}

export function timingSafeEqual(a, b) {
  const x = encoder.encode(String(a));
  const y = encoder.encode(String(b));
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

// ── passwords (PBKDF2-SHA256, per-user salt) ─────────────────────────────────

export async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' }, key, 256,
  );
  return `pbkdf2$sha256$${PBKDF2_ITERATIONS}$${b64url(salt)}$${b64url(new Uint8Array(bits))}`;
}

export async function verifyPassword(password, stored) {
  try {
    const parts = String(stored).split('$');
    if (parts.length !== 5 || parts[0] !== 'pbkdf2') return false;
    const iterations = parseInt(parts[2], 10);
    const salt = fromB64url(parts[3]);
    const expected = fromB64url(parts[4]);
    const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, key, expected.length * 8,
    ));
    if (bits.length !== expected.length) return false;
    let diff = 0;
    for (let i = 0; i < bits.length; i++) diff |= bits[i] ^ expected[i];
    return diff === 0;
  } catch {
    return false;
  }
}

// ── cookies ──────────────────────────────────────────────────────────────────

export function readCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name) return part.slice(idx + 1).trim();
  }
  return null;
}

export function sessionCookie(value, maxAgeSeconds) {
  return `${SESSION_COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSeconds}`;
}

export function clearCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

// ── session lifecycle ────────────────────────────────────────────────────────

function requireSecret(env) {
  if (!env.ENVOICE_SESSION_SECRET) {
    throw Object.assign(
      new Error('ENVOICE_SESSION_SECRET is not set on this worker. Add it in the Cloudflare dashboard (Workers & Pages -> envoice -> Settings -> Variables and Secrets).'),
      { code: 'secret_missing' },
    );
  }
  return env.ENVOICE_SESSION_SECRET;
}

// Issues a fresh session: returns the Set-Cookie value. The caller stores nothing.
export async function createSession(env, user) {
  const secret = requireSecret(env);
  const sid = newSessionId();
  const signature = await hmacSign(secret, sid);
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + SESSION_TTL_DAYS * 86400;
  await env.DB.prepare(
    'INSERT INTO sessions (id_hash, user_id, ver, created_at, expires_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)',
  ).bind(await sha256Hex(sid), user.id, user.session_version, now, expiresAt, now).run();
  return {
    cookie: sessionCookie(`${sid}.${signature}`, SESSION_TTL_DAYS * 86400),
    sidLength: sid.length,
    expiresAt,
  };
}

// Verifies the cookie: HMAC first (cheap, no DB), then the live row.
export async function getSession(request, env, ctx) {
  const raw = readCookie(request, SESSION_COOKIE);
  if (!raw) return null;

  const dot = raw.indexOf('.');
  if (dot === -1) return null;
  const sid = raw.slice(0, dot);
  const signature = raw.slice(dot + 1);
  if (sid.length !== SESSION_ID_CHARS || !signature) return null;

  const secret = requireSecret(env);
  const expected = await hmacSign(secret, sid);
  if (!timingSafeEqual(expected, signature)) return null;

  const row = await env.DB.prepare(
    `SELECT s.id_hash, s.user_id, s.ver, s.expires_at,
            u.email, u.kind, u.session_version
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.id_hash = ?`,
  ).bind(await sha256Hex(sid)).first();

  if (!row) return null;

  const now = Math.floor(Date.now() / 1000);
  if (row.expires_at <= now || row.ver !== row.session_version) {
    ctx.waitUntil(env.DB.prepare('DELETE FROM sessions WHERE id_hash = ?').bind(row.id_hash).run());
    return null;
  }

  // Sliding last_seen, at most once a minute.
  ctx.waitUntil(
    env.DB.prepare('UPDATE sessions SET last_seen_at = ? WHERE id_hash = ? AND last_seen_at < ?')
      .bind(now, row.id_hash, now - 60).run(),
  );

  return { user_id: row.user_id, email: row.email, kind: row.kind, expires_at: row.expires_at };
}

export async function destroySession(request, env) {
  const raw = readCookie(request, SESSION_COOKIE);
  if (!raw) return;
  const sid = raw.split('.')[0];
  if (sid) await env.DB.prepare('DELETE FROM sessions WHERE id_hash = ?').bind(await sha256Hex(sid)).run();
}

export function isValidEmail(email) {
  return typeof email === 'string' && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
}
