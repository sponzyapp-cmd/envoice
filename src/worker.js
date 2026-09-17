// Envoice — the single Cloudflare Worker.
//   /            static, served straight from the asset store (byte-identical file)
//   /e/:id       the same file + one injected <script> with the published payload
//   /s/:id       the same file + the submission (owner detail, or customer confirmation)
//   /api/*       JSON API backed by D1
//
// Auth: HMAC-SHA256 session cookie (see auth.js). Data: D1 only.

import {
  createSession, getSession, destroySession, clearCookie, readCookie,
  hashPassword, verifyPassword, publicId, isValidEmail, SESSION_ID_CHARS,
} from './auth.js';
import {
  findUserByEmail, findUserById, createUser, createEnvoice, getEnvoice, listEnvoices,
  deleteEnvoice, createSubmission, getSubmission, listSubmissions, deleteSubmission,
  clearSubmissions, computeTotal,
} from './db.js';

const MAX_BODY_BYTES = 512 * 1024;
const MIN_PASSWORD = 8;
let templateCache = null;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    try {
      if (url.pathname === '/health') return json({ ok: true, worker: 'envoice' });
      if (url.pathname.startsWith('/api/')) return await handleApi(request, env, ctx, url);
      if (url.pathname.startsWith('/e/')) return await servePublished(request, env, ctx, url);
      if (url.pathname.startsWith('/s/')) return await serveSubmission(request, env, ctx, url);
      return env.ASSETS.fetch(request);
    } catch (err) {
      console.error('envoice.unhandled', err?.stack || String(err));
      if (err && err.code === 'secret_missing') return json({ error: 'secret_missing', message: err.message }, 503);
      return json({ error: 'internal_error' }, 500);
    }
  },
};

// ── API ──────────────────────────────────────────────────────────────────────

async function handleApi(request, env, ctx, url) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders() });

  const limited = await checkRateLimit(request, env);
  if (limited) return limited;

  const path = url.pathname.replace(/\/+$/, '');
  const method = request.method;

  if (path === '/api/me' && method === 'GET') return apiMe(request, env, ctx);
  if (path === '/api/auth/login' && method === 'POST') return apiLogin(request, env, ctx);
  if (path === '/api/auth/signup' && method === 'POST') return apiSignup(request, env, ctx);
  if (path === '/api/auth/logout' && method === 'POST') return apiLogout(request, env, ctx);

  if (path === '/api/envoices' && method === 'POST') return apiCreateEnvoice(request, env, ctx);
  if (path === '/api/envoices' && method === 'GET') return apiListEnvoices(request, env, ctx);
  if (path.startsWith('/api/envoices/') && method === 'DELETE') {
    return apiDeleteEnvoice(request, env, ctx, decodeURIComponent(path.slice('/api/envoices/'.length)));
  }

  if (path === '/api/submissions' && method === 'POST') return apiCreateSubmission(request, env, ctx);
  if (path === '/api/submissions' && method === 'GET') return apiListSubmissions(request, env, ctx);
  if (path === '/api/submissions' && method === 'DELETE') return apiClearSubmissions(request, env, ctx);
  if (path.startsWith('/api/submissions/') && method === 'GET') {
    return apiGetSubmission(request, env, ctx, decodeURIComponent(path.slice('/api/submissions/'.length)));
  }
  if (path.startsWith('/api/submissions/') && method === 'DELETE') {
    return apiDeleteSubmission(request, env, ctx, decodeURIComponent(path.slice('/api/submissions/'.length)));
  }

  return json({ error: 'not_found' }, 404);
}

async function checkRateLimit(request, env) {
  if (!env.RATE_LIMITER) return null;
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const { success } = await env.RATE_LIMITER.limit({ key: ip });
  if (success) return null;
  return json({ error: 'rate_limited' }, 429, { 'Retry-After': '60' });
}

async function apiMe(request, env, ctx) {
  const session = await getSession(request, env, ctx);
  if (!session) return json({ authenticated: false }, 200);
  return json({
    authenticated: true,
    email: session.email,
    kind: session.kind,
    expiresAt: session.expires_at * 1000,
    sessionIdChars: SESSION_ID_CHARS,
  });
}

async function apiLogin(request, env, ctx) {
  const body = await readJson(request);
  if (!body) return json({ error: 'bad_request' }, 400);
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  if (!isValidEmail(email) || !password) return json({ error: 'invalid_credentials', message: 'Enter a valid email and password.' }, 400);

  const user = await findUserByEmail(env, email);
  if (!user) return json({ error: 'invalid_credentials', message: 'No account for that email.' }, 401);
  if (!(await verifyPassword(password, user.password_hash))) {
    return json({ error: 'invalid_credentials', message: 'Wrong password.' }, 401);
  }
  const session = await createSession(env, user);
  return json({ ok: true, email: user.email, kind: user.kind, expiresAt: session.expiresAt * 1000 },
    200, { 'Set-Cookie': session.cookie });
}

async function apiLogout(request, env, ctx) {
  await destroySession(request, env);
  return json({ ok: true }, 200, { 'Set-Cookie': clearCookie() });
}

// Create an account from the header pill. An email that has already received
// submissions is a customer; otherwise it is an owner.
async function apiSignup(request, env, ctx) {
  const body = await readJson(request);
  if (!body) return json({ error: 'bad_request' }, 400);
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  if (!isValidEmail(email)) return json({ error: 'invalid_email', message: 'Enter a valid email address.' }, 400);
  if (password.length < MIN_PASSWORD) {
    return json({ error: 'weak_password', message: `Password must be at least ${MIN_PASSWORD} characters.` }, 400);
  }
  if (await findUserByEmail(env, email)) {
    return json({ error: 'email_taken', message: 'That email already has an account. Sign in instead.' }, 409);
  }
  const { results } = await env.DB.prepare(
    'SELECT 1 AS hit FROM envoice_submissions WHERE customer_email = ? LIMIT 1',
  ).bind(email).all();
  const kind = results && results.length ? 'customer' : 'owner';
  const user = await createUser(env, { email, passwordHash: await hashPassword(password), kind });
  const session = await createSession(env, user);
  return json({ ok: true, email: user.email, kind: user.kind }, 201, { 'Set-Cookie': session.cookie });
}

// Publish. A live session is enough; otherwise the owner's email + password
// claim (or create) the account inline.
async function apiCreateEnvoice(request, env, ctx) {
  const body = await readJson(request);
  if (!body) return json({ error: 'bad_request' }, 400);

  const payload = normalizePayload(body.envoice);
  if (!payload) return json({ error: 'invalid_envoice', message: 'That envoice could not be read.' }, 400);

  const existing = await getSession(request, env, ctx);
  let user = null;
  let setCookie = null;

  if (existing) {
    user = await findUserById(env, existing.user_id);
  } else {
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    if (!isValidEmail(email)) return json({ error: 'invalid_email', message: 'Enter a valid email address.' }, 400);
    if (password.length < MIN_PASSWORD) {
      return json({ error: 'weak_password', message: `Password must be at least ${MIN_PASSWORD} characters.` }, 400);
    }
    const found = await findUserByEmail(env, email);
    if (found) {
      if (!(await verifyPassword(password, found.password_hash))) {
        return json({ error: 'invalid_credentials', message: 'That email already exists and the password does not match.' }, 401);
      }
      user = found;
    } else {
      user = await createUser(env, { email, passwordHash: await hashPassword(password), kind: 'owner' });
    }
    const session = await createSession(env, user);
    setCookie = session.cookie;
  }

  if (!user) return json({ error: 'unauthorized' }, 401);

  const row = await createEnvoice(env, { ownerId: user.id, payload, total: computeTotal(payload) });
  const headers = setCookie ? { 'Set-Cookie': setCookie } : {};
  return json({ ok: true, id: row.id, url: `${new URL(request.url).origin}/e/${row.id}`, total: row.total }, 201, headers);
}

async function apiListEnvoices(request, env, ctx) {
  const session = await getSession(request, env, ctx);
  if (!session) return json({ error: 'unauthorized' }, 401);
  const rows = await listEnvoices(env, session.user_id);
  return json({ ok: true, envoices: rows.map((r) => ({ ...r, url: `/e/${r.id}`, createdAt: r.created_at * 1000 })) });
}

async function apiDeleteEnvoice(request, env, ctx, id) {
  const session = await getSession(request, env, ctx);
  if (!session) return json({ error: 'unauthorized' }, 401);
  if (!id) return json({ error: 'bad_request' }, 400);
  await deleteEnvoice(env, id, session.user_id);
  return json({ ok: true });
}

async function apiCreateSubmission(request, env, ctx) {
  const body = await readJson(request);
  if (!body) return json({ error: 'bad_request' }, 400);

  const envoiceId = String(body.envoiceId || '').trim();
  if (!envoiceId) return json({ error: 'missing_envoice' }, 400);
  const envoice = await getEnvoice(env, envoiceId);
  if (!envoice) return json({ error: 'envoice_not_found', message: 'That envoice link is no longer valid.' }, 404);

  const payload = normalizePayload(body.envoice);
  if (!payload) return json({ error: 'invalid_envoice' }, 400);

  const customerName = String(body.customerName || payload.to || '').trim().slice(0, 200);
  const customerEmail = String(body.customerEmail || '').trim().toLowerCase();
  if (customerEmail && !isValidEmail(customerEmail)) {
    return json({ error: 'invalid_email', message: 'Enter a valid email address.' }, 400);
  }

  const row = await createSubmission(env, {
    envoice, payload, total: computeTotal(payload), customerName, customerEmail,
  });

  // Optional customer signup, in the same breath as the submission.
  let setCookie = null;
  let signedUp = false;
  const signup = body.signup;
  if (signup && typeof signup === 'object') {
    const email = String(signup.email || customerEmail || '').trim().toLowerCase();
    const password = String(signup.password || '');
    if (!isValidEmail(email)) return json({ error: 'invalid_email', message: 'Enter a valid email address.' }, 400);
    if (password.length < MIN_PASSWORD) {
      return json({ error: 'weak_password', message: `Password must be at least ${MIN_PASSWORD} characters.` }, 400);
    }
    let user = await findUserByEmail(env, email);
    if (user) {
      if (!(await verifyPassword(password, user.password_hash))) {
        return json({ error: 'invalid_credentials', message: 'That email is taken and the password does not match.' }, 401);
      }
    } else {
      user = await createUser(env, { email, passwordHash: await hashPassword(password), kind: 'customer' });
    }
    const session = await createSession(env, user);
    setCookie = session.cookie;
    signedUp = true;
  }

  const headers = setCookie ? { 'Set-Cookie': setCookie } : {};
  return json({
    ok: true,
    id: row.id,
    signedUp,
    total: row.total,
    url: `${new URL(request.url).origin}/s/${row.id}`,
    submittedAt: row.submitted_at * 1000,
  }, 201, headers);
}

async function apiListSubmissions(request, env, ctx) {
  const session = await getSession(request, env, ctx);
  if (!session) return json({ error: 'unauthorized' }, 401);
  const rows = await listSubmissions(env, session);
  return json({
    ok: true,
    role: session.kind,
    submissions: rows.map((r) => ({
      id: r.id,
      envoiceId: r.envoice_id,
      total: r.total,
      customerName: r.customer_name,
      customerEmail: r.customer_email,
      submittedAt: r.submitted_at * 1000,
      // the client renders inbox rows from this summary; full payload on click
      summary: payloadSummary(r.payload),
    })),
  });
}

async function apiGetSubmission(request, env, ctx, id) {
  const session = await getSession(request, env, ctx);
  if (!session) return json({ error: 'unauthorized' }, 401);
  if (!id) return json({ error: 'bad_request' }, 400);
  const row = await getSubmission(env, id);
  if (!row) return json({ error: 'not_found' }, 404);

  const isOwner = row.owner_id === session.user_id;
  const isCustomer = session.kind === 'customer' && row.customer_email && row.customer_email === session.email;
  if (!isOwner && !isCustomer) return json({ error: 'forbidden' }, 403);

  return json({
    ok: true,
    submission: {
      id: row.id,
      envoiceId: row.envoice_id,
      envoice: safeParse(row.payload),
      total: row.total,
      customerName: row.customer_name,
      customerEmail: row.customer_email,
      submittedAt: row.submitted_at * 1000,
    },
  });
}

async function apiDeleteSubmission(request, env, ctx, id) {
  const session = await getSession(request, env, ctx);
  if (!session) return json({ error: 'unauthorized' }, 401);
  if (!id) return json({ error: 'bad_request' }, 400);
  const row = await getSubmission(env, id);
  if (!row) return json({ error: 'not_found' }, 404);
  if (row.owner_id !== session.user_id) return json({ error: 'forbidden' }, 403);
  await deleteSubmission(env, id, session.user_id);
  return json({ ok: true });
}

async function apiClearSubmissions(request, env, ctx) {
  const session = await getSession(request, env, ctx);
  if (!session) return json({ error: 'unauthorized' }, 401);
  await clearSubmissions(env, session.user_id);
  return json({ ok: true });
}

// ── HTML serving ─────────────────────────────────────────────────────────────

async function loadTemplate(request, env) {
  if (templateCache) return templateCache;
  const res = await env.ASSETS.fetch(new URL('/', request.url).toString());
  if (!res.ok) throw new Error(`asset_fetch_failed_${res.status}`);
  templateCache = await res.text();
  return templateCache;
}

function inject(html, scriptBody) {
  const tag = `<script>${scriptBody}</script>`;
  return html.includes('<body>') ? html.replace('<body>', `<body>\n${tag}`) : html.replace('</head>', `${tag}</head>`);
}

async function servePublished(request, env, ctx, url) {
  const id = cleanId(url.pathname.slice('/e/'.length));
  const row = id ? await getEnvoice(env, id) : null;
  if (!row) return notFoundPage(request, env);

  const payload = safeParse(row.payload);
  const body = [
    `window.__ENVOICE_DATA__ = ${jsonForScript(payload)};`,
    'window.__ENVOICE_SUBMITTED__ = false;',
    `window.__ENVOICE_ID__ = ${jsonForScript(row.id)};`,
  ].join('\n');
  return htmlResponse(inject(await loadTemplate(request, env), body));
}

async function serveSubmission(request, env, ctx, url) {
  const id = cleanId(url.pathname.slice('/s/'.length));
  const row = id ? await getSubmission(env, id) : null;
  if (!row) return notFoundPage(request, env);

  const payload = safeParse(row.payload);
  const session = await getSession(request, env, ctx);
  const isOwner = session && session.user_id === row.owner_id;
  const isCustomer = session && session.kind === 'customer' && row.customer_email && row.customer_email === session.email;

  const body = (isOwner || isCustomer)
    ? [
      `window.__ENVOICE_SUBMISSION__ = ${jsonForScript({ envoice: payload, submittedAt: row.submitted_at * 1000 })};`,
      `window.__ENVOICE_SUBMISSION_ID__ = ${jsonForScript(row.id)};`,
    ].join('\n')
    : [
      `window.__ENVOICE_DATA__ = ${jsonForScript(payload)};`,
      'window.__ENVOICE_SUBMITTED__ = true;',
      `window.__ENVOICE_ID__ = ${jsonForScript(row.envoice_id)};`,
    ].join('\n');

  return htmlResponse(inject(await loadTemplate(request, env), body));
}

async function notFoundPage(request, env) {
  try {
    const html = await loadTemplate(request, env);
    return htmlResponse(inject(html, 'window.__ENVOICE_MISSING__ = true;'), 404);
  } catch {
    return new Response('Not found', { status: 404, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
  }
}

function htmlResponse(html, status = 200) {
  return new Response(html, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Robots-Tag': 'noindex, nofollow',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    },
  });
}

// ── small helpers ────────────────────────────────────────────────────────────

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...corsHeaders(),
      ...extraHeaders,
    },
  });
}

function corsHeaders() {
  return { 'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' };
}

async function readJson(request) {
  const length = parseInt(request.headers.get('Content-Length') || '0', 10);
  if (length > MAX_BODY_BYTES) return null;
  try {
    const text = await request.text();
    if (text.length > MAX_BODY_BYTES) return null;
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

function cleanId(raw) {
  const id = String(raw || '').split('?')[0].split('#')[0].replace(/\/+$/, '').trim();
  return /^[A-Za-z0-9_-]{6,80}$/.test(id) ? id : null;
}

function safeParse(text) {
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

function normalizePayload(input) {
  if (!input || typeof input !== 'object' || !Array.isArray(input.tiers)) return null;
  if (JSON.stringify(input).length > MAX_BODY_BYTES) return null;
  const out = {
    title: str(input.title), from: str(input.from), to: str(input.to), note: str(input.note),
    currency: str(input.currency) || 'KES',
    tiers: input.tiers.slice(0, 50).map((tier) => ({
      id: str(tier?.id) || publicId('tier'),
      name: str(tier?.name),
      desc: str(tier?.desc),
      selected: tier?.selected === true,
      items: (Array.isArray(tier?.items) ? tier.items : []).slice(0, 500).map((item) => ({
        id: str(item?.id) || publicId('item'),
        name: str(item?.name),
        desc: str(item?.desc),
        price: parseFloat(item?.price) || 0,
        checked: item?.checked !== false,
        expanded: item?.expanded === true,
        expandedClient: item?.expandedClient === true,
      })),
    })),
  };
  return out;
}

function payloadSummary(text) {
  const payload = safeParse(text);
  if (!payload) return { from: '', to: '', title: '', currency: 'KES' };
  return {
    from: str(payload.from), to: str(payload.to), title: str(payload.title),
    currency: str(payload.currency) || 'KES',
  };
}

function str(value) {
  return typeof value === 'string' ? value.slice(0, 5000) : '';
}

// JSON that cannot break out of a <script> tag.
function jsonForScript(value) {
  return JSON.stringify(value ?? null)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}
