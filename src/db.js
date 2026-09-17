// Envoice — D1 access layer. One store: no KV, no R2.

import { publicId } from './auth.js';

export async function findUserByEmail(env, email) {
  return env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
}

export async function findUserById(env, id) {
  return env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(id).first();
}

export async function createUser(env, { email, passwordHash, kind }) {
  const user = {
    id: publicId('usr'),
    email,
    password_hash: passwordHash,
    kind,
    session_version: 1,
    created_at: Math.floor(Date.now() / 1000),
  };
  await env.DB.prepare(
    'INSERT INTO users (id, email, password_hash, kind, session_version, created_at) VALUES (?, ?, ?, ?, ?, ?)',
  ).bind(user.id, user.email, user.password_hash, user.kind, user.session_version, user.created_at).run();
  return user;
}

export async function createEnvoice(env, { ownerId, payload, total }) {
  const now = Math.floor(Date.now() / 1000);
  const row = {
    id: publicId('env'),
    owner_id: ownerId,
    title: str(payload.title),
    from_name: str(payload.from),
    to_name: str(payload.to),
    note: str(payload.note),
    currency: str(payload.currency) || 'KES',
    payload: JSON.stringify(payload),
    total,
    created_at: now,
    updated_at: now,
  };
  await env.DB.prepare(
    `INSERT INTO envoices (id, owner_id, title, from_name, to_name, note, currency, payload, total, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(row.id, row.owner_id, row.title, row.from_name, row.to_name, row.note, row.currency,
    row.payload, row.total, row.created_at, row.updated_at).run();
  return row;
}

export async function getEnvoice(env, id) {
  return env.DB.prepare('SELECT * FROM envoices WHERE id = ?').bind(id).first();
}

export async function listEnvoices(env, ownerId) {
  const { results } = await env.DB.prepare(
    'SELECT id, title, to_name, currency, total, created_at FROM envoices WHERE owner_id = ? ORDER BY created_at DESC LIMIT 200',
  ).bind(ownerId).all();
  return results || [];
}

export async function deleteEnvoice(env, id, ownerId) {
  return env.DB.prepare('DELETE FROM envoices WHERE id = ? AND owner_id = ?').bind(id, ownerId).run();
}

export async function createSubmission(env, { envoice, payload, total, customerName, customerEmail }) {
  const row = {
    id: publicId('sub'),
    envoice_id: envoice.id,
    owner_id: envoice.owner_id,
    payload: JSON.stringify(payload),
    total,
    customer_name: str(customerName),
    customer_email: str(customerEmail).toLowerCase(),
    submitted_at: Math.floor(Date.now() / 1000),
  };
  await env.DB.prepare(
    `INSERT INTO envoice_submissions (id, envoice_id, owner_id, payload, total, customer_name, customer_email, submitted_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(row.id, row.envoice_id, row.owner_id, row.payload, row.total,
    row.customer_name, row.customer_email, row.submitted_at).run();
  return row;
}

export async function getSubmission(env, id) {
  return env.DB.prepare('SELECT * FROM envoice_submissions WHERE id = ?').bind(id).first();
}

// Owner sees everything addressed to them; a customer sees submissions whose
// customer_email matches their own address. No customer_id column anywhere.
export async function listSubmissions(env, user) {
  const sql = user.kind === 'customer'
    ? `SELECT id, envoice_id, owner_id, total, customer_name, customer_email, submitted_at, payload
         FROM envoice_submissions WHERE customer_email = ? ORDER BY submitted_at DESC LIMIT 200`
    : `SELECT id, envoice_id, owner_id, total, customer_name, customer_email, submitted_at, payload
         FROM envoice_submissions WHERE owner_id = ? ORDER BY submitted_at DESC LIMIT 200`;
  const { results } = await env.DB.prepare(sql).bind(user.kind === 'customer' ? user.email : user.user_id).all();
  return results || [];
}

export async function deleteSubmission(env, id, ownerId) {
  return env.DB.prepare('DELETE FROM envoice_submissions WHERE id = ? AND owner_id = ?').bind(id, ownerId).run();
}

export async function clearSubmissions(env, ownerId) {
  return env.DB.prepare('DELETE FROM envoice_submissions WHERE owner_id = ?').bind(ownerId).run();
}

function str(value) {
  return typeof value === 'string' ? value.slice(0, 5000) : '';
}

// Same rule the client uses for "Total": multi-package -> only the selected
// package counts; inside a package only ticked items count.
export function computeTotal(payload) {
  if (!payload || !Array.isArray(payload.tiers)) return 0;
  const multi = payload.tiers.length > 1;
  const tiers = multi ? payload.tiers.filter((t) => t && t.selected === true) : payload.tiers;
  return tiers
    .flatMap((t) => (Array.isArray(t.items) ? t.items : []))
    .filter((i) => i && i.checked)
    .reduce((sum, i) => sum + (parseFloat(i.price) || 0), 0);
}
