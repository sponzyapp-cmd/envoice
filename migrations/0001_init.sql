-- Envoice — initial schema (D1 / SQLite)
-- One users table for both sides; submissions relate to owner_id + envoice_id only.

CREATE TABLE IF NOT EXISTS users (
  id              TEXT PRIMARY KEY,
  email           TEXT NOT NULL UNIQUE,
  password_hash   TEXT NOT NULL,
  kind            TEXT NOT NULL DEFAULT 'owner',   -- 'owner' | 'customer'
  session_version INTEGER NOT NULL DEFAULT 1,      -- bump = log out everywhere
  created_at      INTEGER NOT NULL
);

-- The owner-side document (what gets published at /e/:id)
CREATE TABLE IF NOT EXISTS envoices (
  id          TEXT PRIMARY KEY,
  owner_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title       TEXT NOT NULL DEFAULT '',
  from_name   TEXT NOT NULL DEFAULT '',
  to_name     TEXT NOT NULL DEFAULT '',
  note        TEXT NOT NULL DEFAULT '',
  currency    TEXT NOT NULL DEFAULT 'KES',
  payload     TEXT NOT NULL,                       -- full tiers JSON
  total       REAL NOT NULL DEFAULT 0,             -- recomputed server-side
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_envoices_owner ON envoices(owner_id, created_at DESC);

-- The customer-side final selection. No customer_id: relations are
-- owner_id + envoice_id only, customer identity is plain columns.
CREATE TABLE IF NOT EXISTS envoice_submissions (
  id              TEXT PRIMARY KEY,
  envoice_id      TEXT NOT NULL REFERENCES envoices(id) ON DELETE CASCADE,
  owner_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  payload         TEXT NOT NULL,
  total           REAL NOT NULL DEFAULT 0,
  customer_name   TEXT NOT NULL DEFAULT '',
  customer_email  TEXT NOT NULL DEFAULT '',        -- matched, never a FK
  submitted_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_subs_owner ON envoice_submissions(owner_id, submitted_at DESC);
CREATE INDEX IF NOT EXISTS idx_subs_envoice ON envoice_submissions(envoice_id);
CREATE INDEX IF NOT EXISTS idx_subs_email ON envoice_submissions(customer_email);

-- Sessions: the raw 128-char sid is NEVER stored, only its sha256.
CREATE TABLE IF NOT EXISTS sessions (
  id_hash      TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ver          INTEGER NOT NULL,
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions(expires_at);
