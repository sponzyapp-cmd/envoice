# Envoice

A single Cloudflare Worker that serves the Envoice HTML app and keeps every
claimed envoice, submission and session in **D1**.

- App: <https://envoice.londondke.workers.dev>
- One worker. No KV, no R2, no second service, no build step.

## What the worker does

| Route | Serves |
|---|---|
| `/` | the app, straight from the asset store |
| `/e/:id` | the same file + one injected `<script>` with the published envoice |
| `/s/:id` | the submission — owner detail view when signed in, else the customer's confirmation |
| `/api/*` | JSON API (see below) |
| `/health` | `{"ok":true}` |

The app itself is `public/index.html`. Its CSS and markup are **untouched** from
the original file; only the data layer talks to the API.

## Data model

```
users                 id, email UNIQUE, password_hash, kind ('owner'|'customer'),
                      session_version, created_at
envoices              the owner-side document (published at /e/:id)
envoice_submissions   the customer-side final selection
sessions              sha256(sid) only — the raw session id is never stored
```

A submission is related to **`owner_id` + `envoice_id` only**. There is no
`customer_id`: the customer is `customer_name` / `customer_email`, plain
columns. That is also how the optional customer account works — sign up with
the same email you submitted with and `GET /api/submissions` returns every
submission where that email matches.

## Sessions

- Session id = **128 characters** (base64url of 96 random bytes).
- Cookie = `sid.HMAC-SHA256(SECRET, sid)` — a tampered cookie is rejected before
  any database read.
- D1 stores `sha256(sid)`, never the raw value.
- Lifetime **30 days**, sliding `last_seen_at`. After that the owner signs back
  in with the same email + password.
- Logout deletes the row; bumping `users.session_version` logs a user out
  everywhere.

## Setup

```bash
npm install

# 1. the session signing secret (HMAC key) — create it in the dashboard:
#    Workers & Pages -> envoice -> Settings -> Variables and Secrets
#    type: Secret   name: ENVOICE_SESSION_SECRET
#    value: any long random string, e.g.  openssl rand -base64 96 | tr '+/' '-_' | tr -d '='

# 2. database
npx wrangler d1 migrations apply envoice-db --remote

# 3. deploy
npx wrangler deploy
```

## API

| Method + path | Auth | Purpose |
|---|---|---|
| `POST /api/envoices` | session, or `{email,password}` in the body | publish, returns `{id, url, total}` |
| `GET /api/envoices` | session | the owner's published envoices |
| `DELETE /api/envoices/:id` | session (owner) | unpublish — the `/e/:id` link dies |
| `POST /api/submissions` | none (+ optional `signup{email,password}`) | save a customer selection |
| `GET /api/submissions` | session | owner: everything addressed to them; customer: email match |
| `GET /api/submissions/:id` | session (owner or matching customer) | one submission |
| `DELETE /api/submissions/:id` | session (owner) | delete one |
| `DELETE /api/submissions` | session (owner) | clear the inbox |
| `POST /api/auth/login` / `logout` | — | session lifecycle |
| `GET /api/me` | cookie | who am I |

Rate limit: 50 requests / 60 s per IP (binding `RATE_LIMITER`, namespace 2121),
429s carry `Retry-After`.

## Notes

- The in-progress draft stays in the browser (`localStorage`); only claimed
  envoices and submissions go to D1.
- The old `#d=` / `#s=` compressed-hash links still open correctly as a
  fallback.
- Passwords: PBKDF2-SHA256, 100 000 iterations, per-user salt.
