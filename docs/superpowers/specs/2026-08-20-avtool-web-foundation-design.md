# avtool-web — Foundation (Accounts, Billing, Licensing)

Status: Approved for planning
Date: 2026-08-20

## Purpose

A new Go web service, `avtool-web`, that lets people subscribe to paid
avtool features: account signup/login, Stripe subscription billing, and
license key issuance/validation. This is the Foundation — everything
two follow-on features (a premium/curated threat feed, and a fleet
dashboard for multi-machine status) depend on. Priority support is the
third paid gate and needs no code (process only).

avtool's CLI is free, open-source (MIT), and public on GitHub — anyone
can already build and run it. The subscription must gate something the
free version genuinely lacks (premium feed access, fleet visibility,
priority support), not the CLI itself.

Positioning is deliberately narrow: avtool does exact SHA256 hash
matching only, no heuristics or behavioral detection. Marketing copy on
this site must not oversell it as a full antivirus replacement.

## Non-goals (this Foundation)

- The premium feed pipeline itself and the CLI's `sync premium` command
  — separate, later plan.
- The fleet check-in endpoint, the CLI's phone-home reporting, and the
  real fleet dashboard UI — separate, later plan. This Foundation ships
  only a placeholder "no machines yet" dashboard section.
- The CLI-side `avtool license activate/status` commands — small,
  separate follow-up to the CLI, not bundled into this web-service work.
- Domain registration and final Stripe account setup — these are the
  user's own actions, blocked on answers to the open questions below.
- Any change to the existing avtool CLI's SQLite storage, scanning
  logic, or `internal/` packages. This is a fully separate program that
  happens to live in the same repo.

## Architecture

A single new Go binary, `cmd/avtool-web/main.go`, following the exact
`cmd/<name>/` layout convention already used by the CLI (`cmd/avtool/`).
New packages live under `internal/web/`, intentionally with zero import
coupling to the CLI's existing `internal/` packages — these are two
independent programs sharing a repo, not one extending the other.

The service uses MariaDB, not the CLI's SQLite — a genuinely separate
concern with its own schema, matching the deployment target's existing
database convention (see Deployment below) rather than an extension of
the CLI's local per-machine database.

### Components

- **`internal/web/auth`** — signup/login. Bcrypt password hashing
  (`golang.org/x/crypto/bcrypt`), session cookie backed by a DB session
  table, rate limiting on login attempts. Auth middleware split into a
  hard-require variant (redirects unauthenticated requests) and an
  optional variant (for endpoints that behave differently for logged-in
  vs anonymous callers without forcing a redirect).
- **`internal/web/billing`** — Stripe integration. Creates a Checkout
  Session for subscription signup; a webhook handler processes
  `customer.subscription.created`/`.updated`/`.deleted` and
  `invoice.payment_failed` to keep the local `subscriptions` table in
  sync with Stripe's view of the world. Webhook signature verification
  via Stripe's official Go SDK (`stripe-go`).
- **`internal/web/license`** — key generation on a successful
  subscription event, hashed storage, and a `POST
  /api/v1/license/validate` endpoint for the avtool CLI to call. License
  keys are random opaque tokens generated server-side via `crypto/rand`
  (format `AVTOOL-XXXX-XXXX-XXXX-XXXX`), never derived from user data,
  stored hashed at rest, validated with constant-time comparison
  (`crypto/subtle.ConstantTimeCompare`). Validation requires a network
  call — deliberately not a self-contained/offline-verifiable format
  like a JWT, since the CLI commands that will consume this
  (`sync premium`, `license status`) already require network access.
- **`internal/web/handlers`** — the marketing/landing page (honest
  copy, no overselling detection claims) and the logged-in account
  dashboard (subscription status, license key display, placeholder
  "no machines yet" section for the future fleet feature).
- **`web/templates/`** — server-rendered HTML via Go's `html/template`
  for landing, signup, login, and dashboard pages. No separate frontend
  build pipeline or JS framework for this scope.

### CLI-facing API convention

The one endpoint the avtool CLI itself will call (`/api/v1/license/validate`)
authenticates via an `X-API-Key` header (the license key itself, for this
endpoint) compared with `crypto/subtle.ConstantTimeCompare`, JSON request/
response bodies, a `200` with a JSON `{"valid": true, "tier": "..."}` body
on success, and a `401` with a JSON `{"valid": false, "error": "..."}` body
on auth failure. This mirrors an existing, proven pattern used elsewhere in
this organization's infrastructure for machine-to-machine authenticated
endpoints.

### Configuration

Environment variables only, loaded via a root-owned `.env` file at
deploy time (never committed): `STRIPE_SECRET_KEY`,
`STRIPE_WEBHOOK_SECRET`, `DB_DSN`, `SESSION_SECRET`, `PORT`.

## Data flow

```
Visitor -> landing page -> signup (email/password) -> account created
                                                          |
                                                    Stripe Checkout
                                                    Session created
                                                          |
                                              customer completes payment
                                                          |
                                          Stripe webhook: subscription.created
                                                          |
                                    subscriptions row updated (status=active)
                                                          |
                                       license key generated, hashed, stored
                                                          |
                                    dashboard shows subscription + license key
                                                          |
                        avtool CLI (separate, later work) -> POST /api/v1/license/validate
                                                          |
                                          200 {valid:true, tier:...} or 401
```

## Storage

A new MariaDB database (name TBD alongside the domain name), with four
tables:

- `users` — id, email, password_hash, created_at.
- `sessions` — token_hash, user_id, expires_at.
- `subscriptions` — id, user_id, stripe_customer_id,
  stripe_subscription_id, tier, status, current_period_end. The `tier`
  column exists so a future single-tier-vs-multi-tier pricing decision
  doesn't require a schema change.
- `licenses` — id, user_id, key_hash, created_at, revoked_at.

Schema files live at `database/avtool-web/NNN_description.sql` in this
repo, following the numbered-migration convention already used by
comparable Go services in this organization's infrastructure.

## Deployment

Target: an existing AWS EC2 instance, `pm-prod-development`
(`10.30.1.94`), verified live over SSH. This is a **shared production
box**, not a dedicated dev environment — it already runs several other
projects' services via systemd + Apache reverse proxy. avtool-web must
not disturb any of them.

Established, repeatable per-site pattern on this box (confirmed via two
live examples already running there):

1. A dedicated OS user per domain owns `/home/<domain>/`.
2. The binary runs as a systemd service under that user, secrets in a
   root-owned `chmod 600` `.env` file, listening on `127.0.0.1:<port>`
   only — never bound to a public interface directly.
3. An Apache vhost pair reverse-proxies the public domain (HTTPS via
   Let's Encrypt/certbot) to that local port.
4. `Restart=on-failure` on the systemd unit.

Deployment on this box is a manual, human-run process (no CI/CD
auto-deploy exists there) — expect to SSH in for each deploy and for
initial setup.

## Error handling

- Stripe webhook signature verification failure: reject with 400, log,
  do not process the event.
- Database unavailable at startup: fail fast, do not serve requests
  against a broken connection.
- License validation for an unknown/revoked key: `401` with a JSON error
  body, never a 500 (a malformed-but-plausible key is expected traffic,
  not a server error).
- Bcrypt/session errors during login: generic "invalid credentials"
  response regardless of whether the email exists, to avoid
  user-enumeration.

## Testing

- `internal/web/auth`: signup, login, session create/validate/expire —
  real bcrypt hashing and a real (test) database, not mocks.
- `internal/web/license`: key generation uniqueness, hash validation,
  constant-time comparison behavior.
- `internal/web/billing`: webhook handling tested against Stripe's
  CLI-based webhook simulator (`stripe listen --forward-to`) using
  Stripe test-mode keys, before any contact with the live server.
- End-to-end manual verification after deploy: full signup through
  Stripe test-mode checkout, webhook fires, subscription flips active,
  license key appears on the dashboard, and validates against
  `/api/v1/license/validate` via a real `curl` call.

## Project layout

```
cmd/avtool-web/         Service entry point
internal/web/auth/
internal/web/billing/
internal/web/license/
internal/web/handlers/
web/templates/           HTML templates (landing, signup, login, dashboard)
database/avtool-web/     Numbered SQL schema files
```

## Open items — blocking deployment, not blocking code

- Domain name (not chosen yet).
- Whether to use a dedicated Stripe account for avtool or share an
  existing one — affects tax/payout separation, not code structure.
- Final pricing/tier structure — the `tier` column keeps this schema
  flexible either way.
