# Vaultra — AI Agent Compliance Layer
## Project Context for Claude Code

### What is Vaultra?
B2B SaaS startup — AI Agent Compliance Layer for EU-regulated fintechs.
Generates cryptographic Compliance Receipts for every AI agent decision.
Founder: Jerly Rojas | Location: Rheine, Germany | hello@vaultra.io

### Core Value Proposition
"Compliance-as-a-Receipt" — cryptographic proof (not documentation) for every AI decision.
Targets EU fintechs needing compliance with EU AI Act Art. 12, GDPR Art. 22, eIDAS Art. 41, DORA.
Pricing: $299/mo (Starter, 100K decisions) | $799/mo (Growth, 1M decisions) | Custom (Enterprise)

---

## Architecture

### Infrastructure — 100% Hetzner (Railway cancelled)
- **Server:** Hetzner CX12, 178.104.86.252, Nuremberg — SSH alias `hetzner` (configured in `~/.ssh/config`)
- **Database:** SQLite at `/data/vaultra_admin.db` — WAL mode, foreign_keys ON, 5 indexes, daily backup via `/etc/cron.daily/vaultra-backup` (14-day rotation)
- **DNS/SSL:** Full Strict + Let's Encrypt on all 3 domains
- **TSA:** Sectigo eIDAS QTSP — http://timestamp.sectigo.com/qualified (replaced DigiCert, blocked from cloud IPs) — confirmed STAMPED in production
- **CI/CD:** GitHub Actions auto-deploy on push to `main` (SSH + git pull + restart both services + nginx reload)
- **PyPI:** `vaultra==2.0.2` — `pip install vaultra`

### Key URLs / Services
| Domain | Purpose | Runtime | systemd unit |
|---|---|---|---|
| vaultra.io | Landing page | Nginx, webroot isolated at `/var/www/vaultra-landing` | — |
| admin.vaultra.io | Operator admin panel | Flask/Gunicorn :8000 | `vaultra` |
| app.vaultra.io | Self-service client portal | Flask/Gunicorn :8001 | `vaultra-portal` |
| vaultra.io/verify | Public receipt verifier | — | — |

### Repository
- GitHub: github.com/Jerryto10/vaultra
- Branch: main (auto-deploy via GitHub Actions — live)
- GitHub PAT: rotated Jul 26, 2026 (fine-grained, `Contents: Read and write`), stored via macOS Keychain credential helper

---

## SDK — 7 Compliance Layers (all REAL, wired end-to-end in pipeline.py)
Prior to Jul 2026 only Layer 6 was real; the rest were cosmetic stubs. Now fully connected:

| Layer | Module | Function | Status |
|---|---|---|---|
| 1 | identity.py | Ed25519 cryptographic identity per agent | Real signing |
| 2 | sanitizer.py | 3-engine prompt injection detection | Real, blocks with `ComplianceViolation` |
| 3 | ledger.py | Hash-chained audit ledger | Real hash-chain |
| 4 | guardian.py | ML-based output anomaly detection | Real; offline fallback if `ANTHROPIC_API_KEY` unset |
| 5 | human_gate.py | Authorization for irreversible actions | Blocks TRANSFER/DELETE/IRREVERSIBLE, auto-passes rest |
| 6 | timestamper.py | RFC 3161 — Sectigo eIDAS QTSP | Real (was already) |
| 7 | api_keys.py | SHA-256 hashed keys, instant revocation | Real, reflected in `layers_passed` |

Test suite: `tests/test_pipeline_layers.py` (9 new tests) — 12/12 tests passing total.
`ComplianceViolation` is exported in the public API.

### SDK Usage
```python
from vaultra import VaultraPipeline
pipeline = VaultraPipeline(
    agent_id="credit-bot-v1",
    api_key="vaultra_sk_v1_...",
    scope="credit_decisions",
    regulation="EU AI Act Art. 12"
)
receipt = pipeline.process(input_data, agent_response, decision_type="LOAN_APPROVED")
```

---

## Admin Panel (admin.vaultra.io)
- **Framework:** Flask + Gunicorn (2 workers), systemd `vaultra`
- **Auth:** bcrypt passwords, 30min session timeout, rate limiting (5 attempts/5min) — now backed by SQLite (was per-worker dict, ineffective with multi-worker Gunicorn)
- **Routes:** 20+ routes — clients, receipts, audit log, settings, health check, reports
- **Reports:** PDF + CSV per client
- **Verifier:** Public API at /api/verify/<rid> (CORS enabled)
- **Invite button:** generates client activation link (7-day token) for the portal
- **Internal test client:** "Vaultra Internal - KYC Test Agent" (`kyc-test@vaultra.io`, plan starter) — created directly in the DB on Jul 26, 2026 for the KYC E2E test; safe to keep or archive/revoke via the Clients page

## Client Portal (app.vaultra.io) — functional, built autonomously via CLAUDE.md
- **Framework:** Flask + Gunicorn, systemd `vaultra-portal`
- Client login + activation via invitation token (7 days)
- Dashboard: quota, receipts, plan
- Receipts: search/pagination/detail
- Reports: CSV/PDF download
- Password change
- End-to-end flow tested and confirmed working

### Environment Variables (Hetzner `.env`)
- DB_PATH=/data/vaultra_admin.db
- SECRET_KEY=<required — app refuses to start without it>
- PORTAL_SECRET_KEY=<required — app refuses to start without it>
- PORTAL_ADMIN_TOKEN=<from .env>
- PORTAL_URL=<from .env>
- ADMIN_PASSWORD=<rotated — stored in Bitwarden, never commit the value>
- VAULTRA_TSA=sectigo ✅

Credentials of any kind (values) live only in Hetzner `.env` and Bitwarden — never in this file or git.

---

## Security — full audit completed (Jul 2026)
Done via Claude Code plugins: security-guidance, code-review, supabase, playwright, context7. All critical items resolved:
- ✅ CSRF protection global (synchronizer token + `window.fetch` patch)
- ✅ XSS fixes (stored XSS in PDF reports + onclick handlers, `sanitize_text()` on all fields)
- ✅ Rate limiting moved to SQLite (was per-worker dict)
- ✅ SECRET_KEY mandatory from env
- ✅ WAL mode + indexes on DB
- ✅ Quota race condition fixed (atomic `BEGIN IMMEDIATE` transaction)
- ✅ Guardian bug fixed (missing `x-api-key` header)
- ✅ `.env` and `.git` no longer publicly exposed (isolated webroot)
- ✅ Hardcoded passwords removed from `init_db()` and this file
- ✅ Admin password rotated

### Resolved (Jul 26, 2026)
- ✅ GitHub PAT rotated (fine-grained, `Contents: Read and write`), stored via macOS Keychain credential helper — no more plaintext token in remote URL
- ✅ Git history scrubbed with `git-filter-repo` — the old rotated admin password (exposed in a public repo) removed from all commits, force-pushed, Hetzner clone resynced via `fetch` + `reset --hard`

### Resolved (Aug 2, 2026) — Security Hardening Phase 1 (post-scan, 28-finding audit)
Full plan: `docs/superpowers/plans/2026-07-27-vaultra-security-hardening.md`. Executed via subagent-driven development (11 task-level reviews + 1 final whole-branch review, all clean or resolved via fix loop). Merged to `main` (13 commits, `89e6476..ec5bf2a`), 42/42 tests passing. Not yet pushed to origin/Hetzner — pending explicit go-ahead (push triggers auto-deploy).
- ✅ **F6** — sanitizer.py: a confirmed-critical PatternEngine hit now forces an immediate INJECTION verdict (previously diluted into SUSPICIOUS by the weighted ensemble); refined post-review so the short-circuit only fires on a genuine critical-category hit, not 3+ stacked non-critical categories.
- ✅ **F14** — guardian.py: PII exposure detection in `OfflineGuard` no longer silently suppressed based on declared scope (`send_email`/`send_message`/`share`).
- ✅ **F20** — human_gate.py: the approval token is no longer handed back to the requester (was enabling self-approval of irreversible actions); `decide()` now rejects a `decided_by` matching the requesting agent.
- ✅ **F22** — pipeline.py: Layers 2 (sanitizer) and 4 (guardian) now fail **closed** (raise `ComplianceViolation`) on an analyzer exception, instead of silently marking the layer failed and returning a passing receipt.
- ✅ **New finding (found mid-fix, not in original scan)** — guardian.py's entire pattern dict had ~20 of 25 regex patterns silently broken by stray literal backspace bytes (`\x08`) since the file's first commit, across 6 risk categories (only `pii_exposure` had been partially caught before). All stripped; `OfflineGuard`'s offline pattern-based detection is now fully functional for the first time in production.
- ✅ **F21 — full fix** (originally scoped as backlog-only; user requested the complete fix, not a deferral): Ed25519 identity is no longer ephemeral/unverifiable.
  - SDK (`vaultra/identity.py`) persists its keypair locally (`~/.vaultra/keys/<agent_id>.pem`, 0600) instead of regenerating per process; transmits `identity_signature`/`identity_fingerprint`/`identity_public_key` with every receipt.
  - `admin/app.py` gained `agent_keys` + `agent_key_conflicts` tables: the first public key seen per `(client_id, agent_id)` is trusted (safe — that request is already authenticated by an admin-issued `api_key`, no unauthenticated squatting window); a later *different* key goes to a pending conflict instead of silently overwriting.
  - New admin UI (`/agent-keys`) to review/approve/reject pending key conflicts (deduped by `client_id`+`agent_id`+key).
  - `/api/verify/<rid>` now performs real Ed25519 signature verification against the registered key and exposes `identity_verified: bool` — kept separate from `rfc3161_valid`/`eidas_art41`. The trust decision rests solely on the cryptographic signature check, never on the client-supplied fingerprint string.

### Non-critical findings (medium/low priority, not yet fixed)
- Ledger hash chain has no lock under concurrency (possible fork under high load)
- No retry logic on HTTP calls to the TSA
- CSV formula injection (F7/F8) — Phase 2 of the hardening plan, not yet started
- Future migration SQLite → PostgreSQL/Supabase when volume grows
- No MFA/2FA
- Audit log capped at 200 rows, no pagination
- Stale "DigiCert" branding in some admin templates and `health_check.html` (references retired infra)
- No Playwright E2E tests yet
- **Human Gate approval flow is ephemeral** — `HumanGate.decide(token, ...)` only resolves a pending request held in that same Python process's in-memory `_pending` dict. Once the agent process exits, the token is gone — there's no durable admin.vaultra.io view to list/approve/reject pending DELETE/TRANSFER/IRREVERSIBLE requests after the fact. Found during the Jul 26 KYC E2E test (see below). Needs a real design: persist pending approvals to the DB, add an admin route to list/decide them. (Note: this is a *different* gap than F21's key-conflict admin UI, which is now built.)
- `portal/app.py`'s receipt detail view doesn't surface `identity_verified` (or any genuinely-computed verification field) — found during the F21 fix, portal has no F1-style verification surface at all today.
- `admin/app.py`'s `receive_receipt` runs `agent_id` through `sanitize_text(max_length=100)` before storing, same as `decision` — a second (safe-direction only) source of `identity_verified: false` false-negatives if `agent_id` is unusually long or contains `<`/`>`. Found during the F21 fix.
- Remaining Phase 2–4 of the security hardening plan (admin/portal bcrypt hardening, session revocation, rate-limit proxy trust, CSV injection, constant-time token compare, logout CSRF, cookie flags, timing-based enumeration, CI action pinning, infra details in tracked files) — see the plan file for the full task list.

---

## Development Workflow

### Local Development
```bash
cd ~/vaultra
source .venv/bin/activate
export $(cat .env | xargs)
python admin/app.py
```

### Deploy to Hetzner
Auto-deploys on push to `main` via GitHub Actions. Manual fallback:
```bash
ssh hetzner
cd /home/vaultra/app
git pull origin main
systemctl restart vaultra vaultra-portal
nginx -s reload
```

### Test SDK
```bash
source .venv/bin/activate
python3 -c "from vaultra import VaultraPipeline; print('OK')"
pytest tests/ -v
```

### Check Hetzner services
```bash
ssh hetzner "systemctl status vaultra vaultra-portal"
```

### Note on new terminals
A new shell needs NVM loaded and the npm-global PATH before `claude` works:
```bash
export NVM_DIR="$HOME/.nvm" && \. "$NVM_DIR/nvm.sh"
```
Already added permanently to `~/.zshrc`.

---

## How this project is run
`CLAUDE.md` (this file) is the bridge Claude Code reads automatically to execute complex tasks autonomously (SSH to Hetzner, multi-file edits, tests, commits, deploy).

Workflow: user gives instructions in chat → instructions get transcribed as a Claude Code prompt → Claude Code executes autonomously → user reports the result back in chat.

9 plugins installed in Claude Code: superpowers, frontend-design, playwright, ralph-loop, context7, supabase, code-review, security-guidance, claude-md-management. Plus the `gstack` skill pack (installed separately).

---

## Pending Tasks (Priority Order)

### ✅ Done (Aug 2, 2026)
- Security Hardening Phase 1 (F6, F14, F20, F22, F21 full fix, + the mid-fix guardian.py regex-corruption finding) — see Security section above for details. Merged to `main` locally (13 commits, 42/42 tests); **not yet pushed to origin** (push triggers Hetzner auto-deploy — needs explicit go-ahead).
- **Immediate next decision needed:** (a) push to origin/main to deploy Phase 1 to production, (b) whether to bump the SDK version (currently 2.0.2 published; F6/F22's fail-closed changes are user-visible behavior changes for existing integrators — plan's own Final Verification section flags this as a 2.0.3-vs-2.1.0 call) before the next PyPI publish, and (c) whether to continue directly into Phase 2 (admin/portal fixes) in a follow-up session.

### ✅ Done (Jul 26, 2026)
- Real end-to-end test with an external AI agent — built `demo_kyc_agent.py` (gitignored, distinct from `demo_credit_agent.py`), created a real test client + API key in the production DB, ran 5 cases against `admin.vaultra.io` live: normal approve, sanctions/watchlist reject, low document quality review, a genuine prompt-injection attempt (correctly **blocked by Layer 2**, no receipt generated, logged as `INJECTION_ATTEMPT`), and a GDPR Art. 17 erasure request (correctly **blocked by Layer 5 Human Gate** as a CRITICAL `DELETE` action, receipt generated in `pending` state at 6/7 layers). All 4 non-blocked receipts confirmed stamped (RFC 3161) and `status=valid` in the production `receipts` table. Surfaced one product gap — see "Human Gate approval flow is ephemeral" in Security findings above.

### 🟡 Important — next session
1. Push Phase 1 to origin/main (deploy to Hetzner) once ready, and decide the version bump before the next PyPI publish
2. Security Hardening Phase 2 — admin/portal backend fixes (bcrypt hardening, session revocation, rate-limit proxy trust, CSV injection, constant-time token compare) — see `docs/superpowers/plans/2026-07-27-vaultra-security-hardening.md`
3. Design + build a durable Human Gate approval flow (persist pending DELETE/TRANSFER/IRREVERSIBLE requests to DB, add admin.vaultra.io view to approve/reject) — gap found during the KYC E2E test, distinct from F21's key-conflict admin UI (already built)
4. Stripe — automated payments and subscriptions
5. Resend — transactional email (invitations, quota alerts)
6. Contact rUv (creator of Ruflo, github.com/ruvnet/ruflo, 64K stars) in English to explore an official `ruflo-vaultra` plugin — model: free/open-source plugin that connects to Vaultra's paid backend

### 🟢 Legal / Commercial
5. Letter to employer (Nebentätigkeit §2 authorization) — not expected to be a problem
6. Gewerbe registration (Finanzamt Rheine)
7. Organize a clean delivery folder with all final document versions
8. First outreach — 6 messages drafted (CTO/CCO/CEO × EN/ES), still need the Apollo.io list

### 🟢 Security audit — non-critical (see above section for details)

---

## Documents Generated (in outputs/, pending final folder organization)
- ✅ Vaultra_Risk_Analysis_v2_2_2026.pdf
- ✅ Vaultra_Business_Plan_v2_1_2026.pdf
- ✅ Vaultra_DPA_v1_2_2026.pdf
- ✅ Vaultra_Installation_Guide_2026.pdf
- ✅ Vaultra_Admin_User_Manual_2026.pdf

---

## Important Files
- admin/app.py — Flask backend, admin panel (main file, ~1100 lines)
- admin/templates/ — Jinja2 templates
- portal/app.py — Flask backend, client portal (app.vaultra.io)
- vaultra/pipeline.py — Main SDK pipeline (all 7 layers wired)
- vaultra/timestamper.py — RFC 3161 TSA integration
- vaultra/__init__.py — SDK exports (incl. `ComplianceViolation`)
- tests/test_pipeline_layers.py — 7-layer pipeline test suite
- pyproject.toml — PyPI package config (version 2.0.2)
- requirements.txt — Python dependencies

## Security Notes
- NEVER paste API keys or passwords in chat or commit them to this file
- Store secrets in `~/vaultra/.env` on Hetzner only
- Load with: `export $(cat .env | xargs)`
- Anthropic API keys: rotate immediately if exposed
- Admin password: rotated, stored in Bitwarden and `.env` (`ADMIN_PASSWORD`)
- PyPI token: needed to publish new versions — regenerate if expired
- GitHub PAT: rotated Jul 26, 2026, stored via macOS Keychain — do not embed tokens in the remote URL again
