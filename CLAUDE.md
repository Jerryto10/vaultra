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
- GitHub PAT: rotation was requested — **verify with `git push origin main --dry-run` before assuming it's done**

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

### Pending manual verification
- ⚠️ Confirm GitHub PAT rotation didn't break push (`git push origin main --dry-run`)
- ⚠️ Decide whether to scrub git history (old password was once exposed in a public repo in this file)

### Non-critical findings (medium/low priority, not yet fixed)
- Ledger hash chain has no lock under concurrency (possible fork under high load)
- No retry logic on HTTP calls to the TSA
- CSV formula injection — partially mitigated by `sanitize_text`, needs review
- Future migration SQLite → PostgreSQL/Supabase when volume grows
- No MFA/2FA
- Audit log capped at 200 rows, no pagination
- Stale "DigiCert" branding in some admin templates and `health_check.html` (references retired infra)
- No Playwright E2E tests yet

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

### 🔴 Immediate
1. Confirm GitHub PAT rotation succeeded (push still works)
2. Decide on git history cleanup (old exposed password)

### 🟡 Important — next session
3. Stripe — automated payments and subscriptions
4. Resend — transactional email (invitations, quota alerts)
5. Real end-to-end test with an external AI agent (recommended: a simple KYC agent, different from the already-used `demo_credit_agent`)
6. Contact rUv (creator of Ruflo, github.com/ruvnet/ruflo, 64K stars) in English to explore an official `ruflo-vaultra` plugin — model: free/open-source plugin that connects to Vaultra's paid backend

### 🟢 Legal / Commercial
7. Letter to employer (Nebentätigkeit §2 authorization) — not expected to be a problem
8. Gewerbe registration (Finanzamt Rheine)
9. Organize a clean delivery folder with all final document versions
10. First outreach — 6 messages drafted (CTO/CCO/CEO × EN/ES), still need the Apollo.io list

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
- GitHub PAT: rotation in progress — verify before relying on it
