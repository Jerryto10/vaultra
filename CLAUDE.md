# Vaultra — AI Agent Compliance Layer
## Project Context for Claude Code

### What is Vaultra?
B2B SaaS startup — AI Agent Compliance Layer for EU-regulated fintechs.
Generates cryptographic Compliance Receipts for every AI agent decision.
Founder: Jerly Rojas | Location: Rheine, Germany | hello@vaultra.io

### Core Value Proposition
"Compliance-as-a-Receipt" — cryptographic proof (not documentation) for every AI decision.
Targets EU fintechs needing compliance with EU AI Act Art. 12, GDPR Art. 22, eIDAS Art. 41, DORA.
Pricing: $299/mo (Starter) | $799/mo (Growth) | Custom (Enterprise)

---

## Architecture

### Infrastructure
- **Frontend:** Hetzner (178.104.86.252) → vaultra.io (Nginx)
- **Backend:** Hetzner CX12 (178.104.86.252) — Ubuntu 24.04, Nginx, Let's Encrypt
- **Database:** SQLite at /data/vaultra_admin.db (persistent)
- **DNS:** Cloudflare (SSL: Full Strict)
- **TSA:** Sectigo eIDAS QTSP — http://timestamp.sectigo.com/qualified
- **PyPI:** vaultra==2.0.0

### Key URLs
- vaultra.io — landing page
- admin.vaultra.io — admin panel (Flask + Gunicorn)
- vaultra.io/verify — public receipt verifier

### Repository
- GitHub: github.com/Jerryto10/vaultra
- Branch: main (auto-deploy via GitHub Actions — TODO)

---

## SDK — 7 Compliance Layers
| Layer | Module | Function |
|---|---|---|
| 1 | identity.py | Ed25519 cryptographic identity per agent |
| 2 | sanitizer.py | Input validation + prompt injection detection |
| 3 | ledger.py | Hash-chained audit ledger |
| 4 | guardian.py | ML-based output anomaly detection |
| 5 | human_gate.py | Authorization for irreversible actions |
| 6 | timestamper.py | RFC 3161 — Sectigo eIDAS QTSP |
| 7 | api_keys.py | SHA-256 hashed keys, instant revocation |

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

## Admin Panel
- **Framework:** Flask + Gunicorn (2 workers)
- **Auth:** bcrypt passwords, 30min session timeout, rate limiting (5 attempts/5min)
- **Routes:** 20+ routes — clients, receipts, audit log, settings, health check, reports
- **Reports:** PDF + CSV per client
- **Verifier:** Public API at /api/verify/<rid> (CORS enabled)

### Environment Variables (Hetzner)
- DB_PATH=/data/vaultra_admin.db
- SECRET_KEY=<from .env — required, app refuses to start without it>
- PORTAL_SECRET_KEY=<from .env — required, app refuses to start without it>
- ADMIN_PASSWORD=<from .env — never commit the actual value>
- SUPPORT_PASSWORD=<from .env — never commit the actual value>
- VAULTRA_TSA=sectigo ✅

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
```bash
# SSH to server
ssh root@178.104.86.252

# On server
cd /home/vaultra/app
git pull origin main
systemctl restart vaultra
```

### Test SDK
```bash
source .venv/bin/activate
python3 -c "from vaultra import VaultraPipeline; print('OK')"
```

### Check Hetzner service
```bash
ssh root@178.104.86.252 "systemctl status vaultra"
```

---

## Pending Tasks (Priority Order)
1. Implement Sectigo eIDAS timestamping from Hetzner backend
2. Migrate SQLite DB from Railway to Hetzner
3. Cancel Railway subscription
4. Setup GitHub Actions auto-deploy to Hetzner
5. Revert Cloudflare SSL to Full Strict + reactivate Bot Fight Mode
6. Remove /api/tsa-test endpoint (temporary diagnostic)
7. Update Risk Analysis v2.2
8. Update Business Plan v2.1
9. Update DPA v1.2 (Sectigo + Hetzner)
10. Create Installation Guide + Admin Manual
11. Update messaging (DigiCert → Sectigo eIDAS QTSP)
12. Carta al empleador (Nebentätigkeit §2)
13. Gewerbe registration
14. Stripe setup
15. First outreach (6 messages ready)

---

## Important Files
- admin/app.py — Flask backend (main file, ~1100 lines)
- admin/templates/ — Jinja2 templates
- vaultra/pipeline.py — Main SDK pipeline
- vaultra/timestamper.py — RFC 3161 TSA integration
- vaultra/__init__.py — SDK exports
- pyproject.toml — PyPI package config
- requirements.txt — Python dependencies
- Procfile — Gunicorn startup (legacy Railway)

## Security Notes
- NEVER paste API keys in chat
- Store secrets in ~/vaultra/.env
- Load with: export $(cat .env | xargs)
- Anthropic API keys: rotate immediately if exposed
- Admin password: in .env as ADMIN_PASSWORD
