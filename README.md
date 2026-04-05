# Vaultra — AI Agent Compliance Layer

> **The compliance black box for AI agents.**  
> Cryptographically signed, immutable, auditor-ready evidence for every AI decision.

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Website](https://img.shields.io/badge/website-vaultra.io-green.svg)](https://vaultra.io)
[![RFC 3161](https://img.shields.io/badge/timestamp-RFC%203161%20%2F%20eIDAS-gold.svg)](https://vaultra.io)

---

## The Problem

When your AI agent rejects a loan, flags a transaction, or makes a critical decision — **can you prove to a regulator exactly what happened, why, and that nobody altered it?**

Under the EU AI Act (enforcement August 2026), GDPR Art. 22, and Colorado SB 24-205, companies deploying AI in high-risk domains must demonstrate:

- ✅ What the agent decided, and when
- ✅ What data it used
- ✅ What logic it followed
- ✅ That the record was not tampered with
- ✅ That a human reviewed critical decisions (when required)
- ✅ That an independent authority certified the timestamp — **not just Vaultra**

Most companies can't. Vaultra solves this.

---

## What Vaultra Does

Vaultra is a **7-layer security and compliance framework** for AI agents that generates a **Compliance Receipt** — a cryptographically signed, RFC 3161 timestamped, tamper-proof record — for every agent decision.

```
┌─────────────────────────────────────────────────────┐
│             VAULTRA COMPLIANCE RECEIPT               │
├─────────────────────────────────────────────────────┤
│  Agent:       CreditBot v2.3                        │
│  Decision:    REJECT loan application #4821         │
│  Timestamp:   2026-03-08 18:10:15 UTC               │
│  Input hash:  a3f9c2d1... (verifiable)              │
│  Reasoning:   score=612 < threshold=650             │
│  Scope:       credit_decisions (authorized)         │
│  Human gate:  Not required (auto-decision)          │
│  Chain:       Block #1847 — integrity ✅            │
│  RFC 3161:    Token signed by freetsa.org ✅        │
│  Legal basis: eIDAS Regulation (EU) No 910/2014 ✅  │
│  Compliance:  EU AI Act Art. 13 ✅                  │
│               GDPR Art. 22 ✅                       │
└─────────────────────────────────────────────────────┘
```

---

## Architecture — 7 Compliance Layers

| Layer | Module | Function |
|-------|--------|----------|
| 1 — Identity | `identity.py` | Ed25519 cryptographic identity per agent |
| 2 — Sanitizer | `sanitizer.py` | Input validation + prompt injection detection |
| 3 — Ledger | `ledger.py` | Immutable blockchain-lite audit chain (SQLite) |
| 4 — Guardian | `guardian.py` | ML-based output anomaly detection |
| 5 — Human Gate | `human_gate.py` | Authorization control for irreversible actions |
| 6 — Timestamper | `timestamper.py` | **RFC 3161 trusted timestamp — eIDAS legal standard** |
| 7 — API Keys | `api_keys.py` | **Client authentication — cryptographic keys, never stored in plain text** |

### Layer 6 — RFC 3161 Trusted Timestamping

Layer 6 is what makes Vaultra's receipts **legally unbreakable** — even by Vaultra itself.

Every Compliance Receipt is hashed and submitted to a Trusted Timestamp Authority (TSA). The TSA returns a cryptographically signed token that proves — to any auditor or regulator — that the receipt existed at a specific moment in time and has not been modified since.

- **Standard:** RFC 3161 — Internet X.509 PKI Time Stamp Protocol
- **Legal basis:** eIDAS Regulation (EU) No 910/2014, Article 41
- **TSA (MVP):** freetsa.org (public, free)
- **TSA (Production):** DigiCert / Comodo (~$100–$300/year)
- **Verification:** Any auditor can independently verify the token — no trust in Vaultra required

```python
from vaultra.timestamper import stamp

# Timestamp a Compliance Receipt
result = stamp(receipt_json)
# result.tsr_token_b64  → signed token from TSA
# result.timestamp_utc  → exact moment certified by independent authority
# result.receipt_hash   → SHA-256 hash locked by the token
```

---

## Quick Start

```bash
pip install vaultra
```

```python
from vaultra import VaultraPipeline

# 3-line integration
pipeline = VaultraPipeline(
    agent_id="credit-bot-v2",
    api_key="vaultra_sk_v1_...",   # Get your key at vaultra.io
    scope="credit_decisions"
)
result = pipeline.process(input_data, agent_response)
print(result.summary())  # Signed, RFC 3161 timestamped, auditor-ready
```

## API Endpoints

Vaultra exposes a REST API for SDK integration:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/validate-key` | POST | Validate client API key |
| `/api/receipt` | POST | Register a Compliance Receipt |
| `/health` | GET | Service health check |

## Admin Panel

Vaultra operators manage clients and receipts at **admin.vaultra.io**:
- Create and manage client API keys
- View all Compliance Receipts across clients
- Archive clients (data preserved for audit trail)
- Full audit log of all admin actions
- Session timeout and secure logout

---

## Regulatory Coverage

| Regulation | Articles Covered | Status |
|------------|-----------------|--------|
| EU AI Act | Art. 13 (Transparency), Art. 14 (Human Oversight), Art. 17 (QMS) | ✅ |
| GDPR | Art. 22 (Automated Decision-Making) | ✅ |
| eIDAS | Regulation (EU) No 910/2014, Art. 41 (Trusted Timestamps) | ✅ |
| Colorado SB 24-205 | AI lending decision disclosure | ✅ |
| DORA | Operational resilience logging | 🔄 In progress |

---

## Who Is This For

- **Fintechs** deploying AI for credit scoring, fraud detection, KYC
- **Any company** using AI agents in regulated decision-making
- **Developers** who need to prove their AI is compliant — not just claim it

---

## License

Vaultra is open source under [AGPL-3.0](LICENSE).

**Commercial use without publishing modifications requires a commercial license.**  
Contact: legal@vaultra.io

---

## About

Built by [Jerly Rojas](https://vaultra.io) — solving the AI compliance gap for companies that can't afford €100,000/year enterprise tools but still face €35M fines.

**Website:** https://vaultra.io  
**Contact:** hello@vaultra.io  

---

*Copyright (c) 2026 Jerly Rojas — Vaultra (https://vaultra.io)*
