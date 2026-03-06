[README.md](https://github.com/user-attachments/files/25801277/README.md)
# Vaultra — AI Agent Compliance Layer

> **The compliance black box for AI agents.**  
> Cryptographically signed, immutable, auditor-ready evidence for every AI decision.

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Website](https://img.shields.io/badge/website-vaultra.io-green.svg)](https://vaultra.io)

---

## The Problem

When your AI agent rejects a loan, flags a transaction, or makes a critical decision — **can you prove to a regulator exactly what happened, why, and that nobody altered it?**

Under the EU AI Act (enforcement August 2026), GDPR Art. 22, and Colorado SB 24-205, companies deploying AI in high-risk domains must demonstrate:

- ✅ What the agent decided, and when
- ✅ What data it used
- ✅ What logic it followed
- ✅ That the record was not tampered with
- ✅ That a human reviewed critical decisions (when required)

Most companies can't. Vaultra solves this.

---

## What Vaultra Does

Vaultra is a **5-layer security and compliance framework** for AI agents that generates a **Compliance Receipt** — a cryptographically signed, tamper-proof record — for every agent decision.

```
┌─────────────────────────────────────────────────┐
│           VAULTRA COMPLIANCE RECEIPT             │
├─────────────────────────────────────────────────┤
│  Agent:       CreditBot v2.3                    │
│  Decision:    REJECT loan application #4821     │
│  Timestamp:   2026-03-06 14:47:23 UTC           │
│  Input hash:  a3f9c2d1... (verifiable)          │
│  Reasoning:   score=612 < threshold=650         │
│  Scope:       credit_decisions (authorized)     │
│  Human gate:  Not required (auto-decision)      │
│  Chain:       Block #1847 — integrity ✅        │
│  Compliance:  EU AI Act Art. 13 ✅              │
│               GDPR Art. 22 ✅                   │
└─────────────────────────────────────────────────┘
```

---

## Architecture — 5 Security Layers

| Layer | Module | Function |
|-------|--------|----------|
| 1 — Identity | `identity.py` | Ed25519 cryptographic identity per agent |
| 2 — Sanitizer | `sanitizer.py` | Input validation + prompt injection detection |
| 3 — Ledger | `ledger.py` | Immutable blockchain-lite audit chain (SQLite) |
| 4 — Guardian | `guardian.py` | ML-based output anomaly detection |
| 5 — Human Gate | `human_gate.py` | Authorization control for irreversible actions |

---

## Quick Start

```bash
pip install vaultra
```

```python
from vaultra import VaultraPipeline

# 3-line integration
pipeline = VaultraPipeline(agent_id="credit-bot-v2", scope="credit_decisions")
result = pipeline.process(input_data, agent_response)
receipt = result.compliance_receipt  # Signed, immutable, auditor-ready
```

---

## Regulatory Coverage

| Regulation | Articles Covered | Status |
|------------|-----------------|--------|
| EU AI Act | Art. 13 (Transparency), Art. 14 (Human Oversight), Art. 17 (QMS) | ✅ |
| GDPR | Art. 22 (Automated Decision-Making) | ✅ |
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

Built by [Jerly Rojas](https://vaultra.io) — solving the AI compliance gap for companies that can't afford €50,000/year enterprise tools but still face €35M fines.

**Website:** https://vaultra.io  
**Contact:** hello@vaultra.io  

---

*Copyright (c) 2026 Jerly Rojas — Vaultra (https://vaultra.io)*
