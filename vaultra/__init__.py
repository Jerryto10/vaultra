# Copyright (c) 2026 Jerly Rojas
# Vaultra — AI Agent Compliance Layer
# https://vaultra.io
#
# Este software está protegido bajo licencia AGPL-3.0.
# Para uso comercial sin publicar modificaciones,
# contacta: legal@vaultra.io
#
# This software is protected under the AGPL-3.0 license.
# For commercial use without publishing modifications,
# contact: legal@vaultra.io
# -------------------------------------------------------
"""
Vaultra — AI Agent Compliance Layer

A 7-layer compliance SDK that wraps any AI agent and generates
cryptographically signed, RFC 3161 timestamped, auditor-ready
Compliance Receipts for every AI decision.

Quick start:
    from vaultra import VaultraPipeline
    pipeline = VaultraPipeline(agent_id="my-agent", api_key="vaultra_sk_v1_...")
    receipt = pipeline.process(input_data, agent_response)
"""

# Primary — developer-facing API (3-line integration)
from .pipeline import VaultraPipeline, ComplianceReceipt

# Layer 1 — Cryptographic identity
from .identity import AgentIdentity

# Layer 2 — Input sanitization
from .sanitizer import Sanitizer, SanitizeResult, Verdict

# Layer 3 — Audit ledger
from .ledger import ProvenanceLedger, ProvenanceEntry, EventType, RiskLevel

# Layer 4 — Output guardian
from .guardian import GuardianAgent, GuardianResult, GuardVerdict

# Layer 5 — Human oversight gate
from .human_gate import HumanGate, ApprovalRequest, ActionRisk, ApprovalStatus

# Layer 6 — RFC 3161 timestamping (DigiCert)
from .timestamper import stamp, verify_hash, TimestampResult

# Layer 7 — API key management
from .api_keys import APIKeyManager, ClientRecord

__version__ = "2.0.0"
__author__ = "Jerly Rojas"
__license__ = "AGPL-3.0"

__all__ = [
    # Primary
    "VaultraPipeline",
    "ComplianceReceipt",
    # Layer 1
    "AgentIdentity",
    # Layer 2
    "Sanitizer",
    "SanitizeResult",
    "Verdict",
    # Layer 3
    "ProvenanceLedger",
    "ProvenanceEntry",
    "EventType",
    "RiskLevel",
    # Layer 4
    "GuardianAgent",
    "GuardianResult",
    "GuardVerdict",
    # Layer 5
    "HumanGate",
    "ApprovalRequest",
    "ActionRisk",
    "ApprovalStatus",
    # Layer 6
    "stamp",
    "verify_hash",
    "TimestampResult",
    # Layer 7
    "APIKeyManager",
    "ClientRecord",
]
