# Copyright (c) 2026 Jerly Rojas
# Vaultra — AI Agent Compliance Layer
# https://vaultra.io
# AGPL-3.0 License. Commercial use: legal@vaultra.io

"""
pipeline.py — Vaultra Compliance Pipeline
==========================================
Integrates all 7 compliance layers and validates
the client API key against the Vaultra backend.

Usage:
    from vaultra import VaultraPipeline

    pipeline = VaultraPipeline(
        agent_id="credit-bot-v1",
        api_key="vaultra_sk_v1_...",
        scope="credit_decisions"
    )

    result = pipeline.process(input_data, agent_response)
    print(result.receipt_id)
"""

import os
import re
import hashlib
import json
import time
import uuid
import requests
from dataclasses import dataclass, field
from typing import Optional

from .identity import AgentIdentity
from .sanitizer import Sanitizer, Verdict
from .ledger import ProvenanceLedger, EventType
from .guardian import GuardianAgent, GuardVerdict
from .human_gate import HumanGate, ApprovalStatus
from .api_keys import KEY_PREFIX

# Vaultra backend URL
VAULTRA_API_URL = os.environ.get(
    "VAULTRA_API_URL",
    "https://admin.vaultra.io"
)


class ComplianceViolation(Exception):
    """Raised when Layer 2 (Sanitizer), Layer 4 (Guardian), or Layer 5 (Human
    Gate) hard-blocks a decision."""


# ── Result dataclass ──────────────────────────────────────
@dataclass
class ComplianceReceipt:
    receipt_id:     str
    agent_id:       str
    client_id:      str
    decision:       str
    decision_type:  str
    input_hash:     str
    block_number:   int
    rfc3161_ts:     Optional[str]
    regulation:     str
    timestamp_utc:  float
    layers_passed:  int
    api_validated:  bool
    identity_signature:   Optional[str] = None
    identity_fingerprint: Optional[str] = None
    sanitizer_verdict:    str = "unknown"
    sanitizer_score:      float = 0.0
    guardian_verdict:     str = "unknown"
    guardian_score:       float = 0.0
    ledger_block_hash:    Optional[str] = None
    human_gate_status:    str = "unknown"
    layer_status: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "receipt_id":    self.receipt_id,
            "agent_id":      self.agent_id,
            "client_id":     self.client_id,
            "decision":      self.decision,
            "decision_type": self.decision_type,
            "input_hash":    self.input_hash,
            "block_number":  self.block_number,
            "rfc3161_ts":    self.rfc3161_ts,
            "regulation":    self.regulation,
            "timestamp_utc": self.timestamp_utc,
            "layers_passed": self.layers_passed,
            "api_validated": self.api_validated,
            "identity_signature":   self.identity_signature,
            "identity_fingerprint": self.identity_fingerprint,
            "sanitizer_verdict":    self.sanitizer_verdict,
            "sanitizer_score":      self.sanitizer_score,
            "guardian_verdict":     self.guardian_verdict,
            "guardian_score":       self.guardian_score,
            "ledger_block_hash":    self.ledger_block_hash,
            "human_gate_status":    self.human_gate_status,
            "layer_status":         self.layer_status,
        }

    def summary(self) -> str:
        ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(self.timestamp_utc))
        return (
            f"Vaultra Compliance Receipt\n"
            f"  Receipt ID:    {self.receipt_id}\n"
            f"  Agent:         {self.agent_id}\n"
            f"  Decision:      {self.decision}\n"
            f"  Timestamp:     {ts}\n"
            f"  Block:         #{self.block_number}\n"
            f"  RFC 3161:      {'Stamped' if self.rfc3161_ts else 'Pending'}\n"
            f"  Layers passed: {self.layers_passed}/7\n"
            f"  API validated: {'Yes' if self.api_validated else 'Offline mode'}\n"
            f"  Sanitizer:     {self.sanitizer_verdict} (score={self.sanitizer_score:.3f})\n"
            f"  Guardian:      {self.guardian_verdict} (score={self.guardian_score:.3f})\n"
            f"  Human Gate:    {self.human_gate_status}\n"
        )


# ── Main Pipeline ─────────────────────────────────────────
class VaultraPipeline:
    """
    Main Vaultra compliance pipeline.
    Validates API key, runs all 7 layers, generates receipt.
    """

    def __init__(
        self,
        agent_id: str,
        api_key: str,
        scope: str = "general",
        regulation: str = "EU AI Act",
        offline_mode: bool = False,
        ledger_db_path: str = "vaultra_ledger.db",
    ):
        # Validate agent_id format (R-16)
        self._validate_agent_id(agent_id)

        self.agent_id   = agent_id
        self.api_key    = api_key
        self.scope      = scope
        self.regulation = regulation
        self.offline    = offline_mode
        self._explicit_offline = offline_mode
        self.client_id  = None
        self.plan       = None
        self._block_num = 1000 + int(time.time()) % 9000

        # Validate API key on initialization
        self._validate_api_key()

        # Layer 1 — Ed25519 identity, one keypair per agent instance
        self._identity = AgentIdentity(agent_id)

        # Layer 2 — Injection detection (pattern + heuristic + ML ensemble)
        self._sanitizer = Sanitizer()

        # Layer 3 — Hash-chained audit ledger
        self._ledger = ProvenanceLedger(db_path=ledger_db_path)

        # Layer 4 — Output guardian; falls back to offline heuristics on its
        # own if ANTHROPIC_API_KEY isn't set
        self._guardian = GuardianAgent(prefer_online=True)

        # Layer 5 — Human approval gate for irreversible actions
        self._human_gate = HumanGate()

        print(f"[Vaultra] Pipeline initialized | Agent: {agent_id} | Scope: {scope}")

    def _validate_agent_id(self, agent_id: str):
        """
        Validate agent_id format — R-16 compliance requirement.

        Rules:
        - Must be a non-empty string
        - 3-64 characters long
        - Only letters, numbers, hyphens, underscores, dots
        - Must start with a letter or number
        - Cannot contain spaces or special characters

        A valid agent_id ensures the audit trail is legally
        identifiable and auditor-readable under EU AI Act Art. 12.

        Examples:
            Valid:   "credit-bot-v1", "kyc_agent_2026", "fraud.detector.v2"
            Invalid: "", "my agent", "bot??", "a" (too short)
        """
        if not agent_id:
            raise ValueError(
                "[Vaultra] agent_id cannot be empty. "
                "Use a descriptive name like 'credit-bot-v1' or 'kyc-agent'."
            )

        if not isinstance(agent_id, str):
            raise TypeError(
                f"[Vaultra] agent_id must be a string, got {type(agent_id).__name__}."
            )

        if len(agent_id) < 3:
            raise ValueError(
                f"[Vaultra] agent_id '{agent_id}' is too short (minimum 3 characters). "
                "Use a descriptive name like 'credit-bot-v1'."
            )

        if len(agent_id) > 64:
            raise ValueError(
                f"[Vaultra] agent_id is too long (maximum 64 characters). "
                f"Current length: {len(agent_id)}."
            )

        pattern = r'^[a-zA-Z0-9][a-zA-Z0-9\-_\.]*[a-zA-Z0-9]$|^[a-zA-Z0-9]{3}$'
        if not re.match(pattern, agent_id):
            raise ValueError(
                f"[Vaultra] agent_id '{agent_id}' contains invalid characters. "
                "Only letters, numbers, hyphens (-), underscores (_), and dots (.) are allowed. "
                "Must start and end with a letter or number. "
                "Example: 'credit-bot-v1'"
            )

        # Reserved names check
        reserved = {"test", "demo", "debug", "vaultra", "admin", "system", "root"}
        if agent_id.lower() in reserved:
            raise ValueError(
                f"[Vaultra] agent_id '{agent_id}' is a reserved name. "
                "Use a specific name like 'credit-bot-v1' or 'kyc-agent-prod'."
            )

    def _validate_api_key(self):
        """Validate API key against Vaultra backend."""
        if self.offline:
            print("[Vaultra] Offline mode — skipping API key validation")
            return

        try:
            resp = requests.post(
                f"{VAULTRA_API_URL}/api/validate-key",
                json={"api_key": self.api_key},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("valid"):
                    self.client_id = data["client_id"]
                    self.plan      = data["plan"]
                    print(f"[Vaultra] API key validated | Client: {data['company_name']} | Plan: {self.plan}")
                    return
                else:
                    raise ValueError(f"Invalid API key: {data.get('error', 'Unknown error')}")
            elif resp.status_code == 401:
                raise ValueError("Invalid API key — please check your vaultra_sk_v1_... key")
            elif resp.status_code == 403:
                raise ValueError(f"Account issue: {resp.json().get('error', 'Contact hello@vaultra.io')}")
            else:
                print(f"[Vaultra] Warning: Could not validate API key (HTTP {resp.status_code}) — running in offline mode")
                self.offline = True

        except requests.exceptions.ConnectionError:
            print("[Vaultra] Warning: Cannot reach Vaultra API — running in offline mode")
            self.offline = True
        except requests.exceptions.Timeout:
            print("[Vaultra] Warning: Vaultra API timeout — running in offline mode")
            self.offline = True
        except ValueError:
            raise  # Re-raise auth errors

    def _hash_input(self, input_data) -> str:
        """SHA-256 hash of the input data."""
        if isinstance(input_data, dict):
            content = json.dumps(input_data, sort_keys=True)
        else:
            content = str(input_data)
        return hashlib.sha256(content.encode()).hexdigest()

    def _get_rfc3161_timestamp(self, content: str) -> Optional[str]:
        """Get RFC 3161 timestamp for the receipt."""
        try:
            from vaultra.timestamper import stamp
            result = stamp(content)
            if result.success:
                return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(result.timestamp_utc))
        except Exception as e:
            print(f"[Vaultra] Timestamping warning: {e}")
        return None

    def _record_ledger_event(
        self, event_type, input_str, fingerprint, layer1_passed,
        sanitize_result, decision_type, metadata=None,
    ):
        """Best-effort ledger write for a blocked decision. Never raises."""
        try:
            self._ledger.record(
                event_type=event_type,
                agent_id=self.agent_id,
                agent_fingerprint=fingerprint or "unknown",
                action=decision_type,
                content=input_str,
                layer1_passed=bool(layer1_passed),
                layer2_score=sanitize_result.score if sanitize_result else 0.0,
                layer2_verdict=sanitize_result.verdict.value if sanitize_result else "unknown",
                layer2_triggers=sanitize_result.triggers if sanitize_result else [],
                metadata=metadata or {},
            )
        except Exception as e:
            print(f"[Vaultra] Layer 3 (Ledger) warning: could not record blocked event: {e}")

    def _send_receipt(self, receipt: ComplianceReceipt):
        """Send receipt metadata to Vaultra backend."""
        if self.offline:
            return
        try:
            requests.post(
                f"{VAULTRA_API_URL}/api/receipt",
                json={
                    "api_key":       self.api_key,
                    "agent_id":      receipt.agent_id,
                    "decision":      receipt.decision,
                    "decision_type": receipt.decision_type,
                    "input_hash":    receipt.input_hash,
                    "block_number":  receipt.block_number,
                    "rfc3161_ts":    receipt.rfc3161_ts,
                    "regulation":    receipt.regulation,
                },
                timeout=8,
            )
        except Exception:
            pass  # Non-blocking — receipt is still valid locally

    def process(
        self,
        input_data,
        agent_response: str,
        decision_type: str = "DECISION",
        regulation: Optional[str] = None,
    ) -> ComplianceReceipt:
        """
        Process an AI agent decision through all 7 compliance layers.

        Args:
            input_data:      The input to the AI agent (dict or string)
            agent_response:  The agent's response/decision (string)
            decision_type:   Type of decision (LOAN_APPROVED, KYC_APPROVED, etc.)
            regulation:      Override regulation (default: self.regulation)

        Returns:
            ComplianceReceipt with all compliance metadata

        Raises:
            ComplianceViolation: Layer 2 detected a prompt injection in the
                input, Layer 4 (Guardian) blocked the agent's output, or
                Layer 5 (Human Gate) held an irreversible action that was not
                approved (status is not APPROVED/BYPASSED).
        """
        input_hash = self._hash_input(input_data)
        input_str  = str(input_data)
        self._block_num += 1
        reg = regulation or self.regulation
        layer_status = {}

        # ── Layer 1 — Identity: sign the decision payload ──
        signable = {
            "agent_id":      self.agent_id,
            "input_hash":    input_hash,
            "decision":      agent_response,
            "decision_type": decision_type,
            "block":         self._block_num,
        }
        identity_signature   = None
        identity_fingerprint = None
        try:
            identity_signature   = self._identity.sign(signable).hex()
            identity_fingerprint = self._identity.fingerprint()
            layer_status["identity"] = True
        except Exception as e:
            print(f"[Vaultra] Layer 1 (Identity) warning: {e}")
            layer_status["identity"] = False

        # ── Layer 2 — Sanitizer: block on confirmed prompt injection ──
        sanitize_result = None
        try:
            sanitize_result = self._sanitizer.analyze(input_str)
            layer_status["sanitizer"] = sanitize_result.verdict != Verdict.INJECTION
        except Exception as e:
            print(f"[Vaultra] Layer 2 (Sanitizer) warning: {e}")
            layer_status["sanitizer"] = False

        if sanitize_result is not None and sanitize_result.verdict == Verdict.INJECTION:
            self._record_ledger_event(
                EventType.INJECTION_ATTEMPT, input_str, identity_fingerprint,
                layer_status["identity"], sanitize_result, decision_type,
            )
            raise ComplianceViolation(
                f"BLOCKED — prompt injection detected in input "
                f"(score={sanitize_result.score:.3f}, triggers={sanitize_result.triggers})"
            )

        # ── Layer 4 — Guardian: evaluate the agent's output ──
        guardian_result = None
        try:
            guardian_result = self._guardian.evaluate(
                agent_purpose=f"{self.agent_id} — {self.scope}",
                agent_scope=[self.scope],
                input_text=input_str,
                output_text=agent_response,
            )
            layer_status["guardian"] = guardian_result.verdict != GuardVerdict.BLOCKED
        except Exception as e:
            print(f"[Vaultra] Layer 4 (Guardian) warning: {e}")
            layer_status["guardian"] = False

        if guardian_result is not None and guardian_result.verdict == GuardVerdict.BLOCKED:
            self._record_ledger_event(
                EventType.MESSAGE_BLOCKED, input_str, identity_fingerprint,
                layer_status["identity"], sanitize_result, decision_type,
                metadata={"guardian": guardian_result.to_dict()},
            )
            raise ComplianceViolation(
                f"BLOCKED — Guardian flagged output as unsafe "
                f"(score={guardian_result.score:.3f}, risks={guardian_result.risks_detected})"
            )

        # ── Layer 5 — Human Gate: only gate irreversible/destructive decisions ──
        decision_upper = decision_type.upper()
        if "TRANSFER" in decision_upper:
            gate_action = "transfer_funds"
        elif "DELETE" in decision_upper:
            gate_action = "delete"
        elif "IRREVERSIBLE" in decision_upper:
            gate_action = "modify_config"
        else:
            gate_action = "analyze"

        human_gate_status = None
        try:
            approval = self._human_gate.intercept(
                agent_id=self.agent_id,
                agent_name=self.agent_id,
                action=gate_action,
                context={"decision_type": decision_type, "decision": agent_response[:200]},
                summary=f"{decision_type} decision by {self.agent_id}",
                guardian_verdict=guardian_result.verdict.value if guardian_result else None,
            )
            human_gate_status = approval.status
            layer_status["human_gate"] = approval.status in (
                ApprovalStatus.BYPASSED, ApprovalStatus.APPROVED,
            )
        except Exception as e:
            print(f"[Vaultra] Layer 5 (Human Gate) warning: {e}")
            layer_status["human_gate"] = False

        if human_gate_status is not None and human_gate_status not in (
            ApprovalStatus.APPROVED, ApprovalStatus.BYPASSED,
        ):
            self._record_ledger_event(
                EventType.MESSAGE_BLOCKED, input_str, identity_fingerprint,
                layer_status["identity"], sanitize_result, decision_type,
                metadata={"human_gate_status": human_gate_status.value},
            )
            raise ComplianceViolation(
                f"BLOCKED — Human Gate requires human approval for irreversible action "
                f"(status={human_gate_status.value}, action={gate_action})"
            )

        # ── Layer 3 — Ledger: record the decision with layer 1/2/4/5 context ──
        ledger_block_hash = None
        try:
            entry = self._ledger.record(
                event_type=EventType.MESSAGE_ALLOWED,
                agent_id=self.agent_id,
                agent_fingerprint=identity_fingerprint or "unknown",
                action=decision_type,
                content=input_str,
                layer1_passed=layer_status["identity"],
                layer2_score=sanitize_result.score if sanitize_result else 0.0,
                layer2_verdict=sanitize_result.verdict.value if sanitize_result else "unknown",
                layer2_triggers=sanitize_result.triggers if sanitize_result else [],
                metadata={
                    "guardian_verdict":  guardian_result.verdict.value if guardian_result else "unknown",
                    "guardian_score":    guardian_result.score if guardian_result else 0.0,
                    "human_gate_status": human_gate_status.value if human_gate_status else "unknown",
                },
            )
            ledger_block_hash = entry.block_hash
            layer_status["ledger"] = True
        except Exception as e:
            print(f"[Vaultra] Layer 3 (Ledger) warning: {e}")
            layer_status["ledger"] = False

        # ── Layer 6 — RFC 3161 Timestamp ──
        receipt_content = json.dumps({
            "agent_id":      self.agent_id,
            "input_hash":    input_hash,
            "decision":      agent_response,
            "decision_type": decision_type,
            "block":         self._block_num,
            "timestamp":     time.time(),
        }, sort_keys=True)

        rfc3161_ts = self._get_rfc3161_timestamp(receipt_content)
        layer_status["timestamp"] = rfc3161_ts is not None

        # ── Layer 7 — API Keys: reflects the real remote validation outcome ──
        layer_status["api_keys"] = bool(
            self.api_key and self.api_key.startswith(KEY_PREFIX)
            and (self.client_id is not None or self._explicit_offline)
        )

        layers_passed = sum(1 for passed in layer_status.values() if passed)

        # Build receipt
        receipt = ComplianceReceipt(
            receipt_id    = f"VLT-{uuid.uuid4().hex[:8]}",
            agent_id      = self.agent_id,
            client_id     = self.client_id or "offline",
            decision      = agent_response,
            decision_type = decision_type,
            input_hash    = input_hash,
            block_number  = self._block_num,
            rfc3161_ts    = rfc3161_ts,
            regulation    = reg,
            timestamp_utc = time.time(),
            layers_passed = layers_passed,
            api_validated = not self.offline,
            identity_signature   = identity_signature,
            identity_fingerprint = identity_fingerprint,
            sanitizer_verdict    = sanitize_result.verdict.value if sanitize_result else "unknown",
            sanitizer_score      = sanitize_result.score if sanitize_result else 0.0,
            guardian_verdict     = guardian_result.verdict.value if guardian_result else "unknown",
            guardian_score       = guardian_result.score if guardian_result else 0.0,
            ledger_block_hash    = ledger_block_hash,
            human_gate_status    = human_gate_status.value if human_gate_status else "unknown",
            layer_status         = layer_status,
        )

        # Send to Vaultra backend (non-blocking)
        self._send_receipt(receipt)

        print(f"[Vaultra] Receipt generated: {receipt.receipt_id} | {decision_type} | {layers_passed}/7 layers")
        return receipt


# ── Quick test ────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 55)
    print("Vaultra Pipeline — Integration Test")
    print("=" * 55)

    # Test in offline mode (no API key needed)
    pipeline = VaultraPipeline(
        agent_id="credit-bot-test",
        api_key="vaultra_sk_v1_test",
        scope="credit_decisions",
        offline_mode=True,
        ledger_db_path=":memory:",
    )

    result = pipeline.process(
        input_data={"customer_id": "C-1234", "credit_score": 612, "amount": 5000},
        agent_response="REJECT loan application — score below threshold",
        decision_type="LOAN_REJECTED",
        regulation="EU AI Act",
    )

    print("\n" + result.summary())
    print("\nFull receipt dict:")
    import json
    print(json.dumps(result.to_dict(), indent=2))
