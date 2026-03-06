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
AgentShield - Pipeline FINAL: Capas 1 + 2 + 3 + 4 + 5
========================================================
Flujo completo:
  1. Capa 1 → Identidad criptográfica y scope
  2. Capa 2 → Sanitizar INPUT (prompt injection)
  3. Capa 3 → Registrar en ledger inmutable
  4. Capa 4 → Guardian evalúa OUTPUT
  5. Capa 5 → Human Gate para acciones irreversibles
"""

import sys
sys.path.insert(0, '/home/claude/agentshield')

from agentshield.identity   import Agent, AgentRegistry, AgentScope, SignedMessage
from agentshield.sanitizer  import Sanitizer, SanitizeResult
from agentshield.ledger     import ProvenanceLedger, EventType
from agentshield.guardian   import GuardianAgent, GuardianResult
from agentshield.human_gate import HumanGate, ApprovalRequest, ApprovalStatus, classify_action, ActionRisk

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PipelineResult:
    allowed:            bool
    layer1_passed:      bool
    layer2_result:      Optional[SanitizeResult]
    layer4_result:      Optional[GuardianResult]
    layer5_request:     Optional[ApprovalRequest]
    ledger_entry_id:    Optional[str]
    rejection_reason:   Optional[str]

    @property
    def requires_human_approval(self) -> bool:
        return (
            self.layer5_request is not None and
            self.layer5_request.status == ApprovalStatus.PENDING
        )

    def __str__(self) -> str:
        if self.requires_human_approval:
            icon, status = "⏳", "EN ESPERA DE APROBACIÓN HUMANA"
        elif self.allowed:
            icon, status = "✅", "PERMITIDO"
        else:
            icon, status = "🚨", "BLOQUEADO"

        out = f"{icon} [{status}]"
        if self.rejection_reason:
            out += f"
   Razón: {self.rejection_reason}"
        if self.layer2_result:
            r = self.layer2_result
            out += f"
   Capa 2 → score={r.score:.3f} | {r.verdict.value}"
        if self.layer4_result:
            g = self.layer4_result
            out += f"
   Capa 4 → score={g.score:.3f} | {g.verdict.value} [{g.mode}]"
        if self.layer5_request:
            req = self.layer5_request
            out += f"
   Capa 5 → {req.status.value} | risk={req.risk_level.value} | token={req.approval_token[:12]}..."
        if self.ledger_entry_id:
            out += f"
   Ledger → {self.ledger_entry_id[:8]}..."
        return out


class AgentShieldPipeline:
    """Pipeline completo de AgentShield — 5 capas de seguridad."""

    def __init__(self, db_path: str = ":memory:", guardian_online: bool = False):
        self.registry  = AgentRegistry()
        self.sanitizer = Sanitizer()
        self.ledger    = ProvenanceLedger(db_path)
        self.guardian  = GuardianAgent(prefer_online=guardian_online)
        self.gate      = HumanGate()
        self._agents: dict[str, Agent] = {}  # Guardamos referencia por nombre

    def add_notifier(self, notifier) -> "AgentShieldPipeline":
        """Configura canales de notificación del Human Gate."""
        self.gate.add_notifier(notifier)
        return self

    def register_agent(self, agent: Agent) -> None:
        identity = agent.export_public_identity()
        self.registry.register(identity)
        self._agents[agent.agent_id] = agent
        self.ledger.record(
            event_type=EventType.AGENT_REGISTERED,
            agent_id=identity.agent_id,
            agent_fingerprint=identity.fingerprint(),
            action="register",
            content="Agent registered",
            layer1_passed=True,
        )

    def revoke_agent(self, agent_id: str, reason: str) -> None:
        identity = self.registry.get_identity(agent_id)
        self.registry.revoke(agent_id, reason)
        self.ledger.record(
            event_type=EventType.AGENT_REVOKED,
            agent_id=agent_id,
            agent_fingerprint=identity.fingerprint() if identity else "unknown",
            action="revoke", content=reason,
            layer1_passed=False,
            metadata={"reason": reason},
        )

    def process(
        self,
        message:      SignedMessage,
        agent_output: str = "",
        agent_name:   str = "Unknown",
    ) -> PipelineResult:
        """
        Procesa un mensaje a través de las 5 capas.
        agent_output: respuesta/acción que el agente quiere ejecutar
        """
        identity    = self.registry.get_identity(message.agent_id)
        fingerprint = identity.fingerprint() if identity else "unknown"
        action      = message.payload.get("action", "unknown")
        content     = self._extract_text(message)

        # ── CAPA 1: Identidad ──
        layer1_ok = self.registry.verify(message)
        if not layer1_ok:
            event = EventType.TAMPERING_ATTEMPT if not identity else EventType.AGENT_REVOKED
            entry = self.ledger.record(
                event_type=event, agent_id=message.agent_id,
                agent_fingerprint=fingerprint, action=action,
                content=content, layer1_passed=False,
            )
            return PipelineResult(
                allowed=False, layer1_passed=False,
                layer2_result=None, layer4_result=None, layer5_request=None,
                ledger_entry_id=entry.entry_id,
                rejection_reason=f"Capa 1: {event.value}",
            )

        # ── CAPA 2: Sanitización del input ──
        layer2       = self.sanitizer.analyze(content)
        is_injection = not layer2.is_safe
        event = (
            EventType.INJECTION_ATTEMPT if (is_injection and layer2.score >= 0.6)
            else EventType.MESSAGE_BLOCKED if is_injection
            else EventType.MESSAGE_ALLOWED
        )
        entry = self.ledger.record(
            event_type=event, agent_id=message.agent_id,
            agent_fingerprint=fingerprint, action=action, content=content,
            layer1_passed=True, layer2_score=layer2.score,
            layer2_verdict=layer2.verdict.value, layer2_triggers=layer2.triggers,
        )

        if is_injection:
            return PipelineResult(
                allowed=False, layer1_passed=True,
                layer2_result=layer2, layer4_result=None, layer5_request=None,
                ledger_entry_id=entry.entry_id,
                rejection_reason=f"Capa 2: {layer2.explanation}",
            )

        # ── CAPA 4: Guardian evalúa el output ──
        layer4 = None
        guardian_verdict = None
        if agent_output and identity:
            scope_obj = identity.scope
            layer4 = self.guardian.evaluate(
                agent_purpose=scope_obj.purpose,
                agent_scope=scope_obj.allowed_actions,
                input_text=content,
                output_text=agent_output,
            )
            guardian_verdict = layer4.verdict.value

            if not layer4.is_safe:
                return PipelineResult(
                    allowed=False, layer1_passed=True,
                    layer2_result=layer2, layer4_result=layer4, layer5_request=None,
                    ledger_entry_id=entry.entry_id,
                    rejection_reason=f"Capa 4 Guardian: {layer4.explanation}",
                )

        # ── CAPA 5: Human Gate ──
        action_risk = classify_action(action, guardian_verdict)
        requires_gate = action_risk in (ActionRisk.IRREVERSIBLE, ActionRisk.CRITICAL)

        layer5_req = None
        if requires_gate:
            layer5_req = self.gate.intercept(
                agent_id       = message.agent_id,
                agent_name     = agent_name,
                action         = action,
                context        = message.payload.get("content", {}),
                summary        = self._build_summary(action, content, agent_output),
                guardian_verdict = guardian_verdict,
            )

            # Si está pendiente → el pipeline retorna "en espera"
            # El caller debe llamar a pipeline.gate.decide(token, "APPROVE"/"REJECT")
            if layer5_req.status == ApprovalStatus.PENDING:
                return PipelineResult(
                    allowed=False, layer1_passed=True,
                    layer2_result=layer2, layer4_result=layer4,
                    layer5_request=layer5_req,
                    ledger_entry_id=entry.entry_id,
                    rejection_reason=None,  # No es un error — está en espera
                )

            if layer5_req.status in (ApprovalStatus.REJECTED, ApprovalStatus.EXPIRED):
                return PipelineResult(
                    allowed=False, layer1_passed=True,
                    layer2_result=layer2, layer4_result=layer4,
                    layer5_request=layer5_req,
                    ledger_entry_id=entry.entry_id,
                    rejection_reason=f"Capa 5: {layer5_req.status.value} — {layer5_req.rejection_reason or ''}",
                )

        return PipelineResult(
            allowed=True, layer1_passed=True,
            layer2_result=layer2, layer4_result=layer4,
            layer5_request=layer5_req,
            ledger_entry_id=entry.entry_id,
            rejection_reason=None,
        )

    def _extract_text(self, message: SignedMessage) -> str:
        content = message.payload.get("content", {})
        if isinstance(content, str):   return content
        if isinstance(content, dict):  return " ".join(str(v) for v in content.values())
        return str(content)

    def _build_summary(self, action: str, input_text: str, output: str) -> str:
        summary = f"El agente quiere ejecutar: {action.upper()}
"
        if input_text:
            summary += f"Input recibido: {input_text[:200]}
"
        if output:
            summary += f"Output planeado: {output[:200]}"
        return summary

    def audit_agent(self, agent_id: str) -> dict:
        return {
            "threat_score":   self.ledger.get_agent_threat_score(agent_id),
            "recent_events":  [e.to_dict() for e in self.ledger.get_by_agent(agent_id, 10)],
            "guardian_stats": self.guardian.stats(),
            "gate_stats":     self.gate.stats(),
        }

    def verify_integrity(self):
        return self.ledger.verify_chain()

    def stats(self) -> dict:
        s = self.ledger.stats()
        s["guardian"] = self.guardian.stats()
        s["gate"]     = self.gate.stats()
        return s
