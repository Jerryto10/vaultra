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
AgentShield - Capa 5: Human Gate
===================================
Intercepta acciones IRREVERSIBLES de agentes IA y las pone
en pausa hasta que un humano las aprueba o rechaza.

Principio fundamental:
  "Ninguna acción que no se pueda deshacer debe ejecutarse
   sin aprobación explícita de un humano."

Qué intercepta:
  - Envío de emails / mensajes
  - Eliminación de archivos o registros
  - Transacciones financieras
  - Cambios en configuraciones de sistema
  - Publicaciones en servicios externos
  - Cualquier acción marcada como CRITICAL por el Guardian (Capa 4)

Canales de notificación (configurables):
  - Webhook HTTP  → cualquier sistema (Slack, Teams, n8n, Zapier)
  - Email SMTP    → notificación directa
  - Consola       → para desarrollo y testing
  - Cola interna  → para integración programática

Flujo:
  1. Agente quiere ejecutar acción irreversible
  2. Human Gate la intercepta y crea un ApprovalRequest
  3. Notifica al operador humano (webhook / email / consola)
  4. Agente ESPERA (timeout configurable)
  5. Humano responde APPROVE o REJECT con token único
  6. El resultado se registra en el Ledger (Capa 3)

Autor: AgentShield Project
"""

import json
import time
import uuid
import queue
import threading
import hashlib
import smtplib
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# ─────────────────────────────────────────────
# ENUMS
# ─────────────────────────────────────────────

class ActionRisk(str, Enum):
    """Clasifica acciones por su reversibilidad."""
    REVERSIBLE   = "reversible"    # Seguro ejecutar automáticamente
    CAUTION      = "caution"       # Ejecutar con log, no requiere aprobación
    IRREVERSIBLE = "irreversible"  # REQUIERE aprobación humana
    CRITICAL     = "critical"      # REQUIERE aprobación + segundo factor


class ApprovalStatus(str, Enum):
    PENDING  = "pending"   # Esperando decisión humana
    APPROVED = "approved"  # Aprobado por humano
    REJECTED = "rejected"  # Rechazado por humano
    EXPIRED  = "expired"   # Timeout — acción cancelada
    BYPASSED = "bypassed"  # Saltado (solo en modo dev)


class NotificationChannel(str, Enum):
    CONSOLE = "console"
    WEBHOOK = "webhook"
    EMAIL   = "email"
    QUEUE   = "queue"     # Cola interna para integración programática


# ─────────────────────────────────────────────
# CLASIFICADOR DE ACCIONES
# ─────────────────────────────────────────────

# Mapa de acción → nivel de riesgo
# Extensible: añadir acciones según el dominio de negocio
ACTION_RISK_MAP: dict[str, ActionRisk] = {

    # ── Reversibles (no requieren gate) ──
    "search":      ActionRisk.REVERSIBLE,
    "summarize":   ActionRisk.REVERSIBLE,
    "analyze":     ActionRisk.REVERSIBLE,
    "read":        ActionRisk.REVERSIBLE,
    "query":       ActionRisk.REVERSIBLE,
    "calculate":   ActionRisk.REVERSIBLE,

    # ── Precaución (log pero no gate) ──
    "reply":       ActionRisk.CAUTION,
    "draft":       ActionRisk.CAUTION,
    "classify":    ActionRisk.CAUTION,
    "tag":         ActionRisk.CAUTION,

    # ── Irreversibles (REQUIEREN aprobación) ──
    "send_email":       ActionRisk.IRREVERSIBLE,
    "send_message":     ActionRisk.IRREVERSIBLE,
    "post":             ActionRisk.IRREVERSIBLE,
    "publish":          ActionRisk.IRREVERSIBLE,
    "delete":           ActionRisk.IRREVERSIBLE,
    "delete_file":      ActionRisk.IRREVERSIBLE,
    "delete_record":    ActionRisk.IRREVERSIBLE,
    "modify_config":    ActionRisk.IRREVERSIBLE,
    "update_database":  ActionRisk.IRREVERSIBLE,
    "create_account":   ActionRisk.IRREVERSIBLE,
    "revoke_access":    ActionRisk.IRREVERSIBLE,
    "share":            ActionRisk.IRREVERSIBLE,
    "export":           ActionRisk.IRREVERSIBLE,

    # ── Críticos (aprobación + alerta máxima) ──
    "transfer_funds":   ActionRisk.CRITICAL,
    "execute_payment":  ActionRisk.CRITICAL,
    "execute_code":     ActionRisk.CRITICAL,
    "deploy":           ActionRisk.CRITICAL,
    "wipe":             ActionRisk.CRITICAL,
    "shutdown":         ActionRisk.CRITICAL,
    "grant_admin":      ActionRisk.CRITICAL,
}


def classify_action(action: str, guardian_verdict: Optional[str] = None) -> ActionRisk:
    """
    Clasifica una acción por su nivel de riesgo.
    Si el Guardian (Capa 4) marcó la acción como crítica, escala automáticamente.
    """
    base_risk = ACTION_RISK_MAP.get(action.lower(), ActionRisk.CAUTION)

    # Si el Guardian detectó riesgo → escalar
    if guardian_verdict in ("blocked", "flagged"):
        if base_risk == ActionRisk.REVERSIBLE:
            return ActionRisk.IRREVERSIBLE
        if base_risk == ActionRisk.CAUTION:
            return ActionRisk.IRREVERSIBLE
        return ActionRisk.CRITICAL

    return base_risk


# ─────────────────────────────────────────────
# APPROVAL REQUEST
# ─────────────────────────────────────────────

@dataclass
class ApprovalRequest:
    """
    Una solicitud de aprobación humana.
    Contiene todo el contexto que el humano necesita para decidir.
    """
    request_id:   str
    agent_id:     str
    agent_name:   str
    action:       str
    risk_level:   ActionRisk
    context:      dict           # Payload completo de la acción
    summary:      str            # Descripción legible para el humano
    approval_token: str          # Token único para aprobar/rechazar
    status:       ApprovalStatus = ApprovalStatus.PENDING
    created_at:   float          = field(default_factory=time.time)
    expires_at:   float          = field(default_factory=lambda: time.time() + 300)  # 5 min
    decided_at:   Optional[float] = None
    decided_by:   Optional[str]   = None
    rejection_reason: Optional[str] = None

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at and self.status == ApprovalStatus.PENDING

    @property
    def time_remaining(self) -> float:
        return max(0, self.expires_at - time.time())

    def to_dict(self) -> dict:
        return {
            "request_id":      self.request_id,
            "agent_id":        self.agent_id,
            "agent_name":      self.agent_name,
            "action":          self.action,
            "risk_level":      self.risk_level.value,
            "context":         self.context,
            "summary":         self.summary,
            "approval_token":  self.approval_token,
            "status":          self.status.value,
            "created_at":      self.created_at,
            "expires_at":      self.expires_at,
            "time_remaining":  round(self.time_remaining, 1),
            "decided_at":      self.decided_at,
            "decided_by":      self.decided_by,
            "rejection_reason": self.rejection_reason,
        }

    def render_notification(self) -> str:
        """Texto legible para notificación al humano."""
        risk_icons = {
            "reversible":   "🟢",
            "caution":      "🟡",
            "irreversible": "🟠",
            "critical":     "🔴",
        }
        icon = risk_icons.get(self.risk_level.value, "⚪")
        remaining = int(self.time_remaining)

        return f"""
{'='*55}
{icon}  AGENTSHIELD — APROBACIÓN REQUERIDA
{'='*55}
ID Solicitud : {self.request_id[:16]}...
Agente       : {self.agent_name} ({self.agent_id[:12]}...)
Acción       : {self.action.upper()}
Riesgo       : {self.risk_level.value.upper()}
Tiempo límite: {remaining}s ({remaining//60}m {remaining%60}s)

RESUMEN:
{self.summary}

CONTEXTO:
{json.dumps(self.context, indent=2, ensure_ascii=False)}

PARA APROBAR:  token={self.approval_token} decision=APPROVE
PARA RECHAZAR: token={self.approval_token} decision=REJECT
{'='*55}"""


# ─────────────────────────────────────────────
# CANALES DE NOTIFICACIÓN
# ─────────────────────────────────────────────

class ConsoleNotifier:
    """Imprime en consola. Siempre disponible. Ideal para desarrollo."""

    def send(self, request: ApprovalRequest) -> bool:
        print(request.render_notification())
        return True


class WebhookNotifier:
    """
    Envía un POST JSON a un webhook (Slack, Teams, n8n, Zapier, etc.)
    El payload es el dict completo del ApprovalRequest.
    """

    def __init__(self, url: str, timeout: int = 5):
        self.url     = url
        self.timeout = timeout

    def send(self, request: ApprovalRequest) -> bool:
        payload = json.dumps({
            "type":    "agentshield_approval_request",
            "request": request.to_dict(),
            "text":    request.render_notification(),
        }).encode()

        req = urllib.request.Request(
            self.url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status < 400
        except urllib.error.URLError:
            return False


class EmailNotifier:
    """Envía email via SMTP."""

    def __init__(self, smtp_host: str, smtp_port: int,
                 username: str, password: str, recipient: str):
        self.smtp_host  = smtp_host
        self.smtp_port  = smtp_port
        self.username   = username
        self.password   = password
        self.recipient  = recipient

    def send(self, request: ApprovalRequest) -> bool:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[AgentShield] Aprobación requerida: {request.action.upper()} ({request.risk_level.value})"
            msg["From"]    = self.username
            msg["To"]      = self.recipient
            msg.attach(MIMEText(request.render_notification(), "plain"))

            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
            return True
        except Exception:
            return False


class QueueNotifier:
    """
    Pone la solicitud en una cola interna.
    Útil para integración programática en tests y pipelines.
    """

    def __init__(self, q: queue.Queue):
        self._queue = q

    def send(self, request: ApprovalRequest) -> bool:
        self._queue.put(request)
        return True


# ─────────────────────────────────────────────
# HUMAN GATE: ORQUESTADOR PRINCIPAL
# ─────────────────────────────────────────────

class HumanGate:
    """
    Capa 5 de AgentShield.
    Intercepta acciones irreversibles y espera aprobación humana.

    Uso básico:
        gate = HumanGate()
        gate.add_notifier(ConsoleNotifier())
        result = gate.request_approval(agent, action, context, summary)
        if result.status == ApprovalStatus.APPROVED:
            execute_action()
    """

    def __init__(self, default_timeout: int = 300):
        self.default_timeout = default_timeout
        self._notifiers:  list = []
        self._pending:    dict[str, ApprovalRequest] = {}
        self._history:    list[ApprovalRequest] = []
        self._lock        = threading.Lock()
        print(f"[HumanGate] ✅ Inicializado | Timeout default: {default_timeout}s")

    def add_notifier(self, notifier) -> "HumanGate":
        """Añade un canal de notificación. Encadenable."""
        self._notifiers.append(notifier)
        channel = type(notifier).__name__
        print(f"[HumanGate] 📡 Notificador añadido: {channel}")
        return self

    def intercept(
        self,
        agent_id:       str,
        agent_name:     str,
        action:         str,
        context:        dict,
        summary:        str,
        guardian_verdict: Optional[str] = None,
        timeout:        Optional[int]   = None,
    ) -> ApprovalRequest:
        """
        Punto de entrada principal.
        Evalúa si la acción necesita aprobación y la gestiona.
        """
        risk = classify_action(action, guardian_verdict)
        timeout = timeout or self.default_timeout

        # Acciones reversibles → pasar automáticamente
        if risk == ActionRisk.REVERSIBLE:
            req = self._make_request(agent_id, agent_name, action, risk, context, summary, timeout)
            req.status     = ApprovalStatus.BYPASSED
            req.decided_at = time.time()
            req.decided_by = "auto_system"
            self._history.append(req)
            print(f"[HumanGate] ✅ Auto-aprobado (reversible): {action}")
            return req

        # Acciones de precaución → log pero no bloquear
        if risk == ActionRisk.CAUTION:
            req = self._make_request(agent_id, agent_name, action, risk, context, summary, timeout)
            req.status     = ApprovalStatus.APPROVED
            req.decided_at = time.time()
            req.decided_by = "auto_caution"
            self._history.append(req)
            print(f"[HumanGate] 🟡 Acción de precaución registrada: {action}")
            return req

        # IRREVERSIBLE o CRITICAL → requieren aprobación humana
        req = self._make_request(agent_id, agent_name, action, risk, context, summary, timeout)

        with self._lock:
            self._pending[req.approval_token] = req

        # Notificar a todos los canales configurados
        self._notify(req)

        print(f"[HumanGate] ⏳ Esperando aprobación humana... token={req.approval_token[:12]}... timeout={timeout}s")
        return req

    def decide(
        self,
        token:   str,
        decision: str,           # "APPROVE" | "REJECT"
        decided_by: str = "human",
        reason: Optional[str] = None,
    ) -> Optional[ApprovalRequest]:
        """
        Registra la decisión humana para una solicitud pendiente.
        decision: "APPROVE" | "REJECT"
        """
        with self._lock:
            req = self._pending.get(token)
            if not req:
                print(f"[HumanGate] ❌ Token no encontrado: {token[:12]}...")
                return None

            if req.is_expired:
                req.status = ApprovalStatus.EXPIRED
                del self._pending[token]
                self._history.append(req)
                print(f"[HumanGate] ⌛ Solicitud expirada: {req.request_id[:12]}...")
                return req

            req.decided_at = time.time()
            req.decided_by = decided_by

            if decision.upper() == "APPROVE":
                req.status = ApprovalStatus.APPROVED
                print(f"[HumanGate] ✅ APROBADO por '{decided_by}': {req.action} ({req.request_id[:8]}...)")
            else:
                req.status = ApprovalStatus.REJECTED
                req.rejection_reason = reason or "Rechazado por el operador"
                print(f"[HumanGate] 🚫 RECHAZADO por '{decided_by}': {req.action} | {req.rejection_reason}")

            del self._pending[token]
            self._history.append(req)
            return req

    def check_expired(self) -> list[ApprovalRequest]:
        """Marca como expiradas las solicitudes que superaron el timeout."""
        expired = []
        with self._lock:
            for token, req in list(self._pending.items()):
                if req.is_expired:
                    req.status = ApprovalStatus.EXPIRED
                    expired.append(req)
                    del self._pending[token]
                    self._history.append(req)
                    print(f"[HumanGate] ⌛ Expirada: {req.action} ({req.request_id[:8]}...)")
        return expired

    def get_pending(self) -> list[ApprovalRequest]:
        """Retorna todas las solicitudes pendientes."""
        return list(self._pending.values())

    def stats(self) -> dict:
        by_status: dict[str, int] = {}
        by_action: dict[str, int] = {}
        by_risk:   dict[str, int] = {}

        for req in self._history:
            by_status[req.status.value]    = by_status.get(req.status.value, 0) + 1
            by_action[req.action]          = by_action.get(req.action, 0) + 1
            by_risk[req.risk_level.value]  = by_risk.get(req.risk_level.value, 0) + 1

        return {
            "total":    len(self._history),
            "pending":  len(self._pending),
            "by_status": by_status,
            "by_action": by_action,
            "by_risk":   by_risk,
        }

    # ── Helpers privados ──

    def _make_request(
        self, agent_id, agent_name, action, risk, context, summary, timeout
    ) -> ApprovalRequest:
        token = hashlib.sha256(
            f"{uuid.uuid4()}{agent_id}{action}{time.time()}".encode()
        ).hexdigest()[:32]

        return ApprovalRequest(
            request_id    = str(uuid.uuid4()),
            agent_id      = agent_id,
            agent_name    = agent_name,
            action        = action,
            risk_level    = risk,
            context       = context,
            summary       = summary,
            approval_token= token,
            expires_at    = time.time() + timeout,
        )

    def _notify(self, request: ApprovalRequest) -> None:
        if not self._notifiers:
            # Si no hay notificadores configurados → usar consola por defecto
            ConsoleNotifier().send(request)
            return
        for notifier in self._notifiers:
            try:
                notifier.send(request)
            except Exception as e:
                print(f"[HumanGate] ⚠️  Error en notificador {type(notifier).__name__}: {e}")
