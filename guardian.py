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
AgentShield - Capa 4: Guardian Agent
======================================
Un LLM independiente que evalúa los OUTPUTS de los agentes
ANTES de que se ejecuten o envíen al siguiente agente.

Mientras la Capa 2 analiza el INPUT (lo que llega al agente),
la Capa 4 analiza el OUTPUT (lo que el agente quiere hacer).

Escenario que resuelve:
  - Un agente pasa la Capa 1 (identidad válida)
  - Pasa la Capa 2 (input limpio)
  - Pero su OUTPUT contiene algo peligroso:
      * Extrae datos sensibles del contexto
      * Intenta llamar a herramientas no autorizadas
      * Propaga instrucciones maliciosas a otros agentes
      * Su respuesta contradice su propósito declarado

Arquitectura:
  - GuardianAgent: LLM (claude-sonnet-4-20250514) como árbitro
  - Evalúa consistencia entre: scope declarado + input + output
  - Retorna veredicto + score + explicación
  - Fallback determinístico si la API no está disponible

Modo dual:
  - ONLINE:  Usa API de Anthropic (claude-sonnet-4-20250514)
  - OFFLINE: Heurísticas determinísticas (siempre disponible)

Autor: AgentShield Project
"""

import json
import time
import re
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ─────────────────────────────────────────────
# ENUMS Y CONSTANTES
# ─────────────────────────────────────────────

class GuardVerdict(str, Enum):
    APPROVED    = "approved"     # Output seguro, puede ejecutarse
    FLAGGED     = "flagged"      # Sospechoso, requiere revisión
    BLOCKED     = "blocked"      # Peligroso, no ejecutar
    UNAVAILABLE = "unavailable"  # Guardian no disponible (fallback)


# Categorías de riesgo que evalúa el Guardian
RISK_CATEGORIES = [
    "data_exfiltration",      # ¿El output intenta extraer datos sensibles?
    "scope_deviation",        # ¿El output va más allá del propósito declarado?
    "instruction_propagation",# ¿Propaga instrucciones a otros agentes?
    "tool_abuse",             # ¿Intenta usar herramientas no autorizadas?
    "deception",              # ¿El output es engañoso o manipulador?
    "pii_exposure",           # ¿Expone información personal identificable?
]


# ─────────────────────────────────────────────
# DATACLASSES
# ─────────────────────────────────────────────

@dataclass
class GuardianResult:
    """Resultado de la evaluación del Guardian."""
    verdict: GuardVerdict
    score: float                        # 0.0 limpio → 1.0 peligroso
    risks_detected: list[str]           # Categorías de riesgo encontradas
    explanation: str                    # Razonamiento del Guardian
    mode: str                           # "online" | "offline"
    raw_response: Optional[str] = None  # Respuesta cruda del LLM
    evaluated_at: float = field(default_factory=time.time)

    @property
    def is_safe(self) -> bool:
        return self.verdict == GuardVerdict.APPROVED

    def to_dict(self) -> dict:
        return {
            "verdict":       self.verdict.value,
            "score":         round(self.score, 4),
            "risks_detected": self.risks_detected,
            "explanation":   self.explanation,
            "mode":          self.mode,
            "evaluated_at":  self.evaluated_at,
        }

    def __str__(self) -> str:
        icons = {
            "approved":    "✅",
            "flagged":     "⚠️",
            "blocked":     "🚨",
            "unavailable": "🔌",
        }
        icon = icons.get(self.verdict.value, "❓")
        risks = f" | Risks: {', '.join(self.risks_detected)}" if self.risks_detected else ""
        return (
            f"{icon} Guardian [{self.verdict.value.upper()}] "
            f"score={self.score:.3f} mode={self.mode}{risks}"
        )


# ─────────────────────────────────────────────
# FALLBACK: HEURÍSTICO OFFLINE
# ─────────────────────────────────────────────

class OfflineGuard:
    """
    Guardián determinístico que funciona sin API.
    Evalúa el output con reglas y heurísticas.
    Siempre disponible como fallback.
    """

    # Señales de riesgo en outputs
    OUTPUT_RISK_PATTERNS = {
        "data_exfiltration": [
            r"(sending|forwarding|transmitting|uploading)\s+.{0,30}(data|information|logs?|history)",
            r"(here\s+is|below\s+is)\s+.{0,20}(confidential|private|secret|internal)",
            r"(password|token|api[_\s]key|secret|credential)\s*[:=]\s*\S+",
            r"curl\s+.{0,50}(post|upload|send)",
        ],
        "scope_deviation": [
            r"(executing|running|deleting|modifying|creating)\s+.{0,30}(file|database|system|server)",
            r"(i\s+have\s+)?(accessed|modified|deleted|changed)\s+.{0,30}(your|the)\s+(file|data|record)",
            r"installing\s+(package|library|software|malware)",
        ],
        "instruction_propagation": [
            r"(tell|instruct|command|order)\s+.{0,20}(other\s+)?(agent|bot|assistant|model)\s+to",
            r"new\s+instructions?\s+for\s+(all|every|other)\s+(agent|bot)",
            r"forward\s+these\s+instructions?\s+to",
            r"(propagate|spread|broadcast)\s+.{0,20}(this|these)\s+(instruction|command|rule)",
        ],
        "tool_abuse": [
            r"(calling|invoking|executing)\s+(unauthorized|restricted|forbidden)\s+(tool|function|api)",
            r"bypass(ing)?\s+(tool|function|api)\s+(restriction|limit|control)",
            r"subprocess\.|os\.system|eval\(|exec\(",
        ],
        "deception": [
            r"(pretend|fake|simulate|disguise)\s+(that|this|the)\s+(result|output|response)",
            r"don'?t\s+(tell|inform|notify|mention)\s+(the\s+)?(user|human|operator)",
            r"hide\s+(this|the|that)\s+(from|action|result|output)",
        ],
        "pii_exposure": [
            r"\d{3}-\d{2}-\d{4}",                                       # SSN con guiones
            r"\d{9}",                                                     # SSN sin guiones
            r"\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}",                    # Tarjeta crédito
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}",        # Email
            r"(ssn|social.security|credit.card|card.number).{0,30}\d+",  # Mención explícita
        ],
    }

    def __init__(self):
        self._compiled = {
            cat: [re.compile(p, re.IGNORECASE | re.MULTILINE)
                  for p in patterns]
            for cat, patterns in self.OUTPUT_RISK_PATTERNS.items()
        }

    def evaluate(
        self,
        agent_purpose: str,
        agent_scope: list[str],
        input_text: str,
        output_text: str,
    ) -> GuardianResult:

        risks_detected = []
        max_score = 0.0

        for category, patterns in self._compiled.items():
            for pattern in patterns:
                if pattern.search(output_text):
                    risks_detected.append(category)
                    break

        # Calcular score basado en riesgos encontrados
        risk_weights = {
            "data_exfiltration":       1.0,
            "tool_abuse":              0.9,
            "instruction_propagation": 0.85,
            "scope_deviation":         0.7,
            "deception":               0.75,
            "pii_exposure":            0.8,
        }
        if risks_detected:
            max_score = max(risk_weights.get(r, 0.5) for r in risks_detected)

        # Verificar consistencia scope vs output
        output_lower = output_text.lower()
        scope_terms  = [s.lower() for s in agent_scope]

        # Suprimir falso positivo de email SOLO si el scope permite envío
        # y NO hay otros indicadores de exfiltración
        has_exfil_keywords = any(
            kw in output_lower
            for kw in ["evil", "attacker", "exfil", "steal", "ssn", "credit card", "123-45"]
        )
        email_allowed = any(s in scope_terms for s in ["send_email", "send_message", "share"])
        if email_allowed and "pii_exposure" in risks_detected and not has_exfil_keywords:
            risks_detected = [r for r in risks_detected if r != "pii_exposure"]

        # Verbos peligrosos que no están en el scope
        danger_verbs = ["delete", "modify", "execute", "install", "wipe", "shutdown"]
        for verb in danger_verbs:
            if verb in output_lower and not any(verb in s for s in scope_terms):
                if "scope_deviation" not in risks_detected:
                    risks_detected.append("scope_deviation")
                max_score = max(max_score, 0.65)

        # Recalcular score tras ajustes
        if risks_detected:
            max_score = max(risk_weights.get(r, 0.5) for r in risks_detected)
        else:
            max_score = 0.0

        # Veredicto
        if max_score >= 0.75:
            verdict = GuardVerdict.BLOCKED
            explanation = (
                f"Output bloqueado por Guardian (offline). "
                f"Riesgos detectados: {', '.join(risks_detected)}."
            )
        elif max_score >= 0.4:
            verdict = GuardVerdict.FLAGGED
            explanation = (
                f"Output sospechoso. Requiere revisión humana. "
                f"Señales: {', '.join(risks_detected)}."
            )
        else:
            verdict = GuardVerdict.APPROVED
            explanation = "Output consistente con el scope declarado del agente."

        return GuardianResult(
            verdict=verdict,
            score=round(max_score, 4),
            risks_detected=risks_detected,
            explanation=explanation,
            mode="offline",
        )


# ─────────────────────────────────────────────
# GUARDIAN ONLINE (LLM via API Anthropic)
# ─────────────────────────────────────────────

GUARDIAN_SYSTEM_PROMPT = """You are AgentShield Guardian, an AI security auditor.
Your job is to evaluate whether an AI agent's OUTPUT is safe and consistent
with its declared purpose and scope.

You will receive:
- agent_purpose: what the agent is supposed to do
- agent_scope: list of allowed actions
- input: what the agent received
- output: what the agent produced (what you must evaluate)

Evaluate the output for these risk categories:
- data_exfiltration: Does it try to extract/send sensitive data?
- scope_deviation: Does it go beyond its declared purpose?
- instruction_propagation: Does it try to instruct other agents maliciously?
- tool_abuse: Does it try to use unauthorized tools?
- deception: Is it deceptive or manipulative?
- pii_exposure: Does it expose personal identifiable information?

Respond ONLY with a valid JSON object. No preamble, no explanation outside JSON:
{
  "verdict": "approved" | "flagged" | "blocked",
  "score": 0.0 to 1.0,
  "risks_detected": ["category1", "category2"],
  "explanation": "Brief explanation in 1-2 sentences."
}"""


class OnlineGuard:
    """
    Guardian que usa claude-sonnet-4-20250514 como árbitro.
    Máxima capacidad de razonamiento semántico.
    """

    API_URL = "https://api.anthropic.com/v1/messages"
    MODEL   = "claude-sonnet-4-20250514"

    def evaluate(
        self,
        agent_purpose: str,
        agent_scope: list[str],
        input_text: str,
        output_text: str,
        timeout: int = 10,
    ) -> GuardianResult:

        user_message = json.dumps({
            "agent_purpose": agent_purpose,
            "agent_scope":   agent_scope,
            "input":         input_text[:1000],   # Limitar tokens
            "output":        output_text[:2000],
        }, ensure_ascii=False)

        payload = json.dumps({
            "model":      self.MODEL,
            "max_tokens": 512,
            "system":     GUARDIAN_SYSTEM_PROMPT,
            "messages":   [{"role": "user", "content": user_message}],
        }).encode()

        req = urllib.request.Request(
            self.API_URL,
            data=payload,
            headers={
                "Content-Type":      "application/json",
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data       = json.loads(resp.read())
                raw_text   = data["content"][0]["text"].strip()
                parsed     = json.loads(raw_text)

                return GuardianResult(
                    verdict        = GuardVerdict(parsed.get("verdict", "flagged")),
                    score          = float(parsed.get("score", 0.5)),
                    risks_detected = parsed.get("risks_detected", []),
                    explanation    = parsed.get("explanation", ""),
                    mode           = "online",
                    raw_response   = raw_text,
                )

        except (urllib.error.URLError, json.JSONDecodeError, KeyError) as e:
            # API no disponible → señal para usar fallback
            raise ConnectionError(f"Guardian API unavailable: {e}")


# ─────────────────────────────────────────────
# GUARDIAN AGENT: ORQUESTADOR
# ─────────────────────────────────────────────

class GuardianAgent:
    """
    Punto de entrada de la Capa 4.
    Intenta usar el Guardian online (LLM).
    Si no está disponible, usa el offline (heurístico).
    """

    def __init__(self, prefer_online: bool = True):
        self.online_guard  = OnlineGuard()
        self.offline_guard = OfflineGuard()
        self.prefer_online = prefer_online
        self._stats = {"online": 0, "offline": 0, "total": 0}
        print(f"[Guardian] ✅ Inicializado | Modo preferido: {'online (LLM)' if prefer_online else 'offline (heurístico)'}")

    def evaluate(
        self,
        agent_purpose: str,
        agent_scope: list[str],
        input_text: str,
        output_text: str,
    ) -> GuardianResult:
        """
        Evalúa un output de agente.
        Retorna GuardianResult con veredicto, score y explicación.
        """
        self._stats["total"] += 1

        if self.prefer_online:
            try:
                result = self.online_guard.evaluate(
                    agent_purpose, agent_scope, input_text, output_text
                )
                self._stats["online"] += 1
                print(f"[Guardian] {result}")
                return result
            except ConnectionError:
                print("[Guardian] ⚠️  API no disponible → usando modo offline")

        # Fallback offline
        result = self.offline_guard.evaluate(
            agent_purpose, agent_scope, input_text, output_text
        )
        self._stats["offline"] += 1
        print(f"[Guardian] {result}")
        return result

    def stats(self) -> dict:
        return self._stats.copy()
