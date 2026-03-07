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
"""AgentShield - Firewall de identidad para agentes IA en entornos multi-agente."""
from .identity import Agent, AgentRegistry, AgentScope, TrustLevel, AgentStatus

__version__ = "0.1.0"
__all__ = ["Agent", "AgentRegistry", "AgentScope", "TrustLevel", "AgentStatus"]
