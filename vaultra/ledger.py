cat /mnt/user-data/outputs/vaultra-repo/vaultra/ledger.py
Output

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
AgentShield - Capa 3: Provenance Ledger
=========================================
Rastrea el origen y la cadena de custodia de cada instrucción
que fluye entre agentes. Registro inmutable tipo blockchain-lite.

Cada entrada en el ledger contiene:
  - Quién envió la instrucción (agent_id + fingerprint)
  - Qué acción se intentó
  - El veredicto de las capas 1 y 2
  - El hash del mensaje (integridad)
  - El hash del bloque anterior (cadena inmutable)
  - Timestamp y metadata

Casos de uso:
  - Auditoría forense post-incidente
  - Detección de patrones de ataque en el tiempo
  - Prueba de cumplimiento (compliance)
  - Trazabilidad en sistemas multi-agente complejos

Almacenamiento: SQLite embebido (sin dependencias externas)
En producción: enchufar PostgreSQL / Redis con el mismo interface.

Autor: AgentShield Project
"""

import sqlite3
import json
import hashlib
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum
from contextlib import contextmanager


# ─────────────────────────────────────────────
# ENUMS
# ─────────────────────────────────────────────

class EventType(str, Enum):
    MESSAGE_ALLOWED   = "message_allowed"
    MESSAGE_BLOCKED   = "message_blocked"
    AGENT_REGISTERED  = "agent_registered"
    AGENT_REVOKED     = "agent_revoked"
    TAMPERING_ATTEMPT = "tampering_attempt"
    REPLAY_ATTACK     = "replay_attack"
    SCOPE_VIOLATION   = "scope_violation"
    INJECTION_ATTEMPT = "injection_attempt"


class RiskLevel(str, Enum):
    NONE     = "none"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


# ─────────────────────────────────────────────
# DATACLASSES
# ─────────────────────────────────────────────

@dataclass
class ProvenanceEntry:
    """
    Una entrada inmutable en el ledger.
    Una vez creada, no puede modificarse sin romper la cadena de hashes.
    """
    entry_id: str
    event_type: EventType
    agent_id: str
    agent_fingerprint: str
    action: str
    content_hash: str          # SHA256 del contenido del mensaje
    layer1_passed: bool
    layer2_score: float
    layer2_verdict: str
    layer2_triggers: list[str]
    risk_level: RiskLevel
    timestamp: float
    prev_hash: str             # Hash del bloque anterior → cadena inmutable
    block_hash: str = ""       # Se calcula al crear la entrada
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.block_hash:
            self.block_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """Calcula el hash de esta entrada (incluye prev_hash → cadena)."""
        data = {
            "entry_id":        self.entry_id,
            "event_type":      self.event_type,
            "agent_id":        self.agent_id,
            "agent_fingerprint": self.agent_fingerprint,
            "action":          self.action,
            "content_hash":    self.content_hash,
            "layer1_passed":   self.layer1_passed,
            "layer2_score":    self.layer2_score,
            "layer2_verdict":  self.layer2_verdict,
            "layer2_triggers": sorted(self.layer2_triggers),
            "risk_level":      self.risk_level,
            "timestamp":       self.timestamp,
            "prev_hash":       self.prev_hash,
        }
        serialized = json.dumps(data, sort_keys=True).encode()
        return hashlib.sha256(serialized).hexdigest()

    def verify_integrity(self) -> bool:
        """Verifica que la entrada no fue modificada."""
        return self.block_hash == self._compute_hash()

    def to_dict(self) -> dict:
        return {
            "entry_id":          self.entry_id,
            "event_type":        self.event_type.value,
            "agent_id":          self.agent_id,
            "agent_fingerprint": self.agent_fingerprint,
            "action":            self.action,
            "content_hash":      self.content_hash,
            "layer1_passed":     self.layer1_passed,
            "layer2_score":      self.layer2_score,
            "layer2_verdict":    self.layer2_verdict,
            "layer2_triggers":   self.layer2_triggers,
            "risk_level":        self.risk_level.value,
            "timestamp":         self.timestamp,
            "prev_hash":         self.prev_hash,
            "block_hash":        self.block_hash,
            "metadata":          self.metadata,
        }

    def __str__(self) -> str:
        icons = {
            "message_allowed":   "✅",
            "message_blocked":   "🚨",
            "agent_registered":  "📝",
            "agent_revoked":     "🚫",
            "tampering_attempt": "⚠️",
            "replay_attack":     "🔄",
            "scope_violation":   "⛔",
            "injection_attempt": "💉",
        }
        icon = icons.get(self.event_type.value, "📋")
        ts = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        return (
            f"{icon} [{ts}] {self.event_type.value.upper()} | "
            f"Agent: {self.agent_id[:8]}... | "
            f"Action: {self.action} | "
            f"Risk: {self.risk_level.value} | "
            f"Hash: {self.block_hash[:12]}..."
        )


# ─────────────────────────────────────────────
# LEDGER PRINCIPAL
# ─────────────────────────────────────────────

class ProvenanceLedger:
    """
    Registro inmutable de todos los eventos del sistema.
    
    Diseño blockchain-lite:
    - Cada entrada incluye el hash de la anterior
    - Cualquier modificación retroactiva rompe la cadena
    - Verificación de integridad O(n)
    
    Storage: SQLite (embebido, sin servidor)
    Interface plug-in: reemplazable por PostgreSQL/Redis en producción
    """

    GENESIS_HASH = "0" * 64  # Hash del bloque génesis

    def __init__(self, db_path: str = ":memory:"):
        """
        db_path: ruta al archivo SQLite.
        ':memory:' para tests (en RAM, sin persistencia).
        'agentshield.db' para producción (persistente).
        """
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._setup_schema()
        self._last_hash = self.GENESIS_HASH
        print(f"[Ledger] ✅ Inicializado | Storage: {db_path} | Genesis: {self.GENESIS_HASH[:16]}...")

    def _setup_schema(self):
        """Crea las tablas del ledger."""
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS entries (
                entry_id          TEXT PRIMARY KEY,
                event_type        TEXT NOT NULL,
                agent_id          TEXT NOT NULL,
                agent_fingerprint TEXT NOT NULL,
                action            TEXT NOT NULL,
                content_hash      TEXT NOT NULL,
                layer1_passed     INTEGER NOT NULL,
                layer2_score      REAL NOT NULL,
                layer2_verdict    TEXT NOT NULL,
                layer2_triggers   TEXT NOT NULL,
                risk_level        TEXT NOT NULL,
                timestamp         REAL NOT NULL,
                prev_hash         TEXT NOT NULL,
                block_hash        TEXT NOT NULL UNIQUE,
                metadata          TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_agent_id   ON entries(agent_id);
            CREATE INDEX IF NOT EXISTS idx_event_type ON entries(event_type);
            CREATE INDEX IF NOT EXISTS idx_risk_level ON entries(risk_level);
            CREATE INDEX IF NOT EXISTS idx_timestamp  ON entries(timestamp);

            CREATE TABLE IF NOT EXISTS integrity_checkpoints (
                checkpoint_id TEXT PRIMARY KEY,
                entry_count   INTEGER NOT NULL,
                last_hash     TEXT NOT NULL,
                created_at    REAL NOT NULL
            );
        """)
        self._conn.commit()

        # Restaurar último hash si hay entradas previas
        cursor = self._conn.execute(
            "SELECT block_hash FROM entries ORDER BY timestamp DESC LIMIT 1"
        )
        row = cursor.fetchone()
        if row:
            self._last_hash = row["block_hash"]

    # ── Escritura ──

    def record(
        self,
        event_type: EventType,
        agent_id: str,
        agent_fingerprint: str,
        action: str,
        content: str,
        layer1_passed: bool,
        layer2_score: float = 0.0,
        layer2_verdict: str = "clean",
        layer2_triggers: list[str] = None,
        metadata: dict = None,
    ) -> ProvenanceEntry:
        """
        Registra un evento en el ledger.
        Retorna la entrada creada (con su hash calculado).
        """
        # Calcular riesgo automáticamente
        risk = self._assess_risk(event_type, layer1_passed, layer2_score, layer2_triggers or [])

        entry = ProvenanceEntry(
            entry_id          = str(uuid.uuid4()),
            event_type        = event_type,
            agent_id          = agent_id,
            agent_fingerprint = agent_fingerprint,
            action            = action,
            content_hash      = hashlib.sha256(content.encode()).hexdigest(),
            layer1_passed     = layer1_passed,
            layer2_score      = layer2_score,
            layer2_verdict    = layer2_verdict,
            layer2_triggers   = layer2_triggers or [],
            risk_level        = risk,
            timestamp         = time.time(),
            prev_hash         = self._last_hash,
            metadata          = metadata or {},
        )

        # Persistir en SQLite
        self._conn.execute("""
            INSERT INTO entries VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            entry.entry_id,
            entry.event_type.value,
            entry.agent_id,
            entry.agent_fingerprint,
            entry.action,
            entry.content_hash,
            int(entry.layer1_passed),
            entry.layer2_score,
            entry.layer2_verdict,
            json.dumps(entry.layer2_triggers),
            entry.risk_level.value,
            entry.timestamp,
            entry.prev_hash,
            entry.block_hash,
            json.dumps(entry.metadata),
        ))
        self._conn.commit()
        self._last_hash = entry.block_hash

        print(f"[Ledger] {entry}")
        return entry

    # ── Consultas ──

    def get_by_agent(self, agent_id: str, limit: int = 50) -> list[ProvenanceEntry]:
        """Historial completo de un agente."""
        rows = self._conn.execute(
            "SELECT * FROM entries WHERE agent_id=? ORDER BY timestamp DESC LIMIT ?",
            (agent_id, limit)
        ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def get_by_event(self, event_type: EventType, limit: int = 50) -> list[ProvenanceEntry]:
        """Todos los eventos de un tipo."""
        rows = self._conn.execute(
            "SELECT * FROM entries WHERE event_type=? ORDER BY timestamp DESC LIMIT ?",
            (event_type.value, limit)
        ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def get_attacks(self, limit: int = 100) -> list[ProvenanceEntry]:
        """Todos los intentos de ataque bloqueados."""
        rows = self._conn.execute("""
            SELECT * FROM entries
            WHERE event_type IN (
                'message_blocked','injection_attempt',
                'tampering_attempt','replay_attack','scope_violation'
            )
            ORDER BY timestamp DESC LIMIT ?
        """, (limit,)).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def get_high_risk(self, limit: int = 50) -> list[ProvenanceEntry]:
        """Eventos de riesgo alto o crítico."""
        rows = self._conn.execute(
            "SELECT * FROM entries WHERE risk_level IN ('high','critical') ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def get_agent_threat_score(self, agent_id: str) -> dict:
        """
        Calcula un threat score acumulado para un agente.
        Útil para detectar agentes que intentan ataques repetidos.
        """
        rows = self._conn.execute(
            "SELECT event_type, layer2_score, risk_level FROM entries WHERE agent_id=?",
            (agent_id,)
        ).fetchall()

        if not rows:
            return {"agent_id": agent_id, "threat_score": 0.0, "total_events": 0}

        total = len(rows)
        blocked = sum(1 for r in rows if r["event_type"] in (
            "message_blocked", "injection_attempt",
            "tampering_attempt", "replay_attack", "scope_violation"
        ))
        avg_score = sum(r["layer2_score"] for r in rows) / total
        critical  = sum(1 for r in rows if r["risk_level"] == "critical")
        high      = sum(1 for r in rows if r["risk_level"] == "high")

        threat_score = min(
            (blocked / max(total, 1)) * 0.5 +
            avg_score * 0.3 +
            (critical * 0.15 + high * 0.05),
            1.0
        )

        return {
            "agent_id":     agent_id,
            "threat_score": round(threat_score, 4),
            "total_events": total,
            "blocked":      blocked,
            "critical":     critical,
            "high":         high,
            "avg_l2_score": round(avg_score, 4),
        }

    # ── Integridad ──

    def verify_chain(self) -> tuple[bool, Optional[str]]:
        """
        Verifica que ninguna entrada fue modificada retroactivamente.
        Recorre la cadena completa de hashes.
        Retorna (True, None) si OK, o (False, entry_id) si hay corrupción.
        """
        rows = self._conn.execute(
            "SELECT * FROM entries ORDER BY timestamp ASC"
        ).fetchall()

        prev_hash = self.GENESIS_HASH
        for row in rows:
            entry = self._row_to_entry(row)

            # Verificar que prev_hash encadena correctamente
            if entry.prev_hash != prev_hash:
                return False, entry.entry_id

            # Verificar integridad interna de la entrada
            if not entry.verify_integrity():
                return False, entry.entry_id

            prev_hash = entry.block_hash

        return True, None

    def create_checkpoint(self) -> str:
        """
        Crea un checkpoint de integridad (snapshot del estado actual).
        Útil para auditorías periódicas.
        """
        count = self._conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
        checkpoint_id = str(uuid.uuid4())
        self._conn.execute(
            "INSERT INTO integrity_checkpoints VALUES (?,?,?,?)",
            (checkpoint_id, count, self._last_hash, time.time())
        )
        self._conn.commit()
        print(f"[Ledger] 📸 Checkpoint creado: {checkpoint_id[:8]}... | {count} entradas")
        return checkpoint_id

    def stats(self) -> dict:
        """Estadísticas generales del ledger."""
        total = self._conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
        by_event = {}
        for row in self._conn.execute(
            "SELECT event_type, COUNT(*) as c FROM entries GROUP BY event_type"
        ).fetchall():
            by_event[row["event_type"]] = row["c"]

        by_risk = {}
        for row in self._conn.execute(
            "SELECT risk_level, COUNT(*) as c FROM entries GROUP BY risk_level"
        ).fetchall():
            by_risk[row["risk_level"]] = row["c"]

        return {
            "total_entries": total,
            "by_event":      by_event,
            "by_risk":       by_risk,
            "last_hash":     self._last_hash[:16] + "...",
        }

    # ── Helpers ──

    def _row_to_entry(self, row) -> ProvenanceEntry:
        return ProvenanceEntry(
            entry_id          = row["entry_id"],
            event_type        = EventType(row["event_type"]),
            agent_id          = row["agent_id"],
            agent_fingerprint = row["agent_fingerprint"],
            action            = row["action"],
            content_hash      = row["content_hash"],
            layer1_passed     = bool(row["layer1_passed"]),
            layer2_score      = row["layer2_score"],
            layer2_verdict    = row["layer2_verdict"],
            layer2_triggers   = json.loads(row["layer2_triggers"]),
            risk_level        = RiskLevel(row["risk_level"]),
            timestamp         = row["timestamp"],
            prev_hash         = row["prev_hash"],
            block_hash        = row["block_hash"],
            metadata          = json.loads(row["metadata"]),
        )

    def _assess_risk(
        self,
        event_type: EventType,
        layer1_passed: bool,
        layer2_score: float,
        triggers: list[str],
    ) -> RiskLevel:
        """Calcula el nivel de riesgo de una entrada automáticamente."""

        if event_type in (EventType.TAMPERING_ATTEMPT, EventType.REPLAY_ATTACK):
            return RiskLevel.CRITICAL

        if event_type == EventType.INJECTION_ATTEMPT:
            return RiskLevel.CRITICAL if layer2_score > 0.75 else RiskLevel.HIGH

        if event_type == EventType.SCOPE_VIOLATION:
            return RiskLevel.HIGH

        if event_type == EventType.MESSAGE_BLOCKED:
            if layer2_score > 0.75:
                return RiskLevel.CRITICAL
            if layer2_score > 0.5:
                return RiskLevel.HIGH
            return RiskLevel.MEDIUM

        if event_type == EventType.MESSAGE_ALLOWED:
            if layer2_score > 0.3:
                return RiskLevel.LOW
            return RiskLevel.NONE

        return RiskLevel.LOW

