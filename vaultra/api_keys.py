# Copyright (c) 2026 Jerly Rojas
# Vaultra ? AI Agent Compliance Layer
# https://vaultra.io
# AGPL-3.0 License. Commercial use: legal@vaultra.io

"""
api_keys.py ? API Key management for Vaultra clients
=====================================================
Generates, stores, validates, and revokes client API keys.

Each client receives a unique key in the format:
  vaultra_sk_<32 random hex chars>

Keys are NEVER stored in plain text ? only their SHA-256 hash
is stored. This means even if the database is compromised,
the attacker cannot use the stored values.

Usage:
  from vaultra.api_keys import APIKeyManager

  manager = APIKeyManager()
  key, client_id = manager.create_key("Fintech Corp", "contact@fintech.com")
  is_valid = manager.validate_key(key)
  manager.revoke_key(client_id)
"""

import hashlib
import secrets
import sqlite3
import time
import uuid
from dataclasses import dataclass
from typing import Optional


# -- Key format --------------------------------------------
KEY_PREFIX  = "vaultra_sk_"
KEY_VERSION = "v1"


@dataclass
class ClientRecord:
    client_id:    str
    company_name: str
    email:        str
    key_hash:     str
    key_prefix:   str    # First 8 chars of key (for identification)
    created_at:   float
    last_used_at: Optional[float]
    is_active:    bool
    plan:         str    # "starter", "growth", "enterprise"
    request_count: int

    def to_dict(self) -> dict:
        return {
            "client_id":     self.client_id,
            "company_name":  self.company_name,
            "email":         self.email,
            "key_prefix":    self.key_prefix + "...",
            "created_at":    self.created_at,
            "last_used_at":  self.last_used_at,
            "is_active":     self.is_active,
            "plan":          self.plan,
            "request_count": self.request_count,
        }


class APIKeyManager:
    """
    Manages API keys for all Vaultra clients.

    Storage: SQLite (same pattern as the Ledger).
    In production: replace with PostgreSQL.
    """

    def __init__(self, db_path: str = "vaultra_keys.db"):
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._setup_schema()
        print(f"[APIKeyManager] Initialized | Storage: {db_path}")

    def _setup_schema(self):
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS clients (
                client_id     TEXT PRIMARY KEY,
                company_name  TEXT NOT NULL,
                email         TEXT NOT NULL UNIQUE,
                key_hash      TEXT NOT NULL UNIQUE,
                key_prefix    TEXT NOT NULL,
                created_at    REAL NOT NULL,
                last_used_at  REAL,
                is_active     INTEGER NOT NULL DEFAULT 1,
                plan          TEXT NOT NULL DEFAULT 'starter',
                request_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_key_hash  ON clients(key_hash);
            CREATE INDEX IF NOT EXISTS idx_email      ON clients(email);
            CREATE INDEX IF NOT EXISTS idx_is_active  ON clients(is_active);
        """)
        self._conn.commit()

    # -- Key generation -------------------------------------

    def _generate_raw_key(self) -> str:
        """Generates a cryptographically secure API key."""
        random_part = secrets.token_hex(32)
        return f"{KEY_PREFIX}{KEY_VERSION}_{random_part}"

    def _hash_key(self, raw_key: str) -> str:
        """SHA-256 hash of the key ? what gets stored."""
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    # -- CRUD operations ------------------------------------

    def create_key(
        self,
        company_name: str,
        email: str,
        plan: str = "starter",
    ) -> tuple[str, str]:
        """
        Creates a new API key for a client.

        Returns:
            (raw_key, client_id)

        IMPORTANT: The raw_key is returned ONCE and never stored.
        Send it to the client immediately via secure channel.
        """
        # Check for duplicate email
        existing = self._conn.execute(
            "SELECT client_id FROM clients WHERE email=?", (email,)
        ).fetchone()
        if existing:
            raise ValueError(f"A key already exists for email: {email}")

        raw_key   = self._generate_raw_key()
        key_hash  = self._hash_key(raw_key)
        client_id = str(uuid.uuid4())
        key_prefix = raw_key[:len(KEY_PREFIX) + len(KEY_VERSION) + 1 + 8]

        self._conn.execute("""
            INSERT INTO clients
            (client_id, company_name, email, key_hash, key_prefix,
             created_at, last_used_at, is_active, plan, request_count)
            VALUES (?, ?, ?, ?, ?, ?, NULL, 1, ?, 0)
        """, (client_id, company_name, email, key_hash, key_prefix,
               time.time(), plan))
        self._conn.commit()

        print(f"[APIKeyManager] Key created for {company_name} ({email})")
        print(f"[APIKeyManager] Client ID: {client_id}")
        print(f"[APIKeyManager] Key prefix: {key_prefix}...")
        print(f"[APIKeyManager] Plan: {plan}")

        return raw_key, client_id

    def validate_key(self, raw_key: str) -> Optional[ClientRecord]:
        """
        Validates an API key.

        Returns the ClientRecord if valid and active, None otherwise.
        Also updates last_used_at and increments request_count.
        """
        if not raw_key or not raw_key.startswith(KEY_PREFIX):
            return None

        key_hash = self._hash_key(raw_key)
        row = self._conn.execute(
            "SELECT * FROM clients WHERE key_hash=? AND is_active=1",
            (key_hash,)
        ).fetchone()

        if not row:
            return None

        # Update usage stats
        self._conn.execute("""
            UPDATE clients
            SET last_used_at=?, request_count=request_count+1
            WHERE key_hash=?
        """, (time.time(), key_hash))
        self._conn.commit()

        return self._row_to_record(row)

    def revoke_key(self, client_id: str) -> bool:
        """
        Revokes a client's API key immediately.
        The key cannot be used after revocation.
        """
        result = self._conn.execute(
            "UPDATE clients SET is_active=0 WHERE client_id=?",
            (client_id,)
        )
        self._conn.commit()
        revoked = result.rowcount > 0
        if revoked:
            print(f"[APIKeyManager] Key revoked for client: {client_id}")
        return revoked

    def rotate_key(self, client_id: str) -> Optional[str]:
        """
        Generates a new key for an existing client.
        The old key is immediately invalidated.
        Returns the new raw key, or None if client not found.
        """
        row = self._conn.execute(
            "SELECT * FROM clients WHERE client_id=?", (client_id,)
        ).fetchone()
        if not row:
            return None

        new_raw_key  = self._generate_raw_key()
        new_hash     = self._hash_key(new_raw_key)
        new_prefix   = new_raw_key[:len(KEY_PREFIX) + len(KEY_VERSION) + 1 + 8]

        self._conn.execute("""
            UPDATE clients
            SET key_hash=?, key_prefix=?, is_active=1
            WHERE client_id=?
        """, (new_hash, new_prefix, client_id))
        self._conn.commit()

        print(f"[APIKeyManager] Key rotated for client: {client_id}")
        return new_raw_key

    # -- Queries --------------------------------------------

    def get_client(self, client_id: str) -> Optional[ClientRecord]:
        row = self._conn.execute(
            "SELECT * FROM clients WHERE client_id=?", (client_id,)
        ).fetchone()
        return self._row_to_record(row) if row else None

    def list_clients(self, active_only: bool = True) -> list[ClientRecord]:
        query = "SELECT * FROM clients"
        if active_only:
            query += " WHERE is_active=1"
        query += " ORDER BY created_at DESC"
        rows = self._conn.execute(query).fetchall()
        return [self._row_to_record(r) for r in rows]

    def stats(self) -> dict:
        total   = self._conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
        active  = self._conn.execute("SELECT COUNT(*) FROM clients WHERE is_active=1").fetchone()[0]
        by_plan = {}
        for row in self._conn.execute(
            "SELECT plan, COUNT(*) as c FROM clients WHERE is_active=1 GROUP BY plan"
        ).fetchall():
            by_plan[row["plan"]] = row["c"]
        total_req = self._conn.execute(
            "SELECT SUM(request_count) FROM clients"
        ).fetchone()[0] or 0
        return {
            "total_clients":   total,
            "active_clients":  active,
            "revoked_clients": total - active,
            "by_plan":         by_plan,
            "total_requests":  total_req,
        }

    # -- Helper ---------------------------------------------

    def _row_to_record(self, row) -> ClientRecord:
        return ClientRecord(
            client_id    = row["client_id"],
            company_name = row["company_name"],
            email        = row["email"],
            key_hash     = row["key_hash"],
            key_prefix   = row["key_prefix"],
            created_at   = row["created_at"],
            last_used_at = row["last_used_at"],
            is_active    = bool(row["is_active"]),
            plan         = row["plan"],
            request_count = row["request_count"],
        )


# -- Quick test --------------------------------------------
if __name__ == "__main__":
    import json

    print("=" * 60)
    print("Vaultra ? API Key System Test")
    print("=" * 60)

    manager = APIKeyManager(db_path=":memory:")

    # Create a key
    print("\n1. Creating key for test client...")
    raw_key, client_id = manager.create_key(
        company_name="Fintech Corp S.A.",
        email="cto@fintech-corp.com",
        plan="starter",
    )
    print(f"   Raw key: {raw_key}")
    print(f"   Client ID: {client_id}")

    # Validate
    print("\n2. Validating key...")
    record = manager.validate_key(raw_key)
    if record:
        print(f"   Valid! Company: {record.company_name} | Plan: {record.plan}")
    else:
        print("   INVALID!")

    # Invalid key test
    print("\n3. Testing invalid key...")
    fake = manager.validate_key("vaultra_sk_v1_fakekeyfakekeyfakekeyfakekeyfakekeyfakekeyf")
    print(f"   Result: {'INVALID (correct)' if not fake else 'ERROR - should be invalid'}")

    # Rotate
    print("\n4. Rotating key...")
    new_key = manager.rotate_key(client_id)
    print(f"   New key: {new_key}")
    old_valid = manager.validate_key(raw_key)
    new_valid = manager.validate_key(new_key)
    print(f"   Old key valid: {old_valid is not None} (should be False after rotation)")
    print(f"   New key valid: {new_valid is not None} (should be True)")

    # Stats
    print("\n5. Stats:")
    print(json.dumps(manager.stats(), indent=2))

    print("\nAll tests passed!")
