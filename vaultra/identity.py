# Copyright (c) 2026 Jerly Rojas
# Vaultra — AI Agent Compliance Layer
# https://vaultra.io
# AGPL-3.0 License. Commercial use: legal@vaultra.io

"""
identity.py — Ed25519 cryptographic identity per agent

The keypair is persisted to a local PEM file (default
``~/.vaultra/keys/<agent_id>.pem``) so an agent's identity is stable across
process restarts instead of being regenerated — and therefore unverifiable —
on every run. The private key never leaves this file / process; only the
signature, fingerprint, and raw public key are ever transmitted.
"""

import hashlib
import json
import os
import time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


class AgentIdentity:
    def __init__(self, agent_id: str, key_path: str = None):
        self.agent_id = agent_id
        self.key_path = Path(key_path) if key_path else (
            Path.home() / ".vaultra" / "keys" / f"{agent_id}.pem"
        )
        self._private_key = self._load_or_generate_key(self.key_path)
        self.public_key = self._private_key.public_key()
        self.created_at = time.time()

    @staticmethod
    def _load_or_generate_key(key_path: Path) -> Ed25519PrivateKey:
        """Load the persisted keypair at ``key_path``, or generate one and
        persist it (PEM, private-key file permissions 0600) if none exists."""
        if key_path.exists():
            pem_bytes = key_path.read_bytes()
            return serialization.load_pem_private_key(pem_bytes, password=None)

        private_key = Ed25519PrivateKey.generate()
        key_path.parent.mkdir(parents=True, exist_ok=True)
        pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # Create with 0600 from the outset — never a window where the
        # private key is group/world readable.
        fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem_bytes)
        return private_key

    def sign(self, data: dict) -> bytes:
        payload = json.dumps(data, sort_keys=True).encode()
        return self._private_key.sign(payload)

    def verify(self, data: dict, signature: bytes) -> bool:
        try:
            payload = json.dumps(data, sort_keys=True).encode()
            self.public_key.verify(signature, payload)
            return True
        except Exception:
            return False

    def public_key_bytes(self) -> bytes:
        """Raw-encoded public key bytes (same encoding fingerprint() uses)."""
        return self.public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )

    def public_key_hex(self) -> str:
        """Hex-encoded raw public key, suitable for JSON transport."""
        return self.public_key_bytes().hex()

    def fingerprint(self) -> str:
        return hashlib.sha256(self.public_key_bytes()).hexdigest()[:16]
