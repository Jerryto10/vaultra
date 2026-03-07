# Copyright (c) 2026 Jerly Rojas
# Vaultra — AI Agent Compliance Layer
# https://vaultra.io
# AGPL-3.0 License. Commercial use: legal@vaultra.io

"""
identity.py — Ed25519 cryptographic identity per agent
"""

import hashlib
import json
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


class AgentIdentity:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self._private_key = Ed25519PrivateKey.generate()
        self.public_key = self._private_key.public_key()
        self.created_at = time.time()

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

    def fingerprint(self) -> str:
        pub_bytes = self.public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )
        return hashlib.sha256(pub_bytes).hexdigest()[:16]
