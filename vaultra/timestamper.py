# Copyright (c) 2026 Jerly Rojas
# Vaultra — AI Agent Compliance Layer
# https://vaultra.io
# AGPL-3.0 License. Commercial use: legal@vaultra.io

"""
timestamper.py — RFC 3161 Trusted Timestamp Authority integration
=================================================================
Sends the SHA-256 hash of a Compliance Receipt to a public TSA
(Timestamp Authority) and returns a signed timestamp token.

The token proves — to any auditor or regulator — that the receipt
existed at a specific moment in time, and has not been modified since.

Legal basis: eIDAS Regulation (EU) No 910/2014, Article 41
TSA used: freetsa.org (production: DigiCert / Comodo)

Workflow:
  receipt_hash → TSA request → signed .tsr token → stored in Ledger
"""

import hashlib
import struct
import base64
import time
import requests
from dataclasses import dataclass
from typing import Optional


# ── TSA Endpoints ─────────────────────────────────────────────────────
TSA_SERVERS = {
    "freetsa":  "https://freetsa.org/tsr",        # Free, good for MVP
    "digicert": "https://timestamp.digicert.com",  # Production
    "comodo":   "http://timestamp.comodoca.com",   # Production backup
}

DEFAULT_TSA = "digicert"


# ── Result dataclass ──────────────────────────────────────────────────
@dataclass
class TimestampResult:
    success: bool
    receipt_hash: str          # SHA-256 of the original content
    tsr_token_b64: str         # Base64-encoded .tsr token from TSA
    tsa_url: str               # Which TSA was used
    timestamp_utc: float       # Unix timestamp when token was received
    token_size_bytes: int      # Size of the TSA response
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "rfc3161_timestamp": {
                "success":          self.success,
                "receipt_hash":     self.receipt_hash,
                "tsr_token_b64":    self.tsr_token_b64,
                "tsa_url":          self.tsa_url,
                "timestamp_utc":    self.timestamp_utc,
                "token_size_bytes": self.token_size_bytes,
                "error":            self.error,
                "legal_basis":      "eIDAS Regulation (EU) No 910/2014, Art. 41",
                "standard":         "RFC 3161 — Internet X.509 PKI Timestamp Protocol",
            }
        }

    def summary(self) -> str:
        if self.success:
            t = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(self.timestamp_utc))
            return (
                f"✅ RFC 3161 Timestamp obtained\n"
                f"   Hash:    {self.receipt_hash[:32]}...\n"
                f"   TSA:     {self.tsa_url}\n"
                f"   Time:    {t}\n"
                f"   Token:   {self.token_size_bytes} bytes"
            )
        return f"❌ Timestamp failed: {self.error}"


# ── Core functions ────────────────────────────────────────────────────

def _build_ts_request(content_hash: bytes) -> bytes:
    """
    Builds a minimal RFC 3161 TimeStampReq in DER encoding.

    Structure (ASN.1):
      TimeStampReq ::= SEQUENCE {
        version        INTEGER { v1(1) },
        messageImprint MessageImprint,
        nonce          INTEGER OPTIONAL,
        certReq        BOOLEAN DEFAULT FALSE
      }
      MessageImprint ::= SEQUENCE {
        hashAlgorithm  AlgorithmIdentifier,  -- SHA-256 OID
        hashedMessage  OCTET STRING
      }
    """
    # SHA-256 OID: 2.16.840.1.101.3.4.2.1
    sha256_oid = bytes([
        0x30, 0x0d,                          # SEQUENCE (13 bytes)
        0x06, 0x09,                          # OID (9 bytes)
        0x60, 0x86, 0x48, 0x01, 0x65,
        0x03, 0x04, 0x02, 0x01,              # SHA-256 OID value
        0x05, 0x00                           # NULL params
    ])

    # hashedMessage OCTET STRING
    hash_octet = bytes([0x04, len(content_hash)]) + content_hash

    # MessageImprint SEQUENCE
    msg_imprint_inner = sha256_oid + hash_octet
    msg_imprint = bytes([0x30, len(msg_imprint_inner)]) + msg_imprint_inner

    # version INTEGER v1
    version = bytes([0x02, 0x01, 0x01])

    # nonce INTEGER (8 random bytes for replay protection)
    import os
    nonce_val = os.urandom(8)
    nonce = bytes([0x02, len(nonce_val)]) + nonce_val

    # certReq BOOLEAN TRUE (ask TSA to include its certificate)
    cert_req = bytes([0x01, 0x01, 0xff])

    # Outer SEQUENCE
    inner = version + msg_imprint + nonce + cert_req
    request = bytes([0x30, len(inner)]) + inner

    return request


def stamp(content: str, tsa: str = DEFAULT_TSA) -> TimestampResult:
    """
    Main function. Sends content hash to TSA and returns a TimestampResult.

    Args:
        content: The string to timestamp (typically the receipt JSON)
        tsa:     TSA key from TSA_SERVERS dict

    Returns:
        TimestampResult with the signed token or error details
    """
    tsa_url = TSA_SERVERS.get(tsa, TSA_SERVERS[DEFAULT_TSA])

    # 1. Hash the content
    content_hash = hashlib.sha256(content.encode("utf-8")).digest()
    content_hash_hex = content_hash.hex()

    print(f"[Timestamper] Hashing content → {content_hash_hex[:16]}...")

    try:
        # 2. Build RFC 3161 request
        ts_request = _build_ts_request(content_hash)

        # 3. Send to TSA
        print(f"[Timestamper] Sending to TSA: {tsa_url}")
        response = requests.post(
            tsa_url,
            data=ts_request,
            headers={"Content-Type": "application/timestamp-query"},
            timeout=15,
        )

        if response.status_code != 200:
            return TimestampResult(
                success=False,
                receipt_hash=content_hash_hex,
                tsr_token_b64="",
                tsa_url=tsa_url,
                timestamp_utc=time.time(),
                token_size_bytes=0,
                error=f"TSA returned HTTP {response.status_code}",
            )

        # 4. Encode response token
        tsr_bytes = response.content
        tsr_b64 = base64.b64encode(tsr_bytes).decode("utf-8")

        result = TimestampResult(
            success=True,
            receipt_hash=content_hash_hex,
            tsr_token_b64=tsr_b64,
            tsa_url=tsa_url,
            timestamp_utc=time.time(),
            token_size_bytes=len(tsr_bytes),
        )

        print(result.summary())
        return result

    except requests.exceptions.Timeout:
        return TimestampResult(
            success=False,
            receipt_hash=content_hash_hex,
            tsr_token_b64="",
            tsa_url=tsa_url,
            timestamp_utc=time.time(),
            token_size_bytes=0,
            error="TSA request timed out (15s)",
        )
    except Exception as e:
        return TimestampResult(
            success=False,
            receipt_hash=content_hash_hex,
            tsr_token_b64="",
            tsa_url=tsa_url,
            timestamp_utc=time.time(),
            token_size_bytes=0,
            error=str(e),
        )


def verify_hash(content: str, expected_hash: str) -> bool:
    """
    Verifies that content matches a previously recorded hash.
    Used to confirm a receipt has not been modified since timestamping.
    """
    actual = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return actual == expected_hash


# ── Quick test ────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("Vaultra — RFC 3161 Timestamp Test")
    print("=" * 60)

    test_receipt = '{"agent_id": "fintech-001", "decision": "loan_approved", "amount": 5000, "timestamp": 1741564800}'

    result = stamp(test_receipt)
    print("\nFull result dict:")
    import json
    print(json.dumps(result.to_dict(), indent=2))

    print("\nHash verification:")
    print("  Match:", verify_hash(test_receipt, result.receipt_hash))
    print("  Tamper test:", verify_hash(test_receipt + "modified", result.receipt_hash))
