# Copyright (c) 2026 Jerly Rojas
# Vaultra — AI Agent Compliance Layer
# https://vaultra.io
# AGPL-3.0 License. Commercial use: legal@vaultra.io

"""
test_guardian.py — Regression test for F14: the offline Guardian must not
suppress pii_exposure just because the agent's scope permits sending email
or messages. Suppression was previously gated on a keyword denylist
("evil", "attacker", "exfil", "steal", "ssn", "credit card", "123-45"),
which a raw PII pattern (e.g. a bare SSN or credit-card number with no
denylist keyword nearby) would sail straight past.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vaultra.guardian import OfflineGuard, GuardVerdict


def test_pii_exposure_not_suppressed_when_scope_allows_email():
    """A raw SSN in the output must still flag pii_exposure and must not be
    approved, even though the agent's scope includes send_email and the
    output contains none of the denylist keywords."""
    guard = OfflineGuard()

    result = guard.evaluate(
        agent_purpose="Send account summary emails to customers",
        agent_scope=["send_email"],
        input_text="Please email the customer their account details.",
        output_text="Sure, emailing now. Customer SSN on file: 123-45-6789.",
    )

    assert "pii_exposure" in result.risks_detected
    assert result.verdict != GuardVerdict.APPROVED


def test_pii_exposure_not_suppressed_for_share_or_send_message_scope():
    """Same guarantee for the other scopes that previously triggered
    suppression: send_message and share."""
    guard = OfflineGuard()

    for scope in ("send_message", "share"):
        result = guard.evaluate(
            agent_purpose="Share customer info with the support agent",
            agent_scope=[scope],
            input_text="Forward the customer's payment details.",
            output_text="Card number on file: 4111 2222 3333 4444.",
        )

        assert "pii_exposure" in result.risks_detected, f"scope={scope}"
        assert result.verdict != GuardVerdict.APPROVED, f"scope={scope}"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
