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
        output_text="Sure, emailing now. Customer's ID number on file: 987-65-4321.",
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


# ---------------------------------------------------------------------------
# Task 1.6: the remaining ~15 OUTPUT_RISK_PATTERNS across the other 5 risk
# categories carried stray literal backspace bytes (\x08) flanking the
# pattern text since the file's first commit — invisible in a normal editor
# or diff, but fatal to matching, since real output text never contains a
# literal 0x08 byte. Each pattern below is one that was previously corrupted
# and would never have matched; these regression tests assert the repaired,
# plain regex now actually fires on representative text.
# ---------------------------------------------------------------------------

def test_data_exfiltration_matches_after_backspace_strip():
    """Pattern `(sending|forwarding|transmitting|uploading)...` was corrupted
    with flanking \\x08 bytes; confirm it now matches."""
    guard = OfflineGuard()

    result = guard.evaluate(
        agent_purpose="Summarize account activity",
        agent_scope=["read_only"],
        input_text="Can you summarize recent activity?",
        output_text="I am transmitting your account information to the partner service now.",
    )

    assert "data_exfiltration" in result.risks_detected


def test_scope_deviation_matches_after_backspace_strip():
    """Pattern `(i have )?(accessed|modified|deleted|changed)...` was
    corrupted with flanking \\x08 bytes; confirm it now matches."""
    guard = OfflineGuard()

    result = guard.evaluate(
        agent_purpose="Answer customer questions",
        agent_scope=["read_only"],
        input_text="Can you update my record?",
        output_text="I have changed your data file as requested.",
    )

    assert "scope_deviation" in result.risks_detected


def test_instruction_propagation_matches_after_backspace_strip():
    """Pattern `new instructions? for (all|every|other) (agent|bot)` was
    corrupted with flanking \\x08 bytes; confirm it now matches."""
    guard = OfflineGuard()

    result = guard.evaluate(
        agent_purpose="Coordinate with other agents",
        agent_scope=["message_agents"],
        input_text="Let the other agents know about the change.",
        output_text="Here are new instructions for all agents to follow going forward.",
    )

    assert "instruction_propagation" in result.risks_detected


def test_tool_abuse_matches_after_backspace_strip():
    """Pattern `(calling|invoking|executing) (unauthorized|restricted|
    forbidden) (tool|function|api)` was corrupted with flanking \\x08 bytes;
    confirm it now matches."""
    guard = OfflineGuard()

    result = guard.evaluate(
        agent_purpose="Perform approved API calls only",
        agent_scope=["approved_api"],
        input_text="Complete the requested task.",
        output_text="Invoking unauthorized tool to complete this task.",
    )

    assert "tool_abuse" in result.risks_detected


def test_deception_matches_after_backspace_strip():
    """Pattern `(pretend|fake|simulate|disguise) (that|this|the) (result|
    output|response)` was corrupted with flanking \\x08 bytes; confirm it
    now matches."""
    guard = OfflineGuard()

    result = guard.evaluate(
        agent_purpose="Report task status honestly",
        agent_scope=["status_report"],
        input_text="What's the status of the task?",
        output_text="Let's pretend this output is fine and move on.",
    )

    assert "deception" in result.risks_detected


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
