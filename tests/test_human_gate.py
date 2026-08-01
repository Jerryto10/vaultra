# Copyright (c) 2026 Jerly Rojas
# Vaultra — AI Agent Compliance Layer
# https://vaultra.io
# AGPL-3.0 License. Commercial use: legal@vaultra.io

"""
test_human_gate.py — Regression test for F20: the Human Gate token was
handed back to the requesting caller (the return value of intercept()),
which let the very agent that requested an irreversible action read its
own approval_token and call decide() to self-approve. The fix keeps the
token server-side — it now reaches only the configured out-of-band
notification channels (_notify) — and decide() rejects any decision where
decided_by matches the original requester's agent_id/agent_name.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vaultra.human_gate import HumanGate, ApprovalStatus, QueueNotifier
import queue


def test_intercept_does_not_expose_approval_token_to_caller():
    """The object (and its to_dict()) returned by intercept() must not
    expose the real approval_token — only the out-of-band notifier gets it."""
    gate = HumanGate()
    q = queue.Queue()
    gate.add_notifier(QueueNotifier(q))

    result = gate.intercept(
        agent_id="agent-1",
        agent_name="Agent One",
        action="delete_file",
        context={"file": "report.pdf"},
        summary="Delete a report file",
    )

    assert result.status == ApprovalStatus.PENDING

    # Public surface (object attribute) must not carry the real token.
    assert result.approval_token == ""

    # Public surface (serialized dict) must not carry the token either.
    assert "approval_token" not in result.to_dict()

    # The real token did reach the out-of-band channel (notifier queue),
    # and is the one actually tracked as pending server-side.
    notified = q.get_nowait()
    assert notified.approval_token != ""
    assert notified.approval_token in gate._pending


def test_decide_rejects_self_approval_by_requesting_agent():
    """decide() must reject a decision where decided_by matches the
    agent_id of the agent that originally requested the action."""
    gate = HumanGate()
    q = queue.Queue()
    gate.add_notifier(QueueNotifier(q))

    gate.intercept(
        agent_id="agent-1",
        agent_name="Agent One",
        action="transfer_funds",
        context={"amount": 1000},
        summary="Wire funds to vendor",
    )

    # Only the out-of-band channel has the real token — simulate an
    # attacker/compromised agent that somehow obtained it anyway and
    # tries to approve its own request.
    notified = q.get_nowait()
    real_token = notified.approval_token

    result = gate.decide(real_token, "APPROVE", decided_by="agent-1")

    assert result.status == ApprovalStatus.REJECTED
    assert "auto-aprobaci" in result.rejection_reason.lower() or \
           "self-approval" in result.rejection_reason.lower()
    # The request must no longer be pending — a genuine operator cannot
    # retroactively approve it either, it was consumed as rejected.
    assert real_token not in gate._pending


def test_decide_allows_distinct_operator_to_approve():
    """A decided_by identity distinct from the requesting agent must still
    be able to approve normally (no unrelated behavior change)."""
    gate = HumanGate()
    q = queue.Queue()
    gate.add_notifier(QueueNotifier(q))

    gate.intercept(
        agent_id="agent-1",
        agent_name="Agent One",
        action="delete_file",
        context={"file": "report.pdf"},
        summary="Delete a report file",
    )

    notified = q.get_nowait()
    real_token = notified.approval_token

    result = gate.decide(real_token, "APPROVE", decided_by="ops_human_jane")

    assert result.status == ApprovalStatus.APPROVED
    assert result.decided_by == "ops_human_jane"
