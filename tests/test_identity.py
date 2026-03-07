# Copyright (c) 2026 Jerly Rojas
# Vaultra — AI Agent Compliance Layer
# https://vaultra.io
# AGPL-3.0 License. Commercial use: legal@vaultra.io

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vaultra.identity import AgentIdentity


def test_identity_creation():
    agent = AgentIdentity("agent-001")
    assert agent.agent_id == "agent-001"
    assert agent.fingerprint() is not None
    print("✅ test_identity_creation passed")


def test_sign_and_verify():
    agent = AgentIdentity("agent-002")
    data = {"action": "approve_loan", "amount": 5000}
    signature = agent.sign(data)
    assert agent.verify(data, signature) is True
    print("✅ test_sign_and_verify passed")


def test_tampered_data_fails():
    agent = AgentIdentity("agent-003")
    data = {"action": "approve_loan", "amount": 5000}
    signature = agent.sign(data)
    tampered = {"action": "approve_loan", "amount": 99999}
    assert agent.verify(tampered, signature) is False
    print("✅ test_tampered_data_fails passed")


if __name__ == "__main__":
    test_identity_creation()
    test_sign_and_verify()
    test_tampered_data_fails()
    print("\n🎉 All tests passed!")
