# Copyright (c) 2026 Jerly Rojas
# Vaultra — AI Agent Compliance Layer
# https://vaultra.io
# AGPL-3.0 License. Commercial use: legal@vaultra.io

"""
test_admin_receipt.py — Flask-test-client coverage for admin/app.py's
public /api/receipt ingestion endpoint.

Task 1.8 (F21 2/4): the SDK now sends identity_signature, identity_fingerprint
and identity_public_key alongside every receipt. This module covers the
server-side registry/enrollment/conflict-detection logic that reacts to those
fields:
  - first receipt for a new (client_id, agent_id) enrolls the key as 'active'
  - a repeat receipt with the same key just refreshes last_seen, no conflict
  - a receipt with a *different* key for an already-enrolled agent does not
    clobber the registry, and instead files exactly one pending conflict —
    while the receipt itself is still stored/accepted (the api_key already
    authenticated the request; only the identity-trust upgrade is paused).

There is no pre-existing test module for admin/app.py, so this file sets up
its own minimal, isolated Flask-test-client fixture rather than following an
established convention. Isolation notes:
  - DB_PATH (admin/app.py, module-level constant read once at import time)
    is monkeypatched to a per-test tmp_path file *before* first import, and
    for every subsequent test directly on the already-imported module object
    (functions in admin/app.py resolve DB_PATH as a module global at call
    time, so patching the attribute on the module is sufficient — no need to
    force a re-import per test).
  - init_db() is called against that temp path for every test, so each test
    gets its own fresh schema/tables and no state leaks between tests or into
    the real vaultra_admin.db.
"""

import hashlib
import importlib
import os
import sqlite3
import sys
import time
import uuid

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def admin_app_module(tmp_path, monkeypatch):
    """Import (or reuse) admin.app with DB_PATH pointed at an isolated,
    per-test SQLite file, and a freshly-initialized schema in it."""
    db_path = tmp_path / "test_admin.db"

    monkeypatch.setenv("DB_PATH", str(db_path))
    monkeypatch.setenv("SECRET_KEY", "test-only-secret-key-do-not-use-in-prod")
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("SUPPORT_PASSWORD", "test-support-password")

    if "admin.app" in sys.modules:
        mod = sys.modules["admin.app"]
        # DB_PATH is read from the environment once at import time; on
        # re-use (module already imported by an earlier test) patch the
        # module attribute directly so every function in admin/app.py that
        # references the DB_PATH global picks up the new path.
        monkeypatch.setattr(mod, "DB_PATH", str(db_path))
    else:
        mod = importlib.import_module("admin.app")

    mod.init_db()
    mod.app.config.update(TESTING=True)
    return mod


@pytest.fixture
def client(admin_app_module):
    return admin_app_module.app.test_client()


def _make_client_row(admin_app_module, api_key="vaultra_sk_test_abc123"):
    """Insert a minimal, active client row directly, so /api/receipt's
    api_key lookup succeeds without going through the admin onboarding UI
    (out of scope here)."""
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    client_id = str(uuid.uuid4())
    conn = sqlite3.connect(admin_app_module.DB_PATH)
    try:
        conn.execute(
            """INSERT INTO clients
               (id, company_name, email, plan, status, api_key_hash,
                api_key_prefix, created_at, monthly_limit, receipt_count,
                month_start, month_count, archived)
               VALUES (?, 'Test Co', ?, 'starter', 'active', ?, ?, ?, 100000,
                       0, 0, 0, 0)""",
            (client_id, f"{client_id}@example.com", key_hash, api_key[:12], time.time()),
        )
        conn.commit()
    finally:
        conn.close()
    return client_id, api_key


def _post_receipt(client, api_key, agent_id="agent-1", public_key=None, fingerprint=None, signature=None):
    body = {
        "api_key": api_key,
        "agent_id": agent_id,
        "decision": "APPROVE",
        "decision_type": "LOAN_APPROVED",
        "input_hash": "deadbeef",
        "block_number": 1,
        "regulation": "EU AI Act",
    }
    if public_key is not None:
        body["identity_public_key"] = public_key
    if fingerprint is not None:
        body["identity_fingerprint"] = fingerprint
    if signature is not None:
        body["identity_signature"] = signature
    return client.post("/api/receipt", json=body)


def _agent_keys_row(admin_app_module, client_id, agent_id):
    conn = sqlite3.connect(admin_app_module.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT * FROM agent_keys WHERE client_id=? AND agent_id=?",
            (client_id, agent_id),
        ).fetchone()
    finally:
        conn.close()


def _conflict_rows(admin_app_module, client_id, agent_id):
    conn = sqlite3.connect(admin_app_module.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT * FROM agent_key_conflicts WHERE client_id=? AND agent_id=?",
            (client_id, agent_id),
        ).fetchall()
    finally:
        conn.close()


def _receipt_row(admin_app_module, receipt_id):
    conn = sqlite3.connect(admin_app_module.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT * FROM receipts WHERE id=?", (receipt_id,)
        ).fetchone()
    finally:
        conn.close()


PUB_KEY_A = "aa" * 32
PUB_KEY_B = "bb" * 32
FINGERPRINT_A = "a1b2c3d4e5f60718"
FINGERPRINT_B = "1122334455667788"
SIGNATURE = "cc" * 64


def test_first_receipt_enrolls_key_as_active(admin_app_module, client):
    client_id, api_key = _make_client_row(admin_app_module)

    resp = _post_receipt(
        client, api_key, agent_id="agent-1",
        public_key=PUB_KEY_A, fingerprint=FINGERPRINT_A, signature=SIGNATURE,
    )
    assert resp.status_code == 200
    assert resp.get_json()["success"] is True

    row = _agent_keys_row(admin_app_module, client_id, "agent-1")
    assert row is not None
    assert row["public_key"] == PUB_KEY_A
    assert row["fingerprint"] == FINGERPRINT_A
    assert row["status"] == "active"
    assert row["first_seen"] == row["last_seen"]

    # No conflicts should exist from a first-ever enrollment.
    assert _conflict_rows(admin_app_module, client_id, "agent-1") == []


def test_repeat_receipt_same_key_updates_last_seen_no_conflict(admin_app_module, client):
    client_id, api_key = _make_client_row(admin_app_module)

    _post_receipt(
        client, api_key, agent_id="agent-1",
        public_key=PUB_KEY_A, fingerprint=FINGERPRINT_A, signature=SIGNATURE,
    )
    first_row = _agent_keys_row(admin_app_module, client_id, "agent-1")

    # Ensure a measurable last_seen delta.
    time.sleep(0.01)

    resp = _post_receipt(
        client, api_key, agent_id="agent-1",
        public_key=PUB_KEY_A, fingerprint=FINGERPRINT_A, signature=SIGNATURE,
    )
    assert resp.status_code == 200

    second_row = _agent_keys_row(admin_app_module, client_id, "agent-1")
    assert second_row["public_key"] == PUB_KEY_A
    assert second_row["first_seen"] == first_row["first_seen"]
    assert second_row["last_seen"] >= first_row["last_seen"]
    assert second_row["status"] == "active"

    assert _conflict_rows(admin_app_module, client_id, "agent-1") == []


def test_conflicting_key_does_not_overwrite_registry_but_files_conflict(admin_app_module, client):
    client_id, api_key = _make_client_row(admin_app_module)

    _post_receipt(
        client, api_key, agent_id="agent-1",
        public_key=PUB_KEY_A, fingerprint=FINGERPRINT_A, signature=SIGNATURE,
    )

    resp = _post_receipt(
        client, api_key, agent_id="agent-1",
        public_key=PUB_KEY_B, fingerprint=FINGERPRINT_B, signature=SIGNATURE,
    )
    # Ingestion is never blocked by an identity-trust conflict — the api_key
    # already authenticated this request.
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["success"] is True
    receipt_id = body["receipt_id"]

    # Registry entry must remain the original key, untouched.
    row = _agent_keys_row(admin_app_module, client_id, "agent-1")
    assert row["public_key"] == PUB_KEY_A

    conflicts = _conflict_rows(admin_app_module, client_id, "agent-1")
    assert len(conflicts) == 1
    conflict = conflicts[0]
    assert conflict["status"] == "pending"
    assert conflict["existing_public_key"] == PUB_KEY_A
    assert conflict["incoming_public_key"] == PUB_KEY_B
    assert conflict["incoming_fingerprint"] == FINGERPRINT_B
    assert conflict["receipt_id"] == receipt_id

    # The receipt itself was still stored/accepted, with its identity fields.
    receipt = _receipt_row(admin_app_module, receipt_id)
    assert receipt is not None
    assert receipt["identity_fingerprint"] == FINGERPRINT_B
    assert receipt["identity_signature"] == SIGNATURE


def test_receipt_without_identity_fields_is_accepted_without_enrollment(admin_app_module, client):
    """Older SDKs (pre-1.7) won't send identity_* fields at all — receipt
    ingestion must still work, and no registry row should be created."""
    client_id, api_key = _make_client_row(admin_app_module)

    resp = _post_receipt(client, api_key, agent_id="agent-legacy")
    assert resp.status_code == 200
    assert resp.get_json()["success"] is True

    assert _agent_keys_row(admin_app_module, client_id, "agent-legacy") is None


def test_invalid_api_key_rejected(admin_app_module, client):
    resp = _post_receipt(client, "not-a-real-key", agent_id="agent-1")
    assert resp.status_code == 401
    assert resp.get_json()["success"] is False
