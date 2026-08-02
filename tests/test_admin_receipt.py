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
import json
import os
import sqlite3
import sys
import time
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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


# ── Task 1.9 (F21 3/4): admin UI to list/approve/reject pending key
# conflicts filed by the receive_receipt() differ-branch above. ──────────

CSRF_TOKEN = "test-only-csrf-token"


def _login_as_admin(client, username="alice", role="admin"):
    """Simulate an authenticated admin-panel session directly via Flask's
    test-client session transaction, mirroring how login_required/
    admin_required read session['admin_id']/['role'] (admin/app.py ~lines
    469-490). Also seeds a known csrf_token so POSTs can satisfy
    enforce_csrf() (admin/app.py ~line 106) by echoing it back as the
    X-CSRF-Token header — /agent-keys/<id>/resolve is a mutating route and
    is not in CSRF_EXEMPT_PATHS."""
    with client.session_transaction() as sess:
        sess["admin_id"] = str(uuid.uuid4())
        sess["username"] = username
        sess["role"] = role
        sess["csrf_token"] = CSRF_TOKEN
        sess["last_active"] = time.time()


def _seed_agent_key(admin_app_module, client_id, agent_id, public_key, fingerprint, now=None):
    now = now if now is not None else time.time()
    conn = sqlite3.connect(admin_app_module.DB_PATH)
    try:
        conn.execute(
            """INSERT INTO agent_keys
               (client_id, agent_id, public_key, fingerprint, status,
                first_seen, last_seen)
               VALUES (?, ?, ?, ?, 'active', ?, ?)""",
            (client_id, agent_id, public_key, fingerprint, now, now),
        )
        conn.commit()
    finally:
        conn.close()


def _seed_conflict(admin_app_module, client_id, agent_id, existing_key,
                    incoming_key, incoming_fingerprint, receipt_id=None,
                    created_at=None, status="pending"):
    conflict_id = str(uuid.uuid4())
    created_at = created_at if created_at is not None else time.time()
    conn = sqlite3.connect(admin_app_module.DB_PATH)
    try:
        conn.execute(
            """INSERT INTO agent_key_conflicts
               (id, client_id, agent_id, existing_public_key,
                incoming_public_key, incoming_fingerprint, receipt_id,
                status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (conflict_id, client_id, agent_id, existing_key, incoming_key,
             incoming_fingerprint, receipt_id, status, created_at),
        )
        conn.commit()
    finally:
        conn.close()
    return conflict_id


def test_resolve_approve_updates_agent_keys_and_resolves_conflict(admin_app_module, client):
    client_id, _ = _make_client_row(admin_app_module)
    _seed_agent_key(admin_app_module, client_id, "agent-1", PUB_KEY_A, FINGERPRINT_A)
    conflict_id = _seed_conflict(
        admin_app_module, client_id, "agent-1",
        existing_key=PUB_KEY_A, incoming_key=PUB_KEY_B,
        incoming_fingerprint=FINGERPRINT_B, receipt_id="rid-1",
    )

    _login_as_admin(client)
    resp = client.post(
        f"/agent-keys/{conflict_id}/resolve",
        json={"action": "approve"},
        headers={"X-CSRF-Token": CSRF_TOKEN},
    )
    assert resp.status_code == 200
    assert resp.get_json()["success"] is True

    key_row = _agent_keys_row(admin_app_module, client_id, "agent-1")
    assert key_row["public_key"] == PUB_KEY_B
    assert key_row["fingerprint"] == FINGERPRINT_B
    assert key_row["status"] == "active"

    conflicts = _conflict_rows(admin_app_module, client_id, "agent-1")
    assert len(conflicts) == 1
    assert conflicts[0]["status"] == "resolved"
    assert conflicts[0]["resolved_at"] is not None
    assert conflicts[0]["resolved_by"] == "alice"


def test_resolve_reject_leaves_agent_keys_untouched(admin_app_module, client):
    client_id, _ = _make_client_row(admin_app_module)
    _seed_agent_key(admin_app_module, client_id, "agent-1", PUB_KEY_A, FINGERPRINT_A)
    conflict_id = _seed_conflict(
        admin_app_module, client_id, "agent-1",
        existing_key=PUB_KEY_A, incoming_key=PUB_KEY_B,
        incoming_fingerprint=FINGERPRINT_B, receipt_id="rid-2",
    )

    _login_as_admin(client)
    resp = client.post(
        f"/agent-keys/{conflict_id}/resolve",
        json={"action": "reject"},
        headers={"X-CSRF-Token": CSRF_TOKEN},
    )
    assert resp.status_code == 200
    assert resp.get_json()["success"] is True

    key_row = _agent_keys_row(admin_app_module, client_id, "agent-1")
    assert key_row["public_key"] == PUB_KEY_A  # untouched
    assert key_row["fingerprint"] == FINGERPRINT_A

    conflicts = _conflict_rows(admin_app_module, client_id, "agent-1")
    assert len(conflicts) == 1
    assert conflicts[0]["status"] == "resolved"
    assert conflicts[0]["resolved_by"] == "alice"


def test_resolve_group_resolves_all_duplicate_pending_rows(admin_app_module, client):
    """Carry-forward from Task 1.8's review: a replayed leaked api_key can
    file many duplicate pending rows for the same (client_id, agent_id,
    incoming_public_key). Resolving via any one of their ids must resolve
    the whole group, not just the row whose id was passed."""
    client_id, _ = _make_client_row(admin_app_module)
    _seed_agent_key(admin_app_module, client_id, "agent-1", PUB_KEY_A, FINGERPRINT_A)
    ids = [
        _seed_conflict(
            admin_app_module, client_id, "agent-1",
            existing_key=PUB_KEY_A, incoming_key=PUB_KEY_B,
            incoming_fingerprint=FINGERPRINT_B, receipt_id=f"rid-dup-{i}",
            created_at=time.time() + i,
        )
        for i in range(3)
    ]
    # An unrelated conflict for a different agent must not be touched.
    other_conflict_id = _seed_conflict(
        admin_app_module, client_id, "agent-2",
        existing_key=PUB_KEY_A, incoming_key=PUB_KEY_B,
        incoming_fingerprint=FINGERPRINT_B, receipt_id="rid-other",
    )

    _login_as_admin(client)
    resp = client.post(
        f"/agent-keys/{ids[0]}/resolve",
        json={"action": "reject"},
        headers={"X-CSRF-Token": CSRF_TOKEN},
    )
    assert resp.status_code == 200

    resolved = _conflict_rows(admin_app_module, client_id, "agent-1")
    assert len(resolved) == 3
    assert all(r["status"] == "resolved" for r in resolved)

    untouched = _conflict_rows(admin_app_module, client_id, "agent-2")
    assert len(untouched) == 1
    assert untouched[0]["id"] == other_conflict_id
    assert untouched[0]["status"] == "pending"


def test_agent_keys_list_groups_duplicate_pending_conflicts(admin_app_module, client):
    client_id, _ = _make_client_row(admin_app_module)
    _seed_agent_key(admin_app_module, client_id, "agent-1", PUB_KEY_A, FINGERPRINT_A)
    for i in range(3):
        _seed_conflict(
            admin_app_module, client_id, "agent-1",
            existing_key=PUB_KEY_A, incoming_key=PUB_KEY_B,
            incoming_fingerprint=FINGERPRINT_B, receipt_id=f"rid-{i}",
            created_at=time.time() + i,
        )

    _login_as_admin(client)
    resp = client.get("/agent-keys")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # One collapsed row for the 3 duplicate pending conflicts (only one
    # "row-<id>" table row), showing a count rather than 3 separate
    # identical entries.
    assert body.count('id="row-') == 1
    assert "agent-1" in body


def test_resolve_requires_admin_role(admin_app_module, client):
    client_id, _ = _make_client_row(admin_app_module)
    _seed_agent_key(admin_app_module, client_id, "agent-1", PUB_KEY_A, FINGERPRINT_A)
    conflict_id = _seed_conflict(
        admin_app_module, client_id, "agent-1",
        existing_key=PUB_KEY_A, incoming_key=PUB_KEY_B,
        incoming_fingerprint=FINGERPRINT_B,
    )

    _login_as_admin(client, username="bob", role="support")
    resp = client.post(
        f"/agent-keys/{conflict_id}/resolve",
        json={"action": "approve"},
        headers={"X-CSRF-Token": CSRF_TOKEN},
    )
    assert resp.status_code == 403

    conflicts = _conflict_rows(admin_app_module, client_id, "agent-1")
    assert conflicts[0]["status"] == "pending"


# ── Task 1.10 (F21 4/4): /api/verify/<rid> — real Ed25519 signature check
# against the agent_keys registry enrolled by receive_receipt() above. ──────

def _signable(agent_id, input_hash, decision, decision_type, block):
    """Mirror the exact dict vaultra/pipeline.py signs (see _send_receipt /
    the `signable` construction around line 365): same four data fields plus
    `block` (which maps to the receipt's `block_number` column), JSON-encoded
    with sort_keys=True before signing."""
    return {
        "agent_id": agent_id,
        "input_hash": input_hash,
        "decision": decision,
        "decision_type": decision_type,
        "block": block,
    }


def _sign(private_key, agent_id, input_hash, decision, decision_type, block):
    payload = json.dumps(
        _signable(agent_id, input_hash, decision, decision_type, block),
        sort_keys=True,
    ).encode()
    return private_key.sign(payload)


def _public_key_hex(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def test_verify_receipt_valid_signature_is_identity_verified(admin_app_module, client):
    """Happy path: a receipt whose identity_signature verifies against the
    key registered for (client_id, agent_id) at enrollment must come back
    identity_verified: true. `decision` here ("APPROVE") is plain ASCII with
    no '<'/'>' and well under 2000 chars, so sanitize_text at ingestion is a
    no-op on it — the stored `decision` column matches exactly what was
    signed, so this demonstrates a genuine successful verification rather
    than an accidental false negative (see Task 1.10 brief's note on
    sanitize_text truncation/stripping as an accepted false-negative case)."""
    client_id, api_key = _make_client_row(admin_app_module)
    private_key = Ed25519PrivateKey.generate()
    public_key_hex = _public_key_hex(private_key)
    signature_hex = _sign(
        private_key, "agent-1", "deadbeef", "APPROVE", "LOAN_APPROVED", 1
    ).hex()

    post_resp = _post_receipt(
        client, api_key, agent_id="agent-1",
        public_key=public_key_hex, fingerprint=FINGERPRINT_A, signature=signature_hex,
    )
    rid = post_resp.get_json()["receipt_id"]

    resp = client.get(f"/api/verify/{rid}")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["identity_verified"] is True
    # Must never be conflated with the (still-False, per the F1 fix) RFC 3161
    # / eIDAS fields.
    assert body["rfc3161_valid"] is False
    assert body["eidas_art41"] is False


def test_verify_receipt_signature_not_matching_registered_key_is_unverified(admin_app_module, client):
    """A signature produced by a *different* keypair than the one enrolled
    for (client_id, agent_id) must not verify — even though a public key IS
    registered and a signature IS present."""
    client_id, api_key = _make_client_row(admin_app_module)
    enrolled_key = Ed25519PrivateKey.generate()
    attacker_key = Ed25519PrivateKey.generate()
    enrolled_public_key_hex = _public_key_hex(enrolled_key)

    # First receipt enrolls `enrolled_key` as the trusted key for agent-1.
    first = _post_receipt(
        client, api_key, agent_id="agent-1",
        public_key=enrolled_public_key_hex, fingerprint=FINGERPRINT_A,
        signature=_sign(enrolled_key, "agent-1", "deadbeef", "APPROVE", "LOAN_APPROVED", 1).hex(),
    )
    assert first.get_json()["success"] is True

    # Second receipt claims the same (already-enrolled) public key in its
    # identity_public_key field (so no conflict is filed / registry is
    # untouched), but its identity_signature was actually produced by a
    # different, unregistered key — e.g. a forged/replayed signature.
    forged_signature_hex = _sign(
        attacker_key, "agent-1", "cafebabe", "REJECT", "LOAN_REJECTED", 2
    ).hex()
    second = _post_receipt(
        client, api_key, agent_id="agent-1",
        public_key=enrolled_public_key_hex, fingerprint=FINGERPRINT_A,
        signature=forged_signature_hex,
    )
    rid = second.get_json()["receipt_id"]

    resp = client.get(f"/api/verify/{rid}")
    assert resp.status_code == 200
    assert resp.get_json()["identity_verified"] is False


def test_verify_receipt_no_registered_key_is_unverified(admin_app_module, client):
    """No agent_keys entry at all for (client_id, agent_id) — e.g. an older
    SDK (pre-1.7) that never sent identity_* fields — must yield
    identity_verified: false, not omitted and never defaulted to true."""
    client_id, api_key = _make_client_row(admin_app_module)
    post_resp = _post_receipt(client, api_key, agent_id="agent-legacy")
    rid = post_resp.get_json()["receipt_id"]

    resp = client.get(f"/api/verify/{rid}")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["identity_verified"] is False
    assert body["valid"] is True  # receipt itself is still a valid record
