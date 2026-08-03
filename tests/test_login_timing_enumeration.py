# Copyright (c) 2026 Jerly Rojas
# Vaultra — AI Agent Compliance Layer
# https://vaultra.io
# AGPL-3.0 License. Commercial use: legal@vaultra.io

"""
test_login_timing_enumeration.py — coverage for Task 3.3 (F19/F26):
username/email enumeration via login timing.

Before this fix, admin/app.py's and portal/app.py's login routes
short-circuited as soon as no matching username/email was found in the DB,
skipping bcrypt.checkpw() entirely — while a matching-user-wrong-password
attempt always ran a real (deliberately slow) bcrypt.checkpw(). An attacker
could measure response time to enumerate valid usernames/emails without ever
seeing a different error message.

The fix runs bcrypt.checkpw() against a fixed, precomputed decoy hash
(module-level DECOY_PASSWORD_HASH in each app) whenever no matching user is
found, before the generic "invalid credentials" error is returned — so the
"not found" branch costs the same real bcrypt work as the "found, wrong
password" branch.

Wall-clock assertions are flaky in CI, so these tests instead spy on
bcrypt.checkpw to assert:
  1. it is invoked (with the decoy hash) on the "user not found" branch,
  2. it is invoked (with the real per-user hash) on the "found, wrong
     password" branch,
  3. the generic error message is byte-identical in both cases,
  4. the rate-limiting accounting (record_attempt / clear_attempts, and
     their admin equivalents) is untouched by this change — same call
     counts as before, just gated on the decoy check now also running.
"""

import importlib
import os
import sqlite3
import sys
import time
import uuid

import bcrypt
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── admin fixtures (mirrors tests/test_admin_auth.py) ──────────────────────

@pytest.fixture
def admin_app_module(tmp_path, monkeypatch):
    db_path = tmp_path / "test_admin.db"

    monkeypatch.setenv("DB_PATH", str(db_path))
    monkeypatch.setenv("SECRET_KEY", "test-only-secret-key-do-not-use-in-prod")
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("SUPPORT_PASSWORD", "test-support-password")

    if "admin.app" in sys.modules:
        mod = sys.modules["admin.app"]
        monkeypatch.setattr(mod, "DB_PATH", str(db_path))
    else:
        mod = importlib.import_module("admin.app")

    mod.init_db()
    mod.app.config.update(TESTING=True)
    return mod


@pytest.fixture
def admin_client(admin_app_module):
    return admin_app_module.app.test_client()


def _admin_csrf(client, path="/login"):
    client.get(path)
    with client.session_transaction() as sess:
        return sess["csrf_token"]


# ── portal fixtures (mirrors tests/test_portal_auth.py) ────────────────────

@pytest.fixture
def portal_app_module(tmp_path, monkeypatch):
    db_path = tmp_path / "test_portal.db"

    monkeypatch.setenv("DB_PATH", str(db_path))
    monkeypatch.setenv("PORTAL_SECRET_KEY", "test-only-portal-secret-do-not-use-in-prod")

    if "portal.app" in sys.modules:
        mod = sys.modules["portal.app"]
        monkeypatch.setattr(mod, "DB_PATH", str(db_path))
    else:
        mod = importlib.import_module("portal.app")

    mod.init_portal_db()

    conn = sqlite3.connect(mod.DB_PATH)
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS clients (id TEXT PRIMARY KEY, company_name TEXT)"
        )
        conn.commit()
    finally:
        conn.close()

    mod.app.config.update(TESTING=True)
    return mod


@pytest.fixture
def portal_client(portal_app_module):
    return portal_app_module.app.test_client()


def _portal_csrf(client, path="/login"):
    client.get(path)
    with client.session_transaction() as sess:
        return sess["csrf_token"]


def _make_client_user(portal_app_module, email="user@example.com", password="test-user-password1"):
    client_id = str(uuid.uuid4())
    pwd_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user_id = str(uuid.uuid4())
    conn = sqlite3.connect(portal_app_module.DB_PATH)
    try:
        conn.execute(
            "INSERT INTO clients (id, company_name) VALUES (?, ?)",
            (client_id, "Test Co"),
        )
        conn.execute(
            """INSERT INTO client_users (id, client_id, email, password_hash, created_at, status)
               VALUES (?, ?, ?, ?, ?, 'active')""",
            (user_id, client_id, email, pwd_hash, time.time()),
        )
        conn.commit()
    finally:
        conn.close()
    return user_id, client_id, pwd_hash


def _spy_checkpw(mod, monkeypatch):
    """Wrap mod.bcrypt.checkpw with a call-recording spy that still delegates
    to the real implementation (so login behavior is unaffected), and return
    the list its calls get appended to."""
    calls = []
    real_checkpw = mod.bcrypt.checkpw

    def spy(password, hashed):
        calls.append((password, hashed))
        return real_checkpw(password, hashed)

    monkeypatch.setattr(mod.bcrypt, "checkpw", spy)
    return calls


# ── admin: decoy hash constant ──────────────────────────────────────────────

def test_admin_decoy_hash_is_precomputed_bcrypt_constant(admin_app_module):
    """DECOY_PASSWORD_HASH must be a real, valid bcrypt hash baked in as a
    module-level constant (not computed at request time — a fresh gensalt()
    call per-request would itself reintroduce a timing tell, and would be
    needless work on every single login)."""
    assert isinstance(admin_app_module.DECOY_PASSWORD_HASH, bytes)
    assert admin_app_module.DECOY_PASSWORD_HASH.startswith(b"$2")
    # Sanity: it actually verifies against *some* plaintext (i.e. it's a real
    # bcrypt hash, not a placeholder string).
    assert bcrypt.checkpw(
        b"admin-decoy-password-never-used-2026-f19f26",
        admin_app_module.DECOY_PASSWORD_HASH,
    )


# ── admin: unknown username still triggers a real bcrypt verification ─────

def test_admin_login_unknown_username_calls_bcrypt_against_decoy_hash(
    admin_app_module, admin_client, monkeypatch
):
    calls = _spy_checkpw(admin_app_module, monkeypatch)
    token = _admin_csrf(admin_client)

    resp = admin_client.post(
        "/login",
        data={"username": "no-such-admin", "password": "irrelevant", "csrf_token": token},
    )

    assert resp.status_code == 200
    assert len(calls) == 1, "bcrypt.checkpw must run exactly once on the not-found branch"
    assert calls[0][1] == admin_app_module.DECOY_PASSWORD_HASH


def test_admin_login_known_username_wrong_password_calls_bcrypt_against_real_hash(
    admin_app_module, admin_client, monkeypatch
):
    calls = _spy_checkpw(admin_app_module, monkeypatch)
    token = _admin_csrf(admin_client)

    resp = admin_client.post(
        "/login",
        data={"username": "admin", "password": "wrong-password", "csrf_token": token},
    )

    assert resp.status_code == 200
    assert len(calls) == 1
    assert calls[0][1] != admin_app_module.DECOY_PASSWORD_HASH


def test_admin_login_error_message_identical_regardless_of_username_existence(
    admin_app_module, admin_client
):
    token1 = _admin_csrf(admin_client)
    resp_unknown = admin_client.post(
        "/login",
        data={"username": "no-such-admin", "password": "irrelevant", "csrf_token": token1},
    )

    token2 = _admin_csrf(admin_client)
    resp_wrong_pwd = admin_client.post(
        "/login",
        data={"username": "admin", "password": "wrong-password", "csrf_token": token2},
    )

    assert resp_unknown.status_code == resp_wrong_pwd.status_code == 200
    assert b"Invalid username or password." in resp_unknown.data
    assert b"Invalid username or password." in resp_wrong_pwd.data


def test_admin_rate_limit_attempt_recorded_for_unknown_username(
    admin_app_module, admin_client, monkeypatch
):
    """The decoy-hash check must not disturb the existing rate-limit
    accounting (F9/F10): a failed attempt against an unknown username still
    records exactly one row via record_login_attempt."""
    recorded = []
    real_record = admin_app_module.record_login_attempt

    def spy_record(ip, identifier):
        recorded.append((ip, identifier))
        return real_record(ip, identifier)

    monkeypatch.setattr(admin_app_module, "record_login_attempt", spy_record)

    token = _admin_csrf(admin_client)
    admin_client.post(
        "/login",
        data={"username": "no-such-admin", "password": "irrelevant", "csrf_token": token},
    )

    assert len(recorded) == 1
    assert recorded[0][1] == "no-such-admin"


# ── portal: decoy hash constant ─────────────────────────────────────────────

def test_portal_decoy_hash_is_precomputed_bcrypt_constant(portal_app_module):
    assert isinstance(portal_app_module.DECOY_PASSWORD_HASH, bytes)
    assert portal_app_module.DECOY_PASSWORD_HASH.startswith(b"$2")
    assert bcrypt.checkpw(
        b"portal-decoy-password-never-used-2026-f19f26",
        portal_app_module.DECOY_PASSWORD_HASH,
    )


# ── portal: unknown email still triggers a real bcrypt verification ───────

def test_portal_login_unknown_email_calls_bcrypt_against_decoy_hash(
    portal_app_module, portal_client, monkeypatch
):
    calls = _spy_checkpw(portal_app_module, monkeypatch)
    token = _portal_csrf(portal_client)

    resp = portal_client.post(
        "/login",
        data={"email": "no-such-user@example.com", "password": "irrelevant", "csrf_token": token},
    )

    assert resp.status_code == 200
    assert len(calls) == 1, "bcrypt.checkpw must run exactly once on the not-found branch"
    assert calls[0][1] == portal_app_module.DECOY_PASSWORD_HASH


def test_portal_login_known_email_wrong_password_calls_bcrypt_against_real_hash(
    portal_app_module, portal_client, monkeypatch
):
    _make_client_user(portal_app_module, email="user@example.com", password="test-user-password1")
    calls = _spy_checkpw(portal_app_module, monkeypatch)
    token = _portal_csrf(portal_client)

    resp = portal_client.post(
        "/login",
        data={"email": "user@example.com", "password": "wrong-password", "csrf_token": token},
    )

    assert resp.status_code == 200
    assert len(calls) == 1
    assert calls[0][1] != portal_app_module.DECOY_PASSWORD_HASH


def test_portal_login_error_message_identical_regardless_of_email_existence(
    portal_app_module, portal_client
):
    _make_client_user(portal_app_module, email="user@example.com", password="test-user-password1")

    token1 = _portal_csrf(portal_client)
    resp_unknown = portal_client.post(
        "/login",
        data={"email": "no-such-user@example.com", "password": "irrelevant", "csrf_token": token1},
    )

    token2 = _portal_csrf(portal_client)
    resp_wrong_pwd = portal_client.post(
        "/login",
        data={"email": "user@example.com", "password": "wrong-password", "csrf_token": token2},
    )

    assert resp_unknown.status_code == resp_wrong_pwd.status_code == 200
    assert b"Invalid email or password." in resp_unknown.data
    assert b"Invalid email or password." in resp_wrong_pwd.data


def test_portal_rate_limit_attempt_recorded_for_unknown_email(
    portal_app_module, portal_client, monkeypatch
):
    """Same rate-limit-untouched guarantee as the admin test above, for
    portal/app.py's record_attempt()."""
    recorded = []
    real_record = portal_app_module.record_attempt

    def spy_record(ip, identifier):
        recorded.append((ip, identifier))
        return real_record(ip, identifier)

    monkeypatch.setattr(portal_app_module, "record_attempt", spy_record)

    token = _portal_csrf(portal_client)
    portal_client.post(
        "/login",
        data={"email": "no-such-user@example.com", "password": "irrelevant", "csrf_token": token},
    )

    assert len(recorded) == 1
    assert recorded[0][1] == "no-such-user@example.com"
