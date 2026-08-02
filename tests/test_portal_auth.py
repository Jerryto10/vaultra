# Copyright (c) 2026 Jerly Rojas
# Vaultra — AI Agent Compliance Layer
# https://vaultra.io
# AGPL-3.0 License. Commercial use: legal@vaultra.io

"""
test_portal_auth.py — coverage for Task 2.1 (F24/F25): portal/app.py must
require bcrypt (fail closed at import time if it's unavailable, mirroring the
existing PORTAL_SECRET_KEY mandatory-env pattern) and must no longer accept
or produce SHA-256 password hashes anywhere in the login / activate /
change-password flows.

Fixture setup mirrors tests/test_admin_receipt.py's admin_app_module pattern:
DB_PATH is monkeypatched to a per-test tmp_path file, and the portal schema
is (re)created fresh for every test so no state leaks between tests or into
a real database file. A minimal `clients` table is created by hand here
(normally admin/app.py's init_db() owns that table — both apps share one DB
file in production) because get_current_client() joins against it.
"""

import hashlib
import importlib
import os
import sqlite3
import subprocess
import sys
import time
import uuid

import bcrypt
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


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

    # minimal `clients` table — owned by admin/app.py in production, but
    # get_current_client() joins against it, so tests need it to exist.
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
def client(portal_app_module):
    return portal_app_module.app.test_client()


def _make_client_user(portal_app_module, email="user@example.com", password="test-user-password1", client_id=None):
    client_id = client_id or str(uuid.uuid4())
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
    return user_id, client_id


def _row(portal_app_module, email):
    conn = sqlite3.connect(portal_app_module.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT * FROM client_users WHERE email=?", (email,)
        ).fetchone()
    finally:
        conn.close()


def _row_by_id(portal_app_module, user_id):
    conn = sqlite3.connect(portal_app_module.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT * FROM client_users WHERE id=?", (user_id,)
        ).fetchone()
    finally:
        conn.close()


def _set_password_hash(portal_app_module, email, new_hash):
    conn = sqlite3.connect(portal_app_module.DB_PATH)
    try:
        conn.execute(
            "UPDATE client_users SET password_hash=? WHERE email=?",
            (new_hash, email),
        )
        conn.commit()
    finally:
        conn.close()


def _get_csrf(client, path="/login"):
    client.get(path)
    with client.session_transaction() as sess:
        return sess["csrf_token"]


# ── bcrypt is now mandatory: import failure must raise, not degrade ────────

def test_bcrypt_missing_raises_at_import():
    script = (
        "import sys, os\n"
        f"sys.path.insert(0, {PROJECT_ROOT!r})\n"
        "sys.modules['bcrypt'] = None\n"
        "os.environ['PORTAL_SECRET_KEY'] = 'x'\n"
        "try:\n"
        "    import portal.app\n"
        "    print('NO_RAISE')\n"
        "except RuntimeError as e:\n"
        "    print('RAISED:' + str(e))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, timeout=30, cwd=PROJECT_ROOT,
    )
    assert "RAISED:" in result.stdout, (result.stdout, result.stderr)
    assert "bcrypt" in result.stdout


# ── login: bcrypt succeeds, legacy SHA-256 hashes are hard-rejected ────────

def test_login_succeeds_with_bcrypt_hash(portal_app_module, client):
    _make_client_user(portal_app_module, email="user@example.com", password="test-user-password1")
    token = _get_csrf(client)
    resp = client.post(
        "/login",
        data={"email": "user@example.com", "password": "test-user-password1", "csrf_token": token},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "/dashboard" in resp.headers["Location"]
    with client.session_transaction() as sess:
        assert "client_user_id" in sess


def test_login_rejects_wrong_password(portal_app_module, client):
    _make_client_user(portal_app_module, email="user@example.com", password="test-user-password1")
    token = _get_csrf(client)
    resp = client.post(
        "/login",
        data={"email": "user@example.com", "password": "wrong-password", "csrf_token": token},
    )
    assert resp.status_code == 200
    with client.session_transaction() as sess:
        assert "client_user_id" not in sess


def test_login_rejects_legacy_sha256_hash_even_with_correct_plaintext(portal_app_module, client):
    plaintext = "test-user-password1"
    _make_client_user(portal_app_module, email="user@example.com", password=plaintext)
    legacy_hash = hashlib.sha256(plaintext.encode()).hexdigest()
    _set_password_hash(portal_app_module, "user@example.com", legacy_hash)

    token = _get_csrf(client)
    resp = client.post(
        "/login",
        data={"email": "user@example.com", "password": plaintext, "csrf_token": token},
    )
    assert resp.status_code == 200
    with client.session_transaction() as sess:
        assert "client_user_id" not in sess


# ── activate: new/updated client_users always get bcrypt hashes ───────────

def _make_invitation(portal_app_module, email="invitee@example.com"):
    client_id = str(uuid.uuid4())
    token = uuid.uuid4().hex
    conn = sqlite3.connect(portal_app_module.DB_PATH)
    try:
        conn.execute(
            "INSERT INTO clients (id, company_name) VALUES (?, ?)", (client_id, "Invitee Co")
        )
        conn.execute(
            """INSERT INTO client_invitations (id, client_id, email, token, created_at, expires_at, used)
               VALUES (?, ?, ?, ?, ?, ?, 0)""",
            (str(uuid.uuid4()), client_id, email, token, time.time(), time.time() + 3600),
        )
        conn.commit()
    finally:
        conn.close()
    return token


def test_activate_writes_bcrypt_hash(portal_app_module, client):
    token = _make_invitation(portal_app_module, email="invitee@example.com")
    csrf = _get_csrf(client, path=f"/activate/{token}")
    resp = client.post(
        f"/activate/{token}",
        data={
            "password": "brand-new-password1",
            "confirm_password": "brand-new-password1",
            "csrf_token": csrf,
        },
    )
    assert resp.status_code == 200
    row = _row(portal_app_module, "invitee@example.com")
    assert row is not None
    assert row["password_hash"].startswith("$2")
    assert bcrypt.checkpw(b"brand-new-password1", row["password_hash"].encode())


# ── change-password: rejects legacy current-hash, only ever writes bcrypt ──

FIXED_CSRF_TOKEN = "test-fixed-csrf-token"


def _login_session(client, user_id, client_id):
    with client.session_transaction() as sess:
        sess["client_user_id"] = user_id
        sess["client_id"] = client_id
        sess["email"] = "user@example.com"
        sess["last_seen"] = time.time()
        sess["csrf_token"] = FIXED_CSRF_TOKEN


def test_change_password_rejects_legacy_current_hash(portal_app_module, client):
    plaintext = "test-user-password1"
    user_id, client_id = _make_client_user(portal_app_module, email="user@example.com", password=plaintext)
    legacy_hash = hashlib.sha256(plaintext.encode()).hexdigest()
    _set_password_hash(portal_app_module, "user@example.com", legacy_hash)
    _login_session(client, user_id, client_id)

    resp = client.post(
        "/settings/change-password",
        json={
            "current_password": plaintext,
            "new_password": "brand-new-password1",
            "confirm_password": "brand-new-password1",
        },
        headers={"X-CSRF-Token": FIXED_CSRF_TOKEN},
    )
    assert resp.status_code == 401


def test_change_password_writes_bcrypt_hash(portal_app_module, client):
    user_id, client_id = _make_client_user(
        portal_app_module, email="user@example.com", password="test-user-password1"
    )
    _login_session(client, user_id, client_id)

    resp = client.post(
        "/settings/change-password",
        json={
            "current_password": "test-user-password1",
            "new_password": "brand-new-password1",
            "confirm_password": "brand-new-password1",
        },
        headers={"X-CSRF-Token": FIXED_CSRF_TOKEN},
    )
    assert resp.status_code == 200
    row = _row_by_id(portal_app_module, user_id)
    assert row["password_hash"].startswith("$2")
    assert bcrypt.checkpw(b"brand-new-password1", row["password_hash"].encode())


# ── /api/invite: PORTAL_ADMIN_TOKEN must be compared constant-time (F23) ───
#
# Task 2.5: create_invitation() used `auth != expected` to check the
# X-Admin-Token header against PORTAL_ADMIN_TOKEN, a variable-time string
# comparison vulnerable to timing attacks. Fixed to use
# `hmac.compare_digest`, with the `not expected` guard kept first so an
# empty/unset PORTAL_ADMIN_TOKEN still fails closed rather than ever
# reaching the comparison.

def test_invite_accepts_correct_admin_token(portal_app_module, client, monkeypatch):
    monkeypatch.setenv("PORTAL_ADMIN_TOKEN", "correct-admin-token")
    resp = client.post(
        "/api/invite",
        json={"client_id": str(uuid.uuid4()), "email": "invitee@example.com"},
        headers={"X-Admin-Token": "correct-admin-token"},
    )
    assert resp.status_code == 200
    assert resp.get_json()["success"] is True


def test_invite_rejects_incorrect_admin_token(portal_app_module, client, monkeypatch):
    monkeypatch.setenv("PORTAL_ADMIN_TOKEN", "correct-admin-token")
    resp = client.post(
        "/api/invite",
        json={"client_id": str(uuid.uuid4()), "email": "invitee@example.com"},
        headers={"X-Admin-Token": "wrong-admin-token"},
    )
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "Unauthorized"


def test_invite_fails_closed_when_admin_token_unset(portal_app_module, client, monkeypatch):
    monkeypatch.delenv("PORTAL_ADMIN_TOKEN", raising=False)
    resp = client.post(
        "/api/invite",
        json={"client_id": str(uuid.uuid4()), "email": "invitee@example.com"},
        headers={"X-Admin-Token": ""},
    )
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "Unauthorized"
