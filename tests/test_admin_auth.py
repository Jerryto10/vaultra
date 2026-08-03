# Copyright (c) 2026 Jerly Rojas
# Vaultra — AI Agent Compliance Layer
# https://vaultra.io
# AGPL-3.0 License. Commercial use: legal@vaultra.io

"""
test_admin_auth.py — coverage for Task 2.1 (F24/F25): admin/app.py must
require bcrypt (fail closed at import time if it's unavailable, mirroring the
existing SECRET_KEY mandatory-env pattern) and must no longer accept or
produce SHA-256 password hashes anywhere in the login / change-password /
create-user flows.

Fixture setup follows the established convention from test_admin_receipt.py:
DB_PATH is monkeypatched to a per-test tmp_path file before/around import,
and init_db() is called fresh for every test so no state leaks between tests
or into the real vaultra_admin.db.
"""

import hashlib
import importlib
import os
import sqlite3
import subprocess
import sys
import time

import bcrypt
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


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
        monkeypatch.setattr(mod, "DB_PATH", str(db_path))
    else:
        mod = importlib.import_module("admin.app")

    mod.init_db()
    mod.app.config.update(TESTING=True)
    return mod


@pytest.fixture
def client(admin_app_module):
    return admin_app_module.app.test_client()


def _get_csrf(client, path="/login"):
    """GET a page that calls csrf_token() during render, so the session gets
    a csrf_token planted, then return it alongside the client's cookie jar."""
    client.get(path)
    with client.session_transaction() as sess:
        return sess["csrf_token"]


def _row(admin_app_module, username):
    conn = sqlite3.connect(admin_app_module.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT * FROM admin_users WHERE username=?", (username,)
        ).fetchone()
    finally:
        conn.close()


def _set_password_hash(admin_app_module, username, new_hash):
    conn = sqlite3.connect(admin_app_module.DB_PATH)
    try:
        conn.execute(
            "UPDATE admin_users SET password_hash=? WHERE username=?",
            (new_hash, username),
        )
        conn.commit()
    finally:
        conn.close()


# ── bcrypt is now mandatory: import failure must raise, not degrade ────────

def test_bcrypt_missing_raises_at_import():
    """If bcrypt can't be imported, admin/app.py must refuse to start rather
    than silently falling back to SHA-256 (mirrors the SECRET_KEY pattern)."""
    script = (
        "import sys, os\n"
        f"sys.path.insert(0, {PROJECT_ROOT!r})\n"
        "sys.modules['bcrypt'] = None\n"  # forces `import bcrypt` to raise ImportError
        "os.environ['SECRET_KEY'] = 'x'\n"
        "try:\n"
        "    import admin.app\n"
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


# ── seed users are bcrypt-hashed; SHA-256 is gone from init_db ─────────────

def test_seed_admin_password_hash_is_bcrypt(admin_app_module):
    row = _row(admin_app_module, "admin")
    assert row["password_hash"].startswith("$2")
    assert bcrypt.checkpw(b"test-admin-password", row["password_hash"].encode())


def test_seed_support_password_hash_is_bcrypt(admin_app_module):
    row = _row(admin_app_module, "support")
    assert row["password_hash"].startswith("$2")
    assert bcrypt.checkpw(b"test-support-password", row["password_hash"].encode())


# ── login: bcrypt succeeds, legacy SHA-256 hashes are hard-rejected ────────

def test_login_succeeds_with_bcrypt_hash(admin_app_module, client):
    token = _get_csrf(client)
    resp = client.post(
        "/login",
        data={
            "username": "admin",
            "password": "test-admin-password",
            "csrf_token": token,
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "/dashboard" in resp.headers["Location"]
    with client.session_transaction() as sess:
        assert sess["admin_id"] == _row(admin_app_module, "admin")["id"]


def test_login_rejects_wrong_password(admin_app_module, client):
    token = _get_csrf(client)
    resp = client.post(
        "/login",
        data={
            "username": "admin",
            "password": "wrong-password",
            "csrf_token": token,
        },
    )
    assert resp.status_code == 200  # re-renders login page with error
    with client.session_transaction() as sess:
        assert "admin_id" not in sess


def test_login_rejects_legacy_sha256_hash_even_with_correct_plaintext(admin_app_module, client):
    """A row carrying an old-style SHA-256 hash must never authenticate again
    — no migration-on-login path, just a hard rejection (per the confirmed
    finding: zero such rows exist in production, so this is defense in depth)."""
    plaintext = "test-admin-password"
    legacy_hash = hashlib.sha256(plaintext.encode()).hexdigest()
    _set_password_hash(admin_app_module, "admin", legacy_hash)

    token = _get_csrf(client)
    resp = client.post(
        "/login",
        data={"username": "admin", "password": plaintext, "csrf_token": token},
    )
    assert resp.status_code == 200
    with client.session_transaction() as sess:
        assert "admin_id" not in sess


# ── change-password: rejects legacy current-hash, only ever writes bcrypt ──

FIXED_CSRF_TOKEN = "test-fixed-csrf-token"


def _login_session(client, admin_app_module, username="admin"):
    row = _row(admin_app_module, username)
    with client.session_transaction() as sess:
        sess["admin_id"] = row["id"]
        sess["username"] = row["username"]
        sess["role"] = row["role"]
        sess["csrf_token"] = FIXED_CSRF_TOKEN
        sess["last_active"] = time.time()
        sess["session_start"] = time.time()
        sess["session_version"] = row["session_version"]


def test_change_password_rejects_legacy_current_hash(admin_app_module, client):
    plaintext = "test-admin-password"
    legacy_hash = hashlib.sha256(plaintext.encode()).hexdigest()
    _set_password_hash(admin_app_module, "admin", legacy_hash)
    _login_session(client, admin_app_module)

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


def test_change_password_writes_bcrypt_hash(admin_app_module, client):
    _login_session(client, admin_app_module)
    resp = client.post(
        "/settings/change-password",
        json={
            "current_password": "test-admin-password",
            "new_password": "brand-new-password1",
            "confirm_password": "brand-new-password1",
        },
        headers={"X-CSRF-Token": FIXED_CSRF_TOKEN},
    )
    assert resp.status_code == 200
    row = _row(admin_app_module, "admin")
    assert row["password_hash"].startswith("$2")
    assert bcrypt.checkpw(b"brand-new-password1", row["password_hash"].encode())


# ── create-user: new admin/support accounts always get bcrypt hashes ───────

def test_create_admin_user_writes_bcrypt_hash(admin_app_module, client):
    _login_session(client, admin_app_module)  # role=admin from seed row
    resp = client.post(
        "/settings/create-user",
        json={
            "username": "newbie",
            "password": "another-password1",
            "role": "support",
        },
        headers={"X-CSRF-Token": FIXED_CSRF_TOKEN},
    )
    assert resp.status_code == 200
    row = _row(admin_app_module, "newbie")
    assert row["password_hash"].startswith("$2")
    assert bcrypt.checkpw(b"another-password1", row["password_hash"].encode())


# ── logout: POST-only + CSRF-guarded (Task 3.1, F13) ───────────────────────
#
# /logout used to accept GET, so a third-party page could log a victim out
# with a bare <img src="https://admin.vaultra.io/logout">. It's now POST-only
# (Flask 405s any other method automatically) and runs through the same
# enforce_csrf before_request hook as every other mutating admin route.

def test_logout_rejects_get(admin_app_module, client):
    _login_session(client, admin_app_module)
    resp = client.get("/logout")
    assert resp.status_code == 405
    with client.session_transaction() as sess:
        assert "admin_id" in sess  # session untouched — GET never reaches the handler


def test_logout_rejects_post_without_csrf_token(admin_app_module, client):
    _login_session(client, admin_app_module)
    resp = client.post("/logout")
    assert resp.status_code == 403
    with client.session_transaction() as sess:
        assert "admin_id" in sess  # blocked before the handler could clear it


def test_logout_succeeds_with_valid_csrf_token(admin_app_module, client):
    _login_session(client, admin_app_module)
    resp = client.post(
        "/logout",
        headers={"X-CSRF-Token": FIXED_CSRF_TOKEN},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]
    with client.session_transaction() as sess:
        assert "admin_id" not in sess
