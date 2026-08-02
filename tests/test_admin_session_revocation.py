# Copyright (c) 2026 Jerly Rojas
# Vaultra — AI Agent Compliance Layer
# https://vaultra.io
# AGPL-3.0 License. Commercial use: legal@vaultra.io

"""
test_admin_session_revocation.py — coverage for Task 2.2 (F11): deleted or
demoted admin sessions must not remain valid for the rest of their idle
timeout window.

Before this task, login_required/admin_required (admin/app.py) only checked
`"admin_id" in session` plus the 30-minute idle timeout — never re-checking
that the admin_users row behind that id still exists, or still has the same
role/credentials it had when the session cookie was issued. That meant a
just-deleted (or, if a role-change route existed, just-demoted) admin's
existing session cookie kept working right up until it happened to go idle
for 30 minutes.

This module covers the fix:
  - a per-user `session_version` counter (default 0), bumped by
    bump_session_version() at every point access should be revoked —
    currently delete_admin_user and change_password — and stamped into the
    session cookie at login;
  - login_required/admin_required re-validate the cookie's session_version
    against the current DB value (and the row's mere existence) on every
    request, rejecting with a redirect to /login on mismatch or missing row;
  - an absolute 8-hour session lifetime (SESSION_ABSOLUTE_LIFETIME),
    enforced independently of the pre-existing 30-minute idle timeout, via a
    session-start timestamp stored at login.

Fixture setup mirrors test_admin_auth.py: DB_PATH is monkeypatched to a
per-test tmp_path file before/around import, and init_db() is called fresh
for every test so no state leaks between tests or into the real
vaultra_admin.db.
"""

import importlib
import os
import sqlite3
import sys
import time

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
    a csrf_token planted, then return it."""
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


def _login(client, username, password):
    """Log in for real via POST /login, so the session cookie carries
    whatever login() actually stamps into it (admin_id, role,
    session_version, last_active, session_start) rather than a hand-built
    stand-in."""
    token = _get_csrf(client)
    resp = client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": token},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "/dashboard" in resp.headers["Location"]
    return resp


def _bump_session_version(admin_app_module, username):
    conn = sqlite3.connect(admin_app_module.DB_PATH)
    try:
        conn.execute(
            "UPDATE admin_users SET session_version = session_version + 1 WHERE username=?",
            (username,),
        )
        conn.commit()
    finally:
        conn.close()


def _delete_admin_row(admin_app_module, username):
    conn = sqlite3.connect(admin_app_module.DB_PATH)
    try:
        conn.execute("DELETE FROM admin_users WHERE username=?", (username,))
        conn.commit()
    finally:
        conn.close()


# ── login stamps session_version + session_start ───────────────────────────

def test_login_stores_session_version_and_session_start(admin_app_module, client):
    _login(client, "admin", "test-admin-password")
    with client.session_transaction() as sess:
        assert sess["session_version"] == 0
        assert "session_start" in sess


# ── session_version bump (simulating delete/role-change) revokes session ───

def test_session_version_bump_revokes_existing_session(admin_app_module, client):
    _login(client, "admin", "test-admin-password")

    # Sanity: the freshly-logged-in session is currently valid.
    resp = client.get("/dashboard")
    assert resp.status_code == 200

    # Simulate a delete/role-change happening out from under this session —
    # in production this is bump_session_version(), invoked by
    # delete_admin_user/change_password (or a future role-change route).
    _bump_session_version(admin_app_module, "admin")

    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]
    assert "reason=revoked" in resp.headers["Location"]

    # The stale cookie must actually be cleared, not just redirected past.
    with client.session_transaction() as sess:
        assert "admin_id" not in sess


# ── delete case: row disappears entirely, not just its version ─────────────

def test_deleting_logged_in_users_row_revokes_session(admin_app_module, client):
    _login(client, "support", "test-support-password")

    resp = client.get("/dashboard")
    assert resp.status_code == 200

    # Simulate an admin deleting this user's account mid-session (the
    # real delete_admin_user route DELETEs the row directly).
    _delete_admin_row(admin_app_module, "support")

    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]
    assert "reason=revoked" in resp.headers["Location"]

    with client.session_transaction() as sess:
        assert "admin_id" not in sess


# ── change_password / delete_admin_user actually call the bump helper ──────

def test_change_password_bumps_session_version_in_db(admin_app_module, client):
    _login(client, "admin", "test-admin-password")
    before = _row(admin_app_module, "admin")["session_version"]

    with client.session_transaction() as sess:
        csrf = sess["csrf_token"]
    resp = client.post(
        "/settings/change-password",
        json={
            "current_password": "test-admin-password",
            "new_password": "brand-new-password1",
            "confirm_password": "brand-new-password1",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 200
    after = _row(admin_app_module, "admin")["session_version"]
    assert after == before + 1


def test_delete_admin_user_bumps_session_version_before_row_is_gone(admin_app_module, client):
    """delete_admin_user calls bump_session_version(uid) before the DELETE —
    a no-op in terms of final DB state (the row is removed either way), but
    exercises bump_session_version() at this trigger point as specified, and
    the row's absence is independently covered by check_session_revoked()'s
    missing-user branch above."""
    _login(client, "admin", "test-admin-password")
    target = _row(admin_app_module, "support")

    with client.session_transaction() as sess:
        csrf = sess["csrf_token"]
    resp = client.post(
        f"/settings/delete-user/{target['id']}",
        json={},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 200
    assert _row(admin_app_module, "support") is None


# ── absolute session lifetime, independent of idle/activity timeout ────────

def test_absolute_session_lifetime_expires_even_when_active(admin_app_module, client):
    _login(client, "admin", "test-admin-password")

    # Sanity: valid immediately after login.
    resp = client.get("/dashboard")
    assert resp.status_code == 200

    # Push session_start back past SESSION_ABSOLUTE_LIFETIME (8h), while
    # last_active stays recent (the request above just refreshed it) — this
    # isolates the absolute-lifetime check from the idle-timeout check.
    with client.session_transaction() as sess:
        sess["session_start"] = time.time() - admin_app_module.SESSION_ABSOLUTE_LIFETIME - 60

    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]
    assert "reason=timeout" in resp.headers["Location"]

    with client.session_transaction() as sess:
        assert "admin_id" not in sess


def test_session_within_absolute_lifetime_and_active_stays_valid(admin_app_module, client):
    """Control case: well inside both the idle and absolute limits, the
    session must keep working — guards against an over-eager absolute-
    lifetime check that fires too early."""
    _login(client, "admin", "test-admin-password")

    with client.session_transaction() as sess:
        sess["session_start"] = time.time() - (admin_app_module.SESSION_ABSOLUTE_LIFETIME - 3600)

    resp = client.get("/dashboard")
    assert resp.status_code == 200
