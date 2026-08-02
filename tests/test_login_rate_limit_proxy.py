# Copyright (c) 2026 Jerly Rojas
# Vaultra — AI Agent Compliance Layer
# https://vaultra.io
# AGPL-3.0 License. Commercial use: legal@vaultra.io

"""
test_login_rate_limit_proxy.py — coverage for Task 2.3 (F9 + F10):

F9: both admin/app.py and portal/app.py sit behind exactly one nginx hop in
production (confirmed against the live Hetzner config — proxy_pass straight
to the local Gunicorn worker, no CDN/LB in front). Without ProxyFix,
request.remote_addr is always nginx's own loopback address, so the
SQLite-backed login rate limiter effectively never engages (every request
looks like it comes from the same "IP": nginx). ProxyFix(x_for=1) makes
request.remote_addr reflect the real client IP from the trusted single-hop
X-Forwarded-For header.

F10: the rate limiter used to key solely on ip. That has two failure modes:
  (a) one attacker behind a shared/NATed IP can lock out every other admin
      or client sharing that IP by cycling through usernames/emails, since
      all failed attempts from that IP share one budget;
  (b) an attacker distributed across many source IPs can hammer one victim
      account completely unnoticed, since each IP gets its own budget.
Both apps now key the rate limiter on the normalized account identifier
(username for admin, email for portal) rather than ip, giving a genuine
per-account backoff: an account's failed-attempt count follows the account
across source IPs, and one IP's attempts against account A never touch
account B's budget. `ip` is still recorded on every row for audit purposes,
but no longer gates the throttle decision.
"""

import importlib
import os
import sqlite3
import sys
import time

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


def _get_csrf(client, path="/login"):
    client.get(path)
    with client.session_transaction() as sess:
        return sess["csrf_token"]


def _login_attempts_rows(db_path, scope):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT * FROM login_attempts WHERE scope=?", (scope,)
        ).fetchall()
    finally:
        conn.close()


# ── F9: ProxyFix wiring ─────────────────────────────────────────────────────

def test_admin_proxyfix_reflects_x_forwarded_for(admin_app_module, admin_client):
    """A failed login through the real WSGI stack (ProxyFix included) must
    record the X-Forwarded-For client IP, not the test client's own loopback
    connection address — proving ProxyFix(x_for=1) is actually wired onto
    app.wsgi_app, not just imported."""
    spoofed_ip = "203.0.113.55"
    token = _get_csrf(admin_client)
    admin_client.post(
        "/login",
        data={"username": "admin", "password": "wrong-password", "csrf_token": token},
        headers={"X-Forwarded-For": spoofed_ip},
    )
    rows = _login_attempts_rows(admin_app_module.DB_PATH, "admin")
    assert len(rows) == 1
    assert rows[0]["ip"] == spoofed_ip


def test_admin_without_x_forwarded_for_uses_direct_remote_addr(admin_app_module, admin_client):
    """Sanity check: with no forwarding header, ProxyFix must not invent a
    client IP out of thin air — the direct connection address (the Flask
    test client's default loopback address) is still what's recorded."""
    token = _get_csrf(admin_client)
    admin_client.post(
        "/login",
        data={"username": "admin", "password": "wrong-password", "csrf_token": token},
    )
    rows = _login_attempts_rows(admin_app_module.DB_PATH, "admin")
    assert len(rows) == 1
    assert rows[0]["ip"] not in ("203.0.113.55", "")
    assert rows[0]["ip"] is not None


def test_portal_proxyfix_reflects_x_forwarded_for(portal_app_module, portal_client):
    spoofed_ip = "198.51.100.23"
    token = _get_csrf(portal_client)
    portal_client.post(
        "/login",
        data={"email": "nobody@example.com", "password": "wrong-password", "csrf_token": token},
        headers={"X-Forwarded-For": spoofed_ip},
    )
    rows = _login_attempts_rows(portal_app_module.DB_PATH, "portal")
    assert len(rows) == 1
    assert rows[0]["ip"] == spoofed_ip


# ── F10: per-account backoff, not ip-only ──────────────────────────────────

def test_admin_one_ip_attacking_many_usernames_does_not_lock_out_untouched_account(
    admin_app_module, admin_client
):
    """One attacker behind a single IP cycling through many admin usernames
    must not exhaust the rate-limit budget for an admin account it never
    touched. Pre-fix (ip-only key), all these failures shared one bucket per
    IP and would have locked out every admin behind that address; keyed on
    identifier, "admin"'s budget is untouched by attempts against other
    (nonexistent) usernames from the same IP."""
    attacker_ip = "203.0.113.99"
    for i in range(6):
        token = _get_csrf(admin_client)
        resp = admin_client.post(
            "/login",
            data={
                "username": f"decoy-user-{i}",
                "password": "wrong-password",
                "csrf_token": token,
            },
            headers={"X-Forwarded-For": attacker_ip},
        )
        assert resp.status_code == 200  # never 429 for these — none is "admin"

    # The real "admin" account, never targeted by any of the above, must
    # still be able to log in — its per-account budget is untouched.
    token = _get_csrf(admin_client)
    resp = admin_client.post(
        "/login",
        data={
            "username": "admin",
            "password": "test-admin-password",
            "csrf_token": token,
        },
        headers={"X-Forwarded-For": attacker_ip},
    )
    assert resp.status_code == 302
    assert "/dashboard" in resp.headers["Location"]


def test_admin_one_account_hammered_from_many_ips_still_gets_rate_limited(
    admin_app_module, admin_client
):
    """An attacker distributed across many different source IPs, all
    targeting the same admin username, must still trip the per-account
    limiter — an ip-only or (ip AND identifier)-only key would let each new
    IP start a fresh budget and never catch this."""
    for i in range(admin_app_module.MAX_LOGIN_ATTEMPTS):
        token = _get_csrf(admin_client)
        resp = admin_client.post(
            "/login",
            data={"username": "admin", "password": "wrong-password", "csrf_token": token},
            headers={"X-Forwarded-For": f"203.0.113.{i+1}"},
        )
        assert resp.status_code == 200

    # One more attempt, from yet another fresh IP — the account itself is
    # now rate-limited regardless of source IP.
    token = _get_csrf(admin_client)
    resp = admin_client.post(
        "/login",
        data={"username": "admin", "password": "test-admin-password", "csrf_token": token},
        headers={"X-Forwarded-For": "198.51.100.200"},
    )
    assert resp.status_code == 429
    with admin_client.session_transaction() as sess:
        assert "admin_id" not in sess


def test_admin_identifier_is_case_and_whitespace_normalized_for_rate_limiting(
    admin_app_module, admin_client
):
    """Trivial case/whitespace variation on the submitted username must not
    let an attacker dodge the per-account counter by presenting as a
    "different" identifier each time."""
    variants = ["Admin", " admin ", "ADMIN", "AdMiN", "admin"]
    for variant in variants:
        token = _get_csrf(admin_client)
        resp = admin_client.post(
            "/login",
            data={"username": variant, "password": "wrong-password", "csrf_token": token},
        )
        assert resp.status_code == 200

    # 5 failed attempts (across normalized-equal variants) should have used
    # up the whole MAX_LOGIN_ATTEMPTS budget for "admin".
    token = _get_csrf(admin_client)
    resp = admin_client.post(
        "/login",
        data={"username": "admin", "password": "test-admin-password", "csrf_token": token},
    )
    assert resp.status_code == 429


def test_portal_one_ip_attacking_many_emails_does_not_lock_out_untouched_account(
    portal_app_module, portal_client
):
    """Same invariant as the admin test above, for portal/app.py: one IP
    cycling through many decoy emails must not lock out a real client
    account it never targeted."""
    email = "victim@example.com"
    password = "victim-password1"

    import bcrypt
    import uuid

    client_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    pwd_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    conn = sqlite3.connect(portal_app_module.DB_PATH)
    try:
        conn.execute(
            "INSERT INTO clients (id, company_name) VALUES (?, ?)", (client_id, "Victim Co")
        )
        conn.execute(
            """INSERT INTO client_users (id, client_id, email, password_hash, created_at, status)
               VALUES (?, ?, ?, ?, ?, 'active')""",
            (user_id, client_id, email, pwd_hash, time.time()),
        )
        conn.commit()
    finally:
        conn.close()

    attacker_ip = "203.0.113.150"
    for i in range(6):
        token = _get_csrf(portal_client)
        resp = portal_client.post(
            "/login",
            data={
                "email": f"decoy-{i}@example.com",
                "password": "wrong-password",
                "csrf_token": token,
            },
            headers={"X-Forwarded-For": attacker_ip},
        )
        assert resp.status_code == 200

    token = _get_csrf(portal_client)
    resp = portal_client.post(
        "/login",
        data={"email": email, "password": password, "csrf_token": token},
        headers={"X-Forwarded-For": attacker_ip},
    )
    assert resp.status_code == 302
    assert "/dashboard" in resp.headers["Location"]


def test_portal_one_account_hammered_from_many_ips_still_gets_rate_limited(
    portal_app_module, portal_client
):
    email = "victim2@example.com"
    for i in range(portal_app_module.MAX_ATTEMPTS):
        token = _get_csrf(portal_client)
        resp = portal_client.post(
            "/login",
            data={"email": email, "password": "wrong-password", "csrf_token": token},
            headers={"X-Forwarded-For": f"198.51.100.{i+1}"},
        )
        assert resp.status_code == 200

    token = _get_csrf(portal_client)
    resp = portal_client.post(
        "/login",
        data={"email": email, "password": "wrong-password", "csrf_token": token},
        headers={"X-Forwarded-For": "203.0.113.222"},
    )
    assert resp.status_code == 200
    assert b"Too many login attempts" in resp.data
