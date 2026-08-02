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

Round 1 of this fix (commit 97bb6d1) keyed the limiter solely on the
normalized account identifier and dropped ip from the throttle decision
entirely. Code review caught that this fixed (b) but reintroduced a worse
version of the opposite problem: since check_login_rate runs before password
verification, anyone who knows/guesses an identifier (e.g. the seeded
"admin" username) could fill that identifier's bucket with failed POSTs and
lock the *legitimate* owner out even on a correct password — and with no
per-IP counter at all, a single source had an *unlimited* total attempt
budget as long as it spread guesses across enough different accounts
(credential-spray from one source went completely unthrottled).

Fix-round 2: both apps now gate check_login_rate on TWO independent
counters, combined with OR (reject if EITHER trips):
  - per-identifier (scope, identifier): catches (b), a distributed attack
    against one account from many IPs.
  - per-ip (scope, ip): catches (a)'s mirror image — credential-spray from
    one source against many different accounts — by capping that source's
    *total* attempt volume regardless of how thinly it's spread across
    identifiers.
Both dimensions share one threshold (MAX_LOGIN_ATTEMPTS / MAX_ATTEMPTS) for
this round rather than giving identifier a higher cap — see
task-2.3-report.md for the accepted tradeoff (a residual account-lockout-DoS
risk from a flat per-identifier cutoff). `ip` is recorded on every row and
is now load-bearing for both dimensions, not just audit/forensics.
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

def test_admin_decoy_usernames_from_distinct_ips_do_not_consume_real_accounts_identifier_budget(
    admin_app_module, admin_client
):
    """Failed attempts against decoy usernames, arriving from distinct source
    IPs (each individually well under the per-IP cap), must not exhaust the
    per-identifier budget for an admin account they never touched — the
    identifier dimension still isolates account A's failures from account
    B's regardless of shared infrastructure elsewhere. (Distinct IPs are used
    deliberately here so this test exercises identifier isolation alone,
    without also tripping the per-IP counter — that dimension is covered by
    test_admin_one_ip_spraying_many_accounts_gets_rate_limited_on_ip_dimension
    below, which is the scenario this test used to — incorrectly — assert
    should never be throttled.)"""
    for i in range(6):
        token = _get_csrf(admin_client)
        resp = admin_client.post(
            "/login",
            data={
                "username": f"decoy-user-{i}",
                "password": "wrong-password",
                "csrf_token": token,
            },
            headers={"X-Forwarded-For": f"203.0.113.{100 + i}"},
        )
        assert resp.status_code == 200  # never 429 for these — none is "admin"

    # The real "admin" account, never targeted by any of the above, must
    # still be able to log in — its per-identifier budget is untouched, and
    # this fresh IP's per-ip budget is untouched too.
    token = _get_csrf(admin_client)
    resp = admin_client.post(
        "/login",
        data={
            "username": "admin",
            "password": "test-admin-password",
            "csrf_token": token,
        },
        headers={"X-Forwarded-For": "203.0.113.200"},
    )
    assert resp.status_code == 302
    assert "/dashboard" in resp.headers["Location"]


def test_admin_one_ip_spraying_many_accounts_gets_rate_limited_on_ip_dimension(
    admin_app_module, admin_client
):
    """One attacker IP cycling through many different (nonexistent)
    usernames — at most MAX_LOGIN_ATTEMPTS attempts against any single one of
    them — must still trip the per-IP counter once its *total* attempt
    volume from that source crosses the cap. This is the credential-spray
    case that fix-round 1's identifier-only design left completely
    unthrottled (a single source had unlimited budget as long as it spread
    guesses across enough accounts); restoring the per-IP counter (OR'd with
    the per-identifier one) closes it."""
    attacker_ip = "203.0.113.77"
    for i in range(admin_app_module.MAX_LOGIN_ATTEMPTS):
        token = _get_csrf(admin_client)
        resp = admin_client.post(
            "/login",
            data={
                "username": f"spray-user-{i}",
                "password": "wrong-password",
                "csrf_token": token,
            },
            headers={"X-Forwarded-For": attacker_ip},
        )
        assert resp.status_code == 200

    # One more attempt from the same IP, against yet another never-seen
    # username (zero prior failed attempts of its own), must now be blocked
    # — the per-IP counter has reached its cap even though no single
    # identifier individually exceeded it.
    token = _get_csrf(admin_client)
    resp = admin_client.post(
        "/login",
        data={
            "username": "never-seen-before",
            "password": "wrong-password",
            "csrf_token": token,
        },
        headers={"X-Forwarded-For": attacker_ip},
    )
    assert resp.status_code == 429


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


def test_portal_decoy_emails_from_distinct_ips_do_not_consume_real_accounts_identifier_budget(
    portal_app_module, portal_client
):
    """Same invariant as the equivalent admin test, for portal/app.py: decoy
    emails arriving from distinct source IPs (each under the per-IP cap)
    must not lock out a real client account they never targeted. Distinct
    IPs are used deliberately so this exercises identifier isolation alone
    — see test_portal_one_ip_spraying_many_accounts_gets_rate_limited_on_ip_dimension
    below for the per-ip dimension, which is the scenario this test used to
    — incorrectly — assert should never be throttled."""
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

    for i in range(6):
        token = _get_csrf(portal_client)
        resp = portal_client.post(
            "/login",
            data={
                "email": f"decoy-{i}@example.com",
                "password": "wrong-password",
                "csrf_token": token,
            },
            headers={"X-Forwarded-For": f"203.0.113.{150 + i}"},
        )
        assert resp.status_code == 200

    token = _get_csrf(portal_client)
    resp = portal_client.post(
        "/login",
        data={"email": email, "password": password, "csrf_token": token},
        headers={"X-Forwarded-For": "203.0.113.222"},
    )
    assert resp.status_code == 302
    assert "/dashboard" in resp.headers["Location"]


def test_portal_one_ip_spraying_many_accounts_gets_rate_limited_on_ip_dimension(
    portal_app_module, portal_client
):
    """One attacker IP cycling through many different decoy emails — at most
    MAX_ATTEMPTS attempts against any single one of them — must still trip
    the per-IP counter once its total attempt volume from that source
    crosses the cap. This is the credential-spray case fix-round 1's
    identifier-only design left completely unthrottled."""
    attacker_ip = "203.0.113.180"
    for i in range(portal_app_module.MAX_ATTEMPTS):
        token = _get_csrf(portal_client)
        resp = portal_client.post(
            "/login",
            data={
                "email": f"spray-{i}@example.com",
                "password": "wrong-password",
                "csrf_token": token,
            },
            headers={"X-Forwarded-For": attacker_ip},
        )
        assert resp.status_code == 200

    token = _get_csrf(portal_client)
    resp = portal_client.post(
        "/login",
        data={
            "email": "never-seen-before@example.com",
            "password": "wrong-password",
            "csrf_token": token,
        },
        headers={"X-Forwarded-For": attacker_ip},
    )
    assert resp.status_code == 200
    assert b"Too many login attempts" in resp.data


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


# ── fix-round 2: a legitimate first attempt is never blocked ───────────────
# (explicit re-verification requested by code review alongside the OR-logic
# fix above — this should already hold since both counters start at zero for
# a never-seen ip/identifier pair, but is worth pinning down directly rather
# than only inferring it from the other tests' final assertions.)

def test_admin_correct_password_on_first_attempt_from_fresh_ip_is_never_blocked(
    admin_app_module, admin_client
):
    """A legitimate admin logging in correctly on the very first attempt,
    from an IP with no prior history, must never be rejected by the rate
    limiter — both the per-ip and per-identifier counters start at zero."""
    token = _get_csrf(admin_client)
    resp = admin_client.post(
        "/login",
        data={
            "username": "admin",
            "password": "test-admin-password",
            "csrf_token": token,
        },
        headers={"X-Forwarded-For": "203.0.113.250"},
    )
    assert resp.status_code == 302
    assert "/dashboard" in resp.headers["Location"]
    with admin_client.session_transaction() as sess:
        assert "admin_id" in sess


def test_portal_correct_password_on_first_attempt_from_fresh_ip_is_never_blocked(
    portal_app_module, portal_client
):
    """Same invariant as the admin test above, for portal/app.py."""
    email = "firsttry@example.com"
    password = "correct-horse-battery1"

    import bcrypt
    import uuid

    client_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    pwd_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    conn = sqlite3.connect(portal_app_module.DB_PATH)
    try:
        conn.execute(
            "INSERT INTO clients (id, company_name) VALUES (?, ?)", (client_id, "First Try Co")
        )
        conn.execute(
            """INSERT INTO client_users (id, client_id, email, password_hash, created_at, status)
               VALUES (?, ?, ?, ?, ?, 'active')""",
            (user_id, client_id, email, pwd_hash, time.time()),
        )
        conn.commit()
    finally:
        conn.close()

    token = _get_csrf(portal_client)
    resp = portal_client.post(
        "/login",
        data={"email": email, "password": password, "csrf_token": token},
        headers={"X-Forwarded-For": "203.0.113.251"},
    )
    assert resp.status_code == 302
    assert "/dashboard" in resp.headers["Location"]
    with portal_client.session_transaction() as sess:
        assert "client_user_id" in sess
