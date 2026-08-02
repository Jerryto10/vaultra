"""
Vaultra Client Portal — app.vaultra.io
Self-service portal for Vaultra clients.
"""
import os
import re
import time
import uuid
import hmac
import secrets
import sqlite3
from functools import wraps
from datetime import datetime, timezone

try:
    import bcrypt
except ImportError:
    raise RuntimeError(
        "bcrypt is not installed. Refusing to start without a secure password "
        "hashing library — install bcrypt (see requirements.txt)."
    )

from flask import (
    Flask, render_template, request, session,
    redirect, url_for, jsonify, g
)
from flask_cors import CORS, cross_origin
from markupsafe import escape
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__, template_folder="templates", static_folder="static")
# Trust exactly one reverse-proxy hop for X-Forwarded-For (F9). Confirmed
# against the live Hetzner nginx config: app.vaultra.io's server block
# proxies directly to this Gunicorn worker with no other proxy/CDN/LB in
# front, so request.remote_addr becomes the real client IP instead of
# nginx's own loopback address — otherwise every login attempt is keyed on
# 127.0.0.1 and the rate limiter effectively never bites.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)
PORTAL_SECRET_KEY = os.environ.get("PORTAL_SECRET_KEY")
if not PORTAL_SECRET_KEY:
    raise RuntimeError(
        "PORTAL_SECRET_KEY environment variable is not set. Refusing to start with an "
        "insecure, randomly-generated key — set PORTAL_SECRET_KEY in the environment (.env)."
    )
app.secret_key = PORTAL_SECRET_KEY

# ── CORS — portal is same-origin only; /health is the sole public endpoint ─
CORS(app, origins=["https://app.vaultra.io"], supports_credentials=True)
PUBLIC_ORIGINS = ["https://vaultra.io", "https://app.vaultra.io"]

# ── Security headers ──────────────────────────────────────────────────────
@app.after_request
def security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "img-src 'self' data:; font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self'"
    )
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if "client_user_id" in session:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return response

# ── Database ──────────────────────────────────────────────────────────────
DB_PATH = os.environ.get("DB_PATH", "/data/vaultra_admin.db")

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA synchronous=NORMAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()

def init_portal_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS client_users (
            id             TEXT PRIMARY KEY,
            client_id      TEXT NOT NULL,
            email          TEXT NOT NULL UNIQUE,
            password_hash  TEXT NOT NULL,
            created_at     REAL NOT NULL,
            last_login     REAL,
            status         TEXT NOT NULL DEFAULT 'active'
        );
        CREATE TABLE IF NOT EXISTS client_sessions (
            id              TEXT PRIMARY KEY,
            client_user_id  TEXT NOT NULL,
            created_at      REAL NOT NULL,
            expires_at      REAL NOT NULL,
            ip_address      TEXT
        );
        CREATE TABLE IF NOT EXISTS client_invitations (
            id          TEXT PRIMARY KEY,
            client_id   TEXT NOT NULL,
            email       TEXT NOT NULL,
            token       TEXT NOT NULL UNIQUE,
            created_at  REAL NOT NULL,
            expires_at  REAL NOT NULL,
            used        INTEGER NOT NULL DEFAULT 0
        );

        -- SQLite-backed rate limiting (shared across Gunicorn workers).
        -- scope distinguishes portal vs admin-panel login attempts since both
        -- apps point at the same DB file in production.
        CREATE TABLE IF NOT EXISTS login_attempts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            scope      TEXT NOT NULL DEFAULT 'admin',
            ip         TEXT NOT NULL,
            identifier TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_login_attempts_scope_ip ON login_attempts(scope, ip, created_at);
    """)
    db.commit()

    # Add missing columns if upgrading from a database created before F10 —
    # same idempotent try/except ALTER TABLE convention as admin/app.py's
    # init_db(). CREATE TABLE IF NOT EXISTS above is a no-op against an
    # already-existing login_attempts table, so pre-F10 databases (both apps
    # share one DB file in production) need this migration to gain the
    # `identifier` column.
    for col_sql in [
        "ALTER TABLE login_attempts ADD COLUMN identifier TEXT NOT NULL DEFAULT ''",
    ]:
        try:
            db.execute(col_sql)
        except Exception:
            pass
    db.commit()

    # This index needs the `identifier` column above to already exist, so it
    # can't be created until after the ALTER TABLE migration runs. It matches
    # check_login_rate/clear_attempts' actual query shape (filtered on
    # scope + identifier, no longer on ip — see F10 above).
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_login_attempts_scope_identifier "
        "ON login_attempts(scope, identifier, created_at)"
    )
    db.commit()
    db.close()

# ── Session timeout ───────────────────────────────────────────────────────
SESSION_TIMEOUT = 3600  # 1 hour

# ── Login required decorator ──────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "client_user_id" not in session:
            return redirect(url_for("login"))
        last = session.get("last_seen")
        if last and (time.time() - last) > SESSION_TIMEOUT:
            session.clear()
            return redirect(url_for("login"))
        session["last_seen"] = time.time()
        return f(*args, **kwargs)
    return decorated

def get_current_client():
    """Get current client_user and their client record."""
    db = get_db()
    cu = db.execute(
        "SELECT * FROM client_users WHERE id=?",
        (session["client_user_id"],)
    ).fetchone()
    if not cu:
        return None, None
    client = db.execute(
        "SELECT * FROM clients WHERE id=?",
        (cu["client_id"],)
    ).fetchone()
    return cu, client

def verify_client_ownership(db, receipt_id, client_id):
    """Fetch a receipt only if it belongs to client_id; logs cross-client access attempts."""
    receipt = db.execute("SELECT * FROM receipts WHERE id=?", (receipt_id,)).fetchone()
    if receipt is None:
        return None
    if receipt["client_id"] != client_id:
        app.logger.warning(
            "SECURITY: client_id=%s attempted to access receipt %s belonging to client_id=%s "
            "(ip=%s)", client_id, receipt_id, receipt["client_id"], request.remote_addr
        )
        return None
    return receipt

@app.before_request
def log_cross_client_attempts():
    """Middleware: logs any request whose <rid> URL segment belongs to a
    different client than the current session. Purely a monitoring layer —
    the routes themselves independently enforce access control via their
    own WHERE client_id=? queries; this just flags probing attempts even if
    a future route ever forgets to.
    """
    if not request.view_args:
        return
    rid = request.view_args.get("rid")
    client_id = session.get("client_id")
    if not rid or not client_id:
        return
    db = get_db()
    receipt = db.execute("SELECT client_id FROM receipts WHERE id=?", (rid,)).fetchone()
    if receipt and receipt["client_id"] != client_id:
        app.logger.warning(
            "SECURITY: client_id=%s attempted to access receipt %s belonging to client_id=%s "
            "(ip=%s, path=%s)", client_id, rid, receipt["client_id"], request.remote_addr, request.path
        )

def fmt_date(ts):
    if not ts:
        return "—"
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return "—"

app.jinja_env.globals["fmt_date"] = fmt_date

# ── CSRF protection ────────────────────────────────────────────────────
# Synchronizer-token pattern: one token per session, exposed to templates as
# csrf_token(), checked on every mutating request against the session copy.
def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]

app.jinja_env.globals["csrf_token"] = generate_csrf_token

def verify_csrf_token():
    expected = session.get("csrf_token")
    if not expected:
        return False
    submitted = request.form.get("csrf_token")
    if not submitted:
        submitted = request.headers.get("X-CSRF-Token")
    if not submitted and request.is_json:
        body = request.get_json(silent=True) or {}
        submitted = body.get("csrf_token")
    if not submitted:
        return False
    return hmac.compare_digest(expected, submitted)

# /api/invite is server-to-server (called by the admin panel, authenticated
# via X-Admin-Token, no browser session) — exempt from CSRF enforcement.
CSRF_EXEMPT_PATHS = {"/api/invite"}

@app.before_request
def enforce_csrf():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if request.path in CSRF_EXEMPT_PATHS:
            return
        if not verify_csrf_token():
            return jsonify({"error": "Invalid or missing CSRF token"}), 403

# ── Login rate limiting — SQLite-backed (shared across Gunicorn workers) ──
MAX_ATTEMPTS = 5
LOGIN_WINDOW = 300

def _rl_conn():
    """Short-lived connection with its own transaction control, used only for
    rate-limit bookkeeping so it never interferes with the request's main g.db
    transaction. BEGIN IMMEDIATE serializes concurrent writers (other Gunicorn
    worker processes included) at the SQLite file level."""
    conn = sqlite3.connect(DB_PATH, timeout=5, isolation_level=None)
    conn.execute("PRAGMA busy_timeout=5000")
    return conn

def normalize_login_identifier(identifier):
    """Normalize a submitted email for use as a rate-limit key so trivial
    case variation (or incidental whitespace) can't be used to dodge the
    per-account counter by presenting as a "different" account."""
    return (identifier or "").strip().lower()

def check_login_rate(ip, identifier):
    """Rate-limit keyed on the submitted account identifier, not ip alone (F10).

    The old ip-only limiter had two failure modes: (1) one attacker behind a
    shared/NATed IP could exhaust the shared budget by cycling emails from
    that one IP, locking out every client who happens to log in from the
    same address (one bad actor, many victims); (2) an attacker distributed
    across many source IPs could hammer a single victim account completely
    unnoticed, since each IP got its own separate budget.

    A per-account backoff (count keyed on the normalized identifier alone,
    across all source IPs) fixes both: account A's failed attempts never
    borrow from or spend account B's budget regardless of shared IP, and an
    account under attack is throttled no matter how many different IPs the
    attempts arrive from. `ip` is still recorded on every row (see
    record_attempt) purely for audit/forensics — it is intentionally not
    part of the throttle decision itself, per the report's directive to
    "prefer per-account backoff over a global cutoff."
    """
    identifier = normalize_login_identifier(identifier)
    conn = _rl_conn()
    try:
        now = time.time()
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "DELETE FROM login_attempts WHERE scope='portal' AND created_at < ?",
            (now - LOGIN_WINDOW,)
        )
        count = conn.execute(
            "SELECT COUNT(*) FROM login_attempts "
            "WHERE scope='portal' AND identifier=?",
            (identifier,)
        ).fetchone()[0]
        conn.execute("COMMIT")
        return count < MAX_ATTEMPTS
    finally:
        conn.close()

def record_attempt(ip, identifier):
    identifier = normalize_login_identifier(identifier)
    conn = _rl_conn()
    try:
        conn.execute(
            "INSERT INTO login_attempts (scope, ip, identifier, created_at) "
            "VALUES ('portal', ?, ?, ?)",
            (ip, identifier, time.time())
        )
    finally:
        conn.close()

def clear_attempts(ip, identifier):
    identifier = normalize_login_identifier(identifier)
    conn = _rl_conn()
    try:
        conn.execute(
            "DELETE FROM login_attempts WHERE scope='portal' AND identifier=?",
            (identifier,)
        )
    finally:
        conn.close()

# ── Routes ────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if "client_user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        ip = request.remote_addr
        email = request.form.get("email", "").strip().lower()
        if not check_login_rate(ip, email):
            error = "Too many login attempts. Please wait 5 minutes."
        else:
            password = request.form.get("password", "")
            db = get_db()
            cu = db.execute(
                "SELECT * FROM client_users WHERE email=? AND status='active'",
                (email,)
            ).fetchone()
            ok = False
            if cu:
                if cu["password_hash"].startswith("$2"):
                    ok = bcrypt.checkpw(password.encode(), cu["password_hash"].encode())
            if cu and ok:
                clear_attempts(ip, email)
                session["client_user_id"] = cu["id"]
                session["client_id"] = cu["client_id"]
                session["email"] = cu["email"]
                session["last_seen"] = time.time()
                db.execute("UPDATE client_users SET last_login=? WHERE id=?", (time.time(), cu["id"]))
                db.commit()
                return redirect(url_for("dashboard"))
            record_attempt(ip, email)
            error = "Invalid email or password."
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/activate/<token>", methods=["GET", "POST"])
def activate(token):
    """Client activates their account via invitation link."""
    db = get_db()
    inv = db.execute(
        "SELECT * FROM client_invitations WHERE token=? AND used=0 AND expires_at>?",
        (token, time.time())
    ).fetchone()
    if not inv:
        return render_template("activate.html", error="Invalid or expired invitation link.", token=None)

    error = None
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if len(password) < 8:
            error = "Password must be at least 8 characters."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            pwd_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

            # Check if user already exists
            existing = db.execute(
                "SELECT id FROM client_users WHERE email=?", (inv["email"],)
            ).fetchone()

            if existing:
                db.execute(
                    "UPDATE client_users SET password_hash=? WHERE email=?",
                    (pwd_hash, inv["email"])
                )
            else:
                db.execute(
                    "INSERT INTO client_users (id, client_id, email, password_hash, created_at) VALUES (?,?,?,?,?)",
                    (str(uuid.uuid4()), inv["client_id"], inv["email"], pwd_hash, time.time())
                )
            db.execute("UPDATE client_invitations SET used=1 WHERE id=?", (inv["id"],))
            db.commit()
            return render_template("activate.html", success=True, token=None)

    return render_template("activate.html", inv=inv, token=token, error=error)

@app.route("/dashboard")
@login_required
def dashboard():
    cu, client = get_current_client()
    if not client:
        session.clear()
        return redirect(url_for("login"))
    db = get_db()

    # Stats
    total = db.execute(
        "SELECT COUNT(*) FROM receipts WHERE client_id=?", (client["id"],)
    ).fetchone()[0]
    stamped = db.execute(
        "SELECT COUNT(*) FROM receipts WHERE client_id=? AND rfc3161_ts IS NOT NULL",
        (client["id"],)
    ).fetchone()[0]
    recent = db.execute(
        "SELECT * FROM receipts WHERE client_id=? ORDER BY created_at DESC LIMIT 5",
        (client["id"],)
    ).fetchall()

    # Quota
    quota_pct = 0
    if client["monthly_limit"] and client["monthly_limit"] > 0:
        quota_pct = min(100, round((client["month_count"] or 0) / client["monthly_limit"] * 100))

    plan_labels = {
        "starter": "Starter — $299/mo — 100,000 decisions/mo",
        "growth": "Growth — $799/mo — 1,000,000 decisions/mo",
        "enterprise": "Enterprise — Custom",
    }

    return render_template("dashboard.html",
        cu=cu, client=client, total=total, stamped=stamped,
        recent=recent, quota_pct=quota_pct,
        plan_label=plan_labels.get(client["plan"], client["plan"].upper())
    )

@app.route("/receipts")
@login_required
def receipts():
    cu, client = get_current_client()
    db = get_db()
    search = request.args.get("search", "").strip()
    status_filter = request.args.get("status", "")
    page = max(1, int(request.args.get("page", 1)))
    per_page = 50

    query = "SELECT * FROM receipts WHERE client_id=?"
    params = [client["id"]]
    if status_filter:
        query += " AND status=?"
        params.append(status_filter)
    if search:
        query += " AND (id LIKE ? OR agent_id LIKE ? OR decision_type LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

    total = get_db().execute(
        query.replace("SELECT *", "SELECT COUNT(*)"), params
    ).fetchone()[0]

    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([per_page, (page - 1) * per_page])
    receipt_list = db.execute(query, params).fetchall()
    total_pages = max(1, (total + per_page - 1) // per_page)

    return render_template("receipts.html",
        cu=cu, client=client, receipts=receipt_list,
        search=search, status_filter=status_filter,
        page=page, total_pages=total_pages, total=total
    )

@app.route("/receipts/<rid>")
@login_required
def receipt_detail(rid):
    cu, client = get_current_client()
    db = get_db()
    receipt = verify_client_ownership(db, rid, client["id"])
    if not receipt:
        return "Receipt not found", 404

    import json as _json
    try:
        receipt_json = _json.dumps({
            "receipt_id":    receipt["id"],
            "agent_id":      receipt["agent_id"],
            "decision_type": receipt["decision_type"] or "",
            "decision":      (receipt["decision"] or "")[:2000],
            "regulation":    receipt["regulation"] or "",
            "block_number":  receipt["block_number"],
            "input_hash":    receipt["input_hash"] or "",
            "rfc3161_ts":    receipt["rfc3161_ts"] or None,
            "status":        receipt["status"] or "",
            "created_at":    fmt_date(receipt["created_at"]),
        }, indent=2, ensure_ascii=True)
    except Exception as e:
        receipt_json = f'{{"error": "{str(e)}"}}'

    return render_template("receipt_detail.html",
        cu=cu, client=client, r=receipt, receipt_json=receipt_json
    )

@app.route("/reports")
@login_required
def reports():
    cu, client = get_current_client()
    db = get_db()
    total = db.execute(
        "SELECT COUNT(*) FROM receipts WHERE client_id=?", (client["id"],)
    ).fetchone()[0]
    stamped = db.execute(
        "SELECT COUNT(*) FROM receipts WHERE client_id=? AND rfc3161_ts IS NOT NULL",
        (client["id"],)
    ).fetchone()[0]
    return render_template("reports.html", cu=cu, client=client, total=total, stamped=stamped)

@app.route("/reports/csv")
@login_required
def report_csv():
    import csv, io
    cu, client = get_current_client()
    db = get_db()
    receipts = db.execute(
        "SELECT * FROM receipts WHERE client_id=? ORDER BY created_at DESC",
        (client["id"],)
    ).fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Receipt ID","Agent ID","Decision Type","Regulation",
                     "Block Number","RFC 3161 Timestamp","Input Hash","Status","Created At UTC"])
    for r in receipts:
        writer.writerow([r["id"], r["agent_id"], r["decision_type"],
                        r["regulation"], r["block_number"],
                        r["rfc3161_ts"] or "PENDING",
                        r["input_hash"], r["status"], fmt_date(r["created_at"])])
    company = client["company_name"].replace(" ", "_")
    filename = f"vaultra_receipts_{company}_{time.strftime('%Y%m%d')}.csv"
    from flask import Response
    return Response(output.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"})

@app.route("/reports/pdf")
@login_required
def report_pdf():
    cu, client = get_current_client()
    db = get_db()
    receipts = db.execute(
        "SELECT * FROM receipts WHERE client_id=? ORDER BY created_at DESC",
        (client["id"],)
    ).fetchall()

    approved = sum(1 for r in receipts if "APPROVED" in (r["decision_type"] or ""))
    rejected = sum(1 for r in receipts if "REJECTED" in (r["decision_type"] or ""))
    review   = sum(1 for r in receipts if "REVIEW" in (r["decision_type"] or ""))
    stamped  = sum(1 for r in receipts if r["rfc3161_ts"])

    css = """
    body{font-family:'Courier New',monospace;font-size:11px;color:#111;margin:40px}
    h1{font-size:18px;color:#0a0a0a;border-bottom:2px solid #c9a84c;padding-bottom:8px}
    .meta{background:#f9f7f0;border:1px solid #e0d8c0;padding:12px;margin:16px 0;border-radius:4px}
    .stats{display:flex;gap:16px;margin:16px 0}
    .stat{background:#0a0a0a;color:#c9a84c;padding:10px 16px;border-radius:4px;text-align:center}
    .stat .n{font-size:20px;font-weight:bold}.stat .l{font-size:9px;color:#888}
    table{width:100%;border-collapse:collapse;margin-top:12px;font-size:9px}
    th{background:#0a0a0a;color:#c9a84c;padding:5px 6px;text-align:left}
    tr:nth-child(even){background:#f9f7f0}
    td{padding:4px 6px;border-bottom:1px solid #e8e8e8}
    .badge{display:inline-block;padding:1px 5px;border-radius:3px;font-size:8px;font-weight:bold}
    .approved{background:#d4edda;color:#155724}
    .rejected{background:#f8d7da;color:#721c24}
    .review{background:#fff3cd;color:#856404}
    .stamped{background:#d4edda;color:#155724}
    .pending{background:#fff3cd;color:#856404}
    .footer{margin-top:24px;padding-top:10px;border-top:1px solid #ddd;font-size:8px;color:#888}
    @media print{body{margin:20px}}
    """

    # This HTML is hand-built outside Jinja (no autoescaping) — company_name is
    # admin-editable free text, and agent_id/decision_type/regulation below
    # come from the client's own /api/receipt submissions, so all of it must
    # be explicitly escaped or this is a stored-XSS vector.
    company_name = escape(client["company_name"])
    plan_upper = escape(client["plan"].upper())

    parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        f"<title>Vaultra Compliance Report — {company_name}</title>",
        f"<style>{css}</style></head><body>",
        "<h1>Vaultra — Compliance Receipt Report</h1>",
        "<div class='meta'>",
        f"<p><b>Client:</b> {company_name}</p>",
        f"<p><b>Plan:</b> {plan_upper} | <b>Regulation:</b> EU AI Act Art. 12 + GDPR Art. 22</p>",
        f"<p><b>Generated:</b> {fmt_date(time.time())} | <b>Sectigo eIDAS QTSP</b> — RFC 3161 timestamps</p>",
        f"<p><b>Total:</b> {len(receipts)} receipts | <b>Stamped:</b> {stamped}/{len(receipts)}</p>",
        "</div>",
        "<div class='stats'>",
        f"<div class='stat'><div class='n'>{len(receipts)}</div><div class='l'>TOTAL</div></div>",
        f"<div class='stat'><div class='n'>{approved}</div><div class='l'>APPROVED</div></div>",
        f"<div class='stat'><div class='n'>{rejected}</div><div class='l'>REJECTED</div></div>",
        f"<div class='stat'><div class='n'>{review}</div><div class='l'>REVIEW</div></div>",
        f"<div class='stat'><div class='n'>{stamped}</div><div class='l'>STAMPED</div></div>",
        "</div>",
        "<table><tr><th>Receipt ID</th><th>Agent</th><th>Decision</th>",
        "<th>Regulation</th><th>Block</th><th>RFC 3161</th><th>Status</th><th>Date</th></tr>",
    ]

    for r in receipts:
        dt_raw = (r["decision_type"] or "UNKNOWN").upper()
        bc = "approved" if "APPROVED" in dt_raw else ("rejected" if "REJECTED" in dt_raw else "review")
        dt = escape(dt_raw)
        rid = escape((r["id"] or "")[:8])
        agent = escape(r["agent_id"] or "")
        regulation = escape(r["regulation"] or "")
        status = escape((r["status"] or "").upper())
        rfc_html = '<span class="badge stamped">STAMPED</span>' if r["rfc3161_ts"] else '<span class="badge pending">PENDING</span>'
        parts.append(
            "<tr>"
            + f'<td style="color:#c9a84c;font-size:8px">{rid}</td>'
            + f"<td>{agent}</td>"
            + f'<td><span class="badge {bc}">{dt}</span></td>'
            + f'<td style="font-size:8px">{regulation}</td>'
            + f"<td>#{r['block_number']}</td>"
            + f"<td>{rfc_html}</td>"
            + f"<td>{status}</td>"
            + f"<td style='white-space:nowrap'>{fmt_date(r['created_at'])}</td>"
            + "</tr>"
        )

    parts.extend([
        "</table>",
        "<div class='footer'>",
        "<p>Generated by Vaultra AI Agent Compliance Layer — vaultra.io</p>",
        "<p>All receipts are cryptographically signed and timestamped by Sectigo eIDAS QTSP under eIDAS Art. 41.</p>",
        f"<p>Report generated: {fmt_date(time.time())} | Confidential</p>",
        "</div></body></html>",
    ])

    company = client["company_name"].replace(" ", "_")
    filename = f"vaultra_report_{company}_{time.strftime('%Y%m%d')}.html"
    from flask import Response
    return Response("".join(parts), mimetype="text/html",
        headers={"Content-Disposition": f"inline; filename={filename}"})

@app.route("/settings")
@login_required
def settings():
    cu, client = get_current_client()
    return render_template("settings.html", cu=cu, client=client)

@app.route("/settings/change-password", methods=["POST"])
@login_required
def change_password():
    cu, client = get_current_client()
    data = request.get_json()
    current = data.get("current_password", "")
    new_pwd = data.get("new_password", "")
    confirm = data.get("confirm_password", "")
    if not all([current, new_pwd, confirm]):
        return jsonify({"error": "All fields required"}), 400
    if new_pwd != confirm:
        return jsonify({"error": "Passwords do not match"}), 400
    if len(new_pwd) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    ok = False
    if cu["password_hash"].startswith("$2"):
        ok = bcrypt.checkpw(current.encode(), cu["password_hash"].encode())
    if not ok:
        return jsonify({"error": "Current password incorrect"}), 401
    new_hash = bcrypt.hashpw(new_pwd.encode(), bcrypt.gensalt()).decode()
    db = get_db()
    db.execute("UPDATE client_users SET password_hash=? WHERE id=?", (new_hash, cu["id"]))
    db.commit()
    return jsonify({"success": True})

@app.route("/health")
@cross_origin(origins=PUBLIC_ORIGINS, methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "vaultra-portal", "version": "1.0.1"})

# ── Admin API — create invitation (called from admin panel) ───────────────
@app.route("/api/invite", methods=["POST"])
def create_invitation():
    """Called by admin panel to create a client invitation."""
    auth = request.headers.get("X-Admin-Token", "")
    expected = os.environ.get("PORTAL_ADMIN_TOKEN", "")
    if not expected or auth != expected:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    client_id = data.get("client_id")
    email = data.get("email")
    if not client_id or not email:
        return jsonify({"error": "client_id and email required"}), 400

    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.execute("PRAGMA foreign_keys=ON")
    token = secrets.token_urlsafe(32)
    inv_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO client_invitations (id, client_id, email, token, created_at, expires_at) VALUES (?,?,?,?,?,?)",
        (inv_id, client_id, email, token, time.time(), time.time() + 7 * 86400)
    )
    db.commit()
    db.close()

    portal_url = os.environ.get("PORTAL_URL", "https://app.vaultra.io")
    return jsonify({
        "success": True,
        "invitation_url": f"{portal_url}/activate/{token}",
        "expires_in": "7 days"
    })

# ── Error handlers — no stacktraces leaked to the client ──────────────────
def _wants_json():
    return request.path.startswith("/api/") or request.accept_mimetypes["application/json"] >= request.accept_mimetypes["text/html"]

@app.errorhandler(404)
def handle_404(e):
    if _wants_json():
        return jsonify({"error": "Not found"}), 404
    return (
        "<!DOCTYPE html><html><head><title>404 — Not Found</title>"
        "<style>body{font-family:sans-serif;background:#0a0a0a;color:#eee;"
        "display:flex;align-items:center;justify-content:center;height:100vh;margin:0}"
        ".box{text-align:center}h1{color:#c9a84c;font-size:48px;margin:0}"
        "a{color:#c9a84c}</style></head><body><div class='box'>"
        "<h1>404</h1><p>Page not found.</p><p><a href='/'>Return to dashboard</a></p>"
        "</div></body></html>",
        404,
    )

@app.errorhandler(500)
def handle_500(e):
    app.logger.error("Internal server error on %s: %s", request.path, e)
    if _wants_json():
        return jsonify({"error": "Internal server error"}), 500
    return (
        "<!DOCTYPE html><html><head><title>500 — Server Error</title>"
        "<style>body{font-family:sans-serif;background:#0a0a0a;color:#eee;"
        "display:flex;align-items:center;justify-content:center;height:100vh;margin:0}"
        ".box{text-align:center}h1{color:#c9a84c;font-size:48px;margin:0}"
        "a{color:#c9a84c}</style></head><body><div class='box'>"
        "<h1>500</h1><p>Something went wrong on our end. It's been logged.</p>"
        "<p><a href='/'>Return to dashboard</a></p>"
        "</div></body></html>",
        500,
    )

if __name__ == "__main__":
    init_portal_db()
    app.run(host="127.0.0.1", port=8001, debug=False)
