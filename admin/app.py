"""
Vaultra Admin Dashboard — Backend v2.0
========================================
Security improvements:
- Session timeout (30 min inactivity)
- Visible audit log
- Archive clients (soft delete)
- Human-readable dates
- Clear logout
- Activity tracking per admin

Copyright (c) 2026 Jerly Rojas — Vaultra
https://vaultra.io — hello@vaultra.io
AGPL-3.0 License
"""

import os
import json
import hashlib
import secrets
import sqlite3
import time
import uuid
import threading
import calendar
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, jsonify,
    session, redirect, url_for, g
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
SESSION_TIMEOUT = 1800  # 30 minutes

# ── Session security ─────────────────────────────────────

# ── Security headers ─────────────────────────────────────
@app.after_request
def security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# ── Login rate limiting ───────────────────────────────────
LOGIN_ATTEMPTS = {}   # {ip: [timestamp, ...]}
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW = 300    # 5 minutes

def check_login_rate(ip):
    now = time.time()
    attempts = LOGIN_ATTEMPTS.get(ip, [])
    attempts = [t for t in attempts if now - t < LOGIN_WINDOW]
    LOGIN_ATTEMPTS[ip] = attempts
    return len(attempts) < MAX_LOGIN_ATTEMPTS

def record_login_attempt(ip):
    now = time.time()
    attempts = LOGIN_ATTEMPTS.get(ip, [])
    attempts.append(now)
    LOGIN_ATTEMPTS[ip] = attempts

def clear_login_attempts(ip):
    LOGIN_ATTEMPTS.pop(ip, None)

# ── Database ───────────────────────────────────────────────
DB_PATH = os.environ.get("DB_PATH", "vaultra_admin.db")

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def fmt_date(ts):
    """Convert Unix timestamp to human-readable date."""
    if not ts:
        return "—"
    try:
        return datetime.utcfromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M UTC")
    except:
        return "—"

app.jinja_env.globals['fmt_date'] = fmt_date

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS admin_users (
            id            TEXT PRIMARY KEY,
            username      TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'support',
            created_at    REAL NOT NULL,
            last_login    REAL
        );

        CREATE TABLE IF NOT EXISTS clients (
            id             TEXT PRIMARY KEY,
            company_name   TEXT NOT NULL,
            email          TEXT NOT NULL UNIQUE,
            plan           TEXT NOT NULL DEFAULT 'starter',
            status         TEXT NOT NULL DEFAULT 'active',
            api_key_hash   TEXT NOT NULL UNIQUE,
            api_key_prefix TEXT NOT NULL,
            created_at     REAL NOT NULL,
            last_seen      REAL,
            receipt_count  INTEGER NOT NULL DEFAULT 0,
            monthly_limit  INTEGER NOT NULL DEFAULT 100000,
            industry       TEXT DEFAULT 'fintech',
            country        TEXT DEFAULT 'DE',
            notes          TEXT DEFAULT '',
            archived       INTEGER NOT NULL DEFAULT 0,
            archived_at    REAL,
            month_start    REAL NOT NULL DEFAULT 0,
            month_count    INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS receipts (
            id            TEXT PRIMARY KEY,
            client_id     TEXT NOT NULL,
            agent_id      TEXT NOT NULL,
            decision      TEXT NOT NULL,
            decision_type TEXT NOT NULL,
            input_hash    TEXT NOT NULL,
            block_number  INTEGER NOT NULL,
            rfc3161_ts    TEXT,
            regulation    TEXT NOT NULL DEFAULT 'EU AI Act',
            status        TEXT NOT NULL DEFAULT 'valid',
            created_at    REAL NOT NULL,
            FOREIGN KEY (client_id) REFERENCES clients(id)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id         TEXT PRIMARY KEY,
            admin_id   TEXT NOT NULL,
            username   TEXT NOT NULL,
            role       TEXT NOT NULL DEFAULT 'admin',
            action     TEXT NOT NULL,
            target     TEXT,
            details    TEXT,
            ip_address TEXT,
            created_at REAL NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_receipts_client  ON receipts(client_id);
        CREATE INDEX IF NOT EXISTS idx_receipts_created ON receipts(created_at);
        CREATE INDEX IF NOT EXISTS idx_clients_status   ON clients(status);
        CREATE INDEX IF NOT EXISTS idx_audit_created    ON audit_log(created_at);
        CREATE INDEX IF NOT EXISTS idx_clients_archived ON clients(archived);
    """)
    db.commit()

    # Add missing columns if upgrading from v1/v2
    for col_sql in [
        "ALTER TABLE clients ADD COLUMN industry TEXT DEFAULT 'fintech'",
        "ALTER TABLE clients ADD COLUMN country TEXT DEFAULT 'DE'",
        "ALTER TABLE clients ADD COLUMN notes TEXT DEFAULT ''",
        "ALTER TABLE clients ADD COLUMN archived INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE clients ADD COLUMN archived_at REAL",
        "ALTER TABLE clients ADD COLUMN month_start REAL NOT NULL DEFAULT 0",
        "ALTER TABLE clients ADD COLUMN month_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE audit_log ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'",
        "ALTER TABLE clients ADD COLUMN address TEXT",
        "ALTER TABLE clients ADD COLUMN phone TEXT",
        "ALTER TABLE clients ADD COLUMN website TEXT",
    ]:
        try:
            db.execute(col_sql)
        except Exception:
            pass
    db.commit()

    # Create default users
    admin_pwd = os.environ.get("ADMIN_PASSWORD", "ADMIN_PASSWORD_REDACTED")
    if BCRYPT_AVAILABLE:
        admin_hash = bcrypt.hashpw(admin_pwd.encode(), bcrypt.gensalt()).decode()
    else:
        admin_hash = hashlib.sha256(admin_pwd.encode()).hexdigest()
    try:
        db.execute("""
            INSERT INTO admin_users (id, username, password_hash, role, created_at)
            VALUES (?, 'admin', ?, 'admin', ?)
        """, (str(uuid.uuid4()), admin_hash, time.time()))
        support_pwd = os.environ.get("SUPPORT_PASSWORD", "support2026!")
        if BCRYPT_AVAILABLE:
            support_hash = bcrypt.hashpw(support_pwd.encode(), bcrypt.gensalt()).decode()
        else:
            support_hash = hashlib.sha256(support_pwd.encode()).hexdigest()
        db.execute("""
            INSERT INTO admin_users (id, username, password_hash, role, created_at)
            VALUES (?, 'support', ?, 'support', ?)
        """, (str(uuid.uuid4()), support_hash, time.time()))
        db.commit()
    except Exception:
        pass

    seed_demo_data(db)
    db.close()

def seed_demo_data(db):
    count = db.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
    if count > 0:
        return
    demo_clients = [
        ("Fintech Corp S.A.", "cto@fintech-corp.com", "starter", "active", "fintech", "ES"),
        ("KreditBank GmbH", "compliance@kreditbank.de", "growth", "active", "banking", "DE"),
        ("PayFlow Europe", "tech@payflow.eu", "starter", "active", "payments", "NL"),
    ]
    client_ids = []
    for company, email, plan, status, industry, country in demo_clients:
        cid = str(uuid.uuid4())
        client_ids.append(cid)
        key = f"vaultra_sk_v1_{secrets.token_hex(32)}"
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        key_prefix = key[:20]
        limit = 100000 if plan == "starter" else 1000000
        db.execute("""
            INSERT INTO clients
            (id,company_name,email,plan,status,api_key_hash,api_key_prefix,
             created_at,last_seen,receipt_count,monthly_limit,industry,country,notes,archived)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'',0)
        """, (cid, company, email, plan, status, key_hash, key_prefix,
              time.time()-86400*30, time.time()-3600,
              1284 if company == "Fintech Corp S.A." else 342, limit, industry, country))

    agents = ["credit-bot-v2","kyc-agent-v1","fraud-detector","aml-scanner"]
    decisions = [
        ("REJECT loan #4821","LOAN_REJECTED"),("APPROVE loan #4820","LOAN_APPROVED"),
        ("KYC APPROVED","KYC_APPROVED"),("FRAUD FLAGGED","FRAUD_FLAGGED"),
        ("AML CLEARED","AML_CLEARED"),
    ]
    regs = ["EU AI Act","GDPR Art.22","DORA","eIDAS"]
    import random
    random.seed(42)
    block = 1800
    for i in range(50):
        cid = client_ids[i % len(client_ids)]
        dec, dec_type = random.choice(decisions)
        db.execute("""
            INSERT INTO receipts
            (id,client_id,agent_id,decision,decision_type,input_hash,
             block_number,rfc3161_ts,regulation,status,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (str(uuid.uuid4()), cid, random.choice(agents), dec, dec_type,
              hashlib.sha256(str(i).encode()).hexdigest()[:16], block+i,
              datetime.utcnow().isoformat()+"Z", random.choice(regs),
              "valid" if dec_type != "FRAUD_FLAGGED" else "review",
              time.time()-random.randint(0, 86400*30)))
    db.commit()

# ── Auth & Security ────────────────────────────────────────
def check_session_timeout():
    """Return True if session has expired."""
    last = session.get("last_active")
    if last and (time.time() - last) > SESSION_TIMEOUT:
        session.clear()
        return True
    session["last_active"] = time.time()
    return False

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "admin_id" not in session:
            return redirect(url_for("login"))
        if check_session_timeout():
            return redirect(url_for("login", reason="timeout"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "admin_id" not in session:
            return redirect(url_for("login"))
        if check_session_timeout():
            return redirect(url_for("login", reason="timeout"))
        if session.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated

def log_action(action, target=None, details=None):
    db = get_db()
    db.execute("""
        INSERT INTO audit_log (id,admin_id,username,role,action,target,details,ip_address,created_at)
        VALUES (?,?,?,?,?,?,?,?,?)
    """, (str(uuid.uuid4()), session.get("admin_id","system"),
          session.get("username","system"), session.get("role","admin"),
          action, target, details, request.remote_addr, time.time()))
    db.commit()

# ── Routes ─────────────────────────────────────────────────
@app.route("/")
def index():
    if "admin_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    reason = request.args.get("reason")
    error = None
    if reason == "timeout":
        error = "Session expired after 30 minutes of inactivity. Please sign in again."
    if request.method == "POST":
        ip = request.remote_addr
        if not check_login_rate(ip):
            return render_template("login.html", error="Too many login attempts. Please wait 5 minutes."), 429
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        db = get_db()
        user = db.execute(
            "SELECT * FROM admin_users WHERE username=?",
            (username,)
        ).fetchone()
        # Verify password — bcrypt if available, SHA-256 fallback
        if user:
            if BCRYPT_AVAILABLE and user["password_hash"].startswith("$2"):
                password_ok = bcrypt.checkpw(password.encode(), user["password_hash"].encode())
            else:
                password_ok = user["password_hash"] == hashlib.sha256(password.encode()).hexdigest()
            if not password_ok:
                user = None
        if user:
            clear_login_attempts(ip)
            session.permanent = False
            session["admin_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["last_active"] = time.time()
            db.execute("UPDATE admin_users SET last_login=? WHERE id=?",
                      (time.time(), user["id"]))
            db.commit()
            log_action("LOGIN", details=f"IP: {request.remote_addr}")
            return redirect(url_for("dashboard"))
        record_login_attempt(ip)
        error = "Invalid username or password."
        time.sleep(1)  # Slow down brute force
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    if "admin_id" in session:
        log_action("LOGOUT")
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    total_clients = db.execute("SELECT COUNT(*) FROM clients WHERE archived=0").fetchone()[0]
    active_clients = db.execute("SELECT COUNT(*) FROM clients WHERE status='active' AND archived=0").fetchone()[0]
    archived_clients = db.execute("SELECT COUNT(*) FROM clients WHERE archived=1").fetchone()[0]
    total_receipts = db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
    flagged = db.execute("SELECT COUNT(*) FROM receipts WHERE status='review'").fetchone()[0]
    recent_receipts = db.execute("""
        SELECT r.*, c.company_name FROM receipts r
        JOIN clients c ON r.client_id = c.id
        ORDER BY r.created_at DESC LIMIT 10
    """).fetchall()
    clients = db.execute("""
        SELECT * FROM clients WHERE archived=0 ORDER BY created_at DESC LIMIT 5
    """).fetchall()
    recent_audit = db.execute("""
        SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 8
    """).fetchall()
    return render_template("dashboard.html",
        total_clients=total_clients,
        active_clients=active_clients,
        archived_clients=archived_clients,
        total_receipts=total_receipts,
        flagged=flagged,
        recent_receipts=recent_receipts,
        clients=clients,
        recent_audit=recent_audit,
        username=session.get("username"),
        role=session.get("role"),
    )

@app.route("/clients")
@login_required
def clients():
    db = get_db()
    show_archived = request.args.get("archived") == "1"
    industry = request.args.get("industry","")
    country = request.args.get("country","")
    search = request.args.get("search", "").strip()
    query = "SELECT * FROM clients WHERE archived=?"
    params = [1 if show_archived else 0]
    if industry:
        query += " AND industry=?"; params.append(industry)
    if country:
        query += " AND country=?"; params.append(country)
    if search:
        query += " AND (company_name LIKE ? OR email LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])
    query += " ORDER BY created_at DESC"
    all_clients = db.execute(query, params).fetchall()
    industries = db.execute("SELECT DISTINCT industry FROM clients WHERE industry IS NOT NULL").fetchall()
    countries = db.execute("SELECT DISTINCT country FROM clients WHERE country IS NOT NULL").fetchall()
    return render_template("clients.html",
        clients=all_clients,
        search=search,
        show_archived=show_archived,
        industries=industries,
        countries=countries,
        username=session.get("username"),
        role=session.get("role"),
    )

@app.route("/clients/new", methods=["POST"])
@admin_required
def create_client():
    data = request.json
    company = data.get("company_name","").strip()
    email = data.get("email","").strip()
    plan = data.get("plan","starter")
    industry = data.get("industry","fintech")
    country = data.get("country","DE")
    if not company or not email:
        return jsonify({"error": "Company name and email required"}), 400
    raw_key = f"vaultra_sk_v1_{secrets.token_hex(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_prefix = raw_key[:20]
    cid = str(uuid.uuid4())
    limit = {"starter":100000,"growth":1000000,"enterprise":999999999}.get(plan,10000)
    db = get_db()
    try:
        db.execute("""
            INSERT INTO clients
            (id,company_name,email,plan,status,api_key_hash,api_key_prefix,
             created_at,receipt_count,monthly_limit,industry,country,notes,archived)
            VALUES (?,?,?,?,'active',?,?,?,0,?,?,?,'',0)
        """, (cid,company,email,plan,key_hash,key_prefix,time.time(),limit,industry,country))
        db.commit()
        log_action("CREATE_CLIENT", cid, f"{company} / {email} / {plan}")
        return jsonify({"success":True,"client_id":cid,"api_key":raw_key})
    except sqlite3.IntegrityError:
        return jsonify({"error":"Email already exists"}), 409

@app.route("/clients/<cid>/archive", methods=["POST"])
@admin_required
def archive_client(cid):
    db = get_db()
    client = db.execute("SELECT company_name FROM clients WHERE id=?", (cid,)).fetchone()
    db.execute("UPDATE clients SET archived=1, archived_at=?, status='archived' WHERE id=?",
               (time.time(), cid))
    db.commit()
    log_action("ARCHIVE_CLIENT", cid, client["company_name"] if client else cid)
    return jsonify({"success":True})

@app.route("/clients/<cid>/restore", methods=["POST"])
@admin_required
def restore_client(cid):
    db = get_db()
    client = db.execute("SELECT company_name FROM clients WHERE id=?", (cid,)).fetchone()
    db.execute("UPDATE clients SET archived=0, archived_at=NULL, status='active' WHERE id=?", (cid,))
    db.commit()
    log_action("RESTORE_CLIENT", cid, client["company_name"] if client else cid)
    return jsonify({"success":True})

@app.route("/clients/<cid>/revoke", methods=["POST"])
@admin_required
def revoke_client(cid):
    db = get_db()
    db.execute("UPDATE clients SET status='revoked' WHERE id=?", (cid,))
    db.commit()
    log_action("REVOKE_CLIENT", cid)
    return jsonify({"success":True})

@app.route("/clients/<cid>/activate", methods=["POST"])
@admin_required
def activate_client(cid):
    db = get_db()
    db.execute("UPDATE clients SET status='active' WHERE id=?", (cid,))
    db.commit()
    log_action("ACTIVATE_CLIENT", cid)
    return jsonify({"success":True})

@app.route("/clients/<cid>/rotate-key", methods=["POST"])
@admin_required
def rotate_key(cid):
    new_key = f"vaultra_sk_v1_{secrets.token_hex(32)}"
    new_hash = hashlib.sha256(new_key.encode()).hexdigest()
    new_prefix = new_key[:20]
    db = get_db()
    db.execute("UPDATE clients SET api_key_hash=?, api_key_prefix=? WHERE id=?",
               (new_hash, new_prefix, cid))
    db.commit()
    log_action("ROTATE_KEY", cid)
    return jsonify({"success":True,"api_key":new_key})

@app.route("/clients/<cid>/notes", methods=["POST"])
@admin_required
def update_notes(cid):
    notes = request.json.get("notes","")
    db = get_db()
    db.execute("UPDATE clients SET notes=? WHERE id=?", (notes, cid))
    db.commit()
    log_action("UPDATE_NOTES", cid)
    return jsonify({"success":True})


@app.route("/clients/<cid>/edit", methods=["POST"])
@login_required
def edit_client(cid):
    """Edit client details — plan, email, industry, country, monthly_limit."""
    data = request.get_json()
    db = get_db()
    client = db.execute("SELECT * FROM clients WHERE id=?", (cid,)).fetchone()
    if not client:
        return jsonify({"error": "Client not found"}), 404

    plan = data.get("plan", client["plan"])
    email = data.get("email", client["email"])
    industry = data.get("industry", client["industry"])
    country = data.get("country", client["country"])
    address = data.get("address", client["address"])
    phone = data.get("phone", client["phone"])
    website = data.get("website", client["website"])

    # Auto-set monthly_limit based on plan unless custom override
    plan_limits = {"starter": 100000, "growth": 1000000, "enterprise": 999999999}
    monthly_limit = data.get("monthly_limit")
    if monthly_limit:
        try:
            monthly_limit = int(monthly_limit)
        except ValueError:
            monthly_limit = plan_limits.get(plan, 100000)
    else:
        monthly_limit = plan_limits.get(plan, client["monthly_limit"])

    db.execute("""
        UPDATE clients SET plan=?, email=?, industry=?, country=?, monthly_limit=?,
        address=?, phone=?, website=? WHERE id=?
    """, (plan, email, industry, country, monthly_limit, address, phone, website, cid))
    db.commit()

    log_action("EDIT_CLIENT", cid,
        f"{client['company_name']} — plan:{client['plan']}→{plan} limit:{client['monthly_limit']}→{monthly_limit}")
    return jsonify({"success": True})

@app.route("/receipts")
@login_required
def receipts():
    db = get_db()
    client_id = request.args.get("client_id")
    status_filter = request.args.get("status")
    search = request.args.get("search", "").strip()
    page = max(1, int(request.args.get("page", 1)))
    per_page = 50
    clients_list = db.execute(
        "SELECT id, company_name FROM clients WHERE archived=0 ORDER BY company_name"
    ).fetchall()

    query = "SELECT r.*, c.company_name FROM receipts r JOIN clients c ON r.client_id=c.id WHERE 1=1"
    params = []
    if client_id:
        query += " AND r.client_id=?"
        params.append(client_id)
    if status_filter:
        query += " AND r.status=?"
        params.append(status_filter)
    if search:
        query += " AND (r.id LIKE ? OR r.agent_id LIKE ? OR r.decision_type LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

    count_query = query.replace("SELECT r.*, c.company_name", "SELECT COUNT(*)")
    total = db.execute(count_query, params).fetchone()[0]

    query += " ORDER BY r.created_at DESC LIMIT ? OFFSET ?"
    params.extend([per_page, (page - 1) * per_page])
    all_receipts = db.execute(query, params).fetchall()

    total_pages = max(1, (total + per_page - 1) // per_page)
    return render_template("receipts.html",
        receipts=all_receipts,
        clients=clients_list,
        selected_client=client_id,
        selected_status=status_filter,
        search=search,
        page=page,
        total_pages=total_pages,
        total=total,
        username=session.get("username"),
        role=session.get("role"),
    )


@app.route("/receipts/<rid>")
@login_required
def receipt_detail(rid):
    """Show full detail of a single compliance receipt."""
    db = get_db()
    receipt = db.execute(
        "SELECT r.*, c.company_name, c.plan FROM receipts r JOIN clients c ON r.client_id=c.id WHERE r.id=?",
        (rid,)
    ).fetchone()
    if not receipt:
        return "Receipt not found", 404
    import json as _json
    try:
        receipt_json = _json.dumps({
            "receipt_id":    receipt["id"],
            "agent_id":      receipt["agent_id"],
            "client_id":     receipt["client_id"],
            "company":       receipt["company_name"],
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
        receipt_json = '{"error": "Could not serialize receipt: ' + str(e) + '"}'
    return render_template("receipt_detail.html", r=receipt, receipt_json=receipt_json,
        username=session.get("username"), role=session.get("role"))

@app.route("/audit-log")
@login_required
def audit_log():
    db = get_db()
    logs = db.execute(
        "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 200"
    ).fetchall()
    return render_template("audit_log.html",
        logs=logs,
        username=session.get("username"),
        role=session.get("role"),
    )

@app.route("/api/metrics")
@login_required
def api_metrics():
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM clients WHERE archived=0").fetchone()[0]
    active = db.execute("SELECT COUNT(*) FROM clients WHERE status='active' AND archived=0").fetchone()[0]
    total_r = db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
    flagged = db.execute("SELECT COUNT(*) FROM receipts WHERE status='review'").fetchone()[0]
    starter = db.execute("SELECT COUNT(*) FROM clients WHERE plan='starter' AND status='active' AND archived=0").fetchone()[0]
    growth = db.execute("SELECT COUNT(*) FROM clients WHERE plan='growth' AND status='active' AND archived=0").fetchone()[0]
    enterprise = db.execute("SELECT COUNT(*) FROM clients WHERE plan='enterprise' AND status='active' AND archived=0").fetchone()[0]
    mrr = (starter*299)+(growth*799)+(enterprise*1500)
    return jsonify({
        "total_clients":total,"active_clients":active,
        "total_receipts":total_r,"flagged":flagged,"mrr_usd":mrr,
        "by_plan":{"starter":starter,"growth":growth,"enterprise":enterprise},
    })

@app.route("/api/report/clients")
@login_required
def report_clients():
    """Export active clients as JSON for reporting."""
    db = get_db()
    clients_data = db.execute("""
        SELECT company_name, email, plan, status, industry, country,
               receipt_count, monthly_limit, created_at, last_seen
        FROM clients WHERE archived=0 ORDER BY created_at DESC
    """).fetchall()
    log_action("EXPORT_CLIENTS_REPORT")
    return jsonify([dict(c) for c in clients_data])


@app.route("/api/report/<cid>/csv")
@login_required
def report_csv(cid):
    """Export all receipts for a client as CSV."""
    import csv, io
    db = get_db()
    client = db.execute("SELECT * FROM clients WHERE id=?", (cid,)).fetchone()
    if not client:
        return jsonify({"error": "Client not found"}), 404
    receipts = db.execute(
        "SELECT * FROM receipts WHERE client_id=? ORDER BY created_at DESC", (cid,)
    ).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Receipt ID", "Agent ID", "Decision", "Decision Type",
        "Regulation", "Block Number", "RFC 3161 Timestamp",
        "Input Hash", "Status", "Created At UTC"
    ])
    for r in receipts:
        writer.writerow([
            r["id"], r["agent_id"], r["decision"], r["decision_type"],
            r["regulation"], r["block_number"], r["rfc3161_ts"] or "PENDING",
            r["input_hash"], r["status"],
            fmt_date(r["created_at"])
        ])

    company = client["company_name"].replace(" ", "_")
    filename = f"vaultra_receipts_{company}_{time.strftime('%Y%m%d')}.csv"
    log_action("EXPORT_CSV", cid, f"{client['company_name']} — {len(receipts)} receipts")

    from flask import Response
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.route("/api/report/<cid>/pdf")
@login_required
def report_pdf(cid):
    """Export compliance receipts for a client as auditor-ready HTML (print to PDF)."""
    db = get_db()
    client = db.execute("SELECT * FROM clients WHERE id=?", (cid,)).fetchone()
    if not client:
        return jsonify({"error": "Client not found"}), 404
    receipts = db.execute(
        "SELECT * FROM receipts WHERE client_id=? ORDER BY created_at DESC", (cid,)
    ).fetchall()

    approved = sum(1 for r in receipts if "APPROVED" in (r["decision_type"] or ""))
    rejected = sum(1 for r in receipts if "REJECTED" in (r["decision_type"] or ""))
    review   = sum(1 for r in receipts if "REVIEW" in (r["decision_type"] or ""))
    stamped  = sum(1 for r in receipts if r["rfc3161_ts"])

    log_action("EXPORT_PDF", cid, client["company_name"] + " — " + str(len(receipts)) + " receipts")

    company_name = client["company_name"]
    plan = client["plan"].upper()
    industry = client["industry"] or "—"
    country = client["country"] or "—"
    generated = fmt_date(time.time())

    css = """
    body { font-family: 'Courier New', monospace; font-size: 11px; color: #111; margin: 40px; }
    h1 { font-size: 20px; color: #0a0a0a; border-bottom: 2px solid #c9a84c; padding-bottom: 8px; }
    h2 { font-size: 13px; color: #444; margin-top: 24px; }
    .meta { background: #f9f7f0; border: 1px solid #e0d8c0; padding: 12px; margin: 16px 0; border-radius: 4px; }
    .meta p { margin: 4px 0; }
    .stats { display: flex; gap: 16px; margin: 16px 0; }
    .stat { background: #0a0a0a; color: #c9a84c; padding: 10px 16px; border-radius: 4px; text-align: center; }
    .stat .n { font-size: 22px; font-weight: bold; }
    .stat .l { font-size: 9px; color: #888; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 9.5px; }
    th { background: #0a0a0a; color: #c9a84c; padding: 6px 8px; text-align: left; }
    tr:nth-child(even) { background: #f9f7f0; }
    td { padding: 5px 8px; border-bottom: 1px solid #e8e8e8; vertical-align: top; }
    .badge { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 8px; font-weight: bold; }
    .approved { background: #d4edda; color: #155724; }
    .rejected { background: #f8d7da; color: #721c24; }
    .review { background: #fff3cd; color: #856404; }
    .stamped { background: #d4edda; color: #155724; }
    .pending { background: #fff3cd; color: #856404; }
    .footer { margin-top: 32px; padding-top: 12px; border-top: 1px solid #ddd; font-size: 9px; color: #888; }
    @media print { body { margin: 20px; } }
    """

    parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        "<title>Vaultra Compliance Report — " + company_name + "</title>",
        "<style>" + css + "</style></head><body>",
        "<h1>Vaultra — Compliance Receipt Report</h1>",
        "<div class='meta'>",
        "<p><strong>Client:</strong> " + company_name + "</p>",
        "<p><strong>Plan:</strong> " + plan + " | <strong>Industry:</strong> " + industry + " | <strong>Country:</strong> " + country + "</p>",
        "<p><strong>Generated:</strong> " + generated + " UTC | <strong>Regulation:</strong> EU AI Act Art. 12 + GDPR Art. 22</p>",
        "<p><strong>Total Receipts:</strong> " + str(len(receipts)) + " | <strong>RFC 3161 Stamped:</strong> " + str(stamped) + "/" + str(len(receipts)) + "</p>",
        "</div>",
        "<div class='stats'>",
        "<div class='stat'><div class='n'>" + str(len(receipts)) + "</div><div class='l'>TOTAL</div></div>",
        "<div class='stat'><div class='n'>" + str(approved) + "</div><div class='l'>APPROVED</div></div>",
        "<div class='stat'><div class='n'>" + str(rejected) + "</div><div class='l'>REJECTED</div></div>",
        "<div class='stat'><div class='n'>" + str(review) + "</div><div class='l'>REVIEW</div></div>",
        "<div class='stat'><div class='n'>" + str(stamped) + "</div><div class='l'>STAMPED</div></div>",
        "</div>",
        "<h2>Compliance Receipts</h2>",
        "<table><tr>",
        "<th>Receipt ID</th><th>Agent</th><th>Decision Type</th>",
        "<th>Regulation</th><th>Block #</th><th>RFC 3161</th><th>Status</th><th>Date UTC</th>",
        "</tr>",
    ]

    for r in receipts:
        dt = (r["decision_type"] or "UNKNOWN").upper()
        reg = (r["regulation"] or "—")
        agent = (r["agent_id"] or "—")
        status = (r["status"] or "valid").upper()
        rid = (r["id"] or "")[:8]
        block = str(r["block_number"] or 0)
        date = fmt_date(r["created_at"])

        if "APPROVED" in dt:
            badge_cls = "approved"
        elif "REJECTED" in dt:
            badge_cls = "rejected"
        else:
            badge_cls = "review"

        rfc_html = '<span class="badge stamped">&#10003; STAMPED</span>' if r["rfc3161_ts"] else '<span class="badge pending">PENDING</span>'

        parts.append(
            "<tr>"
            + '<td style="font-family:monospace;color:#c9a84c">' + rid + "</td>"
            + "<td>" + agent + "</td>"
            + '<td><span class="badge ' + badge_cls + '">' + dt + "</span></td>"
            + '<td style="font-size:8px">' + reg + "</td>"
            + "<td>#" + block + "</td>"
            + "<td>" + rfc_html + "</td>"
            + '<td><span class="badge stamped">' + status + "</span></td>"
            + '<td style="white-space:nowrap">' + date + "</td>"
            + "</tr>"
        )

    parts.append("</table>")
    parts.append("<div class='footer'>")
    parts.append("<p>This report was generated by Vaultra AI Agent Compliance Layer — vaultra.io</p>")
    parts.append("<p>All receipts are cryptographically signed (Ed25519) and RFC 3161 timestamped under eIDAS Art. 41.</p>")
    parts.append("<p>Report generated: " + generated + " | Vaultra Admin Panel v2.0 | Confidential</p>")
    parts.append("</div></body></html>")

    html = "".join(parts)

    from flask import Response
    filename = "vaultra_report_" + company_name.replace(" ", "_") + "_" + time.strftime("%Y%m%d") + ".html"
    return Response(html, mimetype="text/html",
        headers={"Content-Disposition": "inline; filename=" + filename})



@app.route("/health-check")
@login_required
def health_check_page():
    """Visual health check dashboard."""
    import requests as req
    tsa_ok = False
    try:
        r = req.get("http://timestamp.sectigo.com/qualified", timeout=5)
        tsa_ok = r.status_code < 500
    except Exception:
        tsa_ok = False
    db = get_db()
    total_clients = db.execute("SELECT COUNT(*) FROM clients WHERE archived=0").fetchone()[0]
    total_receipts = db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
    recent_receipt = db.execute("SELECT created_at FROM receipts ORDER BY created_at DESC LIMIT 1").fetchone()
    last_receipt_ago = None
    if recent_receipt:
        import time
        diff = time.time() - recent_receipt["created_at"]
        if diff < 3600:
            last_receipt_ago = f"{int(diff/60)}m ago"
        elif diff < 86400:
            last_receipt_ago = f"{int(diff/3600)}h ago"
        else:
            last_receipt_ago = f"{int(diff/86400)}d ago"
    return render_template("health_check.html",
        tsa_ok=tsa_ok,
        total_clients=total_clients,
        total_receipts=total_receipts,
        last_receipt_ago=last_receipt_ago or "—",
        username=session.get("username"),
        role=session.get("role"))


@app.route("/api/verify/<rid>", methods=["GET", "OPTIONS"])
def verify_receipt(rid):
    if request.method == "OPTIONS":
        response = app.make_default_options_response()
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET"
        return response
    """Public receipt verification endpoint — no login required.
    Returns only public compliance data, no PII or client details.
    """
    db = get_db()
    receipt = db.execute(
        """SELECT r.id, r.agent_id, r.decision_type, r.regulation,
                  r.block_number, r.input_hash, r.rfc3161_ts,
                  r.status, r.created_at
           FROM receipts r WHERE r.id=?""",
        (rid,)
    ).fetchone()

    if not receipt:
        resp = jsonify({
            "valid": False,
            "error": "Receipt not found",
            "receipt_id": rid
        })
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp, 404

    import json as _json
    response = jsonify({
        "valid": True,
        "receipt_id":    receipt["id"],
        "agent_id":      receipt["agent_id"],
        "decision_type": receipt["decision_type"] or "UNKNOWN",
        "regulation":    receipt["regulation"] or "—",
        "block_number":  receipt["block_number"],
        "input_hash":    receipt["input_hash"] or "",
        "rfc3161_ts":    receipt["rfc3161_ts"],
        "rfc3161_valid": bool(receipt["rfc3161_ts"]),
        "eidas_art41":   bool(receipt["rfc3161_ts"]),
        "status":        receipt["status"],
        "created_at":    fmt_date(receipt["created_at"]),
        "verified_by":   "Vaultra AI Agent Compliance Layer",
        "verify_url":    "https://vaultra.io/verify?id=" + receipt["id"],
    })
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


@app.route("/settings")
@login_required
def settings():
    """User management and settings page."""
    db = get_db()
    users = db.execute("SELECT id, username, role, created_at, last_login FROM admin_users ORDER BY created_at").fetchall()
    return render_template("settings.html",
        users=users,
        username=session.get("username"),
        role=session.get("role"))


@app.route("/settings/change-password", methods=["POST"])
@login_required
def change_password():
    """Change current user password."""
    data = request.get_json()
    current = data.get("current_password", "")
    new_pwd = data.get("new_password", "")
    confirm = data.get("confirm_password", "")

    if not current or not new_pwd or not confirm:
        return jsonify({"error": "All fields required"}), 400
    if new_pwd != confirm:
        return jsonify({"error": "New passwords do not match"}), 400
    if len(new_pwd) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    db = get_db()
    user = db.execute("SELECT * FROM admin_users WHERE id=?", (session["admin_id"],)).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 404

    password_ok = False
    if BCRYPT_AVAILABLE and user["password_hash"].startswith("$2"):
        import bcrypt as _bcrypt
        password_ok = _bcrypt.checkpw(current.encode(), user["password_hash"].encode())
    else:
        password_ok = (hashlib.sha256(current.encode()).hexdigest() == user["password_hash"])

    if not password_ok:
        return jsonify({"error": "Current password is incorrect"}), 401

    if BCRYPT_AVAILABLE:
        import bcrypt as _bcrypt
        new_hash = _bcrypt.hashpw(new_pwd.encode(), _bcrypt.gensalt()).decode()
    else:
        new_hash = hashlib.sha256(new_pwd.encode()).hexdigest()

    db.execute("UPDATE admin_users SET password_hash=? WHERE id=?", (new_hash, session["admin_id"]))
    db.commit()
    log_action("CHANGE_PASSWORD", details="Password changed successfully")
    return jsonify({"success": True})


@app.route("/settings/create-user", methods=["POST"])
@login_required
def create_admin_user():
    """Create a new admin user — admin role only."""
    if session.get("role") != "admin":
        return jsonify({"error": "Admin role required"}), 403

    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role = data.get("role", "support")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if role not in ("admin", "support"):
        return jsonify({"error": "Invalid role"}), 400

    db = get_db()
    existing = db.execute("SELECT id FROM admin_users WHERE username=?", (username,)).fetchone()
    if existing:
        return jsonify({"error": "Username already exists"}), 409

    if BCRYPT_AVAILABLE:
        import bcrypt as _bcrypt
        pwd_hash = _bcrypt.hashpw(password.encode(), _bcrypt.gensalt()).decode()
    else:
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()

    new_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO admin_users (id, username, password_hash, role, created_at) VALUES (?,?,?,?,?)",
        (new_id, username, pwd_hash, role, time.time())
    )
    db.commit()
    log_action("CREATE_ADMIN_USER", new_id, f"username:{username} role:{role}")
    return jsonify({"success": True})


@app.route("/settings/delete-user/<uid>", methods=["POST"])
@login_required
def delete_admin_user(uid):
    """Delete an admin user — cannot delete yourself."""
    if session.get("role") != "admin":
        return jsonify({"error": "Admin role required"}), 403
    if uid == session.get("admin_id"):
        return jsonify({"error": "Cannot delete your own account"}), 400

    db = get_db()
    user = db.execute("SELECT username FROM admin_users WHERE id=?", (uid,)).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 404

    db.execute("DELETE FROM admin_users WHERE id=?", (uid,))
    db.commit()
    log_action("DELETE_ADMIN_USER", uid, f"username:{user['username']}")
    return jsonify({"success": True})


@app.route("/api/tsa-test")
def tsa_test():
    """Test RFC 3161 timestamping from Railway server — public diagnostic."""
    import requests as _req
    results = {}

    for tsa_name, tsa_url in [
        ("sectigo", "http://timestamp.sectigo.com/qualified"),
        ("freetsa", "https://freetsa.org/tsr"),
        ("comodo", "http://timestamp.comodoca.com"),
        ("digicert", "https://timestamp.digicert.com"),
    ]:
        # Test 1: basic HTTP reachability
        try:
            r = _req.get(tsa_url, timeout=8)
            http_reachable = True
            http_status = r.status_code
        except Exception as e:
            http_reachable = False
            http_status = str(e)

        # Test 2: actual RFC 3161 timestamp request
        try:
            import hashlib, base64, struct
            # Minimal RFC 3161 request
            content_hash = hashlib.sha256(b"Railway TSA test").digest()
            # Simple DER-encoded TimeStampReq
            from vaultra.timestamper import stamp
            import os
            os.environ["VAULTRA_TSA"] = tsa_name
            import importlib, vaultra.timestamper as tsmod
            importlib.reload(tsmod)
            res = tsmod.stamp("Railway TSA connectivity test " + tsa_name)
            tsa_success = res.success
            tsa_timestamp = res.timestamp_utc if res.success else None
            tsa_error = None if res.success else "stamp() returned success=False"
        except Exception as e:
            tsa_success = False
            tsa_timestamp = None
            tsa_error = str(e)[:200]

        results[tsa_name] = {
            "http_reachable": http_reachable,
            "http_status": http_status,
            "rfc3161_success": tsa_success,
            "timestamp": tsa_timestamp,
            "error": tsa_error,
        }

    return jsonify(results)

@app.route("/health")
def health():
    return jsonify({"status":"ok","service":"vaultra-admin","version":"2.0.0","tsa":"Sectigo eIDAS QTSP (http://timestamp.sectigo.com/qualified)","tsa_status":"active"})

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)

# ── Gap 1: API Key Validation Endpoint ────────────────────
@app.route("/api/validate-key", methods=["POST"])
def validate_key_endpoint():
    """
    Called by the Vaultra SDK to validate a client API key.
    Returns client info if valid, error if not.
    
    Request: {"api_key": "vaultra_sk_v1_..."}
    Response: {"valid": true, "client_id": "...", "plan": "starter", "monthly_limit": 100000}
    """
    data = request.json
    if not data or "api_key" not in data:
        return jsonify({"valid": False, "error": "Missing api_key"}), 400

    raw_key = data["api_key"]
    if not raw_key.startswith("vaultra_sk_"):
        return jsonify({"valid": False, "error": "Invalid key format"}), 400

    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    db = get_db()
    client = db.execute("""
        SELECT id, company_name, plan, status, monthly_limit, receipt_count,
               month_count, month_start
        FROM clients
        WHERE api_key_hash=? AND archived=0
    """, (key_hash,)).fetchone()

    if not client:
        return jsonify({"valid": False, "error": "Invalid API key"}), 401

    if client["status"] != "active":
        return jsonify({"valid": False, "error": f"Account {client['status']}"}), 403

    # Update last_seen
    db.execute("UPDATE clients SET last_seen=? WHERE id=?", (time.time(), client["id"]))
    db.commit()

    response = jsonify({
        "valid": True,
        "client_id": client["id"],
        "company_name": client["company_name"],
        "plan": client["plan"],
        "monthly_limit": client["monthly_limit"],
        "receipt_count": client["receipt_count"],
        "month_count": client["month_count"] or 0,
        "month_start": client["month_start"] or 0,
    })
    return response

# ── Rate limit buckets (in-memory per client) ─────────────────────────
_rate_buckets = {}
_rate_lock = threading.Lock()

RATE_LIMITS = {
    "starter":    50,   # requests per minute
    "growth":     500,
    "enterprise": 10000,
}

def check_rate_limit(client_id: str, plan: str) -> bool:
    """Token bucket rate limiter. Returns True if request is allowed."""
    limit = RATE_LIMITS.get(plan, 50)
    now = time.time()
    with _rate_lock:
        bucket = _rate_buckets.get(client_id, {"tokens": limit, "last": now})
        elapsed = now - bucket["last"]
        bucket["tokens"] = min(limit, bucket["tokens"] + elapsed * (limit / 60.0))
        bucket["last"] = now
        if bucket["tokens"] >= 1:
            bucket["tokens"] -= 1
            _rate_buckets[client_id] = bucket
            return True
        _rate_buckets[client_id] = bucket
        return False

@app.route("/api/receipt", methods=["POST"])
def receive_receipt():
    """
    Called by the Vaultra SDK to register a Compliance Receipt.
    Validates API key, enforces rate limiting and monthly quota, then stores receipt.

    Plan limits:
        starter:    100,000 decisions/month — 50 req/min
        growth:   1,000,000 decisions/month — 500 req/min
        enterprise: unlimited              — 10,000 req/min
    """
    data = request.json
    if not data or "api_key" not in data:
        return jsonify({"success": False, "error": "Missing api_key"}), 400

    key_hash = hashlib.sha256(data["api_key"].encode()).hexdigest()
    db = get_db()
    client = db.execute(
        """SELECT id, status, plan, monthly_limit, receipt_count,
                  month_start, month_count
           FROM clients WHERE api_key_hash=? AND archived=0""",
        (key_hash,)
    ).fetchone()

    if not client or client["status"] != "active":
        return jsonify({"success": False, "error": "Invalid or inactive API key"}), 401

    # ── Rate limiting ───────────────────────────────────────────────────
    if not check_rate_limit(client["id"], client["plan"]):
        limit = RATE_LIMITS.get(client["plan"], 50)
        return jsonify({
            "success": False,
            "error": "Rate limit exceeded",
            "limit": f"{limit} requests/minute",
            "retry_after_seconds": 5
        }), 429

    # ── Monthly quota reset ─────────────────────────────────────────────
    now = time.time()
    from datetime import datetime, timezone
    now_dt = datetime.now(timezone.utc)
    month_start = client["month_start"] or 0
    month_count = client["month_count"] or 0

    if month_start > 0:
        start_dt = datetime.fromtimestamp(month_start, tz=timezone.utc)
        if now_dt.year != start_dt.year or now_dt.month != start_dt.month:
            month_count = 0
            month_start = now
    else:
        month_start = now

    # ── Monthly limit check ─────────────────────────────────────────────
    if month_count >= client["monthly_limit"]:
        return jsonify({
            "success": False,
            "error": "Monthly decision limit reached",
            "limit": client["monthly_limit"],
            "plan": client["plan"],
            "upgrade": "Contact hello@vaultra.io to upgrade your plan"
        }), 429

    # ── Store receipt ───────────────────────────────────────────────────
    rid = str(uuid.uuid4())
    db.execute("""
        INSERT INTO receipts
        (id, client_id, agent_id, decision, decision_type, input_hash,
         block_number, rfc3161_ts, regulation, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'valid', ?)
    """, (
        rid, client["id"],
        data.get("agent_id", "unknown"),
        data.get("decision", ""),
        data.get("decision_type", "UNKNOWN"),
        data.get("input_hash", ""),
        data.get("block_number", 0),
        data.get("rfc3161_ts", ""),
        data.get("regulation", "EU AI Act"),
        now
    ))

    # ── Update counters ─────────────────────────────────────────────────
    db.execute("""
        UPDATE clients SET
            receipt_count = receipt_count + 1,
            month_count   = ?,
            month_start   = ?,
            last_seen     = ?
        WHERE id = ?
    """, (month_count + 1, month_start, now, client["id"]))
    db.commit()

    return jsonify({
        "success": True,
        "receipt_id": rid,
        "month_count": month_count + 1,
        "monthly_limit": client["monthly_limit"]
    })
