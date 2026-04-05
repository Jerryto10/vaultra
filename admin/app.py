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
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, jsonify,
    session, redirect, url_for, g
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
SESSION_TIMEOUT = 1800  # 30 minutes

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
            monthly_limit  INTEGER NOT NULL DEFAULT 10000,
            industry       TEXT DEFAULT 'fintech',
            country        TEXT DEFAULT 'DE',
            notes          TEXT DEFAULT '',
            archived       INTEGER NOT NULL DEFAULT 0,
            archived_at    REAL
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

    # Add missing columns if upgrading from v1
    try:
        db.execute("ALTER TABLE clients ADD COLUMN industry TEXT DEFAULT 'fintech'")
        db.execute("ALTER TABLE clients ADD COLUMN country TEXT DEFAULT 'DE'")
        db.execute("ALTER TABLE clients ADD COLUMN notes TEXT DEFAULT ''")
        db.execute("ALTER TABLE clients ADD COLUMN archived INTEGER NOT NULL DEFAULT 0")
        db.execute("ALTER TABLE clients ADD COLUMN archived_at REAL")
        db.commit()
    except:
        pass

    # Create default users
    admin_pwd = os.environ.get("ADMIN_PASSWORD", "ADMIN_PASSWORD_REDACTED")
    admin_hash = hashlib.sha256(admin_pwd.encode()).hexdigest()
    try:
        db.execute("""
            INSERT INTO admin_users (id, username, password_hash, role, created_at)
            VALUES (?, 'admin', ?, 'admin', ?)
        """, (str(uuid.uuid4()), admin_hash, time.time()))
        support_pwd = os.environ.get("SUPPORT_PASSWORD", "support2026!")
        support_hash = hashlib.sha256(support_pwd.encode()).hexdigest()
        db.execute("""
            INSERT INTO admin_users (id, username, password_hash, role, created_at)
            VALUES (?, 'support', ?, 'support', ?)
        """, (str(uuid.uuid4()), support_hash, time.time()))
        db.commit()
    except:
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
        limit = 10000 if plan == "starter" else 50000
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
        INSERT INTO audit_log (id,admin_id,username,action,target,details,ip_address,created_at)
        VALUES (?,?,?,?,?,?,?,?)
    """, (str(uuid.uuid4()), session.get("admin_id","system"),
          session.get("username","system"), action, target, details,
          request.remote_addr, time.time()))
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
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
        db = get_db()
        user = db.execute(
            "SELECT * FROM admin_users WHERE username=? AND password_hash=?",
            (username, pwd_hash)
        ).fetchone()
        if user:
            session["admin_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["last_active"] = time.time()
            db.execute("UPDATE admin_users SET last_login=? WHERE id=?",
                      (time.time(), user["id"]))
            db.commit()
            log_action("LOGIN", details=f"IP: {request.remote_addr}")
            return redirect(url_for("dashboard"))
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
    query = "SELECT * FROM clients WHERE archived=?"
    params = [1 if show_archived else 0]
    if industry:
        query += " AND industry=?"; params.append(industry)
    if country:
        query += " AND country=?"; params.append(country)
    query += " ORDER BY created_at DESC"
    all_clients = db.execute(query, params).fetchall()
    industries = db.execute("SELECT DISTINCT industry FROM clients WHERE industry IS NOT NULL").fetchall()
    countries = db.execute("SELECT DISTINCT country FROM clients WHERE country IS NOT NULL").fetchall()
    return render_template("clients.html",
        clients=all_clients,
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
    limit = {"starter":10000,"growth":50000,"enterprise":999999}.get(plan,10000)
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

@app.route("/receipts")
@login_required
def receipts():
    db = get_db()
    client_id = request.args.get("client_id")
    status = request.args.get("status")
    query = """
        SELECT r.*, c.company_name FROM receipts r
        JOIN clients c ON r.client_id = c.id WHERE 1=1
    """
    params = []
    if client_id:
        query += " AND r.client_id=?"; params.append(client_id)
    if status:
        query += " AND r.status=?"; params.append(status)
    query += " ORDER BY r.created_at DESC LIMIT 100"
    all_receipts = db.execute(query, params).fetchall()
    clients_list = db.execute(
        "SELECT id, company_name FROM clients WHERE archived=0 ORDER BY company_name"
    ).fetchall()
    return render_template("receipts.html",
        receipts=all_receipts,
        clients=clients_list,
        username=session.get("username"),
        role=session.get("role"),
    )

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

@app.route("/health")
def health():
    return jsonify({"status":"ok","service":"vaultra-admin","version":"2.0.0"})

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
    Response: {"valid": true, "client_id": "...", "plan": "starter", "monthly_limit": 10000}
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
        SELECT id, company_name, plan, status, monthly_limit, receipt_count
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

    return jsonify({
        "valid": True,
        "client_id": client["id"],
        "company_name": client["company_name"],
        "plan": client["plan"],
        "monthly_limit": client["monthly_limit"],
        "receipt_count": client["receipt_count"],
    })

@app.route("/api/receipt", methods=["POST"])
def receive_receipt():
    """
    Called by the Vaultra SDK to register a Compliance Receipt.
    Validates API key then stores receipt metadata.
    
    Request: {
        "api_key": "vaultra_sk_v1_...",
        "agent_id": "credit-bot-v1",
        "decision": "APPROVE loan #123",
        "decision_type": "LOAN_APPROVED",
        "input_hash": "sha256...",
        "block_number": 1234,
        "rfc3161_ts": "2026-04-05T...",
        "regulation": "EU AI Act"
    }
    """
    data = request.json
    if not data or "api_key" not in data:
        return jsonify({"success": False, "error": "Missing api_key"}), 400

    key_hash = hashlib.sha256(data["api_key"].encode()).hexdigest()
    db = get_db()
    client = db.execute(
        "SELECT id, status, monthly_limit, receipt_count FROM clients WHERE api_key_hash=? AND archived=0",
        (key_hash,)
    ).fetchone()

    if not client or client["status"] != "active":
        return jsonify({"success": False, "error": "Invalid or inactive API key"}), 401

    # Check monthly limit
    if client["receipt_count"] >= client["monthly_limit"]:
        return jsonify({"success": False, "error": "Monthly receipt limit reached"}), 429

    # Store receipt
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
        time.time()
    ))
    db.execute(
        "UPDATE clients SET receipt_count=receipt_count+1, last_seen=? WHERE id=?",
        (time.time(), client["id"])
    )
    db.commit()

    return jsonify({"success": True, "receipt_id": rid})
