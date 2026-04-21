from flask import Flask, request, jsonify, render_template
import os
import json
import hashlib
import threading
import psycopg2
import psycopg2.extras
from encryption import generate_psk, encrypt_credentials, decrypt_credentials
from email_sender import send_credentials_email
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, template_folder="templates")

DATABASE_URL = os.getenv("DATABASE_URL")

ALLOWED_DOMAINS = ['5cnetwork.com', '5cnetwork.in']
ADMIN_EMAIL = 'akash@5cnetwork.com'


def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = True
    return conn


def init_db():
    """Create all tables if they don't exist."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS applications (
            id SERIAL PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            url TEXT,
            username TEXT,
            password TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS psk_tokens (
            id TEXT PRIMARY KEY,
            user_email TEXT,
            app_name TEXT,
            psk_hash TEXT,
            encrypted_creds TEXT,
            expires_at TIMESTAMPTZ,
            used BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id SERIAL PRIMARY KEY,
            user_email TEXT,
            app_name TEXT,
            action TEXT,
            timestamp TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS pending_requests (
            id TEXT PRIMARY KEY,
            user_email TEXT,
            app_name TEXT,
            reason TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMPTZ DEFAULT NOW(),
            reviewed_at TIMESTAMPTZ
        );
    """)
    cur.close()
    conn.close()
    print("Database initialized!")


def is_allowed_email(email):
    domain = email.split('@')[-1].lower()
    return domain in ALLOWED_DOMAINS


def generate_id():
    import uuid
    return str(uuid.uuid4()).replace('-', '')[:20]


def send_admin_notification(user_email, app_name, request_id):
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    gmail_user = os.getenv('GMAIL_USER')
    gmail_password = os.getenv('GMAIL_APP_PASSWORD')
    approve_url = f"{os.getenv('PORTAL_BASE_URL')}/admin"
    msg = MIMEMultipart('alternative')
    msg['Subject'] = f"[CredVault] Approval Required: {user_email} → {app_name}"
    msg['From'] = gmail_user
    msg['To'] = ADMIN_EMAIL
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:20px">
      <h2 style="color:#EF9F27">CredVault — Approval Required</h2>
      <p><strong>{user_email}</strong> has requested access to <strong>{app_name}</strong>.</p>
      <p>Please log in to the admin dashboard to approve or reject:</p>
      <a href="{approve_url}" style="background:#EF9F27;color:#000;padding:10px 20px;text-decoration:none;border-radius:6px;font-weight:bold;display:inline-block;margin-top:10px">
        Open Admin Dashboard
      </a>
    </div>
    """
    msg.attach(MIMEText(html, 'html'))
    try:
        with psycopg2.connect(DATABASE_URL):
            pass
        api_key = os.getenv("MANDRILL_API_KEY")
        if api_key:
            import requests as req
            req.post("https://mandrillapp.com/api/1.0/messages/send", json={
                "key": api_key,
                "message": {
                    "html": html,
                    "subject": msg['Subject'],
                    "from_email": gmail_user,
                    "from_name": "5C Network IT Support",
                    "to": [{"email": ADMIN_EMAIL, "type": "to"}]
                }
            }, timeout=30)
    except Exception as e:
        print(f"Admin notification failed: {e}")


@app.route("/api/process-request", methods=["POST"])
def process_request():
    data = request.json
    user_email = data.get("user_email", "").strip().lower()
    app_name   = data.get("app_name", "").strip()
    reason     = data.get("reason", "").strip()

    if not user_email or not app_name:
        return jsonify({"error": "user_email and app_name are required"}), 400

    if not is_allowed_email(user_email):
        domain = user_email.split('@')[-1]
        conn = get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO audit_logs (user_email, app_name, action) VALUES (%s, %s, %s)",
                    (user_email, app_name, "domain_rejected"))
        cur.close(); conn.close()
        return jsonify({"error": f"Access denied. '{domain}' is not an authorized domain."}), 403

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM applications WHERE name = %s", (app_name,))
    app_row = cur.fetchone()
    if not app_row:
        cur.close(); conn.close()
        return jsonify({"error": f"App '{app_name}' not found"}), 404

    request_id = generate_id()
    cur.execute("""INSERT INTO pending_requests (id, user_email, app_name, reason, status, created_at)
                   VALUES (%s, %s, %s, %s, 'pending', NOW())""",
                (request_id, user_email, app_name, reason))
    cur.execute("INSERT INTO audit_logs (user_email, app_name, action) VALUES (%s, %s, %s)",
                (user_email, app_name, "access_requested"))
    cur.close(); conn.close()

    threading.Thread(target=send_admin_notification, args=(user_email, app_name, request_id), daemon=True).start()

    return jsonify({"success": True, "message": f"Request received. Admin will review and send credentials to {user_email} shortly."})


@app.route("/api/admin/approve/<request_id>", methods=["POST"])
def approve_request(request_id):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM pending_requests WHERE id = %s", (request_id,))
    req = cur.fetchone()

    if not req:
        cur.close(); conn.close()
        return jsonify({"error": "Request not found"}), 404

    if req['status'] != 'pending':
        cur.close(); conn.close()
        return jsonify({"error": f"Request already {req['status']}"}), 400

    cur.execute("SELECT * FROM applications WHERE name = %s", (req['app_name'],))
    app_row = cur.fetchone()
    if not app_row:
        cur.close(); conn.close()
        return jsonify({"error": f"App '{req['app_name']}' not found"}), 404

    psk = generate_psk()
    creds_payload = json.dumps({
        "username": app_row['username'],
        "password": app_row['password'],
        "app_url":  app_row['url'],
        "app_name": req['app_name']
    })
    encrypted = encrypt_credentials(creds_payload, psk)
    psk_hash  = hashlib.sha256(psk.encode()).hexdigest()
    token_id  = generate_id()
    expires_at = datetime.now(timezone.utc) + timedelta(hours=48)

    cur.execute("""INSERT INTO psk_tokens (id, user_email, app_name, psk_hash, encrypted_creds, expires_at, used, created_at)
                   VALUES (%s, %s, %s, %s, %s, %s, FALSE, NOW())""",
                (token_id, req['user_email'], req['app_name'], psk_hash, encrypted, expires_at))

    cur.execute("UPDATE pending_requests SET status='approved', reviewed_at=NOW() WHERE id=%s", (request_id,))
    cur.execute("INSERT INTO audit_logs (user_email, app_name, action) VALUES (%s, %s, %s)",
                (req['user_email'], req['app_name'], "credentials_sent"))
    cur.close(); conn.close()

    portal_link = f"{os.getenv('PORTAL_BASE_URL')}/access/{token_id}"
    threading.Thread(target=send_credentials_email,
                     args=(req['user_email'], req['app_name'], app_row['url'], psk, portal_link),
                     daemon=True).start()

    return jsonify({"success": True, "message": f"Approved. Credentials sent to {req['user_email']}"})


@app.route("/api/admin/reject/<request_id>", methods=["POST"])
def reject_request(request_id):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM pending_requests WHERE id = %s", (request_id,))
    req = cur.fetchone()
    if not req:
        cur.close(); conn.close()
        return jsonify({"error": "Request not found"}), 404
    if req['status'] != 'pending':
        cur.close(); conn.close()
        return jsonify({"error": f"Request already {req['status']}"}), 400
    cur.execute("UPDATE pending_requests SET status='rejected', reviewed_at=NOW() WHERE id=%s", (request_id,))
    cur.execute("INSERT INTO audit_logs (user_email, app_name, action) VALUES (%s, %s, %s)",
                (req['user_email'], req['app_name'], "access_rejected"))
    cur.close(); conn.close()
    return jsonify({"success": True, "message": "Request rejected."})


@app.route("/access/<token_id>", methods=["GET", "POST"])
def access_portal(token_id):
    if request.method == "GET":
        return render_template("portal.html", token_id=token_id)

    psk_input = (request.json or {}).get("psk", "").strip()
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM psk_tokens WHERE id = %s", (token_id,))
    token = cur.fetchone()

    if not token:
        cur.close(); conn.close()
        return jsonify({"error": "Invalid or expired link"}), 404
    if token['used']:
        cur.close(); conn.close()
        return jsonify({"error": "This link has already been used. Contact IT for a new one."}), 400

    exp = token['expires_at']
    if exp:
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > exp:
            cur.close(); conn.close()
            return jsonify({"error": "This link has expired. Please request again."}), 400

    if hashlib.sha256(psk_input.encode()).hexdigest() != token['psk_hash']:
        cur.close(); conn.close()
        return jsonify({"error": "Incorrect key. Please check your email."}), 401

    decrypted = decrypt_credentials(token['encrypted_creds'], psk_input)
    cur.execute("UPDATE psk_tokens SET used=TRUE WHERE id=%s", (token_id,))
    cur.execute("INSERT INTO audit_logs (user_email, app_name, action) VALUES (%s, %s, %s)",
                (token['user_email'], token['app_name'], "credentials_accessed"))
    cur.close(); conn.close()
    return jsonify({"success": True, "credentials": decrypted})


@app.route("/admin/logs", methods=["GET"])
def admin_logs():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 200")
    logs = cur.fetchall()
    cur.close(); conn.close()
    result = []
    for l in logs:
        d = dict(l)
        if d.get('timestamp'):
            d['timestamp'] = d['timestamp'].isoformat()
        result.append(d)
    return jsonify(result)


@app.route("/admin/applications", methods=["GET"])
def admin_applications():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id, name, url, username, created_at FROM applications ORDER BY name")
    apps = cur.fetchall()
    cur.close(); conn.close()
    result = []
    for a in apps:
        d = dict(a)
        if d.get('created_at'):
            d['created_at'] = d['created_at'].isoformat()
        result.append(d)
    return jsonify(result)


@app.route("/admin/applications", methods=["POST"])
def add_application():
    data = request.json
    for field in ["name", "url", "username", "password"]:
        if not data.get(field):
            return jsonify({"error": f"'{field}' is required"}), 400
    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO applications (name, url, username, password) VALUES (%s, %s, %s, %s)",
                (data['name'], data['url'], data['username'], data['password']))
    cur.close(); conn.close()
    return jsonify({"success": True})


@app.route("/admin/tokens", methods=["GET"])
def admin_tokens():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM psk_tokens ORDER BY created_at DESC")
    tokens = cur.fetchall()
    cur.close(); conn.close()
    result = []
    for t in tokens:
        d = dict(t)
        for key in ('expires_at', 'created_at'):
            if d.get(key):
                d[key] = d[key].isoformat()
        result.append(d)
    return jsonify(result)


@app.route("/admin/pending", methods=["GET"])
def admin_pending():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM pending_requests WHERE status='pending' ORDER BY created_at DESC LIMIT 100")
    reqs = cur.fetchall()
    cur.close(); conn.close()
    result = []
    for r in reqs:
        d = dict(r)
        for key in ('created_at', 'reviewed_at'):
            if d.get(key):
                d[key] = d[key].isoformat()
        result.append(d)
    return jsonify(result)


@app.route("/admin", methods=["GET"])
def admin_dashboard():
    return render_template("admin.html")


# Initialize database on startup
init_db()

if __name__ == "__main__":
    print("CredsVault running on http://localhost:5000")
    app.run(debug=True, port=5000)