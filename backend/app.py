from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import os
import json
import hashlib
import threading
import pg8000.native
from encryption import generate_psk, encrypt_credentials, decrypt_credentials
from email_sender import send_credentials_email
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from dotenv import load_dotenv
from functools import wraps
from authlib.integrations.flask_client import OAuth

load_dotenv()

app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("SECRET_KEY", "credsvault_5cnetwork_2024_xK9mP")

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

DATABASE_URL = os.getenv("DATABASE_URL")
ALLOWED_DOMAINS = ['5cnetwork.com', '5cnetwork.in']
ADMIN_EMAIL = 'akash@5cnetwork.com'


def get_db():
    url = urlparse(DATABASE_URL)
    conn = pg8000.native.Connection(
        host=url.hostname,
        port=url.port or 5432,
        database=url.path[1:],
        user=url.username,
        password=url.password,
        ssl_context=True
    )
    return conn


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def @app.route("/admin/auth/google")
def google_login():
    redirect_uri = os.getenv("PORTAL_BASE_URL") + "/admin/auth/callback"
    return google.authorize_redirect(redirect_uri)


@app.route("/admin/auth/callback")
def google_callback():
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo')
        email = user_info.get('email', '')
        # Only allow 5cnetwork.com accounts
        if not email.endswith('@5cnetwork.com'):
            return redirect(url_for('admin_login_page') + '?error=unauthorized')
        session['admin_logged_in'] = True
        session['admin_username'] = email
        session['admin_role'] = 'admin'
        session['admin_email'] = email
        session['admin_name'] = user_info.get('name', email)
        session.permanent = True
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        print(f"Google auth error: {e}")
        return redirect(url_for('admin_login_page') + '?error=auth_failed')


init_db():
    conn = get_db()
    conn.run("""
        CREATE TABLE IF NOT EXISTS applications (
            id SERIAL PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            url TEXT,
            username TEXT,
            password TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    """)
    conn.run("""
        CREATE TABLE IF NOT EXISTS psk_tokens (
            id TEXT PRIMARY KEY,
            user_email TEXT,
            app_name TEXT,
            psk_hash TEXT,
            encrypted_creds TEXT,
            expires_at TIMESTAMPTZ,
            used BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    """)
    conn.run("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id SERIAL PRIMARY KEY,
            user_email TEXT,
            app_name TEXT,
            action TEXT,
            timestamp TIMESTAMPTZ DEFAULT NOW()
        )
    """)
    conn.run("""
        CREATE TABLE IF NOT EXISTS pending_requests (
            id TEXT PRIMARY KEY,
            user_email TEXT,
            app_name TEXT,
            reason TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMPTZ DEFAULT NOW(),
            reviewed_at TIMESTAMPTZ,
            user_name TEXT,
            user_designation TEXT,
            user_department TEXT
        )
    """)
    conn.run("""
        CREATE TABLE IF NOT EXISTS users (
            emp_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            designation TEXT,
            department TEXT
        )
    """)
    conn.run("""
        CREATE TABLE IF NOT EXISTS admins (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'admin',
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    """)
    try:
        conn.run("ALTER TABLE pending_requests ADD COLUMN IF NOT EXISTS user_name TEXT")
        conn.run("ALTER TABLE pending_requests ADD COLUMN IF NOT EXISTS user_designation TEXT")
        conn.run("ALTER TABLE pending_requests ADD COLUMN IF NOT EXISTS user_department TEXT")
    except:
        pass

    # Create default super admin if no admins exist
    existing = conn.run("SELECT COUNT(*) FROM admins")
    if existing[0][0] == 0:
        default_user = os.getenv("ADMIN_USERNAME", "admin")
        default_pass = os.getenv("ADMIN_PASSWORD", "CredVault@5C2024")
        conn.run("INSERT INTO admins (username, password_hash, role) VALUES (:u, :p, 'super')",
                 u=default_user, p=hash_password(default_pass))
        print(f"Default admin created: {default_user}")

    conn.close()
    print("Database initialized!")


def is_allowed_email(email):
    domain = email.split('@')[-1].lower()
    return domain in ALLOWED_DOMAINS


def generate_id():
    import uuid
    return str(uuid.uuid4()).replace('-', '')[:20]


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login_page'))
        return f(*args, **kwargs)
    return decorated


def send_admin_notification(user_email, app_name, request_id):
    try:
        api_key = os.getenv("MANDRILL_API_KEY")
        sender = os.getenv("GMAIL_USER", "akash@5cnetwork.com")
        approve_url = f"{os.getenv('PORTAL_BASE_URL')}/admin"
        html = f"""
        <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:20px">
          <h2 style="color:#EF9F27">CredVault — Approval Required</h2>
          <p><strong>{user_email}</strong> has requested access to <strong>{app_name}</strong>.</p>
          <a href="{approve_url}" style="background:#EF9F27;color:#000;padding:10px 20px;text-decoration:none;border-radius:6px;font-weight:bold;display:inline-block;margin-top:10px">
            Open Admin Dashboard
          </a>
        </div>
        """
        if api_key:
            import requests as req
            req.post("https://mandrillapp.com/api/1.0/messages/send", json={
                "key": api_key,
                "message": {
                    "html": html,
                    "subject": f"[CredVault] Approval Required: {user_email} → {app_name}",
                    "from_email": sender,
                    "from_name": "5C Network IT Support",
                    "to": [{"email": ADMIN_EMAIL, "type": "to"}]
                }
            }, timeout=30)
    except Exception as e:
        print(f"Admin notification failed: {e}")


# ── AUTH ROUTES ──

@app.route("/admin/login", methods=["GET"])
def admin_login_page():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
    return render_template("login.html")


@app.route("/admin/login", methods=["POST"])
def admin_login():
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    conn = get_db()
    rows = conn.run("SELECT id, username, role FROM admins WHERE username=:u AND password_hash=:p",
                    u=username, p=hash_password(password))
    conn.close()
    if not rows:
        return jsonify({"error": "Invalid username or password"}), 401
    session['admin_logged_in'] = True
    session['admin_username'] = rows[0][1]
    session['admin_role'] = rows[0][2]
    session.permanent = True
    return jsonify({"success": True})


@app.route("/admin/logout", methods=["GET"])
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login_page'))


@app.route("/admin/create-admin", methods=["POST"])
def create_admin():
    data = request.json
    auth_password = data.get("auth_password", "")
    new_username = data.get("username", "").strip()
    new_password = data.get("password", "")
    role = data.get("role", "admin")

    if not auth_password or not new_username or not new_password:
        return jsonify({"error": "All fields are required"}), 400
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if role not in ['admin', 'viewer', 'super']:
        return jsonify({"error": "Invalid role"}), 400

    conn = get_db()
    # Verify auth password against any super admin
    auth_rows = conn.run("SELECT id FROM admins WHERE password_hash=:p AND role='super'",
                         p=hash_password(auth_password))
    if not auth_rows:
        conn.close()
        return jsonify({"error": "Invalid verification password. Only super admins can create accounts."}), 403

    try:
        conn.run("INSERT INTO admins (username, password_hash, role) VALUES (:u, :p, :r)",
                 u=new_username, p=hash_password(new_password), r=role)
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        conn.close()
        return jsonify({"error": f"Username already exists"}), 400


@app.route("/admin/reset-password", methods=["POST"])
def reset_password():
    data = request.json
    username = data.get("username", "").strip()
    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")

    if not username or not new_password:
        return jsonify({"error": "Username and new password are required"}), 400
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    conn = get_db()

    # If current password provided, verify it
    if current_password:
        rows = conn.run("SELECT id FROM admins WHERE username=:u AND password_hash=:p",
                        u=username, p=hash_password(current_password))
        if not rows:
            conn.close()
            return jsonify({"error": "Current password is incorrect"}), 401
    else:
        # Without current password, only allow reset if username exists
        rows = conn.run("SELECT id FROM admins WHERE username=:u", u=username)
        if not rows:
            conn.close()
            return jsonify({"error": "Username not found"}), 404

    conn.run("UPDATE admins SET password_hash=:p WHERE username=:u",
             p=hash_password(new_password), u=username)
    conn.close()
    return jsonify({"success": True})


# ── API ROUTES ──

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
        conn.run("INSERT INTO audit_logs (user_email, app_name, action) VALUES (:e, :a, :ac)",
                 e=user_email, a=app_name, ac="domain_rejected")
        conn.close()
        return jsonify({"error": f"Access denied. '{domain}' is not an authorized domain."}), 403

    conn = get_db()
    rows = conn.run("SELECT id, name, url, username, password FROM applications WHERE name = :n", n=app_name)
    if not rows:
        conn.close()
        return jsonify({"error": f"App '{app_name}' not found"}), 404

    # Lookup user details
    email_prefix = user_email.split('@')[0].lower().replace('.', ' ')
    user_rows = conn.run("SELECT name, designation, department FROM users WHERE LOWER(name) LIKE :q LIMIT 1",
                         q=f"%{email_prefix.split(' ')[0]}%")
    user_name = user_rows[0][0] if user_rows else None
    user_designation = user_rows[0][1] if user_rows else None
    user_department = user_rows[0][2] if user_rows else None

    request_id = generate_id()
    conn.run("INSERT INTO pending_requests (id, user_email, app_name, reason, status, user_name, user_designation, user_department) VALUES (:id, :e, :a, :r, 'pending', :un, :ud, :udept)",
             id=request_id, e=user_email, a=app_name, r=reason, un=user_name, ud=user_designation, udept=user_department)
    conn.run("INSERT INTO audit_logs (user_email, app_name, action) VALUES (:e, :a, :ac)",
             e=user_email, a=app_name, ac="access_requested")
    conn.close()

    threading.Thread(target=send_admin_notification, args=(user_email, app_name, request_id), daemon=True).start()
    return jsonify({"success": True, "message": f"Request received. Admin will review and send credentials to {user_email} shortly."})


@app.route("/api/admin/approve/<request_id>", methods=["POST"])
@login_required
def approve_request(request_id):
    conn = get_db()
    rows = conn.run("SELECT id, user_email, app_name, status FROM pending_requests WHERE id = :id", id=request_id)
    if not rows:
        conn.close()
        return jsonify({"error": "Request not found"}), 404

    req_id, user_email, app_name, status = rows[0]
    if status != 'pending':
        conn.close()
        return jsonify({"error": f"Request already {status}"}), 400

    app_rows = conn.run("SELECT id, name, url, username, password FROM applications WHERE name = :n", n=app_name)
    if not app_rows:
        conn.close()
        return jsonify({"error": f"App '{app_name}' not found"}), 404

    _, _, app_url, app_username, app_password = app_rows[0]

    psk = generate_psk()
    creds_payload = json.dumps({
        "username": app_username,
        "password": app_password,
        "app_url":  app_url,
        "app_name": app_name
    })
    encrypted = encrypt_credentials(creds_payload, psk)
    psk_hash  = hashlib.sha256(psk.encode()).hexdigest()
    token_id  = generate_id()
    expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

    conn.run("""INSERT INTO psk_tokens (id, user_email, app_name, psk_hash, encrypted_creds, expires_at, used)
                VALUES (:id, :e, :a, :ph, :ec, :exp, false)""",
             id=token_id, e=user_email, a=app_name, ph=psk_hash, ec=json.dumps(encrypted), exp=expires_at)
    conn.run("UPDATE pending_requests SET status='approved', reviewed_at=NOW() WHERE id=:id", id=request_id)
    conn.run("INSERT INTO audit_logs (user_email, app_name, action) VALUES (:e, :a, :ac)",
             e=user_email, a=app_name, ac="credentials_sent")
    conn.close()

    portal_link = f"{os.getenv('PORTAL_BASE_URL')}/access/{token_id}"
    threading.Thread(target=send_credentials_email,
                     args=(user_email, app_name, app_url, psk, portal_link),
                     daemon=True).start()

    return jsonify({"success": True, "message": f"Approved. Credentials sent to {user_email}"})


@app.route("/api/admin/reject/<request_id>", methods=["POST"])
@login_required
def reject_request(request_id):
    conn = get_db()
    rows = conn.run("SELECT id, user_email, app_name, status FROM pending_requests WHERE id = :id", id=request_id)
    if not rows:
        conn.close()
        return jsonify({"error": "Request not found"}), 404
    req_id, user_email, app_name, status = rows[0]
    if status != 'pending':
        conn.close()
        return jsonify({"error": f"Request already {status}"}), 400
    conn.run("UPDATE pending_requests SET status='rejected', reviewed_at=NOW() WHERE id=:id", id=request_id)
    conn.run("INSERT INTO audit_logs (user_email, app_name, action) VALUES (:e, :a, :ac)",
             e=user_email, a=app_name, ac="access_rejected")
    conn.close()
    return jsonify({"success": True, "message": "Request rejected."})


@app.route("/access/<token_id>", methods=["GET", "POST"])
def access_portal(token_id):
    if request.method == "GET":
        return render_template("portal.html", token_id=token_id)

    psk_input = (request.json or {}).get("psk", "").strip()
    conn = get_db()
    rows = conn.run("SELECT id, user_email, app_name, psk_hash, encrypted_creds, expires_at, used FROM psk_tokens WHERE id = :id", id=token_id)
    if not rows:
        conn.close()
        return jsonify({"error": "Invalid or expired link"}), 404

    tid, user_email, app_name, psk_hash, encrypted_creds, expires_at, used = rows[0]

    if used:
        conn.close()
        return jsonify({"error": "This link has already been used. Contact IT for a new one."}), 400

    if expires_at:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expires_at:
            conn.close()
            return jsonify({"error": "This link has expired. Please request again."}), 400

    if hashlib.sha256(psk_input.encode()).hexdigest() != psk_hash:
        conn.close()
        return jsonify({"error": "Incorrect key. Please check your email."}), 401

    if isinstance(encrypted_creds, str):
        encrypted_creds = json.loads(encrypted_creds)
    decrypted = decrypt_credentials(encrypted_creds, psk_input)

    conn.run("UPDATE psk_tokens SET used=true WHERE id=:id", id=token_id)
    conn.run("INSERT INTO audit_logs (user_email, app_name, action) VALUES (:e, :a, :ac)",
             e=user_email, a=app_name, ac="credentials_accessed")
    conn.close()
    return jsonify({"success": True, "credentials": decrypted})


@app.route("/admin/logs", methods=["GET"])
@login_required
def admin_logs():
    conn = get_db()
    rows = conn.run("SELECT user_email, app_name, action, timestamp FROM audit_logs ORDER BY timestamp DESC LIMIT 200")
    conn.close()
    result = []
    for r in rows:
        result.append({
            "user_email": r[0], "app_name": r[1], "action": r[2],
            "timestamp": r[3].isoformat() if r[3] else None
        })
    return jsonify(result)


@app.route("/admin/applications", methods=["GET"])
@login_required
def admin_applications():
    conn = get_db()
    rows = conn.run("SELECT id, name, url, username, created_at FROM applications ORDER BY name")
    conn.close()
    result = []
    for r in rows:
        result.append({
            "id": r[0], "name": r[1], "url": r[2], "username": r[3],
            "created_at": r[4].isoformat() if r[4] else None
        })
    return jsonify(result)


@app.route("/admin/applications", methods=["POST"])
@login_required
def add_application():
    data = request.json
    for field in ["name", "url", "username", "password"]:
        if not data.get(field):
            return jsonify({"error": f"'{field}' is required"}), 400
    conn = get_db()
    conn.run("INSERT INTO applications (name, url, username, password) VALUES (:n, :u, :un, :p)",
             n=data['name'], u=data['url'], un=data['username'], p=data['password'])
    conn.close()
    return jsonify({"success": True})


@app.route("/admin/tokens", methods=["GET"])
@login_required
def admin_tokens():
    conn = get_db()
    rows = conn.run("SELECT id, user_email, app_name, used, expires_at, created_at FROM psk_tokens ORDER BY created_at DESC")
    conn.close()
    result = []
    for r in rows:
        result.append({
            "id": r[0], "user_email": r[1], "app_name": r[2], "used": r[3],
            "expires_at": r[4].isoformat() if r[4] else None,
            "created_at": r[5].isoformat() if r[5] else None
        })
    return jsonify(result)


@app.route("/admin/pending", methods=["GET"])
@login_required
def admin_pending():
    conn = get_db()
    rows = conn.run("SELECT id, user_email, app_name, reason, status, created_at, user_name, user_designation, user_department FROM pending_requests WHERE status='pending' ORDER BY created_at DESC LIMIT 100")
    conn.close()
    result = []
    for r in rows:
        result.append({
            "id": r[0], "user_email": r[1], "app_name": r[2],
            "reason": r[3], "status": r[4],
            "created_at": r[5].isoformat() if r[5] else None,
            "user_name": r[6], "user_designation": r[7], "user_department": r[8]
        })
    return jsonify(result)


@app.route("/admin/users", methods=["GET"])
@login_required
def admin_users():
    conn = get_db()
    rows = conn.run("SELECT emp_id, name, designation, department FROM users ORDER BY name")
    conn.close()
    return jsonify([{"emp_id": r[0], "name": r[1], "designation": r[2], "department": r[3]} for r in rows])


@app.route("/admin/users", methods=["POST"])
@login_required
def add_user():
    data = request.json
    if not data.get("name"):
        return jsonify({"error": "name is required"}), 400
    import uuid
    emp_id = data.get("emp_id") or str(uuid.uuid4())[:8]
    conn = get_db()
    conn.run("INSERT INTO users (emp_id, name, designation, department) VALUES (:id, :n, :d, :dept) ON CONFLICT (emp_id) DO UPDATE SET name=:n, designation=:d, department=:dept",
             id=emp_id, n=data['name'], d=data.get('designation',''), dept=data.get('department',''))
    conn.close()
    return jsonify({"success": True})


@app.route("/admin", methods=["GET"])
@login_required
def admin_dashboard():
    return render_template("admin.html")


init_db()

if __name__ == "__main__":
    print("CredsVault running on http://localhost:5000")
    app.run(debug=True, port=5000)