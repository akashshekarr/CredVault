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


def init_db():
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
        CREATE TABLE IF NOT EXISTS access_grants (
            id SERIAL PRIMARY KEY,
            user_name TEXT NOT NULL,
            user_email TEXT,
            user_designation TEXT,
            user_department TEXT,
            app_name TEXT NOT NULL,
            access_type TEXT NOT NULL,
            granted_by TEXT,
            granted_at TIMESTAMPTZ DEFAULT NOW(),
            notes TEXT,
            status TEXT DEFAULT 'active'
        )
    """)
    try:
        conn.run("ALTER TABLE access_grants ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active'")
    except:
        pass
    conn.run("""
        CREATE TABLE IF NOT EXISTS user_credentials (
            id SERIAL PRIMARY KEY,
            user_email TEXT NOT NULL,
            app_name TEXT NOT NULL,
            username TEXT,
            password TEXT,
            app_url TEXT,
            granted_at TIMESTAMPTZ DEFAULT NOW(),
            revoked BOOLEAN DEFAULT FALSE,
            UNIQUE(user_email, app_name)
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


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login_page'))


@app.route("/admin/auth/google")
def google_login():
    redirect_uri = os.getenv("PORTAL_BASE_URL") + "/admin/auth/callback"
    return google.authorize_redirect(redirect_uri)


@app.route("/admin/auth/callback")
def google_callback():
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo')
        email = user_info.get('email', '')
        if not email.endswith('@5cnetwork.com'):
            return redirect(url_for('admin_login_page') + '?error=unauthorized')
        session['admin_logged_in'] = True
        session['admin_username'] = email
        session['admin_role'] = 'admin'
        session['admin_name'] = user_info.get('name', email)
        session.permanent = True
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        print(f"Google auth error: {e}")
        return redirect(url_for('admin_login_page') + '?error=auth_failed')


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
    conn = get_db()
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
        return jsonify({"error": "Username already exists"}), 400


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
    if current_password:
        rows = conn.run("SELECT id FROM admins WHERE username=:u AND password_hash=:p",
                        u=username, p=hash_password(current_password))
        if not rows:
            conn.close()
            return jsonify({"error": "Current password is incorrect"}), 401
    else:
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

    # Auto-log to access_grants for tracking
    email_prefix = user_email.split('@')[0].lower().replace('.', ' ')
    urows = conn.run("SELECT name, designation, department FROM users WHERE LOWER(name) LIKE :q LIMIT 1",
                     q=f"%{email_prefix.split(' ')[0]}%")
    u_name = urows[0][0] if urows else user_email.split('@')[0]
    u_desig = urows[0][1] if urows else ''
    u_dept = urows[0][2] if urows else ''
    existing = conn.run("""SELECT id, status FROM access_grants
                           WHERE LOWER(user_name)=LOWER(:n) AND app_name=:a AND access_type='Credentials'
                           ORDER BY granted_at DESC LIMIT 1""",
                        n=u_name, a=app_name)
    if not existing:
        # Brand new grant
        conn.run("""INSERT INTO access_grants (user_name, user_email, user_designation, user_department, app_name, access_type, granted_by, notes, status)
                    VALUES (:un, :ue, :ud, :udept, :a, 'Credentials', 'auto', 'Auto-logged via CredVault approval', 'active')""",
                 un=u_name, ue=user_email, ud=u_desig, udept=u_dept, a=app_name)
    else:
        # Existing grant — reactivate if it was revoked, otherwise leave it.
        # We do NOT clear user_credentials.revoked here; the user must re-enter
        # the PSK so verify_psk can refresh username/password (in case the app
        # password was rotated between revoke and re-approval). verify_psk will
        # UPSERT and clear the revoked flag at that point.
        existing_id, existing_status = existing[0]
        if (existing_status or 'active') != 'active':
            conn.run("""UPDATE access_grants
                        SET status='active', granted_by='auto', granted_at=NOW(),
                            notes='Re-granted via CredVault approval', user_email=:ue
                        WHERE id=:id""",
                     id=existing_id, ue=user_email)

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
    return jsonify([{"user_email": r[0], "app_name": r[1], "action": r[2], "timestamp": r[3].isoformat() if r[3] else None} for r in rows])


@app.route("/admin/applications", methods=["GET"])
@login_required
def admin_applications():
    conn = get_db()
    rows = conn.run("SELECT id, name, url, username, created_at FROM applications ORDER BY name")
    conn.close()
    return jsonify([{"id": r[0], "name": r[1], "url": r[2], "username": r[3], "created_at": r[4].isoformat() if r[4] else None} for r in rows])


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


@app.route("/admin/applications/<app_id>", methods=["GET"])
@login_required
def get_application(app_id):
    """Return one app including its current password — admin needs to see it
    when opening the edit modal so they can keep or change it."""
    conn = get_db()
    rows = conn.run("SELECT id, name, url, username, password, created_at FROM applications WHERE id=:i",
                    i=app_id)
    conn.close()
    if not rows:
        return jsonify({"error": "Not found"}), 404
    r = rows[0]
    return jsonify({
        "id": r[0], "name": r[1], "url": r[2], "username": r[3],
        "password": r[4],
        "created_at": r[5].isoformat() if r[5] else None,
    })


@app.route("/admin/applications/<app_id>", methods=["PUT"])
@login_required
def update_application(app_id):
    """Update an existing app. Password is OPTIONAL on update — if omitted or
    empty, we keep the existing one. Other fields required."""
    data = request.json or {}
    for field in ["name", "url", "username"]:
        if not data.get(field):
            return jsonify({"error": f"'{field}' is required"}), 400

    conn = get_db()
    existing = conn.run("SELECT password FROM applications WHERE id=:i", i=app_id)
    if not existing:
        conn.close()
        return jsonify({"error": "Not found"}), 404

    new_password = data.get('password')
    if not new_password:
        new_password = existing[0][0]  # keep current

    # Detect rename — if name changed, propagate it everywhere it's referenced
    old_name_row = conn.run("SELECT name FROM applications WHERE id=:i", i=app_id)
    old_name = old_name_row[0][0] if old_name_row else None
    new_name = data['name']

    try:
        conn.run("""UPDATE applications
                    SET name=:n, url=:u, username=:un, password=:p
                    WHERE id=:i""",
                 n=new_name, u=data['url'], un=data['username'], p=new_password, i=app_id)
    except Exception as ex:
        conn.close()
        # Most common cause: unique constraint on name
        return jsonify({"error": str(ex)}), 400

    if old_name and old_name != new_name:
        # Propagate name change to dependent rows
        conn.run("UPDATE access_grants SET app_name=:nn WHERE app_name=:on", nn=new_name, on=old_name)
        conn.run("UPDATE pending_requests SET app_name=:nn WHERE app_name=:on", nn=new_name, on=old_name)
        conn.run("UPDATE user_credentials SET app_name=:nn WHERE app_name=:on", nn=new_name, on=old_name)
        conn.run("UPDATE psk_tokens SET app_name=:nn WHERE app_name=:on", nn=new_name, on=old_name)

    # If credentials were rotated, invalidate every saved unlock so users must
    # re-PSK and pick up the new password.
    creds_changed = (data.get('password') and data.get('password') != existing[0][0])
    if creds_changed:
        conn.run("UPDATE user_credentials SET revoked=true WHERE app_name=:n", n=new_name)

    conn.close()
    return jsonify({"success": True, "credentials_rotated": bool(creds_changed)})


@app.route("/admin/applications/<app_id>", methods=["DELETE"])
@login_required
def delete_application(app_id):
    """Hard-delete an app. Cascades to remove related access grants, pending
    requests, saved user credentials, and unused PSK tokens."""
    conn = get_db()
    rows = conn.run("SELECT name FROM applications WHERE id=:i", i=app_id)
    if not rows:
        conn.close()
        return jsonify({"error": "Not found"}), 404
    app_name = rows[0][0]
    try:
        conn.run("DELETE FROM user_credentials WHERE app_name=:n", n=app_name)
        conn.run("DELETE FROM access_grants    WHERE app_name=:n", n=app_name)
        conn.run("DELETE FROM pending_requests WHERE app_name=:n", n=app_name)
        conn.run("DELETE FROM psk_tokens       WHERE app_name=:n AND used=false", n=app_name)
        conn.run("DELETE FROM applications     WHERE id=:i",       i=app_id)
    except Exception as ex:
        conn.close()
        return jsonify({"error": str(ex)}), 400
    conn.close()
    return jsonify({"success": True, "deleted": app_name})


@app.route("/admin/tokens", methods=["GET"])
@login_required
def admin_tokens():
    conn = get_db()
    rows = conn.run("SELECT id, user_email, app_name, used, expires_at, created_at FROM psk_tokens ORDER BY created_at DESC")
    conn.close()
    return jsonify([{"id": r[0], "user_email": r[1], "app_name": r[2], "used": r[3], "expires_at": r[4].isoformat() if r[4] else None, "created_at": r[5].isoformat() if r[5] else None} for r in rows])


@app.route("/admin/pending", methods=["GET"])
@login_required
def admin_pending():
    conn = get_db()
    rows = conn.run("SELECT id, user_email, app_name, reason, status, created_at, user_name, user_designation, user_department FROM pending_requests WHERE status='pending' ORDER BY created_at DESC LIMIT 100")
    conn.close()
    return jsonify([{"id": r[0], "user_email": r[1], "app_name": r[2], "reason": r[3], "status": r[4], "created_at": r[5].isoformat() if r[5] else None, "user_name": r[6], "user_designation": r[7], "user_department": r[8]} for r in rows])


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
             id=emp_id, n=data['name'], d=data.get('designation', ''), dept=data.get('department', ''))
    conn.close()
    return jsonify({"success": True})


@app.route("/admin/access-grants", methods=["GET"])
@login_required
def get_access_grants():
    conn = get_db()
    rows = conn.run("SELECT id, user_name, user_email, user_designation, user_department, app_name, access_type, granted_by, granted_at, notes, status FROM access_grants WHERE status='active' ORDER BY granted_at DESC")
    conn.close()
    return jsonify([{
        "id": r[0], "user_name": r[1], "user_email": r[2],
        "user_designation": r[3], "user_department": r[4],
        "app_name": r[5], "access_type": r[6], "granted_by": r[7],
        "granted_at": r[8].isoformat() if r[8] else None, "notes": r[9],
        "status": r[10]
    } for r in rows])


@app.route("/admin/access-grants", methods=["POST"])
@login_required
def add_access_grant():
    data = request.json
    if not data.get("user_name") or not data.get("app_name") or not data.get("access_type"):
        return jsonify({"error": "user_name, app_name and access_type are required"}), 400
    conn = get_db()
    conn.run("""INSERT INTO access_grants (user_name, user_email, user_designation, user_department, app_name, access_type, granted_by, notes)
                VALUES (:un, :ue, :ud, :udept, :a, :at, :gb, :n)""",
             un=data['user_name'], ue=data.get('user_email',''),
             ud=data.get('user_designation',''), udept=data.get('user_department',''),
             a=data['app_name'], at=data['access_type'],
             gb=session.get('admin_username','admin'), n=data.get('notes',''))
    conn.close()
    return jsonify({"success": True})


@app.route("/admin/access-grants/<int:grant_id>", methods=["DELETE"])
@login_required
def delete_access_grant(grant_id):
    conn = get_db()
    conn.run("DELETE FROM access_grants WHERE id=:id", id=grant_id)
    conn.close()
    return jsonify({"success": True})


@app.route("/admin/reports/user/<user_name>", methods=["GET"])
@login_required
def user_report(user_name):
    conn = get_db()
    rows = conn.run("""SELECT ag.app_name, ag.access_type, ag.granted_at, ag.granted_by, ag.notes,
                       ag.user_designation, ag.user_department, ag.user_email, ag.status
                       FROM access_grants ag
                       WHERE LOWER(ag.user_name) LIKE LOWER(:q)
                       ORDER BY ag.granted_at DESC""",
                    q=f"%{user_name}%")
    conn.close()
    return jsonify([{
        "app_name": r[0], "access_type": r[1],
        "granted_at": r[2].isoformat() if r[2] else None,
        "granted_by": r[3], "notes": r[4],
        "user_designation": r[5], "user_department": r[6], "user_email": r[7],
        "status": r[8]
    } for r in rows])


@app.route("/admin/reports/app/<app_name>", methods=["GET"])
@login_required
def app_report(app_name):
    conn = get_db()
    rows = conn.run("""SELECT ag.user_name, ag.user_email, ag.access_type, ag.granted_at,
                       ag.user_designation, ag.user_department, ag.status
                       FROM access_grants ag
                       WHERE LOWER(ag.app_name) LIKE LOWER(:q)
                       ORDER BY ag.granted_at DESC""",
                    q=f"%{app_name}%")
    conn.close()
    return jsonify([{
        "user_name": r[0], "user_email": r[1], "access_type": r[2],
        "granted_at": r[3].isoformat() if r[3] else None,
        "user_designation": r[4], "user_department": r[5],
        "status": r[6]
    } for r in rows])



# ── USER AUTH ──

@app.route("/user/login", methods=["GET"])
def user_login_page_render():
    if session.get('user_logged_in'):
        return redirect('/dashboard')
    return render_template('user_login.html')


@app.route("/user/login/google")
def user_login():
    redirect_uri = os.getenv("PORTAL_BASE_URL") + "/user/auth/callback"
    return google.authorize_redirect(redirect_uri, prompt='select_account')


@app.route("/user/auth/callback")
def user_auth_callback():
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo')
        email = user_info.get('email', '')
        domain = email.split('@')[-1].lower()
        if domain not in ['5cnetwork.com', '5cnetwork.in']:
            return redirect('/user/login?error=unauthorized')
        session['user_logged_in'] = True
        session['user_email'] = email
        session['user_name'] = user_info.get('name', '')
        session['user_picture'] = user_info.get('picture', '')
        session.permanent = True
        return redirect('/dashboard')
    except Exception as e:
        print(f"User auth error: {e}")
        return redirect('/user/login?error=auth_failed')


@app.route("/user/logout")
def user_logout():
    session.pop('user_logged_in', None)
    session.pop('user_email', None)
    session.pop('user_name', None)
    session.pop('user_picture', None)
    return redirect('/user/login')


def user_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_logged_in'):
            return redirect('/user/login')
        return f(*args, **kwargs)
    return decorated


@app.route("/user/saved-credentials/<app_name>", methods=["GET"])
@user_login_required
def get_saved_credentials(app_name):
    """Returns whether the user has unlocked this app and the username/app_url
    for display. The password is intentionally NOT returned — the dashboard
    only displays a masked placeholder. The browser extension fetches the
    actual password via /api/extension/credentials/<app_name>."""
    user_email = session.get('user_email')
    conn = get_db()
    rows = conn.run("""SELECT username, app_url FROM user_credentials
                       WHERE user_email=:e AND app_name=:a AND revoked=false""",
                    e=user_email, a=app_name)
    conn.close()
    if not rows:
        return jsonify({"found": False})
    return jsonify({
        "found": True,
        "credentials": {
            "username": rows[0][0],
            "app_url":  rows[0][1],
            "app_name": app_name,
        }
    })


@app.route("/admin/revoke-credentials", methods=["POST"])
@login_required
def revoke_credentials():
    data = request.json
    user_email = data.get("user_email", "")
    app_name = data.get("app_name", "")
    grant_id = data.get("grant_id")
    if not user_email or not app_name:
        return jsonify({"error": "user_email and app_name required"}), 400
    conn = get_db()
    # Revoke saved credentials
    conn.run("UPDATE user_credentials SET revoked=true WHERE user_email=:e AND app_name=:a",
             e=user_email, a=app_name)
    # Mark grant as revoked (keep for reports)
    if grant_id:
        conn.run("UPDATE access_grants SET status='revoked' WHERE id=:id", id=grant_id)
    else:
        conn.run("UPDATE access_grants SET status='revoked' WHERE user_email=:e AND app_name=:a AND status='active'",
                 e=user_email, a=app_name)
    conn.run("INSERT INTO audit_logs (user_email, app_name, action) VALUES (:e, :a, 'credentials_revoked')",
             e=user_email, a=app_name)
    conn.close()
    return jsonify({"success": True})


@app.route("/dashboard")
@user_login_required
def user_dashboard():
    return render_template("user_dashboard.html")


@app.route("/user/me")
@user_login_required
def user_me():
    return jsonify({
        "email": session.get('user_email'),
        "name": session.get('user_name'),
        "picture": session.get('user_picture')
    })


@app.route("/user/apps")
@user_login_required
def user_apps():
    conn = get_db()
    rows = conn.run("SELECT id, name, url, username, created_at FROM applications ORDER BY name")
    conn.close()
    return jsonify([{"id": r[0], "name": r[1], "url": r[2], "username": r[3]} for r in rows])


@app.route("/user/my-grants")
@user_login_required
def user_my_grants():
    user_email = session.get('user_email')
    email_prefix = user_email.split('@')[0].lower().replace('.', ' ')
    conn = get_db()
    # Lookup user name
    urows = conn.run("SELECT name FROM users WHERE LOWER(name) LIKE :q LIMIT 1",
                     q=f"%{email_prefix.split(' ')[0]}%")
    user_name = urows[0][0] if urows else email_prefix

    rows = conn.run("""SELECT app_name, access_type, granted_at, notes
                       FROM access_grants
                       WHERE (LOWER(user_name) LIKE LOWER(:q) OR LOWER(user_email)=LOWER(:e))
                         AND COALESCE(status, 'active') = 'active'
                       ORDER BY granted_at DESC""",
                    q=f"%{email_prefix.split(' ')[0]}%", e=user_email)
    conn.close()
    return jsonify([{
        "app_name": r[0], "access_type": r[1],
        "granted_at": r[2].isoformat() if r[2] else None, "notes": r[3]
    } for r in rows])


@app.route("/user/my-pending")
@user_login_required
def user_my_pending():
    user_email = session.get('user_email')
    conn = get_db()
    rows = conn.run("""SELECT app_name, created_at FROM pending_requests
                       WHERE user_email=:e AND status='pending'
                       ORDER BY created_at DESC""", e=user_email)
    conn.close()
    return jsonify([{"app_name": r[0], "created_at": r[1].isoformat() if r[1] else None} for r in rows])


@app.route("/user/request-access", methods=["POST"])
@user_login_required
def user_request_access():
    data = request.json
    user_email = session.get('user_email')
    app_name = data.get("app_name", "").strip()
    reason = data.get("reason", "").strip()

    if not app_name:
        return jsonify({"error": "app_name is required"}), 400

    conn = get_db()
    # Check app exists
    rows = conn.run("SELECT id FROM applications WHERE name=:n", n=app_name)
    if not rows:
        conn.close()
        return jsonify({"error": f"App not found"}), 404

    # Check no duplicate pending
    existing = conn.run("SELECT id FROM pending_requests WHERE user_email=:e AND app_name=:a AND status='pending'",
                        e=user_email, a=app_name)
    if existing:
        conn.close()
        return jsonify({"error": "You already have a pending request for this app"}), 400

    # Lookup user details
    email_prefix = user_email.split('@')[0].lower().replace('.', ' ')
    urows = conn.run("SELECT name, designation, department FROM users WHERE LOWER(name) LIKE :q LIMIT 1",
                     q=f"%{email_prefix.split(' ')[0]}%")
    user_name = urows[0][0] if urows else None
    user_designation = urows[0][1] if urows else None
    user_department = urows[0][2] if urows else None

    request_id = generate_id()
    conn.run("""INSERT INTO pending_requests (id, user_email, app_name, reason, status, user_name, user_designation, user_department)
                VALUES (:id, :e, :a, :r, 'pending', :un, :ud, :udept)""",
             id=request_id, e=user_email, a=app_name, r=reason,
             un=user_name, ud=user_designation, udept=user_department)
    conn.run("INSERT INTO audit_logs (user_email, app_name, action) VALUES (:e, :a, :ac)",
             e=user_email, a=app_name, ac="access_requested")
    conn.close()

    threading.Thread(target=send_admin_notification, args=(user_email, app_name, request_id), daemon=True).start()
    return jsonify({"success": True})


@app.route("/user/verify-psk", methods=["POST"])
@user_login_required
def user_verify_psk():
    data = request.json
    user_email = session.get('user_email')
    app_name = data.get("app_name", "").strip()
    psk_input = data.get("psk", "").strip()

    if not app_name or not psk_input:
        return jsonify({"error": "app_name and psk are required"}), 400

    conn = get_db()
    # Find latest unused token for this user and app
    rows = conn.run("""SELECT id, psk_hash, encrypted_creds, expires_at, used
                       FROM psk_tokens
                       WHERE user_email=:e AND app_name=:a AND used=false
                       ORDER BY created_at DESC LIMIT 1""",
                    e=user_email, a=app_name)

    if not rows:
        conn.close()
        return jsonify({"error": "No active token found. Please request access again."}), 404

    token_id, psk_hash, encrypted_creds, expires_at, used = rows[0]

    if expires_at:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expires_at:
            conn.close()
            return jsonify({"error": "Your key has expired. Please request access again."}), 400

    if hashlib.sha256(psk_input.encode()).hexdigest() != psk_hash:
        conn.close()
        return jsonify({"error": "Incorrect key. Please check your email."}), 401

    if isinstance(encrypted_creds, str):
        encrypted_creds = json.loads(encrypted_creds)

    decrypted = decrypt_credentials(encrypted_creds, psk_input)

    # Persist for future use — the user has now proven they own this email + key,
    # so we save the credentials per-user so they don't need to re-enter PSK.
    # The dashboard will only ever show username + masked password from this point;
    # the actual password is fetched by the AppVault browser extension on demand.
    try:
        d_username = decrypted.get('username') if isinstance(decrypted, dict) else None
        d_password = decrypted.get('password') if isinstance(decrypted, dict) else None
        d_app_url  = decrypted.get('app_url')  if isinstance(decrypted, dict) else None
        # Fall back to applications table for app_url if missing
        if not d_app_url:
            urow = conn.run("SELECT url FROM applications WHERE name=:a", a=app_name)
            if urow:
                d_app_url = urow[0][0]
        conn.run(
            """INSERT INTO user_credentials (user_email, app_name, username, password, app_url, granted_at, revoked)
               VALUES (:e, :a, :un, :pw, :url, NOW(), false)
               ON CONFLICT (user_email, app_name)
               DO UPDATE SET username=:un, password=:pw, app_url=:url, revoked=false, granted_at=NOW()""",
            e=user_email, a=app_name, un=d_username, pw=d_password, url=d_app_url
        )
    except Exception as ex:
        print(f"[verify_psk] failed to persist credentials: {ex}")

    conn.run("UPDATE psk_tokens SET used=true WHERE id=:id", id=token_id)
    conn.run("INSERT INTO audit_logs (user_email, app_name, action) VALUES (:e, :a, :ac)",
             e=user_email, a=app_name, ac="credentials_accessed_dashboard")
    conn.close()

    # Return ONLY non-sensitive info to the dashboard. The password is never
    # surfaced in the UI again — the extension fetches it on demand.
    safe_creds = {
        "username": decrypted.get("username") if isinstance(decrypted, dict) else None,
        "app_url":  decrypted.get("app_url")  if isinstance(decrypted, dict) else None,
        "app_name": app_name,
    }
    return jsonify({"success": True, "credentials": safe_creds})

@app.route("/admin/access", methods=["GET"])
@login_required
def access_management():
    return render_template("access_grants.html")


@app.route("/admin", methods=["GET"])
@login_required
def admin_dashboard():
    return render_template("admin.html")


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  APPVAULT EXTENSION ROUTES — pairing + credential fetch for the browser  ║
# ║  extension. Requires tables: extension_pairing_codes, extension_tokens   ║
# ║  (run extension_db_init.sql once).                                       ║
# ╚══════════════════════════════════════════════════════════════════════════╝

import secrets as _ext_secrets


def _ext_new_token(n_bytes=32):
    return _ext_secrets.token_urlsafe(n_bytes)


def _ext_utc_now():
    return datetime.now(timezone.utc)


def _ext_ensure_aware(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def extension_token_required(f):
    """Auth decorator for extension API calls. Requires Authorization: Bearer <token>."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401
        token = auth_header[7:].strip()
        if not token:
            return jsonify({"error": "Empty token"}), 401

        conn = get_db()
        rows = conn.run(
            "SELECT user_email, revoked FROM extension_tokens WHERE token = :t",
            t=token
        )
        if not rows:
            conn.close()
            return jsonify({"error": "Invalid token"}), 401
        user_email, revoked = rows[0]
        if revoked:
            conn.close()
            return jsonify({"error": "Token revoked"}), 401
        conn.run(
            "UPDATE extension_tokens SET last_used_at = NOW() WHERE token = :t",
            t=token
        )
        conn.close()

        request.extension_user_email = user_email
        return f(*args, **kwargs)
    return decorated


@app.after_request
def _extension_cors(resp):
    if request.path.startswith('/api/extension/'):
        origin = request.headers.get('Origin', '')
        if origin.startswith('chrome-extension://') or origin.startswith('moz-extension://'):
            resp.headers['Access-Control-Allow-Origin'] = origin
            resp.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
            resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
            resp.headers['Access-Control-Max-Age'] = '3600'
    return resp


@app.route('/api/extension/<path:_any>', methods=['OPTIONS'])
def _extension_preflight(_any):
    return ('', 204)


@app.route('/api/extension/pair', methods=['POST'])
@user_login_required
def extension_pair():
    """User clicks 'Pair Extension' on the portal while logged in.
    Mints a single-use pairing code (5 min) bound to their email."""
    user_email = session.get('user_email')
    code = _ext_new_token(16)
    expires_at = _ext_utc_now() + timedelta(minutes=5)
    conn = get_db()
    conn.run(
        """INSERT INTO extension_pairing_codes (code, user_email, expires_at, used)
           VALUES (:c, :e, :exp, false)""",
        c=code, e=user_email, exp=expires_at
    )
    conn.close()
    return jsonify({"code": code, "expires_in_seconds": 300})


@app.route('/api/extension/redeem', methods=['POST'])
def extension_redeem():
    """Extension exchanges a pairing code for a long-lived bearer token."""
    data = request.json or {}
    code = (data.get('code') or '').strip()
    device_label = (data.get('device_label') or 'Browser').strip()[:80]
    if not code:
        return jsonify({"error": "code is required"}), 400

    conn = get_db()
    rows = conn.run(
        "SELECT code, user_email, expires_at, used FROM extension_pairing_codes WHERE code=:c",
        c=code
    )
    if not rows:
        conn.close()
        return jsonify({"error": "Invalid pairing code"}), 400
    _, user_email, expires_at, used = rows[0]
    if used:
        conn.close()
        return jsonify({"error": "Pairing code already used"}), 400
    expires_at = _ext_ensure_aware(expires_at)
    if _ext_utc_now() > expires_at:
        conn.close()
        return jsonify({"error": "Pairing code expired"}), 400

    token = _ext_new_token(32)
    conn.run(
        """INSERT INTO extension_tokens (token, user_email, device_label, created_at, last_used_at, revoked)
           VALUES (:t, :e, :d, NOW(), NOW(), false)""",
        t=token, e=user_email, d=device_label
    )
    conn.run("UPDATE extension_pairing_codes SET used=true WHERE code=:c", c=code)
    conn.close()
    return jsonify({"token": token, "user_email": user_email})


@app.route('/api/extension/revoke', methods=['POST'])
@extension_token_required
def extension_revoke():
    auth_header = request.headers.get('Authorization', '')
    token = auth_header[7:].strip()
    conn = get_db()
    conn.run("UPDATE extension_tokens SET revoked=true WHERE token=:t", t=token)
    conn.close()
    return jsonify({"success": True})


@app.route('/api/extension/me', methods=['GET'])
@extension_token_required
def extension_me():
    email = request.extension_user_email
    conn = get_db()
    urows = conn.run(
        "SELECT name FROM users WHERE LOWER(email)=LOWER(:e) LIMIT 1", e=email
    )
    conn.close()
    name = urows[0][0] if urows else email.split('@')[0]
    return jsonify({"email": email, "name": name})


@app.route('/api/extension/apps', methods=['GET'])
@extension_token_required
def extension_apps():
    email = request.extension_user_email
    conn = get_db()
    rows = conn.run(
        """SELECT app_name, app_url FROM user_credentials
           WHERE user_email=:e AND revoked=false""",
        e=email
    )
    conn.close()
    return jsonify([
        {"app_name": r[0], "app_url": r[1]}
        for r in rows
    ])


@app.route('/api/extension/credentials/<app_name>', methods=['GET'])
@extension_token_required
def extension_credentials(app_name):
    email = request.extension_user_email
    conn = get_db()
    rows = conn.run(
        """SELECT username, password, app_url FROM user_credentials
           WHERE user_email=:e AND app_name=:a AND revoked=false""",
        e=email, a=app_name
    )
    conn.run(
        """INSERT INTO audit_logs (user_email, app_name, action)
           VALUES (:e, :a, 'extension_fetch')""",
        e=email, a=app_name
    )
    conn.close()
    if not rows:
        return jsonify({"error": "Not found or no access"}), 404
    return jsonify({
        "app_name": app_name,
        "username": rows[0][0],
        "password": rows[0][1],
        "app_url": rows[0][2],
    })


@app.route('/api/extension/match-domain', methods=['POST'])
@extension_token_required
def extension_match_domain():
    """Given a hostname (the page the user is currently on), return all of the
    user's unlocked credentials whose stored app_url matches that hostname or
    a known related domain. Used by the popup's 'matching credentials' list."""
    data = request.json or {}
    hostname = (data.get('hostname') or '').strip().lower()
    if not hostname:
        return jsonify([])
    # Strip leading www.
    if hostname.startswith('www.'):
        hostname = hostname[4:]
    # Build a set of acceptable hostnames — exact + parent domains.
    # e.g. 'authenticator.cursor.sh' -> {'authenticator.cursor.sh', 'cursor.sh'}
    parts = hostname.split('.')
    candidates = set()
    for i in range(len(parts) - 1):
        candidates.add('.'.join(parts[i:]))

    # Also fold in the obvious known related hosts. Static map keeps us honest
    # for cases like chatgpt.com<->openai.com that aren't subdomain-related.
    RELATED = {
        'chatgpt.com':       {'openai.com', 'auth.openai.com', 'platform.openai.com'},
        'openai.com':        {'chatgpt.com', 'chat.openai.com'},
        'chat.openai.com':   {'chatgpt.com', 'openai.com'},
        'cursor.com':        {'cursor.sh', 'authenticator.cursor.sh', 'cursor.us.auth0.com'},
        'cursor.sh':         {'cursor.com', 'authenticator.cursor.sh', 'cursor.us.auth0.com'},
        'claude.ai':         {'anthropic.com', 'console.anthropic.com'},
        'anthropic.com':     {'claude.ai', 'console.anthropic.com'},
    }
    for c in list(candidates):
        if c in RELATED:
            candidates.update(RELATED[c])

    email = request.extension_user_email
    conn = get_db()
    rows = conn.run(
        """SELECT app_name, username, password, app_url FROM user_credentials
           WHERE user_email=:e AND revoked=false""",
        e=email
    )
    conn.close()

    out = []
    for app_name, uname, pw, app_url in rows:
        if not app_url:
            continue
        try:
            # Extract host from app_url
            from urllib.parse import urlparse as _up
            au = (app_url or '').strip()
            if not au.startswith('http'):
                au = 'https://' + au
            host = (_up(au).hostname or '').lower()
            if host.startswith('www.'):
                host = host[4:]
        except Exception:
            host = ''
        if not host:
            continue
        # Match if the stored host is in our candidates set, OR the current
        # host ends with the stored host (e.g. authenticator.cursor.sh ends
        # with cursor.sh, which is the stored value).
        match = False
        if host in candidates:
            match = True
        elif hostname == host or hostname.endswith('.' + host):
            match = True
        if match:
            out.append({
                "app_name": app_name,
                "username": uname,
                "password": pw,
                "app_url": app_url,
            })

    # Audit
    if out:
        conn = get_db()
        for cred in out:
            conn.run(
                """INSERT INTO audit_logs (user_email, app_name, action)
                   VALUES (:e, :a, 'extension_match_domain')""",
                e=email, a=cred["app_name"]
            )
        conn.close()

    return jsonify(out)


# ── Auto-create extension tables on startup if missing ────────────────────────
def _ext_init_tables():
    try:
        conn = get_db()
        conn.run("""
            CREATE TABLE IF NOT EXISTS extension_pairing_codes (
                code TEXT PRIMARY KEY,
                user_email TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        conn.run("""
            CREATE TABLE IF NOT EXISTS extension_tokens (
                token TEXT PRIMARY KEY,
                user_email TEXT NOT NULL,
                device_label TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                last_used_at TIMESTAMPTZ DEFAULT NOW(),
                revoked BOOLEAN DEFAULT FALSE
            )
        """)
        conn.close()
        print("[ext] extension tables ready")
    except Exception as e:
        print(f"[ext] table init failed: {e}")


_ext_init_tables()

# ╚══════════════════════════════════════════════════════════════════════════╝


init_db()

if __name__ == "__main__":
    print("CredsVault running on http://localhost:5000")
    app.run(debug=True, port=5000)