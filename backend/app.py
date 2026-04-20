from flask import Flask, request, jsonify, render_template
import firebase_admin
from firebase_admin import credentials, firestore
from encryption import generate_psk, encrypt_credentials, decrypt_credentials
from email_sender import send_credentials_email
import hashlib
import os
import json
import threading
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, template_folder="templates")

# Support both file-based and env-based Firebase credentials
firebase_creds_json = os.getenv("FIREBASE_CREDENTIALS_JSON")
if firebase_creds_json:
    cred_dict = json.loads(firebase_creds_json)
    cred = credentials.Certificate(cred_dict)
else:
    cred = credentials.Certificate(os.getenv("FIREBASE_CREDENTIALS_PATH"))

firebase_admin.initialize_app(cred, {'projectId': 'credvault-39b1f'})
db = firestore.client(database_id='credvault')

ALLOWED_DOMAINS = ['5cnetwork.com', '5cnetwork.in']
ADMIN_EMAIL = 'akash@5cnetwork.com'


def is_allowed_email(email):
    domain = email.split('@')[-1].lower()
    return domain in ALLOWED_DOMAINS


def send_admin_notification(user_email, app_name, request_id):
    """Send email to admin about pending approval request."""
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
      <p>Request ID: <code>{request_id}</code></p>
      <p>Please log in to the admin dashboard to approve or reject:</p>
      <a href="{approve_url}" style="background:#EF9F27;color:#000;padding:10px 20px;text-decoration:none;border-radius:6px;font-weight:bold;display:inline-block;margin-top:10px">
        Open Admin Dashboard
      </a>
      <p style="color:#999;font-size:12px;margin-top:20px">CredVault · 5C Network</p>
    </div>
    """

    msg.attach(MIMEText(html, 'html'))

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(gmail_user, gmail_password)
            server.sendmail(gmail_user, ADMIN_EMAIL, msg.as_string())
    except Exception as e:
        print(f"Admin notification email failed: {e}")


@app.route("/api/process-request", methods=["POST"])
def process_request():
    data = request.json
    user_email = data.get("user_email", "").strip().lower()
    app_name   = data.get("app_name", "").strip()

    if not user_email or not app_name:
        return jsonify({"error": "user_email and app_name are required"}), 400

    # ── Domain verification ──
    if not is_allowed_email(user_email):
        domain = user_email.split('@')[-1]
        db.collection("audit_logs").add({
            "user_email": user_email,
            "app_name":   app_name,
            "action":     "domain_rejected",
            "timestamp":  datetime.now(timezone.utc)
        })
        return jsonify({"error": f"Access denied. '{domain}' is not an authorized domain. Only 5cnetwork.com and 5cnetwork.in emails are allowed."}), 403

    # ── Check app exists ──
    results = db.collection("applications").where("name", "==", app_name).get()
    if not results:
        return jsonify({"error": f"App '{app_name}' not found"}), 404

    # ── Save as pending request ──
    req_ref = db.collection("pending_requests").add({
        "user_email": user_email,
        "app_name":   app_name,
        "status":     "pending",
        "created_at": datetime.now(timezone.utc),
        "reviewed_at": None,
        "reviewed_by": None,
    })
    request_id = req_ref[1].id

    # ── Log the request ──
    db.collection("audit_logs").add({
        "user_email": user_email,
        "app_name":   app_name,
        "action":     "access_requested",
        "timestamp":  datetime.now(timezone.utc)
    })

    # ── Notify admin via email ──
    send_admin_notification(user_email, app_name, request_id)

    return jsonify({"success": True, "message": f"Request received. Admin will review and send credentials to {user_email} shortly."})


@app.route("/api/admin/approve/<request_id>", methods=["POST"])
def approve_request(request_id):
    req_ref  = db.collection("pending_requests").document(request_id)
    req_doc  = req_ref.get()

    if not req_doc.exists:
        return jsonify({"error": "Request not found"}), 404

    req = req_doc.to_dict()

    if req.get("status") != "pending":
        return jsonify({"error": f"Request already {req.get('status')}"}), 400

    user_email = req["user_email"]
    app_name   = req["app_name"]

    # ── Get app credentials ──
    results = db.collection("applications").where("name", "==", app_name).get()
    if not results:
        return jsonify({"error": f"App '{app_name}' not found"}), 404

    app_doc = results[0].to_dict()
    psk = generate_psk()

    creds_payload = json.dumps({
        "username": app_doc["username"],
        "password": app_doc["password"],
        "app_url":  app_doc["url"],
        "app_name": app_name
    })

    encrypted = encrypt_credentials(creds_payload, psk)
    psk_hash  = hashlib.sha256(psk.encode()).hexdigest()

    token_ref = db.collection("psk_tokens").add({
        "user_email":      user_email,
        "app_name":        app_name,
        "psk_hash":        psk_hash,
        "encrypted_creds": encrypted,
        "expires_at":      datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=48),
        "used":            False,
        "created_at":      datetime.now(timezone.utc).replace(tzinfo=None)
    })
    token_id = token_ref[1].id

    portal_link = f"{os.getenv('PORTAL_BASE_URL')}/access/{token_id}"
    send_credentials_email(user_email, app_name, app_doc["url"], psk, portal_link)

    # ── Update request status ──
    req_ref.update({
        "status":      "approved",
        "reviewed_at": datetime.now(timezone.utc),
    })

    db.collection("audit_logs").add({
        "user_email": user_email,
        "app_name":   app_name,
        "action":     "credentials_sent",
        "timestamp":  datetime.now(timezone.utc)
    })

    return jsonify({"success": True, "message": f"Approved. Credentials sent to {user_email}"})


@app.route("/api/admin/reject/<request_id>", methods=["POST"])
def reject_request(request_id):
    req_ref = db.collection("pending_requests").document(request_id)
    req_doc = req_ref.get()

    if not req_doc.exists:
        return jsonify({"error": "Request not found"}), 404

    req = req_doc.to_dict()

    if req.get("status") != "pending":
        return jsonify({"error": f"Request already {req.get('status')}"}), 400

    req_ref.update({
        "status":      "rejected",
        "reviewed_at": datetime.now(timezone.utc),
    })

    db.collection("audit_logs").add({
        "user_email": req["user_email"],
        "app_name":   req["app_name"],
        "action":     "access_rejected",
        "timestamp":  datetime.now(timezone.utc)
    })

    return jsonify({"success": True, "message": "Request rejected."})


@app.route("/access/<token_id>", methods=["GET", "POST"])
def access_portal(token_id):
    if request.method == "GET":
        return render_template("portal.html", token_id=token_id)

    psk_input = (request.json or {}).get("psk", "").strip()
    doc_ref   = db.collection("psk_tokens").document(token_id)
    doc       = doc_ref.get()

    if not doc.exists:
        return jsonify({"error": "Invalid or expired link"}), 404

    token = doc.to_dict()

    if token.get("used"):
        return jsonify({"error": "This link has already been used. Contact IT for a new one."}), 400

    exp = token.get("expires_at")
    if exp:
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > exp:
            return jsonify({"error": "This link has expired. Please request again."}), 400

    if hashlib.sha256(psk_input.encode()).hexdigest() != token["psk_hash"]:
        return jsonify({"error": "Incorrect key. Please check your email."}), 401

    decrypted = decrypt_credentials(token["encrypted_creds"], psk_input)
    doc_ref.update({"used": True})

    db.collection("audit_logs").add({
        "user_email": token["user_email"],
        "app_name":   token["app_name"],
        "action":     "credentials_accessed",
        "timestamp":  datetime.now(timezone.utc)
    })

    return jsonify({"success": True, "credentials": decrypted})


@app.route("/admin/logs", methods=["GET"])
def admin_logs():
    logs = db.collection("audit_logs") \
             .order_by("timestamp", direction=firestore.Query.DESCENDING) \
             .limit(200).get()
    result = []
    for l in logs:
        d = l.to_dict()
        if "timestamp" in d and hasattr(d["timestamp"], "isoformat"):
            d["timestamp"] = d["timestamp"].isoformat()
        result.append(d)
    return jsonify(result)


@app.route("/admin/applications", methods=["GET"])
def admin_applications():
    apps = db.collection("applications").get()
    result = []
    for a in apps:
        d = a.to_dict()
        d["id"] = a.id
        d.pop("password", None)
        result.append(d)
    return jsonify(result)


@app.route("/admin/applications", methods=["POST"])
def add_application():
    data = request.json
    for field in ["name", "url", "username", "password"]:
        if not data.get(field):
            return jsonify({"error": f"'{field}' is required"}), 400
    db.collection("applications").add({
        "name":       data["name"],
        "url":        data["url"],
        "username":   data["username"],
        "password":   data["password"],
        "created_at": datetime.now(timezone.utc)
    })
    return jsonify({"success": True})


@app.route("/admin/tokens", methods=["GET"])
def admin_tokens():
    tokens = db.collection("psk_tokens").get()
    result = []
    for t in tokens:
        d = t.to_dict()
        d["id"] = t.id
        for key in ("expires_at", "created_at"):
            if key in d and hasattr(d[key], "isoformat"):
                d[key] = d[key].isoformat()
        result.append(d)
    return jsonify(result)


@app.route("/admin/pending", methods=["GET"])
def admin_pending():
    reqs = db.collection("pending_requests") \
             .where("status", "==", "pending") \
             .order_by("created_at", direction=firestore.Query.DESCENDING) \
             .limit(100).get()
    result = []
    for r in reqs:
        d = r.to_dict()
        d["id"] = r.id
        for key in ("created_at", "reviewed_at"):
            if key in d and d[key] and hasattr(d[key], "isoformat"):
                d[key] = d[key].isoformat()
        result.append(d)
    return jsonify(result)


@app.route("/admin", methods=["GET"])
def admin_dashboard():
    return render_template("admin.html")


if __name__ == "__main__":
    print("CredsVault running on http://localhost:5000")
    app.run(debug=True, port=5000)