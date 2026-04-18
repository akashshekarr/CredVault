from flask import Flask, request, jsonify, render_template
import firebase_admin
from firebase_admin import credentials, firestore
from encryption import generate_psk, encrypt_credentials, decrypt_credentials
from email_sender import send_credentials_email
import hashlib
import os
import json
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, template_folder="templates")

cred = credentials.Certificate(os.getenv("FIREBASE_CREDENTIALS_PATH"))
firebase_admin.initialize_app(cred, {'projectId': 'credvault-39b1f'})
db = firestore.client(database_id='credvault')



@app.route("/api/process-request", methods=["POST"])
def process_request():
    data = request.json
    user_email = data.get("user_email", "").strip().lower()
    app_name   = data.get("app_name", "").strip()

    if not user_email or not app_name:
        return jsonify({"error": "user_email and app_name are required"}), 400

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

    db.collection("audit_logs").add({
        "user_email": user_email,
        "app_name":   app_name,
        "action":     "credentials_sent",
        "timestamp":  datetime.utcnow()
    })

    return jsonify({"success": True, "message": f"Credentials sent to {user_email}"})


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
    if exp and datetime.now(timezone.utc) > exp.replace(tzinfo=timezone.utc):
        return jsonify({"error": "This link has expired. Please request again."}), 400

    if hashlib.sha256(psk_input.encode()).hexdigest() != token["psk_hash"]:
        return jsonify({"error": "Incorrect key. Please check your email."}), 401

    decrypted = decrypt_credentials(token["encrypted_creds"], psk_input)
    doc_ref.update({"used": True})

    db.collection("audit_logs").add({
        "user_email": token["user_email"],
        "app_name":   token["app_name"],
        "action":     "credentials_accessed",
        "timestamp":  datetime.utcnow()
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
        "created_at": datetime.utcnow()
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


@app.route("/admin", methods=["GET"])
def admin_dashboard():
    return render_template("admin.html")


if __name__ == "__main__":
    print("CredsVault running on http://localhost:5000")
    app.run(debug=True, port=5000)