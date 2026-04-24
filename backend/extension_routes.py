# ── EXTENSION ROUTES ── paste these into app.py (after existing user routes)
# Also run extension_db_init.sql once to create the new tables.

import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import request, jsonify, session


# ── helpers ──────────────────────────────────────────────────────────────────

def _new_token(n_bytes=32):
    return secrets.token_urlsafe(n_bytes)


def _utc_now():
    return datetime.now(timezone.utc)


def _ensure_aware(dt):
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

        # update last_used
        conn.run(
            "UPDATE extension_tokens SET last_used_at = NOW() WHERE token = :t",
            t=token
        )
        conn.close()

        request.extension_user_email = user_email  # stash on request for the handler
        return f(*args, **kwargs)
    return decorated


# ── CORS for extension endpoints ─────────────────────────────────────────────
# Chrome extensions have origin like chrome-extension://<id>. We allow all
# extension origins on /api/extension/* — the bearer token is what protects the data.

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


# ── PAIRING (browser extension <-> portal) ───────────────────────────────────

@app.route('/api/extension/pair', methods=['POST'])
@user_login_required
def extension_pair():
    """User clicks 'Connect Extension' on the portal while logged in.
    We mint a short-lived pairing code (5 minutes) bound to their email.
    The extension will redeem this code for a long-lived bearer token."""
    user_email = session.get('user_email')
    code = _new_token(16)  # short, single-use
    expires_at = _utc_now() + timedelta(minutes=5)
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
    """Extension exchanges a pairing code for a long-lived access token.
    No auth required for this endpoint — possession of a fresh code IS the auth."""
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
    expires_at = _ensure_aware(expires_at)
    if _utc_now() > expires_at:
        conn.close()
        return jsonify({"error": "Pairing code expired"}), 400

    token = _new_token(32)
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
    """Extension can self-revoke (e.g. on uninstall / sign-out)."""
    auth_header = request.headers.get('Authorization', '')
    token = auth_header[7:].strip()
    conn = get_db()
    conn.run("UPDATE extension_tokens SET revoked=true WHERE token=:t", t=token)
    conn.close()
    return jsonify({"success": True})


# ── EXTENSION DATA APIs ──────────────────────────────────────────────────────

@app.route('/api/extension/me', methods=['GET'])
@extension_token_required
def extension_me():
    """Sanity check / health endpoint — returns the paired user's identity."""
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
    """Return all apps the user has saved credentials for, with target URLs.
    Used by the extension to know which sites to autofill on."""
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
    """Return the actual credentials for a given app for the paired user."""
    email = request.extension_user_email
    conn = get_db()
    rows = conn.run(
        """SELECT username, password, app_url FROM user_credentials
           WHERE user_email=:e AND app_name=:a AND revoked=false""",
        e=email, a=app_name
    )
    # Audit log
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
