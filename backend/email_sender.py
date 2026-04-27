import os
import traceback
import requests
from dotenv import load_dotenv

load_dotenv()

def send_credentials_email(to_email, app_name, app_url, psk, portal_link):
    print(f"[EMAIL] Attempting to send to {to_email} for {app_name}")

    api_key = os.getenv("MANDRILL_API_KEY")
    sender  = os.getenv("GMAIL_USER", "akash@5cnetwork.com")

    if not api_key:
        print("[EMAIL] ERROR: MANDRILL_API_KEY not set!")
        return

    html_body = f"""
    <html><body style="font-family:sans-serif;max-width:500px;margin:auto">
      <h2 style="color:#1a73e8">Your credentials for {app_name}</h2>
      <p>Your access request has been approved. Use the pre-shared key below in the App Portal to view your credentials.</p>
      <div style="background:#f8f9fa;padding:16px;border-radius:8px;margin:16px 0">
        <p style="margin:0 0 8px 0"><strong>Pre-shared key</strong></p>
        <code style="background:#e8f0fe;padding:8px 16px;border-radius:6px;font-size:20px;letter-spacing:3px;display:inline-block">{psk}</code>
      </div>
      <p style="color:#555;font-size:13px;margin-top:20px">
        Open the App Portal, click <strong>View Credentials</strong> on <strong>{app_name}</strong>, and paste this key.
      </p>
      <p style="color:#888;font-size:12px;margin-top:16px">Key expires in 48 hours. Single use only. Do not share.</p>
    </body></html>
    """

    payload = {
        "key": api_key,
        "message": {
            "html":       html_body,
            "subject":    f"Your access credentials for {app_name}",
            "from_email": sender,
            "from_name":  "5C Network IT Support",
            "to": [{"email": to_email, "type": "to"}]
        }
    }

    try:
        response = requests.post(
            "https://mandrillapp.com/api/1.0/messages/send",
            json=payload,
            timeout=30
        )
        result = response.json()
        if isinstance(result, list) and result[0].get("status") in ("sent", "queued"):
            print(f"[EMAIL] SUCCESS - sent to {to_email}")
        else:
            print(f"[EMAIL] ERROR - {result}")
    except Exception as e:
        print(f"[EMAIL] UNEXPECTED ERROR: {e}")
        traceback.print_exc()