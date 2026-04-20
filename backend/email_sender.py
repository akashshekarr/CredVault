import os
import traceback
import requests
from dotenv import load_dotenv

load_dotenv()

def send_credentials_email(to_email, app_name, app_url, psk, portal_link):
    print(f"[EMAIL] Attempting to send to {to_email} for {app_name}")

    api_key = os.getenv("RESEND_API_KEY")
    if not api_key:
        print("[EMAIL] ERROR: RESEND_API_KEY not set!")
        return

    html_body = f"""
    <html><body style="font-family:sans-serif;max-width:500px;margin:auto">
      <h2 style="color:#1a73e8">Your credentials for {app_name}</h2>
      <p>Your access request has been approved. Follow the steps below.</p>
      <div style="background:#f8f9fa;padding:16px;border-radius:8px;margin:16px 0">
        <p><strong>Step 1</strong> - Click this link:</p>
        <a href="{portal_link}">{portal_link}</a>
      </div>
      <div style="background:#f8f9fa;padding:16px;border-radius:8px;margin:16px 0">
        <p><strong>Step 2</strong> - Enter this pre-shared key:</p>
        <code style="background:#e8f0fe;padding:8px 16px;border-radius:6px;font-size:20px;letter-spacing:3px">{psk}</code>
      </div>
      <div style="background:#f8f9fa;padding:16px;border-radius:8px;margin:16px 0">
        <p><strong>Step 3</strong> - Visit the app:</p>
        <a href="{app_url}">{app_url}</a>
      </div>
      <p style="color:#888;font-size:12px">Key expires in 48 hours. Single use only. Do not share.</p>
    </body></html>
    """

    try:
        response = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "from": "CredVault IT Support <onboarding@resend.dev>",
                "to": [to_email],
                "subject": f"Your access credentials for {app_name}",
                "html": html_body
            },
            timeout=30
        )
        if response.status_code == 200:
            print(f"[EMAIL] SUCCESS - sent to {to_email}")
        else:
            print(f"[EMAIL] ERROR - status {response.status_code}: {response.text}")
    except Exception as e:
        print(f"[EMAIL] UNEXPECTED ERROR: {e}")
        traceback.print_exc()