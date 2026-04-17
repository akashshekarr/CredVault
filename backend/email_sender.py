import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()


def send_credentials_email(to_email, app_name, app_url, psk, portal_link):
    sender = os.getenv("GMAIL_USER")
    password = os.getenv("GMAIL_APP_PASSWORD")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"Your access credentials for {app_name}"
    msg["From"] = sender
    msg["To"] = to_email

    html_body = f"""
    <html><body style="font-family:sans-serif;max-width:500px;margin:auto">
      <h2 style="color:#1a73e8">Your credentials for {app_name}</h2>
      <p>Your access request has been approved. Follow the steps below.</p>
      <div style="background:#f8f9fa;padding:16px;border-radius:8px;margin:16px 0">
        <p><strong>Step 1</strong> — Click this link:</p>
        <a href="{portal_link}">{portal_link}</a>
      </div>
      <div style="background:#f8f9fa;padding:16px;border-radius:8px;margin:16px 0">
        <p><strong>Step 2</strong> — Enter this pre-shared key:</p>
        <code style="background:#e8f0fe;padding:8px 16px;border-radius:6px;font-size:20px;letter-spacing:3px">{psk}</code>
      </div>
      <div style="background:#f8f9fa;padding:16px;border-radius:8px;margin:16px 0">
        <p><strong>Step 3</strong> — Visit the app:</p>
        <a href="{app_url}">{app_url}</a>
      </div>
      <p style="color:#888;font-size:12px">Key expires in 48 hours. Single use only. Do not share.</p>
    </body></html>
    """

    msg.attach(MIMEText(html_body, "html"))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender, password)
        server.sendmail(sender, to_email, msg.as_string())

    print(f"Email sent to {to_email}")