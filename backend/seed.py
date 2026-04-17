import firebase_admin
from firebase_admin import credentials, firestore
from dotenv import load_dotenv
import os

load_dotenv()

cred = credentials.Certificate(os.getenv("FIREBASE_CREDENTIALS_PATH"))
firebase_admin.initialize_app(cred, {'projectId': 'credvault-39b1f'})
db = firestore.client(database_id='credvault')

applications = [
    {
        "name": "ChatGPT",
        "url": "https://chat.openai.com",
        "username": "company@5cnetwork.com",
        "password": "your_chatgpt_password_here"
    },
    {
        "name": "Claude",
        "url": "https://claude.ai",
        "username": "company@5cnetwork.com",
        "password": "your_claude_password_here"
    },
    {
        "name": "Cursor",
        "url": "https://cursor.sh",
        "username": "company@5cnetwork.com",
        "password": "your_cursor_password_here"
    },
]

for application in applications:
    db.collection("applications").add(application)
    print(f"Added: {application['name']}")

print("\nDone! All applications added.")