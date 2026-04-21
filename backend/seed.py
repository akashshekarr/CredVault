import pg8000.native
from urllib.parse import urlparse
from dotenv import load_dotenv
import os

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
url = urlparse(DATABASE_URL)

conn = pg8000.native.Connection(
    host=url.hostname,
    port=url.port or 5432,
    database=url.path[1:],
    user=url.username,
    password=url.password,
    ssl_context=False  # local connection, no SSL needed
)

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
    try:
        conn.run(
            "INSERT INTO applications (name, url, username, password) VALUES (:n, :u, :un, :p) ON CONFLICT (name) DO UPDATE SET url=:u, username=:un, password=:p",
            n=application['name'],
            u=application['url'],
            un=application['username'],
            p=application['password']
        )
        print(f"Added: {application['name']}")
    except Exception as e:
        print(f"Error adding {application['name']}: {e}")

conn.close()
print("\nDone! All applications seeded.")