import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# SQLite — no server needed, file lives next to app.py
DB_PATH = os.path.join(BASE_DIR, 'diary.db')

UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
