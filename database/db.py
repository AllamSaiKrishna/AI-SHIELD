import sqlite3
import os
from config import Config

def get_db_connection():
    os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)
    schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
    with open(schema_path, 'r') as f:
        schema = f.read()
    
    conn = get_db_connection()
    with conn:
        conn.executescript(schema)
        # Initialize default settings if not exists
        conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('prevention_mode', 'Alert Only')")
        conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('detection_threshold', '0.70')")
        conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('auto_block_severity', 'Critical')")
        conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('block_duration_minutes', '10')")
        
        # Log system initialization in audit_logs
        conn.execute(
            "INSERT INTO audit_logs (event_type, actor, details, status) VALUES (?, ?, ?, ?)",
            ('SYSTEM_INIT', 'DATABASE', 'AI-SHIELD SQLite Database initialized successfully', 'SUCCESS')
        )
    conn.close()

def log_audit(event_type, details, actor='SYSTEM', status='SUCCESS'):
    try:
        conn = get_db_connection()
        with conn:
            conn.execute(
                "INSERT INTO audit_logs (event_type, actor, details, status) VALUES (?, ?, ?, ?)",
                (event_type, actor, details, status)
            )
        conn.close()
    except Exception as e:
        print(f"Audit log failure: {e}")

def get_setting(key, default=None):
    try:
        conn = get_db_connection()
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        conn.close()
        return row['value'] if row else default
    except Exception:
        return default

def set_setting(key, value):
    try:
        conn = get_db_connection()
        with conn:
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
        conn.close()
        return True
    except Exception as e:
        print(f"Error setting {key}: {e}")
        return False
