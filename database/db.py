import sqlite3
import os
import tempfile
from config import Config

_cached_db_path = None

def get_db_path():
    global _cached_db_path
    if _cached_db_path:
        return _cached_db_path

    # 1. Environment variable override
    env_path = os.environ.get('DATABASE_PATH')
    if env_path:
        _cached_db_path = env_path
        return _cached_db_path

    # 2. Try default project instance path
    target_path = Config.DATABASE_PATH
    try:
        dir_name = os.path.dirname(target_path)
        os.makedirs(dir_name, exist_ok=True)
        # Check write permissions
        test_file = os.path.join(dir_name, '.perm_test')
        with open(test_file, 'w') as f:
            f.write('ok')
        os.remove(test_file)
        _cached_db_path = target_path
        return _cached_db_path
    except Exception as e:
        print(f"[!] Warning: Cannot write to default database location ({e}). Using temporary directory.")

    # 3. Cloud / Readonly Mount Fallback (e.g. Streamlit Cloud /mount/src/...)
    fallback_dir = tempfile.gettempdir()
    _cached_db_path = os.path.join(fallback_dir, 'ai_shield.db')
    return _cached_db_path

def get_db_connection():
    db_path = get_db_path()
    conn = sqlite3.connect(db_path, timeout=15.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=MEMORY")
        conn.execute("PRAGMA synchronous=OFF")
    except Exception:
        pass
    return conn

def init_db():
    schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
    with open(schema_path, 'r', encoding='utf-8') as f:
        schema = f.read()
    
    conn = get_db_connection()
    try:
        conn.executescript(schema)
        conn.commit()
    except Exception as e:
        print(f"[!] Schema initialization warning: {e}")

    try:
        with conn:
            conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('prevention_mode', 'Alert Only')")
            conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('detection_threshold', '0.70')")
            conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('auto_block_severity', 'Critical')")
            conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('block_duration_minutes', '10')")
            conn.execute(
                "INSERT INTO audit_logs (event_type, actor, details, status) VALUES (?, ?, ?, ?)",
                ('SYSTEM_INIT', 'DATABASE', 'AI-SHIELD SQLite Database initialized successfully', 'SUCCESS')
            )
    except Exception as e:
        print(f"[!] Default settings warning: {e}")
    finally:
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
