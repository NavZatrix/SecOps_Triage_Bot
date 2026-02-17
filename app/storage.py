import sqlite3
from pathlib import Path

DB_PATH = Path("state.db")

def get_conn():
    """Return a SQLite connection and ensure schema exists."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            dedupe_key TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            count INTEGER NOT NULL
        )
        """
    )
    return conn
