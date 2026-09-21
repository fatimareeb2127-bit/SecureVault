import sqlite3
from pathlib import Path
from datetime import datetime


APP_DIR = Path.home() / ".securevault"

APP_DIR.mkdir(
    parents=True,
    exist_ok=True
)

DATABASE = APP_DIR / "securevault.db"


def connect():

    connection = sqlite3.connect(
        DATABASE
    )

    connection.execute("""
        CREATE TABLE IF NOT EXISTS vault (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            encrypted_data BLOB NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT
        )
    """)

    connection.commit()

    return connection


def add_log(action, details=""):

    connection = connect()

    connection.execute(
        """
        INSERT INTO logs
        (timestamp, action, details)
        VALUES (?, ?, ?)
        """,
        (
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            action,
            details[:500]
        )
    )

    connection.commit()
    connection.close()


def get_logs():

    connection = connect()

    rows = connection.execute(
        """
        SELECT timestamp, action, details
        FROM logs
        ORDER BY id DESC
        LIMIT 500
        """
    ).fetchall()

    connection.close()

    return rows


def clear_logs():

    connection = connect()

    connection.execute(
        "DELETE FROM logs"
    )

    connection.commit()
    connection.close()


def get_counts():

    connection = connect()

    encrypted = connection.execute(
        """
        SELECT COUNT(*)
        FROM logs
        WHERE action = 'File encrypted'
        """
    ).fetchone()[0]

    hashes = connection.execute(
        "SELECT COUNT(*) FROM hashes"
    ).fetchone()[0]

    vault = connection.execute(
        "SELECT COUNT(*) FROM vault"
    ).fetchone()[0]

    logs = connection.execute(
        "SELECT COUNT(*) FROM logs"
    ).fetchone()[0]

    connection.close()

    return encrypted, hashes, vault, logs