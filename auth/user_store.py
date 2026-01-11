"""
User Store Module
-----------------
Handles secure storage and retrieval of SOC users.

Responsibilities:
- SQLite user database
- Password hashing with salt
- User registration storage
- Authentication data lookup
- Password reset token handling

NO GUI
NO SOC logic
"""

import sqlite3
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta
from pathlib import Path

# -------------------------------------------------
# DATABASE LOCATION
# -------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "users.db"


# -------------------------------------------------
# DATABASE INITIALIZATION
# -------------------------------------------------

def initialize_user_db():
    """
    Create user and reset tables if they do not exist.
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                token TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
        """)

        conn.commit()


# -------------------------------------------------
# PASSWORD SECURITY
# -------------------------------------------------

def _generate_salt() -> str:
    return secrets.token_hex(16)


def _hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((password + salt).encode("utf-8")).hexdigest()


# -------------------------------------------------
# USER QUERIES
# -------------------------------------------------

def user_exists() -> bool:
    initialize_user_db()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        return cursor.fetchone()[0] > 0


def get_user_by_username(username: str):
    initialize_user_db()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT username, email, password_hash, salt
            FROM users WHERE username = ?
        """, (username,))
        return cursor.fetchone()


def get_user_by_email(email: str):
    initialize_user_db()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT username, email, password_hash, salt
            FROM users WHERE email = ?
        """, (email,))
        return cursor.fetchone()


# -------------------------------------------------
# USER CREATION
# -------------------------------------------------

def create_user(username: str, email: str, password: str):
    initialize_user_db()

    salt = _generate_salt()
    password_hash = _hash_password(password, salt)

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, salt, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            username,
            email,
            password_hash,
            salt,
            datetime.utcnow().isoformat()
        ))
        conn.commit()


# -------------------------------------------------
# AUTHENTICATION
# -------------------------------------------------

def verify_credentials(identifier: str, password: str) -> bool:
    if "@" in identifier:
        user = get_user_by_email(identifier)
    else:
        user = get_user_by_username(identifier)

    if not user:
        return False

    _, _, stored_hash, salt = user
    input_hash = _hash_password(password, salt)

    return secrets.compare_digest(input_hash, stored_hash)


# -------------------------------------------------
# PASSWORD RESET (TOKEN BASED)
# -------------------------------------------------

def create_reset_token(username: str) -> str:
    """
    Generate and store password reset token (15 min expiry).
    Invalidates previous tokens.
    """
    initialize_user_db()

    token = uuid.uuid4().hex
    expires_at = (datetime.utcnow() + timedelta(minutes=15)).isoformat()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        # Invalidate old tokens
        cursor.execute(
            "DELETE FROM password_resets WHERE username = ?",
            (username,)
        )

        cursor.execute("""
            INSERT INTO password_resets (username, token, expires_at)
            VALUES (?, ?, ?)
        """, (username, token, expires_at))

        conn.commit()

    return token


def validate_reset_token(username: str, token: str) -> bool:
    initialize_user_db()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT expires_at FROM password_resets
            WHERE username = ? AND token = ?
        """, (username, token))

        row = cursor.fetchone()
        if not row:
            return False

        expires_at = datetime.fromisoformat(row[0])
        return datetime.utcnow() < expires_at


def update_password(username: str, new_password: str) -> bool:
    """
    Update user password and invalidate reset tokens.
    """
    initialize_user_db()

    salt = _generate_salt()
    password_hash = _hash_password(new_password, salt)

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE users
            SET password_hash = ?, salt = ?
            WHERE username = ?
        """, (password_hash, salt, username))

        if cursor.rowcount == 0:
            return False

        cursor.execute(
            "DELETE FROM password_resets WHERE username = ?",
            (username,)
        )

        conn.commit()

    return True
