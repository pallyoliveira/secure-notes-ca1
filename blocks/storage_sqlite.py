"""
BLOCK: Storage — SQLite database
SLOT:  storage        (every app needs exactly one storage block)

WHAT THIS BLOCK DOES
    Exactly the same job as storage_json, but keeps the data in a real
    database file (data.db) instead of a text file. The functions have the
    same names and take the same arguments, so you can swap one for the other
    without changing any other block. That is the whole point of the kit.

WHY YOU MIGHT CHOOSE IT
    A database handles two programs writing at once, and it lets you write
    queries. More importantly for this module, it is where you meet
    *parameterised queries* — the single most important habit in this block.

WHAT YOU SHOULD SAY ABOUT IT IN YOUR REPORT
    The file itself is still unencrypted: anyone who can read data.db can read
    every record. What you gain over the JSON block is the ability to let the
    database engine separate code from data, which is what stops SQL injection.
"""

import os
import sqlite3

BLOCK_NAME = "Storage: SQLite database"

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data.db")


def _connect():
    """Open a connection to the database file."""
    conn = sqlite3.connect(DB_FILE)
    # This makes rows behave like dictionaries, so you can write row["text"]
    # instead of having to remember that text is column number 2.
    conn.row_factory = sqlite3.Row
    return conn


def init():
    """Create the tables the first time the app runs.

    "IF NOT EXISTS" means this is safe to call every single startup — if the
    tables are already there, nothing happens.
    """
    with _connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TEXT
            );
            CREATE TABLE IF NOT EXISTS items (
              id       INTEGER PRIMARY KEY AUTOINCREMENT,
              owner    TEXT NOT NULL,
              position INTEGER NOT NULL,
              text     TEXT NOT NULL,
              UNIQUE(owner, position)
            );
        """)


# ---------------------------------------------------------------- users

def get_user(username):
    """Return one user's record as a dictionary, or None.

    *** READ THIS CAREFULLY — IT IS THE MOST IMPORTANT COMMENT IN THE KIT ***

    Look at the question mark in the SQL below, and the (username,) after it.
    That is a PARAMETERISED QUERY. We hand the database the shape of the
    question and the value separately, so the database never confuses one for
    the other.

    The tempting alternative looks like this, and is WRONG:

        conn.execute("SELECT * FROM users WHERE username = '" + username + "'")

    If someone types   ' OR '1'='1   as their username, that builds:

        SELECT * FROM users WHERE username = '' OR '1'='1'

    ...which matches every row, because the typed text stopped being *data*
    and became part of the *query*. That is SQL injection, and it is the
    reason the question mark exists.

    The trailing comma in (username,) is not a typo. It is how Python writes a
    tuple containing exactly one thing.
    """
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return dict(row) if row else None


def create_user(username, password_record):
    """Add a new user. Returns False if the username is taken."""
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password_record))
        return True
    except sqlite3.IntegrityError:
        # The PRIMARY KEY on username means the database itself refuses a
        # duplicate. We catch that refusal and turn it into a tidy False.
        return False


def update_user(username, **fields):
    """Change one or more fields on a user.

    Column NAMES cannot be parameterised — only values can — so we check each
    name against a list we wrote ourselves before letting it near the query.
    An attacker therefore cannot smuggle in a column name of their choosing.
    """
    # PRINCIPLE: Complete mediation — every column name is checked on every
    # call, not trusted because the caller "should" be sensible.
    allowed = {"password", "failed_attempts", "locked_until"}
    fields = {k: v for k, v in fields.items() if k in allowed}
    if not fields:
        return False
    assignments = ", ".join(f"{k} = ?" for k in fields)       # names: checked above
    values = list(fields.values()) + [username]                # values: parameterised
    with _connect() as conn:
        conn.execute(f"UPDATE users SET {assignments} WHERE username = ?", values)
    return True


# ---------------------------------------------------------------- items


def list_items(username):
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT * FROM items
            WHERE owner = ?
            ORDER BY position
            """,
            (username,)
        ).fetchall()

    return [dict(row) for row in rows]


def add_item(username, text):
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute(
            """
            SELECT COALESCE(MAX(position), 0) + 1 AS next_position
            FROM items
            WHERE owner = ?
            """,
            (username,)
        ).fetchone()

        position = row["next_position"]

        cur = conn.execute(
            """
            INSERT INTO items (owner, position, text)
            VALUES (?, ?, ?)
            """,
            (username, position, text)
        )

    return cur.lastrowid


def delete_item(username, item_id):
    """Delete one note belonging to this user.

    Both conditions matter. Dropping "AND owner = ?" would let any logged-in
    user delete anyone's note by guessing the id — a broken access control
    bug, and a very common one in real applications.
    """
    # PRINCIPLE: Least privilege — a signed-in user may act on their own rows
    # and no others. The restriction is enforced here, in the query, rather
    # than by hoping the interface never offers the option.
    with _connect() as conn:
        cur = conn.execute(
            "DELETE FROM items WHERE id = ? AND owner = ?", (item_id, username))
    return cur.rowcount > 0
