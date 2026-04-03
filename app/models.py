"""
Couche d'accès aux données.
Règle absolue : toutes les requêtes SQL sont paramétrées.
Aucune concaténation de chaîne dans une requête SQL.
"""

import sqlite3
from datetime import datetime, timedelta, timezone
from flask import g


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        from flask import current_app
        import os
        db_path = current_app.config.get("DATABASE", "shopsafe.db")
        try:
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
            open(db_path, "a").close()
        except PermissionError:
            db_path = "/tmp/shopsafe.db"
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


def close_db(error=None):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        TEXT    UNIQUE NOT NULL,
            password        TEXT    NOT NULL,
            role            TEXT    NOT NULL DEFAULT 'user',
            email           TEXT    NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until    TEXT,
            created_at      TEXT    DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS products (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL,
            price       REAL    NOT NULL CHECK(price > 0),
            description TEXT,
            stock       INTEGER NOT NULL DEFAULT 0 CHECK(stock >= 0)
        );
        CREATE TABLE IF NOT EXISTS orders (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL REFERENCES users(id),
            product_id  INTEGER NOT NULL REFERENCES products(id),
            quantity    INTEGER NOT NULL CHECK(quantity > 0),
            total       REAL    NOT NULL CHECK(total > 0),
            card_last4  TEXT    NOT NULL,
            card_token  TEXT    NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'confirmed',
            created_at  TEXT    DEFAULT CURRENT_TIMESTAMP
        );
    """)

    from app.security import hash_password
    db.execute("INSERT OR IGNORE INTO users (id,username,password,role,email) VALUES (1,?,?,'admin','admin@shopsafe.fr')",
               ("admin", hash_password("Admin2024!@")))
    db.execute("INSERT OR IGNORE INTO users (id,username,password,role,email) VALUES (2,?,?,'user','alice@shopsafe.fr')",
               ("alice", hash_password("Alice2024!@")))
    db.executemany(
        "INSERT OR IGNORE INTO products (id,name,price,description,stock) VALUES (?,?,?,?,?)",
        [
            (1, "Laptop Pro",        999.99, "Laptop haute performance",    10),
            (2, "Souris Ergo",        29.99, "Souris ergonomique sans fil", 50),
            (3, "Clavier RGB",        79.99, "Clavier mécanique RGB",       25),
        ]
    )
    db.commit()


# ── Users ──────────────────────────────────────────────────────────

def find_user(username: str):
    return get_db().execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()


def find_user_by_id(user_id: int):
    return get_db().execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()


def create_user(username: str, pwd_hash: str, email: str):
    db = get_db()
    db.execute(
        "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
        (username, pwd_hash, email)
    )
    db.commit()


def user_exists(username: str) -> bool:
    return get_db().execute(
        "SELECT 1 FROM users WHERE username = ?", (username,)
    ).fetchone() is not None


def increment_failures(user_id: int):
    db = get_db()
    user = find_user_by_id(user_id)
    new_count = (user["failed_attempts"] or 0) + 1
    locked_until = (
        datetime.now(timezone.utc) + timedelta(minutes=5)
    ).isoformat() if new_count >= 5 else None
    db.execute(
        "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
        (new_count, locked_until, user_id)
    )
    db.commit()
    return new_count, locked_until


def reset_failures(user_id: int):
    db = get_db()
    db.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
        (user_id,)
    )
    db.commit()


# ── Products ───────────────────────────────────────────────────────

def search_products(query: str = ""):
    """Requête paramétrée — LIKE avec tuple, jamais de f-string."""
    if query:
        return get_db().execute(
            "SELECT * FROM products WHERE name LIKE ? OR description LIKE ?",
            (f"%{query}%", f"%{query}%")
        ).fetchall()
    return get_db().execute("SELECT * FROM products").fetchall()


def get_product(product_id: int):
    return get_db().execute(
        "SELECT * FROM products WHERE id = ?", (product_id,)
    ).fetchone()


def decrement_stock(product_id: int, quantity: int):
    db = get_db()
    db.execute(
        "UPDATE products SET stock = stock - ? WHERE id = ? AND stock >= ?",
        (quantity, product_id, quantity)
    )
    db.commit()


# ── Orders ─────────────────────────────────────────────────────────

def create_order(user_id: int, product_id: int, quantity: int,
                 total: float, card_last4: str, card_token: str):
    """card_last4 et card_token seulement — PAN jamais stocké (PCI-DSS)."""
    db = get_db()
    db.execute(
        "INSERT INTO orders (user_id,product_id,quantity,total,card_last4,card_token) "
        "VALUES (?,?,?,?,?,?)",
        (user_id, product_id, quantity, total, card_last4, card_token)
    )
    db.commit()


def get_user_orders(user_id: int):
    """Filtre systématique par user_id depuis la session — IDOR impossible."""
    return get_db().execute(
        "SELECT o.*, p.name AS product_name FROM orders o "
        "JOIN products p ON o.product_id = p.id "
        "WHERE o.user_id = ? ORDER BY o.created_at DESC",
        (user_id,)
    ).fetchall()


def get_all_orders():
    return get_db().execute(
        "SELECT o.*, u.username, p.name AS product_name FROM orders o "
        "JOIN users u ON o.user_id = u.id "
        "JOIN products p ON o.product_id = p.id "
        "ORDER BY o.created_at DESC"
    ).fetchall()


def get_all_users():
    """Sans les colonnes password — jamais exposées en admin."""
    return get_db().execute(
        "SELECT id, username, role, email, failed_attempts, locked_until FROM users"
    ).fetchall()
