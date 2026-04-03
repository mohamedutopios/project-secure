"""
Primitives de securite centralisees.
Toute la logique de securite est ici — un seul endroit a auditer.

Couvre :
- Hachage des mots de passe (scrypt + sel)
- Validation des entrees (whitelist)
- Tokenisation des cartes bancaires (PCI-DSS)
- Decorateurs d'autorisation (moindre privilege)
- Audit trail des evenements de securite        [Phase 6 — Maintenance]
- Verification des dependances (CVE)             [Phase 6 — Maintenance]
"""

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from functools import wraps

from flask import abort, redirect, request, session
from markupsafe import escape


# Phase 6 — AUDIT TRAIL
_log_path = "security.log"
try:
    open(_log_path, "a").close()
except PermissionError:
    _log_path = os.path.join(tempfile.gettempdir(), "security.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(_log_path, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
_handler_file   = logging.FileHandler(_log_path, encoding="utf-8")
_handler_stdout = logging.StreamHandler()
_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
_handler_file.setFormatter(_formatter)
_handler_stdout.setFormatter(_formatter)
_logger = logging.getLogger("shopsafe.security")
_logger.setLevel(logging.DEBUG)
_logger.addHandler(_handler_file)
_logger.addHandler(_handler_stdout)
_logger.propagate = False

SECURITY_EVENTS = {
    "LOGIN_SUCCESS":                "INFO",
    "LOGIN_FAILURE":                "WARNING",
    "LOGIN_BLOCKED":                "WARNING",
    "LOGOUT":                       "INFO",
    "ACCOUNT_LOCKED":               "ERROR",
    "REGISTER_SUCCESS":             "INFO",
    "PRIVILEGE_ESCALATION_ATTEMPT": "ERROR",
    "ACCESS_DENIED_403":            "WARNING",
    "ADMIN_ACCESS":                 "INFO",
    "AUDIT_LOG_ACCESS":             "INFO",
    "ORDER_CREATED":                "INFO",
    "DEPENDENCY_CVE_FOUND":         "ERROR",
    "DEPENDENCY_CHECK_OK":          "INFO",
    "SECRET_ROTATED":               "INFO",
    "AUDIT_LOG_ROTATED":            "INFO",
}


def audit_log(event: str, user: str = "anonymous",
              detail: str = "", level: str = None) -> None:
    if level is None:
        level = SECURITY_EVENTS.get(event, "INFO")

    _forbidden = ("password", "passwd", "secret", "card", "cvv", "token")
    for word in _forbidden:
        if word in detail.lower():
            detail = f"[SANITISE — champ '{word}' non logge]"
            break

    entry = {
        "ts":     datetime.now(timezone.utc).isoformat(),
        "event":  event,
        "user":   user,
        "ip":     _client_ip(),
        "detail": detail,
    }
    msg = json.dumps(entry, ensure_ascii=False)
    getattr(_logger, level.lower(), _logger.info)(msg)


def _client_ip() -> str:
    try:
        xff = request.headers.get("X-Forwarded-For", "")
        return xff.split(",")[0].strip() if xff else (request.remote_addr or "unknown")
    except RuntimeError:
        return "system"


def check_dependencies() -> dict:
    result = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "tool":       "pip-audit",
        "status":     "unknown",
        "vulnerabilities": [],
        "error": None,
    }

    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pip_audit",
             "--format", "json",
             "--requirement", "requirements.txt",
             "--progress-spinner", "off"],
            capture_output=True, text=True, timeout=120
        )

        try:
            data = json.loads(proc.stdout)
            vulns = data.get("vulnerabilities", [])
            result["vulnerabilities"] = vulns
            result["status"] = "vulnerable" if vulns else "clean"

            if vulns:
                audit_log("DEPENDENCY_CVE_FOUND", user="system",
                          detail=f"{len(vulns)} CVE detectes", level="ERROR")
                for v in vulns:
                    pkg  = v.get("name", "?")
                    ver  = v.get("version", "?")
                    for vuln in v.get("vulns", []):
                        vid  = vuln.get("id", "?")
                        fix  = vuln.get("fix_versions", [])
                        _logger.error(
                            json.dumps({
                                "ts": datetime.now(timezone.utc).isoformat(),
                                "event": "CVE_DETAIL",
                                "package": pkg,
                                "version": ver,
                                "cve_id": vid,
                                "fix_versions": fix,
                            })
                        )
            else:
                audit_log("DEPENDENCY_CHECK_OK", user="system",
                          detail="Aucun CVE connu dans les dependances")

        except json.JSONDecodeError:
            result["status"] = "error"
            result["error"]  = "pip-audit non disponible"
            _logger.warning("pip-audit non disponible")

    except FileNotFoundError:
        result["status"] = "error"
        result["error"]  = "pip-audit introuvable"
    except subprocess.TimeoutExpired:
        result["status"] = "error"
        result["error"]  = "Timeout"
    except Exception as e:
        result["status"] = "error"
        result["error"]  = str(e)

    return result


def generate_secret_key() -> str:
    new_key = secrets.token_hex(32)
    audit_log("SECRET_ROTATED", user="system",
              detail="Nouvelle cle generee")
    return new_key


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk   = hashlib.scrypt(password.encode(), salt=salt.encode(),
                          n=16384, r=8, p=1, dklen=32)
    return f"scrypt${salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt, dk_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        dk = hashlib.scrypt(password.encode(), salt=salt.encode(),
                            n=16384, r=8, p=1, dklen=32)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


def validate_username(v: str) -> tuple[bool, str]:
    if not v or not re.match(r'^[a-zA-Z0-9_\-]{3,30}$', v.strip()):
        return False, "3-30 caracteres : lettres, chiffres, tiret, underscore."
    return True, ""


def validate_password(v: str) -> tuple[bool, str]:
    if len(v) < 8:
        return False, "8 caracteres minimum."
    if not any(c.isupper() for c in v):
        return False, "1 lettre majuscule requise."
    if not any(c.isdigit() for c in v):
        return False, "1 chiffre requis."
    if not any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in v):
        return False, "1 caractere special requis (!@#$%...)."
    return True, ""


def validate_email(v: str) -> tuple[bool, str]:
    if not v or not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]{2,}$', v.strip()):
        return False, "Adresse email invalide."
    return True, ""


def validate_int(v, min_v: int = 1, max_v: int = 9999) -> tuple[bool, str]:
    try:
        n = int(v)
        if min_v <= n <= max_v:
            return True, ""
        return False, f"Valeur hors plage ({min_v}-{max_v})."
    except (ValueError, TypeError):
        return False, "Entier attendu."


def validate_card(v: str) -> tuple[bool, str]:
    digits = re.sub(r"[\s\-]", "", v)
    if not re.match(r"^\d{13,19}$", digits):
        return False, "Numero de carte invalide."
    return True, ""


def safe(v) -> str:
    """Encode pour l'affichage HTML — protection XSS."""
    escaped = str(escape(v if v is not None else ""))
    escaped = re.sub(r'(?i)\bon\w+\s*=', 'data-blocked=', escaped)
    return escaped


def tokenize_card(card_number: str) -> tuple[str, str]:
    digits = re.sub(r"[\s\-]", "", card_number)
    last4  = digits[-4:]
    token  = f"tok_{secrets.token_urlsafe(16)}"
    return last4, token


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return redirect("/login")
        if session.get("role") != "admin":
            audit_log("PRIVILEGE_ESCALATION_ATTEMPT",
                      user=session.get("username", "unknown"),
                      detail=f"Tentative acces {request.path}")
            abort(403)
        return f(*args, **kwargs)
    return decorated