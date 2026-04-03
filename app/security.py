"""
Primitives de sécurité centralisées.
Toute la logique de sécurité est ici — un seul endroit à auditer.

Couvre :
- Hachage des mots de passe (scrypt + sel)
- Validation des entrées (whitelist)
- Tokenisation des cartes bancaires (PCI-DSS)
- Décorateurs d'autorisation (moindre privilège)
- Audit trail des événements de sécurité        [Phase 6 — Maintenance]
- Vérification des dépendances (CVE)             [Phase 6 — Maintenance]
"""

import hashlib
import hmac
import json
import logging
import re
import secrets
import subprocess
import sys
from datetime import datetime, timezone
from functools import wraps

from flask import abort, redirect, request, session
from markupsafe import escape


# ─────────────────────────────────────────────────────────────────
# Phase 6 — AUDIT TRAIL
#
# Tous les événements de sécurité sont loggés en JSON structuré.
# Le fichier security.log est la source de vérité pour :
#   - Détecter les anomalies (brute force, escalade de privilèges)
#   - Répondre aux incidents (qui, quoi, quand, depuis quelle IP)
#   - Alimenter un SIEM (Splunk, Wazuh, Elastic Security)
#
# Format : <timestamp> [LEVEL] {"ts":..., "event":..., "user":..., "ip":..., "detail":...}
# ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("security.log", encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
_handler_file   = logging.FileHandler("security.log", encoding="utf-8")
_handler_stdout = logging.StreamHandler()
_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
_handler_file.setFormatter(_formatter)
_handler_stdout.setFormatter(_formatter)
_logger = logging.getLogger("shopsafe.security")
_logger.setLevel(logging.DEBUG)
_logger.addHandler(_handler_file)
_logger.addHandler(_handler_stdout)
_logger.propagate = False

# Catalogue des événements — niveau déduit automatiquement
# Facilite le filtrage dans un SIEM : grep LOGIN_FAILURE security.log | jq .
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
    # Phase 6 — Maintenance
    "DEPENDENCY_CVE_FOUND":         "ERROR",
    "DEPENDENCY_CHECK_OK":          "INFO",
    "SECRET_ROTATED":               "INFO",
    "AUDIT_LOG_ROTATED":            "INFO",
}


def audit_log(event: str, user: str = "anonymous",
              detail: str = "", level: str = None) -> None:
    """
    Phase 6 — enregistre un événement de sécurité en JSON structuré.

    Règles absolues :
      - Jamais de mot de passe, token ou PAN complet dans les logs
      - Niveau déduit du catalogue si non précisé
      - Horodatage UTC systématique
    """
    if level is None:
        level = SECURITY_EVENTS.get(event, "INFO")

    # Sanitisation défensive — aucune donnée sensible accidentelle
    _forbidden = ("password", "passwd", "secret", "card", "cvv", "token")
    for word in _forbidden:
        if word in detail.lower():
            detail = f"[SANITISÉ — champ '{word}' non loggé]"
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


# ─────────────────────────────────────────────────────────────────
# Phase 6 — PATCH MANAGEMENT : vérification des CVE
#
# Appelé par :
#   - Le job GitLab CI `maintenance-dependency-check` (hebdomadaire)
#   - La commande `make check-deps`
#   - Au démarrage de l'application (warning si CVE trouvé)
#
# Politique de correction :
#   CRITICAL (CVSS >= 9.0) → patch sous 24h
#   HIGH     (CVSS 7–8.9)  → patch sous 7 jours
#   MEDIUM                  → patch sous 30 jours
# ─────────────────────────────────────────────────────────────────

def check_dependencies() -> dict:
    """
    Phase 6 — vérifie les dépendances Python contre la base NVD via pip-audit.
    Retourne un dictionnaire avec le résultat et les CVE trouvés.

    Usage :
        result = check_dependencies()
        if result["vulnerabilities"]:
            # alerter l'équipe, bloquer le déploiement
    """
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
                          detail=f"{len(vulns)} CVE détectés", level="ERROR")
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
                          detail="Aucun CVE connu dans les dépendances")

        except json.JSONDecodeError:
            # pip-audit non installé ou sortie non-JSON
            result["status"] = "error"
            result["error"]  = "pip-audit non disponible — installer avec : pip install pip-audit"
            _logger.warning("pip-audit non disponible")

    except FileNotFoundError:
        result["status"] = "error"
        result["error"]  = "pip-audit introuvable — pip install pip-audit"
    except subprocess.TimeoutExpired:
        result["status"] = "error"
        result["error"]  = "Timeout — vérifier la connexion réseau"
    except Exception as e:
        result["status"] = "error"
        result["error"]  = str(e)

    return result


# ─────────────────────────────────────────────────────────────────
# Phase 6 — ROTATION DE LA CLÉ SECRÈTE
#
# La clé secrète Flask signe les cookies de session.
# Elle doit être tournée périodiquement (recommandation : tous les 90 jours)
# et immédiatement en cas de suspicion de compromission.
#
# Procédure :
#   1. Générer une nouvelle clé : make rotate-secret
#   2. Mettre à jour la variable d'environnement SECRET_KEY
#   3. Redémarrer l'application (invalide toutes les sessions actives)
#   4. Loguer l'événement dans l'audit trail
# ─────────────────────────────────────────────────────────────────

def generate_secret_key() -> str:
    """
    Phase 6 — génère une nouvelle clé secrète cryptographiquement sûre.
    256 bits d'entropie (64 caractères hexadécimaux).
    """
    new_key = secrets.token_hex(32)
    audit_log("SECRET_ROTATED", user="system",
              detail="Nouvelle clé générée — mettre à jour SECRET_KEY et redémarrer")
    return new_key


# ─────────────────────────────────────────────────────────────────
# HACHAGE DES MOTS DE PASSE
# ─────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """
    scrypt avec sel aléatoire 16 bytes unique par utilisateur.
    N=16384 rend le brute force GPU prohibitif (coût mémoire).
    Format : scrypt$<sel_hex>$<dk_hex>
    """
    salt = secrets.token_hex(16)
    dk   = hashlib.scrypt(password.encode(), salt=salt.encode(),
                          n=16384, r=8, p=1, dklen=32)
    return f"scrypt${salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """
    Vérification en temps constant — résistant aux timing attacks.
    hmac.compare_digest() garantit une durée identique quel que soit le résultat.
    """
    try:
        scheme, salt, dk_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        dk = hashlib.scrypt(password.encode(), salt=salt.encode(),
                            n=16384, r=8, p=1, dklen=32)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────
# VALIDATION DES ENTRÉES (whitelist)
# ─────────────────────────────────────────────────────────────────

def validate_username(v: str) -> tuple[bool, str]:
    if not v or not re.match(r'^[a-zA-Z0-9_\-]{3,30}$', v.strip()):
        return False, "3–30 caractères : lettres, chiffres, tiret, underscore."
    return True, ""


def validate_password(v: str) -> tuple[bool, str]:
    if len(v) < 8:
        return False, "8 caractères minimum."
    if not any(c.isupper() for c in v):
        return False, "1 lettre majuscule requise."
    if not any(c.isdigit() for c in v):
        return False, "1 chiffre requis."
    if not any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in v):
        return False, "1 caractère spécial requis (!@#$%…)."
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
        return False, f"Valeur hors plage ({min_v}–{max_v})."
    except (ValueError, TypeError):
        return False, "Entier attendu."


def validate_card(v: str) -> tuple[bool, str]:
    digits = re.sub(r"[\s\-]", "", v)
    if not re.match(r"^\d{13,19}$", digits):
        return False, "Numéro de carte invalide."
    return True, ""


def safe(v) -> str:
    """Encode pour l'affichage HTML — protection XSS.

    Double protection :
    1. markupsafe.escape() encode les caractères HTML (<, >, &, ", ')
    2. Suppression des patterns d'event handlers (onerror, onload, onclick…)
       au cas où la valeur serait injectée dans un contexte non-échappé.
    """
    escaped = str(escape(v if v is not None else ""))
    # Neutraliser les event handlers même dans le texte encodé
    escaped = re.sub(r'(?i)\bon\w+\s*=', 'data-blocked=', escaped)
    return escaped


# ─────────────────────────────────────────────────────────────────
# TOKENISATION PCI-DSS
# ─────────────────────────────────────────────────────────────────

def tokenize_card(card_number: str) -> tuple[str, str]:
    """
    Simule la tokenisation PCI-DSS (Stripe/Braintree en production).
    Retourne (4 derniers chiffres, token opaque).
    Le PAN complet n'est JAMAIS persisté.
    """
    digits = re.sub(r"[\s\-]", "", card_number)
    last4  = digits[-4:]
    token  = f"tok_{secrets.token_urlsafe(16)}"
    return last4, token


# ─────────────────────────────────────────────────────────────────
# DÉCORATEURS D'AUTORISATION (moindre privilège)
# ─────────────────────────────────────────────────────────────────

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
                      detail=f"Tentative accès {request.path}")
            abort(403)
        return f(*args, **kwargs)
    return decorated
