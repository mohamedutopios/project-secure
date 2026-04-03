"""
ShopSafe — Boutique e-commerce sécurisée
Application Factory Pattern.

Sécurité intégrée tout au long du développement (Secure SDLC) :
- Authentification forte (scrypt, verrouillage, CSRF)
- Autorisation par rôle (moindre privilège)
- Requêtes SQL paramétrées (pas d'injection possible)
- Secrets depuis variables d'environnement (jamais dans le code)
- Headers de sécurité HTTP sur toutes les réponses
- Audit trail de tous les événements de sécurité
- Tests automatisés (SAST + DAST) dans le pipeline CI/CD
"""

import os
from flask import Flask

from app.extensions import csrf, limiter
from app.models import close_db, init_db
from app.routes.auth import auth_bp
from app.routes.shop import shop_bp
from app.routes.admin import admin_bp


def create_app(config_name: str = None) -> Flask:
    """
    Factory Flask — instancie l'application selon la configuration.
    Permet de créer plusieurs instances indépendantes (tests, prod, dev).
    """
    app = Flask(__name__, instance_relative_config=True)

    _load_config(app, config_name)
    _init_extensions(app)
    _register_blueprints(app)
    _register_error_handlers(app)
    _apply_security_headers(app)

    with app.app_context():
        init_db()

    return app


# ── Configuration ──────────────────────────────────────────────────

def _load_config(app: Flask, config_name: str):
    """
    Charge la configuration depuis les variables d'environnement.
    Aucun secret dans le code source.
    """
    env = config_name or os.environ.get("FLASK_ENV", "development")

    defaults = {
        "TESTING":                    False,
        "DEBUG":                      False,                 # jamais True en prod
        "SECRET_KEY":                 os.environ.get("SECRET_KEY", _dev_secret()),
        "DATABASE":                   os.environ.get("DATABASE_PATH", "shopsafe.db"),
        "SESSION_COOKIE_HTTPONLY":    True,
        "SESSION_COOKIE_SAMESITE":    "Lax",
        "SESSION_COOKIE_SECURE":      env == "production",   # HTTPS en prod
        "PERMANENT_SESSION_LIFETIME": __import__("datetime").timedelta(minutes=30),
        "WTF_CSRF_ENABLED":           True,
        "WTF_CSRF_TIME_LIMIT":        3600,
        "RATELIMIT_STORAGE_URI":      os.environ.get("REDIS_URL", "memory://"),
        "RATELIMIT_HEADERS_ENABLED":  True,
    }

    if env == "testing":
        defaults.update({
            "TESTING":           True,
            "WTF_CSRF_ENABLED":  False,   # désactivé pour les tests unitaires
            "DATABASE":          "shopsafe_test.db",
            "RATELIMIT_ENABLED": False,
        })

    app.config.update(defaults)


def _dev_secret() -> str:
    """
    En développement uniquement : génère une clé aléatoire si absente.
    En production, SECRET_KEY doit être définie dans l'environnement
    (variable d'env, Vault, AWS Secrets Manager…).
    """
    import secrets
    import warnings
    if os.environ.get("FLASK_ENV") == "production":
        raise RuntimeError(
            "SECRET_KEY manquante en production. "
            "Définissez la variable d'environnement SECRET_KEY."
        )
    warnings.warn("SECRET_KEY non définie — clé temporaire générée (développement uniquement).")
    return secrets.token_hex(32)


# ── Extensions ─────────────────────────────────────────────────────

def _init_extensions(app: Flask):
    csrf.init_app(app)
    limiter.init_app(app)
    app.teardown_appcontext(close_db)


# ── Blueprints ─────────────────────────────────────────────────────

def _register_blueprints(app: Flask):
    app.register_blueprint(auth_bp)
    app.register_blueprint(shop_bp)
    app.register_blueprint(admin_bp)


# ── Error handlers ─────────────────────────────────────────────────

def _register_error_handlers(app: Flask):
    from flask import render_template_string, session, request
    from app.security import audit_log

    @app.errorhandler(403)
    def forbidden(e):
        audit_log("ACCESS_DENIED_403",
                  user=session.get("username", "anonymous"),
                  detail=request.path, level="WARNING")
        return render_template_string(
            "<h2>403 — Accès interdit</h2><a href='/'>Retour</a>"
        ), 403

    @app.errorhandler(429)
    def rate_limited(e):
        return render_template_string(
            "<h2>429 — Trop de requêtes. Réessayez dans quelques instants.</h2>"
        ), 429

    @app.errorhandler(400)
    def bad_request(e):
        return render_template_string(
            "<h2>400 — Requête invalide.</h2><a href='/'>Retour</a>"
        ), 400


# ── Headers de sécurité HTTP ───────────────────────────────────────

def _apply_security_headers(app: Flask):
    """
    Appliqués sur toutes les réponses HTTP via after_request.
    Objectif : score A sur securityheaders.com
    """
    @app.after_request
    def set_headers(response):
        response.headers["X-Content-Type-Options"]  = "nosniff"
        response.headers["X-Frame-Options"]         = "DENY"
        response.headers["X-XSS-Protection"]        = "1; mode=block"
        response.headers["Referrer-Policy"]         = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]      = (
            "geolocation=(), microphone=(), camera=(), payment=()"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "frame-ancestors 'none'; "
            "form-action 'self';"
        )
        # Ne pas exposer la technologie utilisée
        response.headers.pop("Server", None)
        return response
