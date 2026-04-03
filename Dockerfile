# Dockerfile — ShopSafe
# Image hardened : utilisateur non-root, pas de secrets dans l'image,
# dépendances épinglées, surface d'attaque minimisée.

FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Image finale ───────────────────────────────────────────────────
FROM python:3.12-slim

# Utilisateur non-root — moindre privilège
RUN groupadd -r shopsafe && useradd -r -g shopsafe -d /app -s /sbin/nologin shopsafe

WORKDIR /app

# Copier les dépendances depuis le builder (pas pip dans l'image finale)
COPY --from=builder /install /usr/local

# Copier le code source
COPY --chown=shopsafe:shopsafe app/       ./app/
COPY --chown=shopsafe:shopsafe wsgi.py    .

# Supprimer les fichiers inutiles qui augmentent la surface d'attaque
RUN find . -name "*.pyc" -delete \
 && find . -name "__pycache__" -delete \
 && find . -name "*.md"  -delete \
 && find . -name "tests" -type d -exec rm -rf {} + 2>/dev/null || true

# Basculer sur l'utilisateur non-root
USER shopsafe

# Variables d'environnement non-sensibles
# Les secrets (SECRET_KEY, DATABASE_URL) sont injectés au runtime
# via les secrets Kubernetes, AWS Secrets Manager ou HashiCorp Vault
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

# Gunicorn : jamais le serveur de développement Flask en production
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "3", "--timeout", "30", "--access-logfile", "-", "--error-logfile", "-", "--log-level", "info", "wsgi:application"]
