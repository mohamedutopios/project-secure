FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim

RUN groupadd -r shopsafe && useradd -r -g shopsafe -d /app -s /sbin/nologin shopsafe

WORKDIR /app

COPY --from=builder /install /usr/local

COPY --chown=shopsafe:shopsafe app/       ./app/
COPY --chown=shopsafe:shopsafe wsgi.py    .

RUN mkdir -p /app/data && chown shopsafe:shopsafe /app/data

RUN find . -name "*.pyc" -delete \
 && find . -name "__pycache__" -delete \
 && find . -name "*.md"  -delete \
 && find . -name "tests" -type d -exec rm -rf {} + 2>/dev/null || true

USER shopsafe

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_PATH=/app/data/shopsafe.db

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "3", "--timeout", "30", "--access-logfile", "-", "--error-logfile", "-", "--log-level", "info", "wsgi:application"]