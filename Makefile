# Makefile — ShopSafe
# Commandes de développement, test et maintenance (Phase 6).
#
# Usage :
#   make install       — installer les dépendances
#   make run           — lancer en développement
#   make test          — lancer les tests pytest
#   make lint          — SAST Semgrep
#   make check-deps    — vérifier les CVE (Phase 6)
#   make audit-logs    — analyser l'audit trail (Phase 6)
#   make rotate-secret — générer une nouvelle SECRET_KEY (Phase 6)

.PHONY: install run test lint check-deps audit-logs rotate-secret clean

# ── Développement ──────────────────────────────────────────────────

install:
	pip install -r requirements.txt

run:
	FLASK_ENV=development python run.py

# ── Phase 4 — Tests ───────────────────────────────────────────────

test:
	pytest tests/ -v --tb=short

test-cov:
	pytest tests/ --cov=app --cov-report=term-missing --cov-fail-under=80

test-sast:
	@echo "=== SAST — Semgrep ==="
	semgrep --config .semgrep.yml --config p/owasp-top-ten --config p/python . || true

test-secrets:
	@echo "=== Détection de secrets — Gitleaks ==="
	gitleaks detect --source . || true

# ── Phase 6 — Maintenance ─────────────────────────────────────────

check-deps:
	@echo "=== Phase 6 — Vérification des CVE dans les dépendances ==="
	@pip install pip-audit --quiet
	pip-audit --requirement requirements.txt
	@echo "=== Politique de correction ==="
	@echo "  CRITICAL (CVSS >= 9.0) : patch sous 24h"
	@echo "  HIGH     (CVSS 7-8.9)  : patch sous 7 jours"
	@echo "  MEDIUM                  : patch sous 30 jours"

audit-logs:
	@echo "=== Phase 6 — Analyse de l'audit trail ==="
	@echo ""
	@echo "--- Derniers événements ---"
	@tail -20 security.log 2>/dev/null | python -c "
import sys, json
for line in sys.stdin:
    try:
        j = json.loads(line[line.index('{'):])
        print(f\"  {j['ts'][:19]}  {j['event']:<35} user={j['user']:<15} ip={j['ip']}\")
    except: pass
" || echo "  (aucun log trouvé)"
	@echo ""
	@echo "--- Statistiques ---"
	@python -c "
import json, collections
events = collections.Counter()
try:
    for line in open('security.log'):
        try:
            j = json.loads(line[line.index('{'):])
            events[j['event']] += 1
        except: pass
    for event, count in events.most_common():
        print(f'  {count:>5}  {event}')
except FileNotFoundError:
    print('  (aucun log trouvé)')
" || true

rotate-secret:
	@echo "=== Phase 6 — Rotation de la clé secrète ==="
	@python -c "
import secrets, datetime
key = secrets.token_hex(32)
print(f'Générée le : {datetime.datetime.utcnow().isoformat()}')
print(f'')
print(f'Nouvelle SECRET_KEY :')
print(f'  {key}')
print(f'')
print(f'Actions requises :')
print(f'  1. Mettre à jour .env : SECRET_KEY={key}')
print(f'  2. Mettre à jour la variable CI/CD GitLab')
print(f'  3. Redémarrer l application (invalide toutes les sessions)')
"

rotate-logs:
	@echo "=== Phase 6 — Rotation des logs ==="
	@python -c "
import os, shutil, datetime
log = 'security.log'
if os.path.exists(log):
    ts = datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    arch = f'security_{ts}.log'
    shutil.copy(log, arch)
    open(log, 'w').close()
    print(f'Archivé : {arch}')
    print('Log actif réinitialisé')
else:
    print('Aucun security.log trouvé')
"

# ── Nettoyage ─────────────────────────────────────────────────────

clean:
	find . -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	find . -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -f shopsafe*.db security*.log pip-audit-report.json
