# ShopSafe — Boutique e-commerce sécurisée

Projet pédagogique illustrant un **Secure SDLC complet**. Même fonctionnalités
que `shopsafe-classic`, développé avec la sécurité intégrée à chaque étape.

---

## Lancement rapide (local)

```bash
pip install -r requirements.txt
cp .env.example .env          # remplir SECRET_KEY
python run.py                 # http://localhost:5002
```

Comptes de test : `admin / Admin2024!@` | `alice / Alice2024!@`

---

## Structure du projet

```
shopsafe-secure/
├── app/
│   ├── __init__.py       # Factory Flask — config, extensions, blueprints, headers
│   ├── extensions.py     # Instances uniques csrf + limiter (source de vérité)
│   ├── models.py         # Accès DB — toutes les requêtes paramétrées
│   ├── security.py       # Primitives de sécurité centralisées + audit trail
│   ├── templates.py      # Template HTML base
│   └── routes/
│       ├── auth.py       # Login, register, logout
│       ├── shop.py       # Produits, commande, mes commandes
│       └── admin.py      # Administration + audit trail
├── tests/
│   ├── conftest.py       # Fixtures pytest (app, client, sessions)
│   └── test_security.py  # Suite de tests de sécurité (37 tests, 40+ assertions)
├── .gitlab-ci.yml        # Pipeline CI/CD complet (voir section dédiée ci-dessous)
├── .semgrep.yml          # Règles SAST custom (SQLi, secrets, MD5, debug…)
├── Dockerfile            # Image hardened — multi-stage, non-root, surface minimale
├── nginx.conf            # Reverse proxy — TLS 1.3, rate limiting, headers
├── wsgi.py               # Point d'entrée Gunicorn (production)
├── run.py                # Point d'entrée développement
├── Makefile              # Commandes dev + Phase 6 maintenance
├── .env.example          # Variables d'environnement (template)
└── requirements.txt
```

---

## Déploiement dans un pipeline GitLab CI/CD

### Prérequis

1. **Un projet GitLab** avec le Container Registry activé
   (Settings > General > Visibility > Container Registry → activé)

2. **Un runner GitLab** avec Docker executor
   (partagé gitlab.com ou self-hosted)

3. **Un cluster Kubernetes** (uniquement pour le stage `deploy`)
   Optionnel pour les stages SAST/test/build/DAST qui fonctionnent sans.

### Étape 1 — Configurer les variables CI/CD

Aller dans **Settings > CI/CD > Variables** et ajouter :

| Variable | Valeur | Type | Options |
|---|---|---|---|
| `SECRET_KEY` | `python -c "import secrets;print(secrets.token_hex(32))"` | Variable | Protected, Masked |
| `KUBECONFIG` | Contenu du fichier kubeconfig (base64) | File | Protected |

Les variables `CI_REGISTRY_USER`, `CI_REGISTRY_PASSWORD` et `CI_REGISTRY` sont **automatiquement fournies par GitLab** — ne pas les créer manuellement.

### Étape 2 — Pousser le code

```bash
cd shopsafe-secure
git init
git remote add origin https://gitlab.com/<votre-namespace>/shopsafe-secure.git
git add .
git commit -m "feat: initial commit — ShopSafe Secure SDLC"
git push -u origin main
```

Le pipeline se déclenche automatiquement.

### Étape 3 — Visualiser le pipeline

Aller dans **CI/CD > Pipelines** pour voir l'exécution en temps réel.

### Le pipeline complet (7 stages)

```
Push sur main ou Merge Request
    │
    ├─ sast-semgrep          Semgrep analyse le code (SQLi, secrets hardcodés, MD5, debug=True)
    │                        → bloque si pattern interdit détecté
    │
    ├─ secrets-gitleaks      Gitleaks scanne l'historique git
    │                        → bloque si un secret est trouvé dans le code
    │
    ├─ sca-trivy             Trivy analyse requirements.txt
    │                        → bloque si CVE HIGH ou CRITICAL dans les dépendances
    │
    ├─ test-security         pytest exécute 37 tests de sécurité
    │                        → bloque si un test échoue ou couverture < 80%
    │
    ├─ build-docker          Construit l'image Docker multi-stage
    │  │                     Scan Trivy de l'image avant push
    │  │                     Push vers GitLab Container Registry
    │  │
    │  └─ dast-zap           Lance l'app comme service Docker dans le pipeline
    │     │                  OWASP ZAP scanne l'app en live
    │     │                  → bloque si vulnérabilités HIGH détectées
    │     │
    │     └─ deploy-prod     Déploiement Kubernetes (MANUEL)
    │                        kubectl set image → rollout
    │                        Nécessite : KUBECONFIG configuré
    │
    └─ maintenance-*         Jobs planifiés (ne bloquent pas le pipeline principal)
       ├─ dependency-check   Vérification hebdomadaire CVE (pip-audit) [schedule]
       ├─ rotate-secret      Génération nouvelle SECRET_KEY [manuel via web]
       └─ rotate-logs        Archivage des logs de sécurité [schedule]
```

### Fonctionnement du DAST dans le pipeline

Le stage `dast-zap` lance **l'image Docker buildée au stage précédent** comme service GitLab CI :

```yaml
services:
  - name: "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA"
    alias: shopsafe-staging
```

ZAP scanne ensuite `http://shopsafe-staging:8080`. Pas besoin d'infrastructure de staging externe — tout se passe dans le pipeline.

### Configurer les jobs planifiés (Phase 6 — Maintenance)

Aller dans **Settings > CI/CD > Schedules** et créer :

| Schedule | Cron | Branche | Description |
|---|---|---|---|
| CVE hebdomadaire | `0 8 * * 1` | main | Vérifie les CVE dans les dépendances chaque lundi 8h |
| Rotation logs | `0 3 1 * *` | main | Archive security.log le 1er de chaque mois |

La rotation de la clé secrète se déclenche manuellement :
**CI/CD > Pipelines > Run pipeline** (sélectionner la branche main).

### Si le pipeline échoue

| Stage qui échoue | Cause probable | Résolution |
|---|---|---|
| `sast-semgrep` | Pattern interdit dans le code (f-string SQL, secret hardcodé) | Corriger le code, ne pas contourner les règles |
| `secrets-gitleaks` | Secret commité (clé API, mot de passe) | Révoquer le secret, le supprimer de l'historique git (`git filter-branch`) |
| `sca-trivy` | CVE HIGH/CRITICAL dans une dépendance | Mettre à jour le package dans `requirements.txt` |
| `test-security` | Test de sécurité en échec ou couverture < 80% | Corriger le bug, ne pas supprimer le test |
| `build-docker` | Erreur de build ou CVE dans l'image | Vérifier le Dockerfile, mettre à jour l'image de base |
| `dast-zap` | Vulnérabilité détectée par ZAP | Consulter le rapport `zap-baseline-report.html` dans les artifacts |
| `deploy-production` | KUBECONFIG manquant ou cluster inaccessible | Configurer la variable File dans CI/CD > Variables |

### Lancer le pipeline sans Kubernetes

Les stages `sast` → `secrets` → `sca` → `test` → `build` → `dast` fonctionnent **sans cluster Kubernetes**. Seul le stage `deploy` (manuel) nécessite un cluster. Pour un usage pédagogique, le pipeline est fonctionnel jusqu'au DAST inclus.

---

## Tests

```bash
# Lancer tous les tests de sécurité
pytest tests/ -v

# Avec couverture de code
pytest tests/ --cov=app --cov-report=term-missing

# Un test spécifique
pytest tests/test_security.py::TestSQLInjection -v
pytest tests/test_security.py::TestAuthentication::test_account_lockout_after_5_failures -v
```

---

## Commandes Makefile

```bash
make install          # Installer les dépendances
make run              # Lancer en développement (http://localhost:5002)
make test             # Lancer les tests pytest
make test-cov         # Tests + couverture (seuil 80%)
make test-sast        # SAST local avec Semgrep
make test-secrets     # Détection de secrets local avec Gitleaks
make check-deps       # Vérifier les CVE (Phase 6)
make audit-logs       # Analyser l'audit trail (Phase 6)
make rotate-secret    # Générer une nouvelle SECRET_KEY (Phase 6)
make rotate-logs      # Archiver security.log (Phase 6)
make clean            # Nettoyer les fichiers temporaires
```

---

## Secure SDLC — Où chaque pratique se matérialise

| Pratique de sécurité | Fichier | Détail |
|---|---|---|
| **Hachage scrypt** | `app/security.py` | `hash_password()` — sel aléatoire 16 bytes, N=16384 |
| **Vérification temps constant** | `app/security.py` | `hmac.compare_digest()` — anti timing attack |
| **Politique de MDP** | `app/security.py` | `validate_password()` — 8+, maj, chiffre, spécial |
| **Verrouillage de compte** | `app/routes/auth.py` | 5 échecs → 5 min, loggé |
| **Requêtes SQL paramétrées** | `app/models.py` | `execute("... WHERE x=?", (val,))` partout |
| **Encodage XSS** | `app/security.py` | `safe()` — escape() + neutralisation event handlers |
| **Protection CSRF** | `app/extensions.py` | `CSRFProtect(app)` — token sur tous les POST |
| **Cookies sécurisés** | `app/__init__.py` | HttpOnly, SameSite=Lax, Secure en prod |
| **Moindre privilège** | `app/security.py` | `@admin_required` — 403 si rôle insuffisant |
| **Protection IDOR** | `app/models.py` | `get_user_orders(user_id)` — filtre session |
| **Tokenisation PCI-DSS** | `app/security.py` | `tokenize_card()` — last4 + token, PAN jamais stocké |
| **Secrets via env vars** | `app/__init__.py` | `os.environ.get("SECRET_KEY")` — erreur si absent en prod |
| **debug=False** | `app/__init__.py` | Jamais True hors développement local |
| **Headers HTTP** | `app/__init__.py` | CSP, X-Frame-Options, X-Content-Type-Options, HSTS… |
| **Rate limiting** | `app/extensions.py` | Flask-Limiter (10/min login, 100/h global) |
| **Audit trail JSON** | `app/security.py` | `audit_log()` — tous les événements de sécurité |
| **SAST** | `.gitlab-ci.yml` | Semgrep à chaque commit |
| **Détection secrets** | `.gitlab-ci.yml` | Gitleaks — bloque si secret dans le code |
| **SCA (CVE dépendances)** | `.gitlab-ci.yml` | Trivy — bloque sur HIGH/CRITICAL |
| **Tests automatisés** | `tests/test_security.py` | 37 tests : SQLi, XSS, auth, IDOR, headers, crypto |
| **DAST** | `.gitlab-ci.yml` | OWASP ZAP — scan dynamique dans le pipeline |
| **Image hardened** | `Dockerfile` | Multi-stage, utilisateur non-root, surface minimale |
| **TLS 1.3** | `nginx.conf` | Protocoles obsolètes désactivés |

---

## Comparaison avec shopsafe-classic

| Vecteur d'attaque | Classic | Secure |
|---|---|---|
| SQLi login `admin'--` | ✅ Bypass total | ❌ Validé avant la requête |
| SQLi search UNION | ✅ Dump users | ❌ Requête paramétrée |
| `/admin` sans auth | ✅ Accès libre | ❌ Redirect /login |
| `/admin` rôle user | ✅ Accès libre | ❌ 403 |
| Brute force 100 tentatives | ✅ Aucune limite | ❌ Rate limit + verrou 5 min |
| MD5 crack `admin123` | ✅ < 1 seconde | ❌ scrypt — infaisable |
| PAN en base | ✅ En clair | ❌ last4 + token seulement |
| XSS `<script>alert(1)` | ✅ Exécuté | ❌ Encodé par `escape()` |
| Secret key | ✅ Hardcodée `secret123` | ❌ Env var — erreur si absente en prod |
| Debug Werkzeug (RCE) | ✅ Activé | ❌ `debug=False` toujours |
| CSRF cross-site | ✅ Possible | ❌ Token CSRF Flask-WTF |
| Headers sécurité | ✅ Aucun | ❌ CSP, X-Frame, HSTS, etc. |
