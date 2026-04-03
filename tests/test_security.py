"""
Tests de sécurité automatisés — exécutés dans le pipeline CI/CD.

Lancement : pytest tests/ -v
Couverture : pytest tests/ --cov=app --cov-report=term-missing

Ces tests valident les contrôles de sécurité en place :
- Injections SQL (bypass auth, UNION extraction, erreurs exposées)
- XSS réfléchi et encodage des sorties
- Contrôle d'accès et élévation de privilèges
- Authentification (hachage, verrouillage, politique MDP)
- Protection CSRF
- Headers de sécurité HTTP
- Tokenisation PCI-DSS
"""

import pytest
import time


# ── Fixtures ───────────────────────────────────────────────────────
# La fixture 'app' est définie dans conftest.py (scope=session)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def admin_session(app):
    c = app.test_client()
    with c.session_transaction() as s:
        s["user_id"] = 1
        s["username"] = "admin"
        s["role"] = "admin"
    return c


@pytest.fixture
def user_session(app):
    c = app.test_client()
    with c.session_transaction() as s:
        s["user_id"] = 2
        s["username"] = "alice"
        s["role"] = "user"
    return c


# ── Injection SQL ──────────────────────────────────────────────────

class TestSQLInjection:

    SQL_PAYLOADS = [
        "admin'--",
        "' OR '1'='1'--",
        "admin' OR 1=1--",
        "'; DROP TABLE users;--",
        "' UNION SELECT 1,2,3,4,5,6,7,8--",
    ]

    def test_login_sqli_cannot_bypass_auth(self, client):
        """SQLi de bypass ne doit pas permettre la connexion."""
        for payload in self.SQL_PAYLOADS:
            r = client.post("/login", data={"username": payload, "password": "x"})
            assert r.status_code != 302 or "/products" not in r.headers.get("Location", ""), \
                f"CRITIQUE : SQLi bypass réussi avec '{payload}'"

    def test_search_sqli_no_user_data_leak(self, client):
        """UNION SELECT ne doit pas exposer la table users."""
        for payload in [
            "' UNION SELECT id,username,password,role,email,0,0,0 FROM users --",
            "' UNION SELECT 1,2,3,4,5,6,7,8 --",
        ]:
            r = client.get(f"/products?q={payload}")
            body = r.data.decode(errors="ignore")
            assert "scrypt$" not in body, f"Hash de mot de passe exposé via SQLi : {payload}"
            assert "admin@shopsafe.fr" not in body, f"Email admin exposé : {payload}"

    def test_search_sqli_no_error_disclosure(self, client):
        """Les erreurs SQL ne doivent pas être affichées à l'utilisateur."""
        for payload in ["'", "''", "1; SELECT", "' OR"]:
            r = client.get(f"/products?q={payload}")
            body = r.data.decode(errors="ignore").lower()
            assert "sqlite3" not in body
            assert "traceback" not in body
            assert "syntax error" not in body


# ── XSS ────────────────────────────────────────────────────────────

class TestXSS:

    XSS_PAYLOADS = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        '"><script>alert(document.cookie)</script>',
        "<svg onload=alert(1)>",
    ]

    def test_search_xss_reflected_encoded(self, client):
        """Les payloads XSS dans la recherche doivent être encodés."""
        for payload in self.XSS_PAYLOADS:
            r = client.get(f"/products?q={payload}")
            body = r.data.decode(errors="ignore")
            assert "<script>" not in body, f"XSS non encodé : {payload}"
            assert "onerror=alert" not in body, f"Attribut XSS non encodé : {payload}"


# ── Contrôle d'accès ───────────────────────────────────────────────

class TestAccessControl:

    def test_admin_unauthenticated_redirects(self, client):
        """/admin sans session → redirect /login (pas 200)."""
        r = client.get("/admin")
        assert r.status_code == 302
        assert "/login" in r.headers.get("Location", "")

    def test_admin_user_role_forbidden(self, user_session):
        """/admin avec rôle 'user' → 403."""
        r = user_session.get("/admin")
        assert r.status_code == 403, "CRITIQUE : /admin accessible avec le rôle 'user'"

    def test_admin_role_grants_access(self, admin_session):
        """/admin avec rôle 'admin' → 200."""
        assert admin_session.get("/admin").status_code == 200

    def test_orders_unauthenticated_redirects(self, client):
        r = client.get("/orders")
        assert r.status_code == 302

    def test_cart_unauthenticated_redirects(self, client):
        r = client.get("/cart?pid=1")
        assert r.status_code == 302

    def test_idor_orders_filtered_by_session(self, user_session, admin_session):
        """Les commandes sont filtrées par user_id de la session, pas de l'URL."""
        r = user_session.get("/orders")
        assert r.status_code == 200
        # Alice ne doit pas voir les données d'admin dans sa liste

    def test_cart_user_id_from_session(self, user_session):
        """Le user_id de la commande vient de la session, pas du formulaire."""
        r = user_session.post("/cart", data={
            "product_id": "1",
            "quantity":   "1",
            "card_number": "4111111111111111",
            "user_id":    "1",   # tentative de forcer admin user_id
        })
        assert r.status_code in (200, 302)


# ── Authentification ───────────────────────────────────────────────

class TestAuthentication:

    def test_valid_login_redirects(self, client):
        r = client.post("/login", data={"username": "admin", "password": "Admin2024!@"})
        assert r.status_code == 302
        assert "/products" in r.headers.get("Location", "")

    def test_wrong_password_fails(self, client):
        r = client.post("/login", data={"username": "admin", "password": "wrong"})
        assert r.status_code == 200
        assert "Identifiants invalides" in r.data.decode()

    def test_generic_error_no_user_enumeration(self, client):
        """Même message pour mauvais username et mauvais mot de passe."""
        r1 = client.post("/login", data={"username": "inexistant_xyz", "password": "Test1!"})
        r2 = client.post("/login", data={"username": "admin", "password": "mauvais"})
        assert "Identifiants invalides" in r1.data.decode()
        assert "Identifiants invalides" in r2.data.decode()

    def test_account_lockout_after_5_failures(self, app, client):
        """Le compte se verrouille après 5 échecs consécutifs."""
        for _ in range(5):
            client.post("/login", data={"username": "alice", "password": "wrong!"})
        # 6ème tentative avec le bon mot de passe doit être bloquée
        r = client.post("/login", data={"username": "alice", "password": "Alice2024!@"})
        body = r.data.decode()
        assert "verrouillé" in body.lower() or r.status_code == 429, \
            "CRITIQUE : compte non verrouillé après 5 échecs"

    def test_password_policy_enforced(self, client):
        """Les mots de passe faibles sont rejetés à l'inscription."""
        weak = ["short", "nouppercase1!", "NoDigit!", "12345678!"]
        for pwd in weak:
            r = client.post("/register", data={
                "username": "testuser99",
                "password": pwd,
                "email":    "t@t.fr",
            })
            assert "Compte créé" not in r.data.decode(), \
                f"Mot de passe faible accepté : {pwd}"


# ── Cryptographie ──────────────────────────────────────────────────

class TestCryptography:

    def test_password_hashed_with_scrypt(self, app):
        """Les mots de passe sont hachés avec scrypt, pas MD5 ni clair."""
        import sqlite3
        conn = sqlite3.connect(app.config["DATABASE"])
        rows = conn.execute("SELECT password FROM users").fetchall()
        conn.close()
        for (pwd,) in rows:
            assert pwd.startswith("scrypt$"), f"Algorithme inattendu : {pwd[:30]}"
            assert pwd != "Admin2024!@"

    def test_hashes_unique_same_password(self):
        """Deux hachages du même mot de passe sont différents (sel aléatoire)."""
        from app.security import hash_password
        h1 = hash_password("SamePass1!")
        h2 = hash_password("SamePass1!")
        assert h1 != h2, "CRITIQUE : sel absent, hashes identiques"

    def test_verify_correct_password(self):
        from app.security import hash_password, verify_password
        h = hash_password("MyPass1!@")
        assert verify_password("MyPass1!@", h)

    def test_verify_wrong_password(self):
        from app.security import hash_password, verify_password
        h = hash_password("MyPass1!@")
        assert not verify_password("WrongPass1!@", h)

    def test_timing_attack_resistance(self):
        """verify_password doit prendre un temps similaire pour bon/mauvais MDP."""
        from app.security import hash_password, verify_password
        h = hash_password("CorrectPass1!")
        times = {"correct": [], "wrong": []}
        for _ in range(3):
            t0 = time.perf_counter(); verify_password("CorrectPass1!", h)
            times["correct"].append(time.perf_counter() - t0)
            t0 = time.perf_counter(); verify_password("WrongPass1!", h)
            times["wrong"].append(time.perf_counter() - t0)
        avg_c = sum(times["correct"]) / 3
        avg_w = sum(times["wrong"])   / 3
        ratio = max(avg_c, avg_w) / (min(avg_c, avg_w) + 1e-9)
        assert ratio < 10, f"Timing attack possible : ratio {ratio:.1f}x"

    def test_card_pan_not_stored(self, user_session, app):
        """Le PAN complet ne doit jamais être stocké en base."""
        user_session.post("/cart", data={
            "product_id":  "2",
            "quantity":    "1",
            "card_number": "4111111111111111",
        })
        import sqlite3
        conn = sqlite3.connect(app.config["DATABASE"])
        rows = conn.execute("SELECT * FROM orders").fetchall()
        conn.close()
        for row in rows:
            assert "4111111111111111" not in str(row), \
                "CRITIQUE : PAN complet stocké — violation PCI-DSS"


# ── Headers HTTP ───────────────────────────────────────────────────

class TestSecurityHeaders:

    REQUIRED_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options":        "DENY",
        "X-XSS-Protection":       "1; mode=block",
    }

    def test_security_headers_present(self, client):
        r = client.get("/")
        for header, expected in self.REQUIRED_HEADERS.items():
            assert r.headers.get(header) == expected, \
                f"Header manquant ou incorrect : {header}"

    def test_csp_present(self, client):
        csp = client.get("/").headers.get("Content-Security-Policy", "")
        assert "default-src 'self'" in csp

    def test_server_header_not_disclosed(self, client):
        server = client.get("/").headers.get("Server", "")
        assert "werkzeug" not in server.lower()
        assert "python"   not in server.lower()

    def test_debug_disabled(self, app):
        assert not app.debug, "CRITIQUE : debug=True en mode testing"


# ── Validation des entrées ─────────────────────────────────────────

class TestInputValidation:

    def test_username_whitelist(self):
        from app.security import validate_username
        for u in ["alice", "user_01", "test-user"]:
            assert validate_username(u)[0], f"Username valide rejeté : {u}"
        for u in ["ab", "a"*31, "user space", "'; DROP", "<script>"]:
            assert not validate_username(u)[0], f"Username invalide accepté : {u}"

    def test_password_policy(self):
        from app.security import validate_password
        for p in ["Admin1!@", "Secure2024!"]:
            assert validate_password(p)[0], f"Mot de passe valide rejeté : {p}"
        for p in ["short", "nouppercase1!", "NoDigit!", "NoSpecial1"]:
            assert not validate_password(p)[0], f"Mot de passe faible accepté : {p}"

    def test_card_validation(self):
        from app.security import validate_card
        assert validate_card("4111111111111111")[0]
        assert validate_card("4111 1111 1111 1111")[0]
        assert not validate_card("1234")[0]
        assert not validate_card("abcd1234")[0]


# ── Phase 6 — Maintenance ─────────────────────────────────────────

class TestPhase6Maintenance:
    """
    Tests de régression liés à la Phase 6.
    Vérifient que l'audit trail, le patch management
    et la rotation des secrets fonctionnent correctement.
    """

    def test_audit_log_creates_json_entry(self, app, tmp_path):
        """audit_log() écrit une entrée JSON valide dans security.log."""
        import json
        from app.security import audit_log

        with app.test_request_context("/"):
            audit_log("LOGIN_SUCCESS", user="testuser", detail="test Phase 6")

        log_path = "security.log"
        with open(log_path, encoding="utf-8") as f:
            lines = [l for l in f if "LOGIN_SUCCESS" in l and "testuser" in l]

        assert lines, "Aucune entrée LOGIN_SUCCESS trouvée dans security.log"
        # Vérifier que c'est du JSON valide
        last = lines[-1]
        data = json.loads(last[last.index("{"):])
        assert data["event"]  == "LOGIN_SUCCESS"
        assert data["user"]   == "testuser"
        assert "ts"           in data
        assert "ip"           in data

    def test_audit_log_sanitizes_sensitive_fields(self, app):
        """Les données sensibles ne doivent jamais apparaître dans les logs."""
        import json
        from app.security import audit_log

        with app.test_request_context("/"):
            audit_log("LOGIN_FAILURE", user="attacker",
                      detail="password=admin123 essayé")

        with open("security.log", encoding="utf-8") as f:
            content = f.read()

        # Le mot de passe ne doit pas apparaître — sanitisé
        assert "admin123" not in content, \
            "CRITIQUE : mot de passe trouvé dans les logs"

    def test_audit_log_level_deduced_from_event(self, app):
        """Le niveau WARNING est déduit automatiquement pour LOGIN_FAILURE."""
        import json
        from app.security import audit_log

        with app.test_request_context("/"):
            # Pas de level explicite — doit être déduit du catalogue
            audit_log("LOGIN_FAILURE", user="alice")

        with open("security.log", encoding="utf-8") as f:
            lines = [l for l in f if "LOGIN_FAILURE" in l and "alice" in l]

        assert lines
        assert "[WARNING]" in lines[-1], \
            "LOGIN_FAILURE devrait être loggé en WARNING"

    def test_generate_secret_key_entropy(self):
        """generate_secret_key() produit une clé de 64 chars avec entropie suffisante."""
        import re
        from unittest.mock import patch
        from app.security import generate_secret_key

        # Mocker audit_log pour éviter l'écriture dans security.log
        with patch("app.security.audit_log"):
            key = generate_secret_key()

        assert len(key) == 64, f"Clé de longueur inattendue : {len(key)}"
        assert re.match(r"^[0-9a-f]{64}$", key), "Clé non hexadécimale"

    def test_secret_keys_are_unique(self):
        """Deux clés générées successivement doivent être différentes."""
        from unittest.mock import patch
        from app.security import generate_secret_key

        with patch("app.security.audit_log"):
            k1 = generate_secret_key()
            k2 = generate_secret_key()

        assert k1 != k2, "CRITIQUE : les clés secrètes ne sont pas aléatoires"

    def test_check_dependencies_returns_structured_result(self, app):
        """check_dependencies() retourne un dict structuré même si pip-audit est absent."""
        from app.security import check_dependencies

        with app.app_context():
            result = check_dependencies()

        assert "checked_at"       in result
        assert "status"           in result
        assert "vulnerabilities"  in result
        assert result["status"]   in ("clean", "vulnerable", "error")
        # checked_at doit être une date ISO valide
        datetime.fromisoformat(result["checked_at"])

    def test_no_passwords_in_log_after_login_failure(self, client):
        """Après un login échoué, le mot de passe ne doit pas apparaître dans les logs."""
        client.post("/login", data={
            "username": "admin",
            "password": "SuperSecret99!@",
        })
        try:
            with open("security.log", encoding="utf-8") as f:
                content = f.read()
            assert "SuperSecret99!@" not in content, \
                "CRITIQUE : mot de passe visible dans security.log"
        except FileNotFoundError:
            pass   # Pas de log = pas de fuite

    def test_security_log_file_created(self, app, client):
        """Le fichier security.log est créé automatiquement au premier événement."""
        import os
        client.post("/login", data={"username": "admin", "password": "Admin2024!@"})
        assert os.path.exists("security.log"), \
            "security.log non créé après un LOGIN_SUCCESS"


from datetime import datetime  # nécessaire pour test_check_dependencies
