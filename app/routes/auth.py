"""Routes d'authentification — login, register, logout."""

from datetime import datetime, timezone

from flask import Blueprint, redirect, render_template_string, request, session

from app.extensions import limiter
from app.models import (create_user, find_user, increment_failures,
                        reset_failures, user_exists)
from app.security import (audit_log, hash_password, login_required, safe,
                          tokenize_card, validate_email, validate_password,
                          validate_username, verify_password)
from app.templates import BASE

auth_bp = Blueprint("auth", __name__)


# ── Login ──────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")   # Protection brute force — rate limiting par IP
def login():
    errors = {}

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        ok, msg = validate_username(username)
        if not ok:
            errors["username"] = msg

        if not errors:
            user = find_user(username)

            # Vérification du verrouillage de compte
            if user and user["locked_until"]:
                lock_dt = datetime.fromisoformat(user["locked_until"])
                if datetime.now(timezone.utc) < lock_dt:
                    remaining = int((lock_dt - datetime.now(timezone.utc)).total_seconds())
                    errors["general"] = f"Compte verrouillé — réessayez dans {remaining}s."
                    audit_log("LOGIN_BLOCKED", username,
                              detail=f"{remaining}s restantes", level="WARNING")

        if not errors:
            # Vérification scrypt en temps constant — résistant timing attack
            valid = user is not None and verify_password(password, user["password"])

            if valid:
                # Régénération de session pour éviter la fixation de session
                session.clear()
                session.permanent       = True
                session["user_id"]      = user["id"]
                session["username"]     = user["username"]
                session["role"]         = user["role"]
                reset_failures(user["id"])
                audit_log("LOGIN_SUCCESS", username)
                return redirect("/products")
            else:
                # Message générique — pas d'user enumeration
                errors["general"] = "Identifiants invalides."
                audit_log("LOGIN_FAILURE", username, level="WARNING")
                if user:
                    count, locked = increment_failures(user["id"])
                    if locked:
                        audit_log("ACCOUNT_LOCKED", username,
                                  detail="5 échecs → verrouillage 5 min", level="ERROR")

    from flask_wtf.csrf import generate_csrf
    token = generate_csrf()
    content = f"""
    <div class="card" style="max-width:440px;margin:auto">
      <h2>🔑 Connexion</h2>
      {"<div class='err-box'>" + errors["general"] + "</div>" if "general" in errors else ""}
      <form method="POST">
        <input type="hidden" name="csrf_token" value="{token}">
        <label>Nom d'utilisateur</label>
        <input name="username" placeholder="admin" autocomplete="username">
        {"<p class='ferr'>" + errors.get("username","") + "</p>" if "username" in errors else ""}
        <label>Mot de passe</label>
        <input name="password" type="password" autocomplete="current-password">
        <button class="btn" type="submit" style="width:100%;margin-top:12px">🔑 Se connecter</button>
      </form>
      <p style="font-size:12px;color:#777;margin-top:12px">
        Comptes de test : <strong>admin / Admin2024!@</strong> | <strong>alice / Alice2024!@</strong>
      </p>
    </div>"""
    return render_template_string(BASE, content=content)


# ── Register ───────────────────────────────────────────────────────

@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    errors  = {}
    success = False

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email    = request.form.get("email", "").strip().lower()

        ok_u, msg_u = validate_username(username)
        ok_p, msg_p = validate_password(password)
        ok_e, msg_e = validate_email(email)
        if not ok_u: errors["username"] = msg_u
        if not ok_p: errors["password"] = msg_p
        if not ok_e: errors["email"]    = msg_e

        if not errors:
            if user_exists(username):
                errors["username"] = "Ce nom est déjà pris."
            else:
                create_user(username, hash_password(password), email)
                audit_log("REGISTER_SUCCESS", username)
                success = True

    from flask_wtf.csrf import generate_csrf
    token = generate_csrf()
    prev_u = safe(request.form.get("username","")) if request.method=="POST" else ""
    prev_e = safe(request.form.get("email",""))    if request.method=="POST" else ""

    content = f"""
    <div class="card" style="max-width:440px;margin:auto">
      <h2>📝 Inscription</h2>
      {"<div class='success-box'>✅ Compte créé. <a href='/login'>Se connecter</a></div>" if success else ""}
      <form method="POST">
        <input type="hidden" name="csrf_token" value="{token}">
        <label>Nom d'utilisateur <small>(3–30 car. alphanum)</small></label>
        <input name="username" value="{prev_u}" placeholder="monpseudo">
        {"<p class='ferr'>" + errors.get("username","") + "</p>" if "username" in errors else ""}
        <label>Mot de passe <small>(8+, 1 maj, 1 chiffre, 1 spécial)</small></label>
        <input name="password" type="password" placeholder="MonPass1!@">
        {"<p class='ferr'>" + errors.get("password","") + "</p>" if "password" in errors else ""}
        <label>Email</label>
        <input name="email" type="email" value="{prev_e}" placeholder="vous@email.fr">
        {"<p class='ferr'>" + errors.get("email","") + "</p>" if "email" in errors else ""}
        <button class="btn" type="submit" style="width:100%;margin-top:12px">Créer le compte</button>
      </form>
    </div>"""
    return render_template_string(BASE, content=content)


# ── Logout ─────────────────────────────────────────────────────────

@auth_bp.route("/logout")
@login_required
def logout():
    audit_log("LOGOUT", session.get("username", "unknown"))
    session.clear()
    return redirect("/")
