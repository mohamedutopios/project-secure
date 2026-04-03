"""Routes boutique — accueil, produits, commande, mes commandes."""

from flask import Blueprint, abort, redirect, render_template_string, request, session
from flask_wtf.csrf import generate_csrf

from app.models import (create_order, decrement_stock, get_product,
                        get_user_orders, search_products)
from app.security import (audit_log, login_required, safe, tokenize_card,
                          validate_card, validate_int)
from app.templates import BASE

shop_bp = Blueprint("shop", __name__)


@shop_bp.route("/")
def index():
    content = """
    <div class="card">
      <h2>🔒 ShopSafe — Boutique sécurisée</h2>
      <p>Comptes de test : <strong>admin / Admin2024!@</strong> &nbsp;|&nbsp; <strong>alice / Alice2024!@</strong></p>
      <div class="info-grid">
        <div class="info-item"><strong>Authentification</strong><br>scrypt + sel · Verrouillage 5 tentatives · CSRF</div>
        <div class="info-item"><strong>Base de données</strong><br>Requêtes paramétrées · Contraintes FK · PRAGMA foreign_keys</div>
        <div class="info-item"><strong>Paiement</strong><br>PAN non stocké · 4 derniers chiffres + token (PCI-DSS)</div>
        <div class="info-item"><strong>Headers HTTP</strong><br>CSP · X-Frame-Options · X-Content-Type-Options · Referrer-Policy</div>
        <div class="info-item"><strong>Secrets</strong><br>Variables d'environnement · Jamais dans le code</div>
        <div class="info-item"><strong>Audit</strong><br>Tous les événements loggés en JSON structuré</div>
      </div>
    </div>"""
    return render_template_string(BASE, content=content)


@shop_bp.route("/products")
def products():
    q     = request.args.get("q", "").strip()
    prods = search_products(q)
    q_s   = safe(q)

    rows = "".join(f"""<tr>
        <td>{safe(p["id"])}</td>
        <td>{safe(p["name"])}</td>
        <td>{p["price"]:.2f} €</td>
        <td>{safe(p["description"] or "")}</td>
        <td>{safe(p["stock"])}</td>
        <td><a class="btn" href="/cart?pid={p['id']}">Commander</a></td>
    </tr>""" for p in prods)

    content = f"""
    <div class="card">
      <h2>📦 Catalogue</h2>
      <form method="GET" style="display:flex;gap:10px;margin-bottom:16px">
        <input name="q" value="{q_s}" placeholder="Rechercher..." style="margin:0;flex:1">
        <button class="btn" type="submit">🔍</button>
      </form>
      <table>
        <tr><th>ID</th><th>Nom</th><th>Prix</th><th>Description</th><th>Stock</th><th>Action</th></tr>
        {rows or '<tr><td colspan="6" style="text-align:center;color:#999">Aucun résultat</td></tr>'}
      </table>
    </div>"""
    return render_template_string(BASE, content=content)


@shop_bp.route("/cart", methods=["GET", "POST"])
@login_required
def cart():
    errors = {}
    msg    = ""

    if request.method == "POST":
        pid      = request.form.get("product_id", "")
        qty      = request.form.get("quantity", "")
        card_raw = request.form.get("card_number", "")

        ok_p, mp = validate_int(pid, 1, 9999)
        ok_q, mq = validate_int(qty, 1, 100)
        ok_c, mc = validate_card(card_raw)
        if not ok_p: errors["product"]  = mp
        if not ok_q: errors["quantity"] = mq
        if not ok_c: errors["card"]     = mc

        if not errors:
            prod = get_product(int(pid))
            if not prod:
                errors["product"] = "Produit introuvable."
            elif prod["stock"] < int(qty):
                errors["quantity"] = f"Stock insuffisant (disponible : {prod['stock']})."

        if not errors:
            total              = prod["price"] * int(qty)
            card_last4, token  = tokenize_card(card_raw)
            # user_id vient de la session serveur — jamais du formulaire (protection IDOR)
            create_order(session["user_id"], int(pid), int(qty),
                         total, card_last4, token)
            decrement_stock(int(pid), int(qty))
            audit_log("ORDER_CREATED", session["username"],
                      detail=f"Produit#{pid} ×{qty} — {total:.2f}€ — ****{card_last4}")
            msg = f"""<div class="success-box">
              ✅ Commande confirmée — <strong>{total:.2f} €</strong><br>
              <small>Carte : ****{card_last4} | Token : {token}</small>
            </div>"""

    pid_g = request.args.get("pid", "1")
    ok, _ = validate_int(pid_g, 1, 9999)
    if not ok:
        abort(400)
    prod = get_product(int(pid_g))
    token = generate_csrf()

    content = f"""
    <div class="card" style="max-width:480px;margin:auto">
      <h2>🛒 Commander</h2>
      {msg}
      {"<h3>" + safe(prod["name"]) + " — " + str(prod["price"]) + " €</h3>" if prod else ""}
      <form method="POST">
        <input type="hidden" name="csrf_token" value="{token}">
        <input type="hidden" name="product_id" value="{pid_g}">
        <label>Quantité</label>
        <input name="quantity" type="number" value="1" min="1" max="100">
        {"<p class='ferr'>" + errors.get("quantity","") + "</p>" if "quantity" in errors else ""}
        <label>Numéro de carte <small>(seuls les 4 derniers chiffres sont conservés)</small></label>
        <input name="card_number" placeholder="4111 1111 1111 1111" maxlength="19">
        {"<p class='ferr'>" + errors.get("card","") + "</p>" if "card" in errors else ""}
        <button class="btn" type="submit" style="width:100%;margin-top:12px">✅ Confirmer</button>
      </form>
    </div>"""
    return render_template_string(BASE, content=content)


@shop_bp.route("/orders")
@login_required
def orders():
    my_orders = get_user_orders(session["user_id"])   # filtré par user_id session
    rows = "".join(f"""<tr>
        <td>{o["id"]}</td>
        <td>{safe(o["product_name"])}</td>
        <td>{o["quantity"]}</td>
        <td>{o["total"]:.2f} €</td>
        <td>****{safe(o["card_last4"])}</td>
        <td>{safe(o["status"])}</td>
    </tr>""" for o in my_orders)

    content = f"""
    <div class="card">
      <h2>📋 Mes commandes</h2>
      <table>
        <tr><th>ID</th><th>Produit</th><th>Qté</th><th>Total</th><th>Carte</th><th>Statut</th></tr>
        {rows or '<tr><td colspan="6" style="text-align:center;color:#999">Aucune commande</td></tr>'}
      </table>
    </div>"""
    return render_template_string(BASE, content=content)
