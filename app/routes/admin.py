"""Routes d'administration — réservées au rôle admin."""

from flask import Blueprint, render_template_string, session, request
from app.security import admin_required, audit_log, safe
from app.models import get_all_orders, get_all_users
from app.templates import BASE
import json

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/admin")
@admin_required   # 403 si rôle != admin — vérifié côté serveur
def admin():
    audit_log("ADMIN_ACCESS", session["username"])
    users  = get_all_users()
    orders = get_all_orders()

    urows = "".join(f"""<tr>
        <td>{u["id"]}</td>
        <td>{safe(u["username"])}</td>
        <td>{safe(u["role"])}</td>
        <td>{safe(u["email"])}</td>
        <td>{u["failed_attempts"]}</td>
        <td>{"🔒 " + str(u["locked_until"])[:16] if u["locked_until"] else "✅ OK"}</td>
    </tr>""" for u in users)

    orows = "".join(f"""<tr>
        <td>{o["id"]}</td>
        <td>{safe(o["username"])}</td>
        <td>{safe(o["product_name"])}</td>
        <td>{o["quantity"]}</td>
        <td>{o["total"]:.2f} €</td>
        <td>****{safe(o["card_last4"])}</td>
        <td><code style="font-size:11px">{safe(o["card_token"])}</code></td>
    </tr>""" for o in orders)

    content = f"""
    <div class="card">
      <h2>⚙️ Administration</h2>
      <h3>👥 Utilisateurs</h3>
      <table>
        <tr><th>ID</th><th>Username</th><th>Rôle</th><th>Email</th><th>Échecs</th><th>Verrou</th></tr>
        {urows}
      </table>
      <h3 style="margin-top:20px">📦 Commandes</h3>
      <table>
        <tr><th>ID</th><th>Client</th><th>Produit</th><th>Qté</th><th>Total</th><th>Carte</th><th>Token</th></tr>
        {orows or '<tr><td colspan="7" style="text-align:center;color:#999">Aucune commande</td></tr>'}
      </table>
    </div>"""
    return render_template_string(BASE, content=content)


@admin_bp.route("/audit-log")
@admin_required
def audit_log_view():
    audit_log("AUDIT_LOG_ACCESS", session["username"])
    try:
        with open("security.log", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()][-80:]
    except FileNotFoundError:
        lines = []

    rows = ""
    colors = {"WARNING": "#e67e22", "ERROR": "#e74c3c", "INFO": "#1a6b3c"}
    for line in reversed(lines):
        try:
            data  = json.loads(line[line.index("{"):])
            lvl   = next((k for k in colors if k in line), "INFO")
            color = colors[lvl]
            rows += f"""<tr>
                <td style="font-size:11px;white-space:nowrap;color:#888">{data.get("ts","")[:19]}</td>
                <td><strong style="color:{color}">{safe(data.get("event",""))}</strong></td>
                <td>{safe(data.get("user","—"))}</td>
                <td style="font-size:11px;color:#888">{safe(data.get("ip","—"))}</td>
                <td style="font-size:12px">{safe(data.get("detail",""))}</td>
            </tr>"""
        except Exception:
            pass

    content = f"""
    <div class="card">
      <h2>🔍 Audit Trail <small style="color:#888">(80 derniers événements)</small></h2>
      <table>
        <tr><th>Timestamp</th><th>Événement</th><th>Utilisateur</th><th>IP</th><th>Détail</th></tr>
        {rows or '<tr><td colspan="5" style="text-align:center;color:#999">Aucun événement</td></tr>'}
      </table>
    </div>"""
    return render_template_string(BASE, content=content)
