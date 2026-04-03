"""Template HTML de base partagé entre toutes les routes."""

BASE = """<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>ShopSafe</title>
  <style>
    *{font-family:Arial,sans-serif;box-sizing:border-box}
    body{margin:0;background:#f0f7f0}
    .hdr{background:#1a6b3c;color:#fff;padding:14px 28px;display:flex;justify-content:space-between;align-items:center}
    .hdr h1{margin:0;font-size:20px}
    .banner{background:#145a32;color:#a9dfbf;font-size:11px;padding:6px 28px;letter-spacing:.3px}
    .wrap{max-width:980px;margin:24px auto;padding:0 20px}
    .nav{background:#fff;padding:10px 18px;border-radius:8px;margin-bottom:18px;display:flex;gap:12px;box-shadow:0 2px 6px rgba(0,0,0,.08)}
    .nav a{color:#1a6b3c;text-decoration:none;font-weight:700;padding:5px 10px;border-radius:4px;font-size:13px}
    .nav a:hover{background:#eafaf1}
    .card{background:#fff;border-radius:10px;padding:22px;margin-bottom:18px;box-shadow:0 2px 10px rgba(0,0,0,.08)}
    .err-box{background:#fdecea;border:1px solid #e74c3c;color:#c0392b;padding:9px 13px;border-radius:4px;margin-bottom:12px;font-size:13px}
    .success-box{background:#eafaf1;border:1px solid #27ae60;color:#1a6b3c;padding:9px 13px;border-radius:4px;margin-bottom:12px;font-size:13px}
    label{display:block;font-size:13px;font-weight:600;margin-bottom:3px;color:#333}
    label small{font-weight:400;color:#999}
    input{width:100%;padding:8px;border:1px solid #ccc;border-radius:4px;margin-bottom:4px;font-size:13px}
    input:focus{border-color:#1a6b3c;outline:none;box-shadow:0 0 0 2px #a9dfbf40}
    .ferr{color:#c0392b;font-size:11px;margin:0 0 8px}
    .btn{background:#1a6b3c;color:#fff;padding:9px 18px;border:none;border-radius:4px;cursor:pointer;font-size:13px;font-weight:700;text-decoration:none;display:inline-block}
    .btn:hover{background:#145a32}
    table{width:100%;border-collapse:collapse;font-size:13px}
    th{background:#1a6b3c;color:#fff;padding:9px 12px;text-align:left}
    td{padding:9px 12px;border-bottom:1px solid #eee}
    tr:hover td{background:#f9fefb}
    .info-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:16px}
    .info-item{border:1px solid #a9dfbf;border-radius:8px;padding:12px;background:#f9fefb;font-size:13px}
    .info-item strong{display:block;color:#1a6b3c;margin-bottom:4px}
  </style>
</head>
<body>
  <div class="hdr">
    <h1>🔒 ShopSafe</h1>
    <div>{% if session.username %}<span style="font-size:13px">👤 {{ session.username }}</span>
    <a href="/logout" style="color:#a9dfbf;margin-left:12px;font-size:13px">Déconnexion</a>{% endif %}</div>
  </div>
  <div class="banner">✅ Secure SDLC — scrypt · SQL paramétrés · CSRF · CSP · Audit trail · Secrets via env vars</div>
  <div class="wrap">
    <div class="nav">
      <a href="/">🏠 Accueil</a>
      <a href="/products">📦 Produits</a>
      {% if session.username %}<a href="/orders">📋 Mes commandes</a>{% endif %}
      {% if session.role == 'admin' %}<a href="/admin">⚙️ Admin</a><a href="/audit-log">🔍 Audit</a>{% endif %}
      {% if not session.username %}<a href="/login">🔑 Connexion</a><a href="/register">📝 Inscription</a>{% endif %}
    </div>
    {{ content | safe }}
  </div>
</body>
</html>"""
