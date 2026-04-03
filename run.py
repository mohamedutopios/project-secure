"""Point d'entrée développement uniquement. En production : wsgi.py + Gunicorn."""
import os
from app import create_app

app = create_app(os.environ.get("FLASK_ENV", "development"))

if __name__ == "__main__":
    print("🔒 ShopSafe SECURE — http://localhost:5002")
    print("   Comptes : admin/Admin2024!@ | alice/Alice2024!@")
    print("   Tests   : pytest tests/ -v")
    app.run(port=5002, debug=False)
