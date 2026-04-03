"""Point d'entrée WSGI pour Gunicorn en production."""
from app import create_app

application = create_app()
