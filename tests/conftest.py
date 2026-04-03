"""Configuration pytest partagée."""
import pytest
from app import create_app
from app.models import init_db


@pytest.fixture(scope="session")
def app():
    application = create_app("testing")
    with application.app_context():
        init_db()
    yield application
    # Nettoyage après la session de tests
    import os
    if os.path.exists(application.config["DATABASE"]):
        os.remove(application.config["DATABASE"])
