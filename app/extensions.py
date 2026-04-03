"""Extensions Flask — instanciées ici pour éviter les imports circulaires."""
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

csrf    = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)
