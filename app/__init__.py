"""
Certificate Tools - Flask Application Factory
"""
from flask import Flask
from flask_session import Session
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import Config


def create_app(config_class=Config):
    """Application factory for creating Flask app instances."""
    app = Flask(__name__, template_folder='../templates', static_folder='../static')
    
    # Load configuration
    app.config.from_object(config_class)
    
    # Configure proxy support - trust X-Forwarded-* headers
    app.wsgi_app = ProxyFix(
        app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
    )
    
    # Initialize extensions
    Session(app)
    
    # Register error handlers
    from .utils.errors import register_error_handlers
    register_error_handlers(app)
    
    # Register blueprints
    from .routes import main, auth, csr, decoder, converter, azure
    app.register_blueprint(main.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(csr.bp)
    app.register_blueprint(decoder.bp)
    app.register_blueprint(converter.bp)
    app.register_blueprint(azure.bp)
    
    return app
