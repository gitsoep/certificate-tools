"""
Certificate Tools - Flask Application Factory
"""
from flask import Flask
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import Config


def create_app(config_class=Config):
    """Application factory for creating Flask app instances."""
    app = Flask(__name__, template_folder='../templates', static_folder='../static')
    
    # Load configuration
    app.config.from_object(config_class)
    
    # Configure proxy support - only trust X-Forwarded-* headers when explicitly enabled
    if app.config.get('BEHIND_PROXY'):
        app.wsgi_app = ProxyFix(
            app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
        )
    
    # Initialize extensions
    Session(app)
    CSRFProtect(app)
    
    # Register error handlers
    from .utils.errors import register_error_handlers
    register_error_handlers(app)
    
    # Make analytics HTML available to all templates
    @app.context_processor
    def inject_analytics():
        return {'analytics_html': app.config.get('ANALYTICS_HTML', '')}

    # Make the release version available to all templates
    @app.context_processor
    def inject_version():
        version = app.config.get('APP_VERSION', 'dev')
        repo_url = app.config.get('GITHUB_REPO_URL', '')
        if version and version[0].isdigit():
            release_url = f'{repo_url}/releases/tag/v{version}'
        elif version.startswith('v') and version[1:2].isdigit():
            release_url = f'{repo_url}/releases/tag/{version}'
        else:
            release_url = f'{repo_url}/releases'
        return {'app_version': version, 'release_url': release_url}
    
    # Security headers
    @app.after_request
    def set_security_headers(response):
        connect_src = app.config.get('CONNECT_SRC', '')
        extra_connect_src = f' {connect_src}' if connect_src else ''
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            f"connect-src 'self'{extra_connect_src}; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'"
        )
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response
    
    # Register blueprints
    from .routes import main, auth, csr, decoder, converter, azure
    app.register_blueprint(main.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(csr.bp)
    app.register_blueprint(decoder.bp)
    app.register_blueprint(converter.bp)
    app.register_blueprint(azure.bp)
    
    return app
